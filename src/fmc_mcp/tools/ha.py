"""FTD HA depth: the pair's live state, monitored interfaces (standby IPs, failure monitoring) and
failover virtual MAC addresses. Forming, switching and breaking the pair are in dangerous.py.

The live state comes from the units themselves through FMC's operational/commands ('show failover',
'show failover state', 'show failover history'; FMC 10.0.1 passes 'show failover <option>' through):
FMC's own per-unit state (metadata.<side>Status) trails a failover by up to a minute and says only
Active/Standby, not whether the standby is ready, why the last failover happened or whether the
failover and state links are up."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import re
from datetime import datetime
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
    object_result,
)
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, ref_label, resolve_in, slim
from fmc_mcp.tools.devices import HA_PAIRS
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.show_commands import Supported, supported_commands
from fmc_mcp.tools.troubleshoot import redact, run_show

HaRef = Annotated[str, Field(description="HA pair name or UUID (fmc_list_ha_pairs)")]
MAC_RE = re.compile(r"^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$")


def _mac(value: str | None, what: str) -> str | None:
    """A MAC in FMC's H.H.H form (accepts aa:bb:cc:dd:ee:ff and aabb.ccdd.eeff)."""
    if value is None:
        return None
    v = value.strip().lower()
    if MAC_RE.match(v):
        return v
    hexes = re.sub(r"[^0-9a-f]", "", v)
    if len(hexes) != 12 or not re.fullmatch(r"[0-9a-f:\-.]+", v):
        raise InvalidRequest(
            f"{what} {value!r} is not a MAC address (use 0050.56aa.0001 or 00:50:56:aa:00:01)."
        )
    return f"{hexes[0:4]}.{hexes[4:8]}.{hexes[8:12]}"


def _monitored_row(m: dict[str, Any]) -> dict[str, Any]:
    v4 = m.get("ipv4Configuration") or {}
    row = {
        "interface": m.get("name"),
        "monitored": m.get("monitorForFailures"),
        "active_ip": v4.get("activeIPv4Address"),
        "mask": v4.get("activeIPv4Mask"),
        "standby_ip": v4.get("standbyIPv4Address"),
        "id": m.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


def _mac_row(m: dict[str, Any]) -> dict[str, Any]:
    return {
        "interface": ref_label(m.get("physicalInterface") or {}),
        "active_mac": m.get("failoverActiveMac"),
        "standby_mac": m.get("failoverStandbyMac"),
        "id": m.get("id"),
    }


async def _pair(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, HA_PAIRS, ref, "HA pair", domain)


def _status(ha: dict[str, Any]) -> dict[str, Any]:
    meta = ha.get("metadata") or {}
    out = {}
    for side in ("primary", "secondary"):
        st = meta.get(f"{side}Status") or {}
        out[side] = {
            "device": ref_label(ha.get(side) or {}),
            "state": st.get("currentStatus"),
        }
    return out


def _link_row(link: dict[str, Any]) -> dict[str, Any]:
    row = {
        "interface": ref_label(link.get("interfaceObject") or {}),
        "logical_name": link.get("logicalName"),
        "active_ip": link.get("activeIP"),
        "standby_ip": link.get("standbyIP"),
        "mask": link.get("subnetMask"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def same_link_for_state(boot: dict[str, Any]) -> bool | None:
    """Whether state replication shares the failover link. FMC 10.0.1 doesn't return
    useSameLinkForFailovers on GET, so compare the two links' interfaces."""
    if boot.get("useSameLinkForFailovers") is not None:
        return bool(boot.get("useSameLinkForFailovers"))
    lan = ref_label((boot.get("lanFailover") or {}).get("interfaceObject") or {})
    state = ref_label((boot.get("statefulFailover") or {}).get("interfaceObject") or {})
    if not lan or not state:
        return None
    return str(lan).lower() == str(state).lower()


# --- the units' own view: 'show failover', 'show failover state', 'show failover history' ----------

_ON = re.compile(r"^Failover\s+(?P<on>On|Off)\b", re.M)
_UNIT = re.compile(r"^Failover unit\s+(?P<unit>\S+)", re.M)
_LAN = re.compile(r"^Failover LAN Interface:\s*(?P<rest>.+?)\s*$", re.M)
_STATE_LINK = re.compile(r"^\s*Link\s*:\s*(?P<rest>.+?)\s*$")
_LINK = re.compile(r"^(?P<name>\S+)\s+(?P<iface>\S+)\s*\((?P<status>[^)]*)\)")
_VERSION = re.compile(r"^Version:\s*Ours\s+(?P<ours>[^,]+?),\s*Mate\s+(?P<mate>\S+)", re.M)
_LAST = re.compile(r"^Last Failover at:\s*(?P<at>.+?)\s*$", re.M)
_HOST = re.compile(r"^\s*(?P<who>This|Other) host:\s*(?P<role>\w+)\s*-\s*(?P<state>.+?)\s*$")
_ACTIVE_TIME = re.compile(r"^\s*Active time:\s*(?P<s>\d+)")
_IFACE = re.compile(r"^\s*Interface\s+(?P<name>\S+)\s+\((?P<addr>[^)]*)\):\s*(?P<status>.+?)\s*$")
_SLOT = re.compile(r"^\s*slot\s+\d+:\s*(?P<what>\S+).*\bstatus\s+\((?P<status>[^)]*)\)")
_STAT = re.compile(
    r"^\s*(?P<obj>[A-Za-z][^\t]*?)(?:\s*\t\s*|\s{2,})"
    r"(?P<xmit>\d+)\s+(?P<xerr>\d+)\s+(?P<rcv>\d+)\s+(?P<rerr>\d+)\s*$"
)
_STATE_HOST = re.compile(r"^(?P<who>This|Other) host\s*-\s*(?P<role>\w+)")
_TIMESTAMP = re.compile(
    r"^(?P<t>\d{1,2}:\d{2}:\d{2})(?:\.\d+)?\s+\S+\s+(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<year>\d{4})\s*$"
)


def _link(rest: str) -> dict[str, Any]:
    """'FAILOVER-LINK Ethernet0/2 (up)' -> name/interface/status; 'Unconfigured.' -> status only."""
    m = _LINK.match(rest.strip())
    if m:
        return {"name": m["name"], "interface": m["iface"], "status": m["status"].strip()}
    return {"status": rest.strip().rstrip(".").lower()}


def parse_show_failover(text: str) -> dict[str, Any]:
    """The parts of 'show failover' a failover check needs: on/off, this unit's role, the failover
    (LAN) and state links with their status, software versions, when the last failover happened,
    each host's state, active time, monitored interfaces and modules (snort, disk), and the
    stateful replication counters (xmit/xerr/rcv/rerr per object type)."""
    out: dict[str, Any] = {}
    if m := _ON.search(text):
        out["failover"] = m["on"]
    if m := _UNIT.search(text):
        out["unit"] = m["unit"]
    if m := _LAN.search(text):
        out["failover_link"] = _link(m["rest"])
    if m := _VERSION.search(text):
        out["version"] = {"ours": m["ours"].strip(), "mate": m["mate"].strip()}
    if m := _LAST.search(text):
        out["last_failover_at"] = m["at"]
    hosts: dict[str, dict[str, Any]] = {}
    stats: dict[str, dict[str, int]] = {}
    cur: dict[str, Any] | None = None
    in_stats = False
    for line in text.splitlines():
        if line.startswith("Stateful Failover"):
            in_stats, cur = True, None
            continue
        if in_stats:
            if m := _STATE_LINK.match(line):
                out["state_link"] = _link(m["rest"])
            elif m := _STAT.match(line):
                stats[m["obj"].strip()] = {k: int(m[k]) for k in ("xmit", "xerr", "rcv", "rerr")}
            continue
        if m := _HOST.match(line):
            cur = {"role": m["role"], "state": m["state"], "interfaces": [], "modules": {}}
            hosts["this" if m["who"] == "This" else "other"] = cur
        elif cur is None:
            continue
        elif m := _ACTIVE_TIME.match(line):
            cur["active_time_s"] = int(m["s"])
        elif m := _IFACE.match(line):
            cur["interfaces"].append({"name": m["name"], "address": m["addr"], "status": m["status"]})
        elif m := _SLOT.match(line):
            cur["modules"][m["what"]] = m["status"]
    if hosts:
        out["hosts"] = hosts
    if stats:
        out["stateful"] = stats
    return out


def parse_failover_state(text: str) -> dict[str, Any]:
    """'show failover state': each unit's state and last failure reason (with when), and the
    configuration and communication state lines."""
    units: dict[str, dict[str, Any]] = {}
    sections: dict[str, list[str]] = {"configuration": [], "communication": []}
    section: str | None = None
    cur: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("===="):
            low = line.lower()
            section = next((k for k in sections if k in low), None)
            continue
        if section:
            sections[section].append(line)
            continue
        if m := _STATE_HOST.match(line):
            cur = {"role": m["role"]}
            units["this" if m["who"] == "This" else "other"] = cur
        elif cur is not None and "state" not in cur:
            cols = re.split(r"\s{2,}", line)
            cur["state"] = cols[0]
            if len(cols) > 1 and cols[1].lower() != "none":
                cur["last_failure_reason"] = cols[1]
            if len(cols) > 2:
                cur["last_failure_at"] = cols[2]
    return {
        "units": units,
        "configuration_state": sections["configuration"],
        "communication_state": sections["communication"],
    }


def parse_failover_history(text: str) -> list[dict[str, Any]]:
    """'show failover history': [{at, from, to, reason}] oldest first. The table has fixed columns
    (From State, To State, Reason); a reason that wraps continues on the next line."""
    entries: list[dict[str, Any]] = []
    cols: tuple[int, int] | None = None
    cur: dict[str, Any] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or set(stripped) == {"="}:
            continue
        if stripped.startswith("From State") and "To State" in line and "Reason" in line:
            cols = (line.index("To State"), line.index("Reason"))
            continue
        if _TIMESTAMP.match(stripped):
            cur = {"at": stripped}
            entries.append(cur)
            continue
        if cur is None:
            continue
        if "to" not in cur:
            if cols and len(line) > cols[0] and line[: cols[0]].strip():
                frm, to, why = line[: cols[0]], line[cols[0] : cols[1]], line[cols[1] :]
            else:
                parts = re.split(r"\s{2,}", stripped, maxsplit=2) + ["", ""]
                frm, to, why = parts[0], parts[1], parts[2]
            cur.update({"from": frm.strip(), "to": to.strip(), "reason": why.strip()})
        else:
            cur["reason"] = f"{cur['reason']} {stripped}".strip()
    return [e for e in entries if e.get("to")]


def _when(at: str | None) -> datetime | None:
    m = _TIMESTAMP.match((at or "").strip())
    if not m:
        return None
    try:
        return datetime.strptime(f"{m['t']} {m['mon']} {m['day']} {m['year']}", "%H:%M:%S %b %d %Y")
    except ValueError:
        return None


def last_failover(histories: dict[str, list[dict[str, Any]]]) -> dict[str, Any] | None:
    """The most recent time a unit became active ('-> Just Active', or '-> Active' on software that
    skips it) across the units' histories, with the reason the unit gave, plus the step the other
    unit took out of the active state just before (when its history has one)."""
    moves: list[tuple[datetime, int, str, dict[str, Any]]] = []
    for unit, entries in histories.items():
        targets = [e for e in entries if e["to"].lower() == "just active"] or [
            e for e in entries if e["to"].lower() == "active"
        ]
        for e in targets:
            when = _when(e.get("at"))
            if when is not None:
                moves.append((when, entries.index(e), unit, e))
    if not moves:
        return None
    when, _, unit, e = max(moves, key=lambda m: (m[0], m[1]))
    out: dict[str, Any] = {"unit": unit, "at": e["at"], "from": e["from"], "reason": e["reason"]}
    for other, entries in histories.items():
        if other == unit:
            continue
        left = [
            x
            for x in entries
            if x["from"].lower().startswith("active")
            and not x["to"].lower().startswith("active")
            and (_when(x.get("at")) or when) <= when
            and (when - (_when(x.get("at")) or when)).total_seconds() <= 600
        ]
        if left:
            x = left[-1]
            out["previous_active"] = {"unit": other, "at": x["at"], "to": x["to"], "reason": x["reason"]}
    return out


def _kind(state: str | None) -> str | None:
    """Active or standby, whatever the exact wording (FMC 'Standby' vs device 'Standby Ready')."""
    s = (state or "").lower()
    if not s:
        return None
    if "standby" in s:
        return "standby"
    if "active" in s:
        return "active"
    return s


def _unit_ids(ha: dict[str, Any]) -> list[dict[str, Any]]:
    meta = ha.get("metadata") or {}
    out = []
    for side in ("primary", "secondary"):
        unit = ha.get(side) or {}
        if unit.get("id"):
            state = (meta.get(f"{side}Status") or {}).get("currentStatus")
            out.append({"role": side, "device": ref_label(unit), "id": unit["id"], "state": state})
    return out


async def read_live(
    ctx: Any, app: FmcApp, ha: dict[str, Any], domain: str | None, history: int
) -> dict[str, Any]:
    """Run the failover show commands through FMC, one at a time (FMC runs one command per device
    at once): 'show failover' and 'show failover state' on the active unit (the primary when FMC
    knows no active unit), 'show failover history' on each unit when `history`. A command that fails
    becomes a note; the rest still run."""
    units = _unit_ids(ha)
    if not units:
        return {"notes": ["FMC lists no units for this pair."]}
    active = next((u for u in units if _kind(u["state"]) == "active"), units[0])
    supported: Supported = await supported_commands(ctx)
    notes: list[str] = []

    async def show(unit: dict[str, Any], cmd: str) -> str | None:
        try:
            text, _ = redact(await run_show(app, str(unit["id"]), cmd, domain, supported))
        except (InvalidRequest, NotFound, UpstreamError) as e:
            notes.append(f"{cmd!r} on {unit['device']}: {e}")
            return None
        return text

    out: dict[str, Any] = {"ran_on": active["device"]}
    text = await show(active, "show failover")
    if text is not None:
        out["failover"] = parse_show_failover(text)
    text = await show(active, "show failover state")
    if text is not None:
        out["state"] = parse_failover_state(text)
    if history:
        hist: dict[str, list[dict[str, Any]]] = {}
        for u in [active] + [u for u in units if u is not active]:
            text = await show(u, "show failover history")
            if text is not None:
                hist[str(u["device"])] = parse_failover_history(text)
        out["history"] = hist
    if notes:
        out["notes"] = notes
    return out


_BLOCKER, _WARNING = "blocker", "warning"


def _check(name: str, level: str, ok: bool | None, detail: str) -> dict[str, Any]:
    return {"check": name, "level": level, "ok": ok, "detail": detail}


def failover_checks(status: dict[str, Any], live: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Pre-checks for a switch: blockers make `ready_for_switch` false, warnings say what the switch
    will cost (connections dropped, a failure that wouldn't fail over). ok=None: no data for it."""
    sf = (live or {}).get("failover") or {}
    units = status["units"]
    checks: list[dict[str, Any]] = []
    if live is not None:
        on = sf.get("failover")
        checks.append(
            _check("failover_on", _BLOCKER, None if on is None else on == "On", f"Failover {on or 'unknown'}")
        )
    states = {role: u.get("device_state") or u.get("state") for role, u in units.items()}
    actives = [role for role, s in states.items() if _kind(s) == "active"]
    detail = ", ".join(f"{units[r]['device']} ({r}) {s or 'unknown'}" for r, s in states.items())
    checks.append(_check("one_active_unit", _BLOCKER, len(actives) == 1, detail))
    others = [r for r in units if r not in actives]
    if live is None:
        checks.append(
            _check(
                "standby_ready",
                _BLOCKER,
                None,
                "FMC says only Active/Standby; whether the standby is Standby Ready needs live=true",
            )
        )
    else:
        ready = [r for r in others if str(units[r].get("device_state") or "").lower() == "standby ready"]
        stby = ", ".join(f"{units[r]['device']} {units[r].get('device_state') or 'unknown'}" for r in others)
        checks.append(
            _check(
                "standby_ready", _BLOCKER, bool(others) and len(ready) == len(others), stby or "no standby"
            )
        )
    if live is not None:
        lan = sf.get("failover_link") or {}
        checks.append(
            _check(
                "failover_link_up",
                _BLOCKER,
                None if not lan else str(lan.get("status")).lower() == "up",
                f"{lan.get('name', '')} {lan.get('interface', '')} {lan.get('status', 'unknown')}".strip(),
            )
        )
        st = sf.get("state_link") or {}
        st_ok = None if not st else str(st.get("status")).lower() == "up"
        st_detail = f"{st.get('name', '')} {st.get('interface', '')} {st.get('status', 'unknown')}".strip()
        if st_ok is False:
            st_detail += ": connections are not replicated and drop at a failover"
        checks.append(_check("state_link_up", _WARNING, st_ok, st_detail))
        bad, waiting = [], []
        for host in (sf.get("hosts") or {}).values():
            for i in host.get("interfaces") or []:
                s = str(i.get("status") or "")
                label = f"{host.get('role')} {i.get('name')}: {s}"
                if re.match(r"(?i)(failed|no link|down)", s):
                    bad.append(label)
                elif re.search(r"(?i)waiting|unknown|testing", s):
                    waiting.append(label)
        hosts_seen = bool(sf.get("hosts"))
        checks.append(
            _check(
                "interfaces_normal",
                _BLOCKER,
                None if not hosts_seen else not bad,
                "; ".join(bad) or ("all Normal on both units" if hosts_seen else "no data"),
            )
        )
        if waiting:
            checks.append(
                _check(
                    "interfaces_tested",
                    _WARNING,
                    False,
                    "; ".join(waiting) + " (Waiting: the units can't test the interface yet, often a "
                    "missing standby IP or no peer on that network)",
                )
            )
        mods = [
            f"{host.get('role')} {name}: {s}"
            for host in (sf.get("hosts") or {}).values()
            for name, s in (host.get("modules") or {}).items()
            if not str(s).lower().startswith("up")
        ]
        checks.append(
            _check(
                "modules_up",
                _BLOCKER,
                None if not hosts_seen else not mods,
                "; ".join(mods) or "snort and disk up",
            )
        )
        ver = sf.get("version") or {}
        checks.append(
            _check(
                "versions_match",
                _BLOCKER,
                None if not ver else ver.get("ours") == ver.get("mate"),
                f"ours {ver.get('ours')}, mate {ver.get('mate')}" if ver else "no data",
            )
        )
        stats = sf.get("stateful") or {}
        errors = sum(v["xerr"] + v["rerr"] for v in stats.values())
        checks.append(
            _check(
                "replication_errors",
                _WARNING,
                None if not stats else errors == 0,
                f"{errors} xerr/rerr in the stateful update statistics" if stats else "no data",
            )
        )
    cfg = status.get("config_status")
    checks.append(
        _check(
            "config_in_sync",
            _BLOCKER,
            None if cfg is None else cfg == "HEALTHY_CONFIG",
            f"FMC configStatus {cfg}" if cfg else "FMC reports no configStatus",
        )
    )
    data = [m for m in status.get("monitored_interfaces") or [] if m.get("interface") != "management"]
    unmonitored = [m["interface"] for m in data if m.get("monitored") is False]
    no_standby = [
        m["interface"] for m in data if m.get("monitored") and m.get("active_ip") and not m.get("standby_ip")
    ]
    problems = []
    if not any(m.get("monitored") for m in data):
        problems.append("no data interface is monitored: a data link failure would not fail over")
    if unmonitored:
        problems.append(f"not monitored: {', '.join(map(str, unmonitored))}")
    if no_standby:
        problems.append(f"no standby IP (monitoring can't test it): {', '.join(map(str, no_standby))}")
    checks.append(
        _check(
            "monitoring_config",
            _WARNING,
            not problems,
            "; ".join(problems) or "every named data interface monitored, with a standby IP",
        )
    )
    return checks


def _merge_live(status: dict[str, Any], data: dict[str, Any], history: int) -> None:
    """Fold the units' own view (read_live) into the FMC status, per unit and per link."""
    sf = data.get("failover") or {}
    hosts = {str(h.get("role", "")).lower(): h for h in (sf.get("hosts") or {}).values()}
    st_units = {
        str(u.get("role", "")).lower(): u for u in ((data.get("state") or {}).get("units") or {}).values()
    }
    histories: dict[str, list[dict[str, Any]]] = data.get("history") or {}
    notes = list(data.get("notes") or [])
    for role, unit in status["units"].items():
        host = hosts.get(role) or {}
        if host.get("state"):
            unit["device_state"] = host["state"]
        if host.get("active_time_s") is not None:
            unit["active_time_s"] = host["active_time_s"]
        if host.get("interfaces"):
            unit["interfaces"] = host["interfaces"]
        if host.get("modules"):
            unit["modules"] = host["modules"]
        st = st_units.get(role) or {}
        if st.get("last_failure_reason"):
            unit["last_failure"] = {"reason": st["last_failure_reason"], "at": st.get("last_failure_at")}
        entries = histories.get(str(unit.get("device")))
        if entries is not None and history:
            unit["history"] = list(reversed(entries))[:history]
        fmc_kind, dev_kind = _kind(unit.get("state")), _kind(unit.get("device_state"))
        if fmc_kind and dev_kind and fmc_kind != dev_kind:
            notes.append(
                f"FMC still shows {unit.get('device')} as {unit.get('state')} while the unit says "
                f"{unit.get('device_state')}: FMC's state trails a failover; the unit's is current."
            )
    if sf.get("failover"):
        status["failover"] = sf["failover"]
    lan = sf.get("failover_link") or {}
    if lan.get("status"):
        status["failover_link"]["status"] = lan["status"]
    state = sf.get("state_link") or {}
    if state:
        status["state_link"].update({k: v for k, v in state.items() if k in ("name", "interface", "status")})
    if sf.get("version"):
        status["versions"] = sf["version"]
    last = last_failover(histories) if histories else None
    if last is None and sf.get("last_failover_at"):
        last = {"at": sf["last_failover_at"], "unit": data.get("ran_on"), "note": "from 'show failover'"}
    if last is not None:
        status["last_failover"] = last
    sync = data.get("state") or {}
    if sync.get("configuration_state") or sync.get("communication_state"):
        status["device_sync"] = {
            "configuration": sync.get("configuration_state"),
            "communication": sync.get("communication_state"),
        }
    stats = sf.get("stateful") or {}
    if stats:
        rows = {k.lower().replace(" ", "_"): v for k, v in stats.items()}
        status["stateful_replication"] = {
            "seen_on": data.get("ran_on"),
            "link_status": state.get("status"),
            "errors": sum(v["xerr"] + v["rerr"] for v in stats.values()),
            **{
                k: {"xmit": rows[k]["xmit"], "rcv": rows[k]["rcv"]}
                for k in ("tcp_conn", "udp_conn")
                if k in rows
            },
        }
    status["live_from"] = data.get("ran_on")
    if notes:
        status["notes"] = notes


def _summary(
    status: dict[str, Any], blockers: list[dict[str, Any]], unknown: list[str], checks: list[dict[str, Any]]
) -> str:
    units = ", ".join(
        f"{u.get('device')} ({role}) {u.get('device_state') or u.get('state') or 'unknown'}"
        for role, u in status["units"].items()
    )
    if blockers:
        head = "Not ready to switch: " + "; ".join(f"{c['check']}: {c['detail']}" for c in blockers)
    elif unknown:
        head = f"Not ready to switch: no data for {', '.join(unknown)}"
    else:
        head = "Ready to switch"
    warnings = [c["check"] for c in checks if c["level"] == "warning" and c["ok"] is False]
    tail = f" Warnings: {', '.join(warnings)}." if warnings else ""
    return f"{head}. Units: {units}.{tail}"


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Get HA pair status")
    async def fmc_get_ha_status(
        ctx: Context,
        ha_pair: HaRef,
        live: Annotated[
            bool,
            Field(
                description="Also read the units' own failover state through FMC ('show failover', "
                "'show failover state'; a few seconds per command): standby ready, link status, "
                "interface and module status, versions, replication counters and the pre-checks"
            ),
        ] = True,
        history: Annotated[
            int,
            Field(
                ge=0,
                le=50,
                description="With live: the latest state changes per unit from 'show failover history' "
                "(newest first) and the last failover with its reason; 0 skips the history",
            ),
        ] = 5,
        domain: Domain = None,
    ) -> Any:
        """One FTD HA pair in detail: each unit's role and state (FMC's, and with live the unit's own:
        Active, Standby Ready, Failed...), the failover link and the state link (separate or shared),
        the failover trigger criteria, every monitored interface (monitored for failures, active and
        standby IP), failover virtual MACs and FMC's config status. With live (default) it also runs
        'show failover', 'show failover state' and 'show failover history' on the units through FMC
        and returns per unit the active time, interface and snort/disk status and last failure
        reason, the link status, software versions, stateful replication counters (TCP/UDP
        connections replicated, errors), the last failover (when, which unit, why) and `checks`
        with `ready_for_switch` (the pre-checks before fmc_ha_action switch; the fmc_ha_failover_check
        prompt runs check, switch and verify). FMC's own unit states trail a failover by up to a
        minute; the units' state is current."""
        app: FmcApp = get_client(ctx)
        ha = await _pair(app, ha_pair, domain)
        base = await app.config_path(f"{HA_PAIRS}/{ha['id']}", domain)
        monitored = await app.all(f"{base}/monitoredinterfaces")
        macs = await app.all(f"{base}/failoverinterfacemacaddressconfigs")
        boot = ha.get("ftdHABootstrap") or {}
        link = boot.get("lanFailover") or {}
        same = same_link_for_state(boot)
        failover_link = {
            **_link_row(link),
            "same_link_for_state": same,
            "encryption": boot.get("isEncryptionEnabled"),
        }
        state_link: dict[str, Any] = (
            {"same_as_failover_link": True}
            if same
            else _link_row(boot.get("statefulFailover") or {}) or {"configured": False}
        )
        status: dict[str, Any] = {
            "name": ha.get("name"),
            "id": ha.get("id"),
            "units": _status(ha),
            "config_status": (ha.get("metadata") or {}).get("configStatus"),
            "failover_link": failover_link,
            "state_link": state_link,
            "trigger_criteria": slim(ha.get("ftdHAFailoverTriggerCriteria")),
            "monitored_interfaces": [_monitored_row(m) for m in monitored.items],
            "failover_macs": [_mac_row(m) for m in macs.items],
        }
        if not live:
            status["checks"] = failover_checks(status, None)
            status["note"] = "FMC's view only; live=true reads the units' own failover state."
            return object_result(status, shape=False)
        data = await read_live(ctx, app, ha, domain, history)
        _merge_live(status, data, history)
        checks = failover_checks(status, data)
        blockers = [c for c in checks if c["level"] == "blocker" and c["ok"] is False]
        unknown = [c["check"] for c in checks if c["level"] == "blocker" and c["ok"] is None]
        status["checks"] = checks
        status["ready_for_switch"] = not blockers and not unknown
        status["summary"] = _summary(status, blockers, unknown, checks)
        return object_result(status, shape=False)

    @reg.write(title="Configure HA monitored interface")
    async def fmc_configure_ha_monitoring(
        ctx: Context,
        ha_pair: HaRef,
        interface: Annotated[
            str, Field(description="Interface logical name (e.g. inside) as listed by fmc_get_ha_status")
        ],
        monitored: Annotated[
            bool | None,
            Field(
                description="Monitor the interface for failures (a failure triggers failover); omit to keep"
            ),
        ] = None,
        standby_ip: Annotated[
            str | None,
            Field(description="Standby unit's IPv4 address on this interface ('none' clears it)"),
        ] = None,
        active_mac: Annotated[
            str | None, Field(description="Failover virtual MAC for the active unit, e.g. 0050.56aa.0001")
        ] = None,
        standby_mac: Annotated[
            str | None, Field(description="Failover virtual MAC for the standby unit (with active_mac)")
        ] = None,
        clear_mac: Annotated[bool, Field(description="Remove the interface's virtual MAC setting")] = False,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Configure one interface of an FTD HA pair: whether a failure on it triggers failover, the
        standby unit's IP address (needed for the standby to answer on that network and for
        interface monitoring), and the failover virtual MAC addresses (so the active MAC stays the
        same after a failover). Preview shows before/after; takes effect after fmc_deploy."""
        app: FmcApp = get_client(ctx)
        if clear_mac and (active_mac or standby_mac):
            raise InvalidRequest("Give active_mac/standby_mac or clear_mac, not both.")
        if (active_mac is None) != (standby_mac is None):
            raise InvalidRequest("Give both active_mac and standby_mac.")
        amac, smac = _mac(active_mac, "active_mac"), _mac(standby_mac, "standby_mac")
        if monitored is None and standby_ip is None and amac is None and not clear_mac:
            raise InvalidRequest("Nothing to change: give monitored, standby_ip, the MACs or clear_mac.")
        ha = await _pair(app, ha_pair, domain)
        base = await app.config_path(f"{HA_PAIRS}/{ha['id']}", domain)
        monitored_all = await app.all(f"{base}/monitoredinterfaces")
        mon = next(
            (m for m in monitored_all.items if str(m.get("name", "")).lower() == interface.lower()), None
        )
        if mon is None:
            names = ", ".join(str(m.get("name")) for m in monitored_all.items) or "none"
            raise InvalidRequest(
                f"HA pair {ha.get('name')!r} has no monitored interface {interface!r} (have: {names}). "
                "Only named data interfaces are listed."
            )
        blockers: list[str] = []
        changes: dict[str, Any] = {}
        new_mon = editable(mon)
        if monitored is not None and monitored != mon.get("monitorForFailures"):
            new_mon["monitorForFailures"] = monitored
            changes["monitored"] = {"from": mon.get("monitorForFailures"), "to": monitored}
        v4 = dict(mon.get("ipv4Configuration") or {})
        if standby_ip is not None:
            want = None if standby_ip.strip().lower() == "none" else standby_ip.strip()
            if want is not None:
                try:
                    addr = ipaddress.IPv4Address(want)
                except ValueError:
                    raise InvalidRequest(f"standby_ip {standby_ip!r} is not an IPv4 address.") from None
                active, mask = v4.get("activeIPv4Address"), v4.get("activeIPv4Mask")
                if not active:
                    blockers.append(
                        f"Interface {interface!r} has no IPv4 address; set one first (fmc_update_interface)."
                    )
                elif str(addr) == active:
                    blockers.append(f"{addr} is the active unit's address.")
                elif mask:
                    net = ipaddress.IPv4Network(f"{active}/{mask}", strict=False)
                    if addr not in net:
                        blockers.append(f"{addr} is not in the interface network {net}.")
                want = str(addr)
            if want != v4.get("standbyIPv4Address"):
                if want is None:
                    v4.pop("standbyIPv4Address", None)
                else:
                    v4["standbyIPv4Address"] = want
                new_mon["ipv4Configuration"] = v4
                was = (mon.get("ipv4Configuration") or {}).get("standbyIPv4Address")
                changes["standby_ip"] = {"from": was, "to": want}
        macs = await app.all(f"{base}/failoverinterfacemacaddressconfigs")
        # MAC configs reference the physical interface ({id, type, name=Ethernet0/1}), not the
        # logical name, so resolve it and match on its id.
        phys = await _physical(app, ha, str(mon.get("name") or interface), domain)
        mac_cfg = next(
            (m for m in macs.items if phys and (m.get("physicalInterface") or {}).get("id") == phys["id"]),
            None,
        )
        mac_body: dict[str, Any] | None = None
        mac_method = None
        if amac is not None:
            have = mac_cfg and (mac_cfg.get("failoverActiveMac"), mac_cfg.get("failoverStandbyMac"))
            if have != (amac, smac):
                if amac == smac:
                    blockers.append("active_mac and standby_mac must differ.")
                if phys is None:
                    blockers.append(f"Couldn't find the physical interface behind {interface!r}.")
                mac_body = {
                    "type": "FailoverInterfaceMacAddressConfig",
                    "physicalInterface": phys,
                    "failoverActiveMac": amac,
                    "failoverStandbyMac": smac,
                }
                mac_method = "PUT" if mac_cfg else "POST"
                if mac_cfg:
                    mac_body["id"] = mac_cfg["id"]
                changes["mac"] = {
                    "from": _mac_row(mac_cfg) if mac_cfg else None,
                    "to": {"active_mac": amac, "standby_mac": smac},
                }
        elif clear_mac and mac_cfg:
            mac_method = "DELETE"
            changes["mac"] = {"from": _mac_row(mac_cfg), "to": None}
        if not changes:
            blockers.append("Nothing to change: the interface already has these settings.")
        mon_path = f"{base}/monitoredinterfaces/{mon['id']}"
        mac_path = f"{base}/failoverinterfacemacaddressconfigs"

        async def apply() -> Any:
            out: dict[str, Any] = {}
            try:
                return await _apply(out)
            except UpstreamError as e:
                done = ", ".join(k for k in out if k != "next") or "nothing"
                raise UpstreamError(f"{e} Already applied: {done}.", e.status_code) from e

        async def _apply(out: dict[str, Any]) -> Any:
            if "monitored" in changes or "standby_ip" in changes:
                out["monitored_interface"] = _monitored_row(
                    await applied(app, lambda: app.api.put(mon_path, new_mon))
                )
            if mac_method == "POST":
                out["mac"] = _mac_row(await applied(app, lambda: app.api.post(mac_path, mac_body)))
            elif mac_method == "PUT" and mac_cfg:
                out["mac"] = _mac_row(
                    await applied(app, lambda: app.api.put(f"{mac_path}/{mac_cfg['id']}", mac_body))
                )
            elif mac_method == "DELETE" and mac_cfg:
                await applied(app, lambda: app.api.delete(f"{mac_path}/{mac_cfg['id']}"))
                out["mac"] = None
            out["next"] = "Deploy the pair (fmc_deploy) and check fmc_run_show_command('show failover')."
            return out

        return await fmc_preview(
            ctx,
            tool="fmc_configure_ha_monitoring",
            args={
                "ha_pair": ha_pair,
                "interface": interface,
                "monitored": monitored,
                "standby_ip": standby_ip,
                "active_mac": active_mac,
                "standby_mac": standby_mac,
                "clear_mac": clear_mac,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Update HA interface {interface!r} on {ha.get('name')!r}",
                details={"changes": changes, "current": _monitored_row(mon)},
                fingerprint={"mon": editable(mon), "mac": mac_cfg and editable(mac_cfg)},
                blockers=blockers,
                side_effects=["Takes effect on both units after the next deployment of the HA pair."],
            ),
            apply=apply,
        )


async def _physical(
    app: FmcApp, ha: dict[str, Any], ifname: str, domain: str | None
) -> dict[str, Any] | None:
    """The {id, type, name} of the primary's physical interface with this logical name (or name)."""
    prim = (ha.get("primary") or {}).get("id")
    if not prim:
        return None
    rows = await app.all(await app.config_path(f"devices/devicerecords/{prim}/physicalinterfaces", domain))
    for i in rows.items:
        if ifname.lower() in {str(i.get("ifname", "")).lower(), str(i.get("name", "")).lower()}:
            return {"id": i["id"], "type": i.get("type", "PhysicalInterface"), "name": i.get("name")}
    return None

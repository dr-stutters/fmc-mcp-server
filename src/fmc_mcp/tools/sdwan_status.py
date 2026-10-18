"""Firewall SD-WAN health (F51c): per branch, the WAN links with their path metrics, the overlay tunnels,
which path each application route takes now and why, and a ranked list of degraded links.

Sources, all queried when called (ADR-003): the SD-WAN topology's endpoints, `health/tunnelstatuses`,
`health/pathmonitoredinterfaces` (status and monitoring settings per interface), each device's
`routing/policybasedroutes` (the app routes), and on the device through FMC: `show path-monitoring`
(RTT, jitter, loss, MOS), `show policy-route`, `show bgp summary` (or `show route bgp`) and `show crypto
ikev2 stats` (authentication failures vs retransmits: a wrong pre-shared key vs a dead path).

FMC 10.0.1 refuses `show path-monitoring`, `show policy-route`, `show bgp summary` and `show bgp
neighbors` through operational/commands (400 "Either command is not supported or entered command is an
invalid command"); `show route bgp`, `show crypto ikev2 sa` and `show crypto ikev2 stats` work. A
command FMC refuses is tried once per call and then reported as "not available" for every device.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
import time
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import InvalidRequest, NotFound, ToolRegistrar, UpstreamError, get_client, object_result
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, ref_label
from fmc_mcp.tools.devices import DEVICES, HA_PAIRS
from fmc_mcp.tools.troubleshoot import redact, run_show, tunnel_row
from fmc_mcp.tools.vpn import S2S, _peer_device, resolve_topology

# Thresholds for a degraded WAN link: (warning, critical). MOS is "lower is worse".
THRESHOLDS = {"loss_pct": (1.0, 5.0), "rtt_ms": (150.0, 300.0), "jitter_ms": (30.0, 50.0)}
MOS_LIMITS = (3.6, 3.1)
COMMANDS = ("show path-monitoring", "show policy-route", "show bgp summary", "show crypto ikev2 stats")
ROUTE_BGP = "show route bgp"  # the fallback when FMC refuses show bgp summary
DOWN = {"OFFLINE", "DOWN", "TUNNEL_DOWN"}
NOT_AVAILABLE = "not available"
SEVERITY = {"critical": 0, "warning": 1, "ok": 2, "unknown": 3, NOT_AVAILABLE: 3}
# FMC's answer to a show command it doesn't pass through (FMC 10.0.1, HTTP 400).
REFUSED = re.compile(r"not supported|invalid command|command is invalid", re.I)
FMC_TUNNEL_LAG = (
    "Tunnel states come from FMC's tunnel monitor, which lagged the devices by 2-3 minutes on FMC "
    "10.0.1 (a hub down still showed every tunnel UP a minute later); 'last_change' says when FMC last "
    "saw a change, and fmc_run_show_command('show crypto ikev2 sa') on the device is current."
)
NO_PATH_METRICS = (
    "Path metrics are not available: FMC refused 'show path-monitoring', so a brownout (loss, delay, "
    "jitter, low MOS) on a link that is still up can't be seen here; wan_links show the path-monitoring "
    "status only. Check on the device console (show path-monitoring) for the numbers."
)

_METRICS = {
    "rtt_ms": re.compile(r"(?:\bRTT|\bDelay|round[- ]trip)[^0-9\n]{0,24}?([\d.]+)", re.I),
    "jitter_ms": re.compile(r"\bJitter[^0-9\n]{0,24}?([\d.]+)", re.I),
    "loss_pct": re.compile(r"\b(?:Loss|Lost)[^0-9\n]{0,24}?([\d.]+)", re.I),
    "mos": re.compile(r"\bMOS[^0-9\n]{0,24}?([\d.]+)", re.I),
}
_IFACE = re.compile(r"^\s*Interface\s*[:=]?\s*([\w./-]+)", re.I | re.M)


def parse_path_monitoring(text: str) -> dict[str, dict[str, float]]:
    """`show path-monitoring` -> {interface logical name (lower case): {rtt_ms, jitter_ms, loss_pct, mos}}.

    One block per "Interface: <name>" line; the metrics are read wherever they appear in the block
    (FTD prints them as 'Average Delay(ms): 23.5 Average Jitter(ms): 2.1 Average Loss(%): 0 Average MOS:
    4.41' and similar), so small format changes between releases don't lose them."""
    out: dict[str, dict[str, float]] = {}
    starts = list(_IFACE.finditer(text))
    for n, m in enumerate(starts):
        block = text[m.end() : starts[n + 1].start() if n + 1 < len(starts) else len(text)]
        vals: dict[str, float] = {}
        for key, rx in _METRICS.items():
            hit = rx.search(block)
            if hit:
                try:
                    vals[key] = float(hit.group(1).rstrip("."))
                except ValueError:
                    continue
        out[m.group(1).rstrip(",").lower()] = vals
    return out


def parse_bgp_summary(text: str) -> list[dict[str, Any]]:
    """Neighbor rows of `show bgp summary`: address, AS, up/down time and state (or prefixes received)."""
    rows: list[dict[str, Any]] = []
    started = False
    for line in text.splitlines():
        if re.match(r"^\s*Neighbor\s+V\s+AS", line):
            started = True
            continue
        if not started or not line.strip():
            continue
        f = line.split()
        if len(f) < 9 or not re.match(r"^[\d.:a-fA-F]+$", f[0]):
            continue
        last = f[-1]
        row: dict[str, Any] = {"neighbor": f[0], "as": f[2], "up_down": f[-2]}
        if last.isdigit():
            row |= {"state": "Established", "prefixes": int(last)}
        else:
            row["state"] = last
        rows.append(row)
    return rows


_IKE_COUNTERS = {
    "active_tunnels": "Active Tunnels",
    "authentication_failures": "Authentication Failures",
    "auth_exchange_failed": "Auth exchange failed",
    "initial_exchange_failed": "Initial exchange failed",
    "retransmit_limit_exceeded": "Retransmit limit exceeded",
    "sas_locally_initiated_failed": "SAs Locally Initiated Failed",
}


def parse_ikev2_stats(text: str) -> dict[str, Any]:
    """The counters of `show crypto ikev2 stats` that separate a key mismatch from a dead path."""
    out: dict[str, Any] = {}
    for key, label in _IKE_COUNTERS.items():
        m = re.search(rf"^\s*{re.escape(label)}:\s*(\d+)\s*$", text, re.M)
        if m:
            out[key] = int(m.group(1))
    m = re.search(r"^\s*Last clear(?:ing time|ed):\s*(.+?)\s*$", text, re.M)
    if m:
        out["counters_since"] = "never cleared" if m.group(1).lower() == "never" else m.group(1)
    return out


def parse_route_bgp(text: str) -> list[dict[str, str]]:
    """BGP routes of `show route bgp`: 'B  10.20.1.0 255.255.255.0 [200/0] via 10.255.20.1, 00:10:00'."""
    rows = []
    for m in re.finditer(r"^\s*B\S*\s+(\d[\d.]+)\s+(\d[\d.]+)\s+\[[\d/]+\]\s+via\s+([\d.]+)", text, re.M):
        rows.append({"prefix": f"{m.group(1)}/{m.group(2)}", "via": m.group(3)})
    return rows


# Last IKEv2 counters seen per device record id: (monotonic time, counters), for growth between calls.
_IKE_SEEN: dict[str, tuple[float, dict[str, Any]]] = {}


def ike_growth(device_id: str, now: dict[str, Any]) -> dict[str, Any] | None:
    """How the IKEv2 failure counters grew since the previous fmc_sdwan_status call (None the first
    time, or when the counters were cleared in between)."""
    before = _IKE_SEEN.get(device_id)
    _IKE_SEEN[device_id] = (time.monotonic(), now)
    if before is None:
        return None
    then, old = before
    keys = ("authentication_failures", "retransmit_limit_exceeded", "initial_exchange_failed")
    if any(now.get(k, 0) < old.get(k, 0) for k in keys):
        return None
    return {"seconds": round(time.monotonic() - then)} | {k: now.get(k, 0) - old.get(k, 0) for k in keys}


def tunnel_down_cause(ike: dict[str, Any] | None) -> str | None:
    """What the IKEv2 counters say about a down tunnel: a key mismatch or a peer that doesn't answer."""
    if not ike:
        return None
    grew = ike.get("since_last_check")
    if grew:
        if grew["authentication_failures"] > 0:
            return (
                f"IKEv2 authentication failures rose by {grew['authentication_failures']} in the last "
                f"{grew['seconds']} s: a pre-shared key (or certificate) mismatch, not a dead path"
            )
        if grew["retransmit_limit_exceeded"] > 0 or grew["initial_exchange_failed"] > 0:
            return (
                "IKEv2 exchanges time out with no authentication failures: the peer doesn't answer "
                "(dead WAN path or UDP 500/4500 blocked)"
            )
        return f"no IKEv2 failures in the last {grew['seconds']} s"
    return (
        f"IKEv2 counters ({ike.get('counters_since', 'since the last clear')}): "
        f"Authentication Failures {ike.get('authentication_failures', '?')}, Retransmit limit exceeded "
        f"{ike.get('retransmit_limit_exceeded', '?')}. Call fmc_sdwan_status again: authentication failures "
        "growing means a key mismatch, retransmits growing alone means the peer doesn't answer"
    )


def _ordering(action: dict[str, Any]) -> str:
    t = str(action.get("forwardingActionType") or "").upper()
    for key, word in (
        ("jitter", "JITTER"),
        ("loss", "LOST"),
        ("loss", "LOSS"),
        ("rtt", "RTT"),
        ("mos", "MOS"),
        ("priority", "PRIORITY"),
        ("order", "ORDER"),
    ):
        if word in t:
            return key
    return t.lower() or "next hop"


METRIC_OF = {"jitter": "jitter_ms", "loss": "loss_pct", "rtt": "rtt_ms", "mos": "mos"}


def link_severity(link: dict[str, Any]) -> tuple[str, list[str]]:
    """critical / warning / ok / unknown for one WAN link, with the reasons."""
    reasons: list[str] = []
    level = "ok"

    def bump(to: str, why: str) -> None:
        nonlocal level
        reasons.append(why)
        if SEVERITY[to] < SEVERITY[level]:
            level = to

    status = str(link.get("status") or "").upper()
    if status in DOWN:
        bump("critical", f"path monitoring reports {status}")
    elif status == "IDLE":
        bump("warning", "path monitoring is IDLE (no probe answers)")
    for key, (warn, crit) in THRESHOLDS.items():
        v = link.get(key)
        if v is None:
            continue
        if v >= crit:
            bump("critical", f"{key} {v:g} >= {crit:g}")
        elif v >= warn:
            bump("warning", f"{key} {v:g} >= {warn:g}")
    mos = link.get("mos")
    if mos is not None:
        if mos <= MOS_LIMITS[1]:
            bump("critical", f"MOS {mos:g} <= {MOS_LIMITS[1]:g}")
        elif mos <= MOS_LIMITS[0]:
            bump("warning", f"MOS {mos:g} <= {MOS_LIMITS[0]:g}")
    if level == "ok" and not status and all(link.get(k) is None for k in (*THRESHOLDS, "mos")):
        level = "unknown"
    return level, reasons


def choose_path(
    ordering: str, egress: list[dict[str, Any]], links: dict[str, dict[str, Any]]
) -> tuple[str | None, str]:
    """The interface an app route sends traffic to now, from FMC's ordering and the live link state."""
    cands = []
    for pos, e in enumerate(egress):
        key = str(e.get("ifname") or e.get("name") or "").lower()
        link = links.get(key) or links.get(str(e.get("id"))) or {}
        cands.append((pos, ref_label(e) if not e.get("ifname") else str(e["ifname"]), link))
    usable = [c for c in cands if str(c[2].get("status") or "").upper() not in DOWN]
    down = [c[1] for c in cands if c not in usable]
    note = f" ({', '.join(down)} down)" if down else ""
    if not usable:
        return None, "every egress interface is down: traffic falls back to the routing table"
    if ordering == "priority":

        def prio(c: tuple[int, str, dict[str, Any]]) -> tuple[int, int]:
            p = c[2].get("priority")
            return (int(p) if isinstance(p, int) else 1 << 30, c[0])

        best = min(usable, key=prio)
        return best[1], f"lowest interface priority ({best[2].get('priority', 'not set')}){note}"
    if ordering in METRIC_OF:
        key = METRIC_OF[ordering]
        measured = [c for c in usable if c[2].get(key) is not None]
        if not measured:
            return usable[0][1], f"no {key} measurement: first usable interface in order{note}"
        best = (max if ordering == "mos" else min)(measured, key=lambda c: c[2][key])
        others = ", ".join(f"{c[1]} {c[2][key]:g}" for c in measured if c is not best)
        return best[1], f"best {key} {best[2][key]:g}" + (f" (vs {others})" if others else "") + note
    return usable[0][1], f"first usable interface in configured order{note}"


async def _device_record(app: FmcApp, dev: dict[str, Any], domain: str | None) -> str:
    """The device record a show command runs on: the device, or an HA pair's primary unit."""
    if dev.get("type") != "DeviceHAPair":
        return str(dev["id"])
    pair = await app.api.get(f"{await app.config_path(HA_PAIRS, domain)}/{dev['id']}")
    return str(((pair or {}).get("primary") or {}).get("id") or dev["id"])


def _role(e: dict[str, Any]) -> str:
    if e.get("peerType") == "HUB":
        return "hub" if e.get("isPrimaryHub", True) else "backup hub"
    return "spoke" if e.get("peerType") == "SPOKE" else str(e.get("peerType") or "peer").lower()


def _monitoring(mon: dict[str, Any]) -> str | None:
    if not mon.get("enable"):
        return None
    kind = str(mon.get("type") or "on")
    return f"{kind} {mon['monitoredIp']}" if mon.get("monitoredIp") else kind


def wan_links(endpoint: dict[str, Any], monitored: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """WAN links of one endpoint keyed by logical name (lower case) and by interface id: the path-monitored
    interfaces FMC reports for the device, plus a spoke's WAN and backup WAN interfaces."""
    links: dict[str, dict[str, Any]] = {}
    for item in monitored:
        i = item.get("interface") or {}
        link = {
            "interface": i.get("name"),
            "logical_name": i.get("ifname"),
            "status": item.get("status"),
            "priority": i.get("priority"),
            "monitoring": _monitoring(i.get("pathMonitoring") or {}),
            "id": i.get("id"),
        }
        links[str(i.get("ifname") or i.get("name") or "").lower()] = link
        links.setdefault(str(i.get("id")), link)
    if endpoint.get("peerType") == "SPOKE":
        wans = [endpoint.get("interface")] + [
            b.get("interface") for b in endpoint.get("backupInterfaces") or []
        ]
        for w in wans:
            if w and str(w.get("id")) not in links:
                link = {"interface": w.get("name"), "status": None, "id": w.get("id")}
                links[str(w.get("name") or "").lower()] = link
                links[str(w.get("id"))] = link
    return links


def _finding(severity: str, device: str, what: str, reason: str, topology: Any) -> dict[str, Any]:
    return {
        "severity": severity,
        "device": device,
        "interface": what,
        "reasons": [reason],
        "topology": topology,
    }


def _own_side(tunnel: dict[str, Any], device: str) -> dict[str, Any]:
    """This device's end (peerA or peerB) of a health/tunnelstatuses row."""
    for k in ("peerA", "peerB"):
        p = tunnel.get(k) or {}
        if (p.get("device") or {}).get("name") == device:
            return p
    return {}


def egress_links(
    links: dict[str, dict[str, Any]], egress: list[dict[str, Any]], own: list[dict[str, Any]], device: str
) -> dict[str, dict[str, Any]]:
    """`links` plus a status for egress tunnel interfaces (VTIs), which path monitoring doesn't list: the
    state of the tunnel on that interface, or TUNNEL_DOWN for a VTI when every tunnel of the device is
    down. Without it an app route's path_now stays on a tunnel that is down."""
    states: dict[str, list[str]] = {}
    for t in own:
        side = (_own_side(t, device).get("interface") or {}).get("name")
        if side:
            states.setdefault(str(side).lower(), []).append(str(t.get("state")))
    all_down = bool(own) and all(str(t.get("state")) != "TUNNEL_UP" for t in own)
    out = dict(links)
    for e in egress:
        key = str(e.get("ifname") or e.get("name") or "").lower()
        if not key or key in links or str(e.get("id")) in links:
            continue
        seen = states.get(key) or states.get(str(e.get("name") or "").lower())
        if seen:
            status = "TUNNEL_UP" if "TUNNEL_UP" in seen else "TUNNEL_DOWN"
        elif str(e.get("type")) == "VTIInterface" and all_down:
            status = "TUNNEL_DOWN"
        else:
            continue
        out[key] = {"logical_name": key, "status": status}
    return out


async def branch_status(
    app: FmcApp,
    endpoint: dict[str, Any],
    topology: dict[str, Any],
    tunnels: list[dict[str, Any]],
    monitored: list[dict[str, Any]],
    commands: bool,
    domain: str | None,
    refused: dict[str, str] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """One branch (or hub): its row and its degraded-link findings. `refused` collects the show
    commands FMC doesn't pass through, so the next devices don't ask again."""
    refused = {} if refused is None else refused
    dev = endpoint.get("device") or {}
    name = str(dev.get("name") or endpoint.get("name"))
    tname = topology.get("name")
    links = wan_links(endpoint, monitored)
    notes: list[str] = []
    evidence: dict[str, Any] = {}
    bgp: list[dict[str, Any]] | None = None
    bgp_routes: list[dict[str, str]] | None = None
    ike: dict[str, Any] | None = None
    metrics = False
    findings: list[dict[str, Any]] = []
    rec = await _device_record(app, dev, domain)
    try:
        path = await app.config_path(f"{DEVICES}/{rec}/routing/policybasedroutes", domain)
        pbr = (await app.all(path, cap=500)).items
    except (NotFound, UpstreamError) as err:
        pbr = []
        notes.append(f"app routes not read: {err}")

    async def show(cmd: str) -> str | None:
        if cmd in refused:
            evidence[cmd] = f"{NOT_AVAILABLE}: {refused[cmd]}"
            return None
        try:
            text, _ = redact(await run_show(app, rec, cmd, domain))
        except (InvalidRequest, NotFound, UpstreamError) as err:
            if REFUSED.search(str(err)):
                refused[cmd] = "FMC doesn't pass this command through (not supported)"
            evidence[cmd] = f"{NOT_AVAILABLE}: {err}"
            return None
        evidence[cmd] = [ln for ln in text.splitlines() if ln.strip()][:40]
        return text

    if commands:
        for cmd in COMMANDS:
            text = await show(cmd)
            if text is None:
                continue
            if cmd == "show path-monitoring":
                metrics = True
                for ifname, vals in parse_path_monitoring(text).items():
                    links.setdefault(ifname, {"logical_name": ifname, "status": None}).update(vals)
            elif cmd == "show bgp summary":
                bgp = parse_bgp_summary(text)
            elif cmd == "show crypto ikev2 stats":
                ike = parse_ikev2_stats(text) or None
                if ike:
                    grew = ike_growth(rec, ike)
                    if grew:
                        ike["since_last_check"] = grew
                evidence[cmd] = [
                    ln for ln in evidence[cmd] if re.search(r"Tunnels|Failure|failed|exceeded|clear", ln)
                ]
        if bgp is None and (text := await show(ROUTE_BGP)) is not None:
            bgp_routes = parse_route_bgp(text)
    peers = ("peerA", "peerB")
    raw_own = [
        x for x in tunnels if name in {((x.get(k) or {}).get("device") or {}).get("name") for k in peers}
    ]
    own = [tunnel_row(x) for x in raw_own]
    routes = []
    for p in pbr:
        ingress = [ref_label(i) for i in p.get("ingressInterfaces") or []]
        for a in p.get("forwardingActions") or []:
            ordering = _ordering(a)
            egress = a.get("egressInterfaces") or []
            chosen, why = choose_path(ordering, egress, egress_links(links, egress, raw_own, name))
            match = a.get("matchCriteria")
            routes.append(
                {
                    # FMC 10 policy-based routes have no name; fmc_create_app_route names the ACL
                    "name": p.get("name") or (ref_label(match) if match else None),
                    "ingress": ingress,
                    "match": ref_label(match) if match else None,
                    "ordering": ordering,
                    "egress": [str(x.get("ifname") or ref_label(x)) for x in egress],
                    "path_now": chosen,
                    "why": why,
                }
            )
    wan = []
    seen: set[int] = set()
    for link in links.values():
        if id(link) in seen:
            continue
        seen.add(id(link))
        level, reasons = link_severity(link)
        measured = any(link.get(k) is not None for k in (*THRESHOLDS, "mos"))
        if commands and not metrics and not measured and level in ("ok", "unknown"):
            level = NOT_AVAILABLE
            reasons = [
                "no path metrics through FMC (show path-monitoring not available); path-monitoring "
                f"status {link.get('status') or 'not reported'}"
            ]
        row = {k: v for k, v in link.items() if v is not None and k != "id"}
        row["health"] = level
        if reasons:
            row["reasons"] = reasons
        wan.append(row)
        if level in ("critical", "warning"):
            label = str(link.get("logical_name") or link.get("interface"))
            findings.append({**_finding(level, name, label, "", tname), "reasons": reasons})
    cause = tunnel_down_cause(ike)
    for x in own:
        if str(x.get("state")) != "TUNNEL_UP":
            level = "critical" if x.get("state") == "TUNNEL_DOWN" else "warning"
            why = f"{x.get('peer_a')} <-> {x.get('peer_b')}: {x.get('state')}"
            if x.get("message"):
                why += f" ({x['message']})"
            f = _finding(level, name, "overlay tunnel", why, tname)
            if cause:
                f["reasons"].append(f"{name}: {cause}")
            findings.append({**f, "_tunnel": x.get("id")})
    up = sum(1 for x in own if x.get("state") == "TUNNEL_UP")
    if ike and isinstance(ike.get("active_tunnels"), int) and ike["active_tunnels"] < up:
        why = (
            f"FMC shows {up} tunnel(s) up but the device has {ike['active_tunnels']} active IKEv2 "
            "tunnel(s): FMC's tunnel monitor lags the device"
        )
        findings.append(_finding("warning", name, "overlay tunnel", why, tname))
    for nb in bgp or []:
        if nb.get("state") != "Established":
            why = f"neighbor {nb['neighbor']} is {nb.get('state')}"
            findings.append(_finding("critical", name, "iBGP overlay", why, tname))
    out: dict[str, Any] = {
        "device": name,
        "role": _role(endpoint),
        "wan_links": sorted(wan, key=lambda r: (SEVERITY[r["health"]], str(r.get("logical_name")))),
        "tunnels": own,
        "tunnels_up": up,
        "bgp_neighbors": bgp,
        "bgp_routes": bgp_routes,
        "ikev2": ike,
        "app_routes": routes or None,
        "evidence": evidence or None,
        "notes": notes or None,
    }
    return {k: v for k, v in out.items() if v is not None}, findings


def rank(findings: list[dict[str, Any]], branches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per down tunnel (it is reported from both ends; the first, a spoke, is kept) and one
    rolled-up critical entry per hub whose tunnels are all down."""
    out: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for f in findings:
        tid = f.pop("_tunnel", None)
        if tid is not None:
            if tid in seen:
                continue
            seen.add(tid)
        out.append(f)
    for b in branches:
        n = len(b.get("tunnels") or [])
        if "hub" in str(b.get("role")) and n and not b.get("tunnels_up"):
            topo = (b["tunnels"][0] or {}).get("topology")
            why = (
                f"all {n} tunnel(s) of {b['role']} {b['device']} are down: the hub, its WAN link or its "
                "path to the spokes is down (a single spoke's fault takes down only its own tunnel)"
            )
            out.append(_finding("critical", b["device"], "hub", why, topo))
    return out


def _is_sdwan(t: dict[str, Any]) -> bool:
    return str(t.get("topologyType")) == "AUTO_VPN" or bool(t.get("autoVpnSettings"))


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="SD-WAN status")
    async def fmc_sdwan_status(
        ctx: Context,
        topology: Annotated[
            str | None, Field(description="SD-WAN topology (name/UUID); default every SD-WAN topology")
        ] = None,
        branch: Annotated[str | None, Field(description="Only this branch or hub device (name/UUID)")] = None,
        show_commands: Annotated[
            bool,
            Field(
                description="Also run show path-monitoring, show policy-route, show bgp summary (or show "
                "route bgp) and show crypto ikev2 stats on the devices (path metrics, live app-route, "
                "BGP and IKE state); commands FMC refuses are reported as not available"
            ),
        ] = True,
        max_devices: Annotated[
            int, Field(ge=1, le=20, description="Run show commands on at most this many devices")
        ] = 6,
        domain: Domain = None,
    ) -> Any:
        """SD-WAN health per branch: the WAN links (path-monitoring status and settings, RTT, jitter,
        loss and MOS from 'show path-monitoring'), the overlay tunnels and iBGP neighbors, every
        application route (policy-based route) with the interface it uses now and why (the configured
        ordering against the live metrics, with 'show policy-route' as evidence), and one ranked list
        of degraded links (down, lossy, slow, jittery or low MOS; a hub whose tunnels are all down is
        one entry). For a down tunnel the IKEv2 counters tell a pre-shared key mismatch (authentication
        failures growing between two calls) from a dead path (retransmits only). FMC 10.0.1 refuses
        show path-monitoring, so path metrics are then 'not available' and a brownout can't be seen
        through FMC. Read-only; queried when called. Show commands cost one FMC request per device
        each (a refused command is tried once per call); limit them with branch or max_devices."""
        app: FmcApp = get_client(ctx)
        if topology:
            t = await resolve_topology(app, topology, domain)
            if not _is_sdwan(t):
                raise InvalidRequest(
                    f"{t.get('name')!r} is not an SD-WAN topology ({t.get('topologyType')})."
                )
            topos = [t]
        else:
            topos = [
                t for t in (await app.all(await app.config_path(S2S, domain), cap=2000)).items if _is_sdwan(t)
            ]
        if not topos:
            note = "No SD-WAN topologies (fmc_create_sdwan_topology builds one)."
            return object_result({"topologies": [], "note": note}, shape=False)
        want: dict[str, Any] | None = None
        if branch:
            want, _ = await _peer_device(app, branch, domain)
        pm_note = None
        try:
            pm_path = await app.config_path("health/pathmonitoredinterfaces", domain)
            pm_items = (await app.all(pm_path, cap=2000)).items
        except (NotFound, UpstreamError) as err:
            pm_items, pm_note = [], f"health/pathmonitoredinterfaces: {err}"
        pm_by_dev: dict[str, list[dict[str, Any]]] = {}
        for p in pm_items:
            pm_by_dev.setdefault(str((p.get("device") or {}).get("id")), []).extend(p.get("interfaces") or [])
        budget = max_devices
        refused: dict[str, str] = {}
        out_topos: list[dict[str, Any]] = []
        ranked: list[dict[str, Any]] = []
        skipped: list[str] = []
        for t in topos:
            base = await app.config_path(f"{S2S}/{t['id']}", domain)
            eps = (await app.all(f"{base}/endpoints", cap=2000)).items
            if want:
                eps = [ep for ep in eps if (ep.get("device") or {}).get("id") == want["id"]]
                if not eps:
                    continue
            tpath = await app.config_path("health/tunnelstatuses", domain)
            tunnels = (await app.all(tpath, {"filter": f"vpnTopologyId:{t['id']}"}, cap=5000)).items
            tunnels = [x for x in tunnels if (x.get("vpnTopology") or {}).get("id") in (None, t["id"])]
            branches = []
            found_here: list[dict[str, Any]] = []
            # spokes first: they are what "a branch" means, and they get the show-command budget first
            for ep in sorted(eps, key=lambda x: x.get("peerType") != "SPOKE"):
                run = show_commands and budget > 0
                budget -= 1 if run else 0
                if show_commands and not run:
                    skipped.append(str((ep.get("device") or {}).get("name")))
                monitored = pm_by_dev.get(str((ep.get("device") or {}).get("id")), [])
                row, found = await branch_status(app, ep, t, tunnels, monitored, run, domain, refused)
                branches.append(row)
                found_here += found
            ranked += rank(found_here, branches)
            out_topos.append({"topology": t.get("name"), "id": t.get("id"), "branches": branches})
        if want and not any(t["branches"] for t in out_topos):
            raise NotFound(f"{want['name']} is in no SD-WAN topology.", 404)
        ranked.sort(key=lambda r: (SEVERITY[r["severity"]], r["device"], str(r["interface"])))
        result: dict[str, Any] = {
            "topologies": out_topos,
            "degraded": ranked,
            "summary": {
                "critical": sum(1 for r in ranked if r["severity"] == "critical"),
                "warning": sum(1 for r in ranked if r["severity"] == "warning"),
                "branches": sum(len(t["branches"]) for t in out_topos),
            },
            "thresholds": {
                **{k: {"warning": w, "critical": c} for k, (w, c) in THRESHOLDS.items()},
                "mos": {"warning": MOS_LIMITS[0], "critical": MOS_LIMITS[1]},
            },
        }
        notes = [pm_note] if pm_note else []
        if "show path-monitoring" in refused:
            notes.append(NO_PATH_METRICS)
        if any(r["interface"] in ("overlay tunnel", "hub") for r in ranked):
            notes.append(FMC_TUNNEL_LAG)
        if skipped:
            notes.append(
                f"Show commands skipped on {', '.join(skipped)} (max_devices={max_devices}): no path metrics "
                "or BGP state for them; pass branch=<name>."
            )
        if notes:
            result["notes"] = notes
        return object_result(result, shape=False)

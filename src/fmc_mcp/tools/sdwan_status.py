"""Firewall SD-WAN health (F51c): per branch, the WAN links with their path metrics, the overlay tunnels,
which path each application route takes now and why, and a ranked list of degraded links.

Sources, all queried when called (ADR-003): the SD-WAN topology's endpoints, `health/tunnelstatuses`,
`health/pathmonitoredinterfaces` (status and monitoring settings per interface), each device's
`routing/policybasedroutes` (the app routes), and on the device through FMC: `show path-monitoring`
(RTT, jitter, loss, MOS), `show policy-route` and `show bgp summary`.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
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
COMMANDS = ("show path-monitoring", "show policy-route", "show bgp summary")
DOWN = {"OFFLINE", "DOWN", "TUNNEL_DOWN"}
SEVERITY = {"critical": 0, "warning": 1, "ok": 2, "unknown": 3}

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


async def branch_status(
    app: FmcApp,
    endpoint: dict[str, Any],
    topology: dict[str, Any],
    tunnels: list[dict[str, Any]],
    monitored: list[dict[str, Any]],
    commands: bool,
    domain: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """One branch (or hub): its row and its degraded-link findings."""
    dev = endpoint.get("device") or {}
    name = str(dev.get("name") or endpoint.get("name"))
    tname = topology.get("name")
    links = wan_links(endpoint, monitored)
    notes: list[str] = []
    evidence: dict[str, Any] = {}
    bgp: list[dict[str, Any]] | None = None
    findings: list[dict[str, Any]] = []
    rec = await _device_record(app, dev, domain)
    try:
        path = await app.config_path(f"{DEVICES}/{rec}/routing/policybasedroutes", domain)
        pbr = (await app.all(path, cap=500)).items
    except (NotFound, UpstreamError) as err:
        pbr = []
        notes.append(f"app routes not read: {err}")
    if commands:
        for cmd in COMMANDS:
            try:
                text, _ = redact(await run_show(app, rec, cmd, domain))
            except (InvalidRequest, NotFound, UpstreamError) as err:
                evidence[cmd] = f"not available: {err}"
                continue
            evidence[cmd] = [ln for ln in text.splitlines() if ln.strip()][:40]
            if cmd == "show path-monitoring":
                for ifname, vals in parse_path_monitoring(text).items():
                    links.setdefault(ifname, {"logical_name": ifname, "status": None}).update(vals)
            elif cmd == "show bgp summary":
                bgp = parse_bgp_summary(text)
    routes = []
    for p in pbr:
        ingress = [ref_label(i) for i in p.get("ingressInterfaces") or []]
        for a in p.get("forwardingActions") or []:
            ordering = _ordering(a)
            egress = a.get("egressInterfaces") or []
            chosen, why = choose_path(ordering, egress, links)
            match = a.get("matchCriteria")
            routes.append(
                {
                    "name": p.get("name"),
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
        row = {k: v for k, v in link.items() if v is not None and k != "id"}
        row["health"] = level
        if reasons:
            row["reasons"] = reasons
        wan.append(row)
        if level in ("critical", "warning"):
            label = str(link.get("logical_name") or link.get("interface"))
            findings.append({**_finding(level, name, label, "", tname), "reasons": reasons})
    peers = ("peerA", "peerB")
    own = [
        tunnel_row(x)
        for x in tunnels
        if name in {((x.get(k) or {}).get("device") or {}).get("name") for k in peers}
    ]
    for x in own:
        if str(x.get("state")) != "TUNNEL_UP":
            level = "critical" if x.get("state") == "TUNNEL_DOWN" else "warning"
            why = f"{x.get('peer_a')} <-> {x.get('peer_b')}: {x.get('state')}"
            findings.append(_finding(level, name, "overlay tunnel", why, tname))
    for nb in bgp or []:
        if nb.get("state") != "Established":
            why = f"neighbor {nb['neighbor']} is {nb.get('state')}"
            findings.append(_finding("critical", name, "iBGP overlay", why, tname))
    out: dict[str, Any] = {
        "device": name,
        "role": _role(endpoint),
        "wan_links": sorted(wan, key=lambda r: (SEVERITY[r["health"]], str(r.get("logical_name")))),
        "tunnels": own,
        "tunnels_up": sum(1 for x in own if x.get("state") == "TUNNEL_UP"),
        "bgp_neighbors": bgp,
        "app_routes": routes or None,
        "evidence": evidence or None,
        "notes": notes or None,
    }
    return {k: v for k, v in out.items() if v is not None}, findings


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
                description="Also run show path-monitoring, show policy-route and show bgp summary on "
                "the devices (path metrics, live app-route and BGP state)"
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
        of degraded links (down, lossy, slow, jittery or low MOS). Read-only; queried when called.
        Show commands cost one FMC request per device each; limit them with branch or max_devices."""
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
            # spokes first: they are what "a branch" means, and they get the show-command budget first
            for ep in sorted(eps, key=lambda x: x.get("peerType") != "SPOKE"):
                run = show_commands and budget > 0
                budget -= 1 if run else 0
                if show_commands and not run:
                    skipped.append(str((ep.get("device") or {}).get("name")))
                monitored = pm_by_dev.get(str((ep.get("device") or {}).get("id")), [])
                row, found = await branch_status(app, ep, t, tunnels, monitored, run, domain)
                branches.append(row)
                ranked += found
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
        if skipped:
            notes.append(
                f"Show commands skipped on {', '.join(skipped)} (max_devices={max_devices}): no path metrics "
                "or BGP state for them; pass branch=<name>."
            )
        if notes:
            result["notes"] = notes
        return object_result(result, shape=False)

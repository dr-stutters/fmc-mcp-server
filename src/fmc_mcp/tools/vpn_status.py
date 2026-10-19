"""Site-to-site VPN status (F41): every S2S topology (policy-based, route-based VTI and SD-WAN) with its
endpoints, VTIs and tunnels, the tunnel state FMC monitors, what the devices themselves say, and the
routing over the tunnels, degraded tunnels first.

Sources, all queried when called (ADR-003): the topologies and their endpoints (policy/ftds2svpns),
`health/tunnelstatuses` (FMC's tunnel monitor: state, message, last change, each end's VPN and VTI
interface), optionally `health/tunnelstatuses/{id}/tunneldetails` (FMC runs show commands on both peers:
bytes, errors, authentication mode, SAs), the devices' VTIs (`virtualtunnelinterfaces`, to tell overlay
routes) and on each device through FMC's operational/commands:

- `show crypto ikev2 sa`: the IKE SAs (status, role, cipher, DH group, authentication, and their age:
  'Life/Active Time' is the lifetime and the seconds since the SA was set up or last rekeyed),
- `show crypto ipsec sa`: the child SAs (packets out and in, send/receive errors, seconds to the next
  rekey): encrypting without decrypting is a one-way tunnel,
- `show vpn-sessiondb l2l`: the LAN-to-LAN sessions (bytes, login time, duration),
- `show crypto ikev2 stats`: authentication failures vs retransmits (a key mismatch vs a dead path),
- `show route` (route-based topologies): the routes over the VTIs (static, BGP, OSPF, EIGRP), the
  overlay routing.

FMC 10.0.1 passes all five through (show crypto <option>, show vpn-sessiondb <option> and show route are in
its supported list); a command an FMC's spec doesn't list is not sent and is reported as not available.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import re
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import InvalidRequest, NotFound, ToolRegistrar, UpstreamError, get_client, object_result
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, ref_label
from fmc_mcp.tools.devices import DEVICES, HA_PAIRS
from fmc_mcp.tools.sdwan_status import (
    FMC_TUNNEL_LAG,
    NOT_AVAILABLE,
    SEVERITY,
    device_record,
    ha_findings,
    ha_units,
    ike_growth,
    is_me,
    parse_ikev2_stats,
    show_on_device,
    tunnel_down_cause,
)
from fmc_mcp.tools.show_commands import supported_commands
from fmc_mcp.tools.troubleshoot import tunnel_row
from fmc_mcp.tools.vpn import S2S, _kind, _peer_device, endpoint_row, resolve_topology

IKE_SA = "show crypto ikev2 sa"
IPSEC_SA = "show crypto ipsec sa"
L2L = "show vpn-sessiondb l2l"
IKE_STATS = "show crypto ikev2 stats"
ROUTES = "show route"
TUNNELS = "health/tunnelstatuses"
TUNNEL_ORDER = {"TUNNEL_DOWN": 0, "UNKNOWN": 1, "TUNNEL_UP": 2}
EVIDENCE_LINES = 15
PROTOCOLS = {"B": "bgp", "O": "ospf", "D": "eigrp", "S": "static", "V": "vpn", "R": "rip", "I": "isis"}

# --- show crypto ikev2 sa ------------------------------------------------------------------------------
_IKE_SESSION = re.compile(
    r"Session-id:\s*(\d+),\s*Status:\s*([\w-]+)(?:,\s*IKE count:\s*(\d+),\s*CHILD count:\s*(\d+))?", re.I
)
_IP = r"[\da-fA-F.:]+"
_IKE_TUNNEL = re.compile(
    rf"^\s*(\d+)\s+({_IP})/(\d+)\s+({_IP})/(\d+)\s+(?:(\S+/\S+)\s+)?([A-Z][A-Z_-]+)\s+(INITIATOR|RESPONDER)\b"
)
_IKE_ENCR = re.compile(
    r"Encr:\s*([^,]+),\s*keysize:\s*(\d+),\s*Hash:\s*([^,]+),\s*DH Grp:\s*(\d+),\s*Auth sign:\s*(\S+?),"
    r"\s*Auth verify:\s*(\S+)",
    re.I,
)
_IKE_LIFE = re.compile(r"Life/Active Time:\s*(\d+)/(\d+)\s*sec", re.I)


def parse_ikev2_sa(text: str) -> list[dict[str, Any]]:
    """`show crypto ikev2 sa` -> one row per IKE SA: local and remote address, state (READY, IN-NEG, ...),
    role, the session's status, cipher, DH group, authentication, lifetime and age in seconds (the time
    since the SA came up or was last rekeyed), and the number of child SAs. Empty for 'There are no
    IKEv2 SAs'."""
    rows: list[dict[str, Any]] = []
    session: dict[str, Any] = {}
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        if m := _IKE_SESSION.search(line):
            session = {"session": int(m.group(1)), "session_status": m.group(2)}
            if m.group(4) is not None:
                session["child_sas"] = int(m.group(4))
            current = None
        elif m := _IKE_TUNNEL.match(line):
            current = {
                **session,
                "local": m.group(2),
                "remote": m.group(4),
                "remote_port": int(m.group(5)),
                "state": m.group(7),
                "role": m.group(8).lower(),
            }
            if m.group(6) and m.group(6) != "Global/Global":
                current["vrf"] = m.group(6)
            rows.append(current)
        elif current is not None and (m := _IKE_ENCR.search(line)):
            current["encryption"] = f"{m.group(1).strip()}-{m.group(2)}"
            if m.group(3).strip().upper() not in ("N/A", "NONE"):
                current["hash"] = m.group(3).strip()
            current["dh_group"] = int(m.group(4))
            sign, verify = m.group(5), m.group(6)
            current["auth"] = sign if sign == verify else f"{sign}/{verify}"
        elif current is not None and (m := _IKE_LIFE.search(line)):
            current["lifetime_s"] = int(m.group(1))
            current["age_s"] = int(m.group(2))
    return rows


# --- show crypto ipsec sa ------------------------------------------------------------------------------
_IDENT = re.compile(r"(local|remote) ident \(addr/mask/prot/port\):\s*\(([^/]+)/([^/]+)/(\d+)/(\d+)\)")
_COUNTER = re.compile(r"#(pkts encaps|pkts decaps|send errors|recv errors):\s*(\d+)")
# 'remaining key lifetime (kB/sec): (4373999/28215)'; the secret redaction masks the word after "key"
_LIFETIME = re.compile(r"remaining key \S+ \((?:kB/sec|sec)\):\s*\((?:(\d+)/)?(\d+)\)")


def _ident(addr: str, mask: str) -> str:
    try:
        net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
    except ValueError:
        return f"{addr}/{mask}"
    return "any" if net.prefixlen == 0 else str(net)


def parse_ipsec_sa(text: str) -> list[dict[str, Any]]:
    """`show crypto ipsec sa` -> one row per child SA: interface (the outside interface, or the VTI for a
    route-based tunnel), crypto map, peer, protected networks (local and remote ident), packets
    encapsulated (sent) and decapsulated (received), send/receive errors, the transform and the seconds
    to the next rekey. Empty for 'There are no ipsec sas'."""
    rows: list[dict[str, Any]] = []
    iface: str | None = None
    cur: dict[str, Any] | None = None
    for line in text.splitlines():
        s = line.strip()
        if m := re.match(r"^interface:\s*(\S+)", s):
            iface, cur = m.group(1), None
        elif s.startswith("Crypto map tag:"):
            cur = {"interface": iface}
            if m := re.search(r"Crypto map tag:\s*([^,]+)", s):
                cur["crypto_map"] = m.group(1).strip()
            rows.append(cur)
        elif cur is None:
            continue
        elif m := _IDENT.search(s):
            cur[f"{m.group(1)}_network"] = _ident(m.group(2), m.group(3))
        elif s.startswith("current_peer:"):
            cur["peer"] = s.split(":", 1)[1].strip()
        elif s.startswith("#"):
            for name, value in _COUNTER.findall(s):
                key = {"pkts encaps": "encaps", "pkts decaps": "decaps"}.get(name, name.replace(" ", "_"))
                cur[key] = int(value)
        elif s.startswith("transform:") and "transform" not in cur:
            cur["transform"] = s.split(":", 1)[1].strip()
        elif m := _LIFETIME.search(s):
            secs = int(m.group(2))
            cur["rekey_in_s"] = min(secs, cur.get("rekey_in_s", secs))
    return rows


# --- show vpn-sessiondb l2l ----------------------------------------------------------------------------
_KV = re.compile(r"([A-Z][A-Za-z0-9 ]*?)\s+:\s+(.*?)(?=\s{2,}[A-Z][A-Za-z0-9 ]*?\s+:\s|\s*$)")
_DURATION = re.compile(r"(?:(\d+)d\s*)?(\d+)h:(\d+)m:(\d+)s")
_L2L_KEYS = {
    "Connection": "peer",
    "Protocol": "protocol",
    "Encryption": "encryption",
    "Hashing": "hashing",
    "Bytes Tx": "bytes_tx",
    "Bytes Rx": "bytes_rx",
    "Login Time": "login_time",
    "Duration": "duration",
}


def parse_l2l_sessions(text: str) -> list[dict[str, Any]]:
    """`show vpn-sessiondb l2l` -> one row per LAN-to-LAN session: peer, protocol, ciphers, bytes sent and
    received, login time and duration (also in seconds). Empty for 'There are presently no active
    sessions'."""
    rows: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for line in text.splitlines():
        for m in _KV.finditer(line.strip()):
            key, value = m.group(1).strip(), " ".join(m.group(2).split())
            if key == "Connection":
                cur = {}
                rows.append(cur)
            if cur is None or key not in _L2L_KEYS:
                continue
            field = _L2L_KEYS[key]
            if field.startswith("bytes_"):
                try:
                    cur[field] = int(value)
                except ValueError:
                    cur[field] = value
            else:
                cur[field] = value
            if field == "duration" and (d := _DURATION.search(value)):
                days, h, mins, secs = (int(x or 0) for x in d.groups())
                cur["duration_s"] = ((days * 24 + h) * 60 + mins) * 60 + secs
    return rows


# --- show route ----------------------------------------------------------------------------------------
_V4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_ROUTE = re.compile(rf"^([A-Za-z][A-Za-z0-9*+% ]{{0,7}}?)\s+({_V4})\s+({_V4})\b\s*(.*)$")
_ROUTE_MORE = re.compile(rf"^\s+\[[\d/]+\]\s+via\s+({_V4})(.*)$")
_VIA = re.compile(rf"via\s+({_V4})")
_CONNECTED = re.compile(r"(?:directly connected|connected by VPN[^,]*),\s*(\S+)")
_AGE = re.compile(r"^(?:\d+:\d{2}:\d{2}|\d+[ywdhms](?:\d+[ywdhms])*)$")


def _out_iface(rest: str) -> str | None:
    """The egress interface at the end of a route line, if any ('via 10.1.1.1, 00:12:41' has none: a
    recursive BGP next hop)."""
    if m := _CONNECTED.search(rest):
        return m.group(1).rstrip(",")
    parts = [p.strip() for p in rest.split(",")]
    last = parts[-1] if len(parts) > 1 else ""
    if not last or _AGE.match(last) or "via" in last or "[" in last:
        return None
    return last.split()[0]


def parse_routes(text: str) -> list[dict[str, Any]]:
    """IPv4 routes of `show route`: {code, protocol, prefix, via: [next hops], interfaces: [egress]};
    an ECMP route's further next hops (indented '[ad/metric] via ...' lines) join their route."""
    rows: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for line in text.splitlines():
        if m := _ROUTE.match(line):
            code = " ".join(m.group(1).split())
            try:
                prefix = str(ipaddress.ip_network(f"{m.group(2)}/{m.group(3)}", strict=False))
            except ValueError:
                cur = None
                continue
            rest = m.group(4)
            cur = {
                "code": code,
                "protocol": "connected" if code[0] in "CL" else PROTOCOLS.get(code[0], code),
                "prefix": prefix,
                "via": _VIA.findall(rest),
                "interfaces": [i for i in [_out_iface(rest)] if i],
            }
            rows.append(cur)
        elif cur is not None and (m := _ROUTE_MORE.match(line)):
            if m.group(1) not in cur["via"]:
                cur["via"].append(m.group(1))
            iface = _out_iface(f"via {m.group(1)}{m.group(2)}")
            if iface and iface not in cur["interfaces"]:
                cur["interfaces"].append(iface)
        elif line.strip():
            cur = None
    return rows


def _is_vti(iface: str, vtis: set[str]) -> bool:
    """A VTI's logical name, or one of a dynamic VTI's virtual-access interfaces ('<name>_va<N>')."""
    low = iface.lower()
    return any(low == v or low.startswith(f"{v}_va") for v in vtis)


def overlay_routes(routes: list[dict[str, Any]], vtis: set[str]) -> list[dict[str, Any]]:
    """The routes that leave over a VTI: egress interface is a VTI (or a virtual-access of a dynamic VTI),
    or, for a recursive next hop (BGP prints none), the route to the next hop does. Connected and local
    routes of the VTIs themselves are left out."""
    if not vtis:
        return []
    networks = [(ipaddress.ip_network(r["prefix"]), r["interfaces"]) for r in routes if r.get("interfaces")]

    def over_vti(hop: str) -> bool:
        try:
            ip = ipaddress.ip_address(hop)
        except ValueError:
            return False
        best = max((n for n in networks if ip in n[0]), key=lambda n: n[0].prefixlen, default=None)
        return best is not None and any(_is_vti(i, vtis) for i in best[1])

    out = []
    for r in routes:
        if r["protocol"] == "connected":
            continue
        if r["interfaces"]:
            hit = any(_is_vti(i, vtis) for i in r["interfaces"])
        else:
            hit = any(over_vti(h) for h in r["via"])
        if hit:
            out.append({k: r[k] for k in ("protocol", "prefix", "via", "interfaces") if r.get(k)})
    return out


# --- FMC's tunnel monitor ------------------------------------------------------------------------------
def _ips(peer: dict[str, Any] | None) -> list[str]:
    addrs = (peer or {}).get("ipAddresses") or {}
    return [str(a) for a in (addrs.get("v4") or []) + (addrs.get("v6") or [])]


def _side_name(peer: dict[str, Any] | None) -> str | None:
    p = peer or {}
    return (p.get("device") or {}).get("name") or (p.get("extranet") or {}).get("name")


def _vti_of(peer: dict[str, Any] | None) -> str | None:
    return ((peer or {}).get("vtiInterface") or {}).get("name")


def tunnel_view(t: dict[str, Any]) -> dict[str, Any]:
    """tunnel_row plus each end's VTI (route-based tunnels) as FMC reports it."""
    row = tunnel_row(t)
    vtis = [v for v in (_vti_of(t.get("peerA")), _vti_of(t.get("peerB"))) if v]
    if vtis:
        row["vti"] = " <-> ".join(vtis) if len(vtis) == 2 else vtis[0]
    return {k: v for k, v in row.items() if v is not None}


def detail_view(data: dict[str, Any]) -> dict[str, Any]:
    """health/tunnelstatuses/{id}/tunneldetails -> per peer: auth mode, VPN address, bytes and errors each
    way, and the SAs (protected network, packets encapsulated/decapsulated, seconds left on each SPI)."""
    out: dict[str, Any] = {}
    item = ((data or {}).get("items") or [data or {}])[0] or {}
    for side in ("peerA", "peerB"):
        p = item.get(side) or {}
        if not p:
            continue
        row: dict[str, Any] = {
            "device": ref_label(p.get("device") or {}) if p.get("device") else None,
            "auth": p.get("authMode"),
            "vpn_ip": p.get("vpnInterfaceIp"),
            "bytes_tx": p.get("bytesTx"),
            "bytes_rx": p.get("bytesRx"),
            "errors_tx": p.get("errorsTx"),
            "errors_rx": p.get("errorsRx"),
        }
        sas = []
        for sa in p.get("securityAssociations") or []:
            sas.append(
                {
                    "network": sa.get("protectedNetwork"),
                    "encaps": sa.get("packetEncaps"),
                    "decaps": sa.get("packetDcaps"),
                    "settings": sa.get("inUseSettings"),
                    "rekey_in_s": min(
                        (
                            int(s["secondsRemaining"])
                            for s in (sa.get("inboundSpi") or {}, sa.get("outboundSpi") or {})
                            if isinstance(s.get("secondsRemaining"), int)
                        ),
                        default=None,
                    ),
                }
            )
        if sas:
            row["sas"] = [{k: v for k, v in sa.items() if v is not None} for sa in sas]
        out[side] = {k: v for k, v in row.items() if v is not None}
    return out


# --- per device: what the device says ------------------------------------------------------------------
async def device_view(
    app: FmcApp,
    record: str,
    domain: str | None,
    refused: dict[str, str],
    supported: Any,
    *,
    route_based: bool,
    vtis: set[str],
) -> dict[str, Any]:
    """The device's own view of its VPN: IKE SAs, child SAs, L2L sessions, IKEv2 counters and (for
    route-based topologies) the routes over its VTIs, with the evidence lines."""
    evidence: dict[str, Any] = {}
    view: dict[str, Any] = {}

    async def show(cmd: str) -> str | None:
        return await show_on_device(app, record, cmd, domain, refused, supported, evidence, EVIDENCE_LINES)

    if (text := await show(IKE_SA)) is not None:
        view["ike_sas"] = parse_ikev2_sa(text)
    if (text := await show(IPSEC_SA)) is not None:
        view["ipsec_sas"] = parse_ipsec_sa(text)
        evidence[IPSEC_SA] = [
            ln.strip()
            for ln in text.splitlines()
            if re.search(r"interface:|current_peer|#pkts encaps|#pkts decaps|errors|remaining key", ln)
        ][: EVIDENCE_LINES * 2]
    if (text := await show(L2L)) is not None:
        view["sessions"] = parse_l2l_sessions(text)
    if (text := await show(IKE_STATS)) is not None:
        ike = parse_ikev2_stats(text) or None
        if ike:
            if grew := ike_growth(record, ike):
                ike["since_last_check"] = grew
            view["ikev2"] = ike
        evidence[IKE_STATS] = [
            ln.strip() for ln in text.splitlines() if re.search(r"Tunnels|Failure|failed|exceeded|clear", ln)
        ]
    if route_based and (text := await show(ROUTES)) is not None:
        routes = parse_routes(text)
        view["overlay_routes"] = overlay_routes(routes, vtis)
        evidence[ROUTES] = [
            ln.strip()
            for ln in text.splitlines()
            if any(_is_vti(w.rstrip(","), vtis) for w in ln.split()) or re.match(r"^B\s", ln)
        ][: EVIDENCE_LINES * 2] or [f"{len(routes)} route(s), none over a VTI"]
    view["evidence"] = evidence
    return view


def _sa_between(view: dict[str, Any] | None, local: list[str], remote: list[str]) -> dict[str, Any] | None:
    """The IKE SA in a device view between one of `local` and one of `remote` (any local when FMC
    doesn't report this end's address)."""
    for sa in (view or {}).get("ike_sas") or []:
        if sa.get("remote") in remote and (not local or sa.get("local") in local):
            return dict(sa)
    return None


def _child_sas(view: dict[str, Any] | None, remote: list[str]) -> list[dict[str, Any]]:
    return [sa for sa in (view or {}).get("ipsec_sas") or [] if sa.get("peer") in remote]


def _finding(
    severity: str, device: str, what: str, reason: str, topology: Any, tunnel: Any = None
) -> dict[str, Any]:
    f = {"severity": severity, "device": device, "what": what, "reasons": [reason], "topology": topology}
    if tunnel is not None:
        f["_tunnel"] = tunnel
    return f


def _one_way(device: str, peer: str, sas: list[dict[str, Any]]) -> str | None:
    out = sum(int(s.get("encaps") or 0) for s in sas)
    back = sum(int(s.get("decaps") or 0) for s in sas)
    if out > 0 and back == 0:
        return (
            f"{device} encrypts to {peer} ({out} packets) but decrypts nothing back: one-way tunnel; the "
            "far end doesn't route or NAT-exempt the return traffic into the tunnel, or an access rule "
            "or the ISP drops ESP/UDP 4500 on the way back"
        )
    if back > 0 and out == 0:
        return (
            f"{device} decrypts from {peer} ({back} packets) but sends nothing into the tunnel: on "
            f"{device} the return traffic isn't routed over the tunnel (route-based) or matches no "
            "crypto ACL / NAT exemption (policy-based)"
        )
    return None


def tunnel_findings(
    t: dict[str, Any],
    row: dict[str, Any],
    views: dict[str, dict[str, Any]],
    names_of: dict[str, set[str]],
) -> list[dict[str, Any]]:
    """Findings for one tunnel from FMC's state and both ends' device views. `views` is keyed by device
    name; `names_of` maps a device name to the names it appears as in tunnel rows (an HA pair's units)."""
    out: list[dict[str, Any]] = []
    topo = row.get("topology")
    tid = t.get("id")
    state = str(t.get("state") or "UNKNOWN")
    ends: list[tuple[str, list[str], list[str], str]] = []
    for me, other in (("peerA", "peerB"), ("peerB", "peerA")):
        name = _side_name(t.get(me))
        dev = next((d for d, alias in names_of.items() if is_me(name, alias)), None)
        if dev:
            ends.append((dev, _ips(t.get(me)), _ips(t.get(other)), _side_name(t.get(other)) or "the peer"))
    label = f"{row.get('peer_a')} <-> {row.get('peer_b')}"
    # a device's view only counts where FMC names the far end's address (else nothing to match)
    seen = [
        (dev, _sa_between(views.get(dev), local, remote))
        for dev, local, remote, _ in ends
        if dev in views and remote and "ike_sas" in views[dev]
    ]
    ready = [(dev, sa) for dev, sa in seen if sa and str(sa.get("state")).upper() == "READY"]
    if state != "TUNNEL_UP":
        level = "critical" if state == "TUNNEL_DOWN" else "warning"
        why = f"{label}: {state}" + (f" ({t['message']})" if t.get("message") else "")
        if state == "UNKNOWN":
            why += " (FMC has no state for it yet: just deployed, or never came up)"
        f = _finding(level, ends[0][0] if ends else str(row.get("peer_a")), "tunnel", why, topo, tid)
        if ready:
            up_dev, up_sa = ready[0]
            f["severity"] = "warning"
            f["reasons"].append(
                f"but {up_dev} has a READY IKE SA with {(up_sa or {}).get('remote')} "
                f"(up {(up_sa or {}).get('age_s', '?')} s): FMC's "
                "tunnel monitor lags the device; the tunnel itself is up"
            )
        else:
            for dev, _, _, peer in ends:
                cause = tunnel_down_cause((views.get(dev) or {}).get("ikev2"), "fmc_vpn_status")
                if dev in views and "ike_sas" in views[dev]:
                    f["reasons"].append(f"{dev}: no READY IKE SA with {peer}")
                if cause:
                    f["reasons"].append(f"{dev}: {cause}")
        out.append(f)
    else:
        for dev, sa in seen:
            if sa is None:
                why = (
                    f"{label}: FMC shows TUNNEL_UP but {dev} has no IKE SA with that peer: the tunnel went "
                    "down in the last minutes (FMC's tunnel monitor lags the device)"
                )
                out.append(_finding("warning", dev, "tunnel", why, topo))
            elif str(sa.get("state")).upper() != "READY":
                why = f"{label}: {dev}'s IKE SA with {sa.get('remote')} is {sa.get('state')}, not READY"
                out.append(_finding("warning", dev, "tunnel", why, topo))
    for dev, _, remote, peer in ends:
        sas = _child_sas(views.get(dev), remote)
        if one_way := _one_way(dev, peer, sas):
            out.append(_finding("warning", dev, "tunnel traffic", one_way, topo))
        errors = sum(int(s.get("send_errors") or 0) + int(s.get("recv_errors") or 0) for s in sas)
        if errors:
            why = f"{dev}: {errors} IPsec send/receive error(s) on the SAs with {peer}"
            out.append(_finding("warning", dev, "tunnel traffic", why, topo))
    return out


def tunnel_device_says(
    t: dict[str, Any], views: dict[str, dict[str, Any]], names_of: dict[str, set[str]]
) -> list[str]:
    """One line per end whose device was checked: its IKE SA and child SA counters for this tunnel."""
    lines = []
    for me, other in (("peerA", "peerB"), ("peerB", "peerA")):
        name = _side_name(t.get(me))
        dev = next((d for d, alias in names_of.items() if is_me(name, alias)), None)
        if dev is None or dev not in views or "ike_sas" not in views[dev] or not _ips(t.get(other)):
            continue
        sa = _sa_between(views[dev], _ips(t.get(me)), _ips(t.get(other)))
        if sa is None:
            lines.append(f"{dev}: no IKE SA")
            continue
        text = f"{dev}: IKE {sa.get('state')} {sa.get('role')}"
        if sa.get("age_s") is not None:
            text += f", up {sa['age_s']} s"
        kids = _child_sas(views[dev], _ips(t.get(other)))
        if kids:
            text += (
                f"; IPsec {sum(int(k.get('encaps') or 0) for k in kids)} out / "
                f"{sum(int(k.get('decaps') or 0) for k in kids)} in"
            )
            rekey = [k["rekey_in_s"] for k in kids if isinstance(k.get("rekey_in_s"), int)]
            if rekey:
                text += f", rekey in {min(rekey)} s"
        lines.append(text)
    return lines


def _around(
    mine: list[dict[str, Any]], eps: list[dict[str, Any]], tunnels: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """For one device's endpoint(s) in a topology: the endpoints it has tunnels with and those tunnels.
    Before FMC monitors any tunnel: a spoke's hubs, or every other endpoint for a hub or a peer."""
    names = {str((e.get("device") or {}).get("name") or e.get("name")) for e in mine}
    sides = ("peerA", "peerB")
    tunnels = [x for x in tunnels if any(is_me(_side_name(x.get(k)), names) for k in sides)]
    others = {str(_side_name(x.get(k))) for x in tunnels for k in sides} - names
    role = str(mine[0].get("peerType"))
    keep = []
    for e in eps:
        name = str(
            (e.get("device") or {}).get("name") or (e.get("extranetInfo") or {}).get("name") or e.get("name")
        )
        if e in mine:
            keep.append(e)
        elif tunnels:
            if any(is_me(o, {name}) for o in others):
                keep.append(e)
        elif role != "SPOKE" or e.get("peerType") == "HUB":
            keep.append(e)
    return keep, tunnels


def rank(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One entry per tunnel (it is reported from both ends), worst first."""
    out: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for f in findings:
        tid = f.pop("_tunnel", None)
        if tid is not None:
            if tid in seen:
                continue
            seen.add(tid)
        out.append(f)
    out.sort(key=lambda r: (SEVERITY[r["severity"]], str(r["topology"]), r["device"], r["what"]))
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="VPN status")
    async def fmc_vpn_status(
        ctx: Context,
        topology: Annotated[
            str | None,
            Field(description="Site-to-site or SD-WAN topology (name/UUID); default every topology"),
        ] = None,
        device: Annotated[
            str | None,
            Field(
                description="Only the topologies this device or HA pair is in (name/UUID), and its "
                "tunnels; its show commands run first, then its peers'"
            ),
        ] = None,
        show_commands: Annotated[
            bool,
            Field(
                description="Also run show crypto ikev2 sa, show crypto ipsec sa, show vpn-sessiondb l2l, "
                "show crypto ikev2 stats and (route-based) show route on the devices: their own view of "
                "the tunnels, traffic each way and the routes over the VTIs"
            ),
        ] = True,
        tunnel_details: Annotated[
            bool,
            Field(
                description="Also ask FMC for each tunnel's details (health/tunnelstatuses/{id}/"
                "tunneldetails: FMC runs show commands on both peers; bytes, errors, auth mode, SAs), "
                "worst tunnels first, at most max_devices tunnels"
            ),
        ] = False,
        max_devices: Annotated[
            int, Field(ge=1, le=20, description="Run show commands on at most this many devices")
        ] = 6,
        domain: Domain = None,
    ) -> Any:
        """Is the VPN up, and if not, where does it break? Every site-to-site topology (policy-based,
        route-based VTI and SD-WAN) with its endpoints (device or extranet peer, interface or VTI, role,
        protected networks, NAT exemption), each tunnel's state from FMC's tunnel monitor (with each
        end's VTI), and the devices' own view through FMC: IKE SAs (state, cipher, age since the last
        rekey), child SAs (packets out and in, errors, time to the next rekey), L2L sessions (bytes,
        duration) and, for route-based topologies, the routes learned over the VTIs (BGP, OSPF, EIGRP,
        static). One ranked list puts degraded tunnels first: down or unknown tunnels (with the IKEv2
        counters telling a pre-shared key mismatch, authentication failures growing between two calls,
        from a dead path, retransmits only), FMC and the device disagreeing (FMC's monitor lags by
        minutes), one-way traffic (encrypting without decrypting: routing, NAT exemption or an access
        rule on one side), IPsec errors, a route-based endpoint with no routes over its VTIs, and an HA
        pair without a working standby. Use it for "is the VPN to X up?" and as the first step of the
        fmc_vpn_troubleshoot prompt; SD-WAN WAN-link metrics and app routes: fmc_sdwan_status.
        Read-only; queried when called: one FMC request per topology plus 4-5 show commands per device
        (limit them with device, topology or max_devices)."""
        app: FmcApp = get_client(ctx)
        if topology:
            topos = [await resolve_topology(app, topology, domain)]
        else:
            topos = (await app.all(await app.config_path(S2S, domain), cap=2000)).items
        if not topos:
            note = "No VPN topologies (fmc_create_s2s_vpn or fmc_create_sdwan_topology builds one)."
            return object_result({"topologies": [], "note": note}, shape=False)
        try:
            pairs = (await app.all(await app.config_path(HA_PAIRS, domain))).items
        except (NotFound, UpstreamError):
            pairs = []
        members = {
            str(p.get("id")): {str((p.get(s) or {}).get("id")) for s in ("primary", "secondary")}
            for p in pairs
        }
        want: dict[str, Any] | None = None
        want_ids: set[str] = set()
        if device:
            want, _ = await _peer_device(app, device, domain)
            want_ids = {str(want["id"])} | {pid for pid, ids in members.items() if str(want["id"]) in ids}
        try:
            records = {
                str(d.get("id")): d
                for d in (await app.all(await app.config_path(DEVICES, domain), cap=2000)).items
            }
        except (NotFound, UpstreamError):
            records = {}
        tpath = await app.config_path(TUNNELS, domain)
        flt = {"filter": f"vpnTopologyId:{topos[0]['id']}"} if topology else None
        all_tunnels = (await app.all(tpath, flt, cap=5000)).items

        # topology -> endpoints and tunnels (filtered to the device when one is asked for)
        plan: list[tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]] = []
        for t in topos:
            eps = (
                await app.all(f"{await app.config_path(f'{S2S}/{t["id"]}', domain)}/endpoints", cap=2000)
            ).items
            tunnels = [x for x in all_tunnels if (x.get("vpnTopology") or {}).get("id") in (None, t["id"])]
            if want:
                mine = [e for e in eps if str((e.get("device") or {}).get("id")) in want_ids]
                if not mine:
                    continue
                eps, tunnels = _around(mine, eps, tunnels)
            plan.append((t, eps, tunnels))
        if want and not plan:
            raise NotFound(f"{want['name']} is in no VPN topology.", 404)

        # which managed devices get show commands: the asked device, then those with degraded tunnels,
        # then hubs, then the rest
        def badness(dev_name: str, tunnels: list[dict[str, Any]]) -> int:
            states = [
                TUNNEL_ORDER.get(str(x.get("state")), 1)
                for x in tunnels
                if any(is_me(_side_name(x.get(k)), {dev_name}) for k in ("peerA", "peerB"))
            ]
            return min(states, default=1)

        candidates: list[tuple[tuple[int, int, int], dict[str, Any], dict[str, Any]]] = []
        for t, eps, tunnels in plan:
            for e in eps:
                dev = e.get("device") or {}
                if e.get("extranet") or not dev.get("id"):
                    continue
                first = 0 if want and str(dev.get("id")) in want_ids else 1
                hub = 0 if e.get("peerType") == "HUB" else 1
                candidates.append(((first, badness(str(dev.get("name")), tunnels), hub), e, t))
        candidates.sort(key=lambda c: c[0])
        supported = await supported_commands(ctx) if show_commands else None
        refused: dict[str, str] = {}
        views: dict[str, dict[str, Any]] = {}
        names_of: dict[str, set[str]] = {}
        dev_rows: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        skipped: list[str] = []
        budget = max_devices
        for _, e, t in candidates:
            dev = e.get("device") or {}
            name = str(dev.get("name"))
            if name in names_of:
                continue
            pair = None
            if dev.get("type") == "DeviceHAPair":
                try:
                    pair = await app.api.get(f"{await app.config_path(HA_PAIRS, domain)}/{dev['id']}")
                except (NotFound, UpstreamError):
                    pair = None
            units = ha_units(pair) if pair else []
            names_of[name] = {name} | {str(u["device"]) for u in units if u.get("device")}
            for f in ha_findings(name, units, t.get("name")):
                f["what"] = f.pop("interface")
                findings.append(f)
            rec_id = str(dev.get("id"))
            record = records.get(rec_id) or {}
            row: dict[str, Any] = {"device": name}
            if units:
                row["ha"] = [{k: u[k] for k in ("role", "device", "state")} for u in units]
            if record and record.get("isConnected") is False:
                row["connected"] = False
                why = (
                    f"FMC can't reach {name} (disconnected): no live device view; its tunnels show "
                    "FMC's last known state"
                )
                findings.append(_finding("warning", name, "device", why, t.get("name")))
            if not show_commands:
                dev_rows.append(row)
                continue
            if budget <= 0 or row.get("connected") is False:
                if budget <= 0:
                    skipped.append(name)
                dev_rows.append(row)
                continue
            budget -= 1
            cfg, rec = await device_record(app, dev, domain, pair)
            route_based = any(
                bool(tt.get("routeBased")) or str(tt.get("topologyType")) == "AUTO_VPN"
                for tt, eps, _ in plan
                if any(str((x.get("device") or {}).get("id")) == rec_id for x in eps)
            )
            vtis: set[str] = set()
            if route_based:
                try:
                    vti_path = await app.config_path(f"{DEVICES}/{cfg}/virtualtunnelinterfaces", domain)
                    for v in (await app.all(vti_path, cap=500)).items:
                        if v.get("ifname"):
                            vtis.add(str(v["ifname"]).lower())
                except (NotFound, UpstreamError) as err:
                    row["notes"] = [f"VTIs not read: {err}"]
            view = await device_view(app, rec, domain, refused, supported, route_based=route_based, vtis=vtis)
            views[name] = view
            if vtis:
                row["vtis"] = sorted(vtis)
            row.update({k: v for k, v in view.items() if v not in (None, [], {})})
            for key in ("ike_sas", "ipsec_sas", "sessions", "overlay_routes"):
                if key in view and not view[key]:
                    row[key] = []
            if route_based and "overlay_routes" in view and not view["overlay_routes"]:
                up = [sa for sa in view.get("ike_sas") or [] if str(sa.get("state")).upper() == "READY"]
                if up:
                    why = (
                        f"{len(up)} IKE SA(s) READY but no routes over the VTIs ({', '.join(sorted(vtis))}): "
                        "traffic won't use the tunnel; check the BGP/OSPF neighbors over the VTI "
                        "(fmc_get_routing) or add static routes to the far side's networks via the VTI"
                    )
                    findings.append(_finding("warning", name, "overlay routing", why, t.get("name")))
            dev_rows.append(row)

        out_topos = []
        tunnel_rows: dict[str, dict[str, Any]] = {}
        worst = sorted(
            (x for _, _, tunnels in plan for x in tunnels if x.get("id")),
            key=lambda x: TUNNEL_ORDER.get(str(x.get("state")), 1),
        )
        detail_ids = {str(x["id"]) for x in worst[:max_devices]} if tunnel_details else set()
        detail_notes: list[str] = []
        for t, eps, tunnels in plan:
            rows = []
            for x in sorted(tunnels, key=lambda x: TUNNEL_ORDER.get(str(x.get("state")), 1)):
                row = tunnel_view(x)
                says = tunnel_device_says(x, views, names_of)
                if says:
                    row["device_says"] = says
                if str(x.get("id")) in detail_ids:
                    try:
                        data = await app.api.get(f"{tpath}/{x['id']}/tunneldetails", timeout=120)
                        row["fmc_details"] = detail_view(data) or (
                            f"{NOT_AVAILABLE}: FMC answered tunneldetails with no data for either peer "
                            "(seen on FMC 10.0.1 for an SD-WAN tunnel that was up); device_says has the "
                            "devices' own view"
                        )
                    except (InvalidRequest, NotFound, UpstreamError) as err:
                        row["fmc_details"] = f"{NOT_AVAILABLE}: {err}"
                findings += tunnel_findings(x, row, views, names_of)
                rows.append(row)
                tunnel_rows[str(x.get("id"))] = row
            counts: dict[str, int] = {}
            for x in tunnels:
                counts[str(x.get("state") or "UNKNOWN")] = counts.get(str(x.get("state") or "UNKNOWN"), 0) + 1
            out_topos.append(
                {
                    "topology": t.get("name"),
                    "kind": _kind(t),
                    "route_based": bool(t.get("routeBased")) or str(t.get("topologyType")) == "AUTO_VPN",
                    "ike": "+".join(
                        v
                        for v, on in (("IKEv1", t.get("ikeV1Enabled")), ("IKEv2", t.get("ikeV2Enabled")))
                        if on
                    )
                    or None,
                    "tunnels_up": counts.get("TUNNEL_UP", 0),
                    "tunnels_down": counts.get("TUNNEL_DOWN", 0),
                    "tunnels_unknown": counts.get("UNKNOWN", 0),
                    "endpoints": [endpoint_row(e) for e in eps],
                    "tunnels": rows,
                    "id": t.get("id"),
                }
            )
            if not tunnels:
                why = (
                    "FMC monitors no tunnel for this topology: not deployed yet (fmc_pending_changes, "
                    "fmc_deploy), or the endpoints never tried to connect"
                )
                findings.append(_finding("warning", str(t.get("name")), "topology", why, t.get("name")))
        if tunnel_details and len(tunnel_rows) > max_devices:
            detail_notes.append(
                f"Tunnel details read for the {max_devices} worst tunnel(s) only (max_devices={max_devices})."
            )
        ranked = rank(findings)
        result: dict[str, Any] = {
            "topologies": [{k: v for k, v in t.items() if v is not None} for t in out_topos],
            "devices": dev_rows,
            "degraded": ranked,
            "summary": {
                "critical": sum(1 for r in ranked if r["severity"] == "critical"),
                "warning": sum(1 for r in ranked if r["severity"] == "warning"),
                "topologies": len(out_topos),
                "tunnels_up": sum(t["tunnels_up"] for t in out_topos),
                "tunnels_down": sum(t["tunnels_down"] for t in out_topos),
                "tunnels_unknown": sum(t["tunnels_unknown"] for t in out_topos),
            },
        }
        notes = list(detail_notes)
        if any(r["what"] == "tunnel" for r in ranked):
            notes.append(FMC_TUNNEL_LAG)
        if skipped:
            notes.append(
                f"Show commands skipped on {', '.join(skipped)} (max_devices={max_devices}): FMC's tunnel "
                "state only for them; pass device=<name>."
            )
        if any(str(t.get("topologyType")) == "AUTO_VPN" for t, _, _ in plan):
            notes.append(
                "SD-WAN topologies: WAN-link path metrics, app routes and the branch view are in "
                "fmc_sdwan_status."
            )
        if notes:
            result["notes"] = notes
        return object_result(result, shape=False)

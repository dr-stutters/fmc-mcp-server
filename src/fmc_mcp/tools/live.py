"""Live flow and identity reads (F55): what is this host talking to right now, and who is on this IP?

FMC 10.0.1's command API refuses `show conn`, `show local-host` and `show user-identity` (400 "Either command
is not supported or entered command is an invalid command", checked live), and the FTD CLI has no
`show user-identity` at all. So:

- fmc_live_connections runs `show conn ... detail` when the FMC's API spec lists it (show_commands reads the
  allowlist at run time, so a newer FMC is picked up), and otherwise reads the device's syslog buffer with
  `show logging` (which FMC allows): LINA's connection built/teardown messages (302013-302021) and Snort's
  connection events (430002/430003, with the access rule, user, application and bytes). That needs the
  platform settings to log to the internal buffer; the tool says so when the buffer is off.
- fmc_user_identity_sessions reads FMC's own identity view: analysis/activesessions (user, current IP,
  device, realm, login and last-seen times) and, with history, analysis/useractivity (logins and logoffs).
  Both are plain REST reads (no subscription, ADR-003); the account's role needs the Events & Logs >
  Analysis > Users permissions.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import re
import time
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import AuthError, InvalidRequest, ResponseFormat, ToolRegistrar, get_client, list_result
from fmc_mcp._core.http import page_of
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.device_config import resolve_device
from fmc_mcp.tools.devices import DeviceRef
from fmc_mcp.tools.show_commands import supported_commands
from fmc_mcp.tools.system import iso
from fmc_mcp.tools.troubleshoot import run_show

SESSIONS = "analysis/activesessions"
ACTIVITY = "analysis/useractivity"
SESSION_CAP = 1000
ROLE_HINT = (
    "The FMC account's role needs the Events & Logs > Analysis > Users permissions (Active Sessions, User "
    "Activity, Users) for FMC's identity view; until then ISE (active sessions by IP or user) is the source."
)
BUFFER_HINT = (
    "Its syslog buffer is off, and FMC's command API refuses 'show conn' (FMC 10.0.1). To see live "
    "connections here, turn on logging to the internal buffer at level informational in the device's "
    "platform settings (Syslog > Logging Destinations > Internal Buffer; REST: "
    "ftdplatformsettingspolicies/{id}/syslog/loggingdestinations with loggingDestination INTERNAL_BUFFER) "
    "and deploy; for the access rule, user and application, also send the rules' connection events to "
    "syslog (fmc_set_access_logging). Meanwhile: fmc_packet_tracer for a verdict, or 'show conn' on the "
    "device CLI."
)

# --- syslog buffer (show logging) -----------------------------------------------------------------

LOG_LINE = re.compile(r"^(?P<time>.*?):?\s*%(?:FTD|ASA)-(?P<sev>\d)-(?P<msg>\d{6}): (?P<text>.*)$")
# One end of a connection: 'inside:10.1.1.10/40000 (203.0.113.5/40000)(LAB\\alice)'; the mapped address and
# the identity user are optional.
_END = (
    r"(?P<{0}if>[^:\s]+):(?P<{0}ip>\S+?)/(?P<{0}port>\d+)"
    r"(?: \((?P<{0}map>[^)]*)\))?(?:\((?P<{0}user>[^)]*)\))?"
)
BUILT = re.compile(
    r"^Built (?P<dir>inbound|outbound) (?P<proto>TCP|UDP|SCTP) connection (?P<id>\d+) for "
    + _END.format("a")
    + " to "
    + _END.format("b")
)
TEARDOWN = re.compile(
    r"^Teardown (?P<proto>TCP|UDP|SCTP) connection (?P<id>\d+) for "
    + _END.format("a")
    + " to "
    + _END.format("b")
    + r" duration (?P<duration>\S+) bytes (?P<bytes>\d+)(?: (?P<rest>.*))?$"
)
ICMP = re.compile(
    r"^(?P<what>Built|Teardown) (?:(?P<dir>inbound|outbound) )?(?P<proto>ICMP|ICMPv6) connection for "
    r"faddr (?P<fip>\S+?)/(?P<fid>\d+)(?:\((?P<fuser>[^)]*)\))? gaddr (?P<gip>\S+?)/\d+ "
    r"laddr (?P<lip>\S+?)/(?P<lid>\d+)(?:\((?P<luser>[^)]*)\))?(?: type (?P<type>\d+) code (?P<code>\d+))?"
)
SNORT_FIELD = re.compile(r"(?:^|, )([A-Za-z][\w ]*?): (.*?)(?=, [A-Za-z][\w ]*?: |$)")
TEARDOWN_USER = re.compile(r"^(?P<reason>.*?)\s*(?:\((?P<user>[^()]*\\[^()]*)\))?\s*$")


@dataclass
class Conn:
    """One connection seen in the log buffer (or in 'show conn')."""

    protocol: str
    initiator: str  # 'inside 10.1.1.10:40000'
    responder: str
    a_ip: str
    b_ip: str
    a_port: int | None = None
    b_port: int | None = None
    conn_id: str | None = None
    state: str = "open"
    user: str | None = None
    rule: str | None = None
    action: str | None = None
    application: str | None = None
    bytes: int | None = None
    duration: str | None = None
    idle: str | None = None
    flags: str | None = None
    reason: str | None = None
    started: str | None = None
    ended: str | None = None

    def row(self) -> dict[str, Any]:
        out = {
            "state": self.state,
            "protocol": self.protocol,
            "initiator": self.initiator,
            "responder": self.responder,
            "user": self.user,
            "rule": self.rule,
            "action": self.action,
            "application": self.application,
            "bytes": self.bytes,
            "duration": self.duration,
            "idle": self.idle,
            "flags": self.flags,
            "reason": self.reason,
            "started": self.started,
            "ended": self.ended,
            "id": self.conn_id,
        }
        return {k: v for k, v in out.items() if v not in (None, "")}

    def ips(self) -> tuple[str, str]:
        return self.a_ip, self.b_ip

    def ports(self) -> tuple[int | None, int | None]:
        return self.a_port, self.b_port


def _side(iface: str | None, ip: str, port: str | int | None) -> str:
    where = f"{iface} " if iface else ""
    return f"{where}{ip}:{port}" if port not in (None, "") else f"{where}{ip}"


def _user(*values: str | None) -> str | None:
    for v in values:
        if v and "\\" in v:
            return v
    return None


def parse_log_buffer(text: str) -> tuple[list[Conn], bool]:
    """Connections from 'show logging' (LINA 302013-302021 and Snort 430002/430003), and whether the
    output has a buffer at all ('Buffer logging: disabled' means none)."""
    enabled = not re.search(r"Buffer logging:\s*disabled", text, re.I)
    by_id: dict[str, Conn] = {}
    order: list[Conn] = []
    c: Conn | None
    snort: list[dict[str, str]] = []
    for raw in text.replace("\r", "").split("\n"):
        m = LOG_LINE.match(raw.strip())
        if not m:
            continue
        msg, body, when = m.group("msg"), m.group("text"), m.group("time").strip() or None
        if msg in ("302013", "302015"):
            b = BUILT.match(body)
            if not b:
                continue
            first = (b["aif"], b["aip"], int(b["aport"]))
            second = (b["bif"], b["bip"], int(b["bport"]))
            # 'outbound': the 'to' side opened the connection; 'inbound': the 'for' side did.
            opener, other = (second, first) if b["dir"] == "outbound" else (first, second)
            c = Conn(
                b["proto"],
                _side(*opener),
                _side(*other),
                opener[1],
                other[1],
                opener[2],
                other[2],
                conn_id=b["id"],
                user=_user(b["auser"], b["buser"]),
                started=when,
            )
            by_id[b["id"]] = c
            order.append(c)
        elif msg in ("302014", "302016"):
            t = TEARDOWN.match(body)
            if not t:
                continue
            c = by_id.get(t["id"])
            if c is None:  # its 'Built' scrolled out of the buffer
                c = Conn(
                    t["proto"],
                    _side(t["aif"], t["aip"], t["aport"]),
                    _side(t["bif"], t["bip"], t["bport"]),
                    t["aip"],
                    t["bip"],
                    int(t["aport"]),
                    int(t["bport"]),
                    conn_id=t["id"],
                )
                by_id[t["id"]] = c
                order.append(c)
            c.state, c.ended = "closed", when
            c.duration, c.bytes = t["duration"], int(t["bytes"])
            rest = TEARDOWN_USER.match(t["rest"] or "")
            if rest:
                c.reason = rest["reason"] or None
                c.user = c.user or _user(rest["user"], t["auser"], t["buser"])
        elif msg in ("302020", "302021"):
            i = ICMP.match(body)
            if not i:
                continue
            key = f"icmp:{i['fip']}:{i['fid']}:{i['lip']}:{i['lid']}"
            # 'outbound': the local address (laddr) sent the first packet; 'inbound': the foreign one.
            ini, res = (i["lip"], i["fip"]) if i["dir"] == "outbound" else (i["fip"], i["lip"])
            kind = f" type {i['type']}" if i["type"] else ""
            c = by_id.get(key)
            if c is None:
                c = Conn(i["proto"], ini, res + kind, ini, res, user=_user(i["fuser"], i["luser"]))
                by_id[key] = c
                order.append(c)
            if i["what"] == "Built":
                c.started = when
            else:
                c.state, c.ended = "closed", when
        elif msg in ("430002", "430003"):
            fields = {k.strip(): v.strip() for k, v in SNORT_FIELD.findall(body)}
            fields["_end"] = "1" if msg == "430003" else ""
            fields["_time"] = when or ""
            snort.append(fields)
    for ev in snort:
        _merge_snort(ev, order)
    return order, enabled


def _merge_snort(ev: dict[str, str], conns: list[Conn]) -> None:
    """Attach a Snort connection event (rule, user, application, bytes) to the LINA connection with the same
    addresses and ports, or add it as its own row."""
    src, dst = ev.get("SrcIP"), ev.get("DstIP")
    if not src or not dst:
        return
    sport, dport = _int(ev.get("SrcPort")), _int(ev.get("DstPort"))
    match = next(
        (
            c
            for c in reversed(conns)
            if {c.a_ip, c.b_ip} == {src, dst} and {c.a_port, c.b_port} == {sport, dport}
        ),
        None,
    )
    if match is None:
        proto = str(ev.get("Protocol") or "").upper() or "IP"
        match = Conn(
            proto,
            _side(ev.get("IngressInterface"), src, sport),
            _side(ev.get("EgressInterface"), dst, dport),
            src,
            dst,
            sport,
            dport,
            started=ev.get("_time") or None,
        )
        conns.append(match)
    match.rule = ev.get("AccessControlRuleName") or match.rule
    match.action = ev.get("AccessControlRuleAction") or match.action
    user = ev.get("User")
    if user and user.lower() not in ("no authentication required", "not found", "unknown"):
        match.user = match.user or user
    match.application = ev.get("ApplicationProtocol") or ev.get("Client") or match.application
    if ev.get("_end"):
        total = _int(ev.get("InitiatorBytes")) or 0
        total += _int(ev.get("ResponderBytes")) or 0
        if total and match.bytes is None:
            match.bytes = total
        if ev.get("ConnectionDuration") and match.duration is None:
            match.duration = f"{ev['ConnectionDuration']}s"
        if match.state == "open" and not match.conn_id:
            match.state = "closed"


def _int(v: Any) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


# --- show conn detail (where FMC allows it) --------------------------------------------------------

CONN_HEAD = re.compile(
    r"^(?P<proto>[A-Z][A-Z0-9]*) (?P<aif>[^:]+): (?P<aip>\S+?)/(?P<aport>\d+) (?P<bif>[^:]+): "
    r"(?P<bip>\S+?)/(?P<bport>\d+),\s*$"
)
CONN_KV = re.compile(r"(flags|idle|uptime|timeout|bytes)\s+([^,]*?)\s*(?:,|$)")
INITIATOR = re.compile(r"Initiator: (?P<ini>\S+?), Responder: (?P<res>\S+)")


def parse_show_conn_detail(text: str) -> list[Conn]:
    """Connections from 'show conn [all] detail' (the 'flags ..., idle ..., bytes ...' line and the
    'Initiator: ..., Responder: ...' line under each connection)."""
    out: list[Conn] = []
    cur: Conn | None = None
    for raw in text.replace("\r", "").split("\n"):
        line = raw.rstrip()
        h = CONN_HEAD.match(line)
        if h:
            cur = Conn(
                h["proto"],
                _side(h["aif"].strip(), h["aip"], h["aport"]),
                _side(h["bif"].strip(), h["bip"], h["bport"]),
                h["aip"],
                h["bip"],
                int(h["aport"]),
                int(h["bport"]),
            )
            out.append(cur)
            continue
        if cur is None or not line.startswith(" "):
            continue
        if "idle" in line and "bytes" in line:
            kv = dict(CONN_KV.findall(line))
            cur.flags = kv.get("flags", "").strip() or None
            cur.idle = kv.get("idle") or None
            cur.duration = kv.get("uptime") or None
            cur.bytes = _int(kv.get("bytes"))
            continue
        i = INITIATOR.search(line)
        if i and i["ini"] == cur.b_ip and i["res"] == cur.a_ip:
            cur.initiator, cur.responder = cur.responder, cur.initiator
            cur.a_ip, cur.b_ip, cur.a_port, cur.b_port = cur.b_ip, cur.a_ip, cur.b_port, cur.a_port
            continue
        low = line.strip().lower()
        if "rule" in low and ":" in low and "lookup" not in low:
            cur.rule = cur.rule or line.split(":", 1)[1].strip() or None
    return out


# --- identity (FMC analysis views) -----------------------------------------------------------------


def session_row(s: dict[str, Any]) -> dict[str, Any]:
    row = {
        "user": s.get("username") or s.get("user"),
        "realm": s.get("realmName"),
        "ip": s.get("currentIP"),
        "device": s.get("device"),
        "authentication": s.get("authenticationType"),
        "login": iso(s.get("loginTime")),
        "last_seen": iso(s.get("lastSeen")),
        "source": s.get("discoveryApplication"),
        "email": s.get("email") or None,
        "department": s.get("department") or None,
        "vpn_profile": s.get("vpnConnectionProfile") or None,
        "vpn_client_ip": s.get("vpnClientPublicIP") or None,
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def activity_row(a: dict[str, Any]) -> dict[str, Any]:
    row = {
        "time": iso(a.get("time")),
        "event": a.get("event"),
        "user": a.get("username"),
        "realm": a.get("realmName"),
        "ip": a.get("ipAddress"),
        "device": a.get("device"),
        "authentication": a.get("authenticationType"),
        "sgt": a.get("securityGroupTag") or None,
        "endpoint_profile": a.get("endpointProfile") or None,
        "description": a.get("description") or None,
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


async def active_sessions(
    app: FmcApp,
    domain: str | None,
    *,
    ip: str | None = None,
    user: str | None = None,
    device: str | None = None,
) -> list[dict[str, Any]]:
    """FMC's active identity sessions (user <-> current IP), filtered server-side. AuthError (403) when the
    account's role lacks the Analysis > Users permissions."""
    params: dict[str, Any] = {}
    if ip:
        params["currentIP"] = ip
    if user:
        params["username"] = user
    if device:
        params["device"] = device
    page = await app.all(await app.config_path(SESSIONS, domain), params, cap=SESSION_CAP)
    return [session_row(s) for s in page.items]


def _role_error(e: AuthError, what: str) -> AuthError:
    if e.status_code == 403:
        return AuthError(f"FMC refused {what} (403). {ROLE_HINT}", 403)
    return e


def _host_filter(host: str | None) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if not host:
        return None
    try:
        return ipaddress.ip_network(host.strip(), strict=False)
    except ValueError:
        raise InvalidRequest(f"host must be an IP address or CIDR network, got {host!r}") from None


def _in(net: ipaddress.IPv4Network | ipaddress.IPv6Network, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]) in net
    except ValueError:
        return False


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Live connections on a device")
    async def fmc_live_connections(
        ctx: Context,
        device: DeviceRef,
        host: Annotated[
            str | None, Field(description="Only connections to or from this IP (or CIDR network)")
        ] = None,
        user: Annotated[
            str | None,
            Field(
                description="Only this user's connections (name as in AD, e.g. alice or LAB\\alice): their "
                "IPs come from FMC's identity sessions, and log lines that name the user match too"
            ),
        ] = None,
        port: Annotated[int | None, Field(ge=0, le=65535, description="Only this port (either side)")] = None,
        protocol: Annotated[
            Literal["tcp", "udp", "icmp"] | None, Field(description="Only this protocol")
        ] = None,
        state: Annotated[
            Literal["open", "closed"] | None,
            Field(description="Only open (no teardown yet) or closed connections"),
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """'What is this host (or user) talking to right now?' on one FTD: its connections with
        initiator and responder (interface, address, port), protocol, state (open/closed), bytes,
        duration or idle time, teardown reason and, when the device logs them, the access rule, user
        and application. FMC 10.0.1 refuses 'show conn' over its API, so the rows come from the
        device's syslog buffer ('show logging': connection built/teardown messages and Snort
        connection events); if the buffer is off the answer says how to turn it on. Where FMC's API
        lists 'show conn' (read from its spec at run time) the live connection table is used instead.
        Newest last; filter by host, user, port, protocol or state. Pair with fmc_packet_tracer (why a
        flow is allowed or dropped) and fmc_user_identity_sessions (who is on an IP)."""
        app: FmcApp = get_client(ctx)
        net = _host_filter(host)
        dev = await resolve_device(app, device, domain)
        notes: list[str] = []
        user_ips: set[str] = set()
        if user:
            try:
                for s in await active_sessions(app, domain, user=user):
                    if s.get("ip"):
                        user_ips.add(str(s["ip"]))
            except AuthError as e:
                if e.status_code != 403:
                    raise
                notes.append(f"User IPs not resolved (FMC identity view refused: 403); {ROLE_HINT}")

        supported = await supported_commands(ctx)
        rule = supported.rules.get("show conn")
        if rule is not None and rule.accepts("detail"):
            words = ["show conn"]
            if net is not None and net.num_addresses == 1:
                words.append(f"address {net.network_address}")
            if port is not None:
                words.append(f"port {port}")
            words.append("detail")
            text = await run_show(app, dev["id"], " ".join(words), domain, supported)
            conns, source = parse_show_conn_detail(text), "show conn detail"
            enabled = True
        else:
            text = await run_show(app, dev["id"], "show logging", domain, supported)
            conns, enabled = parse_log_buffer(text)
            source = "syslog buffer (show logging)"
            if not enabled:
                off = {"device": dev.get("name"), "source": source, "available": False, "note": BUFFER_HINT}
                return list_result(page_of([], limit=limit, offset=offset), fmt=response_format, extra=off)

        rows = []
        for c in conns:
            ips = c.ips()
            if net is not None and not any(_in(net, ip) for ip in ips):
                continue
            if port is not None and port not in c.ports():
                continue
            if protocol and not c.protocol.lower().startswith(protocol):
                continue
            if state and c.state != state:
                continue
            if user:
                named = bool(c.user and user.lower() in c.user.lower())
                if not named and not (user_ips & set(ips)):
                    continue
            rows.append(c.row())
        extra: dict[str, Any] = {
            "device": dev.get("name"),
            "source": source,
            "connections_seen": len(conns),
            "open": sum(1 for r in rows if r.get("state") == "open"),
        }
        if user_ips:
            extra["user_ips"] = sorted(user_ips)
        if source.startswith("syslog"):
            notes.append(
                "From the log buffer: 'open' means no teardown logged yet; bytes and duration arrive with "
                "the teardown; older connections may have scrolled out of the buffer."
            )
        if notes:
            extra["note"] = " ".join(notes)
        columns = [
            "state",
            "protocol",
            "initiator",
            "responder",
            "user",
            "rule",
            "bytes",
            "duration",
            "reason",
        ]
        if source.startswith("show conn"):
            columns = ["protocol", "initiator", "responder", "flags", "idle", "duration", "bytes", "rule"]
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra, columns=columns
        )

    @reg.read(title="User identity sessions")
    async def fmc_user_identity_sessions(
        ctx: Context,
        ip: Annotated[
            str | None, Field(description="Who is on this IP (or CIDR network / range a-b)?")
        ] = None,
        user: Annotated[
            str | None, Field(description="Where is this user logged in (name contains, e.g. alice)?")
        ] = None,
        device: Annotated[
            str | None, Field(description="Only sessions this FTD reported (device name or UUID)")
        ] = None,
        history: Annotated[
            bool,
            Field(
                description="Also return the recent login/logoff events for the IP or user (user activity)"
            ),
        ] = False,
        hours: Annotated[int, Field(ge=1, le=720, description="History window in hours")] = 24,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Which user is on an IP, or where a user is logged in, from FMC's identity view (what the
        firewalls use to match user and group rules): user, realm, current IP, reporting device,
        authentication type (passive from ISE/pxGrid or AD, active captive portal, VPN), login and
        last-seen time. With history, also the user's (or the IP's) recent logins and logoffs. The
        FTD CLI has no 'show user-identity' and FMC 10.0.1 refuses it, so this reads FMC's
        analysis/activesessions and analysis/useractivity; the account's role needs the Events &
        Logs > Analysis > Users permissions (403 otherwise). Use it before evaluating user rules with
        fmc_rule_lookup(identities=...) or fmc_live_connections(user=...)."""
        app: FmcApp = get_client(ctx)
        if not (ip or user or device):
            raise InvalidRequest("Give an ip, a user or a device to look up sessions for.")
        dev_name = (await resolve_device(app, device, domain)).get("name") if device else None
        try:
            rows = await active_sessions(app, domain, ip=ip, user=user, device=dev_name)
        except AuthError as e:
            raise _role_error(e, "the active identity sessions (analysis/activesessions)") from None
        extra: dict[str, Any] = {"sessions": len(rows)}
        if dev_name:
            extra["device"] = dev_name
        if not rows:
            extra["note"] = (
                "No active session: the user isn't logged in where FMC can see it, or no identity source "
                "(ISE/pxGrid, passive AD, captive portal, VPN) reports this IP to FMC."
            )
        if history:
            params: dict[str, Any] = {"time": f"after:{int(time.time()) - hours * 3600}", "sort": "time:desc"}
            if ip:
                params["ipAddress"] = ip
            if user:
                params["username"] = user
            if dev_name:
                params["device"] = dev_name
            try:
                page = await app.all(await app.config_path(ACTIVITY, domain), params, cap=200)
            except AuthError as e:
                raise _role_error(e, "the user activity (analysis/useractivity)") from None
            extra["history"] = [activity_row(a) for a in page.items][:50]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

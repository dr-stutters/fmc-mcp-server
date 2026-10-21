"""FTD hardening check (F80): a platform settings policy and its devices against a YAML baseline.

The checklist is data (fmc_mcp/baselines/ftd-hardening.yaml = docs/baselines/ftd-hardening.yaml; edited
copies in FMC_BUNDLE_DIR, fmc_mcp.baseline); each check id has an evaluator here that reads only the
sections it needs. Findings are ranked by the baseline's severity and carry the check's source and the fix
as a call of an existing tool to preview (F24 platform settings writes, fmc_assign_policy, fmc_deploy, ...),
or the FMC UI page where no tool covers it. Read-only.

FMC 10.0.1 shapes (read 2026-10-21, notes/w6n-fixtures/f80-build-reads.json): SSH access with no entries is
`{paging}` with no items; external authentication not set is `{id, type ExternalAuthSetting, metadata {}}`;
SNMP off has no community or hosts; a banner not set has no bannerText; syslog settings without
timeStampFormat are LEGACY; `backup/files/manager` answers one object (the newest backup), a device without
backups 400 "File not found."; device records carry vdbVersion 'Build 426 - 2026-03-24 09:29:08.0' and
lspVersion 'lsp-rel-20261019-1844'.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import InvalidRequest, NotFound, ToolRegistrar, UpstreamError, ValidationFailed, get_client
from fmc_mcp.baseline import DEFAULT_BASELINE, SEVERITIES, Baseline, Check, load_baseline
from fmc_mcp.catalog import Catalog, IpInterval, parse_ip_value
from fmc_mcp.client import FmcApp
from fmc_mcp.licensing import licence_needs, licences
from fmc_mcp.tools.common import Domain, ref_label, resolve_in
from fmc_mcp.tools.deploy import deployable
from fmc_mcp.tools.devices import DEVICES, HA_PAIRS, Membership, membership_of
from fmc_mcp.tools.platform_settings import PS, banner_text, net_label, wrapper_labels
from fmc_mcp.tools.policies import ACCESS, all_rules, policy_assignments

DEVICE_CAP = 10  # devices of one platform settings policy checked per call
OPEN_DEFAULT = ("any", "any-ipv4", "any-ipv6", "0.0.0.0/0", "::/0")
SERVER_VERSION = "/api/fmc_platform/v1/info/serverversion"
SMART_LICENSE = "/api/fmc_platform/v1/license/smartlicenses"
BACKUPS = "backup/files"

# platform settings sections (key -> sub-path) and the ones each check reads
SECTIONS = {
    "ssh": "sshaccesssettings",
    "http": "httpaccesssettings",
    "snmp": "snmpsettings",
    "syslog_servers": "syslog/servers",
    "syslog_settings": "syslog/syslogsettings",
    "basic_logging": "syslog/basicloggingsetups",
    "destinations": "syslog/loggingdestinations",
    "ntp": "ntpsettings",
    "banner": "bannersettings",
    "external_auth": "externalauthsettings",
    "icmp": "icmpsettings",
    "dns": "dnssettings",
}
NEEDS = {
    "ssh-access-restricted": ("ssh",),
    "https-access-restricted": ("http",),
    "snmp-v3-only": ("snmp",),
    "snmp-hosts-restricted": ("snmp",),
    "syslog-servers": ("basic_logging", "syslog_servers", "destinations"),
    "syslog-rfc5424": ("syslog_settings",),
    "syslog-tls": ("syslog_servers",),
    "ntp-servers": ("ntp",),
    "login-banner": ("banner",),
    "external-authentication": ("external_auth",),
    "icmp-restricted": ("icmp",),
    "dns-configured": ("dns",),
}
_VIRTUAL = re.compile(
    r"\bvirtual\b|\bfor (kvm|vmware|aws|azure|gcp|google|oci|oracle|nutanix|openstack|hyper-v|alibaba)\b",
    re.I,
)
_ISO_DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_LSP_DATE = re.compile(r"(\d{4})(\d{2})(\d{2})-(\d{4})")
_VDB_BUILD = re.compile(r"build\s+(\d+)", re.I)
BANNER_NOTE = (
    "login-banner reads the banner FMC holds; FMC 10.0.1 leaves a deployed banner on the device when the "
    "policy's banner is emptied (fmc_run_show_command 'show banner' shows the device's)."
)


@dataclass
class Outcome:
    status: str  # pass | fail | not_applicable | unknown
    detail: str
    evidence: Any = None
    fix: str | None = None
    fix_tool: str | None = None
    ui: str | None = None


def call(tool: str, domain: str | None = None, **kw: Any) -> str:
    """A tool call as text for the finding's fix (the caller previews it)."""
    if domain:
        kw["domain"] = domain
    return f"{tool}(" + ", ".join(f"{k}={v!r}" for k, v in kw.items()) + ")"


def passed(detail: str, evidence: Any = None) -> Outcome:
    return Outcome("pass", detail, evidence)


def failed(
    detail: str, fix: str | None, tool: str | None, evidence: Any = None, ui: str | None = None
) -> Outcome:
    return Outcome("fail", detail, evidence, fix, tool, ui)


def day(text: Any, pattern: re.Pattern[str] = _ISO_DATE) -> datetime | None:
    m = pattern.search(str(text or ""))
    if not m:
        return None
    try:
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=UTC)
    except ValueError:
        return None


def age_days(when: datetime | None, now: float) -> int | None:
    return None if when is None else int((now - when.timestamp()) // 86400)


def vdb_build(text: Any) -> int | None:
    m = _VDB_BUILD.search(str(text or ""))
    return int(m.group(1)) if m else None


def lsp_key(text: Any) -> str | None:
    """'lsp-rel-20261019-1844' -> '20261019-1844' (sorts by release time)."""
    m = _LSP_DATE.search(str(text or ""))
    return f"{m.group(1)}{m.group(2)}{m.group(3)}-{m.group(4)}" if m else None


def backup_time(b: dict[str, Any]) -> float | None:
    """FMC's creationDate 'YYYY-MM-DD HH:MM:SS' (read as UTC) or an epoch."""
    v = b.get("creationDate")
    if isinstance(v, int | float):
        return float(v) / (1000 if v > 10**11 else 1)
    try:
        return datetime.fromisoformat(str(v).strip().replace(" ", "T")).replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


def backup_rows(data: Any) -> list[dict[str, Any]]:
    """backup/files answers a list ({items}) or, for 'manager' on FMC 10.0.1, one backup object."""
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return [b for b in data["items"] if isinstance(b, dict)]
    if isinstance(data, dict) and data.get("fileName"):
        return [data]
    return []


# --- open source networks --------------------------------------------------------------------------


class Exposure:
    """Whether an access entry's source is 'open': a name in open_sources, or wider than the prefixes."""

    def __init__(self, params: dict[str, Any], resolve: Callable[[], Awaitable[Catalog]]) -> None:
        self.names = {str(s).lower() for s in params.get("open_sources") or OPEN_DEFAULT}
        self.v4 = int(params.get("min_prefix_v4", 8))
        self.v6 = int(params.get("min_prefix_v6", 32))
        self._resolve = resolve

    def wide(self, intervals: list[IpInterval]) -> bool:
        for ver, lo, hi in intervals:
            bits, prefix = (32, self.v4) if ver == 4 else (128, self.v6)
            if hi - lo + 1 > 2 ** (bits - prefix):
                return True
        return False

    async def is_open(self, source: Any) -> bool | None:
        """True / False, None when the object can't be resolved to addresses."""
        label = net_label(source) if source is not None else "any"
        if label.lower() in self.names:
            return True
        literal = source.get("literal") if isinstance(source, dict) else None
        if isinstance(literal, str) or isinstance(source, str):
            got = parse_ip_value(str(literal or source))
            return None if got is None else self.wide(got)
        ref = source.get("object") if isinstance(source, dict) and source.get("object") else source
        if isinstance(ref, dict) and (ref.get("value") or not ref.get("id")):
            got = parse_ip_value(str(ref.get("value") or label))  # an unnamed literal reads as its name
            return None if got is None else self.wide(got)
        cat = await self._resolve()
        got = cat.networks(ref)
        return None if got is None else self.wide(got)


# --- what the checks read ----------------------------------------------------------------------------


@dataclass
class PsRead:
    policy: dict[str, Any]
    domain: str | None
    items: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def one(self, key: str) -> dict[str, Any]:
        rows = self.items.get(key) or []
        return rows[0] if rows else {}

    @property
    def name(self) -> str:
        return str(self.policy.get("name") or self.policy.get("id"))


@dataclass
class DeviceRead:
    record: dict[str, Any]
    membership: Membership | None
    ps: dict[str, Any] | None  # the assigned platform settings policy (reference)
    ha_monitored: list[dict[str, Any]] | None = None
    ha_error: str | None = None
    backups: list[dict[str, Any]] | None = None
    backup_error: str | None = None
    pending: dict[str, Any] | None = None
    pending_error: str | None = None
    needs: dict[str, str] | None = None
    needs_error: str | None = None

    @property
    def name(self) -> str:
        return str(self.record.get("name") or self.record.get("id"))


@dataclass
class FmcRead:
    info: dict[str, Any] | None = None
    info_error: str | None = None
    smart: dict[str, Any] | None = None
    smart_error: str | None = None
    backups: list[dict[str, Any]] | None = None
    backup_error: str | None = None


@dataclass
class Run:
    app: FmcApp
    domain: str | None
    now: float
    fmc: FmcRead = field(default_factory=FmcRead)
    devices: list[DeviceRead] = field(default_factory=list)
    _catalog: Catalog | None = None

    async def catalog(self) -> Catalog:
        if self._catalog is None:
            self._catalog = Catalog(self.app, self.domain)
            await self._catalog.load_networks()
        return self._catalog


def missing(read: PsRead, check: Check) -> Outcome | None:
    """unknown when a section the check needs could not be read."""
    lost = [f"{k} ({read.errors[k]})" for k in NEEDS.get(check.id, ()) if k in read.errors]
    return Outcome("unknown", f"Could not read {', '.join(lost)}.") if lost else None


# --- platform settings checks ---------------------------------------------------------------------------


async def _open_entries(
    entries: list[dict[str, Any]], key: str, exposure: Exposure
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """(open entries as {source, via}, unresolved labels, all labels)."""
    opened, unknown, labels = [], [], []
    for e in entries:
        src = e.get(key)
        label = net_label(src) if src is not None else "any"
        labels.append(label)
        verdict = await exposure.is_open(src)
        if verdict:
            opened.append({"source": label, "via": wrapper_labels(e.get("interfaces")) or None})
        elif verdict is None:
            unknown.append(label)
    return opened, unknown, labels


async def ssh_access(c: Check, ps: PsRead, run: Run) -> Outcome:
    entries = ps.items.get("ssh") or []
    if not entries:
        return passed("No SSH access entries: SSH to the data interfaces is off.")
    exposure = Exposure(c.params, run.catalog)
    opened, unknown, labels = await _open_entries(entries, "ipAddress", exposure)
    if opened:
        first = opened[0]
        fix = (
            call(
                "fmc_configure_ssh_access",
                ps.domain,
                policy=ps.name,
                action="remove",
                network=first["source"],
                interfaces=first["via"] or ["<zone>"],
            )
            + ", then allow only the management network: "
            + call(
                "fmc_configure_ssh_access",
                ps.domain,
                policy=ps.name,
                action="allow",
                network="<management network>",
                interfaces=first["via"] or ["<zone>"],
            )
        )
        detail = "SSH is allowed from " + "; ".join(f"{o['source']} via {o['via']}" for o in opened) + "."
        return failed(detail, fix, "fmc_configure_ssh_access", {"open": opened, "entries": len(entries)})
    if unknown:
        return Outcome("unknown", f"Could not resolve the addresses of {', '.join(unknown)}.")
    return passed(f"SSH allowed only from {', '.join(labels)}.")


async def https_access(c: Check, ps: PsRead, run: Run) -> Outcome:
    h = ps.one("http")
    if not h.get("enableHttpServer"):
        return passed("The HTTPS server is off.")
    entries = h.get("httpConfiguration") or []
    if not entries:
        return passed("The HTTPS server is on with no allowed networks.")
    opened, unknown, labels = await _open_entries(entries, "ipAddress", Exposure(c.params, run.catalog))
    if opened:
        first = opened[0]
        fix = (
            call(
                "fmc_configure_mgmt_access",
                ps.domain,
                policy=ps.name,
                kind="http",
                action="remove",
                networks=[first["source"]],
                interfaces=first["via"] or ["<zone>"],
            )
            + " (with http_server=False to turn the server off when nothing else needs it)"
        )
        detail = "HTTPS is allowed from " + "; ".join(f"{o['source']} via {o['via']}" for o in opened) + "."
        return failed(detail, fix, "fmc_configure_mgmt_access", {"open": opened, "port": h.get("port")})
    if unknown:
        return Outcome("unknown", f"Could not resolve the addresses of {', '.join(unknown)}.")
    return passed(f"HTTPS allowed only from {', '.join(labels)} (port {h.get('port')}).")


async def snmp_v3(c: Check, ps: PsRead, run: Run) -> Outcome:
    s = ps.one("snmp")
    if not s.get("enableSNMPServers"):
        return passed("The SNMP server is off.")
    allowed = {str(v).upper() for v in c.params.get("allowed_versions") or ["SNMPv3"]}
    problems = []
    if s.get("communityString"):
        problems.append("a community string is set (SNMPv1/v2c polling)")
    for h in s.get("snmpMgmtHosts") or []:
        version = str(h.get("snmpVersion") or "")
        if version and version.upper() not in allowed:
            problems.append(f"manager {net_label(h.get('ipAddress'))} uses {version}")
    if not c.params.get("allow_noauth", False):
        for u in s.get("snmpv3Users") or []:
            if str(u.get("securityLevel") or "").lower() == "noauth":
                problems.append(f"SNMPv3 user {u.get('userName')!r} has no authentication (NoAuth)")
    users = len(s.get("snmpv3Users") or [])
    if not problems:
        return passed(f"SNMPv3 only ({len(s.get('snmpMgmtHosts') or [])} manager(s), {users} user(s)).")
    # FMC masks the community; fmc_configure_snmp refuses a change without it while one is set
    kw: dict[str, Any] = {"enabled": False}
    if s.get("communityString") or any(h.get("communityString") for h in s.get("snmpMgmtHosts") or []):
        kw["community"] = "<the current community>"
    fix = (
        call("fmc_configure_snmp", ps.domain, policy=ps.name, **kw)
        + " when nothing polls the devices; SNMPv3 users and v3 managers are set in the FMC UI "
        "(fmc_configure_snmp sets v2c only)"
    )
    return failed(
        "SNMP is on, but " + "; ".join(problems) + ".",
        fix,
        "fmc_configure_snmp",
        {"problems": problems},
        ui="Devices > Platform Settings > <policy> > SNMP (Users, Hosts: SNMPv3)",
    )


async def snmp_hosts(c: Check, ps: PsRead, run: Run) -> Outcome:
    s = ps.one("snmp")
    if not s.get("enableSNMPServers"):
        return Outcome("not_applicable", "The SNMP server is off.")
    hosts = s.get("snmpMgmtHosts") or []
    if not hosts:
        return passed("No SNMP managers configured.")
    opened, unknown, labels = await _open_entries(hosts, "ipAddress", Exposure(c.params, run.catalog))
    if opened:
        fix = call(
            "fmc_configure_snmp",
            ps.domain,
            policy=ps.name,
            remove_hosts=[o["source"] for o in opened],
            add_hosts=["<NMS address>"],
            interfaces=opened[0]["via"] or ["<zone>"],
            community="<community>",
        )
        return failed(
            f"SNMP managers allow any address: {', '.join(o['source'] for o in opened)}.",
            fix,
            "fmc_configure_snmp",
            {"open": opened},
        )
    if unknown:
        return Outcome("unknown", f"Could not resolve the addresses of {', '.join(unknown)}.")
    return passed(f"SNMP managers: {', '.join(labels)}.")


def _server_label(s: dict[str, Any]) -> str:
    return f"{net_label(s.get('ipAddress'))} {s.get('protocol') or 'UDP'}/{s.get('port') or 514}"


async def syslog_servers(c: Check, ps: PsRead, run: Run) -> Outcome:
    basic = ps.one("basic_logging")
    servers = ps.one("syslog_servers").get("servers") or []
    dest = next(
        (d for d in ps.items.get("destinations") or [] if d.get("loggingDestination") == "SYSLOG_SERVERS"),
        None,
    )
    want = int(c.params.get("min_servers", 1))
    problems: list[str] = []
    kw: dict[str, Any] = {}
    if not basic.get("enableLogging"):
        problems.append("device logging is off")
        kw["logging_enabled"] = True
    if len(servers) < want:
        problems.append(f"{len(servers)} syslog server(s), {want} required")
        kw.update(add_servers=["<SIEM address>"], interfaces=["<zone>"])
    if dest is None:
        problems.append("no logging destination sends to the syslog servers (logging trap)")
        kw["server_level"] = "INFO"
    level = ((dest or {}).get("allEventConfig") or {}).get("value")
    evidence = {"servers": [_server_label(s) for s in servers] or None, "level": level}
    if problems:
        fix = call("fmc_configure_syslog", ps.domain, policy=ps.name, **kw)
        return failed("; ".join(problems).capitalize() + ".", fix, "fmc_configure_syslog", evidence)
    return passed(f"Logging on; syslog to {', '.join(evidence['servers'] or [])} at {level}.", evidence)


async def syslog_rfc5424(c: Check, ps: PsRead, run: Run) -> Outcome:
    fmt = ps.one("syslog_settings").get("timeStampFormat") or "LEGACY"
    if fmt == "RFC_5424":
        return passed("Syslog timestamps use RFC 5424.")
    fix = call("fmc_configure_syslog", ps.domain, policy=ps.name, timestamp_format="RFC_5424")
    return failed(
        f"Syslog timestamps are {fmt} (no year, no time zone).", fix, "fmc_configure_syslog", {"format": fmt}
    )


async def syslog_tls(c: Check, ps: PsRead, run: Run) -> Outcome:
    servers = ps.one("syslog_servers").get("servers") or []
    if not servers:
        return Outcome("not_applicable", "No syslog servers (see syslog-servers).")
    plain = [
        s for s in servers if str(s.get("protocol") or "UDP").upper() != "TCP" or not s.get("secureSyslog")
    ]
    if not plain:
        return passed(f"Every syslog server uses TCP with TLS ({len(servers)}).")
    first = plain[0]
    fix = call(
        "fmc_configure_syslog",
        ps.domain,
        policy=ps.name,
        remove_servers=[net_label(first.get("ipAddress"))],
        add_servers=[net_label(first.get("ipAddress"))],
        protocol="TCP",
        port=6514,
        secure=True,
        interfaces=wrapper_labels(first.get("interfaces")) or ["<zone>"],
    )
    return failed(
        f"Syslog without TLS: {', '.join(_server_label(s) for s in plain)}.",
        fix,
        "fmc_configure_syslog",
        {"plain": [_server_label(s) for s in plain]},
    )


async def ntp_servers(c: Check, ps: PsRead, run: Run) -> Outcome:
    n = ps.one("ntp")
    mode = n.get("ntpMode")
    servers = [
        s if isinstance(s, str) else str(s.get("value") or s.get("name"))
        for s in n.get("ntpServerInfos") or []
    ]
    fix = call("fmc_configure_ntp", ps.domain, policy=ps.name, servers=["<NTP server>"])
    if mode == "SYNC_VIA_NTP_SERVER":
        want = int(c.params.get("min_servers", 1))
        if len(servers) >= want:
            return passed(f"NTP servers: {', '.join(servers)}.", {"mode": mode, "servers": servers})
        return failed(
            f"{len(servers)} NTP server(s), {want} required.", fix, "fmc_configure_ntp", {"mode": mode}
        )
    if mode == "SYNC_VIA_MGMT_CENTER_NTP":
        if c.params.get("accept_fmc_sync", True):
            return passed(
                "The devices take their time from FMC (FMC's own NTP: System > Configuration > Time)."
            )
        return failed("The devices take their time from FMC, not from NTP servers.", fix, "fmc_configure_ntp")
    return failed("No NTP mode is set.", fix, "fmc_configure_ntp", {"mode": mode})


async def login_banner(c: Check, ps: PsRead, run: Run) -> Outcome:
    text = banner_text(ps.one("banner"))
    fix = call(
        "fmc_set_banner",
        ps.domain,
        policy=ps.name,
        text="Authorized use only. Activity on this device is monitored and logged.",
    )
    if not text:
        return failed("No login banner.", fix, "fmc_set_banner")
    words = [str(w).lower() for w in c.params.get("must_contain_any") or []]
    if words and not any(w in text.lower() for w in words):
        return failed(
            f"The banner doesn't contain any of {words}.", fix, "fmc_set_banner", {"banner": text[:200]}
        )
    return passed("Login banner set.", {"banner": text[:200]})


async def external_auth(c: Check, ps: PsRead, run: Run) -> Outcome:
    rows = [r for r in ps.items.get("external_auth") or [] if r.get("externalAuthServer")]
    if rows:
        meta = ((rows[0].get("metadata") or {}).get("externalAuthServer")) or {}
        name = meta.get("name") or ref_label(rows[0]["externalAuthServer"])
        method = meta.get("method")
        return passed(f"External authentication: {name}" + (f" ({method})" if method else "") + ".")
    return failed(
        "No external authentication: CLI users are local accounts on each device.",
        None,
        None,
        ui="System > Users > External Authentication (LDAP or RADIUS object), then Devices > Platform "
        "Settings > <policy> > External Authentication; over REST: fmc_api_call on users/externalauths "
        "and the policy's externalauthsettings (fmc_get_definition for the bodies)",
    )


async def icmp_access(c: Check, ps: PsRead, run: Run) -> Outcome:
    rules = ps.one("icmp").get("icmpConfigs") or []
    fix = call(
        "fmc_configure_mgmt_access",
        ps.domain,
        policy=ps.name,
        kind="icmp",
        networks=["<management network>"],
        interfaces=["<zone>"],
    )
    if not rules:
        if c.params.get("require_rules", True):
            return failed(
                "No ICMP access rules: any host may ping and send ICMP to the device's interfaces.",
                fix,
                "fmc_configure_mgmt_access",
            )
        return passed("No ICMP access rules (accepted by the baseline).")
    permits = [r for r in rules if str(r.get("icmpAction") or "Permit").lower() == "permit"]
    opened, unknown, _ = await _open_entries(permits, "network", Exposure(c.params, run.catalog))
    if opened:
        return failed(
            "ICMP is permitted from " + "; ".join(f"{o['source']} via {o['via']}" for o in opened) + ".",
            fix,
            "fmc_configure_mgmt_access",
            {"open": opened},
        )
    if unknown:
        return Outcome("unknown", f"Could not resolve the addresses of {', '.join(unknown)}.")
    return passed(f"{len(rules)} ICMP access rule(s), none from an open source.")


async def dns_configured(c: Check, ps: PsRead, run: Run) -> Outcome:
    groups = ps.one("dns").get("dnsServerGroups") or []
    if groups:
        return passed(
            f"DNS server groups: {', '.join(ref_label(g.get('dnsServerGroup') or {}) for g in groups)}."
        )
    fix = call(
        "fmc_configure_dns", ps.domain, policy=ps.name, servers=["<DNS server>"], interfaces=["<zone>"]
    )
    return failed("No DNS server group: FQDN objects in rules never resolve.", fix, "fmc_configure_dns")


PS_CHECKS: dict[str, Callable[[Check, PsRead, Run], Awaitable[Outcome]]] = {
    "ssh-access-restricted": ssh_access,
    "https-access-restricted": https_access,
    "snmp-v3-only": snmp_v3,
    "snmp-hosts-restricted": snmp_hosts,
    "syslog-servers": syslog_servers,
    "syslog-rfc5424": syslog_rfc5424,
    "syslog-tls": syslog_tls,
    "ntp-servers": ntp_servers,
    "login-banner": login_banner,
    "external-authentication": external_auth,
    "icmp-restricted": icmp_access,
    "dns-configured": dns_configured,
}


# --- device checks ---------------------------------------------------------------------------------------


async def ps_assigned(c: Check, d: DeviceRead, run: Run) -> Outcome:
    if d.ps:
        return passed(f"Platform settings policy {ref_label(d.ps)}.")
    fix = (
        call(
            "fmc_assign_policy",
            run.domain,
            kind="platform_settings",
            policy="<hardened platform settings policy>",
            devices=[d.name],
        )
        + ", then fmc_deploy"
    )
    return failed(
        "No platform settings policy: the device runs FTD defaults (no syslog server, no SNMP, no banner).",
        fix,
        "fmc_assign_policy",
    )


async def ha_monitoring(c: Check, d: DeviceRead, run: Run) -> Outcome:
    if d.membership is None or d.membership.kind != "ha":
        return Outcome("not_applicable", "Not an HA unit.")
    if d.ha_error:
        return Outcome(
            "unknown", f"Could not read the monitored interfaces of {d.membership.container} ({d.ha_error})."
        )
    issues = []
    for m in d.ha_monitored or []:
        v4 = m.get("ipv4Configuration") or {}
        if not v4.get("activeIPv4Address"):
            continue  # no data address (management, diagnostic)
        if c.params.get("require_monitoring", True) and not m.get("monitorForFailures"):
            issues.append({"interface": m.get("name"), "problem": "not monitored for failures"})
        if c.params.get("require_standby_ip", True) and not v4.get("standbyIPv4Address"):
            issues.append({"interface": m.get("name"), "problem": "no standby IP address"})
    if not issues:
        return passed(
            f"Every addressed interface of {d.membership.container} is monitored with a standby IP."
        )
    first = issues[0]
    fix = call(
        "fmc_configure_ha_monitoring",
        run.domain,
        ha_pair=d.membership.container,
        interface=first["interface"],
        monitored=True,
        standby_ip="<standby address>",
    )
    return failed(
        f"{d.membership.container}: " + "; ".join(f"{i['interface']} {i['problem']}" for i in issues) + ".",
        fix,
        "fmc_configure_ha_monitoring",
        {"issues": issues},
    )


async def device_content(c: Check, d: DeviceRead, run: Run) -> Outcome:
    meta = d.record.get("metadata") or {}
    info = run.fmc.info or {}
    issues = []
    behind = False
    lsp, fmc_lsp = meta.get("lspVersion"), info.get("lspVersion")
    if lsp and fmc_lsp and (lsp_key(lsp) or "") < (lsp_key(fmc_lsp) or ""):
        issues.append(f"intrusion rules {lsp} (FMC has {fmc_lsp})")
        behind = True
    vdb, fmc_vdb = meta.get("vdbVersion"), info.get("vdbVersion")
    if vdb_build(vdb) and vdb_build(fmc_vdb) and (vdb_build(vdb) or 0) < (vdb_build(fmc_vdb) or 0):
        issues.append(f"VDB {vdb} (FMC has {fmc_vdb})")
        behind = True
    lsp_age = age_days(day(lsp, _LSP_DATE), run.now)
    if lsp_age is not None and lsp_age > int(c.params.get("lsp_max_age_days", 30)):
        issues.append(f"intrusion rules {lsp} are {lsp_age} days old")
    vdb_age = age_days(day(vdb), run.now)
    if vdb_age is not None and vdb_age > int(c.params.get("vdb_max_age_days", 90)):
        issues.append(f"VDB {vdb} is {vdb_age} days old")
    evidence = {"lsp": lsp, "vdb": vdb, "snort": meta.get("snortVersion")}
    if not lsp and not vdb:
        return Outcome("unknown", "The device record has no LSP or VDB version.")
    if not issues:
        return passed(f"Intrusion rules {lsp}, VDB {vdb}.", evidence)
    if behind:
        fix = call("fmc_deploy", run.domain, devices=[d.name])
        return failed("Out of date: " + "; ".join(issues) + ".", fix, "fmc_deploy", evidence)
    return failed(
        "Out of date: " + "; ".join(issues) + ".",
        None,
        None,
        evidence,
        ui="System > Updates (Rule Updates, Product Updates: import and schedule recurring updates), "
        "then deploy",
    )


async def device_licences(c: Check, d: DeviceRead, run: Run) -> Outcome:
    if d.needs_error:
        return Outcome("unknown", f"Could not read the access policy's rules ({d.needs_error}).")
    held = licences(d.record.get("license_caps"))
    need = dict(d.needs or {})
    for lic in c.params.get("required") or []:
        need.setdefault(str(lic).upper(), "required by the baseline")
    lacking = sorted(n for n in need if n not in held)
    evidence = {"held": sorted(held), "needs": {k: need[k] for k in sorted(need)} or None}
    if not lacking:
        return passed(
            f"Licences {', '.join(sorted(held)) or 'none'} cover what the access policy needs.", evidence
        )
    fix = call("fmc_set_device_licenses", run.domain, device=d.name, add=lacking)
    detail = "Missing licences: " + "; ".join(f"{n} ({need[n]})" for n in lacking) + "."
    return failed(detail, fix, "fmc_set_device_licenses", evidence)


async def device_backup(c: Check, d: DeviceRead, run: Run) -> Outcome:
    if c.params.get("skip_virtual", True) and _VIRTUAL.search(str(d.record.get("model") or "")):
        return Outcome(
            "not_applicable",
            "Threat Defense Virtual has no device backup (FMC's own backup holds its configuration).",
        )
    if d.backup_error:
        return Outcome("unknown", f"Could not read the device's backups ({d.backup_error}).")
    newest = max((t for b in d.backups or [] if (t := backup_time(b)) is not None), default=None)
    limit = int(c.params.get("max_age_days", 7))
    fix = call("fmc_backup_devices", run.domain, devices=[d.name])
    if newest is None:
        return failed("No device backup on FMC.", fix, "fmc_backup_devices")
    age = int((run.now - newest) // 86400)
    when = datetime.fromtimestamp(newest, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if age > limit:
        return failed(
            f"Newest device backup {when} is {age} days old (limit {limit}).", fix, "fmc_backup_devices"
        )
    return passed(f"Newest device backup {when}.")


async def no_pending(c: Check, d: DeviceRead, run: Run) -> Outcome:
    if d.pending_error:
        return Outcome("unknown", f"Could not read the deployable devices ({d.pending_error}).")
    if not d.pending:
        return passed(f"Nothing pending (deployment status {d.record.get('deploymentStatus') or 'unknown'}).")
    stale = [
        str((p.get("policy") or {}).get("name") or (p.get("policy") or {}).get("type") or "?").strip()
        for p in d.pending.get("policyStatusList") or []
        if p.get("upToDate") is False
    ]
    fix = (
        call("fmc_pending_changes", run.domain, device=d.name)
        + ", then "
        + call("fmc_deploy", run.domain, devices=[d.name])
    )
    running = " A deployment is running." if d.pending.get("isDeploying") else ""
    return failed(
        f"FMC holds changes the device doesn't run: {', '.join(stale[:10]) or 'out-of-date policies'}."
        + running,
        fix,
        "fmc_deploy",
        {"out_of_date": stale or None},
    )


DEVICE_CHECKS: dict[str, Callable[[Check, DeviceRead, Run], Awaitable[Outcome]]] = {
    "platform-settings-assigned": ps_assigned,
    "ha-interface-monitoring": ha_monitoring,
    "device-content-current": device_content,
    "device-licences": device_licences,
    "device-backup-recent": device_backup,
    "no-pending-deployment": no_pending,
}


# --- FMC checks ------------------------------------------------------------------------------------------


async def smart_licensing(c: Check, run: Run) -> Outcome:
    if run.fmc.smart_error:
        return Outcome("unknown", f"Could not read Smart Licensing ({run.fmc.smart_error}).")
    s = run.fmc.smart or {}
    meta = s.get("metadata") or {}
    reg, auth = s.get("regStatus"), meta.get("authStatus")
    evidence = {"registration": reg, "authorization": auth, "virtual_account": meta.get("virtualAccount")}
    ui = "System > Licenses > Smart Licenses"
    if reg == "EVALUATION":
        days = meta.get("evalExpiresInDays")
        if c.params.get("allow_evaluation") and days:
            return passed(f"Evaluation mode, {days} days left (accepted by the baseline).", evidence)
        return failed(f"FMC runs in evaluation mode ({days} days left).", None, None, evidence, ui=ui)
    if reg != "REGISTERED":
        return failed(f"FMC is not registered to Smart Licensing ({reg}).", None, None, evidence, ui=ui)
    if auth != "AUTHORIZED":
        return failed(f"Smart Licensing authorization is {auth}.", None, None, evidence, ui=ui)
    return passed("Registered and authorized.", evidence)


async def fmc_backup(c: Check, run: Run) -> Outcome:
    if run.fmc.backup_error:
        return Outcome("unknown", f"Could not read FMC's backups ({run.fmc.backup_error}).")
    newest = max((t for b in run.fmc.backups or [] if (t := backup_time(b)) is not None), default=None)
    ui = "System > Tools > Backup/Restore (and System > Tools > Scheduling for a recurring backup)"
    limit = int(c.params.get("max_age_days", 7))
    if newest is None:
        return failed("FMC has no backup of its own.", None, None, ui=ui)
    age = int((run.now - newest) // 86400)
    when = datetime.fromtimestamp(newest, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if age > limit:
        return failed(f"Newest FMC backup {when} is {age} days old (limit {limit}).", None, None, ui=ui)
    return passed(f"Newest FMC backup {when}.")


async def fmc_content(c: Check, run: Run) -> Outcome:
    if run.fmc.info_error:
        return Outcome("unknown", f"Could not read FMC's versions ({run.fmc.info_error}).")
    info = run.fmc.info or {}
    checks = (
        ("SRU", info.get("sruVersion"), day(info.get("sruVersion")), "sru_max_age_days", 30),
        ("LSP", info.get("lspVersion"), day(info.get("lspVersion"), _LSP_DATE), "lsp_max_age_days", 30),
        ("VDB", info.get("vdbVersion"), day(info.get("vdbVersion")), "vdb_max_age_days", 90),
    )
    issues, evidence = [], {}
    for label, value, when, key, default in checks:
        evidence[label.lower()] = value
        age = age_days(when, run.now)
        if age is not None and age > int(c.params.get(key, default)):
            issues.append(f"{label} {value} is {age} days old")
    if issues:
        return failed(
            "; ".join(issues) + ".",
            None,
            None,
            evidence,
            ui="System > Updates (Rule Updates and Product Updates: recurring imports)",
        )
    return passed(", ".join(f"{k.upper()} {v}" for k, v in evidence.items() if v) + ".", evidence)


FMC_CHECKS: dict[str, Callable[[Check, Run], Awaitable[Outcome]]] = {
    "smart-licensing": smart_licensing,
    "fmc-backup-recent": fmc_backup,
    "fmc-content-current": fmc_content,
}
EVALUATORS = set(PS_CHECKS) | set(DEVICE_CHECKS) | set(FMC_CHECKS)


# --- reading ---------------------------------------------------------------------------------------------


def _err(e: Exception) -> str:
    return str(e).split("\n")[0][:300]


async def read_ps(app: FmcApp, policy: dict[str, Any], keys: set[str], domain: str | None) -> PsRead:
    out = PsRead(policy, domain)
    for key in SECTIONS:
        if key not in keys:
            continue
        try:
            page = await app.all(
                await app.config_path(f"{PS}/{policy['id']}/{SECTIONS[key]}", domain), cap=500
            )
            out.items[key] = list(page.items)
        except UpstreamError as e:
            out.errors[key] = _err(e)
    return out


async def _backups(app: FmcApp, target: str, domain: str | None) -> list[dict[str, Any]]:
    try:
        data = await app.api.get(await app.config_path(f"{BACKUPS}/{target}", domain))
    except ValidationFailed as e:
        if "file not found" in str(e).lower():
            return []
        raise
    return backup_rows(data)


async def read_fmc(app: FmcApp, wanted: set[str], domain: str | None) -> FmcRead:
    out = FmcRead()
    if "fmc-content-current" in wanted or "device-content-current" in wanted:
        try:
            out.info = (((await app.api.get(SERVER_VERSION)) or {}).get("items") or [{}])[0]
        except UpstreamError as e:
            out.info_error = _err(e)
    if "smart-licensing" in wanted:
        try:
            out.smart = (((await app.api.get(SMART_LICENSE)) or {}).get("items") or [{}])[0]
        except UpstreamError as e:
            out.smart_error = _err(e)
    if "fmc-backup-recent" in wanted:
        try:
            out.backups = await _backups(app, "manager", domain)
        except UpstreamError as e:
            out.backup_error = _err(e)
    return out


def _ps_of(assignments: list[dict[str, Any]], ids: set[str]) -> tuple[dict[str, Any] | None, str | None]:
    """The platform settings policy assigned to any of `ids` (a unit or its HA pair), and its owner domain."""
    for a in assignments:
        pol = a.get("policy") or {}
        if pol.get("type") != "FTDPlatformSettingsPolicy":
            continue
        if any(str(t.get("id", "")).lower() in ids for t in a.get("targets") or []):
            return pol, a.get("_domain")
    return None, None


async def read_devices(
    app: FmcApp,
    records: list[dict[str, Any]],
    assignments: list[dict[str, Any]],
    wanted: set[str],
    domain: str | None,
) -> list[DeviceRead]:
    out: list[DeviceRead] = []
    ha_cache: dict[str, tuple[list[dict[str, Any]] | None, str | None]] = {}
    needs_cache: dict[str, tuple[dict[str, str] | None, str | None]] = {}
    pending_rows: list[dict[str, Any]] | None = None
    pending_error = None
    if "no-pending-deployment" in wanted and records:
        try:
            pending_rows = await deployable(app, domain)
        except UpstreamError as e:
            pending_error = _err(e)
    for rec in records:
        member = membership_of(rec)
        ids = {str(rec.get("id")).lower()} | ({member.container_id} if member else set())
        ps, _ = _ps_of(assignments, ids)
        d = DeviceRead(rec, member, ps)
        if "ha-interface-monitoring" in wanted and member and member.kind == "ha":
            if member.container_id not in ha_cache:
                try:
                    path = await app.config_path(
                        f"{HA_PAIRS}/{member.container_id}/monitoredinterfaces", domain
                    )
                    ha_cache[member.container_id] = (list((await app.all(path)).items), None)
                except UpstreamError as e:
                    ha_cache[member.container_id] = (None, _err(e))
            d.ha_monitored, d.ha_error = ha_cache[member.container_id]
        if "device-backup-recent" in wanted:
            try:
                d.backups = await _backups(app, str(rec["id"]), domain)
            except UpstreamError as e:
                d.backup_error = _err(e)
        if "device-licences" in wanted:
            acp = (rec.get("accessPolicy") or {}).get("id")
            if not acp:
                d.needs = {}
            else:
                if acp not in needs_cache:
                    try:
                        full = await app.api.get(await app.config_path(f"{ACCESS}/{acp}", domain))
                        rules = await all_rules(
                            app, await app.config_path(f"{ACCESS}/{acp}/accessrules", domain)
                        )
                        needs_cache[acp] = (licence_needs(full or {}, rules.items), None)
                    except UpstreamError as e:
                        needs_cache[acp] = (None, _err(e))
                d.needs, d.needs_error = needs_cache[acp]
        if pending_rows is not None:
            want = str(rec.get("id")).lower()
            d.pending = next(
                (
                    p
                    for p in pending_rows
                    if want
                    in {
                        str(x.get("id", "")).lower()
                        for x in [p.get("device") or {}, *(p.get("deviceMembers") or [])]
                    }
                ),
                None,
            )
        d.pending_error = pending_error
        out.append(d)
    return out


async def _device_records(app: FmcApp, ref: str, domain: str | None) -> list[dict[str, Any]]:
    """A device, or an HA pair's units, as full device records."""
    try:
        return [await resolve_in(app, DEVICES, ref, "device", domain)]  # expanded: metadata included
    except NotFound:
        try:
            pair = await resolve_in(app, HA_PAIRS, ref, "HA pair", domain)
        except NotFound:
            raise NotFound(f"No device or HA pair named {ref!r} (fmc_list_devices).", 404) from None
        units = []
        for side in ("primary", "secondary"):
            unit = pair.get(side) or {}
            if unit.get("id"):
                units.append(await app.api.get(await app.config_path(f"{DEVICES}/{unit['id']}", domain)))
        return [u for u in units if u]


async def _assigned_records(
    app: FmcApp, ps_id: str, assignments: list[dict[str, Any]], domain: str | None
) -> tuple[list[dict[str, Any]], list[str]]:
    """Device records of a platform settings policy's targets (HA pairs as their units), capped."""
    notes: list[str] = []
    ids: list[str] = []
    for a in assignments:
        if (a.get("policy") or {}).get("id") != ps_id:
            continue
        for t in a.get("targets") or []:
            typ = str(t.get("type") or "")
            if typ == "Device":
                ids.append(str(t["id"]))
            elif typ == "DeviceHAPair":
                pair = await app.api.get(await app.config_path(f"{HA_PAIRS}/{t['id']}", domain)) or {}
                ids += [
                    str((pair.get(s) or {}).get("id"))
                    for s in ("primary", "secondary")
                    if (pair.get(s) or {}).get("id")
                ]
            else:
                notes.append(
                    f"{typ} {ref_label(t)!r}: device checks not run (clusters are checked per node)."
                )
    if len(ids) > DEVICE_CAP:
        notes.append(f"{len(ids)} devices use the policy: device checks ran on the first {DEVICE_CAP}.")
        ids = ids[:DEVICE_CAP]
    if not ids:
        return [], notes
    by_id = {
        str(d.get("id")).lower(): d
        for d in (await app.all(await app.config_path(DEVICES, domain), cap=1000)).items
    }
    records = []
    for i in ids:
        rec = by_id.get(i.lower())
        if rec is None:
            notes.append(f"Device {i} is not in this domain's device list: device checks not run.")
        else:
            records.append(rec)
    return records, notes


def _wanted(baseline: Baseline, checks: list[str] | None) -> list[Check]:
    ids = [c.id for c in baseline.checks]
    if checks:
        unknown = sorted(set(checks) - set(ids))
        if unknown:
            raise InvalidRequest(f"Unknown check ids {unknown}; this baseline has: {', '.join(ids)}.")
        return [c for c in baseline.checks if c.id in set(checks)]
    return [c for c in baseline.checks if c.enabled]


def _row(c: Check, target: str, o: Outcome) -> dict[str, Any]:
    row: dict[str, Any] = {"check": c.id, "target": target}
    if o.status == "fail":
        row.update(severity=c.severity, title=c.title)
    row["detail"] = o.detail
    if o.evidence:
        row["evidence"] = o.evidence
    if o.status == "fail":
        if o.fix:
            row["fix"] = o.fix
        row["fix_tool"] = o.fix_tool
        if o.ui:
            row["ui"] = o.ui
        row["source"] = list(c.source)
    return row


async def hardening_check(
    app: FmcApp,
    *,
    device: str | None,
    platform_settings: str | None,
    baseline: str,
    checks: list[str] | None,
    domain: str | None,
    now: float | None = None,
) -> dict[str, Any]:
    if bool(device) == bool(platform_settings):
        raise InvalidRequest("Give either device or platform_settings.")
    base = await asyncio.to_thread(load_baseline, baseline, app.settings.bundle_dir)
    selected = _wanted(base, checks)
    wanted = {c.id for c in selected}
    run = Run(app, domain, time.time() if now is None else now)
    notes: list[str] = []
    assignments = await policy_assignments(app, domain)
    ps_ref: dict[str, Any] | None
    ps_domain: str | None = domain
    if device:
        records = await _device_records(app, device, domain)
        ids = {str(r.get("id")).lower() for r in records}
        ids |= {m.container_id for r in records if (m := membership_of(r))}
        ps_ref, owner = _ps_of(assignments, ids)
        ps_domain = owner or domain
    else:
        ps_ref = await resolve_in(app, PS, str(platform_settings), "platform settings policy", domain)
        records, more = await _assigned_records(app, str(ps_ref["id"]), assignments, domain)
        notes += more
        if not records:
            notes.append("The policy is assigned to no device: only its own sections were checked.")
    run.fmc = await read_fmc(app, wanted, domain)
    run.devices = await read_devices(app, records, assignments, wanted, domain)

    results: list[tuple[Check, str, Outcome]] = []
    not_evaluated = []
    ps_checks = [c for c in selected if c.scope == "platform_settings"]
    ps_read = None
    if ps_ref and ps_checks:
        keys = {k for c in ps_checks for k in NEEDS.get(c.id, ())}
        ps_read = await read_ps(app, ps_ref, keys, ps_domain)
    for c in selected:
        if c.id not in EVALUATORS:
            not_evaluated.append({"check": c.id, "why": "this server has no evaluator for this check id"})
            continue
        if c.scope == "fmc" and c.id in FMC_CHECKS:
            results.append((c, "FMC", await FMC_CHECKS[c.id](c, run)))
        elif c.scope == "platform_settings" and c.id in PS_CHECKS:
            if ps_read is None:
                results.append((c, "-", Outcome("not_applicable", "No platform settings policy to check.")))
                continue
            target = f"platform settings {ps_read.name}"
            results.append((c, target, missing(ps_read, c) or await PS_CHECKS[c.id](c, ps_read, run)))
        elif c.scope == "device" and c.id in DEVICE_CHECKS:
            for d in run.devices:
                results.append((c, f"device {d.name}", await DEVICE_CHECKS[c.id](c, d, run)))
        else:
            not_evaluated.append(
                {"check": c.id, "why": f"scope {c.scope!r} doesn't match the check's evaluator"}
            )
    if "login-banner" in wanted and ps_read is not None:
        notes.append(BANNER_NOTE)

    order = {c.id: n for n, c in enumerate(base.checks)}
    rank = {s: n for n, s in enumerate(SEVERITIES)}
    fails = [(c, t, o) for c, t, o in results if o.status == "fail"]
    fails.sort(key=lambda x: (rank[x[0].severity], order[x[0].id]))
    findings = [_row(c, t, o) for c, t, o in fails]
    by = {s: n for s in SEVERITIES if (n := sum(1 for c, _, _ in fails if c.severity == s))}
    out: dict[str, Any] = {
        "baseline": base.summary(),
        "target": {
            k: v
            for k, v in (
                ("platform_settings", ref_label(ps_ref) if ps_ref else None),
                ("devices", [d.name for d in run.devices] or None),
            )
            if v
        },
        "summary": {
            "findings": len(findings),
            "by_severity": by or None,
            "passed": sum(1 for *_, o in results if o.status == "pass"),
            "not_applicable": sum(1 for *_, o in results if o.status == "not_applicable"),
            "unknown": sum(1 for *_, o in results if o.status == "unknown"),
            "checks_run": [c.id for c in selected if c.id in EVALUATORS],
            "verdict": "No findings."
            if not findings
            else f"{len(findings)} finding(s), highest {fails[0][0].severity}.",
        },
        "findings": findings,
        "passed": [_row(c, t, o) for c, t, o in results if o.status == "pass"] or None,
        "not_applicable": [_row(c, t, o) for c, t, o in results if o.status == "not_applicable"] or None,
        "unknown": [_row(c, t, o) for c, t, o in results if o.status == "unknown"] or None,
        "not_evaluated": not_evaluated or None,
    }
    if device and ps_ref is None:
        notes.append("No platform settings policy is assigned to the device: its checks were skipped.")
    if notes:
        out["notes"] = notes
    return {k: v for k, v in out.items() if v is not None}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="FTD hardening check")
    async def fmc_hardening_check(
        ctx: Context,
        device: Annotated[
            str | None,
            Field(
                description="Device or HA pair name/UUID: its platform settings policy and the device itself"
            ),
        ] = None,
        platform_settings: Annotated[
            str | None,
            Field(
                description="Platform settings policy name/UUID: the policy and the devices it is assigned to"
            ),
        ] = None,
        baseline: Annotated[
            str,
            Field(
                description="Bundled baseline name, or an edited copy's file name in FMC_BUNDLE_DIR "
                "(docs/baselines/ftd-hardening.yaml is the template)"
            ),
        ] = DEFAULT_BASELINE,
        checks: Annotated[
            list[str] | None,
            Field(description="Only these check ids (default: every enabled check of the baseline)"),
        ] = None,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Check FTD hardening against a baseline (default ftd-hardening-v1: the editable checklist
        docs/baselines/ftd-hardening.yaml, each check with its source). Platform settings: SSH, HTTPS and
        ICMP access not open to any address, SNMP off or v3 only with named managers, logging to syslog
        servers with RFC 5424 timestamps, NTP, a login banner, external authentication, DNS. Per device:
        platform settings assigned, HA interface monitoring and standby IPs, intrusion rule and VDB age,
        licences its access policy needs, a recent backup, nothing pending. FMC: Smart Licensing, its own
        backup, content age. Give device (its policy and the device; an HA pair: both units) or
        platform_settings (the policy and up to 10 devices it is assigned to). Returns findings ranked by
        severity, each with the check's source and its fix as the existing tool call to preview
        (fmc_configure_ssh_access, fmc_configure_snmp, fmc_configure_syslog, fmc_set_banner, fmc_deploy,
        ...) or the FMC UI page; plus passed, not_applicable and unknown checks. Read-only, about 25
        requests for one device."""
        app: FmcApp = get_client(ctx)
        return await hardening_check(
            app,
            device=device,
            platform_settings=platform_settings,
            baseline=baseline,
            checks=checks,
            domain=domain,
        )

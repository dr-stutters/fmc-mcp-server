"""FTD platform settings: a readable summary, syslog configuration and access-policy logging.

Pointing an FTD at the customer's syslog server or SIEM is configuration of the device; this server
never receives syslog itself (ADR-003). Changes reach the devices after fmc_deploy.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    field_changes,
    get_client,
)
from stutters_mcp_core.formatting import mask_secrets

from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import RefResolver
from fmc_mcp.tools.common import Domain, ref_label, resolve_in
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import ACCESS

PS = "policy/ftdplatformsettingspolicies"
Severity = Literal["EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"]
PolicyRef = Annotated[str, Field(description="Platform settings policy name or UUID")]

# Singleton sections (one object per policy, edited with PUT) and list sections.
SINGLE = {
    "basic_logging": "syslog/basicloggingsetups",
    "syslog_servers": "syslog/servers",
    "syslog_settings": "syslog/syslogsettings",
    "ntp": "ntpsettings",
    "snmp": "snmpsettings",
    "http_access": "httpaccesssettings",
    "banner": "bannersettings",
    "dns": "dnssettings",
}
LISTS = {
    "logging_destinations": "syslog/loggingdestinations",
    "event_lists": "syslog/eventlists",
    "ssh_access": "sshaccesssettings",
}


async def resolve_ps(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, PS, ref, "platform settings policy", domain)


async def section(app: FmcApp, pol_id: str, sub: str, domain: str | None) -> list[dict[str, Any]]:
    page = await app.all(await app.config_path(f"{PS}/{pol_id}/{sub}", domain), cap=500)
    return list(page.items)


async def single(app: FmcApp, pol_id: str, key: str, domain: str | None) -> dict[str, Any]:
    items = await section(app, pol_id, SINGLE[key], domain)
    if not items:
        raise NotFound(f"The policy has no {key} section.", 404)
    return items[0]


def _iface_labels(block: Any) -> list[str]:
    if not isinstance(block, dict):
        return []
    return [ref_label(o) for o in block.get("objects") or []] + [str(x) for x in block.get("literals") or []]


def _addr(wrapper: Any) -> str | None:
    if not isinstance(wrapper, dict):
        return None
    if wrapper.get("literal"):
        return str(wrapper["literal"])
    if isinstance(wrapper.get("object"), dict):
        return ref_label(wrapper["object"])
    return None


def server_row(s: dict[str, Any]) -> dict[str, Any]:
    return {
        "host": _addr(s.get("ipAddress")),
        "protocol": s.get("protocol"),
        "port": s.get("port"),
        "via": "management/diagnostic interface"
        if s.get("isMgmtReachable")
        else _iface_labels(s.get("interfaces")),
        "emblem": s.get("logMessagesInEMBLEM") or None,
        "secure": s.get("secureSyslog") or None,
    }


def destination_row(d: dict[str, Any]) -> dict[str, Any]:
    allc = d.get("allEventConfig") or {}
    return {
        "destination": d.get("loggingDestination"),
        "all_events": f"{allc.get('filterCriteria')} {allc.get('value') or ''}".strip() if allc else None,
        "specific": [f"{x.get('class')}={x.get('severity')}" for x in d.get("specificEventConfig") or []]
        or None,
        "id": d.get("id"),
    }


def syslog_summary(
    basic: dict[str, Any], servers: dict[str, Any], settings: dict[str, Any], dests: list[dict[str, Any]]
) -> dict[str, Any]:
    tofmc = basic.get("loggingToFMCType")
    to_fmc = "OFF" if tofmc in (None, "OFF") else str(tofmc)
    if to_fmc != "OFF" and basic.get("loggingToFMCLogLevel"):
        to_fmc += f" at {basic['loggingToFMCLogLevel']}"
    return {
        "logging_enabled": bool(basic.get("enableLogging")),
        "send_to_fmc": to_fmc,
        "emblem_format": basic.get("enableEMBLEMFormat") or False,
        "timestamp_format": settings.get("timeStampFormat") or "LEGACY",
        "facility": settings.get("facility"),
        "device_id": settings.get("syslogDeviceIdConfig"),
        "destinations": [destination_row(d) for d in dests],
        "servers": [server_row(s) for s in servers.get("servers") or []],
        "allow_traffic_when_tcp_server_down": servers.get("allowUserTrafficWhenDown"),
    }


async def assigned_devices(app: FmcApp, pol_id: str, domain: str | None) -> list[str]:
    page = await app.all(await app.config_path("assignment/policyassignments", domain), cap=5000)
    for a in page.items:
        if (a.get("policy") or {}).get("id") == pol_id:
            return [str(t.get("name") or t.get("id")) for t in a.get("targets") or []]
    return []


def _strip(obj: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in editable(obj).items() if k not in ("type", "id", "name", "description")}


def _norm(addr: str) -> str:
    try:
        return str(ipaddress.ip_address(addr.strip()))
    except ValueError:
        return addr.strip().lower()


def server_key(s: dict[str, Any]) -> str:
    return _norm(str(_addr(s.get("ipAddress")) or ""))


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Get platform settings")
    async def fmc_get_platform_settings(
        ctx: Context, policy: PolicyRef, domain: Domain = None
    ) -> dict[str, Any]:
        """Readable summary of an FTD platform settings policy: syslog (logging on/off, what goes to
        FMC, destinations and their levels, syslog servers with interface, protocol and port,
        facility, timestamp format, EMBLEM), NTP, SNMP (secrets masked), SSH and HTTP access,
        banner, DNS, plus the devices it is assigned to. Edit syslog with fmc_configure_syslog; other
        sections through fmc_api_call (fmc_get_definition for the models)."""
        app: FmcApp = get_client(ctx)
        pol = await resolve_ps(app, policy, domain)
        pid = pol["id"]
        got: dict[str, Any] = {}
        for key, sub in SINGLE.items():
            items = await section(app, pid, sub, domain)
            got[key] = items[0] if items else {}
        for key, sub in LISTS.items():
            got[key] = await section(app, pid, sub, domain)
        ntp = got["ntp"]
        return {
            "policy": pol.get("name"),
            "id": pid,
            "assigned_to": await assigned_devices(app, pid, domain),
            "syslog": {
                **syslog_summary(
                    got["basic_logging"],
                    got["syslog_servers"],
                    got["syslog_settings"],
                    got["logging_destinations"],
                ),
                "event_lists": [e.get("name") for e in got["event_lists"]] or None,
            },
            "ntp": mask_secrets({"mode": ntp.get("ntpMode"), "servers": ntp.get("ntpServerInfos")}),
            "snmp": mask_secrets(_strip(got["snmp"])),
            "ssh_access": [
                {
                    "hosts": _addr(s.get("ipAddress")) or s.get("ipAddress"),
                    "via": _iface_labels(s.get("interfaces")),
                }
                for s in got["ssh_access"]
            ]
            or None,
            "http_access": mask_secrets(_strip(got["http_access"])) or None,
            "banner": got["banner"].get("bannerText") or None,
            "dns": mask_secrets(_strip(got["dns"])) or None,
        }

    @reg.write(title="Create platform settings policy")
    async def fmc_create_platform_settings_policy(
        ctx: Context,
        name: Annotated[str, Field(description="New policy name", min_length=1, max_length=64)],
        description: Annotated[str | None, Field(description="Optional description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an FTD platform settings policy with FMC's defaults. Configure syslog with
        fmc_configure_syslog, assign it with fmc_assign_policy(kind='platform_settings'), then deploy."""
        app: FmcApp = get_client(ctx)
        body: dict[str, Any] = {"name": name, "type": "FTDPlatformSettingsPolicy"}
        if description:
            body["description"] = description
        blockers = []
        try:
            await resolve_ps(app, name, domain)
            blockers.append(f"A platform settings policy named {name!r} already exists.")
        except NotFound:
            pass
        path = await app.config_path(PS, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_platform_settings_policy",
            args={"name": name, "description": description, "domain": domain},
            confirm=confirm,
            plan=Plan(f"Create platform settings policy {name!r}", details={"body": body}, blockers=blockers),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Configure syslog (platform settings)")
    async def fmc_configure_syslog(
        ctx: Context,
        policy: PolicyRef,
        add_servers: Annotated[
            list[str] | None,
            Field(description="Syslog server IPs (or host object names) to add, e.g. the customer's SIEM"),
        ] = None,
        remove_servers: Annotated[list[str] | None, Field(description="Syslog servers to remove")] = None,
        protocol: Annotated[Literal["UDP", "TCP"], Field(description="Transport for added servers")] = "UDP",
        port: Annotated[int, Field(ge=1, le=65535, description="Port for added servers")] = 514,
        interfaces: Annotated[
            list[str] | None,
            Field(description="Security zones / interface groups the added servers are reached through"),
        ] = None,
        via_management: Annotated[
            bool, Field(description="Reach added servers through the management/diagnostic interface instead")
        ] = False,
        emblem: Annotated[bool, Field(description="Added servers get messages in EMBLEM format")] = False,
        secure: Annotated[bool, Field(description="TLS syslog for added TCP servers")] = False,
        logging_enabled: Annotated[bool | None, Field(description="Turn device logging on/off")] = None,
        server_level: Annotated[
            Severity | Literal["OFF"] | None,
            Field(
                description="Severity sent to the syslog servers (logging trap); OFF removes the destination"
            ),
        ] = None,
        facility: Annotated[
            Literal["LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7"] | None,
            Field(description="Syslog facility"),
        ] = None,
        timestamp_format: Annotated[
            Literal["RFC_5424", "LEGACY"] | None, Field(description="Timestamp format (RFC 5424 or legacy)")
        ] = None,
        emblem_format: Annotated[
            bool | None, Field(description="EMBLEM format for all syslog (basic logging setup)")
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change the syslog part of an FTD platform settings policy: add or remove syslog servers
        (interface, UDP/TCP, port, EMBLEM, TLS), turn logging on, set the level sent to the servers
        (logging trap), the facility and RFC 5424 timestamps. Only the parts you pass change; the
        preview lists every section and field that changes. Deploy afterwards; verify with
        fmc_run_show_command('show running-config logging')."""
        app: FmcApp = get_client(ctx)
        pol = await resolve_ps(app, policy, domain)
        pid = pol["id"]
        steps: list[tuple[str, str, str, dict[str, Any] | None]] = []  # (name, method, path, body)
        changes: dict[str, Any] = {}
        blockers: list[str] = []
        fingerprint: dict[str, Any] = {}
        base = await app.config_path(f"{PS}/{pid}", domain)

        # servers
        if add_servers or remove_servers:
            cur = await single(app, pid, "syslog_servers", domain)
            fingerprint["servers"] = editable(cur)
            servers = list(cur.get("servers") or [])
            have = {server_key(s) for s in servers}
            new_rows = []
            if add_servers:
                if not via_management and not interfaces:
                    raise InvalidRequest(
                        "Give interfaces (zones) for the new servers, or via_management=true."
                    )
                if secure and protocol != "TCP":
                    raise InvalidRequest("Secure (TLS) syslog needs protocol TCP.")
                iface_block = (
                    (await RefResolver(app, domain).block(interfaces, "zone")) if interfaces else None
                )
                for raw in add_servers:
                    v = raw.strip()
                    try:
                        wrapper: dict[str, Any] = {"literal": str(ipaddress.ip_address(v))}
                    except ValueError:
                        host = await RefResolver(app, domain).single(v, ["host"], "host object")
                        wrapper = {"object": host}
                    key = _norm(str(_addr(wrapper)))
                    if key in have:
                        blockers.append(f"Syslog server {v} is already configured.")
                        continue
                    row: dict[str, Any] = {
                        "ipAddress": wrapper,
                        "protocol": protocol,
                        "port": str(port),
                        "logMessagesInEMBLEM": emblem,
                        "secureSyslog": secure,
                        "isMgmtReachable": via_management,
                    }
                    if iface_block and not via_management:
                        row["interfaces"] = iface_block
                    new_rows.append(row)
                    have.add(key)
            drop = {_norm(r) for r in remove_servers or []}
            missing = drop - {server_key(s) for s in servers}
            if missing:
                blockers.append(f"Not configured, can't remove: {', '.join(sorted(missing))}.")
            kept = [s for s in servers if server_key(s) not in drop]
            desired = {**editable(cur), "servers": kept + new_rows}
            if kept + new_rows != servers:
                changes["servers"] = {
                    "add": [server_row(r) for r in new_rows] or None,
                    "remove": sorted(drop - missing) or None,
                }
                path = f"{base}/{SINGLE['syslog_servers']}/{cur['id']}"
                steps.append(("servers", "PUT", path, desired))

        # basic logging setup
        if logging_enabled is not None or emblem_format is not None:
            cur = await single(app, pid, "basic_logging", domain)
            fingerprint["basic"] = editable(cur)
            desired = editable(cur)
            if logging_enabled is not None:
                desired["enableLogging"] = logging_enabled
            if emblem_format is not None:
                desired["enableEMBLEMFormat"] = emblem_format
            diff = field_changes(editable(cur), desired)
            needs_level = desired.get("loggingToFMCType") not in (None, "OFF")
            if diff and needs_level and not desired.get("loggingToFMCLogLevel"):
                # FMC 10.0.1 rejects the PUT ("LoggingToSecureFMCType is missing") without a level here.
                desired["loggingToFMCLogLevel"] = "ERR"
                diff = field_changes(editable(cur), desired)
            if diff:
                changes["basic_logging"] = diff
                path = f"{base}/{SINGLE['basic_logging']}/{cur['id']}"
                steps.append(("basic_logging", "PUT", path, desired))

        # syslog settings
        if facility or timestamp_format:
            cur = await single(app, pid, "syslog_settings", domain)
            fingerprint["settings"] = editable(cur)
            desired = editable(cur)
            if facility:
                desired["facility"] = facility
            if timestamp_format:
                desired["timeStampFormat"] = timestamp_format
            diff = field_changes(editable(cur), desired)
            if diff:
                changes["syslog_settings"] = diff
                path = f"{base}/{SINGLE['syslog_settings']}/{cur['id']}"
                steps.append(("syslog_settings", "PUT", path, desired))

        # logging destination 'syslog servers'
        if server_level:
            dests = await section(app, pid, LISTS["logging_destinations"], domain)
            fingerprint["destinations"] = [editable(d) for d in dests]
            dest = next((d for d in dests if d.get("loggingDestination") == "SYSLOG_SERVERS"), None)
            dpath = f"{base}/{LISTS['logging_destinations']}"
            if server_level == "OFF":
                if dest:
                    changes["syslog_destination"] = {
                        "from": destination_row(dest)["all_events"],
                        "to": "removed",
                    }
                    steps.append(("destination", "DELETE", f"{dpath}/{dest['id']}", None))
            else:
                want = {"filterCriteria": "SEVERITY", "value": server_level}
                if dest is None:
                    body = {
                        "type": "LoggingDestination",
                        "loggingDestination": "SYSLOG_SERVERS",
                        "allEventConfig": want,
                    }
                    changes["syslog_destination"] = {"from": None, "to": f"SEVERITY {server_level}"}
                    steps.append(("destination", "POST", dpath, body))
                elif dest.get("allEventConfig") != want:
                    body = {**editable(dest), "allEventConfig": want}
                    changes["syslog_destination"] = {
                        "from": destination_row(dest)["all_events"],
                        "to": f"SEVERITY {server_level}",
                    }
                    steps.append(("destination", "PUT", f"{dpath}/{dest['id']}", body))

        if not steps and not blockers:
            blockers.append("Nothing to change.")

        async def apply() -> Any:
            done: list[str] = []
            try:
                for name, method, spath, sbody in steps:
                    try:
                        if method == "DELETE":
                            await app.api.delete(spath)
                        elif method == "POST":
                            await app.api.post(spath, sbody)
                        else:
                            await app.api.put(spath, sbody)
                    except Exception as e:
                        rest = [n for n, *_ in steps][len(done) :]
                        raise UpstreamError(
                            f"Step {name!r} failed ({e}). Applied: {done or 'none'}; not applied: {rest}. "
                            "Check with fmc_get_platform_settings, then repeat the call.",
                            getattr(e, "status_code", None),
                        ) from e
                    done.append(name)
            finally:
                app.invalidate_cache()
            return {"applied": done, "next": "fmc_deploy to the devices using this policy"}

        return await fmc_preview(
            ctx,
            tool="fmc_configure_syslog",
            owned=[pol],
            args={
                "policy": policy,
                "add_servers": add_servers,
                "remove_servers": remove_servers,
                "protocol": protocol,
                "port": port,
                "interfaces": interfaces,
                "via_management": via_management,
                "emblem": emblem,
                "secure": secure,
                "logging_enabled": logging_enabled,
                "server_level": server_level,
                "facility": facility,
                "timestamp_format": timestamp_format,
                "emblem_format": emblem_format,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Change syslog settings of platform settings policy {pol.get('name')!r}",
                details={"changes": changes, "assigned_to": await assigned_devices(app, pid, domain)},
                fingerprint=fingerprint,
                blockers=blockers,
                side_effects=["Reaches the assigned devices on the next deployment."],
            ),
            apply=apply,
        )

    @reg.write(title="Set access policy logging (syslog)")
    async def fmc_set_access_logging(
        ctx: Context,
        policy: Annotated[str, Field(description="Access control policy name or UUID")],
        use_platform_syslog: Annotated[
            bool | None,
            Field(
                description="Send connection events to the syslog servers of the device's platform settings"
            ),
        ] = None,
        severity: Annotated[
            Severity | None,
            Field(description="Severity for those syslog messages (with use_platform_syslog)"),
        ] = None,
        ips_syslog: Annotated[
            bool | None, Field(description="Also send intrusion events to the platform-settings syslog")
        ] = None,
        file_malware_syslog: Annotated[
            bool | None,
            Field(description="Also send file and malware events to the platform-settings syslog"),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Access control policy logging defaults (Logging tab): send connection, intrusion and
        file/malware events as syslog to the servers configured in the device's platform settings
        (fmc_configure_syslog). Rules still choose what to log (fmc_create_access_rule log=...).
        Deploy afterwards."""
        app: FmcApp = get_client(ctx)
        acp = await resolve_in(app, ACCESS, policy, "access policy", domain)
        page = await app.all(await app.config_path(f"{ACCESS}/{acp['id']}/loggingsettings", domain), cap=10)
        if not page.items:
            raise NotFound(f"Access policy {acp.get('name')!r} has no logging settings object.", 404)
        cur = page.items[0]
        desired = editable(cur)
        if use_platform_syslog is not None:
            desired["syslogConfigFromPlatformSetting"] = use_platform_syslog
        if severity:
            desired["severityForPlatformSettingSyslogConfig"] = severity
        if ips_syslog is not None:
            desired["enableipsSyslog"] = ips_syslog
            if ips_syslog:
                desired.setdefault("ipsSyslogSeverity", severity or "ALERT")
        if file_malware_syslog is not None:
            desired["enableFileAndMalwareSyslog"] = file_malware_syslog
            if file_malware_syslog:
                desired.setdefault("fileAndMalwareSyslogSeverity", severity or "ALERT")
        if (ips_syslog or file_malware_syslog) and not desired.get("syslogConfigFromPlatformSetting"):
            raise InvalidRequest(
                "Intrusion and file syslog here use the platform-settings syslog: set use_platform_syslog."
            )
        diff = field_changes(editable(cur), desired)
        path = await app.config_path(f"{ACCESS}/{acp['id']}/loggingsettings/{cur['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_set_access_logging",
            owned=[acp],
            args={
                "policy": policy,
                "use_platform_syslog": use_platform_syslog,
                "severity": severity,
                "ips_syslog": ips_syslog,
                "file_malware_syslog": file_malware_syslog,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Change logging settings of access policy {acp.get('name')!r}",
                details={"changes": diff},
                fingerprint=editable(cur),
                blockers=[] if diff else ["Nothing to change."],
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.put(path, desired)),
        )

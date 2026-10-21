"""Platform settings writes for F69: DNS (the server group the FTD resolves FQDN objects with), NetFlow export
to a collector, ICMP and HTTPS management access, and the login banner. Each section is one object per policy
(a singleton, edited with PUT); the preview shows the field changes. Changes reach the devices after
fmc_deploy. The syslog, NTP, SNMP and SSH writers are in platform_settings.py / platform_access.py."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import json
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    field_changes,
    get_client,
)
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import NETWORK_TYPES, RefResolver, network_literal
from fmc_mcp.tools.common import Domain, pick_by_name, ref_label, ref_of, resolve_object
from fmc_mcp.tools.device_config import network_by_value
from fmc_mcp.tools.object_writes import editable
from fmc_mcp.tools.platform_settings import (
    PS,
    PolicyRef,
    assigned_devices,
    banner_text,
    http_summary,
    icmp_summary,
    net_label,
    netflow_summary,
    resolve_ps,
    section,
    wrapper_labels,
)

DNS_GROUPS = "object/dnsservergroups"
ICMP_OBJECTS = "object/icmpv4objects"
ACLS = "object/extendedaccesslists"
MAX_DNS_SERVERS = 6  # an FTD DNS server group holds up to six servers
MAX_COLLECTORS = 5  # FMC: at most five NetFlow collectors
# FMC's UI defaults, sent when a section is first turned on (the GET of an untouched section omits them).
DNS_EXPIRY_MIN, DNS_POLL_MIN = 1, 240
NETFLOW_REFRESH_MIN, NETFLOW_TEMPLATE_MIN = 1, 30
DEFAULT_CLASS = "class-default"
DEFAULT_PORT = 2055  # NetFlow collectors' usual UDP port
BANNER_LINE_MAX = 510  # characters per banner line on the FTD
BANNER_LINES_MAX = 100
# FMC 10.0.1 / FTD 10.0 (live 2026-10-21): the banner is not part of 'show running-config banner' (it prints
# nothing), 'show banner' shows it; and a policy whose banner lines are emptied deploys no 'no banner', so the
# device keeps the last banner it got.
BANNER_VERIFY = "fmc_run_show_command(command='show banner')"
BANNER_CLEAR_WARNING = (
    "FMC 10.0.1 doesn't remove a deployed banner: with no banner lines the deploy sends no 'no banner', so "
    "the devices keep the old one (check with 'show banner'). To change what they show, set new text "
    "instead (e.g. one line); clearing only empties the policy."
)
BANNER_CLEARED = "cleared (policy only; the devices keep their banner until new text is deployed)"
FlowEvent = Literal["ALL", "CREATED", "DENIED", "UPDATED", "TORN_DOWN"]
# FMC 10.0.1 takes only interface groups for a NetFlow collector's interfaces (a security zone: 400 "Invalid
# selection for Interface group. Only Interface Group object of type Management/ Routed/ Switched is
# allowed.", recorded live 2026-10-21), and of these modes only.
NETFLOW_GROUP_MODES = ("ROUTED", "SWITCHED", "MANAGEMENT")
DEPLOY_NOTE = "Takes effect on the assigned devices after the next deployment."


class TrafficClassSpec(BaseModel):
    """Which traffic a NetFlow class exports, and which flow events."""

    name: str = Field(
        min_length=1, max_length=64, description="Traffic class name (class-default without access_list)"
    )
    access_list: str | None = Field(
        None,
        description="Extended access list object selecting the traffic; omit for all traffic (FMC's "
        "class-default)",
    )
    events: list[FlowEvent] = Field(
        default_factory=lambda: list[FlowEvent](["ALL"]),
        min_length=1,
        description="Flow events to export (default ALL)",
    )


async def _singleton(app: FmcApp, pol_id: str, sub: str, domain: str | None) -> tuple[str, dict[str, Any]]:
    """(PUT path, current object) of a one-per-policy section."""
    items = await section(app, pol_id, sub, domain)
    if not items:
        raise NotFound(f"The platform settings policy has no {sub} section.", 404)
    return await app.config_path(f"{PS}/{pol_id}/{sub}/{items[0]['id']}", domain), items[0]


def _ref(obj: dict[str, Any], fmc_type: str | None = None) -> dict[str, Any]:
    return {"id": obj["id"], "type": fmc_type or obj.get("type"), "name": obj.get("name")}


def _zones(block: dict[str, Any] | None) -> dict[str, Any]:
    return {"objects": list((block or {}).get("objects") or [])}


async def _apply_steps(app: FmcApp, steps: list[tuple[str, Callable[[], Awaitable[Any]]]]) -> dict[str, Any]:
    """Run the steps in order; a failure names what was and wasn't applied."""
    done: list[str] = []
    try:
        for name, fn in steps:
            try:
                await fn()
            except Exception as e:
                rest = [n for n, _ in steps][len(done) :]
                raise UpstreamError(
                    f"Step {name!r} failed ({e}). Applied: {done or 'none'}; not applied: {rest}. "
                    "Check with fmc_get_platform_settings, then repeat the call.",
                    getattr(e, "status_code", None),
                ) from e
            done.append(name)
    finally:
        app.invalidate_cache()
    return {"applied": done, "next": "fmc_deploy to the devices using this policy"}


# --- tools --------------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Configure DNS (platform settings)")
    async def fmc_configure_dns(
        ctx: Context,
        policy: PolicyRef,
        servers: Annotated[
            list[str] | None,
            Field(
                description="DNS server IPs (up to 6). Creates the DNS server group (named server_group, "
                "default '<policy>-dns') on confirm, or reuses the group of that name when it has exactly "
                "these servers"
            ),
        ] = None,
        server_group: Annotated[
            str | None,
            Field(description="An existing DNS server group object; with `servers`, the new group's name"),
        ] = None,
        domain_name: Annotated[
            str | None, Field(max_length=63, description="Default domain of a new server group")
        ] = None,
        interfaces: Annotated[
            list[str] | None,
            Field(
                description="Security zones / interface groups the device sends DNS lookups through; "
                "[] clears"
            ),
        ] = None,
        lookup_via_management: Annotated[
            bool | None, Field(description="Also look up through the management/diagnostic interface")
        ] = None,
        poll_minutes: Annotated[
            int | None, Field(ge=1, le=65535, description="FQDN poll timer (re-resolve interval)")
        ] = None,
        expiry_minutes: Annotated[
            int | None, Field(ge=1, le=65535, description="Expire entry timer for unused resolutions")
        ] = None,
        disable: Annotated[
            bool,
            Field(
                description="Remove the DNS server groups. FMC 10.0.1 refuses this once a group is set (a "
                "default group is mandatory on every update): the preview says so and what to do instead"
            ),
        ] = False,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """DNS for the FTDs using a platform settings policy: the DNS server group they resolve FQDN
        objects with (an FQDN rule deploys fine and never matches without one), the interfaces lookups use,
        lookups through management, and the poll/expiry timers. Give `servers` to create the group (or
        reuse the same-named one when it has the same servers) or `server_group` for an existing one; it
        becomes the default group. FMC keeps a default group once one is set (removing DNS over the API is
        refused: assign the devices another platform settings policy instead). Deploy afterwards; verify
        with fmc_run_show_command('show running-config dns')."""
        app: FmcApp = get_client(ctx)
        if disable and (servers or server_group):
            raise InvalidRequest("Give servers / server_group, or disable=true, not both.")
        pol = await resolve_ps(app, policy, domain)
        path, cur = await _singleton(app, pol["id"], "dnssettings", domain)
        blockers: list[str] = []
        create: dict[str, Any] | None = None
        group_ref: dict[str, Any] | None = None
        want = list(dict.fromkeys(s.strip() for s in servers or [] if s.strip()))
        for s in want:
            try:
                ipaddress.ip_address(s)
            except ValueError:
                raise InvalidRequest(f"DNS server {s!r} is not an IP address.") from None
        if len(want) > MAX_DNS_SERVERS:
            raise InvalidRequest(f"A DNS server group holds at most {MAX_DNS_SERVERS} servers.")
        if want or server_group:
            groups = (await app.all(await app.config_path(DNS_GROUPS, domain))).items
            name = (server_group or f"{pol.get('name')}-dns").strip()
            hit = next((g for g in groups if str(g.get("name", "")).lower() == name.lower()), None)
            if not want:
                group_ref = _ref(pick_by_name(groups, name, "DNS server group"), "DNSServerGroupObject")
            elif hit is not None:
                have = [str(d.get("name-server")) for d in hit.get("dnsservers") or []]
                if {ipaddress.ip_address(h) for h in have if _is_ip(h)} != {
                    ipaddress.ip_address(s) for s in want
                }:
                    blockers.append(
                        f"DNS server group {hit.get('name')!r} exists with servers {have}; pass "
                        "server_group without servers to use it, or another server_group name for a new one."
                    )
                group_ref = _ref(hit, "DNSServerGroupObject")
            else:
                create = {
                    "name": name,
                    "type": "DNSServerGroupObject",
                    "dnsservers": [{"name-server": s} for s in want],
                    "retries": 2,
                    "timeout": 2,
                }
                if domain_name:
                    create["defaultdomain"] = domain_name
                group_ref = {"type": "DNSServerGroupObject", "name": name}  # id filled on confirm
        desired = editable(cur)
        if group_ref is not None:
            others = [
                g
                for g in desired.get("dnsServerGroups") or []
                if not g.get("isDefault")
                and str((g.get("dnsServerGroup") or {}).get("name", "")).lower() != group_ref["name"].lower()
            ]
            desired["dnsServerGroups"] = [*others, {"dnsServerGroup": group_ref, "isDefault": True}]
        if disable:
            _set_list(desired, cur, "dnsServerGroups", [])
            if cur.get("dnsServerGroups"):
                # FMC 10.0.1 (live 2026-10-21): every DNSSetting PUT without a default group is refused, with
                # `dnsServerGroups: []`, without the field, with or without interfaces: 400 "One DNS server
                # group must be set as the default group. Default DNS server group is not configured."
                blockers.append(
                    "FMC won't remove a platform settings policy's DNS server groups once one is set: every "
                    'update needs a default group ("One DNS server group must be set as the default group"). '
                    "To stop the devices resolving through it, assign them a platform settings policy "
                    "without DNS (fmc_assign_policy kind='platform_settings'); to change the servers, pass "
                    "server_group (or servers) for the new default group."
                )
        if interfaces is not None:
            block = await RefResolver(app, domain).block(interfaces, "zone") if interfaces else None
            _set_list(desired, cur, "interfaceObjects", list((block or {}).get("objects") or []))
        if lookup_via_management is not None:
            desired["enableLookupViaMgmt"] = lookup_via_management
        if poll_minutes is not None:
            desired["pollTimerInMins"] = poll_minutes
        if expiry_minutes is not None:
            desired["expiryTimerInMins"] = expiry_minutes
        if desired.get("dnsServerGroups"):
            desired.setdefault("expiryTimerInMins", DNS_EXPIRY_MIN)
            desired.setdefault("pollTimerInMins", DNS_POLL_MIN)
        changes = field_changes(editable(cur), desired, replace=True)
        if not changes and not create and not blockers:
            blockers.append("Nothing to change.")
        if not desired.get("dnsServerGroups") and not disable and not blockers:
            blockers.append("No DNS server group: give servers or server_group.")

        made: dict[str, Any] = {}  # the server group created on confirm

        async def put_settings() -> Any:
            body = dict(desired)
            if "ref" in made:
                body["dnsServerGroups"] = [
                    {**g, "dnsServerGroup": made["ref"]} if not g["dnsServerGroup"].get("id") else g
                    for g in body["dnsServerGroups"]
                ]
            return await app.api.put(path, body)

        # Separate steps: a failed PUT after the POST reports the group as created (a repeat reuses it).
        steps: list[tuple[str, Callable[[], Awaitable[Any]]]] = [("dns", put_settings)]
        if create is not None:
            group_body: dict[str, Any] = create

            async def create_group() -> None:
                obj = await app.api.post(await app.config_path(DNS_GROUPS, domain), group_body)
                made["ref"] = _ref(
                    {**obj, "name": obj.get("name") or group_body["name"]}, "DNSServerGroupObject"
                )

            steps.insert(0, (f"server group {group_body['name']}", create_group))

        return await fmc_preview(
            ctx,
            tool="fmc_configure_dns",
            owned=[pol],
            args={
                "policy": policy,
                "servers": servers,
                "server_group": server_group,
                "domain_name": domain_name,
                "interfaces": interfaces,
                "lookup_via_management": lookup_via_management,
                "poll_minutes": poll_minutes,
                "expiry_minutes": expiry_minutes,
                "disable": disable,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"DNS in platform settings {pol.get('name')!r}",
                details={
                    "changes": changes,
                    "creates_server_group": {"name": create["name"], "servers": want} if create else None,
                    "assigned_to": await assigned_devices(app, pol["id"], domain),
                },
                fingerprint=editable(cur),
                blockers=blockers,
                side_effects=[DEPLOY_NOTE],
            ),
            apply=lambda: _apply_steps(app, steps),
        )

    @reg.write(title="Configure NetFlow export (platform settings)")
    async def fmc_configure_netflow(
        ctx: Context,
        policy: PolicyRef,
        collector: Annotated[
            str | None,
            Field(
                description="NetFlow collector: IP or host object name; added, or updated if already there"
            ),
        ] = None,
        port: Annotated[
            int | None, Field(ge=1, le=65535, description="Collector UDP port (new collectors: 2055)")
        ] = None,
        interfaces: Annotated[
            list[str] | None,
            Field(
                description="Interface groups (routed, switched or management; FMC takes no security zone "
                "here) the collector is reached through (needed for a new collector)"
            ),
        ] = None,
        traffic_classes: Annotated[
            list[TrafficClassSpec] | None,
            Field(
                description="Replace the traffic classes; each exports its events to `collector` (or to "
                "every collector when none is given). Default for a first collector: class-default, ALL "
                "events"
            ),
        ] = None,
        remove_collector: Annotated[
            str | None, Field(description="Collector (IP or host object name) to remove, with its exports")
        ] = None,
        enable: Annotated[
            bool | None, Field(description="Turn NetFlow export on/off (adding a collector turns it on)")
        ] = None,
        collector_name: Annotated[
            str | None,
            Field(
                max_length=64,
                description="Name of the Host object created when `collector` is an IP no host object has "
                "(default nf-collector-<ip>)",
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """NetFlow (NSEL) export from the FTDs using a platform settings policy: flow collectors (host,
        UDP port, the interface groups it is reached through; at most five), the traffic classes that
        export flow events to them (class-default = all traffic, or an extended access list) and on/off.
        FMC takes interface groups here, not security zones (the preview refuses a zone and shows the
        interface group to create from its interfaces). The preview shows every field that changes. Deploy
        afterwards; verify with fmc_run_show_command('show running-config flow-export') and the collector's
        own counters."""
        app: FmcApp = get_client(ctx)
        if collector and remove_collector:
            raise InvalidRequest("Add or remove a collector per call, not both.")
        pol = await resolve_ps(app, policy, domain)
        path, cur = await _singleton(app, pol["id"], "netflowpolicies", domain)
        resolver = RefResolver(app, domain)
        desired = editable(cur)
        collectors = [dict(c) for c in desired.get("flowCollectors") or []]
        classes = [dict(c) for c in desired.get("trafficClasses") or []]
        blockers: list[str] = []
        create_host: dict[str, Any] | None = None
        target: dict[str, Any] | None = None

        def same(a: dict[str, Any], b: dict[str, Any]) -> bool:
            if a.get("id") and b.get("id"):
                return bool(str(a["id"]).lower() == str(b["id"]).lower())
            return str(a.get("name", "")).lower() == str(b.get("name", "")).lower()

        notes: list[str] = []
        if collector:
            target, create_host = await _collector_ref(app, resolver, collector, collector_name, domain)
            if collector_name and create_host is None:
                notes.append(
                    f"{collector!r} is the existing object {target.get('name')!r}, used as the collector; "
                    f"collector_name {collector_name!r} is not used."
                )
            existing = next((c for c in collectors if same(c.get("collectorHost") or {}, target)), None)
            block: dict[str, Any] | None = None
            refused: list[str] = []
            if interfaces:
                block, refused = await _netflow_interfaces(app, interfaces, domain)
                blockers += refused
            if existing is not None:
                if port is not None:
                    existing["port"] = port
                if block:
                    existing["interfaces"] = _zones(block)
            else:
                if not block and not refused:  # none given, or only blank names
                    raise InvalidRequest(
                        "Give the interfaces (interface groups) the new collector is reached through."
                    )
                if len(collectors) >= MAX_COLLECTORS:
                    blockers.append(f"FMC allows at most {MAX_COLLECTORS} NetFlow collectors.")
                collectors.append(
                    {"collectorHost": target, "port": port or DEFAULT_PORT, "interfaces": _zones(block)}
                )
                if traffic_classes is None:
                    if not classes:
                        classes = [_class(DEFAULT_CLASS, None, [target], ["ALL"])]
                    else:  # existing classes also export to the new collector, with their events
                        for c in classes:
                            ev = ((c.get("exportFlows") or [{}])[0]).get("eventType") or ["ALL"]
                            c["exportFlows"] = [
                                *(c.get("exportFlows") or []),
                                {"collectorHost": target, "eventType": ev},
                            ]
                if enable is None:  # a new collector turns export on
                    desired["enable"] = True
        if remove_collector:
            gone, _ = await _collector_ref(app, resolver, remove_collector, None, domain, lookup_only=True)
            kept = [c for c in collectors if not same(c.get("collectorHost") or {}, gone)]
            if len(kept) == len(collectors):
                names = ", ".join(ref_label(c.get("collectorHost") or {}) for c in collectors) or "none"
                blockers.append(f"No collector {remove_collector!r} to remove (collectors: {names}).")
            collectors = kept
            for c in classes:
                c["exportFlows"] = [
                    e for e in c.get("exportFlows") or [] if not same(e.get("collectorHost") or {}, gone)
                ]
            classes = [c for c in classes if c.get("exportFlows")]
        if traffic_classes is not None:
            dests = [target] if target else [c["collectorHost"] for c in collectors]
            if not dests:
                raise InvalidRequest(
                    "Traffic classes export to a collector: give `collector` or add one first."
                )
            if sum(1 for t in traffic_classes if not t.access_list) > 1:
                raise InvalidRequest("Only one traffic class can match all traffic (no access_list).")
            classes = []
            for spec in traffic_classes:
                acl = None
                if spec.access_list:
                    acls = (await app.all(await app.config_path(ACLS, domain), expanded=False)).items
                    acl = _ref(
                        pick_by_name(acls, spec.access_list, "extended access list"), "ExtendedAccessList"
                    )
                name = spec.name if acl else DEFAULT_CLASS  # the FTD's catch-all class has this name
                classes.append(_class(name, acl, dests, [str(e) for e in dict.fromkeys(spec.events)]))
        _set_list(desired, cur, "flowCollectors", collectors)
        _set_list(desired, cur, "trafficClasses", classes)
        if enable is not None:
            desired["enable"] = enable
        if desired.get("enable"):
            if not collectors:
                blockers.append("NetFlow export needs a collector: give `collector`.")
            desired.setdefault("refreshInterval", NETFLOW_REFRESH_MIN)
            desired.setdefault("templateExportTime", NETFLOW_TEMPLATE_MIN)
        changes = field_changes(editable(cur), desired, replace=True)
        if not changes and not blockers:
            blockers.append("Nothing to change.")

        made: dict[str, Any] = {}  # the collector host object created on confirm

        async def put_netflow() -> Any:
            body = dict(desired)
            if "ref" in made:
                body = _fill_host(body, made["placeholder"], made["ref"])
            return await app.api.put(path, body)

        # Separate steps: a failed PUT after the POST reports the host as created (a repeat reuses it).
        steps: list[tuple[str, Callable[[], Awaitable[Any]]]] = [("netflow", put_netflow)]
        if create_host is not None:
            host_body: dict[str, Any] = create_host

            async def create_collector_host() -> None:
                obj = await app.api.post(await app.config_path("object/hosts", domain), host_body)
                ref = {"id": obj["id"], "type": "Host", "name": obj.get("name") or host_body["name"]}
                made.update(placeholder=host_body["name"], ref=ref)

            steps.insert(0, (f"host {host_body['name']}", create_collector_host))

        return await fmc_preview(
            ctx,
            tool="fmc_configure_netflow",
            owned=[pol],
            args={
                "policy": policy,
                "collector": collector,
                "port": port,
                "interfaces": interfaces,
                "traffic_classes": [t.model_dump() for t in traffic_classes]
                if traffic_classes is not None
                else None,
                "remove_collector": remove_collector,
                "enable": enable,
                "collector_name": collector_name,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"NetFlow in platform settings {pol.get('name')!r}",
                details={
                    "changes": changes,
                    "after": netflow_summary(desired),
                    "creates_host_object": create_host,
                    "assigned_to": await assigned_devices(app, pol["id"], domain),
                    **({"notes": notes} if notes else {}),
                },
                fingerprint=editable(cur),
                blockers=blockers,
                side_effects=[DEPLOY_NOTE],
            ),
            apply=lambda: _apply_steps(app, steps),
        )

    @reg.write(title="Configure ICMP / HTTPS management access")
    async def fmc_configure_mgmt_access(
        ctx: Context,
        policy: PolicyRef,
        kind: Annotated[
            Literal["icmp", "http"],
            Field(
                description="icmp: which hosts may ICMP the device's interfaces; http: HTTPS server access"
            ),
        ],
        action: Annotated[Literal["allow", "remove"], Field(description="Add or remove entries")] = "allow",
        networks: Annotated[
            list[str] | None,
            Field(
                description="Source networks (CIDR, IP or network object name). http needs network objects: "
                "a CIDR is matched to an existing object with that value"
            ),
        ] = None,
        interfaces: Annotated[
            list[str] | None, Field(description="Security zones / interface groups the entries apply to")
        ] = None,
        icmp_action: Annotated[
            Literal["permit", "deny"], Field(description="icmp: permit or deny these hosts")
        ] = "permit",
        icmp_service: Annotated[
            str | None,
            Field(
                description="icmp: ICMPv4 object (e.g. echo). FMC needs one on every entry; omitted (allow): "
                "an ICMPv4 object with no type (every ICMP type) is used, or '<policy>-icmp-any' is created "
                "on confirm; omitted (remove): entries of any service"
            ),
        ] = None,
        http_server: Annotated[
            bool | None, Field(description="http: turn the HTTPS server on/off (allow entries turn it on)")
        ] = None,
        http_port: Annotated[int | None, Field(ge=1, le=65535, description="http: HTTPS server port")] = None,
        rate_limit: Annotated[
            int | None, Field(ge=1, le=100, description="icmp: unreachable messages per second")
        ] = None,
        burst_size: Annotated[
            int | None, Field(ge=1, le=10, description="icmp: unreachable burst size")
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Management access on the FTD data interfaces: ICMP (which hosts may ping or send ICMP to the
        device's interfaces, permit/deny, rate limit for unreachables) or the HTTPS server (on/off, port,
        which networks may reach it through which zones). SSH: fmc_configure_ssh_access. FMC 10.0.1 needs an
        ICMP service object on every ICMP entry: without icmp_service an existing 'any' ICMPv4 object is
        used or one is created (the preview names it). The preview shows the entries before and after.
        Deploy afterwards; verify with fmc_run_show_command('show running-config icmp' / 'show
        running-config http')."""
        app: FmcApp = get_client(ctx)
        pol = await resolve_ps(app, policy, domain)
        sub = "icmpsettings" if kind == "icmp" else "httpaccesssettings"
        list_key = "icmpConfigs" if kind == "icmp" else "httpConfiguration"
        path, cur = await _singleton(app, pol["id"], sub, domain)
        resolver = RefResolver(app, domain)
        desired = editable(cur)
        entries = [dict(e) for e in desired.get(list_key) or []]
        blockers: list[str] = []
        if networks and not interfaces and action == "allow":
            raise InvalidRequest("Give the interfaces (zones) the entries apply to.")
        zones = _zones(await resolver.block(interfaces, "zone")) if interfaces else {"objects": []}
        zone_names = wrapper_labels(zones)
        service = await resolver.single(icmp_service, ["icmpv4"], "ICMPv4 object") if icmp_service else None
        create_icmp: dict[str, Any] | None = None
        if kind == "icmp" and action == "allow" and networks and service is None:
            # FMC 10.0.1: "'icmpService' configuration missing. ICMP Service configuration is mandatory for
            # ICMP Access." (live 2026-10-21) -- an entry without a service is refused on the PUT
            service, create_icmp = await _any_icmp_service(app, str(pol.get("name") or "policy"), domain)
        any_service = kind == "icmp" and action == "remove" and not icmp_service
        for raw in dict.fromkeys(n.strip() for n in networks or [] if n.strip()):
            if kind == "icmp":
                lit = network_literal(raw)
                net: dict[str, Any] = (
                    {"literal": lit["value"]} if lit else {"object": await resolver.obj(raw, NETWORK_TYPES)}
                )
                row: dict[str, Any] = {
                    "icmpAction": icmp_action.capitalize(),
                    "network": net,
                    "interfaces": zones,
                }
                if service:
                    row["icmpService"] = service
            else:
                obj = await _network_object(app, resolver, raw, domain)
                if obj is None:
                    blockers.append(
                        f"No network object with the value {raw}: create one (fmc_create_object); HTTPS "
                        "access takes objects only."
                    )
                    continue
                row = {"ipAddress": obj, "interfaces": zones}
            any_zone = action == "remove" and not interfaces  # remove: without interfaces, from every zone
            match = [
                e for e in entries if _same_entry(e, row, kind, any_zone=any_zone, any_service=any_service)
            ]
            if action == "allow":
                if match:
                    blockers.append(f"{raw} via {', '.join(zone_names)} is already allowed.")
                else:
                    entries.append(row)
            elif not match:
                where = f" via {', '.join(zone_names)}" if zone_names else ""
                blockers.append(f"No {kind} entry for {raw}{where}.")
            else:
                entries = [e for e in entries if e not in match]
        if networks:
            _set_list(desired, cur, list_key, entries)
        if kind == "icmp":
            if rate_limit is not None:
                desired["rateLimit"] = str(rate_limit)
            if burst_size is not None:
                desired["burstSize"] = str(burst_size)
        else:
            if http_server is not None:
                desired["enableHttpServer"] = http_server
            elif action == "allow" and networks:
                desired["enableHttpServer"] = True
            if http_port is not None:
                desired["port"] = http_port
        changes = field_changes(editable(cur), desired, replace=True)
        if not changes and not blockers:
            blockers.append("Nothing to change.")
        summary = icmp_summary if kind == "icmp" else http_summary
        made: dict[str, Any] = {}  # the ICMPv4 'any' object created on confirm

        async def put_access() -> Any:
            body = dict(desired)
            if "ref" in made:
                body[list_key] = [
                    {**e, "icmpService": made["ref"]}
                    if not (e.get("icmpService") or {}).get("id")
                    and (e.get("icmpService") or {}).get("name") == made["ref"]["name"]
                    else e
                    for e in body.get(list_key) or []
                ]
            return await app.api.put(path, body)

        steps: list[tuple[str, Callable[[], Awaitable[Any]]]] = [(kind, put_access)]
        if create_icmp is not None:
            icmp_body: dict[str, Any] = create_icmp

            async def create_service() -> None:
                obj = await app.api.post(await app.config_path(ICMP_OBJECTS, domain), icmp_body)
                made["ref"] = _ref({**obj, "name": obj.get("name") or icmp_body["name"]}, "ICMPV4Object")

            steps.insert(0, (f"ICMPv4 object {icmp_body['name']}", create_service))
        return await fmc_preview(
            ctx,
            tool="fmc_configure_mgmt_access",
            owned=[pol],
            args={
                "policy": policy,
                "kind": kind,
                "action": action,
                "networks": networks,
                "interfaces": interfaces,
                "icmp_action": icmp_action,
                "icmp_service": icmp_service,
                "http_server": http_server,
                "http_port": http_port,
                "rate_limit": rate_limit,
                "burst_size": burst_size,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"{kind.upper()} access in platform settings {pol.get('name')!r}",
                details={
                    "before": summary(cur),
                    "after": summary(desired),
                    "changes": changes,
                    **({"creates_icmp_object": create_icmp} if create_icmp else {}),
                    "assigned_to": await assigned_devices(app, pol["id"], domain),
                },
                fingerprint={"section": editable(cur), "icmp_service": service},
                blockers=blockers,
                side_effects=[DEPLOY_NOTE],
            ),
            apply=lambda: _apply_steps(app, steps),
        )

    @reg.write(title="Set login banner (platform settings)")
    async def fmc_set_banner(
        ctx: Context,
        policy: PolicyRef,
        text: Annotated[
            str,
            Field(
                max_length=20000,
                description="Banner shown before login (SSH, console); lines split on newlines; '' empties "
                "the policy's banner (FMC 10.0.1 then leaves the deployed one on the devices). $(hostname) "
                "and $(domain) are filled in by the device",
            ),
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Set (or clear) the login banner of the FTDs using a platform settings policy, e.g. the legal
        'authorised use only' notice. The preview shows the banner before and after. Deploy afterwards;
        verify with fmc_run_show_command('show banner') ('show running-config banner' prints nothing on
        FTD 10.0). Clearing: FMC 10.0.1 deploys no 'no banner', so the devices keep the old banner (the
        preview warns); replace the text instead."""
        app: FmcApp = get_client(ctx)
        lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").split("\n")]
        while lines and not lines[-1]:
            lines.pop()
        if len(lines) > BANNER_LINES_MAX:
            raise InvalidRequest(f"The banner has {len(lines)} lines; keep it to {BANNER_LINES_MAX}.")
        long = [i + 1 for i, ln in enumerate(lines) if len(ln) > BANNER_LINE_MAX]
        if long:
            raise InvalidRequest(f"Banner lines {long} are longer than {BANNER_LINE_MAX} characters.")
        pol = await resolve_ps(app, policy, domain)
        path, cur = await _singleton(app, pol["id"], "bannersettings", domain)
        desired = editable(cur)
        _set_list(desired, cur, "bannerText", lines)
        before, after = banner_text(cur), banner_text(desired)
        warnings = [BANNER_CLEAR_WARNING] if before and not after else []

        async def apply() -> Any:
            out = await _apply_steps(app, [("banner", lambda: app.api.put(path, desired))])
            out["verify"] = f"after the deploy: {BANNER_VERIFY}"
            if warnings:
                out["warning"] = warnings[0]
            return out

        return await fmc_preview(
            ctx,
            tool="fmc_set_banner",
            owned=[pol],
            args={"policy": policy, "text": text, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Login banner in platform settings {pol.get('name')!r}: "
                + ("set" if lines else BANNER_CLEARED),
                details={
                    "before": before,
                    "after": after,
                    "assigned_to": await assigned_devices(app, pol["id"], domain),
                    **({"warnings": warnings} if warnings else {}),
                },
                fingerprint=editable(cur),
                blockers=[] if before != after else ["Nothing to change."],
                side_effects=[DEPLOY_NOTE],
            ),
            apply=apply,
        )


# --- helpers ------------------------------------------------------------------------------------------


def _set_list(desired: dict[str, Any], cur: dict[str, Any], key: str, value: list[Any]) -> None:
    """Put a list field into a PUT body: [] clears one the current object has; a list FMC never had and
    that stays empty is left out (FMC omits unset lists on read, so [] would show as a change)."""
    if value or cur.get(key):
        desired[key] = value
    else:
        desired.pop(key, None)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _class(
    name: str, acl: dict[str, Any] | None, dests: list[dict[str, Any]], events: list[str]
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "trafficClassName": name,
        "trafficClassType": "ACCESS_LIST" if acl else "DEFAULT",
        "exportFlows": [{"collectorHost": d, "eventType": events} for d in dests],
    }
    if acl:
        out["extendedAccessList"] = acl
    return out


def _fill_host(body: dict[str, Any], name: str, ref: dict[str, Any]) -> dict[str, Any]:
    """The NetFlow body with the placeholder collector (no id yet) replaced by the created host object."""

    def fix(h: Any) -> Any:
        return ref if isinstance(h, dict) and not h.get("id") and h.get("name") == name else h

    out = dict(body)
    out["flowCollectors"] = [
        {**c, "collectorHost": fix(c.get("collectorHost"))} for c in body.get("flowCollectors") or []
    ]
    out["trafficClasses"] = [
        {
            **c,
            "exportFlows": [
                {**e, "collectorHost": fix(e.get("collectorHost"))} for e in c.get("exportFlows") or []
            ],
        }
        for c in body.get("trafficClasses") or []
    ]
    if "flowCollectors" not in body:
        out.pop("flowCollectors")
    if "trafficClasses" not in body:
        out.pop("trafficClasses")
    return out


async def _collector_ref(
    app: FmcApp,
    resolver: RefResolver,
    value: str,
    name: str | None,
    domain: str | None,
    *,
    lookup_only: bool = False,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """(reference, host object to create or None) for a collector given as an IP or a host object name.
    An IP no host object has becomes a placeholder {type, name} created on confirm (lookup_only: the
    placeholder is only matched against the configured collectors)."""
    v = value.strip()
    if _is_ip(v):
        ip = str(ipaddress.ip_address(v))
        found = await network_by_value(app, ip, domain)
        if found is not None:
            return _ref(found), None
        host = {"name": name or f"nf-collector-{ip.replace(':', '_')}", "type": "Host", "value": ip}
        return {"type": "Host", "name": host["name"]}, None if lookup_only else host
    return await resolver.single(v, ["host", "network"], "collector host object"), None


async def _netflow_interfaces(
    app: FmcApp, names: list[str], domain: str | None
) -> tuple[dict[str, Any] | None, list[str]]:
    """({"objects": [interface groups]} or None, blockers) for a NetFlow collector's `interfaces`. A security
    zone is refused (FMC 10.0.1 rejects it on the PUT) with the interface group to create from its
    interfaces; so is an interface group of a mode FMC doesn't take here."""
    objects: list[dict[str, Any]] = []
    blockers: list[str] = []
    for raw in dict.fromkeys(n.strip() for n in names if n.strip()):
        t, obj = await resolve_object(app, raw, domain, ["interface_group", "security_zone"])
        mode = str(obj.get("interfaceMode") or "ROUTED").upper()
        if t.key == "security_zone":
            ifs = [{k: i[k] for k in ("type", "id", "name") if i.get(k)} for i in obj.get("interfaces") or []]
            body = {"type": "InterfaceGroup", "name": f"{obj.get('name')}-ifg", "interfaceMode": mode}
            path = await app.config_path("object/interfacegroups", domain)
            blockers.append(
                f"{obj.get('name')!r} is a security zone; FMC takes only interface groups for a NetFlow "
                "collector ('Only Interface Group object of type Management/ Routed/ Switched is allowed'). "
                + (
                    f"Create one with the zone's interfaces: fmc_api_call(method='POST', path='{path}', "
                    f"body={json.dumps({**body, 'interfaces': ifs})}) (no 'device' key in the interface "
                    "entries), then pass its name."
                    if ifs
                    else "The zone has no interfaces: create an interface group with the collector-side "
                    f"interfaces (fmc_api_call POST {path}) and pass its name."
                )
            )
            continue
        if mode not in NETFLOW_GROUP_MODES:
            blockers.append(
                f"Interface group {obj.get('name')!r} is {mode}; NetFlow takes "
                f"{', '.join(m.lower() for m in NETFLOW_GROUP_MODES)} interface groups."
            )
        objects.append(ref_of(obj))
    return ({"objects": objects} if objects else None), blockers


async def _network_object(
    app: FmcApp, resolver: RefResolver, value: str, domain: str | None
) -> dict[str, Any] | None:
    """A network/host object reference for a CIDR/IP (matched by value) or an object name."""
    lit = network_literal(value)
    if lit:
        found = await network_by_value(app, value, domain) if lit["type"] != "Range" else None
        return _ref(found) if found is not None else None
    return await resolver.obj(value, NETWORK_TYPES)


async def _any_icmp_service(
    app: FmcApp, policy_name: str, domain: str | None
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """(reference, object to create or None) for an ICMPv4 service matching every ICMP type: an existing
    ICMPv4 object without a type ('<policy>-icmp-any' first, then by name), else a placeholder
    {type, name} for '<policy>-icmp-any', created on confirm (FMC 10.0.1 ships no ICMP objects)."""
    name = f"{policy_name}-icmp-any"[:64]
    page = await app.all(await app.config_path(ICMP_OBJECTS, domain))
    anys = [
        o
        for o in page.items
        if o.get("id") and str(o.get("icmpType") if o.get("icmpType") is not None else "any").lower() == "any"
    ]
    anys.sort(key=lambda o: (str(o.get("name", "")).lower() != name.lower(), str(o.get("name", "")).lower()))
    if anys:
        return _ref(anys[0], "ICMPV4Object"), None
    return {"type": "ICMPV4Object", "name": name}, {"name": name, "type": "ICMPV4Object"}


def _same_entry(
    a: dict[str, Any], b: dict[str, Any], kind: str, *, any_zone: bool = False, any_service: bool = False
) -> bool:
    """Two ICMP / HTTP access entries for the same network, zones (unless any_zone) and ICMP action and
    service (unless any_service)."""
    if not any_zone and wrapper_labels(a.get("interfaces")) != wrapper_labels(b.get("interfaces")):
        return False
    if kind == "http":
        return net_label(a.get("ipAddress")) == net_label(b.get("ipAddress"))

    def svc(e: dict[str, Any]) -> str:
        return ref_label(e["icmpService"]) if e.get("icmpService") else "any"

    return (
        net_label(a.get("network")) == net_label(b.get("network"))
        and str(a.get("icmpAction", "")).lower() == str(b.get("icmpAction", "")).lower()
        and (any_service or svc(a) == svc(b))
    )

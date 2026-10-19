"""Application-aware routing for Firewall SD-WAN (F51b): WAN interface settings (priority, path
monitoring, HTTP application monitoring), ECMP zones, and application routes (policy-based routing on
applications, networks or users, with the egress interface chosen by order, interface priority or the
best path metric: jitter, packet loss, round-trip time or MOS).

FMC stores an application route as an extended access list (the match: applications, networks,
ports, users) plus a forwarding action in the device's policy-based route for the ingress interfaces.
These tools build both, preview-first; nothing reaches the FTD until fmc_deploy. Check on the device
with fmc_sdwan_status (app routes and the WAN links they use) and fmc_get_routing; FMC 10.0.1's
command API doesn't pass 'show policy-route' or 'show path-monitoring' through.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import difflib
import ipaddress
from typing import Annotated, Any, Literal

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
)
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import RefResolver
from fmc_mcp.tools.common import Domain, ref_label
from fmc_mcp.tools.device_config import (
    InterfaceRef,
    device_interfaces,
    diff_rows,
    interface_put_body,
    pick_interface,
    resolve_device,
    routing_base,
)
from fmc_mcp.tools.devices import DEVICES, INTERFACE_KINDS, DeviceRef, interface_row
from fmc_mcp.tools.object_writes import applied, editable

EXT_ACLS = "object/extendedaccesslists"
APPLICATIONS = "object/applications"
# Interface kinds that carry path monitoring and a priority (routed, named data interfaces).
WAN_KINDS = ["physical", "subinterface", "etherchannel", "vlan", "vti"]

# How the egress interface is picked, as FMC 10.0.1 names it in `forwardingActionType`. ORDER and
# PRIORITY are in the spec's examples; the four metric types are FMC 7.2+ path-monitoring actions
# (Cisco's PBR-with-path-monitoring guide spells them SET_EGRESS_INTERFACE_BY_*, the payloads that
# work spell them SET_EGRESS_INTF_BY_*, like the two the spec shows). Pending live verification (F53).
ORDER_BY: dict[str, str] = {
    "order": "SET_EGRESS_INTF_BY_ORDER",
    "priority": "SET_EGRESS_INTF_BY_PRIORITY",
    "jitter": "SET_EGRESS_INTF_BY_JITTER",
    "loss": "SET_EGRESS_INTF_BY_LOST_PKTS",
    "rtt": "SET_EGRESS_INTF_BY_RTT",
    "mos": "SET_EGRESS_INTF_BY_MOS",
}
ORDER_LABEL = {v: k for k, v in ORDER_BY.items()} | {
    "SET_EGRESS_INTERFACE_BY_JITTER": "jitter",
    "SET_EGRESS_INTERFACE_BY_LOST_PKTS": "loss",
    "SET_EGRESS_INTERFACE_BY_RTT": "rtt",
    "SET_EGRESS_INTERFACE_BY_MOS": "mos",
}
METRIC_ORDERS = {"jitter", "loss", "rtt", "mos"}
OrderBy = Literal["order", "priority", "jitter", "loss", "rtt", "mos"]
PathMonitoring = Literal["off", "auto", "auto4", "auto6", "ip"]
PM_TYPES = {"auto": "AUTO", "auto4": "AUTO4", "auto6": "AUTO6"}

VrfParam = Annotated[
    str | None, Field(description="Virtual router (VRF) name/UUID; default the global table")
]
InterfaceList = Annotated[
    list[str],
    Field(description="Interface hardware names (Ethernet0/1), logical names (wan1) or UUIDs", min_length=1),
]


# --- helpers -------------------------------------------------------------------------------------


def iface_ref(i: dict[str, Any]) -> dict[str, Any]:
    """The {id, type, name, ifname} reference ECMP zones and policy-based routes take."""
    out = {"id": i["id"], "type": i.get("type"), "name": i.get("name")}
    if i.get("ifname"):
        out["ifname"] = i["ifname"]
    return out


def iface_label(ref: dict[str, Any]) -> str:
    name, ifname = ref.get("name"), ref.get("ifname")
    if name and ifname and name != ifname:
        return f"{name} ({ifname})"
    return str(ifname or name or ref.get("id"))


def wan_settings(i: dict[str, Any]) -> dict[str, Any]:
    """Priority, path monitoring (ICMP probes) and HTTP application monitoring of one interface."""
    pm = i.get("pathMonitoring") or {}
    am = i.get("applicationMonitoring") or {}
    if not pm.get("enable"):
        mode = "off"
    elif str(pm.get("type", "")).startswith("PEER_"):
        mode = "ip"
    else:
        mode = str(pm.get("type") or "AUTO").lower()
    return {
        "priority": i.get("priority", 0),
        "path_monitoring": mode,
        "monitored_ip": pm.get("monitoredIp") if mode == "ip" else None,
        "http_monitoring": bool(am.get("enable")),
        "monitored_applications": [ref_label(a) for a in am.get("monitoredApplications") or []] or None,
    }


def wan_row(kind: str, i: dict[str, Any]) -> dict[str, Any]:
    row = interface_row(kind, i)
    return {"interface": row["name"], "logical_name": row["logical_name"], **wan_settings(i)}


def is_wan_configured(i: dict[str, Any]) -> bool:
    s = wan_settings(i)
    return bool(s["priority"]) or s["path_monitoring"] != "off" or bool(s["monitored_applications"])


def pbr_summary(p: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": p.get("name"),
        "ingress": [iface_label(i) for i in p.get("ingressInterfaces") or []],
        "routes": [
            {
                "match": ref_label(a.get("matchCriteria") or {}),
                "order_by": ORDER_LABEL.get(
                    str(a.get("forwardingActionType")), a.get("forwardingActionType")
                ),
                "egress": [iface_label(i) for i in a.get("egressInterfaces") or []] or None,
                "next_hops": a.get("nextHopIPv4Addresses") or None,
            }
            for a in p.get("forwardingActions") or []
        ],
        "id": p.get("id"),
    }


async def collection(app: FmcApp, path: str, domain: str | None) -> list[dict[str, Any]]:
    """Every item of a device routing collection; a model without it (404/405) has none."""
    try:
        page = await app.all(await app.config_path(path, domain), cap=2000)
    except (NotFound, InvalidRequest):
        return []
    except UpstreamError as e:
        if e.status_code in (404, 405):
            return []
        raise
    seen: dict[str, dict[str, Any]] = {}
    for item in page.items:
        seen.setdefault(str(item.get("id") or len(seen)), item)
    return list(seen.values())


async def wan_interfaces(app: FmcApp, device_id: str, domain: str | None) -> list[dict[str, Any]]:
    """Interfaces with a priority, path monitoring or monitored applications set (fmc_get_routing)."""
    return [
        wan_row(kind, i)
        for kind, i in await device_interfaces(app, device_id, domain, WAN_KINDS)
        if i.get("ifname") and is_wan_configured(i)
    ]


def pick_named(
    items: list[tuple[str, dict[str, Any]]], refs: list[str], device: str, blockers: list[str]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ref in refs:
        _, iface = pick_interface(items, ref, device)
        if not iface.get("ifname"):
            blockers.append(f"{iface.get('name')} has no logical name; name it first (fmc_update_interface).")
        if any(o["id"] == iface["id"] for o in out):
            raise InvalidRequest(f"Interface {ref!r} is listed twice.")
        out.append(iface)
    return out


async def application_refs(app: FmcApp, names: list[str] | None, domain: str | None) -> list[dict[str, Any]]:
    """Application references by name (case-insensitive) or app id; FMC can't filter this list."""
    if not names:
        return []
    page = await app.all(await app.config_path(APPLICATIONS, domain), expanded=False, cap=20_000)
    by_name: dict[str, dict[str, Any]] = {}
    for a in page.items:
        by_name.setdefault(str(a.get("name", "")).lower(), a)
    by_id = {str(a.get("id")): a for a in page.items}
    out = []
    for raw in names:
        n = raw.strip()
        hit = by_name.get(n.lower()) or by_id.get(n)
        if hit is None:
            close = difflib.get_close_matches(n.lower(), list(by_name), n=5, cutoff=0.6)
            hint = f" Close: {', '.join(by_name[c]['name'] for c in close)}." if close else ""
            raise NotFound(f"No application {n!r} in FMC's application catalog.{hint}", 404)
        out.append({"id": str(hit["id"]), "type": "Application", "name": hit.get("name")})
    return out


async def find_acl(app: FmcApp, name: str, domain: str | None) -> dict[str, Any] | None:
    """An extended access list by name (listed in full: the spec documents no filter for these)."""
    page = await app.all(await app.config_path(EXT_ACLS, domain), expanded=False)
    hits = [a for a in page.items if str(a.get("name", "")).lower() == name.lower()]
    return hits[0] if hits else None


async def run_steps(app: FmcApp, steps: list[tuple[str, str, str, Any]]) -> list[str]:
    """Apply (name, method, path, body) in order; say what was already applied when one fails."""
    done: list[str] = []
    try:
        for name, method, path, body in steps:
            try:
                if method == "DELETE":
                    await app.api.delete(path)
                elif method == "POST":
                    await app.api.post(path, body)
                else:
                    await app.api.put(path, body)
            except Exception as e:
                raise UpstreamError(
                    f"{name} failed ({e}); already applied: {done or 'nothing'}.",
                    getattr(e, "status_code", None),
                ) from e
            done.append(name)
    finally:
        app.invalidate_cache()
    return done


# --- tools ---------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Configure WAN interface")
    async def fmc_configure_wan_interface(
        ctx: Context,
        device: DeviceRef,
        interface: InterfaceRef,
        priority: Annotated[
            int | None,
            Field(
                ge=0,
                le=65535,
                description="Interface priority (0-65535) that app routes with order_by='priority' use",
            ),
        ] = None,
        path_monitoring: Annotated[
            PathMonitoring | None,
            Field(
                description="ICMP path monitoring: 'auto' (the interface's next hop, IPv4 or IPv6), "
                "'auto4', 'auto6', 'ip' (probe monitored_ip), or 'off'; omit to keep"
            ),
        ] = None,
        monitored_ip: Annotated[
            str | None, Field(description="Peer IPv4/IPv6 address to probe (path_monitoring='ip')")
        ] = None,
        http_monitoring: Annotated[
            bool | None, Field(description="HTTP-based application monitoring on/off; omit to keep")
        ] = None,
        monitored_applications: Annotated[
            list[str] | None,
            Field(
                description="Applications whose HTTP response times are monitored (names, e.g. 'Office 365')"
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make a routed interface a WAN link for application-aware routing: its priority, ICMP path
        monitoring (jitter, loss, RTT and MOS toward the next hop or a monitored IP) and HTTP-based
        application monitoring. App routes ordered by jitter/loss/rtt/mos need path monitoring on
        every egress interface (fmc_create_app_route). Only the fields you pass change; the preview
        shows the before and after. Deploy to apply; check with fmc_run_show_command('show
        path-monitoring')."""
        app: FmcApp = get_client(ctx)
        if all(
            x is None
            for x in (priority, path_monitoring, monitored_ip, http_monitoring, monitored_applications)
        ):
            raise InvalidRequest(
                "Give priority, path_monitoring, monitored_ip, http_monitoring or monitored_applications."
            )
        peer: str | None = None
        if monitored_ip is not None:
            if path_monitoring not in (None, "ip"):
                raise InvalidRequest("monitored_ip goes with path_monitoring='ip'.")
            try:
                peer = str(ipaddress.ip_address(monitored_ip.strip()))
            except ValueError:
                raise InvalidRequest(f"monitored_ip must be an IP address, got {monitored_ip!r}.") from None
        if path_monitoring == "ip" and peer is None:
            raise InvalidRequest("path_monitoring='ip' needs monitored_ip.")
        dev = await resolve_device(app, device, domain)
        kind, current = pick_interface(
            await device_interfaces(app, dev["id"], domain, WAN_KINDS), interface, dev["name"]
        )
        item_path = await app.config_path(
            f"{DEVICES}/{dev['id']}/{INTERFACE_KINDS[kind]}/{current['id']}", domain
        )
        current = await app.api.get(item_path)  # FMC's PUT replaces the whole interface
        desired = interface_put_body(kind, current)
        if priority is not None:
            desired["priority"] = priority
        pm = dict(desired.get("pathMonitoring") or {})
        if path_monitoring == "off":
            pm = {"enable": False}
        elif path_monitoring in PM_TYPES:
            pm = {"enable": True, "type": PM_TYPES[path_monitoring]}
        if peer is not None:
            pm = {
                "enable": True,
                "type": "PEER_IPV6" if ipaddress.ip_address(peer).version == 6 else "PEER_IPV4",
                "monitoredIp": peer,
            }
        if path_monitoring is not None or peer is not None:
            desired["pathMonitoring"] = pm
        am = dict(desired.get("applicationMonitoring") or {})
        if http_monitoring is not None:
            am["enable"] = http_monitoring
            if not http_monitoring:
                am.pop("monitoredApplications", None)
        if monitored_applications is not None:
            refs = await application_refs(app, monitored_applications, domain)
            if refs:
                am["monitoredApplications"] = refs
                am["enable"] = True if http_monitoring is None else am["enable"]
            else:
                am.pop("monitoredApplications", None)
        if http_monitoring is not None or monitored_applications is not None:
            desired["applicationMonitoring"] = am
        before, after = wan_settings(current), wan_settings(desired)
        changes = diff_rows(before, after)
        blockers: list[str] = []
        if not changes:
            blockers.append("Nothing to change: the interface already has these settings.")
        if not current.get("ifname"):
            blockers.append(
                f"{current.get('name')} has no logical name; name it first (fmc_update_interface)."
            )
        if current.get("managementOnly") or str(current.get("name", "")).lower().startswith("management"):
            blockers.append("Management interfaces don't carry WAN traffic.")
        if after["monitored_applications"] and not after["http_monitoring"]:
            blockers.append("monitored_applications needs http_monitoring on.")
        warnings = []
        if after["path_monitoring"] == "auto" and not (current.get("ipv4") or current.get("ipv6")):
            warnings.append("path_monitoring='auto' probes the next hop; this interface has no address yet.")
        return await fmc_preview(
            ctx,
            tool="fmc_configure_wan_interface",
            args={
                "device": device,
                "interface": interface,
                "priority": priority,
                "path_monitoring": path_monitoring,
                "monitored_ip": monitored_ip,
                "http_monitoring": http_monitoring,
                "monitored_applications": monitored_applications,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Configure WAN settings of {current.get('name')} ({current.get('ifname')}) "
                f"on {dev.get('name')}",
                details={"changes": changes, **({"warnings": warnings} if warnings else {})},
                fingerprint=editable(current),
                blockers=blockers,
                side_effects=["Takes effect on the device after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.put(item_path, desired)),
        )

    @reg.write(title="Configure ECMP zone")
    async def fmc_configure_ecmp_zone(
        ctx: Context,
        device: DeviceRef,
        name: Annotated[str, Field(description="ECMP zone name", min_length=1, max_length=48)],
        interfaces: Annotated[
            list[str] | None,
            Field(
                description="The zone's interfaces (replaces the current list): hardware or logical names "
                "or UUIDs; needed to create a zone"
            ),
        ] = None,
        description: Annotated[str | None, Field(description="Description")] = None,
        remove: Annotated[bool, Field(description="Delete the ECMP zone")] = False,
        virtual_router: VrfParam = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create, change or delete an ECMP zone: a set of interfaces across which equal-cost static
        routes load-balance traffic (several WAN links to one destination). An interface can be in one
        zone only. Static routes over the zone's interfaces: fmc_create_static_route
        with the same metric. Deploy to apply; check with fmc_run_show_command('show route')."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        base, vr_name = await routing_base(app, dev, virtual_router, domain)
        where = f"{dev.get('name')} ({vr_name or 'global table'})"
        zones = await collection(app, f"{base}/ecmpzones", domain)
        zone = next(
            (
                z
                for z in zones
                if name.strip().lower() in (str(z.get("name", "")).lower(), str(z.get("id")).lower())
            ),
            None,
        )
        path = await app.config_path(f"{base}/ecmpzones", domain)
        blockers: list[str] = []
        body: dict[str, Any] | None = None
        if remove:
            if interfaces or description:
                raise InvalidRequest("remove can't be combined with other changes.")
            if zone is None:
                raise NotFound(f"No ECMP zone {name!r} on {where}.", 404)
            method, target, after = "DELETE", f"{path}/{zone['id']}", None
        else:
            if zone is None and not interfaces:
                raise InvalidRequest("Creating an ECMP zone needs interfaces.")
            body = editable(zone) if zone else {"type": "ecmpzones", "name": name.strip()}
            if interfaces is not None:
                items = await device_interfaces(app, dev["id"], domain, WAN_KINDS)
                picked = pick_named(items, interfaces, str(dev.get("name")), blockers)
                taken = {
                    str(i.get("id")): str(z.get("name"))
                    for z in zones
                    if z is not zone
                    for i in z.get("interfaces") or []
                }
                for i in picked:
                    if str(i["id"]) in taken:
                        blockers.append(f"{i.get('name')} is already in ECMP zone {taken[str(i['id'])]}.")
                body["interfaces"] = [iface_ref(i) for i in picked]
            if description is not None:
                if description:
                    body["description"] = description
                else:
                    body.pop("description", None)
            after = {
                "name": body.get("name"),
                "interfaces": [iface_label(i) for i in body.get("interfaces") or []],
            }
            if zone and editable(zone) == body:
                blockers.append(f"ECMP zone {zone.get('name')!r} already looks like that.")
            method, target = ("PUT", f"{path}/{zone['id']}") if zone else ("POST", path)
        before = (
            {"name": zone.get("name"), "interfaces": [iface_label(i) for i in zone.get("interfaces") or []]}
            if zone
            else None
        )

        async def apply() -> Any:
            if method == "DELETE":
                return await applied(app, lambda: app.api.delete(target))
            if method == "POST":
                return await applied(app, lambda: app.api.post(target, body))
            return await applied(app, lambda: app.api.put(target, body))

        verb = {"DELETE": "Delete", "POST": "Create", "PUT": "Change"}[method]
        return await fmc_preview(
            ctx,
            tool="fmc_configure_ecmp_zone",
            args={
                "device": device,
                "name": name,
                "interfaces": interfaces,
                "description": description,
                "remove": remove,
                "virtual_router": virtual_router,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"{verb} ECMP zone {name!r} on {where}",
                details={"before": before, "after": after},
                fingerprint={"zones": [editable(z) for z in zones]},
                blockers=blockers,
                side_effects=["Takes effect on the device after the next deployment."]
                + (
                    ["Static routes that rely on the zone stop load-balancing."] if method == "DELETE" else []
                ),
            ),
            apply=apply,
        )

    @reg.write(title="Create application route")
    async def fmc_create_app_route(
        ctx: Context,
        device: DeviceRef,
        name: Annotated[
            str,
            Field(
                description="Route name; also the name of the extended access list that holds the match "
                "(an existing one is reused when no match fields are given)",
                min_length=1,
                max_length=64,
            ),
        ],
        ingress_interfaces: Annotated[
            list[str],
            Field(
                description="Where the traffic enters (LAN side): hardware/logical names or UUIDs",
                min_length=1,
            ),
        ],
        egress_interfaces: Annotated[
            list[str],
            Field(
                description="WAN interfaces to choose from, in preference order for order_by='order'",
                min_length=1,
            ),
        ],
        applications: Annotated[
            list[str] | None,
            Field(description="Applications to match (names from FMC's catalog, e.g. 'WebEx')"),
        ] = None,
        sources: Annotated[
            list[str] | None, Field(description="Source networks: object names or literals (10.10.0.0/16)")
        ] = None,
        destinations: Annotated[
            list[str] | None, Field(description="Destination networks: object names or literals")
        ] = None,
        ports: Annotated[
            list[str] | None, Field(description="Destination ports: object names or literals (tcp/443)")
        ] = None,
        users: Annotated[
            list[str] | None,
            Field(
                description="Realm users or groups ('group:Sales', 'realm\\\\user'); needs an identity policy"
            ),
        ] = None,
        order_by: Annotated[
            OrderBy,
            Field(
                description="How the egress interface is picked: 'order' (first up in the list), 'priority' "
                "(interface priority, fmc_configure_wan_interface), or the best measured path: 'jitter', "
                "'loss', 'rtt' (lowest) or 'mos' (highest); the metrics need path monitoring"
            ),
        ] = "priority",
        virtual_router: VrfParam = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Route an application (or networks, ports, users) out of the best WAN link: policy-based
        routing with path monitoring, FMC's SD-WAN application-aware routing. Creates an extended
        access list named `name` with the match, then adds a forwarding action to the device's
        policy-based route for the ingress interfaces (a new one if those interfaces have none).
        Traffic that matches leaves through the egress interface chosen by `order_by`; the rest
        follows the routing table. The preview shows the match, the ingress and egress interfaces
        with their priority and path monitoring. Deploy to apply; check with
        fmc_sdwan_status (app routes, path in use). Remove with fmc_delete_app_route."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        base, vr_name = await routing_base(app, dev, virtual_router, domain)
        where = f"{dev.get('name')} ({vr_name or 'global table'})"
        blockers: list[str] = []
        warnings: list[str] = []
        items = await device_interfaces(app, dev["id"], domain, WAN_KINDS)
        ingress = pick_named(items, ingress_interfaces, str(dev.get("name")), blockers)
        egress = pick_named(items, egress_interfaces, str(dev.get("name")), blockers)
        if {i["id"] for i in ingress} & {i["id"] for i in egress}:
            raise InvalidRequest("An interface can't be both ingress and egress of one route.")
        # Interface lists carry only summary fields; priority/path monitoring need the full objects.
        egress_full = []
        kinds = {i["id"]: k for k, i in items}
        for i in egress:
            egress_full.append(
                await app.api.get(
                    await app.config_path(
                        f"{DEVICES}/{dev['id']}/{INTERFACE_KINDS[kinds[i['id']]]}/{i['id']}", domain
                    )
                )
            )
        egress_view = [{"interface": iface_label(iface_ref(i)), **wan_settings(i)} for i in egress_full]
        if order_by in METRIC_ORDERS:
            for row in egress_view:
                if row["path_monitoring"] == "off":
                    blockers.append(
                        f"order_by={order_by!r} needs path monitoring on {row['interface']} "
                        "(fmc_configure_wan_interface path_monitoring='auto')."
                    )
        if order_by == "priority" and len({r["priority"] for r in egress_view}) == 1 and len(egress_view) > 1:
            warnings.append(
                "All egress interfaces have the same priority, so FMC load-shares between them; set "
                "priorities with fmc_configure_wan_interface or use order_by='order'."
            )
        if len(egress) == 1:
            warnings.append(
                "One egress interface: no failover if it goes down (traffic falls back to routing)."
            )

        res = RefResolver(app, domain)
        entry: dict[str, Any] = {
            "action": "PERMIT",
            "logging": "DEFAULT",
            "logLevel": "INFORMATIONAL",
            "logInterval": 300,
        }
        for field, values, kind in (
            ("sourceNetworks", sources, "network"),
            ("destinationNetworks", destinations, "network"),
            ("destinationPorts", ports, "port"),
            ("users", users, "user"),
        ):
            block = await res.block(values, kind)
            if block:
                entry[field] = block
        apps = await application_refs(app, applications, domain)
        if apps:
            entry["applications"] = {"applications": apps}
        has_match = any(
            k in entry
            for k in ("sourceNetworks", "destinationNetworks", "destinationPorts", "users", "applications")
        )
        existing_acl = await find_acl(app, name.strip(), domain)
        acl_path = await app.config_path(EXT_ACLS, domain)
        acl_body: dict[str, Any] | None = None
        if has_match:
            if existing_acl:
                blockers.append(
                    f"An extended access list named {existing_acl.get('name')!r} already exists; pick "
                    "another name, or omit the match fields to reuse it."
                )
            acl_body = {"type": "ExtendedAccessList", "name": name.strip(), "entries": [entry]}
            match_view: Any = {
                "applications": [a["name"] for a in apps] or None,
                "sources": sources or None,
                "destinations": destinations or None,
                "ports": ports or None,
                "users": users or None,
            }
            match_view = {k: v for k, v in match_view.items() if v}
        elif existing_acl:
            match_view = {"extended_access_list": existing_acl.get("name"), "reused": True}
        else:
            raise InvalidRequest(
                "Give what to match (applications, sources, destinations, ports or users), or name an "
                "existing extended access list."
            )

        pbrs = await collection(app, f"{base}/policybasedroutes", domain)
        want = {i["id"] for i in ingress}
        target = next(
            (p for p in pbrs if {i.get("id") for i in p.get("ingressInterfaces") or []} == want), None
        )
        for p in pbrs:
            if p is target:
                continue
            clash = want & {i.get("id") for i in p.get("ingressInterfaces") or []}
            if clash:
                names = ", ".join(
                    iface_label(i) for i in p.get("ingressInterfaces") or [] if i.get("id") in clash
                )
                blockers.append(
                    f"{names} already {'is' if len(clash) == 1 else 'are'} an ingress of policy-based route "
                    f"{p.get('name') or p.get('id')!r} with other interfaces; use the same ingress list "
                    f"({', '.join(iface_label(i) for i in p.get('ingressInterfaces') or [])}) "
                    "or change that route."
                )
        if (
            target
            and existing_acl
            and any(
                (a.get("matchCriteria") or {}).get("id") == existing_acl.get("id")
                for a in target.get("forwardingActions") or []
            )
        ):
            blockers.append(f"{existing_acl.get('name')!r} is already routed on these ingress interfaces.")

        def action(acl: dict[str, Any]) -> dict[str, Any]:
            return {
                "forwardingActionType": ORDER_BY[order_by],
                "matchCriteria": {"id": acl["id"], "type": "ExtendedAccessList", "name": acl.get("name")},
                "egressInterfaces": [iface_ref(i) for i in egress],
            }

        pbr_path = await app.config_path(f"{base}/policybasedroutes", domain)
        placeholder = existing_acl or {"id": "<new extended access list>", "name": name.strip()}
        if target:
            pbr_body = editable(target)
            pbr_body["forwardingActions"] = [*(target.get("forwardingActions") or []), action(placeholder)]
            pbr_step = ("update policy-based route", "PUT", f"{pbr_path}/{target['id']}")
        else:
            pbr_body = {
                "type": "PolicyBasedRoutes",
                "name": name.strip(),
                "ingressInterfaces": [iface_ref(i) for i in ingress],
                "forwardingActions": [action(placeholder)],
            }
            pbr_step = ("create policy-based route", "POST", pbr_path)

        async def apply() -> Any:
            acl = existing_acl
            steps: list[str] = []
            if acl_body is not None:
                acl = await app.api.post(acl_path, acl_body)
                steps.append("create extended access list")
            if acl is None:  # pragma: no cover - the preview refuses this case
                raise InvalidRequest("No extended access list to route.")
            body = dict(pbr_body)
            body["forwardingActions"] = [*body["forwardingActions"][:-1], action(acl)]
            try:
                if pbr_step[1] == "PUT":
                    await app.api.put(pbr_step[2], body)
                else:
                    await app.api.post(pbr_step[2], body)
            except Exception as e:
                if acl_body is not None:
                    # Don't leave an orphan access list behind a failed route.
                    try:
                        await app.api.delete(f"{acl_path}/{acl['id']}")
                        steps.append("deleted the new extended access list again")
                    except Exception:  # noqa: BLE001 - report the original failure
                        steps.append(f"extended access list {acl.get('name')!r} left behind")
                app.invalidate_cache()
                raise UpstreamError(
                    f"{pbr_step[0]} failed ({e}); {', '.join(steps) or 'nothing applied'}.",
                    getattr(e, "status_code", None),
                ) from e
            app.invalidate_cache()
            return {
                "applied": [*steps, pbr_step[0]],
                "extended_access_list": {"id": acl.get("id"), "name": acl.get("name")},
                "next": "fmc_deploy, then fmc_sdwan_status (app routes and the path each uses)",
            }

        return await fmc_preview(
            ctx,
            tool="fmc_create_app_route",
            args={
                "device": device,
                "name": name,
                "ingress_interfaces": ingress_interfaces,
                "egress_interfaces": egress_interfaces,
                "applications": applications,
                "sources": sources,
                "destinations": destinations,
                "ports": ports,
                "users": users,
                "order_by": order_by,
                "virtual_router": virtual_router,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Route {name!r} on {where} by {order_by} over "
                f"{', '.join(r['interface'] for r in egress_view)}",
                details={
                    "steps": (["create extended access list"] if acl_body else []) + [pbr_step[0]],
                    "match": match_view,
                    "ingress": [iface_label(iface_ref(i)) for i in ingress],
                    "egress": egress_view,
                    "policy_based_route": (target.get("name") or target.get("id")) if target else "(new)",
                    **({"warnings": warnings} if warnings else {}),
                },
                fingerprint={
                    "pbrs": [editable(p) for p in pbrs],
                    "acl": existing_acl and existing_acl.get("id"),
                    "egress": [editable(i) for i in egress_full],
                },
                blockers=blockers,
                side_effects=[
                    "Takes effect on the device after the next deployment; matching flows then leave "
                    f"through the {order_by}-selected egress interface instead of the routing table's."
                ],
            ),
            apply=apply,
        )

    @reg.write(title="Delete application route", destructive=True)
    async def fmc_delete_app_route(
        ctx: Context,
        device: DeviceRef,
        name: Annotated[
            str,
            Field(
                description="The route's extended access list (its name in fmc_create_app_route), or a "
                "policy-based route's name/UUID to delete it with every route in it"
            ),
        ],
        keep_access_list: Annotated[
            bool, Field(description="Keep the extended access list object (default: delete it when unused)")
        ] = False,
        virtual_router: VrfParam = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Remove an application route: its forwarding action leaves the policy-based route (the
        policy-based route is deleted when nothing is left in it) and its extended access list is
        deleted unless another route still uses it or keep_access_list is set. fmc_sdwan_status lists a
        device's app routes. Deploy to apply; the traffic then follows the routing table again."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        base, vr_name = await routing_base(app, dev, virtual_router, domain)
        where = f"{dev.get('name')} ({vr_name or 'global table'})"
        pbrs = await collection(app, f"{base}/policybasedroutes", domain)
        pbr_path = await app.config_path(f"{base}/policybasedroutes", domain)
        acl_path = await app.config_path(EXT_ACLS, domain)
        low = name.strip().lower()

        def matches(a: dict[str, Any]) -> bool:
            m = a.get("matchCriteria") or {}
            return low in (str(m.get("name", "")).lower(), str(m.get("id", "")).lower())

        whole = next(
            (p for p in pbrs if low in (str(p.get("name") or "").lower(), str(p.get("id")).lower())), None
        )
        holders = [p for p in pbrs if any(matches(a) for a in p.get("forwardingActions") or [])]
        steps: list[tuple[str, str, str, Any]] = []
        removed: list[dict[str, Any]] = []
        if holders:
            for p in holders:
                left = [a for a in p.get("forwardingActions") or [] if not matches(a)]
                removed += [a for a in p.get("forwardingActions") or [] if matches(a)]
                if left:
                    body = {**editable(p), "forwardingActions": left}
                    steps.append(
                        (
                            f"update policy-based route {p.get('name') or p['id']}",
                            "PUT",
                            f"{pbr_path}/{p['id']}",
                            body,
                        )
                    )
                else:
                    steps.append(
                        (
                            f"delete policy-based route {p.get('name') or p['id']}",
                            "DELETE",
                            f"{pbr_path}/{p['id']}",
                            None,
                        )
                    )
        elif whole:
            removed = list(whole.get("forwardingActions") or [])
            steps.append(
                (
                    f"delete policy-based route {whole.get('name') or whole['id']}",
                    "DELETE",
                    f"{pbr_path}/{whole['id']}",
                    None,
                )
            )
        else:
            known = sorted(
                {
                    ref_label(a.get("matchCriteria") or {})
                    for p in pbrs
                    for a in p.get("forwardingActions") or []
                }
            )
            raise NotFound(
                f"No application route {name!r} on {where}. Routes: {', '.join(known) or 'none'}.", 404
            )
        # Match ids still referenced once the change is made (an access list shared with another route stays).
        remaining: list[dict[str, Any]] = []
        for p in pbrs:
            if holders and p in holders:
                remaining += [a for a in p.get("forwardingActions") or [] if not matches(a)]
            elif p is not whole or holders:
                remaining += list(p.get("forwardingActions") or [])
        still_used = {str((a.get("matchCriteria") or {}).get("id")) for a in remaining}
        acls = {
            str((a.get("matchCriteria") or {}).get("id")): a.get("matchCriteria") or {}
            for a in removed
            if (a.get("matchCriteria") or {}).get("type") == "ExtendedAccessList"
        }
        kept: list[str] = []
        if not keep_access_list:
            for acl_id, ref in acls.items():
                if acl_id in still_used:
                    kept.append(f"{ref_label(ref)} (still used by another route)")
                    continue
                steps.append(
                    (f"delete extended access list {ref_label(ref)}", "DELETE", f"{acl_path}/{acl_id}", None)
                )

        async def apply() -> Any:
            return {"applied": await run_steps(app, steps), "next": "fmc_deploy"}

        return await fmc_preview(
            ctx,
            tool="fmc_delete_app_route",
            args={
                "device": device,
                "name": name,
                "keep_access_list": keep_access_list,
                "virtual_router": virtual_router,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Delete application route {name!r} on {where}",
                details={
                    "steps": [s[0] for s in steps],
                    "routes_removed": pbr_summary({"forwardingActions": removed})["routes"],
                    **({"access_lists_kept": kept} if kept else {}),
                },
                fingerprint={"pbrs": [editable(p) for p in pbrs]},
                side_effects=[
                    "Takes effect on the device after the next deployment; matching traffic then follows "
                    "the routing table."
                ],
                blast_radius=len(removed),
            ),
            apply=apply,
        )

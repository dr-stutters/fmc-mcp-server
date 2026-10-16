"""Device configuration (write tier, preview-first): interfaces, static routes and policy assignment.

These change FMC's copy of the device configuration only; nothing reaches the FTD until fmc_deploy.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import RefResolver
from fmc_mcp.tools.common import Domain, ref_label, ref_of, resolve_in, resolve_object
from fmc_mcp.tools.devices import (
    DEVICES,
    INTERFACE_KINDS,
    DeviceRef,
    interface_row,
    name_zones,
    zone_names,
)
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import POLICY_KINDS

# Interface kinds an interface reference is searched in (in this order).
NAMED_KINDS = ["physical", "subinterface", "etherchannel", "vlan", "vti", "loopback", "bridge_group"]
# Kinds that fmc_delete_interface may remove (physical interfaces can only be reset).
DELETABLE_KINDS = {"subinterface", "etherchannel", "vlan", "vti", "loopback", "bridge_group"}
ASSIGNABLE = {
    "access": "AccessPolicy",
    "nat": "FTDNatPolicy",
    "platform_settings": "FTDPlatformSettingsPolicy",
}

InterfaceRef = Annotated[
    str,
    Field(
        description="Interface hardware name (Ethernet0/1, GigabitEthernet0/1.100), logical name "
        "(inside) or UUID, from fmc_list_device_interfaces"
    ),
]
Ipv4Setting = Annotated[
    str | None,
    Field(
        description="IPv4: 'address/prefix' (10.1.1.1/24 or 10.1.1.1/255.255.255.0), 'dhcp', or "
        "'none' to remove the address; omit to keep"
    ),
]
ZoneSetting = Annotated[
    str | None,
    Field(description="Security zone name/UUID, or 'none' to remove it from its zone; omit to keep"),
]


# --- helpers ------------------------------------------------------------------------------------


def ipv4_block(value: str) -> dict[str, Any] | None:
    """FMC's `ipv4` container for 'a.b.c.d/len', 'a.b.c.d/mask' or 'dhcp'; None means remove."""
    v = value.strip().lower()
    if v in ("none", ""):
        return None
    if v == "dhcp":
        return {"dhcp": {"enableDefaultRouteDHCP": False, "dhcpRouteMetric": 1}}
    try:
        iface = ipaddress.IPv4Interface(value.strip())
    except ValueError:
        raise InvalidRequest(f"Invalid IPv4 setting {value!r}: use 10.1.1.1/24, 'dhcp' or 'none'.") from None
    if "/" not in value:
        raise InvalidRequest(f"IPv4 address {value!r} needs a prefix length, e.g. {value}/24.")
    if iface.network.prefixlen < 32 and iface.ip in (
        iface.network.network_address,
        iface.network.broadcast_address,
    ):
        raise InvalidRequest(f"{value!r} is the network or broadcast address of its subnet.")
    return {"static": {"address": str(iface.ip), "netmask": str(iface.network.prefixlen)}}


async def device_interfaces(
    app: FmcApp, device_id: str, domain: str | None, kinds: list[str] | None = None
) -> list[tuple[str, dict[str, Any]]]:
    """(kind, interface) for every interface of the given kinds (expanded)."""
    out: list[tuple[str, dict[str, Any]]] = []
    for kind in kinds or NAMED_KINDS:
        try:
            page = await app.all(
                await app.config_path(f"{DEVICES}/{device_id}/{INTERFACE_KINDS[kind]}", domain), cap=2000
            )
        except UpstreamError as e:
            # Kinds the model doesn't support answer 405 ("VLAN Interface type is not supported on this
            # device model", e.g. FTDv); a missing collection is not an error here.
            if e.status_code in (404, 405):
                continue
            raise
        out += [(kind, i) for i in page.items]
    return out


def pick_interface(
    items: list[tuple[str, dict[str, Any]]], ref: str, device: str
) -> tuple[str, dict[str, Any]]:
    want = ref.strip()
    low = want.lower()

    def full_name(kind: str, i: dict[str, Any]) -> str:
        return str(interface_row(kind, i)["name"] or "").lower()

    for field in ("id", "name", "ifname"):
        if field == "name":
            hits = [(k, i) for k, i in items if full_name(k, i) == low]
        else:
            hits = [(k, i) for k, i in items if str(i.get(field, "")).lower() == low]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            raise InvalidRequest(f"Interface {ref!r} is ambiguous on {device}; pass its UUID.")
    names = ", ".join(
        f"{i.get('name')}" + (f" ({i['ifname']})" if i.get("ifname") else "") for _, i in items[:40]
    )
    raise NotFound(f"No interface {ref!r} on {device}. Interfaces: {names or 'none'}.", 404)


async def zone_ref(res: RefResolver, value: str) -> dict[str, Any]:
    return await res.single(value, ["security_zone"], "security zone")


def iface_summary(kind: str, i: dict[str, Any]) -> dict[str, Any]:
    row = interface_row(kind, i)
    return {k: v for k, v in row.items() if v not in (None, "") and k not in ("id",)}


def diff_rows(before: dict[str, Any], after: dict[str, Any]) -> dict[str, dict[str, Any]]:
    keys = list(dict.fromkeys([*before, *after]))
    return {k: {"from": before.get(k), "to": after.get(k)} for k in keys if before.get(k) != after.get(k)}


async def resolve_device(app: FmcApp, device: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, DEVICES, device, "device", domain)


async def routing_base(
    app: FmcApp, dev: dict[str, Any], vr: str | None, domain: str | None
) -> tuple[str, str | None]:
    """The routing collection prefix for the global table or a virtual router (VRF)."""
    base = f"{DEVICES}/{dev['id']}/routing"
    if not vr:
        return base, None
    page = await app.all(await app.config_path(f"{base}/virtualrouters", domain), cap=500)
    for v in page.items:
        if v.get("id") == vr or str(v.get("name", "")).lower() == vr.lower():
            return f"{base}/virtualrouters/{v['id']}", str(v.get("name"))
    names = ", ".join(str(v.get("name")) for v in page.items) or "none (only the global table)"
    raise NotFound(f"No virtual router {vr!r} on {dev.get('name')}. Virtual routers: {names}.", 404)


async def network_by_value(app: FmcApp, value: str, domain: str | None) -> dict[str, Any] | None:
    """An existing Host/Network object whose value equals a CIDR or address (0.0.0.0/0 -> any-ipv4)."""
    net = ipaddress.ip_network(value.strip(), strict=False)
    wanted = {str(net), str(net.network_address)} if net.num_addresses == 1 else {str(net)}
    for kind in ("networks", "hosts"):
        page = await app.all(
            await app.config_path(f"object/{kind}", domain), {"filter": f"nameOrValue:{net.network_address}"}
        )
        for o in page.items:
            try:
                have = str(ipaddress.ip_network(str(o.get("value", "")), strict=False))
            except ValueError:
                continue
            if have in wanted or o.get("value") in wanted:
                found: dict[str, Any] = o
                return found
    return None


def route_row(kind: str, r: dict[str, Any]) -> dict[str, Any]:
    gw = r.get("gateway") or {}
    gateway = None
    if isinstance(gw.get("literal"), dict):
        gateway = gw["literal"].get("value")
    elif isinstance(gw.get("object"), dict):
        gateway = ref_label(gw["object"])
    return {
        "kind": kind,
        "networks": [ref_label(n) for n in r.get("selectedNetworks") or []],
        "interface": r.get("interfaceName"),
        "gateway": gateway,
        "metric": r.get("metricValue"),
        "tracked_by": ref_label(r["routeTracking"]) if r.get("routeTracking") else None,
        "tunneled": r.get("isTunneled") or None,
        "id": r.get("id"),
    }


ROUTE_TABLE_CAP = 5000


def route_key(r: dict[str, Any]) -> tuple[str, frozenset[str], str]:
    """What makes two static routes in one table the same route: interface, destinations, gateway.
    A gateway given as a host object and the same IP as a literal count as different (FMC decides)."""
    gw = r.get("gateway") or {}
    if isinstance(gw.get("literal"), dict):
        gateway = "ip:" + str(gw["literal"].get("value", "")).lower()
    else:
        gateway = "obj:" + str((gw.get("object") or {}).get("id", ""))
    nets = frozenset(str(n.get("id")) for n in r.get("selectedNetworks") or [])
    return str(r.get("interfaceName", "")).lower(), nets, gateway


LicenseCap = Literal["ESSENTIALS", "IPS", "MALWARE_DEFENSE", "URL", "CARRIER"]


def register(reg: ToolRegistrar) -> None:
    # --- read: routes -------------------------------------------------------------------------

    @reg.read(title="List device routes")
    async def fmc_list_routes(
        ctx: Context,
        device: DeviceRef,
        virtual_router: Annotated[
            str | None, Field(description="Virtual router (VRF) name/UUID; default the global table")
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the static routes FMC holds for a device (IPv4 and IPv6: networks, egress interface,
        gateway, metric, SLA tracking) plus a summary of the other routing configured on it (virtual
        routers, BGP, OSPFv2/v3, EIGRP, policy-based routes, ECMP zones). This is the configuration,
        not the live table: use fmc_run_show_command('show route') for what the FTD is using."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        base, vr_name = await routing_base(app, dev, virtual_router, domain)
        rows: list[dict[str, Any]] = []
        for kind, sub in (("static4", "ipv4staticroutes"), ("static6", "ipv6staticroutes")):
            page = await app.all(await app.config_path(f"{base}/{sub}", domain), cap=5000)
            rows += [route_row(kind, r) for r in page.items]
        summary: dict[str, Any] = {}
        subs = {"bgp": "bgp", "ospfv2": "ospfv2routes", "eigrp": "eigrproutes", "pbr": "policybasedroutes"}
        if not virtual_router:
            subs |= {"ospfv3": "ospfv3routes", "ecmp_zones": "ecmpzones"}
        for key, sub in subs.items():
            try:
                page = await app.page(await app.config_path(f"{base}/{sub}", domain), limit=1, expanded=False)
            except (NotFound, InvalidRequest):
                continue
            if page.total:
                summary[key] = page.total
        if not virtual_router:
            vrs = await app.all(await app.config_path(f"{base}/virtualrouters", domain), expanded=False)
            user_vrs = [v.get("name") for v in vrs.items if str(v.get("name")).lower() != "global"]
            if user_vrs:
                summary["virtual_routers"] = user_vrs
        extra: dict[str, Any] = {"device": dev.get("name"), "table": vr_name or "global"}
        if summary:
            extra["other_routing"] = summary
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    # --- write: interfaces ------------------------------------------------------------------------

    @reg.write(title="Set device licences")
    async def fmc_set_device_licenses(
        ctx: Context,
        device: DeviceRef,
        add: Annotated[
            list[LicenseCap] | None, Field(description="Licences to add, e.g. IPS for intrusion policies")
        ] = None,
        remove: Annotated[list[LicenseCap] | None, Field(description="Licences to remove")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add or remove a device's licence capabilities (ESSENTIALS, IPS, MALWARE_DEFENSE, URL, CARRIER).
        Intrusion policies on access rules need IPS, file policies MALWARE_DEFENSE, URL categories URL;
        without them the deploy fails validation ("requires a Threat license"). Uses the FMC's Smart
        Licensing (or evaluation) entitlements; takes effect with the next deployment."""
        app: FmcApp = get_client(ctx)
        if set(add or []) & set(remove or []):
            raise InvalidRequest("A licence can't be in both add and remove.")
        d = await resolve_in(app, DEVICES, device, "device", domain)
        path = await app.config_path(f"{DEVICES}/{d['id']}", domain)
        cur = await app.api.get(path)
        have = list(cur.get("license_caps") or [])
        want = [c for c in have if c not in (remove or [])] + [c for c in (add or []) if c not in have]
        if "ESSENTIALS" not in want:
            raise InvalidRequest("ESSENTIALS is the base licence and can't be removed.")

        async def apply() -> Any:
            now = await app.api.get(path)  # rebuilt from the current record: the PUT replaces it
            body = {
                "id": now["id"],
                "type": "Device",
                "name": now.get("name"),
                "hostName": now.get("hostName"),
                "license_caps": want,
            }
            if now.get("performanceTier"):
                body["performanceTier"] = now["performanceTier"]
            return await applied(app, lambda: app.api.put(path, body))

        dropped = [c for c in have if c not in want]
        return await fmc_preview(
            ctx,
            tool="fmc_set_device_licenses",
            args={"device": device, "add": add, "remove": remove, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Licences of {cur.get('name')!r}: {', '.join(have)} -> {', '.join(want)}",
                details={"from": have, "to": want},
                fingerprint=have,
                blockers=[] if want != have else ["Nothing to change."],
                side_effects=["Consumes the licences from Smart Licensing; effective after the next deploy."]
                + (
                    [f"Rules that need {', '.join(dropped)} (intrusion/file/URL) will fail the next deploy."]
                    if dropped
                    else []
                ),
            ),
            apply=apply,
        )

    @reg.write(title="Configure interface")
    async def fmc_update_interface(
        ctx: Context,
        device: DeviceRef,
        interface: InterfaceRef,
        logical_name: Annotated[
            str | None, Field(description="Logical name (nameif), e.g. inside; 'none' clears it")
        ] = None,
        enabled: Annotated[bool | None, Field(description="Admin state; omit to keep")] = None,
        security_zone: ZoneSetting = None,
        ipv4: Ipv4Setting = None,
        mtu: Annotated[int | None, Field(ge=64, le=9198, description="MTU; omit to keep")] = None,
        description: Annotated[str | None, Field(description="Description ('' clears it)")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Configure an existing device interface (physical, subinterface, EtherChannel, VLAN, VTI or
        loopback): logical name, admin state, security zone, IPv4 (static or DHCP), MTU and
        description. Only the fields you pass change. A routed data interface needs a logical name to
        carry traffic or join a zone. Preview shows the before/after; deploy with fmc_deploy."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        kind, current = pick_interface(
            await device_interfaces(app, dev["id"], domain), interface, dev["name"]
        )
        if kind != "physical" and current.get("type") == "PhysicalInterface":
            kind = "physical"
        # FMC's PUT replaces the whole interface: start from the full object, not the list item.
        item_path = await app.config_path(
            f"{DEVICES}/{dev['id']}/{INTERFACE_KINDS[kind]}/{current['id']}", domain
        )
        current = await app.api.get(item_path)
        desired = editable(current)
        if logical_name is not None:
            if logical_name.strip().lower() == "none":
                desired.pop("ifname", None)
            else:
                desired["ifname"] = logical_name.strip()
        if enabled is not None:
            desired["enabled"] = enabled
        if security_zone is not None:
            if security_zone.strip().lower() == "none":
                desired.pop("securityZone", None)
            else:
                desired["securityZone"] = await zone_ref(RefResolver(app, domain), security_zone)
        if ipv4 is not None:
            block = ipv4_block(ipv4)
            if block is None:
                desired.pop("ipv4", None)
            else:
                desired["ipv4"] = block
        if mtu is not None:
            desired["MTU"] = mtu
        if description is not None:
            if description:
                desired["description"] = description
            else:
                desired.pop("description", None)
        if kind == "physical" and desired.get("ifname") and desired.get("mode") in (None, "NONE"):
            desired["mode"] = "NONE"  # routed
        zones = await zone_names(app, domain)
        before = name_zones([iface_summary(kind, current)], zones)[0]
        after = name_zones([iface_summary(kind, desired)], zones)[0]
        changes = diff_rows(before, after)
        blockers = [] if changes else ["Nothing to change: the interface already has these settings."]
        if (desired.get("securityZone") or desired.get("ipv4")) and not desired.get("ifname"):
            blockers.append("An interface needs a logical_name before it can take a zone or an address.")
        if current.get("managementOnly") or str(current.get("name", "")).lower().startswith("management"):
            blockers.append(
                "Management interfaces are configured on the device (configure network), not here."
            )
        path = await app.config_path(f"{DEVICES}/{dev['id']}/{INTERFACE_KINDS[kind]}/{current['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_update_interface",
            args={
                "device": device,
                "interface": interface,
                "logical_name": logical_name,
                "enabled": enabled,
                "security_zone": security_zone,
                "ipv4": ipv4,
                "mtu": mtu,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Configure {kind} interface {current.get('name')} on {dev.get('name')}",
                details={"changes": changes},
                fingerprint=editable(current),
                blockers=blockers,
                side_effects=["Takes effect on the device after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.put(path, desired)),
        )

    @reg.write(title="Create subinterface")
    async def fmc_create_subinterface(
        ctx: Context,
        device: DeviceRef,
        parent: Annotated[str, Field(description="Parent physical/EtherChannel interface, e.g. Ethernet0/1")],
        vlan_id: Annotated[int, Field(ge=1, le=4094, description="802.1Q VLAN tag")],
        logical_name: Annotated[str, Field(description="Logical name (nameif), e.g. dmz", min_length=1)],
        subinterface_id: Annotated[
            int | None, Field(ge=1, le=4294967295, description="Subinterface number (default: the VLAN id)")
        ] = None,
        security_zone: Annotated[str | None, Field(description="Security zone name/UUID")] = None,
        ipv4: Annotated[str | None, Field(description="'address/prefix' or 'dhcp'")] = None,
        mtu: Annotated[int | None, Field(ge=64, le=9198, description="MTU (default 1500)")] = None,
        description: Annotated[str | None, Field(description="Description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a VLAN subinterface (Ethernet0/1.<id>) on a device with logical name, zone and IPv4.
        The parent must be enabled to pass traffic (fmc_update_interface). Remove with
        fmc_delete_interface. Takes effect after fmc_deploy."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        items = await device_interfaces(app, dev["id"], domain, ["physical", "etherchannel", "subinterface"])
        pkind, par = pick_interface([x for x in items if x[0] != "subinterface"], parent, dev["name"])
        sub_id = subinterface_id or vlan_id
        body: dict[str, Any] = {
            "type": "SubInterface",
            "name": par["name"],
            "subIntfId": sub_id,
            "vlanId": vlan_id,
            "ifname": logical_name.strip(),
            "enabled": True,
            "MTU": mtu or 1500,
        }
        if security_zone:
            body["securityZone"] = await zone_ref(RefResolver(app, domain), security_zone)
        if ipv4:
            block = ipv4_block(ipv4)
            if block:
                body["ipv4"] = block
        if description:
            body["description"] = description
        blockers = []
        for k, i in items:
            if (
                k == "subinterface"
                and i.get("name") == par["name"]
                and int(i.get("subIntfId") or -1) == sub_id
            ):
                blockers.append(f"{par['name']}.{sub_id} already exists.")
            if k == "subinterface" and i.get("name") == par["name"] and int(i.get("vlanId") or -1) == vlan_id:
                blockers.append(
                    f"VLAN {vlan_id} is already used on {par['name']} ({par['name']}.{i.get('subIntfId')})."
                )
            if str(i.get("ifname", "")).lower() == logical_name.strip().lower():
                blockers.append(f"Logical name {logical_name!r} is already used by {i.get('name')}.")
        if pkind == "physical" and not par.get("enabled"):
            side = [f"The parent {par['name']} is disabled; enable it or the subinterface stays down."]
        else:
            side = []
        path = await app.config_path(f"{DEVICES}/{dev['id']}/subinterfaces", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_subinterface",
            args={
                "device": device,
                "parent": parent,
                "vlan_id": vlan_id,
                "logical_name": logical_name,
                "subinterface_id": subinterface_id,
                "security_zone": security_zone,
                "ipv4": ipv4,
                "mtu": mtu,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create subinterface {par['name']}.{sub_id} (VLAN {vlan_id}) on {dev.get('name')}",
                details={"interface": iface_summary("subinterface", body), "body": body},
                fingerprint={"parent": par.get("id"), "device": dev["id"]},
                blockers=blockers,
                side_effects=[*side, "Takes effect on the device after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Delete interface", destructive=True)
    async def fmc_delete_interface(
        ctx: Context,
        device: DeviceRef,
        interface: InterfaceRef,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a logical interface (subinterface, EtherChannel, VLAN, VTI, loopback or bridge
        group) from a device. Physical interfaces can't be deleted: clear them with
        fmc_update_interface. The preview lists static routes that use the interface; FMC refuses
        the delete while NAT, routes or other config still reference it."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        kind, current = pick_interface(
            await device_interfaces(app, dev["id"], domain), interface, dev["name"]
        )
        blockers = []
        if kind not in DELETABLE_KINDS or current.get("type") == "PhysicalInterface":
            blockers.append(
                f"{current.get('name')} is a {kind} interface; only logical interfaces can be deleted."
            )
        users: list[str] = []
        ifname = current.get("ifname")
        if ifname:
            base = f"{DEVICES}/{dev['id']}/routing"
            for sub in ("ipv4staticroutes", "ipv6staticroutes"):
                page = await app.all(await app.config_path(f"{base}/{sub}", domain))
                users += [
                    f"route {', '.join(route_row('', r)['networks'])} via {ifname}"
                    for r in page.items
                    if r.get("interfaceName") == ifname
                ]
        if users:
            blockers.append(f"Still used by: {'; '.join(users)}. Delete those routes first.")
        path = await app.config_path(f"{DEVICES}/{dev['id']}/{INTERFACE_KINDS[kind]}/{current['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_interface",
            args={"device": device, "interface": interface, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete {kind} interface {current.get('name')} on {dev.get('name')}",
                details={"interface": iface_summary(kind, current)},
                fingerprint=editable(current),
                blockers=blockers,
                side_effects=["Removed from the device on the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )

    # --- write: static routes ----------------------------------------------------------------------

    @reg.write(title="Create static route")
    async def fmc_create_static_route(
        ctx: Context,
        device: DeviceRef,
        interface: Annotated[str, Field(description="Egress interface logical name (nameif), e.g. outside")],
        networks: Annotated[
            list[str],
            Field(
                min_length=1,
                description="Destination network object names/UUIDs, or CIDRs that match an existing "
                "object's value ('0.0.0.0/0' = any-ipv4 for a default route)",
            ),
        ],
        gateway: Annotated[str, Field(description="Next-hop IP address or host object name/UUID")],
        metric: Annotated[int, Field(ge=1, le=254, description="Administrative distance")] = 1,
        virtual_router: Annotated[
            str | None, Field(description="Virtual router (VRF) name/UUID; default the global table")
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a static route (IPv4 or IPv6, picked from the gateway) to a device, in the global table
        or a virtual router. Destinations must be network/host objects; a CIDR is accepted when an
        object with that value exists (create one with fmc_create_object otherwise). Takes effect
        after fmc_deploy; check with fmc_list_routes and fmc_run_show_command('show route')."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        base, vr_name = await routing_base(app, dev, virtual_router, domain)
        res = RefResolver(app, domain)
        blockers: list[str] = []
        selected: list[dict[str, Any]] = []
        for n in networks:
            v = n.strip()
            obj: dict[str, Any] | None
            try:
                ipaddress.ip_network(v, strict=False)
                literal = not is_uuid(v)
            except ValueError:
                literal = False
            if literal:
                obj = await network_by_value(app, v, domain)
                if obj is None:
                    blockers.append(
                        f"No network object with value {v}; create one (fmc_create_object) first."
                    )
                    continue
                selected.append(ref_of(obj))
            else:
                selected.append(await res.single(v, ["host", "network", "network_group"], "network"))
        try:
            gw_ip = ipaddress.ip_address(gateway.strip())
            gw: dict[str, Any] = {"literal": {"type": "Host", "value": str(gw_ip)}}
            version = gw_ip.version
        except ValueError:
            _, host_obj = await resolve_object(app, gateway, domain, ["host"])
            gw = {"object": ref_of(host_obj)}
            version = 6 if ":" in str(host_obj.get("value", "")) else 4
        for n in networks:
            try:
                fam = ipaddress.ip_network(n.strip(), strict=False).version
            except ValueError:
                continue
            if fam != version:
                blockers.append(f"{n} is IPv{fam} but the gateway is IPv{version}.")
        names = [i.get("ifname") for _, i in await device_interfaces(app, dev["id"], domain)]
        match_name = next((x for x in names if str(x or "").lower() == interface.strip().lower()), None)
        if match_name:
            interface = str(match_name)
        else:
            known = ", ".join(sorted(str(x) for x in names if x)) or "none (name an interface first)"
            blockers.append(f"{dev.get('name')} has no interface named {interface!r}. Named: {known}.")
        body: dict[str, Any] = {
            "type": "IPv4StaticRoute" if version == 4 else "IPv6StaticRoute",
            "interfaceName": interface,
            "selectedNetworks": selected,
            "gateway": gw,
            "metricValue": metric,
            "isTunneled": False,
        }
        sub = "ipv4staticroutes" if version == 4 else "ipv6staticroutes"
        path = await app.config_path(f"{base}/{sub}", domain)
        if selected and not blockers:
            # One table rarely holds more than a few hundred routes; past the cap the check is skipped
            # for the rest and FMC's own refusal still applies.
            existing = await app.all(path, cap=ROUTE_TABLE_CAP)
            want = route_key(body)
            dup = next((r for r in existing.items if route_key(r) == want), None)
            if dup is not None:
                blockers.append(
                    f"{dev.get('name')} already has this route ({vr_name or 'global table'}, id "
                    f"{dup.get('id')}, metric {dup.get('metricValue')}); delete it first or change it."
                )
        return await fmc_preview(
            ctx,
            tool="fmc_create_static_route",
            args={
                "device": device,
                "interface": interface,
                "networks": networks,
                "gateway": gateway,
                "metric": metric,
                "virtual_router": virtual_router,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Add static route on {dev.get('name')} ({vr_name or 'global table'})",
                details={"route": route_row(f"static{version}", body), "body": body},
                fingerprint={"device": dev["id"], "body": body},
                blockers=blockers,
                side_effects=["Takes effect on the device after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Delete static route", destructive=True)
    async def fmc_delete_static_route(
        ctx: Context,
        device: DeviceRef,
        route_id: Annotated[str, Field(description="Static route UUID (from fmc_list_routes)")],
        virtual_router: Annotated[
            str | None, Field(description="Virtual router (VRF) the route is in; default global")
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete one static route (IPv4 or IPv6) from a device. Preview shows the route. Takes effect
        after fmc_deploy."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        base, vr_name = await routing_base(app, dev, virtual_router, domain)
        if not is_uuid(route_id):
            raise InvalidRequest(f"route_id must be a route UUID from fmc_list_routes, got {route_id!r}.")
        current: dict[str, Any] | None = None
        kind = sub = ""
        for k, s in (("static4", "ipv4staticroutes"), ("static6", "ipv6staticroutes")):
            try:
                current = await app.api.get(await app.config_path(f"{base}/{s}/{route_id.strip()}", domain))
            except NotFound:
                continue
            kind, sub = k, s
            break
        if not current:
            raise NotFound(f"No static route {route_id!r} on {dev.get('name')} ({vr_name or 'global'}).", 404)
        path = await app.config_path(f"{base}/{sub}/{current['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_static_route",
            args={"device": device, "route_id": route_id, "virtual_router": virtual_router, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete static route on {dev.get('name')}",
                details={"route": route_row(kind, current)},
                fingerprint=editable(current),
                side_effects=["Removed from the device on the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )

    # --- write: policy assignment -------------------------------------------------------------------

    @reg.write(title="Assign policy to devices")
    async def fmc_assign_policy(
        ctx: Context,
        kind: Annotated[
            Literal["access", "nat", "platform_settings"], Field(description="Policy type to assign")
        ],
        policy: Annotated[str, Field(description="Policy name or UUID")],
        devices: Annotated[
            list[str], Field(min_length=1, description="Device (or HA pair/cluster) names/UUIDs")
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Assign an access control, NAT or platform settings policy to devices. A device has one policy
        of each type, so this replaces its current one (shown in the preview). The new policy reaches
        the device on the next fmc_deploy. Current assignments: fmc_list_policy_assignments."""
        app: FmcApp = get_client(ctx)
        pol = await resolve_in(app, POLICY_KINDS[kind], policy, f"{kind} policy", domain)
        targets: list[dict[str, Any]] = []
        for ref in dict.fromkeys(d.strip() for d in devices):
            try:
                d = await resolve_device(app, ref, domain)
            except NotFound:
                d = await resolve_in(app, "devicehapairs/ftddevicehapairs", ref, "device or HA pair", domain)
            targets.append({"id": d["id"], "type": d.get("type") or "Device", "name": d.get("name")})
        assignments = await app.all(await app.config_path("assignment/policyassignments", domain), cap=5000)
        mine = next((a for a in assignments.items if (a.get("policy") or {}).get("id") == pol["id"]), None)
        policy_type = ASSIGNABLE[kind]
        current: dict[str, str] = {}
        for a in assignments.items:
            p = a.get("policy") or {}
            if p.get("type") != policy_type:
                continue
            for t in a.get("targets") or []:
                current[str(t.get("id"))] = str(p.get("name"))
        existing = list((mine or {}).get("targets") or [])
        have = {t.get("id") for t in existing}
        new = [t for t in targets if t["id"] not in have]
        changes = [{"device": t["name"], "from": current.get(t["id"]), "to": pol.get("name")} for t in new]
        blockers = [] if new else [f"Already assigned: {', '.join(str(t['name']) for t in targets)}."]
        body: dict[str, Any] = {
            "type": "PolicyAssignment",
            "policy": {"id": pol["id"], "type": pol.get("type") or policy_type},
            "targets": [{"id": t.get("id"), "type": t.get("type")} for t in existing]
            + [{"id": t["id"], "type": t["type"]} for t in new],
        }
        if mine:
            body["id"] = mine["id"]
            path = await app.config_path(f"assignment/policyassignments/{mine['id']}", domain)
        else:
            path = await app.config_path("assignment/policyassignments", domain)

        async def apply() -> Any:
            if mine:
                return await applied(app, lambda: app.api.put(path, body))
            return await applied(app, lambda: app.api.post(path, body))

        return await fmc_preview(
            ctx,
            tool="fmc_assign_policy",
            args={"kind": kind, "policy": policy, "devices": devices, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Assign {kind} policy {pol.get('name')!r} to {len(new)} device(s)",
                details={"changes": changes},
                fingerprint={"assignment": mine and editable(mine), "current": current},
                blockers=blockers,
                side_effects=["The devices get the new policy on the next deployment."],
            ),
            apply=apply,
        )

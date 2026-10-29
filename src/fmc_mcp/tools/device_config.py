"""Device configuration (write tier, preview-first): interfaces, static routes and policy assignment.

These change FMC's copy of the device configuration only; nothing reaches the FTD until fmc_deploy.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import re
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    AuthError,
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
from fmc_mcp.preview import fmc_preview, owner_domain
from fmc_mcp.refs import RefResolver
from fmc_mcp.tools.common import Domain, ref_label, ref_of, resolve_in, resolve_object
from fmc_mcp.tools.device_groups import DeviceOrGroup, expand_devices
from fmc_mcp.tools.devices import (
    DEVICES,
    INTERFACE_KINDS,
    DeviceRef,
    interface_row,
    name_zones,
    zone_names,
)
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import ASSIGNMENTS, POLICY_KINDS, policy_assignments

# Interface kinds an interface reference is searched in (in this order).
NAMED_KINDS = ["physical", "subinterface", "etherchannel", "vlan", "vti", "loopback", "bridge_group"]
# Kinds that fmc_delete_interface may remove (physical interfaces can only be reset).
DELETABLE_KINDS = {"subinterface", "etherchannel", "vlan", "vti", "loopback", "bridge_group"}
# Fields FMC returns in an interface GET but refuses in the PUT body for that kind. FMC 10.0.1 answers
# a VTI PUT that echoes managementOnly with 400 "Fields: { managementOnly } must be excluded from json
# payload" (seen live on an SD-WAN spoke's static VTI, 2026-10-18).
GET_ONLY_FIELDS: dict[str, tuple[str, ...]] = {"vti": ("managementOnly",)}
# fmc_update_interface mode -> FMC's interface `mode` (NONE is routed).
IFACE_MODES = {"routed": "NONE", "inline": "INLINE", "passive": "PASSIVE"}
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


def interface_put_body(kind: str, obj: dict[str, Any]) -> dict[str, Any]:
    """An interface as FMC accepts it back in a PUT: no metadata/links, and none of the fields that
    kind only returns (GET_ONLY_FIELDS)."""
    body = editable(obj)
    for name in GET_ONLY_FIELDS.get(kind, ()):
        body.pop(name, None)
    return body


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


def failover_check(new: dict[str, Any], others: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    """Dual-ISP failover around a new static route, against the other routes of its table to the same
    networks: for a tracked route, the floating backups (higher metric) and warnings when there is none,
    one has the same metric or one is preferred; for an untracked route, the tracked route it backs up."""
    nets = frozenset(str(n.get("id")) for n in new.get("selectedNetworks") or [])
    same = [r for r in others if frozenset(str(n.get("id")) for n in r.get("selectedNetworks") or []) == nets]
    metric = int(new.get("metricValue") or 1)
    dest = ", ".join(ref_label(n) for n in new.get("selectedNetworks") or [])
    out: dict[str, Any] = {}
    warnings: list[str] = []

    def label(r: dict[str, Any]) -> str:
        row = route_row("static4", r)
        return f"via {row['gateway']} on {row['interface']} (metric {row['metric']}, id {row['id']})"

    tracking = new.get("routeTracking")
    if tracking:
        backups = [r for r in same if int(r.get("metricValue") or 1) > metric]
        out["floating_backup"] = [route_row("static4", r) for r in backups]
        equal = [r for r in same if int(r.get("metricValue") or 1) == metric]
        better = [r for r in same if int(r.get("metricValue") or 1) < metric]
        if not same:
            warnings.append(
                f"No other route to {dest} in this table: while {ref_label(tracking)} is down these networks "
                f"have no route. Add a floating backup through the other ISP with a higher metric "
                f"(fmc_create_static_route metric={min(metric + 9, 254)})."
            )
        for r in equal:
            warnings.append(
                f"The route {label(r)} has the same metric as this tracked route: it is no floating backup "
                f"(FTD load-shares or refuses equal routes on different interfaces). Give it a higher metric."
            )
        for r in better:
            warnings.append(
                f"The route {label(r)} has a lower metric: it wins while both are up, so tracking this one "
                "changes nothing. The tracked primary needs the lowest metric."
            )
    else:
        primaries = [r for r in same if r.get("routeTracking")]
        backed = [r for r in primaries if int(r.get("metricValue") or 1) < metric]
        if backed:
            out["backs_up"] = [route_row("static4", r) for r in backed]
        for r in primaries:
            if int(r.get("metricValue") or 1) >= metric:
                warnings.append(
                    f"The tracked route {label(r)} has a metric no lower than this one ({metric}): give this "
                    "route a higher metric to make it the floating backup."
                )
    return out, warnings


# --- logical interfaces (fmc_create_interface) ----------------------------------------------------

CreateKind = Literal["loopback", "vti", "etherchannel", "bvi"]


@dataclass(frozen=True)
class LogicalKind:
    """How FMC 10.0.1 models one logical interface kind (spec: FTDLoopbackInterface, FTDVTIInterface,
    FTDEtherChannelInterface, FTDBridgeGroupInterface)."""

    collection: str  # INTERFACE_KINDS key
    type: str
    id_field: str
    low: int
    high: int
    prefix: str  # FMC's hardware name: <prefix><id>


LOGICAL_KINDS: dict[str, LogicalKind] = {
    "loopback": LogicalKind("loopback", "LoopbackInterface", "loopbackId", 1, 1024, "Loopback"),
    "vti": LogicalKind("vti", "VTIInterface", "tunnelId", 0, 10413, "Tunnel"),
    "etherchannel": LogicalKind(
        "etherchannel", "EtherChannelInterface", "etherChannelId", 1, 48, "Port-channel"
    ),
    "bvi": LogicalKind("bridge_group", "BridgeGroupInterface", "bridgeGroupId", 1, 250, "BVI"),
}
MAX_MEMBERS = {"etherchannel": 16, "bvi": 64}  # 8 active + 8 standby LACP links; 64 per bridge group
MEMBER_KINDS = {"etherchannel": ("physical",), "bvi": ("physical", "subinterface", "etherchannel")}
# FMC's loopback and bridge-group (BVI) interfaces carry no security zone (none in the UI or in the
# FMC 10.0.1 spec examples): a BVI's traffic is zoned on its member interfaces.
NO_ZONE_KINDS = {"loopback", "bridge_group"}
NO_DHCP_KINDS = {"loopback", "vti"}
# FTDv (any hypervisor or cloud): FMC names the model "... Threat Defense for KVM" (VMware, AWS, Azure, GCP,
# OCI, Hyper-V, Nutanix, OpenStack, ...) and gives it an FTDv performance tier.
VIRTUAL_MODEL = re.compile(
    r"\bvirtual\b|\bftdv\b|threat defense for (?:vmware|kvm|aws|azure|gcp|google|oci|oracle|hyper-v|"
    r"nutanix|openstack|alibaba)",
    re.I,
)


def is_virtual(device: dict[str, Any]) -> bool:
    """An FTDv, from the device record's performance tier or model."""
    tier = str(device.get("performanceTier") or "")
    return tier.upper().startswith("FTDV") or bool(VIRTUAL_MODEL.search(str(device.get("model") or "")))


def bridge_group_of(items: list[tuple[str, dict[str, Any]]]) -> dict[str, str]:
    """Interface id -> the bridge group (BVI) it belongs to."""
    return {
        str(m["id"]): str(i.get("name") or i.get("id"))
        for k, i in items
        if k == "bridge_group"
        for m in i.get("selectedInterfaces") or []
        if m.get("id")
    }


def iref(i: dict[str, Any]) -> dict[str, Any]:
    """An interface reference for a request body."""
    return {"id": i["id"], "type": i.get("type"), "name": i.get("name")}


def static_network(i: dict[str, Any]) -> ipaddress.IPv4Interface | None:
    st = (i.get("ipv4") or {}).get("static") or {}
    if not st.get("address"):
        return None
    try:
        return ipaddress.IPv4Interface(f"{st['address']}/{st.get('netmask') or 32}")
    except ValueError:
        return None


def logical_members(items: list[tuple[str, dict[str, Any]]]) -> dict[str, str]:
    """Interface id -> the EtherChannel or BVI it already belongs to."""
    out: dict[str, str] = {}
    for kind, i in items:
        if kind in ("etherchannel", "bridge_group"):
            for m in i.get("selectedInterfaces") or []:
                if m.get("id"):
                    out[str(m["id"])] = str(i.get("name") or i.get("ifname") or i.get("id"))
    return out


@dataclass
class LogicalPlan:
    body: dict[str, Any]  # the POST body
    hardware_name: str  # what FMC will call it (Loopback1, Tunnel2, Virtual-Template1, Port-channel1, BVI1)
    blockers: list[str]
    side_effects: list[str]


def free_number(used: set[int], lk: LogicalKind) -> int:
    for n in range(max(lk.low, 1), lk.high + 1):
        if n not in used:
            return n
    raise InvalidRequest(f"No free {lk.prefix} id between {lk.low} and {lk.high} on this device.")


def plan_logical_interface(
    kind: str,
    device: dict[str, Any],
    items: list[tuple[str, dict[str, Any]]],
    *,
    logical_name: str | None,
    number: int | None,
    members: list[str],
    zone: dict[str, Any] | None,
    ipv4: str | None,
    tunnel_source: str | None,
    tunnel_type: str,
    borrow_ip_from: str | None,
    lacp_mode: str,
    mtu: int | None,
    description: str | None,
    enabled: bool,
) -> LogicalPlan:
    """The POST body, name, blockers and side effects for one new logical interface. Arguments that don't
    fit the kind raise InvalidRequest; problems in the device's current configuration become blockers."""
    lk = LOGICAL_KINDS[kind]
    dname = str(device.get("name"))
    name = (logical_name or "").strip() or None
    block = ipv4_block(ipv4) if ipv4 else None
    dynamic = tunnel_type == "dynamic"
    a = f"{'an' if kind[0] in 'aeiou' else 'a'} {kind}"  # "a loopback", "an etherchannel"
    wrong: list[str] = []
    if members and kind not in MEMBER_KINDS:
        wrong.append("members are for etherchannel and bvi")
    if kind != "vti" and (tunnel_source or borrow_ip_from or dynamic):
        wrong.append("tunnel_source, borrow_ip_from and tunnel_type are for vti")
    if kind != "etherchannel" and lacp_mode != "active":
        wrong.append("lacp_mode is for etherchannel")
    if zone and lk.collection in NO_ZONE_KINDS:
        wrong.append(
            f"{a} takes no security zone in FMC"
            + (": zone its member interfaces instead (fmc_update_interface)" if kind == "bvi" else "")
        )
    if block and "dhcp" in block and lk.collection in NO_DHCP_KINDS:
        wrong.append(f"{a} takes a static address only, not dhcp")
    if mtu is not None and kind == "loopback":
        wrong.append("a loopback has no MTU setting")
    if kind in ("loopback", "vti") and not name:
        wrong.append(f"{a} needs a logical_name")
    if kind in MEMBER_KINDS and not members:
        wrong.append(f"{a} needs members (its member interfaces)")
    if kind in MEMBER_KINDS and len(members) > MAX_MEMBERS[kind]:
        wrong.append(f"at most {MAX_MEMBERS[kind]} members for {a}")
    if kind == "vti":
        if not tunnel_source:
            wrong.append("a vti needs tunnel_source (the interface the tunnel leaves from, usually the WAN)")
        if dynamic and (ipv4 or not borrow_ip_from):
            wrong.append("a dynamic vti borrows its address: give borrow_ip_from (a loopback), not ipv4")
        if not dynamic and bool(ipv4) == bool(borrow_ip_from):
            wrong.append("a static vti needs exactly one of ipv4 (e.g. a /30) or borrow_ip_from")
    if number is not None and not lk.low <= number <= lk.high:
        wrong.append(f"{kind} ids run {lk.low}-{lk.high}")
    if wrong:
        raise InvalidRequest(f"kind={kind!r}: " + "; ".join(wrong) + ".")

    blockers: list[str] = []
    side: list[str] = []
    if kind == "etherchannel" and is_virtual(device):
        blockers.append(
            f"{dname} is an FTDv ({device.get('model') or device.get('performanceTier')}): FMC doesn't "
            "support EtherChannel interfaces on virtual Threat Defense (FMC 10.0.1 refuses the POST with "
            "\"Etherchannel interface is not supported on 'Virtual' Threat Defense\"). Use separate "
            "interfaces, or a bvi to bridge them."
        )
    mode = str(device.get("ftdMode") or "ROUTED").upper()
    if mode != "ROUTED" and kind in ("loopback", "vti"):
        blockers.append(f"{dname} is in {mode.lower()} mode; loopbacks and VTIs need routed mode.")
    same_kind = [i for k, i in items if k == lk.collection]
    used = {int(i.get(lk.id_field) or 0) for i in same_kind}
    n = number if number is not None else free_number(used, lk)
    if number is not None and number in used:
        owner = next(i for i in same_kind if int(i.get(lk.id_field) or 0) == number)
        blockers.append(f"{lk.type} id {number} is already {owner.get('name')} on {dname}.")
    if name:
        for k, i in items:
            if str(i.get("ifname") or "").lower() == name.lower():
                blockers.append(f"Logical name {name!r} is already used by {interface_row(k, i)['name']}.")
    if (zone or block) and not name:
        blockers.append(
            f"{a[0].upper()}{a[1:]} needs a logical_name before it can take a zone or an address."
        )
    hw = f"Virtual-Template{n}" if kind == "vti" and dynamic else f"{lk.prefix}{n}"
    body: dict[str, Any] = {"type": lk.type, lk.id_field: n, "enabled": enabled}
    if name:
        body["ifname"] = name
    owners = logical_members(items)

    def pick(
        ref: str, pool: list[tuple[str, dict[str, Any]]], what: str
    ) -> tuple[str, dict[str, Any]] | None:
        try:
            return pick_interface(pool, ref, dname)
        except (NotFound, InvalidRequest) as e:
            blockers.append(f"{what}: {e}")
            return None

    if kind == "vti":
        src = pick(str(tunnel_source), [x for x in items if x[0] != "vti"], "tunnel_source")
        if src:
            s = src[1]
            if s.get("managementOnly") or str(s.get("name", "")).lower().startswith("management"):
                blockers.append(
                    f"{s.get('name')} is a management interface; source the tunnel from a data interface."
                )
            elif not s.get("ifname"):
                blockers.append(
                    f"Tunnel source {s.get('name')} has no logical name; set one with "
                    "fmc_update_interface first."
                )
            body["tunnelSource"] = iref(s)
        body["tunnelType"] = "DYNAMIC" if dynamic else "STATIC"
        body["ipsecMode"] = "ipv4"
        if borrow_ip_from:
            b = pick(borrow_ip_from, [x for x in items if x[0] != "vti"], "borrow_ip_from")
            if b:
                if static_network(b[1]) is None:
                    blockers.append(
                        f"{b[1].get('name')} has no static IPv4 address for the tunnel to borrow."
                    )
                body["ipAddressAssignmentType"] = "BORROW_IP_FROM_INTERFACE"
                body["borrowIPfrom"] = iref(b[1])
        side.append(
            "A VTI carries traffic once a route-based VPN uses it (fmc_create_s2s_vpn route_based, or an "
            "SD-WAN topology) and routes point at it."
        )
        if not zone:
            side.append(
                "No security zone: access rules can't match the tunnel's traffic by zone until it has one "
                "(fmc_update_interface security_zone=...)."
            )
    if kind in MEMBER_KINDS:
        pool = [x for x in items if x[0] in MEMBER_KINDS[kind]]
        picked: list[dict[str, Any]] = []
        for ref in members:
            got = pick(ref, pool, "member")
            if not got:
                continue
            mk, m = got
            label = m.get("name") if mk != "subinterface" else interface_row(mk, m)["name"]
            if any(p["id"] == m["id"] for p in picked):
                blockers.append(f"Member {label} is listed twice.")
                continue
            picked.append(m)
            if m.get("managementOnly") or str(m.get("name", "")).lower().startswith("management"):
                blockers.append(f"{label} is a management interface and can't be a member.")
            if str(m.get("id")) in owners:
                blockers.append(f"{label} is already a member of {owners[str(m['id'])]}.")
            if kind == "etherchannel":
                if m.get("ifname") or m.get("ipv4") or m.get("securityZone"):
                    blockers.append(
                        f"{label} is configured (logical name, address or zone); EtherChannel members "
                        "inherit the channel's settings: clear it first (fmc_update_interface "
                        "logical_name='none', ipv4='none', security_zone='none')."
                    )
                subs = [i for k, i in items if k == "subinterface" and i.get("name") == m.get("name")]
                if subs:
                    names = ", ".join(str(interface_row("subinterface", i)["name"]) for i in subs)
                    blockers.append(
                        f"{label} has subinterfaces ({names}); delete them first or create them on the "
                        "EtherChannel afterwards."
                    )
                if not m.get("enabled"):
                    side.append(
                        f"Member {label} is disabled; enable it (fmc_update_interface) or the link "
                        "stays down."
                    )
            else:
                if static_network(m) or (m.get("ipv4") or {}).get("dhcp"):
                    blockers.append(
                        f"{label} has its own IPv4 address; bridge-group members can't: clear it first "
                        "(fmc_update_interface ipv4='none'). The address goes on the BVI."
                    )
                if not m.get("ifname"):
                    side.append(
                        f"Member {label} has no logical name: give it one and a SWITCHED security zone "
                        "(fmc_update_interface) before it passes traffic; FMC refuses a ROUTED zone on a "
                        "bridge-group member."
                    )
        body["selectedInterfaces"] = [iref(m) for m in picked]
        if kind == "etherchannel":
            body["mode"] = "NONE"
            body["lacpMode"] = lacp_mode.upper()
            side.append(
                "The peer switch needs a matching port-channel "
                + ("(LACP)." if lacp_mode != "on" else "(static, mode on).")
            )
    if zone:
        body["securityZone"] = zone
    if block:
        body["ipv4"] = block
        mine = static_network(body)
        if mine is not None:
            if kind == "bvi":
                body["ipAddress"] = str(mine.ip)  # the spec's examples mirror the address here
            for k, i in items:
                other = static_network(i)
                if other is not None and other.network.overlaps(mine.network):
                    blockers.append(
                        f"{mine} overlaps {interface_row(k, i)['name']} ({other}); routed interfaces need "
                        "separate subnets."
                    )
    if mtu is not None:
        body["MTU"] = mtu
    if description:
        body["description"] = description
    return LogicalPlan(body, hw, list(dict.fromkeys(blockers)), side)


LicenseCap = Literal["ESSENTIALS", "IPS", "MALWARE_DEFENSE", "URL", "CARRIER"]


async def _assignment_domain(app: FmcApp, pol: dict[str, Any], here: str, listed_in: str | None) -> str:
    """The domain to write a policy's assignment in: the policy's owner (its metadata.domain, else the
    ancestor whose list holds its assignment) when that is an ancestor of the calling domain (FMC refuses
    it below), else the calling domain."""
    dom = owner_domain(pol)
    owner = str(dom["id"]).lower() if dom else ""
    if not owner and listed_in:
        owner = (await app.domain_uuid(listed_in)).lower()
    if owner and owner != here and owner in {d.lower() for d in await app.domain_ancestors(here)}:
        return owner
    return here


async def _device_domain_assignments(
    app: FmcApp, records: dict[str, dict[str, Any]], here: str, seen_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Assignments listed only in the devices' own (descendant) domains: called from Global for a leaf
    device, Global's list lacks the leaf-owned policy it runs (FMC lists a domain's own policies'
    assignments), so the preview's `from` would be empty. One list per such domain; unreadable ones are
    skipped."""
    seen = {str(a.get("id")) for a in seen_rows}
    out: list[dict[str, Any]] = []
    below: list[str] = []
    for rec in records.values():
        dom = owner_domain(rec)
        uuid = str(dom["id"]).lower() if dom else ""
        if uuid and uuid != here and uuid not in below and here in await app.domain_ancestors(uuid):
            below.append(uuid)
    for uuid in below:
        try:
            page = await app.all(await app.config_path(ASSIGNMENTS, uuid), cap=5000)
        except (AuthError, NotFound):
            continue
        for a in page.items:
            if str(a.get("id")) not in seen:
                seen.add(str(a.get("id")))
                out.append(a)
    return out


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
        device: DeviceOrGroup,
        add: Annotated[
            list[LicenseCap] | None, Field(description="Licences to add, e.g. IPS for intrusion policies")
        ] = None,
        remove: Annotated[list[LicenseCap] | None, Field(description="Licences to remove")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add or remove a device's licence capabilities (ESSENTIALS, IPS, MALWARE_DEFENSE, URL, CARRIER),
        or those of every device in a device group (one preview; members that already match are left
        alone). Intrusion policies on access rules need IPS, file policies MALWARE_DEFENSE, URL categories
        URL; without them the deploy fails validation ("requires a Threat license"). Uses the FMC's Smart
        Licensing (or evaluation) entitlements; takes effect with the next deployment."""
        app: FmcApp = get_client(ctx)
        if set(add or []) & set(remove or []):
            raise InvalidRequest("A licence can't be in both add and remove.")
        fleet = await expand_devices(app, [device], domain, units=True)
        rows: list[tuple[str, dict[str, Any], list[str], list[str]]] = []  # (path, record, have, want)
        for ref in fleet.refs:
            if fleet.from_group(ref):  # a group member: its UUID
                path = await app.config_path(f"{DEVICES}/{ref}", domain)
            else:
                d = await resolve_in(app, DEVICES, ref, "device", domain)
                path = await app.config_path(f"{DEVICES}/{d['id']}", domain)
            cur = await app.api.get(path)
            have = list(cur.get("license_caps") or [])
            want = [c for c in have if c not in (remove or [])] + [c for c in (add or []) if c not in have]
            if "ESSENTIALS" not in want:
                raise InvalidRequest("ESSENTIALS is the base licence and can't be removed.")
            rows.append((path, cur, have, want))
        changing = [r for r in rows if r[2] != r[3]]

        async def put(path: str, want: list[str]) -> Any:
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

        group = next(iter(fleet.groups), None)
        if not rows:
            raise InvalidRequest(f"Device group {group!r} has no devices.")

        async def apply() -> Any:
            if group is None:
                return await put(rows[0][0], rows[0][3])
            done: list[dict[str, Any]] = []
            for path, cur, _, want in changing:
                try:
                    await put(path, want)
                except Exception as e:  # say which members already changed (one PUT per member)
                    rest = [str(c.get("name")) for _, c, _, _ in changing][len(done) :]
                    applied_names = [str(d["device"]) for d in done] or "none"
                    raise UpstreamError(
                        f"Licences of {cur.get('name')!r} failed ({e}). Applied: {applied_names}; not "
                        f"applied: {rest}. Check with fmc_license_status, then repeat the call.",
                        getattr(e, "status_code", None),
                    ) from e
                done.append({"device": cur.get("name"), "license_caps": want})
            return {"group": group, "updated": done}

        dropped = sorted({c for _, _, h, w in changing for c in h if c not in w})
        side = ["Consumes the licences from Smart Licensing; effective after the next deploy."]
        if dropped:
            side.append(
                f"Rules that need {', '.join(dropped)} (intrusion/file/URL) will fail the next deploy."
            )
        if group is not None:
            plan = Plan(
                f"Licences of {len(changing)} of the {len(rows)} device(s) in group {group!r}",
                details={
                    "changes": [{"device": c.get("name"), "from": h, "to": w} for _, c, h, w in changing],
                    "unchanged": [c.get("name") for _, c, h, w in rows if h == w],
                },
                fingerprint=[(c.get("id"), h) for _, c, h, _ in rows],
                blockers=[] if changing else ["Nothing to change."],
                blast_radius=len(changing),
                side_effects=side,
            )
        else:
            _, cur, have, want = rows[0]
            plan = Plan(
                f"Licences of {cur.get('name')!r}: {', '.join(have)} -> {', '.join(want)}",
                details={"from": have, "to": want},
                fingerprint=have,
                blockers=[] if want != have else ["Nothing to change."],
                side_effects=side,
            )
        return await fmc_preview(
            ctx,
            tool="fmc_set_device_licenses",
            args={"device": device, "add": add, "remove": remove, "domain": domain},
            confirm=confirm,
            plan=plan,
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
        mode: Annotated[
            Literal["routed", "inline", "passive"] | None,
            Field(
                description="Physical interface / EtherChannel mode: routed (FMC 'None'), inline (an inline "
                "set member, fmc_create_inline_set) or passive (IPS-only, a SPAN copy); omit to keep"
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Configure an existing device interface (physical, subinterface, EtherChannel, VLAN, VTI,
        loopback or BVI): logical name, admin state, security zone, IPv4 (static or DHCP), MTU,
        description and, on physical interfaces and EtherChannels, the mode (routed, or IPS-only inline /
        passive: no address, an INLINE / PASSIVE zone). Only the fields you pass change. A routed data
        interface needs a logical name to carry traffic or join a zone; loopbacks and BVIs take no zone,
        loopbacks and VTIs no DHCP, and an address on a VTI replaces the one it borrowed. Preview shows
        the before/after; deploy with fmc_deploy. New loopbacks, VTIs, EtherChannels and BVIs:
        fmc_create_interface; inline pairs: fmc_create_inline_set."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        items = await device_interfaces(app, dev["id"], domain)
        kind, current = pick_interface(items, interface, dev["name"])
        if kind != "physical" and current.get("type") == "PhysicalInterface":
            kind = "physical"
        # FMC's PUT replaces the whole interface: start from the full object, not the list item.
        item_path = await app.config_path(
            f"{DEVICES}/{dev['id']}/{INTERFACE_KINDS[kind]}/{current['id']}", domain
        )
        current = await app.api.get(item_path)
        desired = interface_put_body(kind, current)
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
                if kind == "vti" and desired.get("borrowIPfrom"):  # its own address replaces the borrowed one
                    desired.pop("borrowIPfrom", None)
                    desired["ipAddressAssignmentType"] = "MANUAL_IP"
            if kind == "bridge_group":  # FMC mirrors a BVI's static address in ipAddress
                own = static_network(desired)
                if own is not None:
                    desired["ipAddress"] = str(own.ip)
                else:
                    desired.pop("ipAddress", None)
        if mtu is not None:
            desired["MTU"] = mtu
        if description is not None:
            if description:
                desired["description"] = description
            else:
                desired.pop("description", None)
        if mode is not None:
            desired["mode"] = IFACE_MODES[mode]
        if kind == "physical" and desired.get("ifname") and desired.get("mode") in (None, "NONE"):
            desired["mode"] = "NONE"  # routed
        zones = await zone_names(app, domain)
        before = name_zones([iface_summary(kind, current)], zones)[0]
        after = name_zones([iface_summary(kind, desired)], zones)[0]
        changes = diff_rows(before, after)
        blockers = [] if changes else ["Nothing to change: the interface already has these settings."]
        if (desired.get("securityZone") or desired.get("ipv4")) and not desired.get("ifname"):
            blockers.append("An interface needs a logical_name before it can take a zone or an address.")
        if kind in NO_ZONE_KINDS and security_zone and security_zone.strip().lower() != "none":
            blockers.append(
                f"A {kind.replace('_', ' ')} interface takes no security zone in FMC"
                + ("; zone the bridge group's members instead." if kind == "bridge_group" else ".")
            )
        if kind in NO_DHCP_KINDS and ipv4 and ipv4.strip().lower() == "dhcp":
            blockers.append(f"A {kind} interface takes a static address only, not dhcp.")
        bvi = bridge_group_of(items).get(str(current.get("id")))
        new_zone = (
            desired.get("securityZone") if security_zone and security_zone.strip().lower() != "none" else None
        )
        if bvi and new_zone and new_zone.get("id"):
            zone = await app.api.get(await app.config_path(f"object/securityzones/{new_zone['id']}", domain))
            zmode = str(zone.get("interfaceMode") or "").upper()
            if zmode and zmode != "SWITCHED":
                blockers.append(
                    f"{current.get('name')} is a member of {bvi}: FMC needs a SWITCHED security zone on a "
                    f"bridge-group member and {zone.get('name')!r} is {zmode} (FMC refuses it with "
                    '"Security zone should be in same mode as of Interface mode type"). Use a SWITCHED '
                    "zone (fmc_create_security_zone interface_mode='SWITCHED')."
                )
        ips_mode = str(desired.get("mode") or "NONE").upper()
        if mode is not None and kind not in ("physical", "etherchannel"):
            blockers.append(
                f"Only physical interfaces and EtherChannels have a mode; {kind} is always routed."
            )
        elif ips_mode in ("INLINE", "PASSIVE"):
            what = "An inline" if ips_mode == "INLINE" else "A passive"
            if desired.get("ipv4"):
                blockers.append(
                    f"{what} interface takes no IP address: clear it in the same call "
                    "(ipv4='none'), after moving any routes, NAT or VPN off its logical name."
                )
            if not desired.get("ifname"):
                blockers.append(f"{what} interface needs a logical_name.")
            zid = (desired.get("securityZone") or {}).get("id")
            if zid:
                zone = await app.api.get(await app.config_path(f"object/securityzones/{zid}", domain))
                zmode = str(zone.get("interfaceMode") or "").upper()
                if zmode and zmode != ips_mode:
                    blockers.append(
                        f"{what} interface needs a security zone of mode {ips_mode} and "
                        f"{zone.get('name')!r} is {zmode}: pass security_zone='none' or such a zone "
                        f"(fmc_create_security_zone interface_mode='{ips_mode}')."
                    )
        if kind == "loopback" and mtu is not None:
            blockers.append("A loopback has no MTU setting.")
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
                "mode": mode,
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

    @reg.write(title="Create interface")
    async def fmc_create_interface(
        ctx: Context,
        device: DeviceRef,
        kind: Annotated[
            CreateKind,
            Field(
                description="loopback, vti (static or dynamic virtual tunnel interface), etherchannel "
                "(port-channel of physical members) or bvi (bridge group virtual interface over members)"
            ),
        ],
        logical_name: Annotated[
            str | None,
            Field(
                description="Logical name (nameif), e.g. bgp-lo or s2s-tunnel; required for loopback and "
                "vti, and for an etherchannel or bvi that takes an address or zone"
            ),
        ] = None,
        number: Annotated[
            int | None,
            Field(
                ge=0,
                le=10413,
                description="Loopback id (1-1024), tunnel id (0-10413), EtherChannel id (1-48) or bridge "
                "group id (1-250); default: the lowest free one",
            ),
        ] = None,
        members: Annotated[
            list[str] | None,
            Field(
                description="etherchannel / bvi: member interfaces (hardware or logical name, or UUID). "
                "EtherChannel members are unconfigured physical interfaces; BVI members are physical, "
                "subinterface or EtherChannel interfaces without an address"
            ),
        ] = None,
        security_zone: Annotated[
            str | None,
            Field(description="Security zone name/UUID (vti, etherchannel; a bvi is zoned on its members)"),
        ] = None,
        ipv4: Annotated[
            str | None,
            Field(
                description="'address/prefix' (a loopback usually /32, a static vti /30) or 'dhcp' "
                "(etherchannel, bvi)"
            ),
        ] = None,
        tunnel_source: Annotated[
            str | None,
            Field(
                description="vti: the interface the tunnel leaves from (usually the WAN; needs a "
                "logical name)"
            ),
        ] = None,
        tunnel_type: Annotated[
            Literal["static", "dynamic"],
            Field(
                description="vti: static (one peer: route-based VPN, SD-WAN spoke) or dynamic (DVTI on a "
                "hub/headend; needs borrow_ip_from)"
            ),
        ] = "static",
        borrow_ip_from: Annotated[
            str | None,
            Field(description="vti: borrow this interface's address (usually a loopback) instead of ipv4"),
        ] = None,
        lacp_mode: Annotated[
            Literal["active", "passive", "on"],
            Field(description="etherchannel: LACP mode (on = static channel, no LACP)"),
        ] = "active",
        mtu: Annotated[
            int | None, Field(ge=64, le=9198, description="MTU (vti, etherchannel, bvi; default 1500)")
        ] = None,
        description: Annotated[str | None, Field(description="Description")] = None,
        enabled: Annotated[bool, Field(description="Admin state")] = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a logical interface on a device: a loopback (router id, routing source, the address a
        VTI borrows), a static or dynamic VTI for route-based VPN and SD-WAN (sourced from the WAN, with
        its own address or a borrowed loopback one), an EtherChannel (port-channel of physical members,
        LACP or static; hardware models only, FMC refuses it on FTDv) or a bridge group virtual
        interface (BVI) over member interfaces, with logical name, zone and IPv4. The id defaults to the
        lowest free one. The preview shows the interface, its members and what blocks it (used names or
        ids, configured or taken members, overlapping subnets, EtherChannel on FTDv). Change it with
        fmc_update_interface, remove it with fmc_delete_interface; list it with
        fmc_list_device_interfaces(kinds=[...]). Takes effect after fmc_deploy."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        items = await device_interfaces(app, dev["id"], domain)
        zone = await zone_ref(RefResolver(app, domain), security_zone) if security_zone else None
        plan = plan_logical_interface(
            kind,
            dev,
            items,
            logical_name=logical_name,
            number=number,
            members=[m for m in members or [] if m.strip()],
            zone=zone,
            ipv4=ipv4,
            tunnel_source=tunnel_source,
            tunnel_type=tunnel_type,
            borrow_ip_from=borrow_ip_from,
            lacp_mode=lacp_mode,
            mtu=mtu,
            description=description,
            enabled=enabled,
        )
        lk = LOGICAL_KINDS[kind]
        summary = iface_summary(lk.collection, {**plan.body, "name": plan.hardware_name})
        if zone:
            summary["zone"] = zone.get("name") or summary.get("zone")
        path = await app.config_path(f"{DEVICES}/{dev['id']}/{INTERFACE_KINDS[lk.collection]}", domain)
        label = f" ({plan.body['ifname']})" if plan.body.get("ifname") else ""
        return await fmc_preview(
            ctx,
            tool="fmc_create_interface",
            args={
                "device": device,
                "kind": kind,
                "logical_name": logical_name,
                "number": number,
                "members": members,
                "security_zone": security_zone,
                "ipv4": ipv4,
                "tunnel_source": tunnel_source,
                "tunnel_type": tunnel_type,
                "borrow_ip_from": borrow_ip_from,
                "lacp_mode": lacp_mode,
                "mtu": mtu,
                "description": description,
                "enabled": enabled,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create {kind} {plan.hardware_name}{label} on {dev.get('name')}",
                details={"interface": summary, "body": plan.body},
                fingerprint={
                    "device": dev["id"],
                    "interfaces": sorted(
                        (str(i.get("id")), str(i.get("ifname") or ""), str(i.get(lk.id_field) or ""))
                        for _, i in items
                    ),
                },
                blockers=plan.blockers,
                side_effects=[*plan.side_effects, "Takes effect on the device after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, plan.body)),
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
        fmc_update_interface. The preview blocks while static routes, a VTI (borrowed address or tunnel
        source), a VPN topology, a bridge group or subinterfaces still use it, and lists the members an
        EtherChannel or BVI releases; FMC also refuses while NAT or other config references it."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        items = await device_interfaces(app, dev["id"], domain)
        kind, current = pick_interface(items, interface, dev["name"])
        blockers = []
        side: list[str] = []
        if kind not in DELETABLE_KINDS or current.get("type") == "PhysicalInterface":
            blockers.append(
                f"{current.get('name')} is a {kind} interface; only logical interfaces can be deleted."
            )
        cid, label = str(current.get("id")), interface_row(kind, current)["name"]
        for k, i in items:
            if k != "vti" or str(i.get("id")) == cid:
                continue
            vti = i.get("ifname") or i.get("name")
            if (i.get("borrowIPfrom") or {}).get("id") == cid:
                blockers.append(
                    f"VTI {vti} borrows {label}'s address: delete it, or give it its own address first "
                    "(fmc_update_interface ipv4=...)."
                )
            if (i.get("tunnelSource") or {}).get("id") == cid:
                blockers.append(f"VTI {vti} is sourced from {label}: delete it first.")
        topology = (current.get("metadata") or {}).get("vpnTopologyName")
        if topology:
            blockers.append(
                f"{label} belongs to VPN topology {topology!r}: take the device out of it first "
                "(fmc_update_ftdsdwan_topology remove_spokes, or fmc_delete_s2s_vpn)."
            )
        owner = logical_members(items).get(cid)
        if owner:
            blockers.append(f"{label} is a member of {owner}: remove it from there first.")
        if kind == "etherchannel":
            subs = [i for k, i in items if k == "subinterface" and i.get("name") == current.get("name")]
            if subs:
                names = ", ".join(str(interface_row("subinterface", i)["name"]) for i in subs)
                blockers.append(f"{label} still has subinterfaces ({names}): delete them first.")
        if current.get("selectedInterfaces"):
            names = ", ".join(ref_label(m) for m in current["selectedInterfaces"])
            if kind == "bridge_group":
                side.append(
                    f"Its members ({names}) leave the bridge group but FMC keeps their logical names: "
                    "clear them (fmc_update_interface logical_name='none', and security_zone='none' if "
                    "they have one) unless they are reused."
                )
            else:
                side.append(f"Its members ({names}) are released as unconfigured interfaces.")
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
                f"Delete {kind} interface {label} on {dev.get('name')}",
                details={"interface": iface_summary(kind, current)},
                fingerprint=editable(current),
                blockers=list(dict.fromkeys(blockers)),
                side_effects=[*side, "Removed from the device on the next deployment."],
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
        track: Annotated[
            str | None,
            Field(
                description="SLA monitor name/UUID (fmc_create_sla_monitor) this route tracks: it leaves the "
                "routing table while the monitor is down, so a floating route to the same networks with a "
                "higher metric takes over. IPv4 routes only"
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a static route (IPv4 or IPv6, picked from the gateway) to a device, in the global table
        or a virtual router. Destinations must be network/host objects; a CIDR is accepted when an
        object with that value exists (create one with fmc_create_object otherwise). Dual-ISP failover:
        the primary route with track=<SLA monitor> and a floating backup through the other ISP with a
        higher metric; the preview names the backup and warns when there is none or it has the same
        metric. Takes effect after fmc_deploy; check with fmc_list_routes and
        fmc_run_show_command('show route', 'show sla monitor operational-state')."""
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
        if track:
            if version != 4:
                blockers.append("Route tracking (SLA monitor) is for IPv4 static routes only.")
            else:
                _, monitor = await resolve_object(app, track, domain, ["sla_monitor"])
                body["routeTracking"] = {
                    "id": monitor["id"],
                    "type": "SLAMonitor",
                    "name": monitor.get("name"),
                }
        warnings: list[str] = []
        failover: dict[str, Any] = {}
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
            failover, warnings = failover_check(body, [r for r in existing.items if route_key(r) != want])
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
                "track": track,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Add static route on {dev.get('name')} ({vr_name or 'global table'})",
                details={
                    "route": route_row(f"static{version}", body),
                    **failover,
                    **({"warnings": warnings} if warnings else {}),
                    "body": body,
                },
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
        """Delete one static route (IPv4 or IPv6) from a device. Preview shows the route, and warns when it
        is the device's last route tracking an SLA monitor (FMC leaves that 'sla monitor' on the device).
        Takes effect after fmc_deploy."""
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
        side = ["Removed from the device on the next deployment."]
        tracking = current.get("routeTracking") or {}
        others: list[str] = []
        if tracking.get("id"):
            # imported here: sla_monitors imports this module
            from fmc_mcp.tools.sla_monitors import leftover_warning, resolve_monitor, routes_tracking

            mid = str(tracking["id"])
            others = sorted(
                str(r["id"])
                for r in await routes_tracking(app, mid, domain, dev)
                if str(r["id"]) != current["id"]
            )
            if not others:
                try:
                    sla_id = (await resolve_monitor(app, mid, domain)).get("slaId")
                except NotFound:
                    sla_id = None
                side.append(
                    f"This is the last route on {dev.get('name')} tracking SLA monitor "
                    f"{ref_label(tracking)}. " + leftover_warning(sla_id, str(dev.get("name")))
                )
        path = await app.config_path(f"{base}/{sub}/{current['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_static_route",
            args={"device": device, "route_id": route_id, "virtual_router": virtual_router, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete static route on {dev.get('name')}",
                details={"route": route_row(kind, current)},
                fingerprint={"route": editable(current), "other_tracking_routes": others},
                side_effects=side,
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
            list[str],
            Field(
                min_length=1,
                description="Device (or HA pair/cluster) names/UUIDs, or device groups ('group:<name>')",
            ),
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Assign an access control, NAT or platform settings policy to devices (or every device of a
        device group). A device has one policy
        of each type, so this replaces its current one (the preview's `from`, also when it is a policy
        inherited from an ancestor domain or one the device's own child domain owns). A policy owned by
        an ancestor domain (e.g. a Global policy for a leaf device) is assigned in that domain, the only
        one where FMC takes it (the preview's `assigned_in`). The new policy reaches the device on the
        next fmc_deploy. Current assignments: fmc_list_policy_assignments."""
        app: FmcApp = get_client(ctx)
        here = (await app.domain_uuid(domain)).lower()
        pol = await resolve_in(app, POLICY_KINDS[kind], policy, f"{kind} policy", domain)
        targets: list[dict[str, Any]] = []
        records: dict[str, dict[str, Any]] = {}
        fleet = await expand_devices(app, devices, domain)
        for ref in fleet.refs:
            try:
                d = await resolve_device(app, ref, domain)
            except NotFound:
                d = await resolve_in(app, "devicehapairs/ftddevicehapairs", ref, "device or HA pair", domain)
            targets.append({"id": d["id"], "type": d.get("type") or "Device", "name": d.get("name")})
            records[d["id"]] = d
        # the leaf's own list misses policies inherited from Global: policy_assignments reads both
        assignments = await policy_assignments(app, domain)
        found = next((a for a in assignments if (a.get("policy") or {}).get("id") == pol["id"]), None)
        mine = {k: v for k, v in found.items() if k != "_domain"} if found else None
        policy_type = ASSIGNABLE[kind]
        current: dict[str, str] = {}
        for a in assignments + await _device_domain_assignments(app, records, here, assignments):
            p = a.get("policy") or {}
            if p.get("type") != policy_type:
                continue
            for t in a.get("targets") or []:
                current.setdefault(str(t.get("id")), str(p.get("name")))
        if kind == "access":  # the device record names its access policy even when no list shows it
            for tid, rec in records.items():
                acp = rec.get("accessPolicy") or {}
                if tid not in current and acp.get("name"):
                    current[tid] = str(acp["name"])
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
        owner = (found or {}).get("_domain")
        # FMC 10.0.1 takes an assignment of an ancestor's policy only in the policy's own domain: the POST
        # in the child domain answered 406 "You do not have the required authorization to do this
        # operation." (Global policy, leaf device, final-live 2026-10-21); the same call in Global worked.
        write_in = await _assignment_domain(app, pol, here, owner)
        write_name = await app.domain_name(write_in)
        elsewhere = write_in.lower() != here
        if mine:
            body["id"] = mine["id"]
            path = await app.config_path(f"{ASSIGNMENTS}/{mine['id']}", write_in)
        else:
            path = await app.config_path(ASSIGNMENTS, write_in)

        async def apply() -> Any:
            try:
                if mine:
                    return await applied(app, lambda: app.api.put(path, body))
                return await applied(app, lambda: app.api.post(path, body))
            except UpstreamError as e:
                if elsewhere and (isinstance(e, AuthError) or e.status_code in (403, 406)):
                    raise UpstreamError(
                        f"FMC refused the assignment in domain {write_name!r}, which owns "
                        f"{pol.get('name')!r}: {e}. FMC takes this policy's assignments only there, so "
                        f"the account needs write access to {write_name!r}; or assign a policy of "
                        f"{await app.domain_name(here)!r} instead.",
                        e.status_code,
                    ) from e
                raise

        side_effects = ["The devices get the new policy on the next deployment."]
        if elsewhere:
            side_effects.append(
                f"{pol.get('name')!r} belongs to domain {write_name!r}: the assignment is made there (FMC "
                f"10.0.1 refuses it in {await app.domain_name(here)!r} with 406 'You do not have the "
                "required authorization'). Same devices, same effect."
            )
        if owner:
            side_effects.append(
                f"{pol.get('name')} belongs to domain {owner!r} (inherited here); its assignment "
                f"keeps its {len(existing)} other target(s)."
            )
        return await fmc_preview(
            ctx,
            tool="fmc_assign_policy",
            args={"kind": kind, "policy": policy, "devices": devices, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Assign {kind} policy {pol.get('name')!r} to {len(new)} device(s)",
                details={
                    "changes": changes,
                    **({"policy_domain": owner} if owner else {}),
                    **({"assigned_in": write_name} if elsewhere else {}),
                    **({"groups": fleet.groups} if fleet.groups else {}),
                },
                fingerprint={
                    "assignment": mine and editable(mine),
                    "current": current,
                    "write_in": write_in.lower(),
                },
                blockers=blockers,
                side_effects=side_effects,
            ),
            apply=apply,
        )

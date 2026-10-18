"""Firewall SD-WAN (F51a): build and change FMC's SD-WAN wizard topology (AUTO_VPN hub and spoke).

The wizard's topology is an `FTDS2SVpn` with `topologyType: AUTO_VPN` (with HUB_AND_SPOKE FMC silently
drops `autoVpnSettings`). Each hub terminates spokes on a dynamic VTI (DVTI) that borrows its address
from a loopback, and hands each spoke a tunnel address from an `IPv4AddressPool`; spokes are added on
their physical WAN interface and FMC builds the spoke's static VTI itself. With iBGP on, FMC generates
the overlay routing (`router bgp <AS>` with community-tagged route maps and the inside networks
redistributed). Reads stay on fmc_list_vpn_topologies(kind='sdwan') and fmc_get_vpn_topology; delete
with fmc_delete_s2s_vpn.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
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
    get_client,
)
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, pick_by_name, ref_label, resolve_object
from fmc_mcp.tools.device_config import device_interfaces, iref, pick_interface
from fmc_mcp.tools.devices import DEVICES, INTERFACE_KINDS
from fmc_mcp.tools.vpn import (
    DEFAULT_IKE_POLICY,
    DEFAULT_IPSEC_PROPOSAL,
    MASK,
    S2S,
    WEAK_IKE_POLICY,
    WEAK_IPSEC_PROPOSAL,
    TopologyRef,
    _named,
    _one,
    _peer_device,
    endpoint_row,
    resolve_topology,
    strong_crypto_allowed,
    topology_row,
)

POOLS = "object/ipv4addresspools"
WAN_KINDS = ["physical", "subinterface", "etherchannel", "vlan"]
DEFAULT_AS = 65000
DEFAULT_COMMUNITY = 1000
MAX_TUNNEL_ID = 10413
MAX_LOOPBACK_ID = 1024
# The top-level topology fields a PUT on policy/ftds2svpns/{id} carries (with autoVpnSettings). FMC
# 10.0.1 refuses the GET body's sub-resource references (ikeSettings, ipsecSettings,
# advancedSettings, endpoints) with 422 "Invalid value 'either need to be mapped to concrete types
# ...' for field 'ipsecSettings'"; those have their own endpoints.
TOPOLOGY_PUT_FIELDS = (
    "id",
    "name",
    "type",
    "description",
    "topologyType",
    "routeBased",
    "ikeV1Enabled",
    "ikeV2Enabled",
)


class SpokeSpec(BaseModel):
    """One branch (spoke) of an SD-WAN topology."""

    device: str = Field(min_length=1, description="Spoke FTD or HA pair (name/UUID)")
    wan_interface: str = Field(
        min_length=1,
        description="The spoke's WAN interface (logical or hardware name); it must be in a security zone. "
        "FMC builds the spoke's VTI on it and addresses it from the hub's spoke pool",
    )
    backup_wan_interface: str | None = Field(
        None,
        description="A second WAN interface for a second tunnel to the hub (e.g. inet or LTE). It "
        "terminates on the hub's second-WAN DVTI (hub_backup_wan_interface) in the companion "
        "topology '<name>-wan2'; both tunnels carry iBGP, so traffic fails over when one goes down",
    )
    inside_interfaces: list[str] = Field(
        default_factory=list,
        description="Inside interfaces whose connected networks the overlay advertises (iBGP)",
    )


Spokes = Annotated[list[SpokeSpec] | None, Field(description="Spokes (branches) to add")]
PoolArg = Annotated[
    str | None,
    Field(
        description="The hub's spoke tunnel address pool: an existing IPv4 address pool (name/UUID), or a "
        "subnet such as 10.255.255.0/24 to create one (the hub takes the first address on a new "
        "loopback, spokes get the rest). Each hub needs its own, non-overlapping subnet"
    ),
]
DvtiArg = Annotated[
    str,
    Field(
        description="Logical name of the hub's dynamic VTI: reused when it exists on the hub, otherwise "
        "created (sourced from the hub WAN interface, borrowing the loopback's address)"
    ),
]
LoopbackArg = Annotated[
    str | None,
    Field(
        description="Existing loopback (logical or hardware name) the new DVTI borrows its address "
        "from; omit to create one with the pool subnet's first address"
    ),
]
SpokeLoopbacksArg = Annotated[
    str | list[str] | None,
    Field(
        description="overlay='ospf': the /32 loopback each spoke's tunnel borrows its address from, so both "
        "tunnel ends are unnumbered (needed for OSPF routes on the spokes, FMC 10.0.1). A subnet outside "
        "the spoke pools (e.g. 10.255.9.0/24: the spokes get its addresses in order, from the first), or "
        "one address per spoke in the order of the spokes. A spoke loopback that already has the address "
        "is reused"
    ),
]


# --- planning -----------------------------------------------------------------------------------


@dataclass
class PoolPlan:
    ref: dict[str, Any] | None  # an existing pool
    body: dict[str, Any] | None  # or one to create
    network: ipaddress.IPv4Network | None
    hub_ip: str | None  # the first address of a new pool subnet (for a new loopback)

    def label(self) -> str:
        if self.ref:
            return str(self.ref.get("name"))
        return f"{(self.body or {}).get('name')} (new: {(self.body or {}).get('ipAddressRange')})"


@dataclass
class HubPlan:
    """A hub (primary or backup): its device, DVTI and loopback (existing or new) and spoke pool."""

    role: str  # "primary hub" / "backup hub"
    device: dict[str, Any]  # {id, type, name}: Device or DeviceHAPair
    iface_device: str  # the device record whose interfaces are used (an HA pair's primary)
    primary: bool
    pool: PoolPlan
    inside: list[dict[str, Any]]
    dvti: dict[str, Any] | None = None  # existing DVTI ref
    dvti_body: dict[str, Any] | None = None  # or one to create (borrowIPfrom filled at apply)
    loopback: dict[str, Any] | None = None  # existing loopback ref
    loopback_body: dict[str, Any] | None = None  # or one to create
    blockers: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "role": self.role,
            "device": self.device["name"],
            "dvti": self.dvti["name"] if self.dvti else f"{(self.dvti_body or {}).get('ifname')} (new)",
            "spoke_pool": self.pool.label(),
            "inside": [ref_label(i) for i in self.inside] or None,
        }
        if self.dvti_body:
            out["dvti_source"] = ref_label(self.dvti_body["tunnelSource"])
            out["loopback"] = (
                ref_label(self.loopback)
                if self.loopback
                else f"{(self.loopback_body or {}).get('ifname')} (new: {self.pool.hub_ip}/32)"
            )
        return {k: v for k, v in out.items() if v is not None}


def _parse_range(rng: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address] | None:
    try:
        a, b = (ipaddress.IPv4Address(x.strip()) for x in rng.split("-", 1))
    except (ValueError, ipaddress.AddressValueError):
        return None
    return a, b


def pool_network(pool: dict[str, Any]) -> ipaddress.IPv4Network | None:
    """The subnet an existing IPv4 address pool hands addresses from (range start + mask)."""
    rng = _parse_range(str(pool.get("ipAddressRange") or ""))
    if not rng:
        return None
    mask = str(pool.get("mask") or "32")
    try:
        return ipaddress.IPv4Network(f"{rng[0]}/{mask}", strict=False)
    except ValueError:
        return None


async def plan_pool(app: FmcApp, ref: str, new_name: str, domain: str | None) -> PoolPlan:
    ref = ref.strip()
    if "/" in ref:
        try:
            net = ipaddress.IPv4Network(ref, strict=False)
        except ValueError:
            raise InvalidRequest(f"Spoke pool {ref!r} is not an IPv4 subnet or a pool name.") from None
        if net.prefixlen > 29:
            raise InvalidRequest(f"Spoke pool {ref!r} is too small; use a /29 or larger (e.g. a /24).")
        hosts = list(net.hosts())
        body = {
            "type": "IPv4AddressPool",
            "name": new_name,
            "ipAddressRange": f"{hosts[1]}-{hosts[-1]}",
            "mask": str(net.netmask),
            "description": "SD-WAN spoke tunnel addresses (fmc_create_sdwan_topology)",
        }
        return PoolPlan(None, body, net, str(hosts[0]))
    full = await app.config_path(POOLS, domain)
    if is_uuid(ref):
        pool: dict[str, Any] = await app.api.get(f"{full}/{ref}")
    else:
        page = await app.all(full, expanded=True, cap=2000)
        pool = pick_by_name(page.items, ref, "IPv4 address pool", partial=not page.complete)
    return PoolPlan(
        {"id": pool["id"], "type": pool.get("type") or "IPv4AddressPool", "name": pool.get("name")},
        None,
        pool_network(pool),
        None,
    )


def _free_id(used: set[int], top: int) -> int:
    return next(n for n in range(1, top + 1) if n not in used)


async def plan_hub(
    app: FmcApp,
    *,
    role: str,
    primary: bool,
    device: str,
    wan_interface: str | None,
    dvti: str,
    loopback: str | None,
    pool: str | None,
    pool_name: str,
    inside: list[str],
    zone: dict[str, Any],
    domain: str | None,
    taken_loopbacks: set[int] | None = None,
    taken_tunnels: set[int] | None = None,
) -> HubPlan:
    dev, iface_dev = await _peer_device(app, device, domain)
    vtis = await device_interfaces(app, iface_dev, domain, ["vti"])
    loops = await device_interfaces(app, iface_dev, domain, ["loopback"])
    others = await device_interfaces(app, iface_dev, domain, WAN_KINDS)
    if not pool:
        raise InvalidRequest(f"The {role} needs a spoke pool (an IPv4 address pool or a subnet).")
    pp = await plan_pool(app, pool, pool_name, domain)
    inside_refs = [iref(pick_interface(others, i, dev["name"])[1]) for i in inside]
    hub = HubPlan(role, dev, iface_dev, primary, pp, inside_refs)
    existing = [i for _, i in vtis if str(i.get("ifname") or "").lower() == dvti.strip().lower()]
    if existing:
        v = existing[0]
        hub.dvti = iref(v)
        if str(v.get("tunnelType") or "").upper() != "DYNAMIC":
            hub.blockers.append(
                f"{dvti!r} on {dev['name']} is a {v.get('tunnelType') or 'static'} VTI; an SD-WAN hub "
                "needs a dynamic VTI (pick another name to create one)."
            )
        return hub
    if not wan_interface:
        raise InvalidRequest(
            f"{dev['name']} has no VTI named {dvti!r}: give the {role}'s WAN interface to create it."
        )
    _, wan = pick_interface(others, wan_interface, dev["name"])
    if not wan.get("ifname"):
        hub.blockers.append(
            f"WAN interface {wan.get('name')} on {dev['name']} has no logical name; set one with "
            "fmc_update_interface first."
        )
    if loopback:
        _, lo = pick_interface(loops, loopback, dev["name"])
        hub.loopback = iref(lo)
        if not ((lo.get("ipv4") or {}).get("static") or {}).get("address"):
            hub.blockers.append(f"Loopback {lo.get('name')} on {dev['name']} has no IPv4 address.")
    else:
        if pp.hub_ip is None:
            raise InvalidRequest(
                f"With an existing pool, name the loopback the {role}'s DVTI borrows its address "
                "from (hub_loopback / backup_hub_loopback), or give the pool as a subnet."
            )
        lid = _free_id(
            {int(i.get("loopbackId") or 0) for _, i in loops} | (taken_loopbacks or set()), MAX_LOOPBACK_ID
        )
        hub.loopback_body = {
            "type": "LoopbackInterface",
            "loopbackId": lid,
            "enabled": True,
            "ifname": f"{dvti.strip()}-lo",
            "ipv4": {"static": {"address": pp.hub_ip, "netmask": "255.255.255.255"}},
        }
    tid = _free_id({int(i.get("tunnelId") or 0) for _, i in vtis} | (taken_tunnels or set()), MAX_TUNNEL_ID)
    hub.dvti_body = {
        "type": "VTIInterface",
        "tunnelType": "DYNAMIC",
        "tunnelId": tid,
        "ifname": dvti.strip(),
        "enabled": True,
        "tunnelSource": iref(wan),
        "securityZone": {"id": zone["id"], "type": "SecurityZone", "name": zone.get("name")},
        "ipAddressAssignmentType": "BORROW_IP_FROM_INTERFACE",
        "ipsecMode": "ipv4",
        "description": "SD-WAN hub DVTI (fmc_create_sdwan_topology)",
    }
    return hub


@dataclass
class SpokePlan:
    device: dict[str, Any]
    wan: dict[str, Any]
    backup: dict[str, Any] | None
    inside: list[dict[str, Any]]
    blockers: list[str]
    iface_device: str = ""  # the device record whose interfaces are used (an HA pair's primary)
    loopbacks: list[tuple[Any, dict[str, Any]]] = field(default_factory=list)  # the spoke's, at planning
    vti_ids: set[str] = field(default_factory=set)  # the spoke's VTIs before the topology
    loopback_ip: str | None = None  # overlay='ospf': the /32 its tunnel borrows
    loopback: dict[str, Any] | None = None  # an existing loopback with that address
    loopback_body: dict[str, Any] | None = None  # or one to create

    def endpoint(self, wan: dict[str, Any] | None = None) -> dict[str, Any]:
        """The spoke endpoint on its WAN interface (or on `wan`: the backup WAN's endpoint in the
        companion topology). Never `backupInterfaces`: FMC 10.0.1 drops it on AUTO_VPN spokes."""
        ep: dict[str, Any] = {
            "name": self.device["name"],
            "type": "EndPoint",
            "peerType": "SPOKE",
            "extranet": False,
            "device": self.device,
            "interface": wan or self.wan,
            "connectionType": "BIDIRECTIONAL",
        }
        if self.inside:
            ep["insideInterface"] = self.inside
        return ep

    def backup_endpoint(self) -> dict[str, Any]:
        assert self.backup is not None
        return self.endpoint(self.backup)

    def summary(self) -> dict[str, Any]:
        out = {
            "device": self.device["name"],
            "wan": ref_label(self.wan),
            "backup_wan": ref_label(self.backup) if self.backup else None,
            "inside": [ref_label(i) for i in self.inside] or None,
        }
        if self.loopback_ip:
            name = ref_label(self.loopback) if self.loopback else f"{OSPF_LOOPBACK} (new)"
            out["tunnel_borrows"] = f"{name} {self.loopback_ip}/32"
        return {k: v for k, v in out.items() if v is not None}


async def plan_spoke(app: FmcApp, spec: SpokeSpec, domain: str | None) -> SpokePlan:
    dev, iface_dev = await _peer_device(app, spec.device, domain)
    others = await device_interfaces(app, iface_dev, domain, WAN_KINDS)
    blockers: list[str] = []

    def wan_ref(name: str) -> dict[str, Any]:
        _, i = pick_interface(others, name, dev["name"])
        if not i.get("securityZone"):
            blockers.append(
                f"WAN interface {i.get('name')} on {dev['name']} is in no security zone; SD-WAN only uses "
                "zoned interfaces (fmc_update_interface zone=...)."
            )
        if not i.get("ifname"):
            blockers.append(f"WAN interface {i.get('name')} on {dev['name']} has no logical name.")
        return iref(i)

    wan = wan_ref(spec.wan_interface)
    backup = wan_ref(spec.backup_wan_interface) if spec.backup_wan_interface else None
    if backup and backup["id"] == wan["id"]:
        raise InvalidRequest(f"{dev['name']}: backup_wan_interface must differ from wan_interface.")
    inside = [iref(pick_interface(others, i, dev["name"])[1]) for i in spec.inside_interfaces]
    return SpokePlan(dev, wan, backup, inside, blockers, iface_dev)


OSPF_LOOPBACK = "sdwan-ospf-lo"


def spoke_loopback_addresses(spec: str | list[str], count: int) -> list[ipaddress.IPv4Address]:
    """spoke_loopbacks -> one address per spoke: a subnet's addresses in order (its hosts, or the
    address itself for a /32), or the listed addresses ('/32' optional)."""
    items = [spec] if isinstance(spec, str) else list(spec)
    if len(items) == 1 and "/" in items[0]:
        try:
            net = ipaddress.IPv4Network(items[0].strip(), strict=False)
        except ValueError:
            raise InvalidRequest(f"spoke_loopbacks {items[0]!r} is not an IPv4 subnet or address.") from None
        hosts = [net.network_address] if net.prefixlen == 32 else list(net.hosts())
        if len(hosts) < count:
            raise InvalidRequest(f"spoke_loopbacks {net} has {len(hosts)} address(es) for {count} spoke(s).")
        return hosts[:count]
    out = []
    for raw in items:
        text = raw.strip().removesuffix("/32")
        try:
            out.append(ipaddress.IPv4Address(text))
        except ValueError:
            raise InvalidRequest(
                f"spoke_loopbacks: {raw!r} is not an IPv4 address (give one /32 per spoke, or one subnet)."
            ) from None
    if len(out) != count:
        raise InvalidRequest(f"spoke_loopbacks lists {len(out)} address(es) for {count} spoke(s).")
    if len(set(out)) != len(out):
        raise InvalidRequest("spoke_loopbacks lists an address twice; each spoke needs its own.")
    return out


async def plan_spoke_loopbacks(
    app: FmcApp,
    spokes: list[SpokePlan],
    spec: str | list[str],
    pools: list[ipaddress.IPv4Network],
    domain: str | None,
) -> list[str]:
    """Give each spoke its /32 loopback (an existing one with the address, or one to create); returns
    blockers. The addresses must stay out of the spoke pools: the hub hands those to tunnels."""
    blockers: list[str] = []
    for sp, ip in zip(spokes, spoke_loopback_addresses(spec, len(spokes)), strict=True):
        sp.loopback_ip = str(ip)
        for net in pools:
            if ip in net:
                blockers.append(
                    f"{sp.device['name']}: loopback {ip} is in the spoke pool {net}; take spoke_loopbacks "
                    "from another block."
                )
        sp.loopbacks = await device_interfaces(app, sp.iface_device, domain, ["loopback"])
        vtis = await device_interfaces(app, sp.iface_device, domain, ["vti"])
        sp.vti_ids = {str(i.get("id")) for _, i in vtis}
        loops = [i for _, i in sp.loopbacks]
        same = [i for i in loops if ((i.get("ipv4") or {}).get("static") or {}).get("address") == str(ip)]
        if same:
            sp.loopback = iref(same[0])
            continue
        named = [i for i in loops if str(i.get("ifname") or "").lower() == OSPF_LOOPBACK]
        if named:
            have = ((named[0].get("ipv4") or {}).get("static") or {}).get("address")
            blockers.append(
                f"{sp.device['name']} already has loopback {OSPF_LOOPBACK!r} ({have}); give that address "
                "in spoke_loopbacks to reuse it, or remove it."
            )
            continue
        sp.loopback_body = {
            "type": "LoopbackInterface",
            "loopbackId": _free_id({int(i.get("loopbackId") or 0) for i in loops}, MAX_LOOPBACK_ID),
            "enabled": True,
            "ifname": OSPF_LOOPBACK,
            "ipv4": {"static": {"address": str(ip), "netmask": "255.255.255.255"}},
            "description": "SD-WAN OSPF overlay: the spoke tunnel borrows this address "
            "(fmc_create_sdwan_topology)",
        }
    return blockers


WAN2_SUFFIX = "-wan2"
BACKUP_WAN_NOTE = (
    "Spokes with backup_wan_interface get their second tunnel from a companion AUTO_VPN topology "
    "'{companion}': the same hub on a second DVTI (sourced from its second WAN, with its own loopback "
    "and spoke pool) and each such spoke on its backup WAN. FMC 10.0.1 drops backupInterfaces on an "
    "AUTO_VPN spoke and allows one endpoint per device per topology, so this is how a spoke gets a "
    "second WAN tunnel (live on mcp-sdwan-t1, 2026-10-18: two IKEv2 SAs and two iBGP sessions per "
    "spoke; spoke WAN down -> traffic on the other tunnel without a lost ping). Both topologies share "
    "the iBGP settings; delete both to remove the overlay (fmc_delete_s2s_vpn)."
)


def companion_name(name: str) -> str:
    """The companion topology that carries the spokes' backup WAN tunnels."""
    return f"{name}{WAN2_SUFFIX}"


def hub_endpoint(hub: HubPlan, dvti: dict[str, Any], pool: dict[str, Any]) -> dict[str, Any]:
    ep: dict[str, Any] = {
        "name": hub.device["name"],
        "type": "EndPoint",
        "peerType": "HUB",
        "isPrimaryHub": hub.primary,
        "extranet": False,
        "device": hub.device,
        "interface": dvti,
        "ipv4PoolsForSpokeVti": [pool],
        "connectionType": "BIDIRECTIONAL",
    }
    if hub.inside:
        ep["insideInterface"] = hub.inside
    return ep


def overlap_blockers(hubs: list[HubPlan], extra: list[ipaddress.IPv4Network] | None = None) -> list[str]:
    """FMC needs every hub's spoke pool on its own subnet ('configure IPv4 Pools with unique subnet')."""
    nets = [(h.role, h.pool.network) for h in hubs if h.pool.network] + [
        ("existing hub", n) for n in extra or []
    ]
    out = []
    for i, (ra, a) in enumerate(nets):
        for rb, b in nets[i + 1 :]:
            if a.overlaps(b):
                out.append(
                    f"The {ra} and {rb} spoke pools overlap ({a} / {b}); each hub needs its own subnet."
                )
    return out


class Builder:
    """Applies the plan in dependency order and undoes what it created when a step fails."""

    def __init__(self, app: FmcApp, domain: str | None, secret: str | None = None) -> None:
        self.app = app
        self.domain = domain
        self.secret = secret
        self.done: list[str] = []
        self.undo: list[tuple[str, str]] = []  # (label, path to DELETE), newest last

    async def post(self, path: str, body: dict[str, Any], label: str, *, undo: bool = True) -> dict[str, Any]:
        made: dict[str, Any] = await self.app.api.post(path, body)
        self.done.append(label)
        if undo and made.get("id"):
            self.undo.append((label, f"{path}/{made['id']}"))
        return made

    async def pool(self, pp: PoolPlan) -> dict[str, Any]:
        if pp.ref:
            return pp.ref
        assert pp.body is not None
        made = await self.post(
            await self.app.config_path(POOLS, self.domain), pp.body, f"pool {pp.body['name']!r}"
        )
        return {"id": made["id"], "type": made.get("type") or "IPv4AddressPool", "name": made.get("name")}

    async def hub_dvti(self, hub: HubPlan) -> dict[str, Any]:
        if hub.dvti:
            return hub.dvti
        assert hub.dvti_body is not None
        base = await self.app.config_path(f"{DEVICES}/{hub.iface_device}", self.domain)
        lo = hub.loopback
        if lo is None:
            assert hub.loopback_body is not None
            made = await self.post(
                f"{base}/{INTERFACE_KINDS['loopback']}",
                hub.loopback_body,
                f"loopback {hub.loopback_body['ifname']!r} on {hub.device['name']}",
            )
            lo = {"id": made["id"], "type": "LoopbackInterface", "name": made.get("name")}
        body = {**hub.dvti_body, "borrowIPfrom": lo}
        made = await self.post(
            f"{base}/{INTERFACE_KINDS['vti']}", body, f"DVTI {body['ifname']!r} on {hub.device['name']}"
        )
        return {"id": made["id"], "type": made.get("type") or "VTIInterface", "name": made.get("name")}

    async def spoke_loopback(self, sp: SpokePlan) -> dict[str, Any]:
        """The /32 loopback a spoke's tunnel borrows (created before the topology, so an undo deletes
        the topology and its VTIs first)."""
        if sp.loopback:
            return sp.loopback
        assert sp.loopback_body is not None
        base = await self.app.config_path(f"{DEVICES}/{sp.iface_device}", self.domain)
        made = await self.post(
            f"{base}/{INTERFACE_KINDS['loopback']}",
            sp.loopback_body,
            f"loopback {sp.loopback_body['ifname']!r} {sp.loopback_ip}/32 on {sp.device['name']}",
        )
        sp.loopback = {"id": made["id"], "type": "LoopbackInterface", "name": made.get("name")}
        return sp.loopback

    async def borrow(self, sp: SpokePlan, endpoints: str, made: dict[str, Any]) -> None:
        """Make the VTI FMC generated for a spoke endpoint borrow the spoke's loopback (unnumbered)."""
        assert sp.loopback is not None
        base = await self.app.config_path(
            f"{DEVICES}/{sp.iface_device}/{INTERFACE_KINDS['vti']}", self.domain
        )
        ep = await self.app.api.get(f"{endpoints}/{made['id']}") if made.get("id") else {}
        meta = ((ep or {}).get("metadata") or {}).get("vtiInterfaceMetadataList") or []
        ids = [
            str((m.get("vtiInterface") or {}).get("id"))
            for m in meta
            if (m.get("vtiInterface") or {}).get("id")
        ]
        if not ids:  # no metadata: the spoke's static VTIs on its WAN that the topology added
            page = await self.app.all(base, expanded=True, cap=500)
            ids = [
                str(v["id"])
                for v in page.items
                if str(v.get("id")) not in sp.vti_ids
                and str(v.get("tunnelType") or "STATIC").upper() == "STATIC"
                and (v.get("tunnelSource") or {}).get("id") == sp.wan["id"]
            ]
        if not ids:
            raise UpstreamError(
                f"FMC created no tunnel interface for spoke {sp.device['name']} to borrow into."
            )
        for vid in ids:
            vti = await self.app.api.get(f"{base}/{vid}")
            body = {k: v for k, v in vti.items() if k not in ("links", "metadata", "managementOnly", "ipv4")}
            body |= {"ipAddressAssignmentType": "BORROW_IP_FROM_INTERFACE", "borrowIPfrom": sp.loopback}
            await self.app.api.put(f"{base}/{vid}", body)
            self.done.append(
                f"tunnel {vti.get('ifname') or vti.get('name')} on {sp.device['name']} borrows "
                f"{sp.loopback_ip}/32"
            )

    async def run(self, what: str, steps: Callable[[], Awaitable[Any]]) -> Any:
        try:
            return await steps()
        except Exception as e:  # undo whatever was created, newest first
            failed = []
            for label, path in reversed(self.undo):
                try:
                    await self.app.api.delete(path)
                except Exception:
                    failed.append(label)
            self.app.invalidate_cache()
            cleanup = (
                f"Removing what was created failed for: {', '.join(failed)}; delete those by hand."
                if failed
                else "Everything created was deleted again; fix the cause and retry."
                if self.undo
                else ""
            )
            msg = str(e)
            if self.secret:
                msg = msg.replace(self.secret, MASK)
            after = f" after {', '.join(self.done)}" if self.done else ""
            raise UpstreamError(
                f"{what} failed{after}: {msg}. {cleanup}".strip(), getattr(e, "status_code", None)
            ) from None


async def _zone(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    _, z = await resolve_object(app, ref, domain, ["security_zone"])
    return z


def _route_settings(overlay: str, bgp_as: int, community: int, multipath: bool) -> dict[str, Any]:
    rs: dict[str, Any] = {"enableBgp": overlay == "bgp"}
    if overlay == "bgp":
        rs |= {
            "autonomousSystemNumber": bgp_as,
            "communityAttribute": community,
            "communityTagToAdvertiseLearntRoutes": community,
            "enableMultiPath": multipath,
            "distributeConnectedNetwork": {
                "enableDistribution": True,
                "interfaceSelection": "INSIDE_INTERFACE",
            },
        }
    return rs


OSPF_OVERLAY_NOTE = (
    "overlay='ospf': FMC generates no overlay routing. Each spoke's tunnel borrows its /32 loopback "
    "(spoke_loopbacks), so both tunnel ends are unnumbered like the hub's DVTI: that is how an OSPF overlay "
    "carried traffic on FMC 10.0.1 (live, mcp-sdwan-t1, 2026-10-18: FULL adjacencies on the hub's "
    "virtual-access interfaces, OSPF routes on every spoke, all hosts reachable). With numbered spoke "
    "tunnels the spokes installed no OSPF routes. Then run fmc_configure_ospf in one area on the hub "
    "(networks: the spoke pool and the hub's inside networks) and on every spoke (its loopback /32 or the "
    "spoke_loopbacks block, and its inside networks), and deploy."
)
OSPF_UNVERIFIED = (
    "overlay='ospf' with {what} is not supported yet (the unnumbered OSPF overlay was verified with one hub "
    "and one WAN tunnel per spoke); build without it or use overlay='bgp'."
)


def _deploy_note(names: list[str]) -> str:
    return f"Takes effect after deploying {', '.join(sorted(set(names)))} (fmc_deploy)."


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create SD-WAN topology")
    async def fmc_create_sdwan_topology(
        ctx: Context,
        name: Annotated[str, Field(description="New topology name", min_length=1, max_length=64)],
        hub: Annotated[str, Field(description="Primary hub FTD or HA pair (name/UUID)")],
        tunnel_zone: Annotated[
            str,
            Field(
                description="Security zone for the overlay: the hub DVTI and every spoke VTI join it "
                "(use it in access rules for spoke traffic)"
            ),
        ],
        spoke_pool: PoolArg,
        hub_wan_interface: Annotated[
            str | None, Field(description="Hub WAN interface the new DVTI is sourced from")
        ] = None,
        hub_dvti: DvtiArg = "sdwan-dvti",
        hub_loopback: LoopbackArg = None,
        hub_inside_interfaces: Annotated[
            list[str] | None, Field(description="Hub inside interfaces advertised into the overlay")
        ] = None,
        spokes: Spokes = None,
        hub_backup_wan_interface: Annotated[
            str | None,
            Field(
                description="Hub WAN interface for a second DVTI that the spokes' backup_wan_interface "
                "tunnels terminate on (built as the companion topology '<name>-wan2')"
            ),
        ] = None,
        hub_backup_dvti: Annotated[
            str,
            Field(
                description="Logical name of the hub's second-WAN DVTI: reused when it exists, otherwise "
                "created from hub_backup_wan_interface and a loopback"
            ),
        ] = "sdwan-dvti-wan2",
        hub_backup_loopback: LoopbackArg = None,
        backup_wan_pool: Annotated[
            str | None,
            Field(
                description="Spoke tunnel address pool of the second-WAN DVTI: an existing IPv4 address "
                "pool or a subnet (its own, not overlapping spoke_pool)"
            ),
        ] = None,
        backup_hub: Annotated[
            str | None,
            Field(description="Backup (secondary) hub FTD or HA pair; spokes keep a tunnel to both"),
        ] = None,
        backup_hub_wan_interface: Annotated[
            str | None, Field(description="Backup hub WAN interface for its DVTI")
        ] = None,
        backup_hub_dvti: DvtiArg = "sdwan-dvti",
        backup_hub_loopback: LoopbackArg = None,
        backup_spoke_pool: PoolArg = None,
        backup_hub_inside_interfaces: Annotated[
            list[str] | None, Field(description="Backup hub inside interfaces advertised into the overlay")
        ] = None,
        overlay: Annotated[
            Literal["bgp", "ospf"],
            Field(
                description="Overlay routing: bgp (FMC generates iBGP over the tunnels, community-tagged, "
                "inside networks redistributed) or ospf (no generated BGP: each spoke tunnel borrows a /32 "
                "loopback from spoke_loopbacks, then you run OSPF over the tunnel and inside networks with "
                "fmc_configure_ospf)"
            ),
        ] = "bgp",
        spoke_loopbacks: SpokeLoopbacksArg = None,
        bgp_as: Annotated[int, Field(ge=1, le=4294967295, description="iBGP AS number")] = DEFAULT_AS,
        community: Annotated[
            int, Field(ge=1, le=65535, description="BGP community tagging the overlay's routes")
        ] = DEFAULT_COMMUNITY,
        multipath: Annotated[
            bool, Field(description="ECMP over several tunnels (maximum-paths ibgp) when BGP is on")
        ] = True,
        pre_shared_key: Annotated[
            str | None,
            Field(
                description="IKEv2 pre-shared key (never echoed back); default: FMC generates one per tunnel",
                min_length=8,
                max_length=127,
            ),
        ] = None,
        ike_policies: Annotated[
            list[str] | None, Field(description=f"IKEv2 policy names (default {DEFAULT_IKE_POLICY})")
        ] = None,
        ipsec_proposals: Annotated[
            list[str] | None,
            Field(description=f"IKEv2 IPsec proposal names (default {DEFAULT_IPSEC_PROPOSAL})"),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Build an SD-WAN hub-and-spoke topology the way FMC's SD-WAN wizard does (FMC 7.6+): a
        dynamic VTI on the hub (created from its WAN interface and a loopback when it doesn't exist), a
        spoke tunnel address pool, the spokes on their WAN interfaces (FMC builds each spoke's VTI and
        addresses it from the pool), an optional backup hub with its own DVTI and pool, IKEv2, and iBGP
        overlay routing generated by FMC (or OSPF: each spoke tunnel then borrows a /32 loopback created
        from spoke_loopbacks, and you configure OSPF with fmc_configure_ospf). The preview shows every
        object, interface and endpoint in creation order; a failed step deletes what was created.
        Interfaces must have logical names and WAN interfaces a security zone. Then deploy the hubs and
        spokes (fmc_deploy) and check fmc_get_vpn_topology and fmc_run_show_command('show route bgp')."""
        app: FmcApp = get_client(ctx)
        spokes = spokes or []
        if backup_hub and not backup_spoke_pool:
            raise InvalidRequest("backup_hub needs backup_spoke_pool (its own subnet or pool).")
        if not backup_hub and (backup_spoke_pool or backup_hub_wan_interface or backup_hub_loopback):
            raise InvalidRequest("backup_* settings need backup_hub.")
        wan2_wanted = any(s.backup_wan_interface for s in spokes)
        if wan2_wanted and not backup_wan_pool:
            raise InvalidRequest(
                "Spokes with backup_wan_interface need backup_wan_pool (the second-WAN DVTI's own subnet "
                "or pool) and hub_backup_wan_interface (or an existing hub_backup_dvti)."
            )
        if not wan2_wanted and (backup_wan_pool or hub_backup_wan_interface or hub_backup_loopback):
            raise InvalidRequest(
                "hub_backup_wan_interface / backup_wan_pool / hub_backup_loopback are for spokes with "
                "backup_wan_interface; give at least one."
            )
        if wan2_wanted and hub_backup_dvti.strip().lower() == hub_dvti.strip().lower():
            raise InvalidRequest("hub_backup_dvti must differ from hub_dvti.")
        if overlay == "bgp" and spoke_loopbacks:
            raise InvalidRequest("spoke_loopbacks is for overlay='ospf' (iBGP runs over numbered tunnels).")
        if overlay == "ospf" and spokes and not spoke_loopbacks:
            raise InvalidRequest(
                "overlay='ospf' needs spoke_loopbacks (a subnet outside the spoke pools, or one address per "
                "spoke): each spoke tunnel borrows a /32 loopback, without which the spokes install no OSPF "
                "routes (FMC 10.0.1)."
            )
        companion = companion_name(name)
        blockers: list[str] = []
        try:
            await resolve_topology(app, name, domain)
            blockers.append(f"A VPN topology named {name!r} already exists.")
        except NotFound:
            pass
        zone = await _zone(app, tunnel_zone, domain)
        hubs = [
            await plan_hub(
                app,
                role="primary hub",
                primary=True,
                device=hub,
                wan_interface=hub_wan_interface,
                dvti=hub_dvti,
                loopback=hub_loopback,
                pool=spoke_pool,
                pool_name=f"{name}-pool",
                inside=hub_inside_interfaces or [],
                zone=zone,
                domain=domain,
            )
        ]
        wan2: HubPlan | None = None
        if wan2_wanted:
            p0 = hubs[0]
            wan2 = await plan_hub(
                app,
                role="primary hub (second WAN)",
                primary=True,
                device=hub,
                wan_interface=hub_backup_wan_interface,
                dvti=hub_backup_dvti,
                loopback=hub_backup_loopback,
                pool=backup_wan_pool,
                pool_name=f"{companion}-pool",
                inside=hub_inside_interfaces or [],
                zone=zone,
                domain=domain,
                taken_loopbacks={p0.loopback_body["loopbackId"]} if p0.loopback_body else set(),
                taken_tunnels={p0.dvti_body["tunnelId"]} if p0.dvti_body else set(),
            )
            if len(companion) > 64:
                blockers.append(f"The companion topology name {companion!r} is longer than 64 characters.")
            try:
                await resolve_topology(app, companion, domain)
                blockers.append(f"A VPN topology named {companion!r} already exists.")
            except NotFound:
                pass
            if backup_hub:
                blockers.append(
                    "backup_wan_interface with a backup hub is not supported yet (the second-WAN tunnels "
                    "were verified with one hub only); build without one of them."
                )
        if backup_hub:
            hubs.append(
                await plan_hub(
                    app,
                    role="backup hub",
                    primary=False,
                    device=backup_hub,
                    wan_interface=backup_hub_wan_interface,
                    dvti=backup_hub_dvti,
                    loopback=backup_hub_loopback,
                    pool=backup_spoke_pool,
                    pool_name=f"{name}-backup-pool",
                    inside=backup_hub_inside_interfaces or [],
                    zone=zone,
                    domain=domain,
                )
            )
            if hubs[1].device["id"] == hubs[0].device["id"]:
                raise InvalidRequest("hub and backup_hub must be different devices.")
        planned = [await plan_spoke(app, s, domain) for s in spokes]
        seen = {h.device["id"] for h in hubs}
        for sp in planned:
            if sp.device["id"] in seen:
                raise InvalidRequest(f"{sp.device['name']} appears twice (as a hub or spoke).")
            seen.add(sp.device["id"])
        for h in hubs + ([wan2] if wan2 else []):
            blockers += h.blockers
        for sp in planned:
            blockers += sp.blockers
        blockers += overlap_blockers(hubs + ([wan2] if wan2 else []))
        if overlay == "ospf":
            if backup_hub:
                blockers.append(OSPF_UNVERIFIED.format(what="a backup hub"))
            if wan2:
                blockers.append(OSPF_UNVERIFIED.format(what="backup_wan_interface"))
            if planned and spoke_loopbacks:
                nets = [h.pool.network for h in hubs + ([wan2] if wan2 else []) if h.pool.network]
                blockers += await plan_spoke_loopbacks(app, planned, spoke_loopbacks, nets, domain)
        if wan2 and wan2.dvti and hubs[0].dvti and wan2.dvti["id"] == hubs[0].dvti["id"]:
            blockers.append(
                "hub_backup_dvti is the same interface as hub_dvti; the second WAN needs its own DVTI."
            )

        strong_ok = await strong_crypto_allowed(app)
        weak = strong_ok is False
        side_effects = [_deploy_note([h.device["name"] for h in hubs] + [s.device["name"] for s in planned])]
        if wan2:
            side_effects.append(BACKUP_WAN_NOTE.format(companion=companion))
        if weak and not ike_policies and not ipsec_proposals:
            side_effects.append(
                "FMC has no strong-crypto (export-controlled) licence, so the defaults are "
                f"{WEAK_IKE_POLICY} / {WEAK_IPSEC_PROPOSAL} (DES): fine for a lab, not for production. "
                "FMC may also refuse SD-WAN topologies without it."
            )
        if overlay == "bgp" and multipath and len(hubs) > 1:
            side_effects.append(
                "multipath is on with two hubs: spokes spread traffic over both hub tunnels (ECMP), so "
                "return traffic that routes through one hub only (one DC gateway) is asymmetric and can "
                "be dropped. Use multipath=False for primary/backup hubs unless both hubs return traffic "
                "symmetrically (live on mcp-sdwan-t2)."
            )
        if overlay == "ospf":
            side_effects.append(OSPF_OVERLAY_NOTE)
        policies = await _named(
            app,
            "object/ikev2policies",
            ike_policies or [WEAK_IKE_POLICY if weak else DEFAULT_IKE_POLICY],
            "IKEv2 policy",
            domain,
        )
        proposals = await _named(
            app,
            "object/ikev2ipsecproposals",
            ipsec_proposals or [WEAK_IPSEC_PROPOSAL if weak else DEFAULT_IPSEC_PROPOSAL],
            "IKEv2 IPsec proposal",
            domain,
        )
        if weak and (strong := [p["name"] for p in [*policies, *proposals] if p["strong"]]):
            blockers.append(
                f"FMC has no strong-crypto licence, so it won't deploy {', '.join(strong)}; use DES ones "
                f"such as {WEAK_IKE_POLICY} and {WEAK_IPSEC_PROPOSAL}."
            )
        zone_ref = {"id": zone["id"], "type": "SecurityZone", "name": zone.get("name")}
        topo_body = {
            "name": name,
            "type": "FTDS2SVpn",
            "topologyType": "AUTO_VPN",
            "routeBased": True,
            "ikeV1Enabled": False,
            "ikeV2Enabled": True,
            "autoVpnSettings": {
                "routeSettings": _route_settings(overlay, bgp_as, community, multipath),
                "spokeSvtiSecurityZone": zone_ref,
            },
        }
        ike_v2: dict[str, Any] = {
            "authenticationType": "MANUAL_PRE_SHARED_KEY" if pre_shared_key else "AUTOMATIC_PRE_SHARED_KEY",
            "policies": [
                {"id": p["id"], "type": p.get("type") or "IKEv2Policy", "name": p["name"]} for p in policies
            ],
        }
        if pre_shared_key:
            ike_v2 |= {"manualPreSharedKey": pre_shared_key, "enforceHexBasedPreSharedKeyOnly": False}
        else:
            ike_v2["automaticPreSharedKeyLength"] = 24
        proposal_refs = [
            {"id": p["id"], "type": p.get("type") or "IKEv2IPsecProposal", "name": p["name"]}
            for p in proposals
        ]
        path = await app.config_path(S2S, domain)
        steps: list[str] = []
        for h in hubs + ([wan2] if wan2 else []):
            if h.pool.body:
                steps.append(
                    f"create IPv4 address pool {h.pool.body['name']!r} ({h.pool.body['ipAddressRange']})"
                )
            if h.loopback_body:
                steps.append(
                    f"create loopback {h.loopback_body['ifname']!r} {h.pool.hub_ip}/32 on {h.device['name']}"
                )
            if h.dvti_body:
                steps.append(f"create DVTI {h.dvti_body['ifname']!r} on {h.device['name']}")
        steps += [
            f"create loopback {OSPF_LOOPBACK!r} {s.loopback_ip}/32 on {s.device['name']}"
            for s in planned
            if s.loopback_body
        ]
        steps += ["create AUTO_VPN topology", "set IKEv2 and IPsec"]
        steps += [f"add {h.role} {h.device['name']}" for h in hubs]
        steps += [f"add spoke {s.device['name']}" for s in planned]
        steps += [
            f"set the tunnel FMC generates on {s.device['name']} to borrow {s.loopback_ip}/32 "
            "(BORROW_IP_FROM_INTERFACE)"
            for s in planned
            if s.loopback_ip
        ]
        if wan2:
            steps += [f"create AUTO_VPN topology {companion!r}", f"set IKEv2 and IPsec on {companion!r}"]
            steps += [f"add hub {wan2.device['name']} on its second-WAN DVTI to {companion!r}"]
            steps += [
                f"add spoke {s.device['name']} on its backup WAN to {companion!r}"
                for s in planned
                if s.backup
            ]

        async def apply() -> Any:
            b = Builder(app, domain, pre_shared_key)

            async def topology(
                topo_name: str, eps: list[dict[str, Any]], tag: str
            ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
                topo = await b.post(path, {**topo_body, "name": topo_name}, f"topology {topo_name!r}")
                app.invalidate_cache()
                base = f"{path}/{topo['id']}"
                ike = await _one(app, f"{base}/ikesettings")
                await app.api.put(
                    f"{base}/ikesettings/{ike['id']}",
                    {"id": ike["id"], "type": ike.get("type") or "IkeSettings", "ikeV2Settings": ike_v2},
                )
                ips = await _one(app, f"{base}/ipsecsettings")
                await app.api.put(
                    f"{base}/ipsecsettings/{ips['id']}",
                    {
                        **{k: v for k, v in ips.items() if k not in ("links", "metadata")},
                        "ikeV2IpsecProposal": proposal_refs,
                    },
                )
                b.done.append(f"IKE/IPsec settings{tag}")
                # endpoints go with the topology: no separate undo
                made = [
                    await b.post(f"{base}/endpoints", ep, f"endpoint {ep['name']}{tag}", undo=False)
                    for ep in eps
                ]
                return topo, made

            async def steps_() -> Any:
                hub_eps = []
                for h in hubs:
                    pool = await b.pool(h.pool)
                    dvti = await b.hub_dvti(h)
                    hub_eps.append(hub_endpoint(h, dvti, pool))
                wan2_ep = None
                if wan2:
                    pool2 = await b.pool(wan2.pool)  # pool, loopback, DVTI: as for the primary
                    wan2_ep = hub_endpoint(wan2, await b.hub_dvti(wan2), pool2)
                unnumbered = [sp for sp in planned if sp.loopback_ip]
                for sp in unnumbered:
                    await b.spoke_loopback(sp)
                topo, made = await topology(name, hub_eps + [sp.endpoint() for sp in planned], "")
                for sp, m in zip(planned, made[len(hub_eps) :], strict=True):
                    if sp.loopback_ip:
                        await b.borrow(sp, f"{path}/{topo['id']}/endpoints", m)
                out: dict[str, Any] = {
                    "topology": topology_row(topo),
                    "endpoints": [endpoint_row(m) for m in made],
                }
                deleting = "fmc_delete_s2s_vpn"
                if wan2_ep is not None:
                    backups = [sp.backup_endpoint() for sp in planned if sp.backup]
                    t2, made2 = await topology(companion, [wan2_ep, *backups], f" ({companion})")
                    out["backup_wan_topology"] = {
                        "topology": topology_row(t2),
                        "endpoints": [endpoint_row(m) for m in made2],
                    }
                    deleting = f"fmc_delete_s2s_vpn on {name!r} and {companion!r}"
                check = "show route bgp" if overlay == "bgp" else "show route ospf"
                first = (
                    "Configure OSPF on the hubs and spokes (fmc_configure_ospf; see the preview note), then "
                    if overlay == "ospf"
                    else ""
                )
                return {
                    **out,
                    "created": b.done,
                    "next": f"{first}Deploy the hubs and spokes (fmc_deploy), then check "
                    f"fmc_get_vpn_topology, fmc_list_vpn_tunnels and fmc_run_show_command('{check}'). "
                    f"To remove it: {deleting}, then fmc_delete_interface for a DVTI/loopback created here.",
                }

            return await b.run(f"Building SD-WAN topology {name!r}", steps_)

        shown_ike = {**ike_v2, "manualPreSharedKey": MASK} if pre_shared_key else ike_v2
        return await fmc_preview(
            ctx,
            tool="fmc_create_sdwan_topology",
            args={
                "name": name,
                "hub": hub,
                "tunnel_zone": tunnel_zone,
                "spoke_pool": spoke_pool,
                "hub_wan_interface": hub_wan_interface,
                "hub_dvti": hub_dvti,
                "hub_loopback": hub_loopback,
                "hub_inside_interfaces": hub_inside_interfaces,
                "spokes": [s.model_dump() for s in spokes],
                "hub_backup_wan_interface": hub_backup_wan_interface,
                "hub_backup_dvti": hub_backup_dvti,
                "hub_backup_loopback": hub_backup_loopback,
                "backup_wan_pool": backup_wan_pool,
                "backup_hub": backup_hub,
                "backup_hub_wan_interface": backup_hub_wan_interface,
                "backup_hub_dvti": backup_hub_dvti,
                "backup_hub_loopback": backup_hub_loopback,
                "backup_spoke_pool": backup_spoke_pool,
                "backup_hub_inside_interfaces": backup_hub_inside_interfaces,
                "overlay": overlay,
                "spoke_loopbacks": spoke_loopbacks,
                "bgp_as": bgp_as,
                "community": community,
                "multipath": multipath,
                "pre_shared_key": pre_shared_key,
                "ike_policies": ike_policies,
                "ipsec_proposals": ipsec_proposals,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create SD-WAN topology {name!r}: hub {hubs[0].device['name']}"
                + (f", backup hub {hubs[1].device['name']}" if len(hubs) > 1 else "")
                + f", {len(planned)} spoke(s), overlay {overlay}",
                details={
                    "steps": steps,
                    "topology": topo_body,
                    "hubs": [h.summary() for h in hubs],
                    "spokes": [s.summary() for s in planned],
                    **(
                        {
                            "backup_wan": {
                                "topology": companion,
                                "hub": wan2.summary(),
                                "spokes": [s.summary() for s in planned if s.backup],
                            }
                        }
                        if wan2
                        else {}
                    ),
                    "ike_v2": shown_ike,
                    "ipsec_proposals": [p["name"] for p in proposal_refs],
                },
                fingerprint={
                    "hubs": [h.summary() for h in hubs],
                    "spokes": [s.endpoint() for s in planned],
                    "spoke_loopbacks": [s.summary().get("tunnel_borrows") for s in planned],
                    "backup_wan": (
                        [wan2.summary(), [s.backup_endpoint() for s in planned if s.backup]] if wan2 else None
                    ),
                    "zone": zone["id"],
                    "ike": [p["id"] for p in policies],
                    "ipsec": [p["id"] for p in proposals],
                },
                blockers=blockers,
                side_effects=side_effects,
                blast_radius=len(hubs) + len(planned),
            ),
            apply=apply,
        )

    @reg.write(title="Update SD-WAN topology")
    async def fmc_update_sdwan_topology(
        ctx: Context,
        topology: TopologyRef,
        add_spokes: Spokes = None,
        remove_spokes: Annotated[
            list[str] | None, Field(description="Spoke devices (name/UUID) to remove from the topology")
        ] = None,
        add_backup_hub: Annotated[
            str | None, Field(description="Add this FTD or HA pair as a backup (secondary) hub")
        ] = None,
        backup_hub_wan_interface: Annotated[
            str | None, Field(description="Backup hub WAN interface for its new DVTI")
        ] = None,
        backup_hub_dvti: DvtiArg = "sdwan-dvti",
        backup_hub_loopback: LoopbackArg = None,
        backup_spoke_pool: PoolArg = None,
        backup_hub_inside_interfaces: Annotated[
            list[str] | None, Field(description="Backup hub inside interfaces advertised into the overlay")
        ] = None,
        remove_backup_hub: Annotated[
            str | None, Field(description="Remove this backup hub (name/UUID); the primary hub stays")
        ] = None,
        multipath: Annotated[
            bool | None, Field(description="Turn ECMP over several tunnels on or off (BGP overlay)")
        ] = None,
        spoke_loopbacks: SpokeLoopbacksArg = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change an SD-WAN (AUTO_VPN) topology: add or remove spokes, add or remove a backup hub (with
        its own DVTI and spoke pool, created as in fmc_create_sdwan_topology), or switch ECMP. Spokes
        added to an OSPF overlay get a /32 loopback from spoke_loopbacks that their tunnel borrows. The
        preview lists the endpoints before and after and the devices to deploy: adding or removing a
        spoke changes the hubs' configuration too, and a hub change reaches every spoke. The primary
        hub can't be removed (delete the topology with fmc_delete_s2s_vpn instead)."""
        app: FmcApp = get_client(ctx)
        add_spokes = add_spokes or []
        remove_spokes = remove_spokes or []
        if not (add_spokes or remove_spokes or add_backup_hub or remove_backup_hub or multipath is not None):
            raise InvalidRequest(
                "Nothing to change: give spokes or a backup hub to add or remove, or multipath."
            )
        if add_backup_hub and not backup_spoke_pool:
            raise InvalidRequest("add_backup_hub needs backup_spoke_pool (its own subnet or pool).")
        t = await resolve_topology(app, topology, domain)
        if str(t.get("topologyType")) != "AUTO_VPN" and not t.get("autoVpnSettings"):
            raise InvalidRequest(
                f"{t.get('name')!r} is not an SD-WAN topology ({t.get('topologyType')}); this tool "
                "only changes AUTO_VPN topologies (fmc_create_sdwan_topology)."
            )
        path = await app.config_path(f"{S2S}/{t['id']}", domain)
        endpoints = (await app.all(f"{path}/endpoints", cap=2000)).items
        by_dev: dict[Any, dict[str, Any]] = {(e.get("device") or {}).get("id"): e for e in endpoints}
        hubs_now = [e for e in endpoints if e.get("peerType") == "HUB"]
        blockers: list[str] = []
        # The companion topology '<name>-wan2' that carries the spokes' backup WAN tunnels, if any.
        companion = companion_name(str(t.get("name")))
        c_topo: dict[str, Any] | None = None
        c_path = ""
        c_by_dev: dict[Any, dict[str, Any]] = {}
        if not str(t.get("name")).endswith(WAN2_SUFFIX):
            try:
                c_topo = await resolve_topology(app, companion, domain)
            except NotFound:
                c_topo = None
        if c_topo is not None:
            c_path = await app.config_path(f"{S2S}/{c_topo['id']}", domain)
            c_eps = (await app.all(f"{c_path}/endpoints", cap=2000)).items
            c_by_dev = {(e.get("device") or {}).get("id"): e for e in c_eps}

        async def find(ref: str, role: str) -> dict[str, Any]:
            dev, _ = await _peer_device(app, ref, domain)
            ep = by_dev.get(dev["id"])
            if ep is None or ep.get("peerType") != role:
                raise InvalidRequest(f"{dev['name']} is not a {role.lower()} of {t.get('name')!r}.")
            return ep

        removing = [await find(r, "SPOKE") for r in remove_spokes]
        drop_hub = None
        if remove_backup_hub:
            drop_hub = await find(remove_backup_hub, "HUB")
            if drop_hub.get("isPrimaryHub"):
                raise InvalidRequest(
                    f"{drop_hub.get('name')} is the primary hub; delete the topology "
                    "(fmc_delete_s2s_vpn) instead."
                )
        new_hub: HubPlan | None = None
        if add_backup_hub:
            if any(not e.get("isPrimaryHub") for e in hubs_now) and not drop_hub:
                blockers.append(f"{t.get('name')!r} already has a backup hub; remove it first.")
            zone = (t.get("autoVpnSettings") or {}).get("spokeSvtiSecurityZone")
            if not zone:
                raise InvalidRequest("The topology has no overlay security zone (autoVpnSettings).")
            new_hub = await plan_hub(
                app,
                role="backup hub",
                primary=False,
                device=add_backup_hub,
                wan_interface=backup_hub_wan_interface,
                dvti=backup_hub_dvti,
                loopback=backup_hub_loopback,
                pool=backup_spoke_pool,
                pool_name=f"{t.get('name')}-backup-pool",
                inside=backup_hub_inside_interfaces or [],
                zone=zone,
                domain=domain,
            )
            if new_hub.device["id"] in by_dev:
                raise InvalidRequest(f"{new_hub.device['name']} is already in {t.get('name')!r}.")
            blockers += new_hub.blockers
            existing_nets = []
            for e in hubs_now:
                if e is drop_hub:
                    continue
                for p in e.get("ipv4PoolsForSpokeVti") or []:
                    try:
                        pool = await app.api.get(f"{await app.config_path(POOLS, domain)}/{p['id']}")
                    except (NotFound, UpstreamError):
                        continue
                    if (n := pool_network(pool)) is not None:
                        existing_nets.append(n)
            blockers += overlap_blockers([new_hub], existing_nets)
        adding = [await plan_spoke(app, s, domain) for s in add_spokes]
        # an OSPF overlay: FMC generates no BGP (enableBgp false); a missing setting is not taken for one
        ospf = (((t.get("autoVpnSettings") or {}).get("routeSettings")) or {}).get("enableBgp") is False
        if spoke_loopbacks and not (ospf and adding):
            raise InvalidRequest("spoke_loopbacks is for spokes added to an OSPF overlay (add_spokes).")
        if ospf and adding and not spoke_loopbacks:
            raise InvalidRequest(
                f"{t.get('name')!r} runs an OSPF overlay: give spoke_loopbacks (one address per added "
                "spoke, or a subnet outside the spoke pools) so the new tunnels borrow a /32 loopback."
            )
        if ospf and new_hub:
            blockers.append(OSPF_UNVERIFIED.format(what="a backup hub"))
        if ospf and adding and spoke_loopbacks:
            if any(sp.backup for sp in adding):
                blockers.append(OSPF_UNVERIFIED.format(what="backup_wan_interface"))
            pool_nets = []
            for e in hubs_now:
                for p in e.get("ipv4PoolsForSpokeVti") or []:
                    try:
                        pool = await app.api.get(f"{await app.config_path(POOLS, domain)}/{p['id']}")
                    except (NotFound, UpstreamError):
                        continue
                    if (n := pool_network(pool)) is not None:
                        pool_nets.append(n)
            blockers += await plan_spoke_loopbacks(app, adding, spoke_loopbacks, pool_nets, domain)
        for sp in adding:
            if sp.device["id"] in by_dev and by_dev[sp.device["id"]] not in removing:
                raise InvalidRequest(f"{sp.device['name']} is already in {t.get('name')!r}.")
            if new_hub and sp.device["id"] == new_hub.device["id"]:
                raise InvalidRequest(f"{sp.device['name']} can't be both the backup hub and a spoke.")
            blockers += sp.blockers
            if sp.backup and c_topo is None:
                blockers.append(
                    f"{sp.device['name']}: backup_wan_interface needs the second-WAN topology {companion!r} "
                    "(FMC 10.0.1 drops backupInterfaces on AUTO_VPN spokes). Create the topology with "
                    "fmc_create_sdwan_topology(hub_backup_wan_interface=..., backup_wan_pool=...) to get it."
                )
            elif sp.backup and sp.device["id"] in c_by_dev:
                blockers.append(f"{sp.device['name']} is already in {companion!r}.")
        # removed spokes leave the companion too
        c_removing = [
            c_by_dev[(e.get("device") or {}).get("id")]
            for e in removing
            if (e.get("device") or {}).get("id") in c_by_dev
        ]
        new_topo = None
        c_new_topo = None

        def multipath_put(topo: dict[str, Any]) -> dict[str, Any]:
            rs = ((topo.get("autoVpnSettings") or {}).get("routeSettings")) or {}
            return {
                **{k: topo[k] for k in TOPOLOGY_PUT_FIELDS if k in topo},
                "autoVpnSettings": {
                    **(topo.get("autoVpnSettings") or {}),
                    "routeSettings": {**rs, "enableMultiPath": multipath},
                },
            }

        if multipath is not None:
            rs = ((t.get("autoVpnSettings") or {}).get("routeSettings")) or {}
            if not rs.get("enableBgp"):
                blockers.append("multipath applies to the iBGP overlay, which this topology doesn't use.")
            new_topo = multipath_put(t)
            if c_topo is not None:  # both topologies feed the same router bgp: keep them alike
                c_new_topo = multipath_put(c_topo)

        def label(e: dict[str, Any]) -> str:
            role = (
                "spoke" if e.get("peerType") == "SPOKE" else "hub" if e.get("isPrimaryHub") else "backup hub"
            )
            return f"{e.get('name')} ({role})"

        before = [label(e) for e in endpoints]
        gone = {id(e) for e in removing} | ({id(drop_hub)} if drop_hub else set())
        after = [label(e) for e in endpoints if id(e) not in gone]
        after += [f"{new_hub.device['name']} (backup hub)"] if new_hub else []
        after += [f"{s.device['name']} (spoke)" for s in adding]
        after += [f"{s.device['name']} (spoke, backup WAN in {companion})" for s in adding if s.backup]
        hub_names = [str(e.get("name")) for e in hubs_now]
        if new_hub or drop_hub or new_topo:
            deploy = [str(e.get("name")) for e in endpoints] + [s.device["name"] for s in adding]
            deploy += [new_hub.device["name"]] if new_hub else []
        else:
            deploy = hub_names + [s.device["name"] for s in adding] + [str(e.get("name")) for e in removing]
        side_effects = [_deploy_note(deploy)]
        if removing or drop_hub:
            side_effects.append("Removed devices' tunnels go down when they are deployed.")
        if any(sp.backup for sp in adding):
            side_effects.append(BACKUP_WAN_NOTE.format(companion=companion))
        if c_removing:
            side_effects.append(f"Removed spokes also leave the second-WAN topology {companion!r}.")
        if c_new_topo is not None:
            side_effects.append(f"multipath is set on {companion!r} too (both feed the same iBGP).")
        if ospf and adding:
            side_effects.append(
                "The added spokes' tunnels borrow their /32 loopback (unnumbered, as OSPF needs on FMC "
                "10.0.1); add each loopback and inside network to the spoke's OSPF area (fmc_configure_ospf)."
            )

        async def apply() -> Any:
            b = Builder(app, domain)

            async def steps_() -> Any:
                if new_topo is not None:
                    await app.api.put(path, new_topo)
                    b.done.append(f"multipath {'on' if multipath else 'off'}")
                if c_new_topo is not None:
                    await app.api.put(c_path, c_new_topo)
                    b.done.append(f"multipath {'on' if multipath else 'off'} on {companion}")
                for e in c_removing:
                    await app.api.delete(f"{c_path}/endpoints/{e['id']}")
                    b.done.append(f"removed {e.get('name')} from {companion}")
                for e in removing + ([drop_hub] if drop_hub else []):
                    await app.api.delete(f"{path}/endpoints/{e['id']}")
                    b.done.append(f"removed {label(e)}")
                made = []
                if new_hub:
                    pool = await b.pool(new_hub.pool)
                    dvti = await b.hub_dvti(new_hub)
                    ep = hub_endpoint(new_hub, dvti, pool)
                    made.append(await b.post(f"{path}/endpoints", ep, f"backup hub {ep['name']}"))
                for sp in adding:
                    if (
                        sp.loopback_ip
                    ):  # before the endpoint: an undo deletes the endpoint (and its VTI) first
                        await b.spoke_loopback(sp)
                    made.append(
                        await b.post(f"{path}/endpoints", sp.endpoint(), f"spoke {sp.device['name']}")
                    )
                    if sp.loopback_ip:
                        await b.borrow(sp, f"{path}/endpoints", made[-1])
                    if sp.backup:
                        made.append(
                            await b.post(
                                f"{c_path}/endpoints",
                                sp.backup_endpoint(),
                                f"spoke {sp.device['name']} (backup WAN, {companion})",
                            )
                        )
                app.invalidate_cache()
                return {
                    "topology": t.get("name"),
                    "changed": b.done,
                    "added": [endpoint_row(m) for m in made],
                    "next": _deploy_note(deploy),
                }

            return await b.run(f"Changing SD-WAN topology {t.get('name')!r}", steps_)

        return await fmc_preview(
            ctx,
            tool="fmc_update_sdwan_topology",
            owned=[t, c_topo],
            args={
                "topology": topology,
                "add_spokes": [s.model_dump() for s in add_spokes],
                "remove_spokes": remove_spokes,
                "add_backup_hub": add_backup_hub,
                "backup_hub_wan_interface": backup_hub_wan_interface,
                "backup_hub_dvti": backup_hub_dvti,
                "backup_hub_loopback": backup_hub_loopback,
                "backup_spoke_pool": backup_spoke_pool,
                "backup_hub_inside_interfaces": backup_hub_inside_interfaces,
                "remove_backup_hub": remove_backup_hub,
                "multipath": multipath,
                "spoke_loopbacks": spoke_loopbacks,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Change SD-WAN topology {t.get('name')!r}: "
                + ", ".join(
                    x
                    for x in (
                        f"+{len(adding)} spoke(s)" if adding else "",
                        f"-{len(removing)} spoke(s)" if removing else "",
                        f"+backup hub {new_hub.device['name']}" if new_hub else "",
                        f"-backup hub {drop_hub.get('name')}" if drop_hub else "",
                        f"multipath {'on' if multipath else 'off'}" if multipath is not None else "",
                    )
                    if x
                ),
                details={
                    "endpoints_before": before,
                    "endpoints_after": after,
                    "add_spokes": [s.summary() for s in adding] or None,
                    "add_backup_hub": new_hub.summary() if new_hub else None,
                    "remove": [label(e) for e in removing] + ([label(drop_hub)] if drop_hub else []) or None,
                },
                fingerprint={
                    "topology": topology_row(t),
                    "settings": t.get("autoVpnSettings"),
                    "endpoints": sorted(str(e.get("id")) for e in endpoints),
                    "companion": sorted(str(e.get("id")) for e in c_by_dev.values()) if c_topo else None,
                    "add": [s.endpoint() for s in adding],
                    "add_loopbacks": [s.summary().get("tunnel_borrows") for s in adding],
                    "add_backup": [s.backup_endpoint() for s in adding if s.backup],
                    "hub": new_hub.summary() if new_hub else None,
                },
                blockers=blockers,
                side_effects=side_effects,
                blast_radius=len(set(deploy)),
            ),
            apply=apply,
        )

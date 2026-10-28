"""Device tools: managed FTDs, interfaces, HA pairs and clusters."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    InvalidRequest,
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, ref_label, resolve_in, slim

DEVICES = "devices/devicerecords"
HA_PAIRS = "devicehapairs/ftddevicehapairs"
CLUSTERS = "deviceclusters/ftddevicecluster"
INLINE_SETS = "inlinesets"  # IPS-only interface pairs (F96)

INTERFACE_KINDS = {
    "physical": "physicalinterfaces",
    "subinterface": "subinterfaces",
    "etherchannel": "etherchannelinterfaces",
    "vlan": "vlaninterfaces",
    "vti": "virtualtunnelinterfaces",
    "loopback": "loopbackinterfaces",
    "bridge_group": "bridgegroupinterfaces",
}

DeviceRef = Annotated[str, Field(description="Device name or UUID (from fmc_list_devices)")]


@dataclass(frozen=True)
class Membership:
    """A device's place in an HA pair or cluster."""

    container: str  # the pair's or cluster's name
    container_id: str  # lower-case UUID
    kind: Literal["ha", "cluster"]
    role: str | None  # HA: 'active' | 'standby' (FMC's failover state); cluster: 'control' | 'data'
    primary: bool = False  # HA: the primary unit

    @property
    def carries_traffic(self) -> bool:
        """The unit a pair's or cluster's traffic is traced on: the active unit, the control node."""
        return self.role in ("active", "control")

    def label(self, unit: str) -> str:
        """'mcp-fw-ha (mcp-fw-ha-a, active)'."""
        return f"{self.container} ({unit}, {self.role})" if self.role else f"{self.container} ({unit})"

    def left_out(self, unit: str, why: str | None = None) -> str:
        """Why a unit is skipped: 'mcp-fw-ha-b (standby unit of mcp-fw-ha)', or with `why`
        'mcp-fw-ha-a (active unit of mcp-fw-ha, disconnected)'."""
        what = "unit" if self.kind == "ha" else "node"
        return f"{unit} ({self.role or 'member'} {what} of {self.container}{f', {why}' if why else ''})"


def failover_role(state: Any) -> str | None:
    """'active', 'standby' or FMC's own word ('failed', ...) for an HA unit's failover state."""
    s = str(state or "").strip().lower()
    if not s:
        return None
    return "standby" if "standby" in s else "active" if "active" in s else s


def membership_of(d: dict[str, Any]) -> Membership | None:
    """The HA pair or cluster a device record belongs to, from FMC's metadata.containerDetails (expanded
    records, FMC 7.x+: {id, name, type DeviceHAPair|DeviceCluster, role PRIMARY|SECONDARY|Control|Data,
    status Active|Standby for an HA unit}); None for a standalone device."""
    c = (d.get("metadata") or {}).get("containerDetails") or {}
    if not isinstance(c, dict) or not c.get("id"):
        return None
    role = str(c.get("role") or "").lower()
    if "cluster" in str(c.get("type") or "").lower():
        return Membership(str(c.get("name")), str(c["id"]).lower(), "cluster", role or None)
    return Membership(
        str(c.get("name")), str(c["id"]).lower(), "ha", failover_role(c.get("status")), role == "primary"
    )


async def memberships(
    app: FmcApp, devices: list[dict[str, Any]], domain: str | None
) -> dict[str, Membership]:
    """Unit id (lower case) -> Membership for the HA-pair and cluster members among `devices` (expanded
    records). FMC names the container in each record; records without containerDetails at all (older
    FMC, or no member among them) are matched against the HA pair and cluster collections instead."""
    out = {str(d.get("id")).lower(): m for d in devices if (m := membership_of(d))}
    if out:
        return out
    try:
        pairs = (await app.all(await app.config_path(HA_PAIRS, domain), cap=500)).items
    except UpstreamError:
        pairs = []
    for p in pairs:
        meta = p.get("metadata") or {}
        for side in ("primary", "secondary"):
            unit = p.get(side) or {}
            if unit.get("id"):
                state = (meta.get(f"{side}Status") or {}).get("currentStatus")
                out[str(unit["id"]).lower()] = Membership(
                    str(p.get("name")),
                    str(p.get("id")).lower(),
                    "ha",
                    failover_role(state),
                    side == "primary",
                )
    try:
        clusters = (await app.all(await app.config_path(CLUSTERS, domain), cap=500)).items
    except UpstreamError:
        clusters = []
    for c in clusters:
        control = c.get("controlDevice") or c.get("masterDevice") or {}
        data = c.get("dataDevices") or c.get("slaveDevices") or []
        for node, role in [(control, "control"), *((n, "data") for n in data)]:
            unit = (node or {}).get("deviceDetails") or node or {}
            if unit.get("id"):
                out[str(unit["id"]).lower()] = Membership(
                    str(c.get("name")), str(c.get("id")).lower(), "cluster", role
                )
    return out


def traffic_unit(units: list[tuple[dict[str, Any], Membership]]) -> dict[str, Any]:
    """The unit of one HA pair or cluster that carries its traffic: the active unit (FMC's failover
    state) or the control node; else the primary, else the first."""
    for pick in (
        lambda m: m.carries_traffic,
        lambda m: m.primary,
        lambda m: True,
    ):
        hit = next((d for d, m in units if pick(m)), None)
        if hit is not None:
            return hit
    raise NotFound("The HA pair or cluster has no units.", 404)


class UnitDisconnected(InvalidRequest):
    """An HA unit or cluster node that FMC lists as disconnected was asked to trace (resolve_unit with
    `traceable`). The message says so and names the connected peers; `device` labels pair and unit."""

    def __init__(self, message: str, device: str) -> None:
        super().__init__(message)
        self.device = device


def disconnected_note(
    dev: dict[str, Any], member: Membership, units: list[tuple[dict[str, Any], Membership]]
) -> str:
    """Why nothing can be traced on an HA unit / cluster node that FMC lists as disconnected, and what to do
    instead: the connected peers by name; when the unit is the one FMC calls active (control), that FMC's
    failover (cluster) state may be stale because a peer may have taken over. A peer is never picked
    silently: a standby unit drops everything."""
    name = str(dev.get("name"))
    ha = member.kind == "ha"
    what = "unit" if ha else "node"
    head = f"{member.left_out(name, 'disconnected')}: FMC can't run packet tracer on it"
    peers = [(d, m) for d, m in units if str(d.get("id")).lower() != str(dev.get("id")).lower()]
    if not peers:
        return f"{head}."
    up = [(d, m) for d, m in peers if d.get("isConnected") is True]
    if not up:
        down = ", ".join(str(d.get("name")) for d, _ in peers)
        return (
            f"{head}, and no other {what} of {member.container} is connected ({down}): FMC can't reach "
            f"the {'pair' if ha else 'cluster'}."
        )
    listed = ", ".join(f"{d.get('name')} ({m.role or 'member'} {what})" for d, m in up)
    carrier = next((d for d, m in up if m.carries_traffic), None)
    if carrier is not None:
        return (
            f"{head}. Connected: {listed}: trace on {carrier.get('name')}, or give {member.container}'s name."
        )
    state, check = ("failover", "fmc_get_ha_status") if ha else ("cluster", "fmc_list_clusters")
    names = " or ".join(str(d.get("name")) for d, _ in up)
    took_over = f"{names} may have taken over" if ha else f"{names} may have become the control node"
    role = f"the {member.role} {what}" if member.role else f"the {what} to trace on"
    why = ": a standby unit drops everything" if ha else ""
    return (
        f"{head}. Connected: {listed}. FMC still lists {name} as {role}, but FMC's {state} state may be "
        f"stale ({took_over} while FMC lost {name}): check {check}, then trace on the "
        f"{'active unit' if ha else 'control node'} by its name. No other {what} is traced on "
        f"automatically{why}."
    )


async def resolve_unit(
    app: FmcApp, ref: str, domain: str | None, *, traceable: bool = False
) -> tuple[dict[str, Any], Membership | None]:
    """A device to run something on the device itself (packet tracer), by name or UUID; an HA pair's or
    cluster's name or UUID means its active unit / control node (traffic_unit). (device record, its
    membership or None). With `traceable`, an HA unit or cluster node that FMC lists as disconnected is
    refused (UnitDisconnected, naming the connected peers) instead of being sent a trace FMC answers
    with a 503; a standalone device is left to FMC's own answer."""
    units: list[tuple[dict[str, Any], Membership]] | None = None
    try:
        dev = await resolve_in(app, DEVICES, ref, "device", domain)
    except (InvalidRequest, NotFound) as e:
        miss = e
        page = await app.all(await app.config_path(DEVICES, domain), cap=1000)
        members = await memberships(app, page.items, domain)
        want = ref.strip().lower()
        units = [
            (d, m)
            for d in page.items
            if (m := members.get(str(d.get("id")).lower())) and want in (m.container.lower(), m.container_id)
        ]
        if not units:
            raise miss from None
        dev = traffic_unit(units)
        member: Membership | None = members[str(dev.get("id")).lower()]
    else:
        member = membership_of(dev)
    if traceable and member is not None and dev.get("isConnected") is False:
        if units is None:  # a unit named directly: its peers from the device list (this failure path only)
            page = await app.all(await app.config_path(DEVICES, domain), cap=1000)
            units = [
                (d, m)
                for d in page.items
                if (m := membership_of(d)) is not None and m.container_id == member.container_id
            ] or [(dev, member)]
        raise UnitDisconnected(disconnected_note(dev, member, units), member.label(str(dev.get("name"))))
    return dev, member


def device_row(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": d.get("name"),
        "host": d.get("hostName"),
        "model": d.get("model"),
        "version": d.get("sw_version"),
        "health": d.get("healthStatus"),
        "connected": d.get("isConnected"),
        "mode": d.get("ftdMode"),
        "access_policy": ref_label(d["accessPolicy"]) if d.get("accessPolicy") else None,
        "device_group": ref_label(d["deviceGroup"]) if d.get("deviceGroup") else None,
        "deployment": d.get("deploymentStatus"),
        "id": d.get("id"),
    }


def interface_row(kind: str, i: dict[str, Any]) -> dict[str, Any]:
    ipv4 = i.get("ipv4") or {}
    static = ipv4.get("static") or {}
    addr = None
    if static.get("address"):
        addr = f"{static['address']}/{static.get('netmask', '')}"
    elif ipv4.get("dhcp"):
        addr = "dhcp"
    name = i.get("name")
    if kind == "subinterface" and i.get("subIntfId") is not None and "." not in str(name):
        name = f"{name}.{i['subIntfId']}"  # FMC names a subinterface after its parent
    return {
        "kind": kind,
        "name": name,
        "logical_name": i.get("ifname"),
        "enabled": i.get("enabled"),
        "mode": i.get("mode"),
        "zone": ref_label(i["securityZone"]) if i.get("securityZone") else None,
        "ipv4": addr,
        "vlan": i.get("vlanId") or i.get("subIntfId"),
        "mtu": i.get("MTU"),
        "description": i.get("description"),
        "id": i.get("id"),
        **logical_details(i),
    }


def logical_details(i: dict[str, Any]) -> dict[str, Any]:
    """What only logical interfaces carry: EtherChannel / bridge-group members and LACP mode, a VTI's
    tunnel type, source, borrowed address and VPN topology. Empty for other interfaces."""
    out: dict[str, Any] = {}
    if i.get("selectedInterfaces"):
        out["members"] = [ref_label(m) for m in i["selectedInterfaces"]]
    if i.get("lacpMode"):
        out["lacp"] = str(i["lacpMode"]).lower()
    if i.get("tunnelType"):
        out["tunnel_type"] = str(i["tunnelType"]).lower()
    if i.get("tunnelSource"):
        out["tunnel_source"] = ref_label(i["tunnelSource"])
    if i.get("borrowIPfrom"):
        out["borrows_from"] = ref_label(i["borrowIPfrom"])
    topo = (i.get("metadata") or {}).get("vpnTopologyName")
    if topo:
        out["vpn_topology"] = topo
    return out


async def inline_sets(app: FmcApp, device_id: str, domain: str | None) -> list[dict[str, Any]]:
    """Every inline set of a device (expanded); a model or version without them (404/405) has none."""
    try:
        page = await app.all(await app.config_path(f"{DEVICES}/{device_id}/{INLINE_SETS}", domain), cap=500)
    except UpstreamError as e:
        if e.status_code in (404, 405):
            return []
        raise
    return list(page.items)


def pair_names(s: dict[str, Any]) -> list[list[str]]:
    return [
        [ref_label(p.get("first") or {}), ref_label(p.get("second") or {})]
        for p in s.get("inlinepairs") or []
    ]


def inline_set_row(s: dict[str, Any]) -> dict[str, Any]:
    """An inline set in plain words, for previews, fmc_get_device and the device export."""
    row = {
        "name": s.get("name"),
        "id": s.get("id"),
        "pairs": pair_names(s),
        "tap_mode": bool(s.get("tapMode")),
        "fail_open_snort_down": s.get("failOpenSnortDown"),
        "fail_open_snort_busy": s.get("failOpenSnortBusy"),
        "propagate_link_state": s.get("propogateLinkState"),
        "strict_tcp": s.get("strictTCPEnforcement"),
        "mtu": s.get("mtu"),
        "bypass": s.get("bypass"),
        "description": s.get("description"),
    }
    return {k: v for k, v in row.items() if v is not None}


async def zone_names(app: FmcApp, domain: str | None) -> dict[str, str]:
    """Security zone id -> name. Interfaces reference their zone by id only."""
    key = f"zones:{domain or ''}"
    cached = app.cache_get(key)
    if cached is None:
        page = await app.all(await app.config_path("object/securityzones", domain), expanded=False)
        cached = {str(z.get("id")): str(z.get("name")) for z in page.items}
        app.cache_put(key, cached)
    names: dict[str, str] = cached
    return names


def name_zones(rows: list[dict[str, Any]], zones: dict[str, str]) -> list[dict[str, Any]]:
    for r in rows:
        if r.get("zone") in zones:
            r["zone"] = zones[r["zone"]]
    return rows


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List managed devices")
    async def fmc_list_devices(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="Filter: device name contains (case-insensitive)")
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the FTD devices FMC manages: name, management host, model, software version, health,
        connection state, assigned access policy, device group and deployment status. An FMC with no
        registered devices returns an empty list."""
        app: FmcApp = get_client(ctx)
        path = await app.config_path(DEVICES, domain)
        if name:
            page = await app.all(path)
            rows = [device_row(d) for d in page.items if name.lower() in str(d.get("name", "")).lower()]
            return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)
        page = await app.page(path, limit=limit, offset=offset)
        page.items = [device_row(d) for d in page.items]
        return list_result(page, fmt=response_format)

    @reg.read(title="Get device")
    async def fmc_get_device(ctx: Context, device: DeviceRef, domain: Domain = None) -> ToolResult:
        """Get one managed device in full: model, serial, version, health and message, license
        capabilities, performance tier, assigned access/health policies, HA/cluster role and
        deployment status, its inline sets (IPS-only interface pairs: tap mode, fail-open), and its DHCP
        server pools and relay settings (`dhcp`, when set; change them with fmc_configure_dhcp). Interfaces
        are listed by fmc_list_device_interfaces."""
        from fmc_mcp.tools.dhcp import device_dhcp  # dhcp builds on device_config, which imports this module

        app: FmcApp = get_client(ctx)
        d = await resolve_in(app, DEVICES, device, "device", domain)
        if not d.get("model") and d.get("id"):
            d = await app.api.get(await app.config_path(f"{DEVICES}/{d['id']}", domain))
        out = slim(d)
        if d.get("id"):
            sets = await inline_sets(app, str(d["id"]), domain)
            if sets:
                out["inline_sets"] = [inline_set_row(s) for s in sets]
            try:
                dhcp = await device_dhcp(app, d, domain)
            except UpstreamError as e:
                dhcp = {"error": str(e)}
            if dhcp:
                out["dhcp"] = dhcp
        return object_result(out)

    @reg.read(title="List device interfaces")
    async def fmc_list_device_interfaces(
        ctx: Context,
        device: DeviceRef,
        kinds: Annotated[
            list[
                Literal["physical", "subinterface", "etherchannel", "vlan", "vti", "loopback", "bridge_group"]
            ]
            | None,
            Field(description="Interface kinds to include (default: physical, subinterface, etherchannel)"),
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List a device's interfaces with logical name (nameif), security zone, IPv4 address, VLAN,
        MTU and admin state. Useful before building zone-based rules or NAT."""
        app: FmcApp = get_client(ctx)
        d = await resolve_in(app, DEVICES, device, "device", domain)
        rows: list[dict[str, Any]] = []
        notes: list[str] = []
        for kind in kinds or ["physical", "subinterface", "etherchannel"]:
            path = await app.config_path(f"{DEVICES}/{d['id']}/{INTERFACE_KINDS[kind]}", domain)
            try:
                page = await app.all(path, cap=2000)
            except UpstreamError as e:
                if e.status_code not in (404, 405):
                    raise
                notes.append(f"{kind}: not supported on this model")
                continue
            rows += [interface_row(kind, i) for i in page.items]
            if not page.complete:
                notes.append(f"{kind}: only the first 2000 shown")
        if any(r.get("zone") for r in rows):
            rows = name_zones(rows, await zone_names(app, domain))
        extra = {"device": d.get("name"), **({"note": "; ".join(notes)} if notes else {})}
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.read(title="List HA pairs")
    async def fmc_list_ha_pairs(
        ctx: Context,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List FTD high-availability (failover) pairs: primary and secondary device, which one is
        active, failover link and health. Returns an empty list when no HA pairs exist."""
        app: FmcApp = get_client(ctx)
        page = await app.page(await app.config_path(HA_PAIRS, domain), limit=limit, offset=offset)
        page.items = [_ha_row(h) for h in page.items]
        return list_result(page, fmt=response_format)

    @reg.read(title="List clusters")
    async def fmc_list_clusters(
        ctx: Context,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List FTD clusters with their control and data nodes. Returns an empty list when the FMC
        manages no clusters."""
        app: FmcApp = get_client(ctx)
        page = await app.page(await app.config_path(CLUSTERS, domain), limit=limit, offset=offset)
        page.items = [_cluster_row(c) for c in page.items]
        return list_result(page, fmt=response_format)


def _ha_row(h: dict[str, Any]) -> dict[str, Any]:
    boot = h.get("ftdHABootstrap") or {}
    link = boot.get("lanFailover") or {}
    return {
        "name": h.get("name"),
        "primary": ref_label(h["primary"]) if h.get("primary") else None,
        "secondary": ref_label(h["secondary"]) if h.get("secondary") else None,
        "active_primary": (h.get("metadata") or {}).get("primaryStatus", {}).get("currentStatus"),
        "failover_link": ref_label(link["interfaceObject"]) if link.get("interfaceObject") else None,
        "health": h.get("healthStatus"),
        "model": h.get("model"),
        "id": h.get("id"),
    }


def _cluster_row(c: dict[str, Any]) -> dict[str, Any]:
    control = c.get("controlDevice") or c.get("masterDevice") or {}
    data = c.get("dataDevices") or c.get("slaveDevices") or []
    return {
        "name": c.get("name"),
        "control_node": ref_label(control.get("deviceDetails") or control) if control else None,
        "data_nodes": [ref_label(n.get("deviceDetails") or n) for n in data],
        "id": c.get("id"),
    }

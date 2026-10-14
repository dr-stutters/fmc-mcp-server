"""Device tools: managed FTDs, interfaces, HA pairs and clusters."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from stutters_mcp_core.http import page_of

from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, ref_label, resolve_in, slim

DEVICES = "devices/devicerecords"
HA_PAIRS = "devicehapairs/ftddevicehapairs"
CLUSTERS = "deviceclusters/ftddevicecluster"

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
    }


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
        deployment status. Interfaces are listed by fmc_list_device_interfaces."""
        app: FmcApp = get_client(ctx)
        d = await resolve_in(app, DEVICES, device, "device", domain)
        if not d.get("model") and d.get("id"):
            d = await app.api.get(await app.config_path(f"{DEVICES}/{d['id']}", domain))
        return object_result(slim(d))

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

"""Flow context on one device: which named interface (and zone) a flow enters and leaves by, and the
device's access policy, worked out from FMC's configuration (interface subnets and static routes).

This saves the model the fmc_list_device_interfaces / fmc_list_routes / fmc_list_policy_assignments
round trips before fmc_rule_lookup and fmc_packet_tracer."""

import ipaddress
from dataclasses import dataclass
from typing import Any

from stutters_mcp_core import UpstreamError

from fmc_mcp.catalog import Catalog
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.device_config import device_interfaces
from fmc_mcp.tools.devices import DEVICES, interface_row, zone_names

Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Net = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class Leg:
    """One side of a flow on the device: the interface and how it was found."""

    interface: str  # logical name (nameif)
    zone: str | None
    how: str  # 'connected <subnet>' or 'route <net> via <gw>'

    def as_dict(self) -> dict[str, Any]:
        return {"interface": self.interface, "zone": self.zone, "found_by": self.how}


@dataclass
class DeviceContext:
    interfaces: list[dict[str, Any]]  # interface_row()s with a logical name and zone names
    routes: list[tuple[Net, str, str]]  # (destination network, interface name, gateway label)

    def leg(self, ip: Address) -> Leg | None:
        """The interface traffic to/from `ip` uses: a connected subnet first, then the longest
        matching static route."""
        best: tuple[int, dict[str, Any], str] | None = None
        for row in self.interfaces:
            try:
                net = ipaddress.ip_interface(str(row.get("ipv4") or "")).network
            except ValueError:
                continue
            if ip in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, row, f"connected {net}")
        if best is not None:
            return Leg(str(best[1]["logical_name"]), best[1].get("zone"), best[2])
        hit: tuple[int, str, str] | None = None
        for net, ifname, gw in self.routes:
            if ip.version == net.version and ip in net and (hit is None or net.prefixlen > hit[0]):
                hit = (net.prefixlen, ifname, f"route {net} via {gw}")
        if hit is None:
            return None
        zone = next((r.get("zone") for r in self.interfaces if r.get("logical_name") == hit[1]), None)
        return Leg(hit[1], zone, hit[2])


async def device_context(app: FmcApp, dev: dict[str, Any], cat: Catalog, domain: str | None) -> DeviceContext:
    """Named interfaces (with zone names) and static routes of a device."""
    zones = await zone_names(app, domain)
    rows = []
    for kind, i in await device_interfaces(app, dev["id"], domain):
        row = interface_row(kind, i)
        if not row.get("logical_name"):
            continue
        if row.get("zone") in zones:
            row["zone"] = zones[row["zone"]]
        rows.append(row)
    await cat.load_networks()
    routes: list[tuple[Net, str, str]] = []
    base = f"{DEVICES}/{dev['id']}/routing"
    for sub in ("ipv4staticroutes", "ipv6staticroutes"):
        try:
            page = await app.all(await app.config_path(f"{base}/{sub}", domain), cap=5000)
        except UpstreamError as e:
            if e.status_code in (404, 405):
                continue
            raise
        for r in page.items:
            gw = r.get("gateway") or {}
            gw_label = str(
                (gw.get("literal") or {}).get("value") or (gw.get("object") or {}).get("name") or "?"
            )
            for ref in r.get("selectedNetworks") or []:
                for v, lo, hi in cat.networks(ref) or []:
                    try:
                        nets: list[Net] = (
                            list(
                                ipaddress.summarize_address_range(
                                    ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi)
                                )
                            )
                            if v == 4
                            else list(
                                ipaddress.summarize_address_range(
                                    ipaddress.IPv6Address(lo), ipaddress.IPv6Address(hi)
                                )
                            )
                        )
                    except (TypeError, ValueError):
                        continue
                    routes += [(n, str(r.get("interfaceName") or ""), gw_label) for n in nets]
    return DeviceContext(rows, routes)


async def access_policy_of(app: FmcApp, dev: dict[str, Any], domain: str | None) -> dict[str, Any] | None:
    """The access control policy assigned to the device ({id, name, type}) or None."""
    acp = dev.get("accessPolicy")
    if not acp and dev.get("id"):
        rec = await app.api.get(await app.config_path(f"{DEVICES}/{dev['id']}", domain))
        acp = (rec or {}).get("accessPolicy")
    return acp if isinstance(acp, dict) and acp.get("id") else None

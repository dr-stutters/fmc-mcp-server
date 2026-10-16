"""Flow context on one device: which named interface (and zone) a flow enters and leaves by, and the
device's access policy, worked out from FMC's configuration (interface subnets and static routes).

This saves the model the fmc_list_device_interfaces / fmc_list_routes / fmc_list_policy_assignments
round trips before fmc_rule_lookup and fmc_packet_tracer."""

import contextlib
import ipaddress
from dataclasses import dataclass
from typing import Any

from fmc_mcp._core import UpstreamError
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
    routes: list[tuple[Net, str, str, int]]  # (destination, interface name, gateway label, metric)

    def leg(self, ip: Address) -> Leg | None:
        """The interface traffic to/from `ip` uses: the longest match among connected subnets
        (enabled interfaces) and static routes; on a tie a connected subnet wins, then the lower
        metric."""
        best: tuple[int, int, int, str, str | None, str] | None = None  # (prefix, connected, -metric, ...)
        for row in self.interfaces:
            if row.get("enabled") is False:
                continue
            for net in row.get("_nets") or []:
                if ip.version == net.version and ip in net:
                    cand = (
                        net.prefixlen,
                        1,
                        0,
                        str(row["logical_name"]),
                        row.get("zone"),
                        f"connected {net}",
                    )
                    if best is None or cand[:3] > best[:3]:
                        best = cand
        for net, ifname, gw, metric in self.routes:
            if ip.version == net.version and ip in net:
                zone = next((r.get("zone") for r in self.interfaces if r.get("logical_name") == ifname), None)
                cand = (net.prefixlen, 0, -metric, ifname, zone, f"route {net} via {gw}")
                if best is None or cand[:3] > best[:3]:
                    best = cand
        if best is None:
            return None
        return Leg(best[3], best[4], best[5])


def _interface_nets(row: dict[str, Any], raw: dict[str, Any]) -> list[Net]:
    """Connected IPv4 and IPv6 subnets of an interface."""
    nets: list[Net] = []
    with contextlib.suppress(ValueError):
        nets.append(ipaddress.ip_interface(str(row.get("ipv4") or "")).network)
    for a in ((raw.get("ipv6") or {}).get("addresses")) or []:
        try:
            nets.append(ipaddress.ip_interface(f"{a.get('address')}/{a.get('prefix')}").network)
        except ValueError:
            continue
    return nets


async def device_context(app: FmcApp, dev: dict[str, Any], cat: Catalog, domain: str | None) -> DeviceContext:
    """Named interfaces (with zone names) and static routes of a device."""
    zones = await zone_names(app, domain)
    rows = []
    for kind, i in await device_interfaces(app, dev["id"], domain):
        row = interface_row(kind, i)
        if not row.get("logical_name"):
            continue
        row["_nets"] = _interface_nets(row, i)
        if row.get("zone") in zones:
            row["zone"] = zones[row["zone"]]
        rows.append(row)
    await cat.load_networks()
    routes: list[tuple[Net, str, str, int]] = []
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
                    metric = int(r.get("metricValue") or 1)
                    routes += [(n, str(r.get("interfaceName") or ""), gw_label, metric) for n in nets]
    return DeviceContext(rows, routes)


async def access_policy_of(app: FmcApp, dev: dict[str, Any], domain: str | None) -> dict[str, Any] | None:
    """The access control policy assigned to the device ({id, name, type}) or None."""
    acp = dev.get("accessPolicy")
    if not acp and dev.get("id"):
        rec = await app.api.get(await app.config_path(f"{DEVICES}/{dev['id']}", domain))
        acp = (rec or {}).get("accessPolicy")
    return acp if isinstance(acp, dict) and acp.get("id") else None

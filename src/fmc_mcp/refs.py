"""Turn what the model writes ("10.1.1.0/24", "web-servers", "tcp/443", "inside") into FMC rule and
group condition blocks: {"objects": [refs], "literals": [values]}."""

from __future__ import annotations

import ipaddress
from typing import Any

from stutters_mcp_core import InvalidRequest

from fmc_mcp.catalog import parse_port_query
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import PROTOCOLS, ref_of, resolve_object

NETWORK_TYPES = ["host", "network", "range", "fqdn", "network_group"]
PORT_TYPES = ["port", "port_group", "icmpv4", "icmpv6"]
URL_TYPES = ["url", "url_group"]
ZONE_TYPES = ["security_zone", "interface_group"]
DYNAMIC_TYPES = ["dynamic_object"]


def network_literal(text: str) -> dict[str, str] | None:
    """A Host/Network/Range literal for an address, CIDR or range; None if it isn't one."""
    v = text.strip()
    try:
        if "-" in v:
            a, b = (ipaddress.ip_address(x.strip()) for x in v.split("-", 1))
            if a.version != b.version or int(a) > int(b):
                raise InvalidRequest(f"Invalid address range {v!r}")
            return {"type": "Range", "value": f"{a}-{b}"}
        if "/" in v:
            net = ipaddress.ip_network(v, strict=False)
            if net.num_addresses == 1:
                return {"type": "Host", "value": str(net.network_address)}
            return {"type": "Network", "value": str(net)}
        return {"type": "Host", "value": str(ipaddress.ip_address(v))}
    except ValueError:
        return None


def port_literal(text: str) -> dict[str, str] | None:
    """A PortLiteral / ICMP literal for 'tcp/443', 'udp/1000-2000', 'icmp', 'icmp/8'; None otherwise.
    A bare number needs a protocol, so it is not a literal (it may be an object name)."""
    t = text.strip()
    if "/" not in t and " " not in t and t.lower() not in ("icmp", "icmpv6", "tcp", "udp"):
        return None
    try:
        proto, lo, hi = parse_port_query(t)
    except ValueError:
        return None
    if proto not in PROTOCOLS:
        return None
    if proto in ("1", "58"):
        lit = {"type": "ICMPv4PortLiteral" if proto == "1" else "ICMPv6PortLiteral", "protocol": proto}
        lit["icmpType"] = "Any" if (lo, hi) in ((0, 65535), (0, 255)) else str(lo)
        return lit
    if (lo, hi) == (0, 65535):
        return {"type": "PortLiteral", "protocol": proto}
    return {"type": "PortLiteral", "protocol": proto, "port": str(lo) if lo == hi else f"{lo}-{hi}"}


def url_literal(text: str) -> dict[str, str] | None:
    t = text.strip()
    if "://" in t:
        return {"type": "Url", "url": t}
    return None


class RefResolver:
    """Resolves names once per tool call (each lookup costs FMC requests)."""

    def __init__(self, app: FmcApp, domain: str | None) -> None:
        self.app = app
        self.domain = domain
        self._cache: dict[tuple[str, str], dict[str, Any]] = {}

    async def obj(self, name: str, types: list[str]) -> dict[str, Any]:
        key = (name, ",".join(types))
        if key not in self._cache:
            _, found = await resolve_object(self.app, name, self.domain, types)
            self._cache[key] = ref_of(found)
        return self._cache[key]

    async def block(self, values: list[str] | None, kind: str) -> dict[str, Any] | None:
        """{"objects": [...], "literals": [...]} for networks, ports, urls or zones; None if no values."""
        if not values:
            return None
        objects: list[dict[str, Any]] = []
        literals: list[dict[str, Any]] = []
        for raw in values:
            v = str(raw).strip()
            if not v:
                continue
            lit = None
            if kind == "network":
                lit = network_literal(v)
            elif kind == "port":
                lit = port_literal(v)
            elif kind == "url":
                lit = url_literal(v)
            if lit is not None:
                literals.append(lit)
                continue
            types = {
                "network": NETWORK_TYPES,
                "port": PORT_TYPES,
                "url": URL_TYPES,
                "zone": ZONE_TYPES,
                "dynamic": DYNAMIC_TYPES,
            }[kind]
            objects.append(await self.obj(v, types))
        out: dict[str, Any] = {}
        if objects:
            out["objects"] = objects
        if literals:
            out["literals"] = literals
        return out or None

    async def single(self, value: str, types: list[str], what: str) -> dict[str, Any]:
        """One object reference (NAT fields, intrusion policy, ...)."""
        if not value.strip():
            raise InvalidRequest(f"Empty {what}.")
        return await self.obj(value, types)

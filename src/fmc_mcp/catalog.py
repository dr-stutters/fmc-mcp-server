"""An in-memory catalog of network and port objects, used to evaluate rules offline.

FMC's expanded rules reference objects by name/id only, so matching a flow against rules needs the
values of every host, network, range, port object and (nested) group. The catalog loads them in a
handful of paged requests per tool call and resolves references into numeric intervals.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import PROTO_NUMBERS

# (ip version, first address, last address) as integers
IpInterval = tuple[int, int, int]
# (protocol number as str, or "" for any; first port, last port); ICMP uses the type as the "port"
PortSpec = tuple[str, int, int]

CATALOG_CAP = 20_000


def parse_ip_value(value: str) -> list[IpInterval] | None:
    """'10.0.0.1', '10.0.0.0/8', '10.0.0.1-10.0.0.9', 'any'. None if not an address (e.g. FQDN)."""
    v = value.strip()
    if v.lower() in ("any", "any-ipv4"):
        return [(4, 0, 2**32 - 1)] + ([] if v.lower() == "any-ipv4" else [(6, 0, 2**128 - 1)])
    try:
        if "-" in v:
            a, b = (ipaddress.ip_address(x.strip()) for x in v.split("-", 1))
            return [(a.version, int(a), int(b))]
        net = ipaddress.ip_network(v, strict=False)
        return [(net.version, int(net.network_address), int(net.broadcast_address))]
    except ValueError:
        return None


def parse_port_value(protocol: Any, port: Any) -> PortSpec:
    proto = str(protocol or "").strip().upper()
    proto = PROTO_NUMBERS.get(proto, proto)
    p = str(port or "").strip()
    if not p:
        return (proto, 0, 65535)
    if "-" in p:
        lo, hi = p.split("-", 1)
        return (proto, int(lo), int(hi))
    return (proto, int(p), int(p))


def parse_port_query(text: str) -> PortSpec:
    """'443', 'tcp/443', 'UDP 53', '6/22', 'tcp/1000-2000', 'icmp'. ValueError for anything else: the
    protocol must be a known name or a number 0-255 and the port 0-65535, so a name such as
    'sdwan-single' is not read as protocol SDWAN-SINGLE."""
    t = text.strip().replace(" ", "/")
    if "/" in t:
        proto, port = t.split("/", 1)
    elif t.replace("-", "").isdigit():
        proto, port = "", t
    else:
        proto, port = t, ""
    p = proto.strip().upper()
    if p and p not in PROTO_NUMBERS and not (p.isdigit() and int(p) <= 255):
        raise ValueError(f"not a protocol: {proto!r}")
    if port and not re.fullmatch(r"\d+(-\d+)?", port.strip()):
        raise ValueError(f"not a port or port range: {port!r}")
    spec = parse_port_value(proto, port)
    if not spec[1] <= spec[2] <= 65535:
        raise ValueError(f"not a port or port range: {port!r}")
    return spec


def ip_contains(outer: list[IpInterval], inner: list[IpInterval]) -> bool:
    """Every interval of `inner` lies inside a single interval of `outer`."""
    return all(any(o[0] == i[0] and o[1] <= i[1] and i[2] <= o[2] for o in outer) for i in inner)


def port_contains(outer: list[PortSpec], inner: list[PortSpec]) -> bool:
    return all(any(o[0] in ("", i[0]) and o[1] <= i[1] and i[2] <= o[2] for o in outer) for i in inner)


@dataclass
class Catalog:
    app: FmcApp
    domain: str | None
    objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    complete: bool = True
    _loaded: set[str] = field(default_factory=set)

    async def _load(self, path: str) -> None:
        if path in self._loaded:
            return
        full = await self.app.config_path(path, self.domain)
        cached = self.app.cache_get(full)
        if cached is None:
            page = await self.app.all(full, cap=CATALOG_CAP)
            cached = (page.items, page.complete)
            self.app.cache_put(full, cached)
        found, complete = cached
        self.complete = self.complete and complete
        for o in found:
            if o.get("id"):
                self.objects[o["id"]] = o
        self._loaded.add(path)

    async def load_networks(self) -> None:
        # The networkaddresses aggregate leaves out ranges (FMC 10.0), so load them separately.
        for p in ("object/networkaddresses", "object/ranges", "object/networkgroups"):
            await self._load(p)

    async def load_ports(self) -> None:
        for p in (
            "object/protocolportobjects",
            "object/icmpv4objects",
            "object/icmpv6objects",
            "object/portobjectgroups",
        ):
            await self._load(p)

    # --- networks ------------------------------------------------------------------------

    def networks(self, block: Any, _seen: frozenset[str] = frozenset()) -> list[IpInterval] | None:
        """Intervals for a rule/group block ({objects, literals}) or a single reference. None when
        something can't be resolved to addresses (FQDN, unknown object)."""
        refs: list[Any]
        if isinstance(block, dict) and ("objects" in block or "literals" in block):
            refs = list(block.get("objects") or []) + list(block.get("literals") or [])
        elif isinstance(block, list):
            refs = block
        else:
            refs = [block]
        out: list[IpInterval] = []
        for ref in refs:
            got = self._network_ref(ref, _seen)
            if got is None:
                return None
            out += got
        return out

    def _network_ref(self, ref: Any, seen: frozenset[str]) -> list[IpInterval] | None:
        if not isinstance(ref, dict):
            return None
        obj = ref
        rid = ref.get("id")
        if rid:
            if rid in seen:
                return []
            obj = self.objects.get(rid, ref)
        if "objects" in obj or "literals" in obj or str(obj.get("type", "")).lower() == "networkgroup":
            if "objects" not in obj and "literals" not in obj:
                return None  # a group we couldn't load
            return self.networks(obj, seen | {rid} if rid else seen)
        if obj.get("value") is None:
            return None
        return parse_ip_value(str(obj["value"]))

    # --- ports ---------------------------------------------------------------------------

    def ports(self, block: Any, _seen: frozenset[str] = frozenset()) -> list[PortSpec] | None:
        refs: list[Any]
        if isinstance(block, dict) and ("objects" in block or "literals" in block):
            refs = list(block.get("objects") or []) + list(block.get("literals") or [])
        elif isinstance(block, list):
            refs = block
        else:
            refs = [block]
        out: list[PortSpec] = []
        for ref in refs:
            got = self._port_ref(ref, _seen)
            if got is None:
                return None
            out += got
        return out

    def _port_ref(self, ref: Any, seen: frozenset[str]) -> list[PortSpec] | None:
        if not isinstance(ref, dict):
            return None
        obj = ref
        rid = ref.get("id")
        if rid:
            if rid in seen:
                return []
            obj = self.objects.get(rid, ref)
        typ = str(obj.get("type", "")).lower()
        if typ == "portobjectgroup" or "objects" in obj:
            if "objects" not in obj and "literals" not in obj:
                return None
            return self.ports(obj, seen | {rid} if rid else seen)
        if "icmp" in typ or obj.get("icmpType") is not None:
            proto = "58" if "v6" in typ else "1"
            t = obj.get("icmpType")
            if obj.get("code") not in (None, "", "Any"):
                return None  # ICMP codes aren't modelled; the rule becomes conditional
            if t in (None, "", "Any"):
                return [(proto, 0, 255)]
            try:
                return [(proto, int(t), int(t))]
            except ValueError:
                return [(proto, 0, 255)]
        if "protocol" not in obj and "port" not in obj:
            return None
        try:
            return [parse_port_value(obj.get("protocol"), obj.get("port"))]
        except ValueError:
            return None

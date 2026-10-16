"""Turn what the model writes ("10.1.1.0/24", "web-servers", "tcp/443", "inside") into FMC rule and
group condition blocks: {"objects": [refs], "literals": [values]}."""

from __future__ import annotations

import ipaddress
from typing import Any

from fmc_mcp._core import InvalidRequest, NotFound
from fmc_mcp.catalog import parse_port_query
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import PROTOCOLS, ref_of, resolve_object

NETWORK_TYPES = ["host", "network", "range", "fqdn", "network_group"]
PORT_TYPES = ["port", "port_group", "icmpv4", "icmpv6"]
URL_TYPES = ["url", "url_group"]
ZONE_TYPES = ["security_zone", "interface_group"]
DYNAMIC_TYPES = ["dynamic_object"]
REALM_GROUPS = "object/realmusergroups"
REALM_USERS = "object/realmusers"


def identity_label(ref: dict[str, Any]) -> str:
    """'realm\\name' for a realm user or group reference."""
    realm = (ref.get("realm") or {}).get("name")
    return f"{realm}\\{ref.get('name')}" if realm else str(ref.get("name"))


def identity_ref(item: dict[str, Any]) -> dict[str, Any]:
    """A RealmUser / RealmUserGroup reference as access rules take it (FMC needs the realm in it)."""
    ref = {"id": item["id"], "type": item.get("type"), "name": item.get("name")}
    realm = item.get("realm") or {}
    if realm.get("id"):
        ref["realm"] = {"id": realm["id"], "type": "Realm", "name": realm.get("name")}
    return ref


async def identity_catalog(app: FmcApp, domain: str | None) -> list[dict[str, Any]]:
    """Downloaded realm groups, then users (FMC lists them once a realm has synced)."""
    out: list[dict[str, Any]] = []
    for path in (REALM_GROUPS, REALM_USERS):
        page = await app.all(await app.config_path(path, domain))
        out += [i for i in page.items if i.get("id")]
    return out


def match_identity(catalog: list[dict[str, Any]], text: str) -> dict[str, Any]:
    """Find a realm user or group by 'name', 'realm\\name' or 'group:name' / 'user:name'."""
    t = text.strip()
    kind = None
    low = t.lower()
    if low.startswith(("group:", "user:")):
        kind = "RealmUserGroup" if low.startswith("group:") else "RealmUser"
        t = t.split(":", 1)[1].strip()
    realm = None
    if "\\" in t:
        realm, t = (x.strip() for x in t.split("\\", 1))
    hits = [
        i
        for i in catalog
        if str(i.get("name", "")).lower() == t.lower()
        and (kind is None or i.get("type") == kind)
        and (realm is None or str((i.get("realm") or {}).get("name", "")).lower() == realm.lower())
    ]
    groups = [h for h in hits if h.get("type") == "RealmUserGroup"]
    if len(hits) > 1 and len(groups) == 1 and kind is None:
        hits = groups  # a group and a user with one name: the group (say user:<name> for the user)
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        where = ", ".join(identity_label(h) for h in hits)
        raise InvalidRequest(f"{text!r} is ambiguous ({where}); write it as realm\\name.")
    if not catalog:
        raise NotFound(
            f"No realm user or group {text!r}: FMC has no downloaded users or groups. Create an AD/LDAP "
            "realm (fmc_create_realm) and download it (fmc_download_realm) first.",
            404,
        )
    raise NotFound(
        f"No realm user or group {text!r} (see fmc_get_realm for the downloaded ones; after adding it "
        "in AD, run fmc_download_realm).",
        404,
    )


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
        self._identities: list[dict[str, Any]] | None = None

    async def identity(self, name: str) -> dict[str, Any]:
        if self._identities is None:
            self._identities = await identity_catalog(self.app, self.domain)
        return identity_ref(match_identity(self._identities, name))

    async def obj(self, name: str, types: list[str]) -> dict[str, Any]:
        key = (name, ",".join(types))
        if key not in self._cache:
            _, found = await resolve_object(self.app, name, self.domain, types)
            self._cache[key] = ref_of(found)
        return self._cache[key]

    async def block(self, values: list[str] | None, kind: str) -> dict[str, Any] | None:
        """{"objects": [...], "literals": [...]} for networks, ports, urls, zones or realm users/groups;
        None if no values."""
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
            if kind == "user":
                objects.append(await self.identity(v))
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

"""Helpers shared by the tool modules: parameter types, response shaping, name/id resolution."""

import difflib
import re
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from pydantic import Field

from fmc_mcp._core import InvalidRequest, NotFound
from fmc_mcp._core.writes import field_changes
from fmc_mcp.client import FmcApp, is_uuid

Domain = Annotated[
    str | None,
    Field(description="FMC domain name (e.g. 'Global') or UUID; default FMC_DOMAIN or the login's domain"),
]

# --- object types -------------------------------------------------------------------------------


@dataclass(frozen=True)
class ObjType:
    key: str  # our name, e.g. "host"
    path: str  # collection path under the domain, e.g. "object/hosts"
    fmc_type: str  # the "type" FMC uses in references, e.g. "Host"
    family: str  # network | port | url | zone | vlan | other
    writable: bool = True  # whether the write tools manage it


OBJECT_TYPES: dict[str, ObjType] = {
    t.key: t
    for t in (
        ObjType("host", "object/hosts", "Host", "network"),
        ObjType("network", "object/networks", "Network", "network"),
        ObjType("range", "object/ranges", "Range", "network"),
        ObjType("fqdn", "object/fqdns", "FQDN", "network"),
        ObjType("network_group", "object/networkgroups", "NetworkGroup", "network"),
        ObjType("port", "object/protocolportobjects", "ProtocolPortObject", "port"),
        ObjType("port_group", "object/portobjectgroups", "PortObjectGroup", "port"),
        ObjType("icmpv4", "object/icmpv4objects", "ICMPV4Object", "port"),
        ObjType("icmpv6", "object/icmpv6objects", "ICMPV6Object", "port"),
        ObjType("url", "object/urls", "Url", "url"),
        ObjType("url_group", "object/urlgroups", "UrlGroup", "url"),
        ObjType("security_zone", "object/securityzones", "SecurityZone", "zone"),
        ObjType("interface_group", "object/interfacegroups", "InterfaceGroup", "zone"),
        ObjType("vlan_tag", "object/vlantags", "VlanTag", "vlan"),
        ObjType("vlan_group", "object/vlangrouptags", "VlanGroupTag", "vlan"),
        ObjType("dynamic_object", "object/dynamicobjects", "DynamicObject", "other", writable=False),
        ObjType("time_range", "object/timeranges", "TimeRange", "other"),
        ObjType("application", "object/applications", "Application", "other", writable=False),
        ObjType("url_category", "object/urlcategories", "URLCategory", "other", writable=False),
        ObjType("geolocation", "object/geolocations", "Geolocation", "other", writable=False),
    )
}

ObjectTypeName = Literal[
    "host",
    "network",
    "range",
    "fqdn",
    "network_group",
    "port",
    "port_group",
    "icmpv4",
    "icmpv6",
    "url",
    "url_group",
    "security_zone",
    "interface_group",
    "vlan_tag",
    "vlan_group",
    "dynamic_object",
    "time_range",
    "application",
    "url_category",
    "geolocation",
]
# Types that support FMC's `nameOrValue` and `unusedOnly` filters.
FILTERABLE = {
    "host",
    "network",
    "range",
    "fqdn",
    "network_group",
    "port",
    "port_group",
    "icmpv4",
    "icmpv6",
    "url",
    "url_group",
    "vlan_tag",
    "vlan_group",
}
# Types tried, in order, when a tool gets an object name without a type.
SEARCH_ORDER = [
    "host",
    "network",
    "range",
    "fqdn",
    "network_group",
    "port",
    "port_group",
    "url",
    "url_group",
    "security_zone",
    "interface_group",
    "icmpv4",
    "vlan_tag",
    "vlan_group",
]

_BY_FMC_TYPE = {t.fmc_type.lower(): t for t in OBJECT_TYPES.values()}


def type_for(fmc_type: str | None) -> ObjType | None:
    """Our ObjType for an FMC reference type ('Host', 'NetworkGroup', 'ProtocolPortObject', ...)."""
    return _BY_FMC_TYPE.get(str(fmc_type or "").lower())


def obj_type(key: str) -> ObjType:
    try:
        return OBJECT_TYPES[key]
    except KeyError:
        raise InvalidRequest(f"Unknown object type {key!r}; choose from {', '.join(OBJECT_TYPES)}") from None


# --- shaping ----------------------------------------------------------------------------------

PROTOCOLS = {"1": "ICMP", "6": "TCP", "17": "UDP", "58": "ICMPv6", "47": "GRE", "50": "ESP", "51": "AH"}
PROTO_NUMBERS = {v.upper(): k for k, v in PROTOCOLS.items()}


def proto_name(p: Any) -> str:
    s = str(p or "").strip()
    return PROTOCOLS.get(s, s.upper())


def ref_label(ref: Any) -> str:
    """One readable label for a reference or literal inside a rule or group."""
    if not isinstance(ref, dict):
        return str(ref)
    if ref.get("name"):
        return str(ref["name"])
    if "value" in ref:
        return str(ref["value"])
    if "port" in ref or "protocol" in ref:
        proto = proto_name(ref.get("protocol"))
        if ref.get("icmpType") is not None:
            return f"{proto} type {ref['icmpType']}" + (f" code {ref['code']}" if ref.get("code") else "")
        port = ref.get("port")
        return f"{proto}/{port}" if port else proto
    if ref.get("url"):
        return str(ref["url"])
    if "startTag" in ref:  # VlanTagLiteral
        lo, hi = ref.get("startTag"), ref.get("endTag", ref.get("startTag"))
        return f"VLAN {lo}" if lo == hi else f"VLAN {lo}-{hi}"
    return str(ref.get("id", "?"))


def block_labels(block: Any) -> list[str]:
    """Labels for a rule condition block {"objects": [...], "literals": [...]} (or a plain list)."""
    if isinstance(block, list):
        return [ref_label(r) for r in block]
    if not isinstance(block, dict):
        return []
    out = [ref_label(r) for r in block.get("objects") or []]
    out += [ref_label(r) for r in block.get("literals") or []]
    return out


_META_KEEP = ("ruleIndex", "index", "section", "category", "readOnly", "lastUser", "timestamp", "domain")


# Secret-ish FMC fields the core's masking doesn't recognise (device registration key, NAT id,
# VPN pre-shared keys).
SECRET_FIELDS = {"regkey", "natid", "manualpresharedkey", "presharedkey"}


def slim(obj: Any) -> Any:
    """Trim FMC noise (`links` everywhere, most of `metadata`) and mask registration secrets."""
    if isinstance(obj, list):
        return [slim(x) for x in obj]
    if not isinstance(obj, dict):
        return obj
    out: dict[str, Any] = {}
    for k, v in obj.items():
        if k == "links":
            continue
        if k.lower() in SECRET_FIELDS and v not in (None, ""):
            out[k] = "********"
            continue
        if k == "metadata" and isinstance(v, dict):
            meta = {mk: v[mk] for mk in _META_KEEP if mk in v}
            if isinstance(meta.get("lastUser"), dict):
                meta["lastUser"] = meta["lastUser"].get("name")
            if isinstance(meta.get("domain"), dict):
                meta["domain"] = meta["domain"].get("name")
            if isinstance(meta.get("readOnly"), dict):
                meta["readOnly"] = meta["readOnly"].get("state")
            out[k] = meta
            continue
        out[k] = slim(v)
    return out


def smart_license_row(item: dict[str, Any]) -> dict[str, Any]:
    """One /license/smartlicenses item with its status fields lifted out of `metadata`.

    FMC 10 puts authStatus (AUTHORIZED, OUT_OF_COMPLIANCE, ...), virtualAccount, exportControl,
    evalUsed, evalExpiresInDays and the sync/renew times in items[].metadata, which slim() would drop.
    Top-level values win over metadata ones of the same name."""
    meta = item.get("metadata")
    row: dict[str, Any] = slim(meta) if isinstance(meta, dict) else {}
    row.update(slim({k: v for k, v in item.items() if k != "metadata"}))
    return row


# FMC gives the objects it creates ids whose third group is 0ed3 ("00000000-0000-0ed3-0000-021474836604",
# "005056B9-1CC8-0ed3-0000-034211017460"); its built-in network and port objects ship with fixed ids, the
# same on every FMC (any-ipv4 cb7116e8-66a6-480b-8f9b-295191a0940a, AOL 1834d812-38bb-11e2-86aa-62f0c593a59a).
# FMC 10.0.1 ships no built-in FQDN, ICMP or port-group objects; security zones get v1 UUIDs without 0ed3.
_FMC_CREATED_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-0ed3-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
# The families FMC ships built-in objects of (networks, network groups, ports).
_BUILTIN_FAMILIES = ("network", "port")


def is_builtin_object(obj: dict[str, Any]) -> bool:
    """Whether an object is one of FMC's built-in network or port objects (any, RFC1918, HTTP, ...), from
    its type and id alone: the same answer in every domain and for every API user's role (metadata.readOnly
    says SYSTEM, DOMAIN or RBAC depending on both)."""
    t = type_for(obj.get("type"))
    oid = str(obj.get("id") or "")
    return bool(oid) and t is not None and t.family in _BUILTIN_FAMILIES and not _FMC_CREATED_ID.match(oid)


def is_system(obj: dict[str, Any]) -> bool:
    """True for FMC's built-in read-only objects (any, RFC1918 groups, well-known ports, ...).

    A child domain sees everything an ancestor owns as readOnly with reason DOMAIN, FMC's built-ins
    included (FMC 10.0.1: HTTP, SSH and IPv4-Private-10.0.0.0-8 say SYSTEM only in Global); for those the
    type and id decide (is_builtin_object). Any other inherited object (Global's own hosts, groups, ...) is
    not a system object; writes to it are blocked with the owner domain instead (fmc_mcp.preview)."""
    ro = (obj.get("metadata") or {}).get("readOnly")
    if not (isinstance(ro, dict) and ro.get("state")):
        return False
    if ro.get("reason") != "DOMAIN":
        return True
    return is_builtin_object(obj)


def domain_path(name: str) -> str:
    """A domain name as fmc_list_domains and `domain` arguments write it: FMC's metadata.domain names a
    child domain 'Global \\ mcp-test-leaf' (FMC 10.0.1), the domain list 'Global/mcp-test-leaf'."""
    return re.sub(r"\s*\\\s*", "/", name.strip())


def ref_of(obj: dict[str, Any]) -> dict[str, Any]:
    """The minimal {id, type, name} reference FMC accepts inside other objects."""
    out = {"id": obj["id"], "type": obj.get("type")}
    if obj.get("name"):
        out["name"] = obj["name"]
    return out


def object_summary(obj: dict[str, Any]) -> dict[str, Any]:
    """Flat row for list output: name, type, value (or members for groups), description, id."""
    row: dict[str, Any] = {"name": obj.get("name"), "type": obj.get("type")}
    if "value" in obj:
        row["value"] = obj["value"]
    elif "port" in obj or obj.get("type") == "ProtocolPortObject":
        row["value"] = ref_label({"protocol": obj.get("protocol"), "port": obj.get("port")})
    elif "icmpType" in obj:
        row["value"] = ref_label({"protocol": "1", "icmpType": obj.get("icmpType"), "code": obj.get("code")})
    elif "url" in obj:
        row["value"] = obj["url"]
    elif "objects" in obj or "literals" in obj:
        row["members"] = block_labels(obj)
    elif "data" in obj:
        row["value"] = obj["data"]
    if obj.get("interfaceMode"):
        row["mode"] = obj["interfaceMode"]
    if obj.get("description"):
        row["description"] = obj["description"]
    ro = (obj.get("metadata") or {}).get("readOnly") or {}
    if is_system(obj):
        row["system"] = True  # in every domain, so not `inherited_from` too
    elif isinstance(ro, dict) and ro.get("reason") == "DOMAIN":
        owner = ((obj.get("metadata") or {}).get("domain") or {}).get("name")
        row["inherited_from"] = domain_path(str(owner)) if owner else None
    row["id"] = obj.get("id")
    return row


# --- resolution -------------------------------------------------------------------------------


def pick_by_name(
    items: list[dict[str, Any]], ref: str, what: str, *, partial: bool = False
) -> dict[str, Any]:
    exact = [i for i in items if i.get("name") == ref]
    if not exact:
        exact = [i for i in items if str(i.get("name", "")).lower() == ref.lower()]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        kinds = ", ".join(f"{i.get('name')} ({i.get('type')}, {i.get('id')})" for i in exact)
        raise InvalidRequest(f"{what} {ref!r} is ambiguous: {kinds}. Pass the id instead.")
    names = [str(i.get("name")) for i in items if i.get("name")]
    close = difflib.get_close_matches(ref, names, n=5, cutoff=0.5)
    hint = f" Did you mean: {', '.join(close)}?" if close else ""
    if partial:
        hint += " (The collection was too large to scan completely; pass the UUID instead.)"
    raise NotFound(f"No {what} named {ref!r}.{hint}", 404)


async def resolve_in(app: FmcApp, path: str, ref: str, what: str, domain: str | None) -> dict[str, Any]:
    """Find one item of a (small) collection, e.g. a policy or device, by UUID or name."""
    ref = ref.strip()
    full = await app.config_path(path, domain)
    if is_uuid(ref):
        data: dict[str, Any] = await app.api.get(f"{full}/{ref}")
        return data
    page = await app.all(full)
    return pick_by_name(page.items, ref, what, partial=not page.complete)


async def resolve_object(
    app: FmcApp,
    ref: str,
    domain: str | None,
    types: list[str] | None = None,
    *,
    full_fallback: bool = True,
) -> tuple[ObjType, dict[str, Any]]:
    """Resolve an object name or UUID, optionally restricted to some types. Types are searched in
    order (default SEARCH_ORDER) and the first type with a match wins (FMC keeps names unique within
    a family such as network objects, so cross-type clashes are rare; pass `type` to be explicit)."""
    ref = ref.strip()
    if not ref:
        raise InvalidRequest("Empty object name.")
    candidates = [obj_type(t) for t in (types or SEARCH_ORDER)]
    found: list[tuple[ObjType, dict[str, Any]]] = []
    partial = False
    if is_uuid(ref):
        for t in candidates:
            try:
                obj = await app.api.get(f"{await app.config_path(t.path, domain)}/{ref}")
            except NotFound:
                continue
            if isinstance(obj, dict) and obj.get("id"):
                return t, obj
    else:
        # First pass uses FMC's nameOrValue filter (cheap). That index lags a few seconds behind
        # creates, so when nothing matches and the caller named the types, retry with full listings.
        # Existence checks (expected to miss) pass full_fallback=False to skip the costly second pass.
        passes = [True, False] if types is not None and full_fallback else [True]
        for filtered in passes:
            for t in candidates:
                params = {"filter": f"nameOrValue:{ref}"} if filtered and t.key in FILTERABLE else None
                if not filtered and t.key not in FILTERABLE:
                    continue  # already listed in full on the first pass
                page = await app.all(await app.config_path(t.path, domain), params)
                partial = partial or not page.complete
                found += [(t, h) for h in _name_hits(page.items, ref)]
                if found:
                    break
            if found:
                break
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        kinds = ", ".join(f"{t.key} {o.get('id')}" for t, o in found)
        raise InvalidRequest(f"Object name {ref!r} is ambiguous ({kinds}); pass `type` or the id.")
    scope = ", ".join(t.key for t in candidates)
    more = " Some collections were too large to scan completely; pass the UUID." if partial else ""
    raise NotFound(
        f"No object {ref!r} found (looked in: {scope}). Try fmc_list_objects or fmc_find_object.{more}", 404
    )


def _name_hits(items: list[dict[str, Any]], ref: str) -> list[dict[str, Any]]:
    return [i for i in items if i.get("name") == ref] or [
        i for i in items if str(i.get("name", "")).lower() == ref.lower()
    ]


# Rule condition fields (access and prefilter rules) shown by label in update previews.
RULE_CONDITION_FIELDS = (
    "sourceZones",
    "destinationZones",
    "sourceInterfaces",
    "destinationInterfaces",
    "sourceNetworks",
    "destinationNetworks",
    "sourcePorts",
    "destinationPorts",
    "sourceDynamicObjects",
    "destinationDynamicObjects",
    "vlanTags",
    "urls",
    "users",
)


def _condition_labels(block: Any) -> list[str]:
    """block_labels plus URL categories (they live in the urls block too)."""
    out = block_labels(block)
    if isinstance(block, dict):
        for c in block.get("urlCategoriesWithReputation") or []:
            cat = ref_label(c.get("category") or {})
            rep = c.get("reputation")
            out.append(f"category:{cat}" + (f" ({rep})" if rep else ""))
    return out


def rule_changes(current: dict[str, Any], desired: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Field changes for a rule update. Conditions are compared as labels before/after, so a
    replaced condition shows what it removes (a literal replaced by an object, for example); the
    other fields as dotted field changes."""

    rest_cur = {k: v for k, v in current.items() if k not in RULE_CONDITION_FIELDS}
    rest_new = {k: v for k, v in desired.items() if k not in RULE_CONDITION_FIELDS}
    changes = field_changes(rest_cur, rest_new, replace=True)  # rules are PUT whole
    for f in RULE_CONDITION_FIELDS:
        before, after = _condition_labels(current.get(f)), _condition_labels(desired.get(f))
        if before != after:
            changes[f] = {"from": before or "any", "to": after or "any"}
    return changes

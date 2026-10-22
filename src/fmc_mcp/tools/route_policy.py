"""BGP/OSPF route policy (F77): IPv4 prefix lists and route maps as FMC objects, plus the pieces
fmc_configure_bgp and fmc_configure_ospf use to put them on a device (neighbour filters, maximum
prefix, default-originate and redistribution).

Shapes, FMC 10.0.1 (spec, cross-checked with the CiscoDevNet terraform provider's definitions):
- object/ipv4prefixlists: {name, entries[{sequence, action PERMIT|DENY, ipAddress, minPrefixLenth
  (FMC's spelling), maxPrefixLength}]}; FMC answers with type IPV4PrefixList (its non-expanded listing
  rows have none: references get it from REF_TYPES).
- object/routemaps: {name, type RouteMap, entries[{sequence, action, ipv4PrefixListAddresses[],
  communityLists[], asPathLists[], localPreferenceSetting, metricBandwidth, weightSetting,
  communityListSetting (+ the well-known community flags, addToExistingCommunity), asPathPrependASPath[]}]}.
- A BGP neighbour's neighborFiltering: neighborRouteMap[{routeMap, filterUpdateAction IN|OUT}],
  ipv4PrefixListFilter[{ipv4PrefixList, filterUpdateAction}], neighborMaximumPrefix{maxPrefixLimit,
  thresholdValue (session terminated) or warningOnly: true, restartInterval},
  neighborDefaultOriginate{routeMap}.
- redistributeProtocols (BGP address family or OSPF process): [{type RedistributeConnected|Static|OSPF|BGP,
  routeMap, routeMetric{metricValue, metricType}, processId, asNumber, subnets, matchInternal...}].
OSPFv2 has no passive interfaces in FMC's model (only OSPFv3 processes do), so none are offered here.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, ConfigDict, Field

from fmc_mcp._core import Confirm, InvalidRequest, NotFound, Plan, ToolRegistrar, UpstreamError, get_client
from fmc_mcp._core.writes import field_changes
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, pick_by_name, ref_label
from fmc_mcp.tools.object_writes import applied, editable

PREFIX_LISTS = "object/ipv4prefixlists"
ROUTE_MAPS = "object/routemaps"
COMMUNITY_LISTS = ("object/standardcommunitylists", "object/expandedcommunitylists")
AS_PATH_LISTS = "object/aspathlists"
NONE = "none"  # the value that removes a filter, as elsewhere ('none' clears)
# Each collection's object type, for references to it. FMC 10.0.1's non-expanded object/ipv4prefixlists
# listing has no `type` ({name, id} rows; object/routemaps rows do carry it), and a route map whose
# ipv4PrefixListAddresses reference has type null is refused with HTTP 500 "Prefix lists cannot be added
# inside Access Lists and vice versa. Also IPv4 and IPv6 lists are not interchangeable." The same POST
# with IPV4PrefixList is accepted (live 2026-10-21). FMC's own type wins when a row has one; the
# community and AS-path list types are the spec's (not seen live).
REF_TYPES = {
    PREFIX_LISTS: "IPV4PrefixList",
    ROUTE_MAPS: "RouteMap",
    COMMUNITY_LISTS[0]: "StandardCommunityList",
    COMMUNITY_LISTS[1]: "ExpandedCommunityList",
    AS_PATH_LISTS: "ASPathList",
}

PolicyName = Annotated[
    str,
    Field(min_length=1, max_length=64, pattern=r"^\S+$", description="Object name (no spaces)"),
]


# --- objects --------------------------------------------------------------------------------------


class PrefixEntry(BaseModel):
    """One line of an IPv4 prefix list."""

    model_config = ConfigDict(extra="forbid")

    prefix: str = Field(description="IPv4 network, e.g. 192.0.2.0/24 (0.0.0.0/0 for the default route)")
    action: Literal["permit", "deny"] = "permit"
    seq: int | None = Field(
        None, ge=1, le=2147483647, description="Sequence number; default: 5 after the previous line"
    )
    ge: int | None = Field(
        None, ge=1, le=32, description="Also match longer prefixes, at least this long (> the prefix length)"
    )
    le: int | None = Field(
        None, ge=1, le=32, description="Also match longer prefixes, at most this long (> the prefix length)"
    )


class RouteMapEntry(BaseModel):
    """One sequence of a route map: what it matches (all given must hold) and what it sets."""

    model_config = ConfigDict(extra="forbid")

    action: Literal["permit", "deny"] = "permit"
    seq: int | None = Field(
        None, ge=0, le=65535, description="Sequence number; default: 10 after the previous entry"
    )
    match_prefix_list: list[str] | None = Field(
        None, description="IPv4 prefix lists (name/UUID) the route's address must match"
    )
    match_community: list[str] | None = Field(
        None, description="BGP standard or expanded community lists (name/UUID)"
    )
    match_as_path: list[str] | None = Field(None, description="BGP AS-path lists (their number/UUID)")
    set_local_pref: int | None = Field(None, ge=1, le=4294967295, description="Set BGP local preference")
    set_metric: int | None = Field(None, ge=0, le=4294967295, description="Set the metric (BGP MED)")
    set_weight: int | None = Field(None, ge=0, le=65535, description="Set the BGP weight")
    set_community: str | None = Field(
        None,
        description="Set BGP communities: one number or AA:NN, plus no-export / no-advertise / internet "
        "(space separated), or 'none' to strip them",
    )
    set_community_additive: bool = Field(
        False, description="Add to the route's communities instead of replacing"
    )
    set_prepend: list[int] | None = Field(
        None, max_length=10, description="Prepend these AS numbers to the AS path, e.g. [65000, 65000]"
    )


def _action(a: str) -> str:
    return a.upper()


def prefix_entries(entries: list[PrefixEntry]) -> tuple[list[dict[str, Any]], list[str]]:
    """FMC entries for a prefix list, validated like the device does, plus warnings."""
    if not entries:
        raise InvalidRequest("A prefix list needs at least one entry.")
    out: list[dict[str, Any]] = []
    warnings: list[str] = []
    seqs: set[int] = set()
    last = 0
    for e in entries:
        try:
            net = ipaddress.IPv4Network(e.prefix.strip(), strict=False)
        except ValueError:
            raise InvalidRequest(f"{e.prefix!r} is not an IPv4 network (e.g. 192.0.2.0/24).") from None
        if str(net) != e.prefix.strip() and "/" in e.prefix:
            warnings.append(f"{e.prefix} has host bits set; FMC stores it as {net}.")
        n = net.prefixlen
        if e.ge is not None and e.ge <= n:
            raise InvalidRequest(f"{net}: ge {e.ge} must be longer than the prefix length /{n}.")
        if e.le is not None and e.le <= n:
            raise InvalidRequest(f"{net}: le {e.le} must be longer than the prefix length /{n}.")
        if e.ge is not None and e.le is not None and e.ge > e.le:
            raise InvalidRequest(f"{net}: ge {e.ge} can't be more than le {e.le}.")
        seq = e.seq if e.seq is not None else last + 5
        if seq in seqs:
            raise InvalidRequest(f"Sequence {seq} is used twice.")
        seqs.add(seq)
        last = seq
        row: dict[str, Any] = {"sequence": seq, "action": _action(e.action), "ipAddress": str(net)}
        if e.ge is not None:
            row["minPrefixLenth"] = e.ge  # FMC's spelling
        if e.le is not None:
            row["maxPrefixLength"] = e.le
        out.append(row)
    return sorted(out, key=lambda r: int(r["sequence"])), warnings


def prefix_line(entry: dict[str, Any]) -> str:
    """'seq 5 permit 192.0.2.0/24 ge 25 le 32' for an FMC prefix-list entry."""
    line = f"seq {entry.get('sequence')} {str(entry.get('action', '')).lower()} {entry.get('ipAddress')}"
    if entry.get("minPrefixLenth") is not None:
        line += f" ge {entry['minPrefixLenth']}"
    if entry.get("maxPrefixLength") is not None:
        line += f" le {entry['maxPrefixLength']}"
    return line


WELL_KNOWN = {
    "no-export": "communityListSettingNoExport",
    "no-advertise": "communityListSettingNoAdvertise",
    "internet": "communityListSettingInternet",
}


def community_fields(text: str, additive: bool) -> dict[str, Any]:
    """FMC route-map set fields for 'set community ...'."""
    tokens = text.lower().split()
    if not tokens:
        raise InvalidRequest("set_community is empty.")
    if tokens == [NONE]:
        if additive:
            raise InvalidRequest("set_community='none' can't be additive.")
        return {"specificCommunityNone": True}
    out: dict[str, Any] = {}
    for t in tokens:
        if t in WELL_KNOWN:
            out[WELL_KNOWN[t]] = True
            continue
        if "communityListSetting" in out:
            raise InvalidRequest("FMC sets one specific community per route-map entry; use another entry.")
        try:
            if ":" in t:
                hi, lo = (int(x) for x in t.split(":", 1))
                if not (0 <= hi <= 65535 and 0 <= lo <= 65535):
                    raise ValueError
                value = hi * 65536 + lo
            else:
                value = int(t)
            if not 1 <= value <= 4294967295:
                raise ValueError
        except ValueError:
            raise InvalidRequest(
                f"Community {t!r} must be a number, AA:NN, no-export, no-advertise, internet or none."
            ) from None
        out["communityListSetting"] = value
    if additive:
        out["addToExistingCommunity"] = True
    return out


def community_text(e: dict[str, Any]) -> str | None:
    if e.get("specificCommunityNone"):
        return NONE
    parts = []
    v = e.get("communityListSetting")
    if v not in (None, 0, ""):
        n = int(v)
        parts.append(f"{n >> 16}:{n & 0xFFFF}" if n > 65535 else str(n))
    parts += [k for k, f in WELL_KNOWN.items() if e.get(f)]
    if parts and e.get("addToExistingCommunity"):
        parts.append("additive")
    return " ".join(parts) or None


def route_map_line(entry: dict[str, Any]) -> str:
    """'seq 10 permit; match prefix-list X; set local-preference 200' for an FMC route-map entry."""
    parts = [f"seq {entry.get('sequence')} {str(entry.get('action', '')).lower()}"]
    for key, label in (
        ("ipv4PrefixListAddresses", "match ip address prefix-list"),
        ("ipv4AccessListAddresses", "match ip address"),
        ("communityLists", "match community"),
        ("asPathLists", "match as-path"),
    ):
        refs = entry.get(key) or []
        if refs:
            parts.append(f"{label} {', '.join(ref_label(r) for r in refs)}")
    for key, label in (
        ("localPreferenceSetting", "set local-preference"),
        ("metricBandwidth", "set metric"),
        ("weightSetting", "set weight"),
    ):
        if entry.get(key) is not None:
            parts.append(f"{label} {entry[key]}")
    comm = community_text(entry)
    if comm:
        parts.append(f"set community {comm}")
    if entry.get("asPathPrependASPath"):
        parts.append("set as-path prepend " + " ".join(str(a) for a in entry["asPathPrependASPath"]))
    return "; ".join(parts)


class PolicyRefs:
    """Name/UUID -> reference lookups for prefix lists, route maps, community and AS-path lists, one
    listing per collection per call."""

    def __init__(self, app: FmcApp, domain: str | None) -> None:
        self.app = app
        self.domain = domain
        self._lists: dict[str, list[dict[str, Any]]] = {}

    async def rows(self, path: str) -> list[dict[str, Any]]:
        """The collection's {name, id, type} rows; a row FMC lists without a type gets the collection's
        (REF_TYPES), so a reference built from it is one FMC accepts."""
        if path not in self._lists:
            try:
                page = await self.app.all(await self.app.config_path(path, self.domain), expanded=False)
                default = REF_TYPES.get(path)
                self._lists[path] = [
                    r if r.get("type") or default is None else {**r, "type": default} for r in page.items
                ]
            except NotFound:
                self._lists[path] = []
        return self._lists[path]

    async def one(self, paths: tuple[str, ...] | str, ref: str, what: str) -> dict[str, Any]:
        text = str(ref).strip()
        rows: list[dict[str, Any]] = []
        for p in (paths,) if isinstance(paths, str) else paths:
            rows += await self.rows(p)
        if is_uuid(text):
            hit = next((r for r in rows if str(r.get("id", "")).lower() == text.lower()), None)
            if hit is None:
                raise NotFound(f"No {what} with id {text}.", 404)
        else:
            hit = pick_by_name(rows, text, what)
        out = {"id": hit["id"], "type": hit.get("type")}
        if hit.get("name") is not None:
            out["name"] = hit["name"]
        return out

    async def prefix_list(self, ref: str) -> dict[str, Any]:
        return await self.one(PREFIX_LISTS, ref, "IPv4 prefix list")

    async def route_map(self, ref: str) -> dict[str, Any]:
        return await self.one(ROUTE_MAPS, ref, "route map")


async def route_map_entries(refs: PolicyRefs, entries: list[RouteMapEntry]) -> list[dict[str, Any]]:
    if not entries:
        raise InvalidRequest("A route map needs at least one entry.")
    out: list[dict[str, Any]] = []
    seqs: set[int] = set()
    last = 0
    for e in entries:
        seq = e.seq if e.seq is not None else last + 10
        if seq in seqs:
            raise InvalidRequest(f"Sequence {seq} is used twice.")
        seqs.add(seq)
        last = seq
        sets = (
            e.set_local_pref,
            e.set_metric,
            e.set_weight,
            e.set_community,
            e.set_prepend,
        )
        if e.action == "deny" and any(s is not None for s in sets):
            raise InvalidRequest(f"Sequence {seq} denies the route, so its set clauses would never apply.")
        row: dict[str, Any] = {"sequence": seq, "action": _action(e.action)}
        if e.match_prefix_list:
            row["ipv4PrefixListAddresses"] = [await refs.prefix_list(r) for r in e.match_prefix_list]
        if e.match_community:
            row["communityLists"] = [
                await refs.one(COMMUNITY_LISTS, r, "community list") for r in e.match_community
            ]
        if e.match_as_path:
            row["asPathLists"] = [await refs.one(AS_PATH_LISTS, r, "AS-path list") for r in e.match_as_path]
        if e.set_local_pref is not None:
            row["localPreferenceSetting"] = e.set_local_pref
        if e.set_metric is not None:
            row["metricBandwidth"] = e.set_metric
        if e.set_weight is not None:
            row["weightSetting"] = e.set_weight
        if e.set_community is not None:
            row.update(community_fields(e.set_community, e.set_community_additive))
        elif e.set_community_additive:
            raise InvalidRequest(f"Sequence {seq}: set_community_additive needs set_community.")
        if e.set_prepend:
            if any(not 1 <= a <= 4294967295 for a in e.set_prepend):
                raise InvalidRequest(f"Sequence {seq}: set_prepend takes AS numbers 1-4294967295.")
            row["asPathPrependASPath"] = list(e.set_prepend)
        out.append(row)
    return sorted(out, key=lambda r: int(r["sequence"]))


async def _existing(
    app: FmcApp, path: str, name: str, what: str, domain: str | None
) -> dict[str, Any] | None:
    page = await app.all(await app.config_path(path, domain))
    try:
        return pick_by_name(page.items, name, what)
    except NotFound:
        return None


async def _object_write(
    ctx: Context,
    *,
    tool: str,
    args: dict[str, Any],
    confirm: str | None,
    path: str,
    what: str,
    name: str,
    body: dict[str, Any],
    lines: list[str],
    line_of: Any,
    replace: bool,
    warnings: list[str],
    uses: str,
) -> dict[str, Any]:
    app: FmcApp = get_client(ctx)
    domain = args.get("domain")
    existing = await _existing(app, path, name, what, domain)
    blockers: list[str] = []
    details: dict[str, Any] = {what.replace(" ", "_"): name, "entries": lines}
    side_effects = list(warnings)
    if existing is None:
        if replace:
            blockers.append(f"No {what} named {name!r} to replace; leave replace off to create it.")
        target, method = await app.config_path(path, domain), "POST"
        summary = f"Create {what} {name!r}"
        side_effects.append(f"Changes nothing on devices until {uses} and is deployed.")
    else:
        old = [line_of(e) for e in existing.get("entries") or []]
        if not replace:
            blockers.append(
                f"A {what} named {name!r} already exists ({len(old)} entries); pass replace=true to "
                "replace its entries."
            )
        body = {**editable(existing), **{k: v for k, v in body.items() if k != "type"}}
        target, method = await app.config_path(f"{path}/{existing['id']}", domain), "PUT"
        summary = f"Replace the entries of {what} {name!r}"
        if old != lines:
            details["changes"] = {"entries": {"from": old, "to": lines}}
        elif body.get("description") == existing.get("description"):
            blockers.append(f"{what.capitalize()} {name!r} already has exactly these entries.")
        side_effects.append(
            f"Every device whose BGP/OSPF uses {name!r} (directly or through a route map) gets the new "
            "entries on its next deployment."
        )
    details["body"] = body

    async def apply() -> Any:
        if method == "POST":
            return await applied(app, lambda: app.api.post(target, body))
        return await applied(app, lambda: app.api.put(target, body))

    return await fmc_preview(
        ctx,
        tool=tool,
        args=args,
        confirm=confirm,
        plan=Plan(
            summary,
            details=details,
            fingerprint={"existing": existing and editable(existing), "body": body},
            blockers=blockers,
            side_effects=side_effects,
        ),
        apply=apply,
        owned=[existing] if existing else [],
    )


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create prefix list")
    async def fmc_create_prefix_list(
        ctx: Context,
        name: PolicyName,
        entries: Annotated[
            list[PrefixEntry],
            Field(
                description="Lines in order, e.g. [{'prefix': '192.0.2.0/24', 'action': 'deny'}, "
                "{'prefix': '0.0.0.0/0', 'le': 32}] (the last one permits everything else)"
            ),
        ],
        description: Annotated[str | None, Field(description="Optional description")] = None,
        replace: Annotated[
            bool, Field(description="The prefix list exists: replace all its entries with these")
        ] = False,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an IPv4 prefix list object (or replace an existing one's entries with replace=true):
        ordered permit/deny lines on a network, optionally with ge/le to match longer prefixes inside
        it. Like the device, a route no line matches is denied. Use it on a BGP neighbour
        (fmc_configure_bgp neighbor_prefix_list_in / _out) or in a route map (fmc_create_route_map
        match_prefix_list). The preview shows the lines as the device will have them."""
        rows, warnings = prefix_entries(entries)
        # No `type` on the POST: the spec's request example and the terraform provider send none, and
        # FMC answers with its own spelling (IPV4PrefixList), which a replace PUT sends back as it came.
        body: dict[str, Any] = {"name": name, "entries": rows}
        if description:
            body["description"] = description
        return await _object_write(
            ctx,
            tool="fmc_create_prefix_list",
            args={
                "name": name,
                "entries": [e.model_dump() for e in entries],
                "description": description,
                "replace": replace,
                "domain": domain,
            },
            confirm=confirm,
            path=PREFIX_LISTS,
            what="prefix list",
            name=name,
            body=body,
            lines=[prefix_line(r) for r in rows],
            line_of=prefix_line,
            replace=replace,
            warnings=warnings,
            uses="a BGP neighbour or a route map uses it",
        )

    @reg.write(title="Create route map")
    async def fmc_create_route_map(
        ctx: Context,
        name: PolicyName,
        entries: Annotated[
            list[RouteMapEntry],
            Field(
                description="Sequences in order, e.g. [{'action': 'deny', 'match_prefix_list': ['lab-lo2']}, "
                "{'action': 'permit', 'set_local_pref': 200}]"
            ),
        ],
        description: Annotated[str | None, Field(description="Optional description")] = None,
        replace: Annotated[
            bool, Field(description="The route map exists: replace all its entries with these")
        ] = False,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a route map object (or replace an existing one's entries with replace=true): ordered
        permit/deny sequences that match IPv4 prefix lists, BGP community lists or AS-path lists (all
        given in one sequence must match; none = every route) and set local preference, metric, weight,
        communities or an AS-path prepend. A route no sequence permits is dropped. Use it on a BGP
        neighbour (fmc_configure_bgp neighbor_route_map_in / _out) or to filter redistribution
        (redistribute=[{..., 'route_map': name}] on fmc_configure_bgp / fmc_configure_ospf). The
        preview shows each sequence in the device's terms."""
        app: FmcApp = get_client(ctx)
        rows = await route_map_entries(PolicyRefs(app, domain), entries)
        body: dict[str, Any] = {"name": name, "type": "RouteMap", "entries": rows}
        if description:
            body["description"] = description
        return await _object_write(
            ctx,
            tool="fmc_create_route_map",
            args={
                "name": name,
                "entries": [e.model_dump() for e in entries],
                "description": description,
                "replace": replace,
                "domain": domain,
            },
            confirm=confirm,
            path=ROUTE_MAPS,
            what="route map",
            name=name,
            body=body,
            lines=[route_map_line(r) for r in rows],
            line_of=route_map_line,
            replace=replace,
            warnings=[],
            uses="BGP or OSPF uses it (a neighbour filter or redistribution)",
        )


# --- BGP neighbour filters ---------------------------------------------------------------------

DIRECTIONS = (("in", "IN"), ("out", "OUT"))
# neighborFiltering list key -> (inner reference key, label in the readable row)
FILTER_KEYS = (
    ("neighborRouteMap", "routeMap", "route_map"),
    ("ipv4PrefixListFilter", "ipv4PrefixList", "prefix_list"),
    ("neighborFilterList", "asPathList", "as_path_filter"),
    ("neighborDistributeLists", "accessList", "distribute_list"),
)


def neighbor_filters(n: dict[str, Any]) -> dict[str, Any]:
    """The filter settings of one BGP neighbour, readable; only what is set (so a neighbour without
    filters reads exactly as before F77)."""
    nf = n.get("neighborFiltering") or {}
    out: dict[str, Any] = {}
    for key, inner, label in FILTER_KEYS:
        for r in nf.get(key) or []:
            direction = str(r.get("filterUpdateAction") or "").lower() or "in"
            out[f"{label}_{direction}"] = ref_label(r.get(inner) or {})
    mp = nf.get("neighborMaximumPrefix") or {}
    if mp.get("maxPrefixLimit"):
        row: dict[str, Any] = {"limit": mp["maxPrefixLimit"]}
        if mp.get("warningOnly"):
            row["warning_only"] = True
        else:
            if mp.get("thresholdValue") is not None:
                row["threshold_percent"] = mp["thresholdValue"]
            if mp.get("restartInterval"):
                row["restart_minutes"] = mp["restartInterval"]
        out["max_prefix"] = row
    if "neighborDefaultOriginate" in nf and nf["neighborDefaultOriginate"] is not None:
        rm = (nf["neighborDefaultOriginate"] or {}).get("routeMap")
        out["default_originate"] = {"route_map": ref_label(rm)} if rm else True
    return out


class NeighborFilters(BaseModel):
    """What fmc_configure_bgp was asked to change on one neighbour's filters (None = leave as is)."""

    route_map_in: str | None = None
    route_map_out: str | None = None
    prefix_list_in: str | None = None
    prefix_list_out: str | None = None
    max_prefix: int | None = None
    max_prefix_warning_only: bool | None = None
    default_originate: bool | None = None
    default_originate_route_map: str | None = None

    def given(self) -> bool:
        return any(v is not None for v in self.model_dump().values())


async def resolve_filters(refs: PolicyRefs, f: NeighborFilters) -> dict[str, dict[str, Any] | None]:
    """{slot: reference, or None to remove} for the route-map / prefix-list slots that were given."""
    out: dict[str, dict[str, Any] | None] = {}
    for slot in (
        "route_map_in",
        "route_map_out",
        "prefix_list_in",
        "prefix_list_out",
        "default_originate_route_map",
    ):
        value = getattr(f, slot)
        if value is None:
            continue
        if value.strip().lower() == NONE:
            out[slot] = None
        elif slot.startswith("prefix_list"):
            out[slot] = await refs.prefix_list(value)
        else:
            out[slot] = await refs.route_map(value)
    return out


def apply_filters(
    n: dict[str, Any], f: NeighborFilters, resolved: dict[str, dict[str, Any] | None]
) -> dict[str, Any]:
    """A copy of neighbour `n` with the requested filter changes; everything else is kept."""
    nf = dict(n.get("neighborFiltering") or {})
    for key, inner, label in FILTER_KEYS[:2]:
        for direction, action in DIRECTIONS:
            slot = f"{label}_{direction}"
            if slot not in resolved:
                continue
            ref = resolved[slot]
            current = nf.get(key) or []
            same = [
                r
                for r in current
                if str(r.get("filterUpdateAction") or "").upper() == action
                and ref is not None
                and str((r.get(inner) or {}).get("id")) == str(ref["id"])
            ]
            if same:
                continue  # already that object: keep FMC's own entries as they are
            rows = [r for r in current if str(r.get("filterUpdateAction") or "").upper() != action]
            if ref is not None:
                rows.append({inner: ref, "filterUpdateAction": action})
            if rows:
                nf[key] = rows
            else:
                nf.pop(key, None)
    if f.max_prefix is not None or f.max_prefix_warning_only is not None:
        current = dict(nf.get("neighborMaximumPrefix") or {})
        limit = f.max_prefix if f.max_prefix is not None else current.get("maxPrefixLimit")
        if f.max_prefix == 0:
            if f.max_prefix_warning_only:
                raise InvalidRequest("max_prefix=0 removes the limit; max_prefix_warning_only needs a limit.")
            nf.pop("neighborMaximumPrefix", None)
        elif not limit:
            raise InvalidRequest("max_prefix_warning_only needs max_prefix (the neighbor has no limit yet).")
        else:
            warn = (
                f.max_prefix_warning_only
                if f.max_prefix_warning_only is not None
                else bool(current.get("warningOnly"))
            )
            mp = {
                k: v
                for k, v in current.items()
                if k not in ("warningOnly", "thresholdValue", "restartInterval")
            }
            mp["maxPrefixLimit"] = int(limit)
            if warn:
                mp["warningOnly"] = True  # FMC takes warningOnly true only; termination is thresholdValue
            else:
                mp["thresholdValue"] = current.get("thresholdValue") or 75
                if current.get("restartInterval"):
                    mp["restartInterval"] = current["restartInterval"]
            nf["neighborMaximumPrefix"] = mp
    if f.default_originate is False:
        if f.default_originate_route_map not in (None, NONE):
            raise InvalidRequest("default_originate=false can't take a default_originate_route_map.")
        nf.pop("neighborDefaultOriginate", None)
    elif f.default_originate or (
        "default_originate_route_map" in resolved
        and (resolved["default_originate_route_map"] is not None or "neighborDefaultOriginate" in nf)
    ):  # a route map turns default-originate on; 'none' only drops the condition of an existing one
        current = nf.get("neighborDefaultOriginate")
        do = dict(current or {})
        if "default_originate_route_map" in resolved:
            ref = resolved["default_originate_route_map"]
            if ref is None:
                do.pop("routeMap", None)
            else:
                do["routeMap"] = ref
        if not do.get("routeMap") and do != current:
            # 'none' on a default-originate with a route map would drop the default route itself
            removing = "default_originate_route_map" in resolved and bool((current or {}).get("routeMap"))
            raise InvalidRequest(default_originate_needs_route_map(removing=removing))
        nf["neighborDefaultOriginate"] = do
    return {**n, "neighborFiltering": nf}


def default_originate_needs_route_map(*, removing: bool) -> str:
    """Why default-originate without a route map is refused. FMC 10.0.1 answers 200 to a neighbour's
    neighborDefaultOriginate without routeMap ({} or {type: neighbordefaultoriginate}) and stores
    neighborFiltering {}: no 'default-originate' reaches the device. With a route map it is stored and
    deployed as 'neighbor ... default-originate route-map ...' (live 2026-10-21, W6N live-B)."""
    if removing:
        return (
            "default_originate_route_map='none' would leave default-originate without a route map, which "
            "FMC 10.0.1 drops: the neighbor would stop getting the default route. To stop it, pass "
            "default_originate=false; to change the condition, name another route map."
        )
    return (
        "FMC 10.0.1 keeps a BGP neighbor's default-originate only with a route map: without one it "
        "answers OK and stores nothing, so the device never sends the default route. Pass "
        "default_originate_route_map=<route map>. For an unconditional default route, use a route map "
        "with one permit entry and no match: fmc_create_route_map(name='<name>', entries=[{'action': "
        "'permit'}])."
    )


def _holds(sent: Any, stored: Any) -> bool:
    """Whether `stored` (FMC's re-read) holds what `sent` asked for: a block FMC kept (not missing or
    emptied), a reference by its id, a list when every sent row has a match, words by value (case
    ignored: IN/OUT, PERMIT). Keys FMC adds (type, overridable, ...), the `type` FMC may leave out of a
    stored reference, and numbers or flags inside a kept block (FMC may store its own default or leave one
    out, e.g. a maximum-prefix threshold) don't count."""
    if isinstance(sent, dict):
        if not isinstance(stored, dict) or (sent and not stored):
            return False
        if sent.get("id") is not None:
            return str(stored.get("id", "")).lower() == str(sent["id"]).lower()
        return all(_holds(v, stored.get(k)) for k, v in sent.items() if k != "type")
    if isinstance(sent, list):
        return isinstance(stored, list) and all(any(_holds(s, t) for t in stored) for s in sent)
    if isinstance(sent, str):
        return stored is not None and sent.upper() == str(stored).upper()
    return True


def missing_filters(sent: dict[str, Any], stored: dict[str, Any] | None) -> list[str]:
    """The neighborFiltering keys a request carried for one neighbour (`sent`) that FMC's re-read of
    that neighbour's neighborFiltering (`stored`) doesn't hold. FMC 10.0.1 answers OK to a BGP create
    (POST) whose new neighbour has neighborDefaultOriginate {routeMap} and stores neighborFiltering {}
    (W6N final-live, 2026-10-21); the same block in an update (PUT) is stored, and an
    ipv4PrefixListFilter in the create is kept (live-B and final-live)."""
    have = stored or {}
    return [k for k, v in sent.items() if not _holds(v, have.get(k))]


# --- redistribution ----------------------------------------------------------------------------


class Redistribution(BaseModel):
    """Routes from another source to redistribute (or stop redistributing, remove=true). Naming a
    source that is already redistributed replaces its route map, metric and match with these."""

    model_config = ConfigDict(extra="forbid")

    protocol: Literal["connected", "static", "ospf", "bgp"] = Field(
        description="Source: connected, static, ospf (into BGP, or another OSPF process) or bgp (into OSPF)"
    )
    process_id: int | None = Field(None, ge=1, le=65535, description="Source OSPF process (protocol='ospf')")
    route_map: str | None = Field(None, description="Route map (name/UUID) that picks and changes the routes")
    metric: int | None = Field(None, ge=0, le=4294967295, description="Metric the routes get")
    metric_type: Literal["type_1", "type_2"] | None = Field(
        None, description="Into OSPF: external metric type (default type_2)"
    )
    subnets: bool | None = Field(
        None, description="Into OSPF: include subnets, not only classful networks (default true)"
    )
    match: (
        list[Literal["internal", "external_1", "external_2", "nssa_external_1", "nssa_external_2"]] | None
    ) = Field(None, description="protocol='ospf': which OSPF routes (device default: internal)")
    remove: bool = Field(False, description="Stop redistributing this source")


PROTOCOL_TYPES = {
    "connected": "RedistributeConnected",
    "static": "RedistributeStatic",
    "ospf": "RedistributeOSPF",
    "bgp": "RedistributeBGP",
}
TYPE_PROTOCOLS = {v.lower(): k for k, v in PROTOCOL_TYPES.items()}
MATCH_FIELDS = {
    "internal": "matchInternal",
    "external_1": "matchExternal1",
    "external_2": "matchExternal2",
    "nssa_external_1": "matchNssaExternal1",
    "nssa_external_2": "matchNssaExternal2",
}
MODELLED = {"type", "routeMap", "routeMetric", "processId", "asNumber", "subnets", *MATCH_FIELDS.values()}


def redistribution_row(r: dict[str, Any]) -> dict[str, Any]:
    """One redistributeProtocols entry, readable."""
    t = str(r.get("type") or "")
    row: dict[str, Any] = {"protocol": TYPE_PROTOCOLS.get(t.lower(), t)}
    if r.get("processId") not in (None, ""):
        row["process"] = r["processId"]
    if r.get("asNumber") not in (None, ""):
        row["as"] = r["asNumber"]
    if r.get("routeMap"):
        row["route_map"] = ref_label(r["routeMap"])
    metric = r.get("routeMetric") or {}
    if metric.get("metricValue") is not None:
        row["metric"] = metric["metricValue"]
    if metric.get("metricType"):
        row["metric_type"] = str(metric["metricType"]).lower()
    if r.get("subnets") is not None:
        row["subnets"] = r["subnets"]
    match = [k for k, f in MATCH_FIELDS.items() if r.get(f)]
    if match:
        row["match"] = match
    if r.get("tagNumber") is not None:
        row["tag"] = r["tagNumber"]
    return row


def _key(r: dict[str, Any]) -> tuple[str, str]:
    """Which source an entry redistributes: its type plus the OSPF process / BGP AS."""
    sub = r.get("processId") if r.get("processId") not in (None, "") else r.get("asNumber")
    return str(r.get("type") or "").lower(), "" if sub in (None, "") else str(sub)


async def apply_redistribution(
    current: list[dict[str, Any]],
    specs: list[Redistribution],
    refs: PolicyRefs,
    *,
    target: Literal["bgp", "ospf"],
    own_process: int | None = None,
    bgp_as: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """The new redistributeProtocols list, a readable diff and blockers. Entries for other sources,
    and fields this tool doesn't model (e.g. a tag), are kept."""
    out = [dict(r) for r in current]
    diff: dict[str, list[Any]] = {"added": [], "changed": [], "removed": []}
    blockers: list[str] = []
    seen: set[tuple[str, str]] = set()
    for s in specs:
        allowed = (
            ("connected", "static", "ospf") if target == "bgp" else ("connected", "static", "ospf", "bgp")
        )
        if s.protocol not in allowed:
            raise InvalidRequest(f"BGP can't redistribute {s.protocol} into itself.")
        if s.protocol == "ospf" and s.process_id is None:
            raise InvalidRequest("redistribute protocol='ospf' needs process_id (the source OSPF process).")
        if s.protocol != "ospf" and (s.process_id is not None or s.match):
            raise InvalidRequest("process_id and match apply to protocol='ospf' only.")
        if target == "ospf" and s.protocol == "ospf" and s.process_id == own_process:
            raise InvalidRequest(f"OSPF process {own_process} can't redistribute itself.")
        if target == "bgp" and (s.metric_type is not None or s.subnets is not None):
            raise InvalidRequest("metric_type and subnets apply to redistribution into OSPF only.")
        if s.protocol == "bgp" and not bgp_as and not s.remove:
            blockers.append("redistribute protocol='bgp' needs BGP on the device (its AS); set it up first.")
        if s.remove and any(
            x is not None for x in (s.route_map, s.metric, s.metric_type, s.subnets, s.match)
        ):
            raise InvalidRequest("remove=true takes only protocol (and process_id for ospf).")
        sub = s.process_id if s.protocol == "ospf" else (bgp_as if s.protocol == "bgp" else None)
        key = (PROTOCOL_TYPES[s.protocol].lower(), "" if sub in (None, "") else str(sub))
        label = f"{s.protocol}{f' {sub}' if sub not in (None, '') else ''}"
        if key in seen:
            raise InvalidRequest(f"redistribute names {label} twice.")
        seen.add(key)
        idx = next((i for i, r in enumerate(out) if _key(r) == key), None)
        if s.remove:
            if idx is None:
                blockers.append(f"{label} isn't redistributed into {target.upper()}.")
            else:
                diff["removed"].append(redistribution_row(out.pop(idx)))
            continue
        entry = {k: v for k, v in (out[idx] if idx is not None else {}).items() if k not in MODELLED}
        entry["type"] = PROTOCOL_TYPES[s.protocol]
        if s.protocol == "ospf":
            entry["processId"] = str(s.process_id) if target == "bgp" else s.process_id
            for m in s.match or []:
                entry[MATCH_FIELDS[m]] = True
        if s.protocol == "bgp" and bgp_as:
            entry["asNumber"] = int(bgp_as) if str(bgp_as).isdigit() else bgp_as
        if s.route_map and s.route_map.strip().lower() != NONE:
            entry["routeMap"] = await refs.route_map(s.route_map)
        metric: dict[str, Any] = {}
        if s.metric is not None:
            if target == "ospf" and s.metric > 16777214:
                raise InvalidRequest("An OSPF metric is at most 16777214.")
            metric["metricValue"] = s.metric
        if target == "ospf":
            metric["metricType"] = (s.metric_type or "type_2").upper()
            entry["subnets"] = True if s.subnets is None else s.subnets
        if metric:
            entry["routeMetric"] = metric
        if idx is None:
            out.append(entry)
            diff["added"].append(redistribution_row(entry))
        else:
            before = redistribution_row(out[idx])
            out[idx] = entry
            after = redistribution_row(entry)
            if before == after:
                blockers.append(f"{label} is already redistributed that way.")
            else:
                diff["changed"].append(
                    {"source": label, "changes": field_changes(before, after, replace=True)}
                )
    return out, {k: v for k, v in diff.items() if v}, blockers


def neighbor_diff(before: dict[str, Any] | None, after: dict[str, Any]) -> dict[str, Any]:
    """{field: {from, to}} between two readable neighbour rows (a new neighbour: from None)."""
    return field_changes(before or {}, after, replace=True)


REF_PATHS = {"routeMap": ROUTE_MAPS, "ipv4PrefixList": PREFIX_LISTS}


async def fill_names(refs: PolicyRefs, *models: Any) -> None:
    """Give route-map and prefix-list references without a name their name (in place), so the read
    view names them; costs nothing when FMC already sent the names."""
    missing: list[tuple[str, dict[str, Any]]] = []

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                if k in REF_PATHS and isinstance(v, dict) and v.get("id") and not v.get("name"):
                    missing.append((REF_PATHS[k], v))
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    for m in models:
        walk(m)
    for path, ref in missing:
        try:
            rows = await refs.rows(path)
        except (InvalidRequest, UpstreamError):
            # names are a nicety: a listing FMC refuses leaves the id, never fails the read view
            refs._lists[path] = []
            continue
        hit = next((r for r in rows if str(r.get("id")) == str(ref["id"])), None)
        if hit and hit.get("name"):
            ref["name"] = hit["name"]

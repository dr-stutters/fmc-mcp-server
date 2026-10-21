"""Object tools: list/get, find by value, where-used, unused objects."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    AuthError,
    InvalidRequest,
    NotFound,
    ResponseFormat,
    ToolRegistrar,
    ValidationFailed,
    get_client,
    list_result,
    object_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.catalog import Catalog, parse_ip_value, parse_port_query, port_contains
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import owner_domain
from fmc_mcp.rules import flatten_access_rule, flatten_nat_rule, flatten_prefilter_rule
from fmc_mcp.tools.common import (
    FILTERABLE,
    OBJECT_TYPES,
    Domain,
    ObjectTypeName,
    ObjType,
    block_labels,
    is_system,
    obj_type,
    object_summary,
    resolve_object,
    slim,
)

ObjectRef = Annotated[str, Field(description="Object name or UUID")]
OptionalType = Annotated[
    ObjectTypeName | None,
    Field(
        description="Object type; speeds up the lookup and disambiguates names (default: search common types)"
    ),
]

# Usage entries of these types are policies whose rules we can drill into.
RULE_SOURCES = {
    "accesspolicy": ("policy/accesspolicies/{id}/accessrules", flatten_access_rule),
    "prefilterpolicy": ("policy/prefilterpolicies/{id}/prefilterrules", flatten_prefilter_rule),
    "ftdnatpolicy": ("policy/ftdnatpolicies/{id}/natrules", flatten_nat_rule),
}


def _references(node: Any, ids: set[str]) -> bool:
    """True if any {id: ...} inside `node` is one of `ids`."""
    if isinstance(node, dict):
        if node.get("id") in ids and node.get("type") not in ("AccessRule", "PrefilterRule"):
            return True
        return any(_references(v, ids) for k, v in node.items() if k not in ("metadata", "links"))
    if isinstance(node, list):
        return any(_references(v, ids) for v in node)
    return False


async def _usage(app: FmcApp, obj: dict[str, Any], t: ObjType, domain: str) -> Any:
    return await app.all(
        await app.config_path("object/operational/usage", domain),
        {"filter": f"uuid:{obj['id']};type:{obj.get('type') or t.fmc_type}"},
        cap=5000,
    )


def _no_usage(t: ObjType, obj: dict[str, Any], e: Exception) -> InvalidRequest:
    return InvalidRequest(
        f"FMC can't report usage for {t.key} objects ({e}). Search rules instead, e.g. "
        f"fmc_list_access_rules(text={obj.get('name')!r})."
    )


# Reading a referencing policy's rules: FMC can't say which domain holds a policy (usage items carry no
# domain), so its rules are tried domain by domain. Bounded: at most DOMAIN_TRIES domains per policy (the one
# that last worked first) and MISS_BUDGET 404s per call, so 40 tenants x 20 policies stays a few dozen GETs.
DOMAIN_TRIES = 5
MISS_BUDGET = 30


def _policy_domains(app: FmcApp, here: str, usage_in: str) -> list[str]:
    """Where to read a referencing policy's rules, in order: the requested domain (it sees its own
    policies and its ancestors'), then the domains below the one usage was reported in (a policy of a
    child domain is invisible from its parent: GET ... 404), nearest first."""
    names = {d["uuid"].lower(): d["name"] for d in app.domains}
    top = names.get(usage_in.lower(), "")
    below = sorted(
        (d for d in app.domains if top and d["name"].startswith(top + "/")),
        key=lambda d: (d["name"].count("/"), d["name"]),
    )
    return [here] + [d["uuid"] for d in below if d["uuid"].lower() != here.lower()]


class _RuleReader:
    """Reads each policy's rules from the first domain that sees the policy, trying the domain that last
    worked first, within DOMAIN_TRIES per policy and MISS_BUDGET 404s per call."""

    def __init__(self, app: FmcApp, domains: list[str]) -> None:
        self.app = app
        self.domains = list(domains)
        self.misses = 0

    async def rules(self, path: str) -> list[dict[str, Any]] | None:
        for dom in self.domains[:DOMAIN_TRIES]:
            if self.misses >= MISS_BUDGET:
                return None
            try:
                page = await self.app.all(await self.app.config_path(path, dom), cap=10_000)
            except NotFound:
                self.misses += 1
                continue
            self.domains.remove(dom)
            self.domains.insert(0, dom)
            return page.items
        return None


async def _rules_domain(app: FmcApp, rules: list[dict[str, Any]]) -> str | None:
    """The domain that holds a policy, from its rules' metadata.domain (an inherited policy's rules
    name the ancestor)."""
    for r in rules:
        dom = ((r.get("metadata") or {}).get("domain") or {}).get("id")
        if dom:
            return await app.domain_name(str(dom))
    return None


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List objects")
    async def fmc_list_objects(
        ctx: Context,
        type: Annotated[ObjectTypeName, Field(description="Object type to list")] = "host",
        name_or_value: Annotated[
            str | None,
            Field(description="Filter: name or value contains (server-side where FMC supports it)"),
        ] = None,
        unused_only: Annotated[bool, Field(description="Only objects not referenced anywhere")] = False,
        include_system: Annotated[bool, Field(description="Include FMC's built-in read-only objects")] = True,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List FMC objects of one type (hosts, networks, ranges, FQDNs, network/port/URL groups,
        ports, ICMP, URLs, security zones, interface groups, VLAN tags, dynamic objects, time ranges,
        applications, URL categories, geolocations) with value or group members. To find which
        objects contain an IP or port use fmc_find_object."""
        app: FmcApp = get_client(ctx)
        t = obj_type(type)
        path = await app.config_path(t.path, domain)
        filters = []
        if t.key in FILTERABLE:
            if name_or_value:
                filters.append(f"nameOrValue:{name_or_value}")
            if unused_only:
                filters.append("unusedOnly:true")
        params = {"filter": ";".join(filters)} if filters else None
        local_name = name_or_value if t.key not in FILTERABLE else None
        if include_system and not local_name:
            page = await app.page(path, params, limit=limit, offset=offset)
            page.items = [object_summary(o) for o in page.items]
            return list_result(page, fmt=response_format)
        everything = await app.all(path, params, cap=20_000)
        rows = [
            object_summary(o)
            for o in everything.items
            if (include_system or not is_system(o))
            and (not local_name or local_name.lower() in str(o.get("name", "")).lower())
        ]
        extra = None if everything.complete else {"note": "Scanned only the first 20000 objects."}
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.read(title="Get object")
    async def fmc_get_object(
        ctx: Context, object: ObjectRef, type: OptionalType = None, domain: Domain = None
    ) -> ToolResult:
        """Get one FMC object by name or UUID: value, description, overrides, and for groups the
        members (objects and literals) by name. Accepts any type fmc_list_objects lists."""
        app: FmcApp = get_client(ctx)
        t, obj = await resolve_object(app, object, domain, [type] if type else None)
        if not obj.get("metadata") and obj.get("id"):
            obj = await app.api.get(await app.config_path(f"{t.path}/{obj['id']}", domain))
        out = {"object_type": t.key, **slim(obj)}
        if "objects" in obj or "literals" in obj:
            out["members"] = block_labels(obj)
        return object_result(out)

    @reg.read(title="Find objects by value")
    async def fmc_find_object(
        ctx: Context,
        value: Annotated[
            str,
            Field(
                description="An IP/CIDR/range (finds objects and groups containing it), a port such as "
                "'443', 'tcp/443' or 'udp/53' (finds port objects and groups covering it), or text"
            ),
        ],
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Find the objects that match a value: for an IP address or subnet, every host, network,
        range and network group containing it (FMC's own containment search); for a port, every port
        object and port group covering it (ranges included); otherwise objects whose name or value
        contains the text. Answers 'is there already an object for 10.1.1.5?' before creating one."""
        app: FmcApp = get_client(ctx)
        v = value.strip()
        if parse_ip_value(v) is not None or _looks_like_ip(v):
            return await _search(app, v, domain, limit, offset, response_format)
        try:
            spec = parse_port_query(v)
        except ValueError:
            return await _search(app, v, domain, limit, offset, response_format)
        cat = Catalog(app, domain)
        await cat.load_ports()
        rows = []
        for o in cat.objects.values():
            got = cat.ports(o) if ("objects" in o or "literals" in o) else cat._port_ref(o, frozenset())
            if got and _port_hit(got, spec):
                rows.append(object_summary(o))
        rows.sort(key=lambda r: (r.get("type") != "ProtocolPortObject", str(r.get("name"))))
        extra = {"query": f"{spec[0] or 'any'}/{spec[1]}" + (f"-{spec[2]}" if spec[2] != spec[1] else "")}
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.read(title="Where is an object used")
    async def fmc_where_used(
        ctx: Context,
        object: ObjectRef,
        type: OptionalType = None,
        drill_down: Annotated[
            bool, Field(description="Also list the individual access/prefilter/NAT rules that reference it")
        ] = True,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Show everything that references an object: the policies, groups and other objects FMC
        reports, plus (drill_down) the exact rules in each access, prefilter and NAT policy that use
        it directly or through a group. Use before changing or deleting an object. On a multi-domain
        FMC an object inherited from an ancestor domain is checked there (FMC answers usage only in the
        owner domain), across every domain below it; policies and rules say which domain holds them."""
        app: FmcApp = get_client(ctx)
        here = await app.domain_uuid(domain)
        t, obj = await resolve_object(app, object, domain, [type] if type else None)
        owner = owner_domain(obj)
        usage_in = here
        try:
            usage = await _usage(app, obj, t, here)
        except ValidationFailed as e:
            # FMC 10.0.1 answers 400 "API not supported for object ... in current domain" for an object
            # the domain only inherits; the owner domain answers, for every domain below it (#210). A login
            # scoped to the child domain doesn't list (or see) the owner: then there's nothing to ask.
            known = {d["uuid"].lower() for d in app.domains}
            owner_id = str((owner or {}).get("id") or "").lower()
            if not owner_id or owner_id == here.lower() or owner_id not in known:
                raise _no_usage(t, obj, e) from None
            try:
                usage = await _usage(app, obj, t, owner_id)
            except (ValidationFailed, AuthError, NotFound):
                raise _no_usage(t, obj, e) from None
            usage_in = owner_id
        multi = len(app.domains) > 1
        used_by = [{"type": u.get("type"), "name": u.get("name"), "id": u.get("id")} for u in usage.items]
        out: dict[str, Any] = {
            "object": {"name": obj.get("name"), "type": obj.get("type"), "id": obj["id"]},
            "in_use": bool(used_by),
            "used_by": used_by,
        }
        if multi and owner:
            out["object"]["domain"] = await app.domain_name(str(owner["id"]))
        if usage_in != here:
            out["note"] = (
                f"{obj.get('name')!r} is inherited from {await app.domain_name(usage_in)!r}: FMC reports its "
                "usage there, for that domain and every domain below it."
            )
        if drill_down and used_by:
            ids = {obj["id"]} | {
                u["id"] for u in used_by if u.get("type") and "group" in str(u["type"]).lower()
            }
            rules: list[dict[str, Any]] = []
            unread: list[str] = []
            where = _policy_domains(app, here, usage_in)
            reader = _RuleReader(app, where)
            for u in used_by[:20]:
                src = RULE_SOURCES.get(str(u.get("type", "")).lower())
                if not src:
                    continue
                path_t, flatten = src
                found = await reader.rules(path_t.format(id=u["id"]))
                if found is None:
                    unread.append(str(u.get("name")))
                    continue
                pol_domain = await _rules_domain(app, found)
                if multi and pol_domain:
                    u["domain"] = pol_domain
                for r in found:
                    if _references({k: v for k, v in r.items() if k != "id"}, ids):
                        row = {"policy": u.get("name"), **flatten(r)}
                        if multi and pol_domain:
                            row["domain"] = pol_domain
                        rules.append(row)
            out["rules"] = rules
            if unread:
                every = len(where) <= DOMAIN_TRIES and reader.misses < MISS_BUDGET
                out["warnings"] = [
                    f"Couldn't read the rules of {', '.join(unread)} in any domain this login sees."
                    if every
                    else f"Couldn't find the rules of {', '.join(unread)} in the domains tried (up to "
                    f"{DOMAIN_TRIES} per policy of {len(where)}, {reader.misses} misses): list them with "
                    "fmc_list_access_rules / fmc_list_nat_rules and the policy's domain."
                ]
        return out

    @reg.read(title="Find unused objects")
    async def fmc_unused_objects(
        ctx: Context,
        types: Annotated[
            list[ObjectTypeName] | None,
            Field(
                description="Types to check (default: host, network, range, fqdn, network_group, port, "
                "port_group, url, url_group)"
            ),
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List user-created objects that nothing references (no policy, group or other object), as
        clean-up candidates. FMC's built-in system objects are excluded (also in a child domain, where
        they are inherited from Global); objects inherited from an ancestor domain say so in
        `inherited_from`. Confirm with fmc_where_used before deleting."""
        app: FmcApp = get_client(ctx)
        keys = types or [
            "host",
            "network",
            "range",
            "fqdn",
            "network_group",
            "port",
            "port_group",
            "url",
            "url_group",
        ]
        rows: list[dict[str, Any]] = []
        skipped = []
        for key in keys:
            t = OBJECT_TYPES[key]
            if key not in FILTERABLE:
                skipped.append(key)
                continue
            page = await app.all(
                await app.config_path(t.path, domain), {"filter": "unusedOnly:true"}, cap=20_000
            )
            # is_system also knows the built-ins a child domain inherits (they say DOMAIN there, #197).
            rows += [{"object_type": key, **object_summary(o)} for o in page.items if not is_system(o)]
        extra = {"note": f"Not checkable via FMC's unused filter: {', '.join(skipped)}"} if skipped else None
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)


def _looks_like_ip(v: str) -> bool:
    return v.count(".") == 3 or (":" in v and v.count(":") >= 2)


def _port_hit(have: list[tuple[str, int, int]], want: tuple[str, int, int]) -> bool:
    proto, lo, hi = want
    if not proto:
        return any(h[1] <= lo and hi <= h[2] for h in have if h[0] in ("6", "17", ""))
    return port_contains(have, [want])


async def _search(
    app: FmcApp, text: str, domain: str | None, limit: int, offset: int, fmt: ResponseFormat
) -> ToolResult:
    path = await app.config_path("search/object", domain)
    page = await app.page(path, {"filter": f"text:{text}"}, limit=limit, offset=offset, expanded=False)
    page.items = [
        {"name": i.get("name"), "type": i.get("type"), "value": i.get("value"), "id": i.get("id")}
        for i in page.items
    ]
    return list_result(page, fmt=fmt, extra={"query": text})

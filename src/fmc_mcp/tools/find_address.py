"""Where does an address appear? (F59)

One IP address, network or range across network objects and groups, dynamic-object mappings, access
and prefilter rules, NAT rules, static routes and VPN endpoints, ranked by how directly each place
names it. Built on the offline-analysis catalog (fmc_mcp.catalog: objects and nested groups resolved
to addresses once per call) and the policy helpers fmc_rule_lookup and fmc_list_nat_rules use; every
collection is read once, paged, with caps so one call stays within FMC's rate limit.

User-to-IP (identity) rows come from the lookups in IDENTITY_LOOKUPS: FMC's identity sessions
(identity_sources.users_on_ip, the reader behind fmc_user_ip_lookup and fmc_user_identity_sessions).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from typing import Annotated, Any, Literal, get_args

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    InvalidRequest,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.catalog import Catalog, IpInterval, parse_ip_value
from fmc_mcp.client import FmcApp
from fmc_mcp.flow import access_policy_of
from fmc_mcp.rules import flatten_nat_rule
from fmc_mcp.tools.common import Domain, is_system, ref_label
from fmc_mcp.tools.device_config import resolve_device
from fmc_mcp.tools.devices import DEVICES
from fmc_mcp.tools.dynamic_objects import DYNAMIC, mappings_of
from fmc_mcp.tools.identity_sources import users_on_ip
from fmc_mcp.tools.policies import (
    ACCESS,
    NAT,
    PREFILTER,
    all_rules,
    nat_address_refs,
    nat_policy_of,
    resolve_policy,
)
from fmc_mcp.tools.vpn import S2S

Area = Literal[
    "objects",
    "dynamic_objects",
    "access_rules",
    "prefilter_rules",
    "nat_rules",
    "static_routes",
    "vpn",
    "identity",
]
AREAS: tuple[str, ...] = get_args(Area)

# Bounds per call (each is one or two requests per item; FMC allows ~120 requests a minute).
POLICY_CAP = 25  # access, prefilter and NAT policies scanned per kind
DEVICE_CAP = 30  # devices whose static routes are read
TOPOLOGY_CAP = 25  # VPN topologies whose endpoints are read
DYNAMIC_CAP = 50  # dynamic objects whose mappings are read

MATCH_ORDER = {"exact": 0, "inside": 1, "contains": 2, "overlaps": 3}
AREA_ORDER = {
    a: i
    for i, a in enumerate(
        (
            "identity",
            "dynamic_objects",
            "objects",
            "access_rules",
            "prefilter_rules",
            "nat_rules",
            "static_routes",
            "vpn",
        )
    )
}
COLUMNS = ["rank", "match", "area", "where", "side", "via", "value"]
LIMITS = (
    "FMC's configuration, read offline: per-device object overrides, inherited parent-policy rules, "
    "virtual-router (VRF) routes, FQDN objects and route-based VPN tunnels (no protected networks) are "
    "not resolved. Matches only through 'any' (0.0.0.0/0, ::/0) are counted, and FMC's built-in objects "
    "left out of the objects area, unless include_broad. Live state: fmc_packet_tracer / fmc_rule_lookup."
)

# async (app, address, domain) -> rows {where, via, value[, side]} for users on that IP.
IdentityLookup = Callable[
    [FmcApp, ipaddress.IPv4Address | ipaddress.IPv6Address, str | None], Awaitable[list[dict[str, Any]]]
]
IDENTITY_LOOKUPS: list[IdentityLookup] = [users_on_ip]


def relation(have: IpInterval, want: IpInterval) -> str | None:
    """How a configured value relates to the address asked about: 'exact', 'contains' (the value
    covers it), 'inside' (the value lies within the asked network), 'overlaps', or None."""
    if have[0] != want[0]:
        return None
    if have[1:] == want[1:]:
        return "exact"
    if have[1] <= want[1] and want[2] <= have[2]:
        return "contains"
    if want[1] <= have[1] and have[2] <= want[2]:
        return "inside"
    if have[1] <= want[2] and want[1] <= have[2]:
        return "overlaps"
    return None


def is_any(iv: IpInterval) -> bool:
    return iv[1] == 0 and iv[2] == (2**32 - 1 if iv[0] == 4 else 2**128 - 1)


def interval_text(iv: IpInterval) -> str:
    """10.1.1.5, 10.1.1.0/24, or 10.1.1.5-10.1.1.9."""
    cls = ipaddress.IPv4Address if iv[0] == 4 else ipaddress.IPv6Address
    lo, hi = cls(iv[1]), cls(iv[2])
    if lo == hi:
        return str(lo)
    nets = list(ipaddress.summarize_address_range(lo, hi))
    return str(nets[0]) if len(nets) == 1 else f"{lo}-{hi}"


@dataclass(frozen=True)
class Match:
    relation: str
    size: int  # addresses in the matching value: smaller is more specific
    value: str  # the configured value that matched
    path: tuple[str, ...] = ()  # object names from the reference down to that value
    broad: bool = False  # only through 'any'

    def key(self) -> tuple[bool, int, int]:
        return (self.broad, MATCH_ORDER[self.relation], self.size)


def better(a: Match | None, b: Match | None) -> Match | None:
    if a is None:
        return b
    if b is None:
        return a
    return b if b.key() < a.key() else a


@dataclass
class Tracer:
    """Resolves references (objects, nested groups, literals) against the address asked about."""

    cat: Catalog
    want: IpInterval

    def value(self, text: str, path: tuple[str, ...] = ()) -> Match | None:
        best: Match | None = None
        for iv in parse_ip_value(text) or []:
            rel = relation(iv, self.want)
            if rel:
                m = Match(rel, iv[2] - iv[1] + 1, interval_text(iv), path, is_any(iv))
                best = better(best, m)
        return best

    def ref(self, ref: Any, seen: frozenset[str] = frozenset()) -> Match | None:
        """Best match of a reference or literal; a group is followed into its members."""
        if not isinstance(ref, dict):
            return None
        obj = ref
        rid = ref.get("id")
        if rid:
            if rid in seen:
                return None
            obj = self.cat.objects.get(str(rid), ref)
        name = str(obj.get("name") or ref.get("name") or "")
        if "objects" in obj or "literals" in obj:
            inner = seen | {str(rid)} if rid else seen
            best: Match | None = None
            for member in [*(obj.get("objects") or []), *(obj.get("literals") or [])]:
                best = better(best, self.ref(member, inner))
            return replace(best, path=(name, *best.path)) if best and name else best
        if obj.get("value") is None:
            return None
        return self.value(str(obj["value"]), (name,) if name else ())

    def block(self, block: Any) -> tuple[Match | None, int]:
        """Best match among a rule block's objects and literals, and how many of them match."""
        if not isinstance(block, dict):
            return None, 0
        best: Match | None = None
        count = 0
        for ref in [*(block.get("objects") or []), *(block.get("literals") or [])]:
            m = self.ref(ref)
            if m:
                count += 1
                best = better(best, m)
        return best, count


@dataclass
class Search:
    app: FmcApp
    domain: str | None
    tracer: Tracer
    include_broad: bool
    hits: list[dict[str, Any]] = field(default_factory=list)
    searched: dict[str, Any] = field(default_factory=dict)
    skipped_broad: int = 0
    warnings: list[str] = field(default_factory=list)
    dynamic: dict[str, Match | None] = field(default_factory=dict)
    dynamic_budget: int = DYNAMIC_CAP

    def add(self, area: str, m: Match, where: str, side: str | None = None, via: str | None = None) -> None:
        if m.broad and not self.include_broad:
            self.skipped_broad += 1
            return
        self.hits.append(
            {
                "match": m.relation,
                "area": area,
                "where": where,
                "side": side,
                "via": via if via is not None else (" > ".join(m.path) or "literal"),
                "value": m.value,
                "_key": (*m.key(), AREA_ORDER.get(area, 99)),
            }
        )

    async def dynamic_match(self, oid: str, name: str) -> Match | None:
        """The best mapping of one dynamic object (mappings read once per call, within the cap)."""
        if oid in self.dynamic:
            return self.dynamic[oid]
        if self.dynamic_budget <= 0:
            self.warnings.append(f"Dynamic objects past the first {DYNAMIC_CAP} were not read.")
            self.dynamic[oid] = None
            return None
        self.dynamic_budget -= 1
        try:
            maps, complete = await mappings_of(self.app, oid, self.domain)
        except UpstreamError as e:
            self.warnings.append(f"Mappings of dynamic object {name!r} could not be read ({e}).")
            self.dynamic[oid] = None
            return None
        if not complete:
            self.warnings.append(f"Dynamic object {name!r} has more mappings than were read.")
        best: Match | None = None
        for text in maps:
            best = better(best, self.tracer.value(text, (name, text)))
        self.dynamic[oid] = best
        return best

    async def rule_side(
        self, rule: dict[str, Any], nets_field: str, dyn_field: str
    ) -> tuple[Match | None, int]:
        best, count = self.tracer.block(rule.get(nets_field))
        for o in (rule.get(dyn_field) or {}).get("objects") or []:
            if o.get("id"):
                m = await self.dynamic_match(str(o["id"]), str(o.get("name") or o["id"]))
                if m:
                    count += 1
                    best = better(best, m)
        return best, count


def _rule_where(policy: str, rule: dict[str, Any], action: Any) -> str:
    idx = (rule.get("metadata") or {}).get("ruleIndex")
    where = f"{policy} #{idx} {rule.get('name')}" if idx is not None else f"{policy}: {rule.get('name')}"
    where += f" ({action})"
    if rule.get("enabled") is False:
        where += " [disabled]"
    return where


async def _policies(s: Search, kind: str, path: str, one: str | None, label: str) -> list[dict[str, Any]]:
    """One named policy, or every policy of a kind (up to POLICY_CAP)."""
    if one:
        return [await resolve_policy(s.app, kind, one, s.domain)]
    page = await s.app.all(await s.app.config_path(path, s.domain), expanded=False, cap=POLICY_CAP)
    if not page.complete:
        s.warnings.append(
            f"Only the first {POLICY_CAP} {label} were searched; narrow with device or a policy."
        )
    return page.items


async def _objects(s: Search) -> None:
    cat = s.tracer.cat
    count = 0
    for obj in cat.objects.values():
        if not s.include_broad and is_system(obj):
            continue
        count += 1
        m = s.tracer.ref(obj)
        if m:
            via = " > ".join(m.path[1:]) or "value"
            s.add("objects", m, f"{obj.get('type')} {obj.get('name')}", via=via)
    s.searched["objects"] = count


async def _dynamic_objects(s: Search) -> None:
    page = await s.app.all(await s.app.config_path(DYNAMIC, s.domain), cap=DYNAMIC_CAP)
    if not page.complete:
        s.warnings.append(f"Only the first {DYNAMIC_CAP} dynamic objects were searched.")
    for o in page.items:
        m = await s.dynamic_match(str(o["id"]), str(o.get("name")))
        if m:
            s.add("dynamic_objects", m, f"dynamic object {o.get('name')}", via="mapping")
    s.searched["dynamic_objects"] = len(page.items)


async def _access_rules(s: Search, policies: list[dict[str, Any]]) -> None:
    rules_read = 0
    for p in policies:
        rules = await all_rules(s.app, await s.app.config_path(f"{ACCESS}/{p['id']}/accessrules", s.domain))
        if not rules.complete:
            s.warnings.append(f"Access policy {p.get('name')!r} has more rules than were read.")
        rules_read += len(rules.items)
        for r in rules.items:
            for side, nets, dyn in (
                ("source", "sourceNetworks", "sourceDynamicObjects"),
                ("destination", "destinationNetworks", "destinationDynamicObjects"),
            ):
                m, n = await s.rule_side(r, nets, dyn)
                if m:
                    via = " > ".join(m.path) or "literal"
                    if n > 1:
                        via += f" (+{n - 1} more)"
                    s.add("access_rules", m, _rule_where(str(p.get("name")), r, r.get("action")), side, via)
    s.searched["access_policies"] = len(policies)
    s.searched["access_rules"] = rules_read


async def _prefilter_rules(s: Search, policies: list[dict[str, Any]]) -> None:
    rules_read = 0
    for p in policies:
        path = await s.app.config_path(f"{PREFILTER}/{p['id']}/prefilterrules", s.domain)
        rules = await all_rules(s.app, path)
        rules_read += len(rules.items)
        for r in rules.items:
            both = " (bidirectional)" if r.get("bidirectional") else ""
            for side, nets in (("source", "sourceNetworks"), ("destination", "destinationNetworks")):
                m, n = s.tracer.block(r.get(nets))
                if m:
                    via = " > ".join(m.path) or "literal"
                    if n > 1:
                        via += f" (+{n - 1} more)"
                    action = f"{r.get('ruleType') or 'PREFILTER'} {r.get('action')}"
                    s.add("prefilter_rules", m, _rule_where(str(p.get("name")), r, action), side + both, via)
    s.searched["prefilter_policies"] = len(policies)
    s.searched["prefilter_rules"] = rules_read


async def _nat_rules(s: Search, policies: list[dict[str, Any]]) -> None:
    rules_read = 0
    for p in policies:
        rules = await all_rules(s.app, await s.app.config_path(f"{NAT}/{p['id']}/natrules", s.domain))
        rules_read += len(rules.items)
        for r in rules.items:
            row = flatten_nat_rule(r)
            where = f"{p.get('name')} {row.get('section') or ''} #{row.get('index') or '-'}".replace(
                "  ", " "
            )
            where += f" ({row.get('kind')} {row.get('nat_type') or ''}".rstrip() + ")"
            if row.get("enabled") is False:
                where += " [disabled]"
            for key, ref in nat_address_refs(r):
                m = s.tracer.ref(ref)
                if m:
                    s.add("nat_rules", m, where, key)
    s.searched["nat_policies"] = len(policies)
    s.searched["nat_rules"] = rules_read


async def _static_routes(s: Search, devices: list[dict[str, Any]]) -> None:
    sub = "ipv4staticroutes" if s.tracer.want[0] == 4 else "ipv6staticroutes"
    read = 0
    for d in devices:
        path = await s.app.config_path(f"{DEVICES}/{d['id']}/routing/{sub}", s.domain)
        try:
            page = await s.app.all(path, cap=5000)
        except UpstreamError as e:
            if e.status_code in (404, 405):
                continue
            s.warnings.append(f"Static routes of {d.get('name')} could not be read ({e}).")
            continue
        read += len(page.items)
        for r in page.items:
            gw = r.get("gateway") or {}
            lit = gw.get("literal") if isinstance(gw.get("literal"), dict) else None
            gw_label = (lit or {}).get("value") or ref_label(gw.get("object") or {}) or "?"
            where = f"{d.get('name')}: route via {gw_label} on {r.get('interfaceName')}"
            best: Match | None = None
            for ref in r.get("selectedNetworks") or []:
                best = better(best, s.tracer.ref(ref))
            if best:
                s.add("static_routes", best, where, "destination")
            if lit and lit.get("value"):
                m = s.tracer.value(str(lit["value"]))
                if m:
                    s.add("static_routes", m, where, "gateway", "literal")
            elif isinstance(gw.get("object"), dict):
                m = s.tracer.ref(gw["object"])
                if m:
                    s.add("static_routes", m, where, "gateway")
    s.searched["devices"] = len(devices)
    s.searched["static_routes"] = read


async def _vpn(s: Search) -> None:
    topos = await s.app.all(await s.app.config_path(S2S, s.domain), cap=TOPOLOGY_CAP)
    if not topos.complete:
        s.warnings.append(f"Only the first {TOPOLOGY_CAP} VPN topologies were searched.")
    endpoints = 0
    for t in topos.items:
        page = await s.app.all(await s.app.config_path(f"{S2S}/{t['id']}/endpoints", s.domain), cap=2000)
        endpoints += len(page.items)
        for e in page.items:
            info = e.get("extranetInfo") or {}
            peer = info.get("name") if e.get("extranet") else ref_label(e.get("device") or {})
            where = f"VPN {t.get('name')}: {peer or e.get('name')} ({e.get('peerType') or 'PEER'})"
            prot = e.get("protectedNetworks") or {}
            refs = [
                *(prot.get("networks") or []),
                *(prot.get("objects") or []),
                *(prot.get("literals") or []),
            ]
            best: Match | None = None
            for ref in refs:
                best = better(best, s.tracer.ref(ref))
            if best:
                s.add("vpn", best, where, "protected network")
            for addr in str(info.get("ipAddress") or "").split(","):
                m = s.tracer.value(addr) if addr.strip() else None
                if m:
                    s.add("vpn", m, where, "peer address", "extranet peer")
    s.searched["vpn_topologies"] = len(topos.items)
    s.searched["vpn_endpoints"] = endpoints


async def _identity(s: Search) -> str | None:
    """Rows from the user-to-IP sources in IDENTITY_LOOKUPS (FMC's identity sessions); a note when none."""
    want = s.tracer.want
    if want[1] != want[2]:
        return "identity: user sessions are looked up for a single address only"
    if not IDENTITY_LOOKUPS:
        return "identity: no user-to-IP lookup on this server"
    ip = ipaddress.IPv4Address(want[1]) if want[0] == 4 else ipaddress.IPv6Address(want[1])
    for lookup in IDENTITY_LOOKUPS:
        try:
            rows = await lookup(s.app, ip, s.domain)
        except UpstreamError as e:
            s.warnings.append(f"Identity lookup failed ({e}).")
            continue
        for row in rows:
            m = Match("exact", 1, str(row.get("value") or ip))
            s.add("identity", m, str(row.get("where")), row.get("side"), str(row.get("via") or "session"))
    return None


def parse_query(address: str) -> IpInterval:
    text = address.strip()
    got = parse_ip_value(text) if text.lower() not in ("any", "any-ipv4", "any-ipv6") else None
    if not got or len(got) != 1:
        raise InvalidRequest(
            f"{address!r} is not one IP address, CIDR network or range (e.g. 10.99.1.10, 10.99.1.0/24, "
            "10.99.1.10-10.99.1.20); FQDNs and 'any' can't be searched."
        )
    if is_any(got[0]):
        raise InvalidRequest("'any' (0.0.0.0/0, ::/0) matches everything; ask about a narrower network.")
    return got[0]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Find where an address appears")
    async def fmc_find_address(
        ctx: Context,
        address: Annotated[
            str,
            Field(
                description="An IP address, CIDR network or range, e.g. 10.99.1.10, 10.99.1.0/24 or "
                "10.99.1.10-10.99.1.20"
            ),
        ],
        areas: Annotated[
            list[Area] | None,
            Field(
                description="Where to look (default: everywhere): objects, dynamic_objects, access_rules, "
                "prefilter_rules, nat_rules, static_routes, vpn, identity"
            ),
        ] = None,
        device: Annotated[
            str | None,
            Field(
                description="Only this FTD (name or UUID): its access, prefilter and NAT policies and its "
                "static routes"
            ),
        ] = None,
        access_policy: Annotated[
            str | None,
            Field(description="Only this access control policy (and the prefilter policy it links)"),
        ] = None,
        nat_policy: Annotated[str | None, Field(description="Only this NAT policy")] = None,
        include_broad: Annotated[
            bool,
            Field(
                description="Also list matches only through 'any' (0.0.0.0/0, ::/0; otherwise only "
                "counted) and FMC's built-in objects such as IPv4-Private-10.0.0.0-8 in the objects area "
                "(rules that use them are always listed)"
            ),
        ] = False,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """'Where does 10.1.2.3 appear?' in one call: every place FMC's configuration names an IP
        address, network or range: host/network/range objects and the groups holding them,
        dynamic-object mappings, access and prefilter rules (source or destination; literal, via an
        object, a nested group or a dynamic object), NAT rules (original/translated source and
        destination), static routes (destination or gateway), VPN protected networks and extranet
        peers, and the users FMC has an identity session for on a single IP (as fmc_user_ip_lookup
        reads them; a role without Analysis > Users gives a warning instead). Ranked: exact matches
        first, then the narrowest values that contain it; each row says where it lives (policy, rule
        index and action; NAT section; device route; VPN endpoint) and via which object chain. Use it
        before changing or retiring an address, in an incident ('what touches this host?'), or before
        fmc_contain_host. Bounded: 25 policies per kind, 30 devices, 25 VPN topologies, 50 dynamic
        objects (a warning names what was not searched); narrow with device, access_policy or
        nat_policy. Offline configuration only (see `limits`); for live verdicts use
        fmc_packet_tracer or fmc_rule_lookup."""
        app: FmcApp = get_client(ctx)
        want = parse_query(address)
        wanted = set(areas or AREAS)
        cat = Catalog(app, domain)
        await cat.load_networks()
        s = Search(app, domain, Tracer(cat, want), include_broad)
        dev = await resolve_device(app, device, domain) if device else None

        acps: list[dict[str, Any]] = []
        if wanted & {"access_rules", "prefilter_rules"}:
            if access_policy:
                acps = [await resolve_policy(app, "access", access_policy, domain)]
            elif dev is not None:
                ref = await access_policy_of(app, dev, domain)
                acps = [await resolve_policy(app, "access", str(ref["id"]), domain)] if ref else []
            else:
                acps = await _policies(s, "access", ACCESS, None, "access policies")
        if "objects" in wanted:
            await _objects(s)
        if "dynamic_objects" in wanted:
            await _dynamic_objects(s)
        if "access_rules" in wanted:
            await _access_rules(s, acps)
        if "prefilter_rules" in wanted:
            if access_policy or dev is not None:
                ids = {str((a.get("prefilterPolicySetting") or {}).get("id")) for a in acps}
                pfs = [await resolve_policy(app, "prefilter", i, domain) for i in sorted(ids - {"None"})]
            else:
                pfs = await _policies(s, "prefilter", PREFILTER, None, "prefilter policies")
            await _prefilter_rules(s, pfs)
        if "nat_rules" in wanted:
            one = nat_policy
            if one is None and dev is not None:
                one = await nat_policy_of(app, str(dev["id"]), domain)
                if one is None:
                    s.searched["nat_policies"] = 0
            if one is not None or dev is None:
                await _nat_rules(s, await _policies(s, "nat", NAT, one, "NAT policies"))
        if "static_routes" in wanted:
            if dev is not None:
                devices = [dev]
            else:
                page = await app.all(await app.config_path(DEVICES, domain), cap=DEVICE_CAP)
                if not page.complete:
                    s.warnings.append(f"Static routes of only the first {DEVICE_CAP} devices were searched.")
                devices = page.items
            await _static_routes(s, devices)
        if "vpn" in wanted:
            await _vpn(s)
        not_checked = [n for n in [await _identity(s)] if n] if "identity" in wanted else []

        hits = sorted(s.hits, key=lambda h: h["_key"])
        rows = []
        for i, h in enumerate(hits, 1):
            row = {"rank": i, **{k: v for k, v in h.items() if k != "_key" and v is not None}}
            rows.append(row)
        by_area: dict[str, int] = {}
        for h in hits:
            by_area[h["area"]] = by_area.get(h["area"], 0) + 1
        extra: dict[str, Any] = {"address": interval_text(want), "by_area": by_area, "searched": s.searched}
        if s.skipped_broad:
            extra["hidden_broad_matches"] = s.skipped_broad
        if not_checked:
            extra["not_checked"] = not_checked
        if not cat.complete:
            s.warnings.append(
                "The object catalog was larger than the scan cap; some objects were not resolved."
            )
        if s.warnings:
            extra["warning"] = " ".join(dict.fromkeys(s.warnings))
        extra["limits"] = LIMITS
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra, columns=COLUMNS
        )

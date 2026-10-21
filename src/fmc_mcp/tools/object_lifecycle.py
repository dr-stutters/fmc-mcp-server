"""Object lifecycle at scale (F70): delete many objects in one preview, replace one object with another
everywhere it is referenced.

fmc_delete_objects (dangerous) selects by names, a name prefix or FMC's unused filter across value objects
and groups, security zones and interface groups, dynamic objects and policies. The preview lists every
victim and every refusal (FMC built-ins, objects an ancestor domain owns, objects still in use with what
uses them); an object used only by other victims is deleted after them (policies, then the groups that hold
an object, then the object). Value objects, groups and dynamic objects go out with FMC's bulk DELETE
(`?bulk=true&filter=ids:...`) per type; zones and policies one by one (FMC has no bulk delete for them).

fmc_replace_object (write) is the reference walk behind fmc_where_used and fmc_find_address (F59) turned
into a change: FMC's usage API names the policies, groups and devices that reference the object; their
access and prefilter rules, groups, NAT rules and static routes are read and every reference to the old
object is swapped for the new one, rules and groups first, NAT rules and static routes second. Access rules
go out as FMC's bulk partial update (`PUT accessrules?bulk=true&partialUpdate=true` with `{id, type, <the
changed condition blocks>}`), the shape the F67 probe recorded on 10.0.1: atomic per request, and the
rule's other fields, section, category and position stay as they are.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import fnmatch
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal, get_args

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    ValidationFailed,
    get_client,
)
from fmc_mcp._core.http import Page
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview, owner_domain
from fmc_mcp.rules import flatten_nat_rule
from fmc_mcp.tools.common import (
    FILTERABLE,
    OBJECT_TYPES,
    ROLE_READ_ONLY,
    Domain,
    ObjectTypeName,
    ObjType,
    is_builtin_object,
    is_system,
    obj_type,
    object_summary,
    ref_label,
    ref_of,
    resolve_object,
    role_read_only,
)
from fmc_mcp.tools.devices import DEVICES
from fmc_mcp.tools.dynamic_objects import DYNAMIC
from fmc_mcp.tools.find_address import DEVICE_CAP, POLICY_CAP
from fmc_mcp.tools.object_writes import editable
from fmc_mcp.tools.policies import ACCESS, NAT, POLICY_KINDS, PREFILTER, all_rules, policy_assignments

USAGE = "object/operational/usage"
# FMC 10.0.1's `unusedOnly` filter never lists network groups (live 2026-10-21: count 0 in the leaf and in
# Global while the usage API named no referrer and FMC accepted the group's DELETE). Only there, and only when
# the filter answers no group of the type at all in the domain (that blind-filter signature), does an empty
# usage answer free a group. Everywhere else the filter stays authoritative: "in use" by the filter with no
# referrer named is refused, since the usage API is not known to be complete for other types.
BLIND_FILTER_TYPES = frozenset({"network_group"})
GROUP_USAGE_CAP = 40  # groups the unused-objects listing checks with the usage API (one request each)

# --- shared ---------------------------------------------------------------------------------------


def chunks[T](items: list[T], size: int) -> Iterator[list[T]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def inherited_from(obj: dict[str, Any], here: str) -> str | None:
    """The owner domain's name when an ancestor domain owns `obj` (FMC changes it only there)."""
    ro = (obj.get("metadata") or {}).get("readOnly")
    dom = owner_domain(obj)
    if dom and str(dom.get("id", "")).lower() != here:
        return str(dom.get("name") or dom["id"])
    if isinstance(ro, dict) and ro.get("state") and ro.get("reason") == "DOMAIN":
        return str((dom or {}).get("name") or "an ancestor domain")
    return None


async def usage_of(
    app: FmcApp, obj: dict[str, Any], t: ObjType, domain: str | None
) -> list[dict[str, Any]] | None:
    """What FMC's usage API says references an object ({type, name, id} rows), or None where FMC can't
    tell (400 for security zones and dynamic objects, and for objects a child domain only inherits)."""
    try:
        page = await app.all(
            await app.config_path(USAGE, domain),
            {"filter": f"uuid:{obj['id']};type:{obj.get('type') or t.fmc_type}"},
            cap=5000,
        )
    except ValidationFailed:
        return None
    return [{"type": u.get("type"), "name": u.get("name"), "id": u.get("id")} for u in page.items]


@dataclass
class FreeGroups:
    rows: list[dict[str, Any]] = field(default_factory=list)  # groups the usage API says nothing uses
    checked: int = 0  # usage requests made
    unchecked: list[str] = field(default_factory=list)  # left over when the cap was reached


async def filter_is_blind(app: FmcApp, key: str, domain: str | None) -> bool:
    """FMC's unused filter answers no group of a BLIND_FILTER_TYPES type at all in the domain: FMC 10.0.1's
    for network groups (one request, one row at most)."""
    if key not in BLIND_FILTER_TYPES:
        return False
    path = await app.config_path(OBJECT_TYPES[key].path, domain)
    page = await app.page(path, {"filter": "unusedOnly:true"}, limit=1, expanded=False)
    return not page.items


async def free_groups(app: FmcApp, key: str, domain: str | None, budget: int = GROUP_USAGE_CAP) -> FreeGroups:
    """Groups of type `key` nothing references, for a type whose unused filter is blind here (see
    filter_is_blind: FMC 10.0.1 lists no network group). Built-ins, groups an ancestor domain owns (the
    usage API can't answer for them here) and groups another group holds are skipped without a request; the
    rest are asked one by one, at most `budget`. A usage answer FMC refuses (400) keeps the group out."""
    t = OBJECT_TYPES[key]
    here = (await app.domain_uuid(domain)).lower()
    page = await app.all(await app.config_path(t.path, domain), cap=20_000)
    held: set[str] = set()
    for g in page.items:
        held |= referenced_ids(g)
    out = FreeGroups()
    for g in sorted(page.items, key=lambda o: str(o.get("name", "")).lower()):
        gid = str(g.get("id", "")).lower()
        if not gid or gid in held or is_system(g) or inherited_from(g, here):
            continue
        if out.checked >= budget:
            out.unchecked.append(str(g.get("name") or gid))
            continue
        out.checked += 1
        if await usage_of(app, g, t, domain) == []:
            out.rows.append(g)
    return out


def referenced_ids(node: Any) -> set[str]:
    """Every {id: ...} reference inside a rule or group body (its own id, metadata and links left out)."""
    found: set[str] = set()

    def walk(n: Any) -> None:
        if isinstance(n, dict):
            if n.get("id"):
                found.add(str(n["id"]).lower())
            for k, v in n.items():
                if k not in ("metadata", "links"):
                    walk(v)
        elif isinstance(n, list):
            for v in n:
                walk(v)

    if isinstance(node, dict):
        for k, v in node.items():
            if k not in ("id", "metadata", "links"):
                walk(v)
    return found


# --- bulk delete ----------------------------------------------------------------------------------

Kind = Literal["objects", "zones", "dynamic_objects", "policies"]
DeletePolicyKind = Literal["access", "nat", "prefilter", "platform_settings"]
BULK_TYPES: tuple[str, ...] = tuple(k for k in OBJECT_TYPES if k in FILTERABLE)
ZONE_TYPES = ("security_zone", "interface_group")
DELETE_POLICY_KINDS: tuple[str, ...] = get_args(DeletePolicyKind)
CHUNK = 50  # ids per bulk DELETE: 50 UUIDs keep the query string under 2 KB
USAGE_CAP = 60  # in-use candidates whose users are read (one usage request each)
MAX_VICTIMS = 500
MIN_PREFIX = 3
REFUSED_SHOWN = 100
KIND_ORDER = {"policies": 0, "objects": 1, "dynamic_objects": 2, "zones": 3}


@dataclass
class Candidate:
    kind: str  # objects | zones | dynamic_objects | policies
    key: str  # object type key (host, security_zone, dynamic_object) or policy kind (access, nat, ...)
    obj: dict[str, Any]
    users: dict[str, str] = field(default_factory=dict)  # id -> label of what references it
    reason: str | None = None  # why it can't be deleted (whatever else is deleted)
    in_use: bool = False  # the reason is a use (not a built-in or an ancestor's object)
    level: int = 0

    def refuse(self, reason: str, *, in_use: bool = True) -> None:
        self.reason = reason
        self.in_use = in_use

    @property
    def id(self) -> str:
        return str(self.obj.get("id")).lower()

    @property
    def name(self) -> str:
        return str(self.obj.get("name") or self.obj.get("id"))

    def row(self) -> dict[str, Any]:
        if self.kind == "policies":
            row: dict[str, Any] = {"name": self.obj.get("name"), "type": self.obj.get("type")}
        else:
            s = object_summary(self.obj)
            row = {k: s[k] for k in ("name", "type", "value", "members") if s.get(k) not in (None, [])}
            if self.kind == "zones" and self.obj.get("interfaceMode"):
                row["mode"] = self.obj["interfaceMode"]
        row["id"] = self.obj.get("id")
        return row


@dataclass
class Selector:
    names: set[str]
    prefix: str | None
    exclude: list[str]
    not_found: set[str] = field(default_factory=set)
    excluded: list[str] = field(default_factory=list)

    def picks(self, obj: dict[str, Any]) -> bool:
        name = str(obj.get("name") or "").lower()
        oid = str(obj.get("id") or "").lower()
        if self.names and name not in self.names and oid not in self.names:
            return False
        if self.prefix and not name.startswith(self.prefix):
            return False
        self.not_found -= {name, oid}
        if any(fnmatch.fnmatchcase(name, pat) for pat in self.exclude):
            self.excluded.append(str(obj.get("name")))
            return False
        return True


@dataclass
class Gather:
    app: FmcApp
    domain: str | None
    here: str
    sel: Selector
    unused_only: bool
    warnings: list[str] = field(default_factory=list)
    cands: list[Candidate] = field(default_factory=list)
    usage_budget: int = field(default_factory=lambda: USAGE_CAP)

    async def listing(self, path: str, filters: list[str], cap: int = 20_000) -> list[dict[str, Any]]:
        params = {"filter": ";".join(filters)} if filters else None
        page = await self.app.all(await self.app.config_path(path, self.domain), params, cap=cap)
        if not page.complete:
            self.warnings.append(f"{path} has more items than the first {cap} that were read.")
        return page.items

    async def _blind(self, key: str, filtered: bool) -> bool:
        """The unused filter (which just answered no row) is blind for this type here (FMC 10.0.1's for
        network groups): with a name filter, asked again without it."""
        if key not in BLIND_FILTER_TYPES:
            return False
        return await filter_is_blind(self.app, key, self.domain) if filtered else True

    async def objects(self, types: list[str]) -> None:
        """Value objects and groups: FMC's unused filter says which are free; the usage API names the
        users of the others (so an object used only by other victims can go after them). Where the filter
        is blind (FMC 10.0.1 lists no network group at all) network groups are listed without it and an
        empty usage answer frees them."""
        for key in types:
            t = OBJECT_TYPES[key]
            base = [f"nameOrValue:{self.sel.prefix}"] if self.sel.prefix else []
            blind = False
            if self.unused_only:
                rows = await self.listing(t.path, [*base, "unusedOnly:true"])
                if not rows and await self._blind(key, bool(base)):
                    blind, rows = True, await self.listing(t.path, base)
                hits = [o for o in rows if self.sel.picks(o)]
                free = set() if blind else {str(o.get("id")).lower() for o in hits}
            else:
                hits = [o for o in await self.listing(t.path, base) if self.sel.picks(o)]
                if not hits:
                    continue
                free = {
                    str(o.get("id")).lower() for o in await self.listing(t.path, [*base, "unusedOnly:true"])
                }
                blind = not free and await self._blind(key, bool(base))
            for o in hits:
                c = Candidate("objects", key, o)
                self.cands.append(c)
                if not self._fixed(c) and c.id not in free:
                    await self._users_from_usage(c, t, blind=blind)

    async def _users_from_usage(self, c: Candidate, t: ObjType, *, blind: bool = False) -> None:
        """`blind`: FMC's unused filter lists no group of this type here, so it says nothing about `c`; the
        usage API decides (an empty answer frees it, no answer is unknown, not "in use")."""
        blind_note = f"FMC's unused filter lists no {c.key.replace('_', ' ')} here"
        if self.usage_budget <= 0:
            if blind:
                c.refuse(
                    f"not checked ({blind_note}, and more than {USAGE_CAP} selected objects needed the "
                    "usage API; narrow the selection or check with fmc_where_used)",
                    in_use=False,
                )
                return
            c.refuse(
                f"in use (what uses it was not read: more than {USAGE_CAP} selected objects are in use; "
                "narrow the selection or check with fmc_where_used)"
            )
            return
        self.usage_budget -= 1
        used = await usage_of(self.app, c.obj, t, self.domain)
        if used is None and blind:
            c.refuse(
                f"not checked ({blind_note} and its usage API can't answer for this one; fmc_where_used)",
                in_use=False,
            )
        elif used is None:
            c.refuse("in use (FMC's usage API can't say by what here; fmc_where_used)")
        elif not used and not blind:
            c.refuse("in use (FMC's unused filter says so, its usage API names nothing)")
        for u in used or []:
            label = f"{u.get('type')} {u.get('name')}"
            if u.get("type") == "Device":
                label = f"static routes of device {u.get('id')}"  # usage names a device's route setting
            c.users[str(u.get("id")).lower()] = label

    def _fixed(self, c: Candidate) -> bool:
        """System and inherited objects, and objects the API user's role may not change (readOnly reason
        RBAC, #249), are refused whatever else is selected. The owner domain is checked before FMC's
        read-only flag: in a child domain FMC 10.0.1 marks an ancestor's objects read-only, sometimes without
        a reason, so they would otherwise read as built-ins. FMC's own built-ins (fixed ids,
        is_builtin_object) are said to be built-in there too, not "defined in Global": deleting them in
        Global is refused as well."""
        owner = inherited_from(c.obj, self.here)
        if owner and is_builtin_object(c.obj):
            c.refuse("FMC built-in (system) object, read-only in every domain", in_use=False)
        elif owner:
            c.refuse(f"defined in domain {owner!r} (only inherited here; delete it there)", in_use=False)
        elif c.kind == "policies":
            if c.obj.get("isSystemDefined"):
                c.refuse("system-defined policy", in_use=False)
        elif is_system(c.obj):
            c.refuse("FMC built-in (system) object", in_use=False)
        elif role_read_only(c.obj):
            c.refuse(ROLE_READ_ONLY, in_use=False)
        return c.reason is not None

    async def zones(self) -> list[Candidate]:
        out = []
        for key in ZONE_TYPES:
            for o in await self.listing(OBJECT_TYPES[key].path, [], cap=5000):
                if not self.sel.picks(o):
                    continue
                c = Candidate("zones", key, o)
                if not self._fixed(c) and o.get("interfaces"):
                    names = ", ".join(sorted({ref_label(i) for i in o["interfaces"]}))
                    c.refuse(f"assigned to {len(o['interfaces'])} device interface(s) ({names})")
                out.append(c)
        self.cands += out
        return out

    async def dynamic_objects(self) -> list[Candidate]:
        out = []
        for o in await self.listing(DYNAMIC, [], cap=5000):
            if self.sel.picks(o):
                c = Candidate("dynamic_objects", "dynamic_object", o)
                self._fixed(c)
                out.append(c)
        self.cands += out
        return out

    async def policies(self, kinds: list[str]) -> None:
        targets: dict[str, list[str]] = {}
        loaded = False
        for pk in kinds:
            found = [p for p in await self.listing(POLICY_KINDS[pk], [], cap=2000) if self.sel.picks(p)]
            if not found:
                continue
            if not loaded:
                for a in await policy_assignments(self.app, self.domain):
                    pid = str((a.get("policy") or {}).get("id", "")).lower()
                    targets.setdefault(pid, []).extend(ref_label(t) for t in a.get("targets") or [])
                loaded = True
            links: dict[str, dict[str, str]] = {}
            if pk == "prefilter":  # an access policy that links a prefilter policy keeps it in use
                for acp in await self.listing(ACCESS, [], cap=2000):
                    pf = str((acp.get("prefilterPolicySetting") or {}).get("id", "")).lower()
                    if pf:
                        links.setdefault(pf, {})[str(acp["id"]).lower()] = f"AccessPolicy {acp.get('name')}"
            for p in found:
                c = Candidate("policies", pk, p)
                self.cands.append(c)
                if self._fixed(c):
                    continue
                if targets.get(c.id):
                    c.refuse(f"assigned to {', '.join(sorted(set(targets[c.id])))} (reassign those first)")
                c.users.update(links.get(c.id, {}))

    async def rule_users(self, cands: list[Candidate]) -> None:
        """Access, prefilter and NAT rules that reference zones or dynamic objects (FMC's usage API can't
        tell for these types): one pass over the rules of the first POLICY_CAP policies of each kind."""
        open_ = {c.id: c for c in cands if c.reason is None}
        if not open_:
            return
        for path, sub, label in (
            (ACCESS, "accessrules", "AccessPolicy"),
            (PREFILTER, "prefilterrules", "PrefilterPolicy"),
            (NAT, "natrules", "FTDNatPolicy"),
        ):
            page = await self.app.all(
                await self.app.config_path(path, self.domain), expanded=False, cap=POLICY_CAP
            )
            if not page.complete:
                self.warnings.append(
                    f"Only the rules of the first {POLICY_CAP} {label}s were checked for references to the "
                    "selected zones and dynamic objects; FMC refuses to delete one that is still used."
                )
            for p in page.items:
                rules = await all_rules(
                    self.app, await self.app.config_path(f"{path}/{p['id']}/{sub}", self.domain)
                )
                ids: set[str] = set()
                for r in rules.items:
                    ids |= referenced_ids(r)
                for cid in ids & set(open_):
                    open_[cid].users[str(p["id"]).lower()] = f"{label} {p.get('name')}"


def settle(cands: list[Candidate], unused_only: bool) -> tuple[dict[str, Candidate], list[Candidate], int]:
    """(victims by id, refused, in-use matches skipped by unused_only). A candidate used by anything that
    is not itself a victim is refused; refusals cascade (a group that stays keeps its members in use).
    With unused_only every match in use is skipped (only counted) instead."""
    skipped = 0
    if unused_only:
        keep = []
        for c in cands:
            if c.in_use or (c.reason is None and c.users):
                skipped += 1
            else:
                keep.append(c)
        cands = keep
    victims = {c.id: c for c in cands if c.reason is None}
    changed = True
    while changed:
        changed = False
        for c in list(victims.values()):
            outside = sorted(label for uid, label in c.users.items() if uid not in victims)
            if outside:
                shown = "; ".join(outside[:5]) + (
                    f"; and {len(outside) - 5} more" if len(outside) > 5 else ""
                )
                c.refuse(f"in use by {shown}")
                del victims[c.id]
                changed = True

    def level(c: Candidate, seen: frozenset[str] = frozenset()) -> int:
        users = [victims[u] for u in c.users if u in victims and u not in seen]
        return 0 if not users else 1 + max(level(u, seen | {c.id}) for u in users)

    for c in victims.values():
        c.level = level(c)
    return victims, [c for c in cands if c.id not in victims], skipped


def delete_steps(victims: dict[str, Candidate]) -> list[tuple[int, str, str, list[Candidate]]]:
    """(level, kind, key, candidates) in the order they are deleted: whatever uses another victim first."""
    groups: dict[tuple[int, str, str], list[Candidate]] = {}
    for c in victims.values():
        groups.setdefault((c.level, c.kind, c.key), []).append(c)
    order = sorted(groups, key=lambda k: (k[0], KIND_ORDER[k[1]], k[2]))
    return [
        (lvl, kind, key, sorted(groups[(lvl, kind, key)], key=lambda c: c.name)) for lvl, kind, key in order
    ]


def _collection(kind: str, key: str) -> str:
    return POLICY_KINDS[key] if kind == "policies" else obj_type(key).path


def _requests(steps: list[tuple[int, str, str, list[Candidate]]]) -> int:
    return sum(
        -(-len(cs) // CHUNK) if kind in ("objects", "dynamic_objects") else len(cs)
        for _, kind, _, cs in steps
    )


# --- replace everywhere ---------------------------------------------------------------------------

Scope = Literal["access_rules", "prefilter_rules", "groups", "nat_rules", "static_routes"]


def nat_where(policy: str, row: dict[str, Any]) -> str:
    """A NAT rule for the replace preview: a manual rule by index and section, an auto NAT rule (no index:
    FMC keeps one per object) by the object it translates: 'mcp-w6-nat auto NAT of mcp-w6-a (DYNAMIC)'."""
    if row.get("kind") == "auto":
        nat_type = f" ({row['nat_type']})" if row.get("nat_type") else ""
        return f"{policy} auto NAT of {row.get('original_source') or '?'}{nat_type}"
    index = f" #{row['index']}" if row.get("index") is not None else ""
    section = f" ({str(row['section']).lower()})" if row.get("section") else ""
    return f"{policy} manual NAT{index}{section}"


SCOPES: tuple[str, ...] = get_args(Scope)  # also the order the changes are applied in
REPLACEABLE = (
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
)
GROUP_TYPES = {"network": "network_group", "port": "port_group", "url": "url_group", "vlan": "vlan_group"}
ROUTE_TYPES = {"Host", "Network", "NetworkGroup"}  # what a static route's networks take
USAGE_AREAS = {
    "accesspolicy": "access_rules",
    "prefilterpolicy": "prefilter_rules",
    "ftdnatpolicy": "nat_rules",
}
VRF = re.compile(r"virtual router\s+(.+?)\s*$", re.IGNORECASE)
RULE_CHUNK = 100  # access rules per bulk partial PUT (FMC applies a batch atomically)
NAT_PORT_TYPES = {"ProtocolPortObject"}  # NAT port fields take one TCP/UDP port object (IProtocolPortObject)
MAX_SITES = 300


def swap(node: Any, old_id: str, new_ref: dict[str, Any]) -> tuple[Any, int]:
    """A copy of `node` with every reference to `old_id` replaced by `new_ref` (lists keep one entry per
    id, so a block that already names the new object just loses the old one), and how many were swapped."""
    if isinstance(node, dict):
        if str(node.get("id", "")).lower() == old_id:
            return dict(new_ref), 1
        out: dict[str, Any] = {}
        count = 0
        for k, v in node.items():
            if k in ("metadata", "links"):
                out[k] = v
                continue
            out[k], n = swap(v, old_id, new_ref)
            count += n
        return out, count
    if isinstance(node, list):
        items: list[Any] = []
        seen: set[str] = set()
        count = 0
        for v in node:
            nv, n = swap(v, old_id, new_ref)
            count += n
            key = str(nv.get("id")).lower() if isinstance(nv, dict) and nv.get("id") else None
            if key is not None:
                if key in seen:
                    continue
                seen.add(key)
            items.append(nv)
        return items, count
    return node, 0


@dataclass
class Site:
    area: str
    where: str
    path: str  # where the item is PUT
    item: dict[str, Any]  # as read (metadata included: the owner domain)
    desired: dict[str, Any]
    fields: list[str]
    bulk: str | None = None  # access rules: the collection they are bulk-PUT to

    def row(self) -> dict[str, Any]:
        return {"where": self.where, "fields": self.fields}

    def partial(self) -> dict[str, Any]:
        """The bulk partial-update body: id, type and only the condition blocks that change (whole blocks,
        literals included), so FMC keeps every other field and the rule's position."""
        return {
            "id": self.item["id"],
            "type": self.item.get("type") or "AccessRule",
            **{k: self.desired[k] for k in self.fields},
        }


ACP_OF_PATH = re.compile(r"/policy/accesspolicies/([^/]+)/accessrules", re.IGNORECASE)


def access_policies_of(sites: list[Site]) -> list[dict[str, Any]]:
    """The access policies whose rules the sites change ({id, name}), for the preview's lock check (F76)."""
    out: dict[str, dict[str, Any]] = {}
    for s in sites:
        if s.area != "access_rules":
            continue
        ref = (s.item.get("metadata") or {}).get("accessPolicy") or {}
        m = ACP_OF_PATH.search(s.bulk or s.path)
        pid = ref.get("id") or (m.group(1) if m else None)
        if pid:
            out.setdefault(str(pid).lower(), {"id": pid, "name": ref.get("name")})
    return list(out.values())


def make_site(
    area: str, where: str, path: str, item: dict[str, Any], old_id: str, new_ref: dict[str, Any], **kw: Any
) -> Site | None:
    body = {k: v for k, v in editable(item).items() if k != "commentHistoryList"}  # comments are append-only
    desired: dict[str, Any] = {}
    fields = []
    for k, v in body.items():
        if k == "id":
            desired[k] = v
            continue
        desired[k], n = swap(v, old_id, new_ref)
        if n:
            fields.append(k)
    return Site(area, where, path, item, desired, fields, **kw) if fields else None


@dataclass
class Walk:
    app: FmcApp
    domain: str | None
    here: str
    old: dict[str, Any]
    new_ref: dict[str, Any]
    scope: set[str]
    sites: list[Site] = field(default_factory=list)
    not_changed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    complete: bool = True
    holders: set[str] = field(default_factory=set)  # groups that hold the old object, nested ones too

    @property
    def old_id(self) -> str:
        return str(self.old["id"]).lower()

    def covered(self, ids: set[str]) -> bool:
        """True when a container references the old object itself, or a group holding it that is changed."""
        return bool(ids & ({self.old_id} | (self.holders if "groups" in self.scope else set())))

    async def capped(self, path: str, label: str, cap: int, expanded: bool = False) -> list[dict[str, Any]]:
        page = await self.app.all(await self.app.config_path(path, self.domain), expanded=expanded, cap=cap)
        if not page.complete:
            self.complete = False
            self.warnings.append(f"Only the first {cap} {label} were searched.")
        return page.items

    async def rules(self, path: str, label: str) -> Page | None:
        """A policy's rules, or None (noted) when the policy isn't readable here: FMC's usage API in an
        ancestor domain also names a descendant domain's policies, whose rules only that domain serves."""
        try:
            return await all_rules(self.app, path)
        except NotFound:
            self.not_changed.append(f"{label} (in another domain: repeat there)")
            return None

    async def groups(self, family: str) -> None:
        key = GROUP_TYPES.get(family)
        if key is None:
            return
        t = OBJECT_TYPES[key]
        page = await self.app.all(await self.app.config_path(t.path, self.domain), cap=20_000)
        if not page.complete:
            self.complete = False
            self.warnings.append(f"Only the first 20000 {key} objects were searched.")
        members = {str(g["id"]).lower(): referenced_ids(g) for g in page.items if g.get("id")}
        frontier = {self.old_id}
        while frontier:  # groups holding the old object, then the groups holding those, ...
            frontier = {gid for gid, ids in members.items() if ids & frontier} - self.holders
            self.holders |= frontier
        if "groups" not in self.scope:
            return
        for g in page.items:
            path = await self.app.config_path(f"{t.path}/{g['id']}", self.domain)
            site = make_site("groups", f"{g.get('type')} {g.get('name')}", path, g, self.old_id, self.new_ref)
            if site:
                self.sites.append(site)

    async def access_rules(self, policies: dict[str, str], from_usage: bool) -> None:
        for pid, pname in policies.items():
            base = await self.app.config_path(f"{ACCESS}/{pid}/accessrules", self.domain)
            rules = await self.rules(base, f"access policy {pname!r}")
            if rules is None:
                continue
            refs: set[str] = set()
            for r in rules.items:
                refs |= referenced_ids(r)
                idx = (r.get("metadata") or {}).get("ruleIndex")
                where = f"{pname} #{idx} {r.get('name')}" if idx is not None else f"{pname}: {r.get('name')}"
                site = make_site(
                    "access_rules", where, f"{base}/{r['id']}", r, self.old_id, self.new_ref, bulk=base
                )
                if site:
                    self.sites.append(site)
            if from_usage and not self.covered(refs):
                self.not_changed.append(
                    f"access policy {pname!r} (outside its rules, e.g. Security Intelligence, "
                    "or through a group not changed)"
                )

    async def prefilter_rules(self, policies: dict[str, str], from_usage: bool) -> None:
        for pid, pname in policies.items():
            base = await self.app.config_path(f"{PREFILTER}/{pid}/prefilterrules", self.domain)
            rules = await self.rules(base, f"prefilter policy {pname!r}")
            if rules is None:
                continue
            refs: set[str] = set()
            for r in rules.items:
                refs |= referenced_ids(r)
                idx = (r.get("metadata") or {}).get("ruleIndex")
                where = f"{pname} #{idx} {r.get('name')}" if idx is not None else f"{pname}: {r.get('name')}"
                site = make_site("prefilter_rules", where, f"{base}/{r['id']}", r, self.old_id, self.new_ref)
                if site:
                    self.sites.append(site)
            if from_usage and not self.covered(refs):
                self.not_changed.append(
                    f"prefilter policy {pname!r} (outside its rules or through a group not changed)"
                )

    async def nat_rules(self, policies: dict[str, str], from_usage: bool) -> None:
        for pid, pname in policies.items():
            rules = await self.rules(
                await self.app.config_path(f"{NAT}/{pid}/natrules", self.domain), f"NAT policy {pname!r}"
            )
            if rules is None:
                continue
            refs: set[str] = set()
            for r in rules.items:
                refs |= referenced_ids(r)
                if self.old_id not in referenced_ids(r):
                    continue
                sub = "autonatrules" if r.get("type") == "FTDAutoNatRule" else "manualnatrules"
                path = await self.app.config_path(f"{NAT}/{pid}/{sub}/{r['id']}", self.domain)
                # PUT back what the typed endpoint returns, not the natrules aggregate's row
                full: dict[str, Any] = await self.app.api.get(path)
                where = nat_where(pname, flatten_nat_rule(full))
                site = make_site(
                    "nat_rules", re.sub(r"\s+", " ", where), path, full, self.old_id, self.new_ref
                )
                if site:
                    self.sites.append(site)
            if from_usage and not self.covered(refs):
                self.not_changed.append(
                    f"NAT policy {pname!r} (outside its rules or through a group not changed)"
                )

    async def static_routes(self, devices: dict[str, str], from_usage: bool) -> None:
        for did, dname in devices.items():
            refs: set[str] = set()
            for sub in ("ipv4staticroutes", "ipv6staticroutes"):
                base = await self.app.config_path(f"{DEVICES}/{did}/routing/{sub}", self.domain)
                try:
                    page = await self.app.all(base, cap=5000)
                except UpstreamError as e:
                    if e.status_code in (404, 405):
                        continue
                    raise
                for r in page.items:
                    refs |= referenced_ids(r)
                    nets = ", ".join(ref_label(n) for n in r.get("selectedNetworks") or [])
                    gw = r.get("gateway") or {}
                    via = ref_label(gw.get("object") or gw.get("literal") or {})
                    where = f"{dname}: {nets} via {via} on {r.get('interfaceName')}"
                    site = make_site(
                        "static_routes", where, f"{base}/{r['id']}", r, self.old_id, self.new_ref
                    )
                    if site:
                        self.sites.append(site)
            if from_usage and not self.covered(refs):
                self.not_changed.append(f"device {dname!r} (static routes or other device settings)")

    async def run(self, family: str, used: list[dict[str, Any]] | None) -> None:
        """Rules and groups first, NAT and static routes second; containers from FMC's usage API when it
        answers, otherwise every policy (POLICY_CAP per kind) and device (DEVICE_CAP)."""
        await self.groups(family)
        from_usage = used is not None
        found: dict[str, dict[str, str]] = {a: {} for a in SCOPES}
        if used is not None:
            for u in used:
                uid, utype, uname = str(u.get("id") or ""), str(u.get("type") or ""), str(u.get("name") or "")
                area = USAGE_AREAS.get(utype.lower())
                if utype == "Device" and "static route" in uname.lower():
                    vrf = VRF.search(uname)
                    if vrf and vrf.group(1).lower() != "global":
                        self.not_changed.append(
                            f"static routes in virtual router {vrf.group(1)!r} of device {uid}"
                        )
                        continue
                    area = "static_routes"
                if area is None:
                    if uid.lower() not in self.holders:
                        self.not_changed.append(f"{utype} {uname}".strip())
                    elif "groups" not in self.scope:
                        self.not_changed.append(f"group {uname} (groups not in scope)")
                    continue
                if area not in self.scope:
                    self.not_changed.append(f"{utype} {uname} ({area} not in scope)")
                    continue
                found[area][uid] = uname
        else:
            for area, path, label in (
                ("access_rules", ACCESS, "access policies"),
                ("prefilter_rules", PREFILTER, "prefilter policies"),
                ("nat_rules", NAT, "NAT policies"),
            ):
                if area in self.scope:
                    found[area] = {
                        p["id"]: str(p.get("name")) for p in await self.capped(path, label, POLICY_CAP)
                    }
        if "access_rules" in self.scope:
            await self.access_rules(found["access_rules"], from_usage)
        if "prefilter_rules" in self.scope:
            await self.prefilter_rules(found["prefilter_rules"], from_usage)
        if "nat_rules" in self.scope:
            await self.nat_rules(found["nat_rules"], from_usage)
        if (
            "static_routes" in self.scope
            and family == "network"
            and (found["static_routes"] or not from_usage)
        ):
            listed = await self.capped(DEVICES, "devices", DEVICE_CAP, expanded=True)
            names = {str(d["id"]): str(d.get("name")) for d in listed}
            devices = {d: names.get(d, d) for d in found["static_routes"]} if from_usage else names
            await self.static_routes(devices, from_usage)


def site_blockers(walk: Walk, new: dict[str, Any]) -> list[str]:
    out = []
    new_type = str(new.get("type"))
    for s in walk.sites:
        owner = inherited_from(s.item, walk.here)
        if owner:
            out.append(f"{s.where} is defined in domain {owner!r}; FMC changes it only there.")
        if s.area == "nat_rules":
            ports = [f for f in s.fields if f.endswith("Port")]
            if ports and new_type not in NAT_PORT_TYPES:
                out.append(
                    f"{s.where}: NAT {', '.join(ports)} take one TCP/UDP port object, not a {new_type}."
                )
        if s.area == "static_routes":
            if "gateway" in s.fields and new_type != "Host":
                out.append(f"{s.where}: a static route's gateway must be a host object, not a {new_type}.")
            if "selectedNetworks" in s.fields and new_type not in ROUTE_TYPES:
                out.append(f"{s.where}: static route networks take hosts, networks or network groups.")
    if str(new["id"]).lower() in walk.holders:
        out.append(
            f"{new.get('name')!r} holds {walk.old.get('name')!r} (directly or through a nested group): "
            "putting it in place of the old object would make a group contain itself."
        )
    return out


# --- tools ----------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Delete objects in bulk")
    async def fmc_delete_objects(
        ctx: Context,
        names: Annotated[
            list[str] | None,
            Field(description="Exact names or UUIDs to delete (any of the selected kinds and types)"),
        ] = None,
        prefix: Annotated[
            str | None,
            Field(description=f"Every object whose name starts with this (at least {MIN_PREFIX} characters)"),
        ] = None,
        unused_only: Annotated[
            bool,
            Field(
                description="Only what nothing references (FMC's unused filter; network groups: FMC's usage "
                "API when the filter lists none at all, as FMC 10.0.1's does); alone, every unused object of "
                "the selected types. In-use matches are then skipped (counted), not refused"
            ),
        ] = False,
        kinds: Annotated[
            list[Kind] | None,
            Field(
                description="What to look at: objects (value objects and groups), zones (security zones, "
                "interface groups), dynamic_objects, policies (default: objects)"
            ),
        ] = None,
        types: Annotated[
            list[ObjectTypeName] | None,
            Field(description="Object types for kind 'objects' (default: every type FMC bulk-deletes)"),
        ] = None,
        policy_kinds: Annotated[
            list[DeletePolicyKind] | None,
            Field(
                description="Policy kinds for kind 'policies' (default: access, nat, prefilter, "
                "platform_settings)"
            ),
        ] = None,
        exclude: Annotated[
            list[str] | None,
            Field(description="Names or shell patterns to keep, e.g. ['mcp-demo-seed-*'] (case-insensitive)"),
        ] = None,
        dry_run: Annotated[
            bool, Field(description="Only show what would be deleted (no confirm token is issued)")
        ] = False,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete many objects in one preview and one confirm: by names, by a name prefix (a demo or PoC
        reset) or every unused object (cleanup), across network/port/URL/VLAN objects and groups, security
        zones and interface groups, dynamic objects (with their mappings) and access, NAT, prefilter and
        platform-settings policies. The preview lists the exact victims per kind and refuses, with the
        reason, FMC's built-in objects, objects an ancestor domain owns, policies assigned to devices,
        zones on interfaces and anything still used by something that is not deleted too (what uses it is
        named; an object used only by other victims is deleted after them). Deleted with FMC's bulk
        DELETE per type, 50 per request; stops at the first failure and says what was deleted.
        Irreversible: fmc_export_policy_bundle first keeps a copy. One object: fmc_delete_object."""
        app: FmcApp = get_client(ctx)
        if names and prefix:
            raise InvalidRequest("Pass names or prefix, not both.")
        pre = (prefix or "").strip().lower() or None
        if prefix is not None and (pre is None or len(pre) < MIN_PREFIX):
            raise InvalidRequest(f"prefix needs at least {MIN_PREFIX} characters.")
        wanted = {n.strip().lower() for n in names or [] if n.strip()}
        if not (wanted or pre or unused_only):
            raise InvalidRequest("Select what to delete: names, prefix or unused_only=true.")
        if dry_run and confirm:
            raise InvalidRequest(
                "A dry run never applies; call again without dry_run to get a confirm token."
            )
        chosen = list(dict.fromkeys(kinds or ["objects"]))
        bad = [t for t in types or [] if t not in BULK_TYPES]
        if bad:
            raise InvalidRequest(
                f"Not deletable here: {', '.join(bad)}. Types: {', '.join(BULK_TYPES)}; zones and dynamic "
                "objects are kinds of their own."
            )
        here = (await app.domain_uuid(domain)).lower()
        sel = Selector(wanted, pre, [p.strip().lower() for p in exclude or [] if p.strip()], set(wanted))
        g = Gather(app, domain, here, sel, unused_only)
        if "policies" in chosen:
            await g.policies(list(dict.fromkeys(policy_kinds or DELETE_POLICY_KINDS)))
        if "objects" in chosen:
            await g.objects(list(dict.fromkeys(types or BULK_TYPES)))
        scan: list[Candidate] = []
        if "zones" in chosen:
            scan += await g.zones()
        if "dynamic_objects" in chosen:
            scan += await g.dynamic_objects()
        await g.rule_users(scan)

        victims, refused, skipped = settle(g.cands, unused_only)
        steps = delete_steps(victims)
        by_kind: dict[str, list[dict[str, Any]]] = {}
        for _, kind, _, cs in steps:
            for c in cs:
                row = c.row()
                after = sorted(victims[u].name for u in c.users if u in victims)
                if after:
                    row["after"] = after
                by_kind.setdefault(kind, []).append(row)
        reasons: dict[str, int] = {}
        for c in refused:
            label = (c.reason or "").split(" (")[0].split(" by ")[0]
            reasons[label] = reasons.get(label, 0) + 1
        details: dict[str, Any] = {
            "delete": by_kind,
            "counts": {k: len(v) for k, v in by_kind.items()},
            "order": [
                f"{len(cs)} {key}" + (" (bulk)" if kind in ("objects", "dynamic_objects") else "")
                for _, kind, key, cs in steps
            ],
            "requests": _requests(steps),
        }
        if refused:
            details["refused"] = [
                {**c.row(), "kind": c.kind, "reason": c.reason} for c in refused[:REFUSED_SHOWN]
            ]
            details["refused_counts"] = reasons
            if len(refused) > REFUSED_SHOWN:
                details["refused_note"] = f"{len(refused) - REFUSED_SHOWN} more refused rows not shown."
        if skipped:
            details["in_use_skipped"] = skipped
        if sel.excluded:
            details["excluded"] = sorted(sel.excluded)
        if sel.not_found:
            details["not_found"] = sorted(sel.not_found)
        if g.warnings:
            details["warnings"] = list(dict.fromkeys(g.warnings))
        blockers = []
        if not victims:
            blockers.append(
                "Nothing to delete" + (": every match is refused (see refused)." if refused else ".")
            )
        if len(victims) > MAX_VICTIMS:
            blockers.append(f"{len(victims)} objects selected; at most {MAX_VICTIMS} per call (narrow it).")
        side = ["Irreversible: the objects are gone (fmc_export_policy_bundle keeps a copy first)."]
        if "dynamic_objects" in by_kind:
            side.append("A deleted dynamic object's IP mappings are deleted with it.")
        if "policies" in by_kind:
            side.append("A deleted policy's rules are deleted with it.")
        plan = Plan(
            f"Delete {len(victims)} object(s) in {details['requests']} request(s)",
            details=details,
            fingerprint={
                "victims": sorted((c.kind, c.key, c.id, c.level) for c in victims.values()),
                "refused": sorted((c.kind, c.id) for c in refused),
            },
            blockers=blockers,
            side_effects=side,
            blast_radius=len(victims),
        )
        if dry_run:
            out: dict[str, Any] = {
                "status": "dry_run",
                "action": plan.summary,
                "preview": {"domain": await app.domain_name(here), **plan.details},
                "note": "Dry run: nothing was changed and no confirm token was issued.",
            }
            if blockers:
                out["blockers"] = blockers
            return out

        async def apply() -> Any:
            total = len(victims)
            done: list[str] = []
            try:
                for _, kind, key, cs in steps:
                    path = await app.config_path(_collection(kind, key), domain)
                    if kind in ("objects", "dynamic_objects"):
                        for chunk in chunks(cs, CHUNK):
                            ids = ",".join(str(c.obj["id"]) for c in chunk)
                            try:
                                await app.api.delete(path, params={"bulk": "true", "filter": f"ids:{ids}"})
                            except UpstreamError as e:
                                raise _stopped(
                                    done, total, f"the {key} batch starting at {chunk[0].name!r}", e
                                ) from e
                            done += [c.name for c in chunk]
                        continue
                    for c in cs:
                        try:
                            await app.api.delete(f"{path}/{c.obj['id']}")
                        except UpstreamError as e:
                            raise _stopped(done, total, f"{key} {c.name!r}", e) from e
                        done.append(c.name)
            finally:
                app.invalidate_cache()
            return {
                "deleted": len(done),
                "by_kind": {k: len(v) for k, v in by_kind.items()},
                "next": "fmc_unused_objects shows what is left; fmc_pending_changes before a deploy",
            }

        return await fmc_preview(
            ctx,
            tool="fmc_delete_objects",
            args={
                "names": names,
                "prefix": prefix,
                "unused_only": unused_only,
                "kinds": kinds,
                "types": types,
                "policy_kinds": policy_kinds,
                "exclude": exclude,
                "dry_run": dry_run,
                "domain": domain,
            },
            confirm=confirm,
            plan=plan,
            apply=apply,
        )

    @reg.write(title="Replace an object everywhere", destructive=True)
    async def fmc_replace_object(
        ctx: Context,
        old: Annotated[str, Field(description="The object to replace (name or UUID)")],
        new: Annotated[str, Field(description="The object to use instead (name or UUID, same family)")],
        type: Annotated[
            ObjectTypeName | None,
            Field(
                description="Type of the old object (needed for dynamic objects; default: search common "
                "types)"
            ),
        ] = None,
        scope: Annotated[
            list[Scope] | None,
            Field(
                description="Where to replace it (default all): access_rules, prefilter_rules, groups, "
                "nat_rules, static_routes"
            ),
        ] = None,
        delete_old: Annotated[
            bool, Field(description="Delete the old object once nothing references it any more")
        ] = False,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Replace one object with another everywhere it is referenced: access and prefilter rule
        conditions, the network/port/URL/VLAN groups that hold it, NAT rules (original and translated
        source, destination and ports) and static routes (networks, gateway), then optionally delete the
        old object. The two must be of one family (a host can become a network, range or group, a port a
        port group, a zone an interface group). FMC's usage API names what references the old object, so
        only those policies and devices are read; where it can't tell (zones, dynamic objects, an object
        the domain only inherits) the first 25 policies per kind and 30 devices are searched. The preview
        lists every rule, group, NAT rule and route with the fields that change, and what references the
        old object outside the scope (VPN, Security Intelligence, other policy types), which keeps
        delete_old from running; for a zone, so do the device interfaces still in it (they stay in the old
        zone: move them with fmc_update_interface). Applied rules and groups first (access rules as bulk
        partial updates, 100 per request), then NAT rules and static routes; stops at the first failure.
        Takes effect after a deploy."""
        app: FmcApp = get_client(ctx)
        if type is not None and type not in REPLACEABLE:
            raise InvalidRequest(f"{type} objects can't be replaced here; types: {', '.join(REPLACEABLE)}.")
        t_old, cur_old = await resolve_object(app, old, domain, [type] if type else None)
        if t_old.key not in REPLACEABLE:
            raise InvalidRequest(f"{t_old.key} objects can't be replaced here.")
        same = (
            [t_old.key]
            if t_old.family == "other"
            else [k for k in REPLACEABLE if OBJECT_TYPES[k].family == t_old.family]
        )
        try:
            t_new, cur_new = await resolve_object(app, new, domain, same)
        except NotFound:
            raise InvalidRequest(
                f"No {' / '.join(same)} object {new!r}: the new object must be of the same family as "
                f"{cur_old.get('name')!r} ({t_old.key})."
            ) from None
        if str(cur_new["id"]).lower() == str(cur_old["id"]).lower():
            raise InvalidRequest("old and new are the same object.")
        here = (await app.domain_uuid(domain)).lower()
        wanted = set(scope or SCOPES)
        used = await usage_of(app, cur_old, t_old, domain)
        walk = Walk(app, domain, here, cur_old, ref_of(cur_new), wanted)
        await walk.run(t_old.family, used)
        ifs = (cur_old.get("interfaces") or []) if t_old.family == "zone" else []
        if ifs:  # interface membership is set on the interface, not in the zone (fmc_update_interface)
            shown = ", ".join(sorted({ref_label(i) for i in ifs})[:10])
            walk.not_changed.append(
                f"{len(ifs)} device interface(s) in {t_old.key} {cur_old.get('name')!r} ({shown}): they stay "
                "in it, so rules that now name the new one don't match their traffic until "
                "fmc_update_interface moves them"
            )

        changes: dict[str, list[dict[str, Any]]] = {}
        for s in walk.sites:
            changes.setdefault(s.area, []).append(s.row())
        rule_puts = sum(-(-len(ss) // RULE_CHUNK) for ss in _per_bulk(walk.sites).values())
        writes = rule_puts + sum(1 for s in walk.sites if s.bulk is None) + (1 if delete_old else 0)
        details: dict[str, Any] = {
            "old": {**_brief(cur_old), "object_type": t_old.key},
            "new": {**_brief(cur_new), "object_type": t_new.key},
            "changes": changes,
            "counts": {a: len(v) for a, v in changes.items()},
            "found_by": "FMC's usage API"
            if used is not None
            else ("a search of every policy and device (FMC's usage API can't report this object here)"),
            "write_requests": writes,
        }
        not_changed = list(dict.fromkeys(walk.not_changed))
        if not_changed:
            details["not_changed"] = not_changed
        if walk.warnings:
            details["warnings"] = list(dict.fromkeys(walk.warnings))
        blockers = site_blockers(walk, cur_new)
        if len(walk.sites) > MAX_SITES:
            blockers.append(
                f"{len(walk.sites)} places to change; at most {MAX_SITES} per call (narrow scope)."
            )
        if delete_old:
            details["delete_old"] = True
            if is_system(cur_old):
                blockers.append("delete_old: the old object is an FMC built-in and can't be deleted.")
            elif role_read_only(cur_old):
                blockers.append(f"delete_old: the old object is {ROLE_READ_ONLY}.")
            owner = inherited_from(cur_old, here)
            if owner:
                blockers.append(
                    f"delete_old: the old object is defined in domain {owner!r}; delete it there."
                )
            if not_changed:
                blockers.append(
                    "delete_old: the old object stays referenced (see not_changed); drop delete_old or fix "
                    "those references first."
                )
            if not walk.complete:
                blockers.append("delete_old: not every policy or device was searched (see warnings).")
        if not walk.sites and not delete_old:
            blockers.append(
                f"Nothing in the scope references {cur_old.get('name')!r}"
                + ("; see not_changed." if not_changed else ".")
            )
        old_path = await app.config_path(f"{t_old.path}/{cur_old['id']}", domain)

        async def apply() -> Any:
            done: dict[str, int] = {}
            total = len(walk.sites)
            result: dict[str, Any] = {}
            try:
                for area in SCOPES:
                    area_sites = [s for s in walk.sites if s.area == area]
                    batches = (
                        [cs for ss in _per_bulk(area_sites).values() for cs in chunks(ss, RULE_CHUNK)]
                        if area == "access_rules"
                        else [[s] for s in area_sites]
                    )
                    for batch in batches:
                        try:
                            if batch[0].bulk:
                                await app.api.put(
                                    batch[0].bulk,
                                    [s.partial() for s in batch],
                                    params={"bulk": "true", "partialUpdate": "true"},
                                )
                            else:
                                await app.api.put(batch[0].path, batch[0].desired)
                        except UpstreamError as e:
                            what = batch[0].where + (
                                f" (+{len(batch) - 1} more rules)" if len(batch) > 1 else ""
                            )
                            n = sum(done.values())
                            raise UpstreamError(
                                f"Replace stopped after {n} of {total} changes ({_summary(done)}): {what} "
                                f"failed: {e}. Nothing after it was attempted"
                                + (" and the old object was not deleted" if delete_old else "")
                                + ". Preview again to see what still references it.",
                                getattr(e, "status_code", None),
                            ) from e
                        done[area] = done.get(area, 0) + len(batch)
                result["replaced"] = done or None
                if delete_old:
                    try:
                        await app.api.delete(old_path)
                        result["old_deleted"] = True
                    except UpstreamError as e:
                        result["old_deleted"] = False
                        result["warning"] = (
                            f"Every reference was replaced, but FMC refused to delete the old object: {e}"
                        )
            finally:
                app.invalidate_cache()
            result["next"] = "fmc_pending_changes, then fmc_deploy to the devices of the changed policies"
            return result

        return await fmc_preview(
            ctx,
            tool="fmc_replace_object",
            owned=[cur_old] if delete_old else [],
            lock_refs=access_policies_of(walk.sites),  # another user's lock on one of them blocks
            args={
                "old": old,
                "new": new,
                "type": type,
                "scope": scope,
                "delete_old": delete_old,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Replace {cur_old.get('name')!r} with {cur_new.get('name')!r} in {len(walk.sites)} place(s)"
                + (" and delete it" if delete_old else ""),
                details=details,
                fingerprint={
                    "old": editable(cur_old),
                    "new": [cur_new.get("id"), cur_new.get("type")],
                    "sites": [[s.area, s.path, editable(s.item)] for s in walk.sites],
                    "not_changed": not_changed,
                },
                blockers=blockers,
                side_effects=["Takes effect on devices after the next deployment (fmc_pending_changes)."],
                blast_radius=len(walk.sites) + (1 if delete_old else 0),
            ),
            apply=apply,
        )


def _per_bulk(sites: list[Site]) -> dict[str, list[Site]]:
    out: dict[str, list[Site]] = {}
    for s in sites:
        if s.bulk:
            out.setdefault(s.bulk, []).append(s)
    return out


def _brief(obj: dict[str, Any]) -> dict[str, Any]:
    s = object_summary(obj)
    return {k: s[k] for k in ("name", "type", "value", "members", "id") if s.get(k) not in (None, [])}


def _summary(done: dict[str, int]) -> str:
    return ", ".join(f"{n} {a}" for a, n in done.items()) or "none"


def _stopped(done: list[str], total: int, what: str, e: UpstreamError) -> UpstreamError:
    shown = ", ".join(done[:20]) + (f" and {len(done) - 20} more" if len(done) > 20 else "")
    return UpstreamError(
        f"Delete stopped after {len(done)} of {total}: {what} failed: {e}. "
        + (f"Deleted: {shown}. " if done else "Nothing was deleted. ")
        + "Preview again to see what is left.",
        getattr(e, "status_code", None),
    )

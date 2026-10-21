"""Access policy structure reads (F76): locks, categories and inheritance, shared by the preview wrapper,
fmc_get_access_policy, fmc_pending_changes and the structure tools (tools/policy_structure.py).

Locks: FMC (7.6+) lets a user lock an access policy so nobody else can change it
(`policy/operational/policylocks`, access policies only). Every expanded access policy carries the state in
`metadata.lockingStatus` (FMC 10.0.1, recorded live: {status: LOCKED, metadata: {lockedByUser: {name}}}; the
spec documents {status, userName, ticketId, ticketName}), so a preview names the holder without an extra
request; the lock list is read only when a locked policy doesn't name its holder,
and by the tools that report locks (fmc_policy_lock, fmc_pending_changes). With nothing locked FMC 10.0.1
answers the list with one empty item.

Inheritance: every access policy has one inheritance setting whose id is the policy's own id; a base policy
is its `basePolicy` reference (no key when there is none). Categories: policy/accesspolicies/{id}/categories,
each with metadata.section and the start/end rule index.

Kept free of tool-module imports: fmc_mcp.preview uses it for every write preview."""

from __future__ import annotations

from typing import Any

from fmc_mcp._core import NotFound, UpstreamError
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.tools.common import pick_by_name

ACCESS = "policy/accesspolicies"
LOCKS = "policy/operational/policylocks"
ACCESS_TYPES = {"AccessPolicy"}
SECTIONS = ("mandatory", "default")
CHAIN_LIMIT = 10  # inheritance levels walked (FMC allows a handful; a loop is cut here too)


def is_access_policy(obj: dict[str, Any] | None) -> bool:
    return isinstance(obj, dict) and obj.get("type") in ACCESS_TYPES and bool(obj.get("id"))


def lock_state(obj: dict[str, Any] | None) -> dict[str, Any] | None:
    """{status, locked_by?, ticket?} from an access policy's metadata.lockingStatus; None when FMC sent none
    (an older FMC, or a reference instead of the policy)."""
    ls = ((obj or {}).get("metadata") or {}).get("lockingStatus")
    if not isinstance(ls, dict) or not ls.get("status"):
        return None
    out: dict[str, Any] = {"status": str(ls["status"]).upper()}
    # FMC 10.0.1 nests the holder as lockingStatus.metadata.lockedByUser.name (live); the spec says userName
    user = (
        ls.get("userName")
        or (ls.get("lockedByUser") or {}).get("name")
        or ((ls.get("metadata") or {}).get("lockedByUser") or {}).get("name")
    )
    if user:
        out["locked_by"] = str(user)
    ticket = ls.get("ticketName") or ls.get("ticketId")
    if ticket not in (None, "", 0):
        out["ticket"] = str(ticket)
    return out


def lock_row(entry: dict[str, Any]) -> dict[str, Any]:
    """One `policies[]` entry of the policylocks answer as {policy, policy_id, status, locked_by?}."""
    pol = entry.get("policy") or {}
    meta = entry.get("metadata") or {}
    row: dict[str, Any] = {
        "policy": pol.get("name"),
        "policy_id": pol.get("id"),
        "status": str(entry.get("status") or ("LOCKED" if meta.get("isLocked") else "UNLOCKED")).upper(),
    }
    user = (meta.get("lockedByUser") or {}).get("name")
    if user:
        row["locked_by"] = str(user)
    return row


async def read_locks(app: FmcApp, domain: str | None) -> list[dict[str, Any]] | None:
    """Every lock entry FMC lists in the domain (lock_row rows; FMC may list unlocked policies too), or None
    when the lock list can't be read (FMC before 7.6, a role without the permission)."""
    try:
        page = await app.all(await app.config_path(LOCKS, domain), cap=5000)
    except UpstreamError:
        return None
    rows: list[dict[str, Any]] = []
    for item in page.items:
        if not isinstance(item, dict):
            continue
        # FMC 10.0.1 answers {items: [{}], count 1} when nothing is locked: an empty item is no lock
        entries = item.get("policies") if "policies" in item else [item] if item.get("policy") else []
        rows.extend(lock_row(e) for e in entries or [] if isinstance(e, dict) and e.get("policy"))
    return rows


def locked(rows: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [r for r in rows or [] if r.get("status") == "LOCKED"]


def same_user(a: str | None, b: str | None) -> bool:
    return bool(a and b and a.strip().lower() == b.strip().lower())


async def holder(app: FmcApp, acp: dict[str, Any], domain: str | None) -> dict[str, Any] | None:
    """The policy's lock state, with the holder looked up in the lock list when the policy says LOCKED but
    names nobody. None when FMC reports no lock state at all."""
    state = lock_state(acp)
    if state is None or state["status"] != "LOCKED" or state.get("locked_by"):
        return state
    for row in locked(await read_locks(app, domain)):
        if str(row.get("policy_id", "")).lower() == str(acp.get("id", "")).lower() and row.get("locked_by"):
            return {**state, "locked_by": row["locked_by"]}
    return state


def describe(name: str, state: dict[str, Any], me: str | None) -> str:
    who = state.get("locked_by") or "another user (FMC doesn't say who)"
    ticket = f" under ticket {state['ticket']!r}" if state.get("ticket") else ""
    if same_user(state.get("locked_by"), me):
        return (
            f"Access policy {name!r} is locked by you ({who}){ticket}: nobody else can change it until you "
            "unlock it (fmc_policy_lock action='unlock')."
        )
    return f"Access policy {name!r} is locked by {who}{ticket}."


def _classify(
    name: str, state: dict[str, Any], me: str | None, blockers: list[str], notes: list[str]
) -> None:
    if same_user(state.get("locked_by"), me):
        notes.append(describe(name, state, me))
    else:
        blockers.append(
            describe(name, state, me)
            + " FMC refuses changes to it until they unlock it (in the FMC UI, or fmc_policy_lock "
            "action='unlock' as that user; break_lock=True takes the lock away from them)."
        )


async def lock_findings(
    app: FmcApp,
    owned: list[dict[str, Any] | None],
    domain: str | None,
    refs: list[dict[str, Any] | None] | None = None,
) -> tuple[list[str], list[str]]:
    """(blockers, notes) for the access policies a write changes: another user's lock blocks the preview (FMC
    would refuse the write with a bare error), the API user's own lock is a note.

    `owned`: policy records (their metadata.lockingStatus says it, no request). `refs`: policies known only
    by reference ({id, name}), e.g. the policies whose rules fmc_replace_object edits: one read of FMC's lock
    list covers them all (nothing when it can't be read)."""
    me = getattr(app.settings, "username", None)
    blockers: list[str] = []
    notes: list[str] = []
    seen: set[str] = set()
    for obj in owned:
        if not is_access_policy(obj):
            continue
        assert obj is not None
        seen.add(str(obj["id"]).lower())
        state = await holder(app, obj, domain)
        if state is None or state["status"] != "LOCKED":
            continue
        _classify(str(obj.get("name") or obj.get("id")), state, me, blockers, notes)
    want = {
        str(r["id"]).lower(): r
        for r in refs or []
        if isinstance(r, dict) and r.get("id") and str(r["id"]).lower() not in seen
    }
    if want:
        for row in locked(await read_locks(app, domain)):
            ref = want.pop(str(row.get("policy_id") or "").lower(), None)
            if ref is None:
                continue
            state = {"status": "LOCKED", **({"locked_by": row["locked_by"]} if row.get("locked_by") else {})}
            _classify(str(ref.get("name") or row.get("policy") or ref["id"]), state, me, blockers, notes)
    return blockers, notes


# --- categories ------------------------------------------------------------------------------------------


def _index(v: Any) -> int | None:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def category_row(c: dict[str, Any]) -> dict[str, Any]:
    """A category as {name, section, rules (first-last index, or 'none'), id}."""
    meta = c.get("metadata") or {}
    start, end = _index(meta.get("startIndex")), _index(meta.get("endIndex"))
    span = f"{start}" if start == end else f"{start}-{end}"
    row = {
        "name": c.get("name"),
        "section": str(meta.get("section") or "").lower() or None,
        "rules": "none" if start is None or end is None else span,
        "id": c.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


def _category_order(c: dict[str, Any]) -> tuple[int, int]:
    meta = c.get("metadata") or {}
    section = str(meta.get("section") or "").lower()
    pos = _index(meta.get("position"))
    return (SECTIONS.index(section) if section in SECTIONS else 2, pos if pos is not None else 10**6)


async def list_categories(app: FmcApp, acp: dict[str, Any], domain: str | None) -> list[dict[str, Any]]:
    """The policy's categories, Mandatory first, then FMC's position (or FMC's own order: the sort is
    stable, and an empty category's rule index is -1)."""
    page = await app.all(await app.config_path(f"{ACCESS}/{acp['id']}/categories", domain), cap=1000)
    return sorted((c for c in page.items if isinstance(c, dict) and c.get("id")), key=_category_order)


def find_category(cats: list[dict[str, Any]], ref: str, policy: dict[str, Any]) -> dict[str, Any]:
    ref = ref.strip()
    if is_uuid(ref):
        for c in cats:
            if str(c.get("id", "")).lower() == ref.lower():
                return c
        raise NotFound(f"No category {ref} in {policy.get('name')!r}.", 404)
    return pick_by_name(cats, ref, f"category in {policy.get('name')!r}")


async def category_blocker(
    app: FmcApp, acp: dict[str, Any], name: str, domain: str | None
) -> tuple[str | None, str | None]:
    """(the category's name as FMC spells it, None), or (None, a blocker): FMC refuses a rule for a
    category that doesn't exist with a bare error."""
    try:
        cat = find_category(await list_categories(app, acp, domain), name, acp)
    except NotFound:
        return None, (
            f"Policy {acp.get('name')!r} has no category {name!r}; create it first (fmc_create_category)."
        )
    return str(cat.get("name")), None


def rule_category(rule: dict[str, Any]) -> str | None:
    cat = (rule.get("metadata") or {}).get("category")
    return None if cat in (None, "", "--Undefined--") else str(cat)


def rule_place(rule: dict[str, Any]) -> dict[str, Any]:
    """Where a rule sits: {index, name, section, category, id}."""
    meta = rule.get("metadata") or {}
    row = {
        "index": meta.get("ruleIndex"),
        "name": rule.get("name"),
        "section": str(meta.get("section") or "").lower() or None,
        "category": rule_category(rule),
        "id": rule.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


# --- inheritance -----------------------------------------------------------------------------------------


async def inheritance_setting(app: FmcApp, policy_id: str, domain: str | None) -> dict[str, Any] | None:
    """The policy's inheritance setting ({id, basePolicy?}), or None when FMC lists none."""
    path = await app.config_path(f"{ACCESS}/{policy_id}/inheritancesettings", domain)
    page = await app.all(path, cap=10)
    return next((s for s in page.items if isinstance(s, dict) and s.get("id")), None)


def base_of(setting: Any) -> dict[str, Any] | None:
    base = setting.get("basePolicy") if isinstance(setting, dict) else None
    return base if isinstance(base, dict) and base.get("id") else None


async def base_chain(app: FmcApp, policy_id: str, domain: str | None) -> list[dict[str, Any]]:
    """The policy's ancestors, nearest first ([{id, name?}]); stops at CHAIN_LIMIT or a loop."""
    chain: list[dict[str, Any]] = []
    seen = {policy_id.lower()}
    current = policy_id
    for _ in range(CHAIN_LIMIT):
        base = base_of(await inheritance_setting(app, current, domain))
        if base is None or str(base["id"]).lower() in seen:
            break
        chain.append({"id": base["id"], **({"name": base["name"]} if base.get("name") else {})})
        seen.add(str(base["id"]).lower())
        current = str(base["id"])
    return chain


async def policy_names(app: FmcApp, domain: str | None) -> dict[str, str]:
    page = await app.all(await app.config_path(ACCESS, domain), cap=5000)
    return {str(p.get("id", "")).lower(): str(p.get("name")) for p in page.items if p.get("id")}


def named(chain: list[dict[str, Any]], names: dict[str, str]) -> list[str]:
    return [str(c.get("name") or names.get(str(c["id"]).lower()) or c["id"]) for c in chain]


async def chain_names(app: FmcApp, chain: list[dict[str, Any]], domain: str | None) -> list[str]:
    """The chain's names; the policy list is read only when FMC's references carry no name."""
    names = await policy_names(app, domain) if any(not c.get("name") for c in chain) else {}
    return named(chain, names)


async def policy_structure(app: FmcApp, p: dict[str, Any], domain: str | None) -> dict[str, Any]:
    """fmc_get_access_policy's structure block: the lock, the base chain and the categories. Parts FMC
    doesn't answer are left out."""
    out: dict[str, Any] = {}
    state = await holder(app, p, domain)
    if state is not None:
        out["lock"] = state
    try:
        chain = await base_chain(app, str(p["id"]), domain)
    except UpstreamError:
        chain = []
    if chain:
        out["base_chain"] = await chain_names(app, chain, domain)
    try:
        cats = await list_categories(app, p, domain)
    except UpstreamError:
        cats = []
    if cats:
        out["categories"] = [category_row(c) for c in cats]
    return out

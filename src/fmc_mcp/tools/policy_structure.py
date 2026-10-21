"""Access policy structure (F76): rule categories, inheritance (a base policy) and policy locks.

- Categories group rules inside the Mandatory or Default section: fmc_create_category (in a section,
  above a category, or before/after a rule index), fmc_rename_category, fmc_delete_category, over
  policy/accesspolicies/{id}/categories. FMC's REST API has no category move: rules move into a category
  with fmc_update_access_rule(category=...).
- Inheritance: a child access policy runs its base policy's Mandatory rules before its own rules and the
  base's Default rules after them. fmc_set_base_policy (and fmc_create_access_policy base_policy=...) over
  policy/accesspolicies/{id}/inheritancesettings, FMC's only way to set it (the policy body has no base
  field). FMC 10.0.1 gives every access policy one setting whose id is the policy's own id; a policy
  without a base has no basePolicy key.
- Locks: fmc_policy_lock over policy/operational/policylocks (access policies only). The holder is surfaced
  in fmc_get_access_policy, fmc_pending_changes and every access policy write preview. The shared reads
  live in fmc_mcp.acp_structure.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    get_client,
)
from fmc_mcp.acp_structure import (
    LOCKS,
    SECTIONS,
    base_chain,
    base_of,
    category_row,
    chain_names,
    find_category,
    holder,
    list_categories,
    lock_row,
    named,
    policy_names,
    read_locks,
    rule_category,
    rule_place,
    same_user,
)
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, ref_label
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import ACCESS, all_rules, policy_assignments, resolve_policy

PolicyRef = Annotated[str, Field(description="Access control policy name or UUID")]
CategoryRef = Annotated[str, Field(description="Category name or UUID (fmc_get_access_policy lists them)")]
CategoryName = Annotated[
    str, Field(description="Category name (unique in the policy)", min_length=1, max_length=50)
]
SHOWN = 10  # rule names listed per section in a preview
NO_LOCKS = (
    "FMC reports no lock state for this policy and its lock list can't be read: policy locks need FMC "
    "7.6 or later and a role that may lock policies."
)


async def rules_summary(app: FmcApp, acp: dict[str, Any], domain: str | None) -> dict[str, Any]:
    """What a base policy hands down: its Mandatory and Default rules (counts and the first names) and its
    default action."""
    path = await app.config_path(f"{ACCESS}/{acp['id']}/accessrules", domain)
    by: dict[str, list[str]] = {s: [] for s in SECTIONS}
    for r in (await all_rules(app, path)).items:
        section = str((r.get("metadata") or {}).get("section") or "default").lower()
        by.setdefault(section, []).append(str(r.get("name")))
    out: dict[str, Any] = {
        section: {"rules": len(names), "names": names[:SHOWN]} for section, names in by.items() if names
    }
    out["default_action"] = (acp.get("defaultAction") or {}).get("action")
    return out


async def assigned_to(app: FmcApp, policy_id: str, domain: str | None) -> list[str]:
    out: list[str] = []
    for a in await policy_assignments(app, domain):
        if str((a.get("policy") or {}).get("id", "")).lower() == policy_id.lower():
            out += [ref_label(t) for t in a.get("targets") or []]
    return out


def base_body(policy_id: str, base: dict[str, Any] | None) -> dict[str, Any]:
    """The inheritance setting PUT: the setting's id is the policy's id; no base = no basePolicy key (the
    shape FMC 10.0.1 reads back for a policy without a base)."""
    body: dict[str, Any] = {"type": "AccessPolicyInheritanceSetting", "id": policy_id}
    if base:
        body["basePolicy"] = {"id": base["id"], "type": "AccessPolicy"}
    return body


async def put_base(
    app: FmcApp, policy_id: str, base: dict[str, Any] | None, domain: str | None
) -> dict[str, Any]:
    """Point the policy's inheritance setting at `base` ({id, name}) or at no base (None), then read the
    setting back: the result says which base FMC holds and warns when it isn't the one asked for."""
    path = await app.config_path(f"{ACCESS}/{policy_id}/inheritancesettings/{policy_id}", domain)
    await app.api.put(path, base_body(policy_id, base))
    app.invalidate_cache()
    got = base_of(await app.api.get(path))
    want = str((base or {}).get("id") or "").lower()
    same = str((got or {}).get("id") or "").lower() == want
    shown: str | None = None
    if got is not None and same:
        shown = str((base or {}).get("name") or got["id"])
    elif got is not None:  # not the base asked for: name it (FMC's reference carries only the id)
        shown = got.get("name") or (await policy_names(app, domain)).get(str(got["id"]).lower()) or got["id"]
    out: dict[str, Any] = {
        "base_policy": shown,
        "next": "fmc_pending_changes on the policy's devices, then fmc_deploy",
    }
    if not same:
        out["warning"] = (
            f"FMC reports base {shown or 'none'} after the change, not {(base or {}).get('name') or 'none'}: "
            "check the policy's Inheritance Settings in the FMC UI."
        )
    return out


def inheritance_effect(base_name: str) -> str:
    return (
        f"Traffic is checked against {base_name!r}'s Mandatory rules first, then this policy's own rules, "
        f"then {base_name!r}'s Default rules, then the default action. Devices running this policy get "
        "the base's rules on their next deployment (fmc_pending_changes shows them)."
    )


async def lock_now(app: FmcApp, p: dict[str, Any], domain: str | None) -> tuple[dict[str, Any], bool]:
    """(the policy's lock state, whether FMC reported any): the lock list's entry first, then the policy's
    own metadata.lockingStatus."""
    rows = await read_locks(app, domain)
    listed = next(
        (r for r in rows or [] if str(r.get("policy_id", "")).lower() == str(p["id"]).lower()), None
    )
    if listed:
        return {k: v for k, v in listed.items() if k in ("status", "locked_by")}, True
    state = await holder(app, p, domain)
    if state is not None:
        return state, True
    # FMC 10.0.1 lists nothing when nothing is locked; then the policy's own lockingStatus decides
    return {"status": "UNLOCKED" if rows is not None else "UNKNOWN"}, rows is not None


def _lock_plan(
    p: dict[str, Any], state: dict[str, Any], me: str | None, action: str, break_lock: bool
) -> tuple[list[str], list[str]]:
    """(blockers, side effects) of a lock or unlock request."""
    name = p.get("name")
    status = state.get("status")
    who = state.get("locked_by") or "another user"
    mine = same_user(state.get("locked_by"), me)
    blockers: list[str] = []
    side: list[str] = []
    if action == "lock":
        if status == "LOCKED" and mine:
            blockers.append(f"Nothing to change: {name!r} is already locked by you ({me}).")
        elif status == "LOCKED":
            blockers.append(
                f"{name!r} is locked by {who}; they must unlock it first (or take it from them with "
                "action='unlock', break_lock=True)."
            )
        side.append(
            f"Until it is unlocked only {me} (this server's FMC account) can change {name!r}; FMC refuses "
            "other users' edits."
        )
        return blockers, side
    if status == "UNLOCKED":
        blockers.append(f"Nothing to change: {name!r} isn't locked.")
    elif status == "LOCKED" and not mine and not break_lock:
        blockers.append(
            f"{name!r} is locked by {who}, not by {me}. Ask them to unlock it, or repeat with "
            "break_lock=True to take the lock away from them."
        )
    elif status == "LOCKED" and not mine:
        side.append(
            f"Takes the lock away from {who}: anyone can change the policy again, even while they are "
            "still working on it."
        )
    side.append(f"Other users can change {name!r} again.")
    return blockers, side


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create access policy category")
    async def fmc_create_category(
        ctx: Context,
        policy: PolicyRef,
        name: CategoryName,
        section: Annotated[
            Literal["mandatory", "default"] | None,
            Field(description="Section to create it in (default: FMC's choice, the Default section)"),
        ] = None,
        above_category: Annotated[
            str | None, Field(description="Create it directly above this existing category (name or UUID)")
        ] = None,
        insert_before: Annotated[
            int | None,
            Field(ge=1, description="Create it above this 1-based rule index (fmc_list_access_rules)"),
        ] = None,
        insert_after: Annotated[
            int | None, Field(ge=1, description="Create it below this 1-based rule index")
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a rule category to an access control policy: in the Mandatory or Default section, directly
        above another category, or at a rule position. Categories group rules inside a section; fill one
        with fmc_create_access_rule(category=...) or fmc_update_access_rule(category=...). The preview
        lists the policy's categories now; the result shows the new one with its rule range."""
        app: FmcApp = get_client(ctx)
        positions = {
            "section": section,
            "above_category": above_category,
            "insert_before": insert_before,
            "insert_after": insert_after,
        }
        given = [k for k, v in positions.items() if v]
        if len(given) > 1:
            raise InvalidRequest(f"Give one position ({' or '.join(given)}), not several.")
        p = await resolve_policy(app, "access", policy, domain)
        cats = await list_categories(app, p, domain)
        blockers: list[str] = []
        new = name.strip()
        if any(str(c.get("name", "")).lower() == new.lower() for c in cats):
            blockers.append(f"Policy {p.get('name')!r} already has a category named {new!r}.")
        params: dict[str, Any] = {}
        where = f"in the {section or 'default'} section"
        if section:
            params["section"] = section
        if above_category:
            try:
                above = find_category(cats, above_category, p)
            except NotFound as e:
                blockers.append(str(e))
            else:
                params["aboveCategory"] = above.get("name")
                where = f"above category {above.get('name')!r} ({category_row(above).get('section')} section)"
        idx = insert_before or insert_after
        if idx:
            rules_path = await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain)
            count = len((await all_rules(app, rules_path)).items)
            if idx > count:
                blockers.append(f"Position {idx} is beyond the last rule ({count} rules).")
            params["insertBefore" if insert_before else "insertAfter"] = idx
            where = f"{'above' if insert_before else 'below'} rule {idx}"
        body = {"name": new, "type": "Category"}
        path = await app.config_path(f"{ACCESS}/{p['id']}/categories", domain)

        async def apply() -> Any:
            created = await applied(app, lambda: app.api.post(path, body, params=params))
            after = await list_categories(app, p, domain)
            mine = next((c for c in after if c.get("name") == new), None)
            return {
                "category": category_row(mine or (created if isinstance(created, dict) else {})),
                "categories": [category_row(c) for c in after],
                "next": "fmc_create_access_rule(category=...) or fmc_update_access_rule(category=...)",
            }

        details: dict[str, Any] = {
            "policy": p.get("name"),
            "position": where,
            "categories_now": [category_row(c) for c in cats],
            "body": body,
        }
        if params:
            details["params"] = params
        return await fmc_preview(
            ctx,
            tool="fmc_create_category",
            owned=[p],
            args={"policy": policy, "name": name, **positions, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Create category {new!r} in {p.get('name')!r} {where}",
                details=details,
                fingerprint={"policy": p["id"], "categories": [c.get("id") for c in cats], "params": params},
                blockers=blockers,
                side_effects=["A category changes no traffic by itself; its rules work as before."],
            ),
            apply=apply,
        )

    @reg.write(title="Rename access policy category")
    async def fmc_rename_category(
        ctx: Context,
        policy: PolicyRef,
        category: CategoryRef,
        new_name: CategoryName,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Rename a rule category of an access control policy. Its rules, section and position stay; tools
        that select rules by category (fmc_bulk_update_access_rules, policy bundles) use the new name."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        cats = await list_categories(app, p, domain)
        cur = find_category(cats, category, p)
        new = new_name.strip()
        blockers: list[str] = []
        clash = [
            c for c in cats if str(c.get("name", "")).lower() == new.lower() and c.get("id") != cur.get("id")
        ]
        if str(cur.get("name")) == new:
            blockers.append("Nothing to change: the category already has that name.")
        elif clash:
            blockers.append(f"Policy {p.get('name')!r} already has a category named {new!r}.")
        body = {**editable(cur), "name": new}
        body.setdefault("type", "Category")
        path = await app.config_path(f"{ACCESS}/{p['id']}/categories/{cur['id']}", domain)

        async def apply() -> Any:
            done = await applied(app, lambda: app.api.put(path, body))
            return {"category": category_row(done) if isinstance(done, dict) and done.get("name") else new}

        return await fmc_preview(
            ctx,
            tool="fmc_rename_category",
            owned=[p],
            args={"policy": policy, "category": category, "new_name": new_name, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Rename category {cur.get('name')!r} to {new!r} in {p.get('name')!r}",
                details={
                    "policy": p.get("name"),
                    "category": category_row(cur),
                    "changes": {"name": {"from": cur.get("name"), "to": new}},
                },
                fingerprint=editable(cur),
                blockers=blockers,
                side_effects=["Changes no traffic; the rename alone needs no deployment."],
            ),
            apply=apply,
        )

    @reg.write(title="Delete access policy category", destructive=True)
    async def fmc_delete_category(
        ctx: Context,
        policy: PolicyRef,
        category: CategoryRef,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a rule category from an access control policy. The preview lists the rules in it, which
        FMC keeps (the FMC UI files them into the category above, or the section). The result re-reads the
        policy and shows where each of those rules is now, and names any rule FMC no longer lists."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        cats = await list_categories(app, p, domain)
        cur = find_category(cats, category, p)
        rules_path = await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain)
        members = [
            r
            for r in (await all_rules(app, rules_path)).items
            if (rule_category(r) or "").lower() == str(cur.get("name", "")).lower()
        ]
        path = await app.config_path(f"{ACCESS}/{p['id']}/categories/{cur['id']}", domain)

        async def apply() -> Any:
            await applied(app, lambda: app.api.delete(path))
            out: dict[str, Any] = {"deleted": cur.get("name"), "rules_now": []}
            if not members:
                return out
            now = {str(r.get("id")): r for r in (await all_rules(app, rules_path)).items}
            out["rules_now"] = [rule_place(now[str(r.get("id"))]) for r in members if str(r.get("id")) in now]
            lost = [str(r.get("name")) for r in members if str(r.get("id")) not in now]
            if lost:
                out["rules_missing"] = lost
                out["warning"] = (
                    "FMC no longer lists these rules after the delete: re-create them "
                    "(fmc_create_access_rule) from the preview's rule list."
                )
            return out

        side = ["Changes no traffic as long as FMC keeps the rules; the result says where they went."]
        if members:
            side.insert(
                0,
                f"Its {len(members)} rule(s) stay in the policy: FMC files them into the category above it, "
                "or the section (the FMC UI's behaviour; the result re-reads the rules to show it).",
            )
        return await fmc_preview(
            ctx,
            tool="fmc_delete_category",
            owned=[p],
            args={"policy": policy, "category": category, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete category {cur.get('name')!r} from {p.get('name')!r}",
                details={
                    "policy": p.get("name"),
                    "category": category_row(cur),
                    "rules_in_category": [rule_place(r) for r in members],
                },
                fingerprint={"category": editable(cur), "members": [r.get("id") for r in members]},
                side_effects=side,
            ),
            apply=apply,
        )

    @reg.write(title="Set an access policy's base policy (inheritance)")
    async def fmc_set_base_policy(
        ctx: Context,
        policy: Annotated[str, Field(description="The child access policy (name or UUID)")],
        base: Annotated[
            str,
            Field(
                description="Base (parent) access policy name or UUID, or 'none' to stop inheriting. A "
                "base from an ancestor domain (a Global corporate policy for a leaf-domain site) works"
            ),
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make an access policy inherit from a base policy, change its base, or stop inheriting ('none').
        A child runs the base's Mandatory rules before its own rules and the base's Default rules after
        them, so a corporate parent's mandatory rules apply at every site. The preview shows the base chain
        before and after, what the new base hands down (rules per section, default action) and the
        devices that get it on their next deployment; a loop (the base inherits from this policy) is
        refused."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        before = await base_chain(app, str(p["id"]), domain)
        new: dict[str, Any] | None = None
        above: list[dict[str, Any]] = []
        blockers: list[str] = []
        if base.strip().lower() != "none":
            new = await resolve_policy(app, "access", base, domain)
            if str(new["id"]).lower() == str(p["id"]).lower():
                blockers.append("A policy can't be its own base.")
            else:
                above = await base_chain(app, str(new["id"]), domain)
        names = await policy_names(app, domain) if any(not c.get("name") for c in before + above) else {}
        if new and any(str(c["id"]).lower() == str(p["id"]).lower() for c in above):
            loop = " -> ".join([str(new.get("name"))] + named(above, names))
            blockers.append(
                f"{new.get('name')!r} already inherits from {p.get('name')!r} ({loop}): that would be a loop."
            )
        current = before[0] if before else None
        if current and new and str(current["id"]).lower() == str(new["id"]).lower():
            blockers.append(f"Nothing to change: the base is already {new.get('name')!r}.")
        elif not current and not new:
            blockers.append("Nothing to change: the policy has no base.")
        devices = await assigned_to(app, str(p["id"]), domain)
        chain_from = [str(p.get("name"))] + named(before, names)
        chain_to = [str(p.get("name"))] + ([str(new.get("name"))] + named(above, names) if new else [])
        details: dict[str, Any] = {
            "policy": p.get("name"),
            "base": {"from": chain_from[1] if len(chain_from) > 1 else None, "to": (new or {}).get("name")},
            "chain": {"from": chain_from, "to": chain_to},
            "assigned_to": devices,
        }
        side = ["Takes effect on devices after the next deployment."]
        if new and not blockers:
            details["inherited_from_base"] = await rules_summary(app, new, domain)
            details["own_default_action"] = (p.get("defaultAction") or {}).get("action")
            side.insert(0, inheritance_effect(str(new.get("name"))))
        elif not new and current:
            side.insert(0, f"The policy stops getting {chain_from[1]!r}'s rules.")
        target = {"id": new["id"], "name": new.get("name")} if new else None
        summary = (
            f"Set the base policy of {p.get('name')!r} to {new.get('name')!r}"
            if new
            else f"Remove the base policy of {p.get('name')!r}"
        )
        return await fmc_preview(
            ctx,
            tool="fmc_set_base_policy",
            owned=[p],
            args={"policy": policy, "base": base, "domain": domain},
            confirm=confirm,
            plan=Plan(
                summary,
                details={**details, "body": base_body(str(p["id"]), target)},
                fingerprint={"policy": p["id"], "before": before, "to": (new or {}).get("id")},
                blockers=blockers,
                side_effects=side,
                blast_radius=len(devices),
            ),
            apply=lambda: put_base(app, str(p["id"]), target, domain),
        )

    @reg.write(title="Lock or unlock an access policy")
    async def fmc_policy_lock(
        ctx: Context,
        policy: PolicyRef,
        action: Annotated[Literal["lock", "unlock"], Field(description="lock or unlock")],
        include_parents: Annotated[
            bool,
            Field(description="Also lock/unlock every base policy above it (FMC's lockParentsInHierarchy)"),
        ] = False,
        break_lock: Annotated[
            bool,
            Field(description="Unlock a policy another user has locked (takes the lock away from them)"),
        ] = False,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Lock an access control policy so no other user can change it (a change window), or unlock it.
        The lock is held by this server's FMC account. The preview shows who holds the lock now; a lock
        held by someone else is refused, and unlocking it needs break_lock=True. Access policies only (FMC
        7.6+). Who holds a lock is also shown by fmc_get_access_policy and in every access policy write
        preview."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        me = getattr(app.settings, "username", None)
        state, known = await lock_now(app, p, domain)
        blockers, side = _lock_plan(p, state, me, action, break_lock)
        if not known:
            blockers.insert(0, NO_LOCKS)
        parents: list[str] = []
        if include_parents:
            parents = await chain_names(app, await base_chain(app, str(p["id"]), domain), domain)
            side.append(
                f"The base policies above it are {action}ed too: {', '.join(parents)}."
                if parents
                else "The policy has no base policy: include_parents adds nothing."
            )
        entry: dict[str, Any] = {"lock": action == "lock", "policy": {"id": p["id"], "type": "AccessPolicy"}}
        if include_parents:
            entry["lockParentsInHierarchy"] = True
        body = {"policies": [entry]}
        path = await app.config_path(LOCKS, domain)

        async def apply() -> Any:
            result = await app.api.post(path, body)
            entries = result.get("policies") if isinstance(result, dict) else None
            rows = [lock_row(e) for e in entries or [] if isinstance(e, dict) and e.get("policy")]
            return {"locks": rows} if rows else result

        return await fmc_preview(
            ctx,
            tool="fmc_policy_lock",
            owned=[p],
            lock_check=False,  # this tool reports the lock itself
            args={
                "policy": policy,
                "action": action,
                "include_parents": include_parents,
                "break_lock": break_lock,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"{action.capitalize()} access policy {p.get('name')!r}"
                + (f" and its base policies ({', '.join(parents)})" if parents else ""),
                details={"policy": p.get("name"), "lock_now": state, "api_user": me, "body": body},
                fingerprint={"policy": p["id"], "state": state, "parents": parents},
                blockers=blockers,
                side_effects=side,
            ),
            apply=apply,
        )

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
    UpstreamError,
    get_client,
)
from fmc_mcp.acp_structure import (
    LOCKS,
    SECTIONS,
    base_chain,
    base_of,
    category_row,
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
INHERIT_SCAN = 25  # assigned access policies whose base chain a base change checks (descendants' devices)
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


async def assigned_to(
    app: FmcApp, policy_id: str, domain: str | None
) -> tuple[list[str], list[dict[str, Any]], list[str]]:
    """(devices the policy is assigned to, [{policy, devices}] for assigned access policies that inherit
    from it further down, notes). A policy's base change reaches its descendants' devices too: each other
    assigned access policy's base chain is read (one request per level, the first INHERIT_SCAN policies)."""
    direct: list[str] = []
    below: list[dict[str, Any]] = []
    notes: list[str] = []
    others: list[dict[str, Any]] = []
    for a in await policy_assignments(app, domain):
        pol = a.get("policy") or {}
        if str(pol.get("id", "")).lower() == policy_id.lower():
            direct += [ref_label(t) for t in a.get("targets") or []]
        elif pol.get("id") and pol.get("type", "AccessPolicy") == "AccessPolicy" and a.get("targets"):
            others.append(a)
    if len(others) > INHERIT_SCAN:
        notes.append(
            f"Only the first {INHERIT_SCAN} of {len(others)} assigned access policies were checked for "
            "inheriting from it."
        )
    for a in others[:INHERIT_SCAN]:
        pol = a["policy"]
        try:
            chain = await base_chain(app, str(pol["id"]), domain)
        except UpstreamError:
            notes.append(f"The base policy of {pol.get('name') or pol['id']!r} couldn't be read.")
            continue
        if any(str(c["id"]).lower() == policy_id.lower() for c in chain):
            devices = [ref_label(t) for t in a.get("targets") or []]
            below.append({"policy": pol.get("name") or pol["id"], "devices": devices})
    return direct, below, notes


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


# --- the child's Logging settings ------------------------------------------------------------------------
# FMC 10.0.1 keeps a policy's own Logging settings (loggingsettings: syslog from the platform settings or
# not, IPS / file syslog) when it gets a base policy through the REST API; the FMC UI ticks "Inherit from
# base policy" for a new child. Recorded live (W6N live-A): a child created with POST + PUT
# inheritancesettings had {syslogConfigFromPlatformSetting false, inheritFromParent false}, and its first
# deployment failed FMC's validation (400 "Access Control Policy Logging configuration is invalid. Access
# Control rules inherited from base policy '<base>' have syslog configured to use Logging configuration")
# because the base's rules send syslog through the Logging settings. PUT loggingsettings/<id>
# {..., inheritFromParent: true} fixed it: FMC answered with the base's setting (its id,
# metadata.inheritedPolicy) and the deployment passed. Clearing the base brings the policy's own back.
# A new child (fmc_create_access_policy base_policy=) always inherits, as the FMC UI does: its own are
# FMC's defaults. An existing policy given another base (fmc_set_base_policy) may be deployed with Logging
# settings someone chose, so they inherit only when FMC needs it (the base's send syslog, the policy's
# own have no destination) or when asked. Making an inheriting policy stop inheriting over REST isn't
# recorded on FMC 10.0.1 (the GET answers with the base's setting and id), so no tool does it.


async def logging_setting(app: FmcApp, policy_id: str, domain: str | None) -> dict[str, Any] | None:
    """The access policy's Logging settings object, or None when FMC lists none."""
    page = await app.all(await app.config_path(f"{ACCESS}/{policy_id}/loggingsettings", domain), cap=10)
    return next((s for s in page.items if isinstance(s, dict) and s.get("id")), None)


def syslog_destination(setting: dict[str, Any]) -> bool:
    """Whether the Logging settings give the rules' connection syslog a destination (the platform-settings
    servers or an alert): what FMC's deploy validation looks for in a child whose base's rules send syslog."""
    return bool(setting.get("syslogConfigFromPlatformSetting") or setting.get("syslogConfig"))


def own_logging(setting: dict[str, Any]) -> str:
    """What the policy's own Logging settings send, in words."""
    on = [
        label
        for key, label in (
            ("syslogConfigFromPlatformSetting", "connection syslog to the platform-settings servers"),
            ("syslogConfig", "connection syslog to an alert"),
            ("enableipsSyslog", "intrusion syslog"),
            ("enableFileAndMalwareSyslog", "file/malware syslog"),
        )
        if setting.get(key)
    ]
    return ", ".join(on) if on else "no syslog destination: FMC's defaults"


def logging_needed(setting: dict[str, Any], base_setting: dict[str, Any] | None) -> bool:
    """Whether FMC would refuse the policy's deployment with its own Logging settings under this base: the
    base's send syslog and the policy's own give it no destination (W6N live-A's first deploy failure)."""
    return base_setting is not None and syslog_destination(base_setting) and not syslog_destination(setting)


def logging_plan(
    setting: dict[str, Any] | None, base_setting: dict[str, Any] | None, asked: bool | None
) -> tuple[bool, str | None]:
    """(whether the base change also makes the policy's Logging settings inherit, a note for the preview).
    The policy may be deployed with Logging settings someone chose, so they change only when FMC needs it
    (logging_needed) or when asked (inherit_logging=True); inherit_logging=False never changes them.
    base_setting: the new base's Logging settings (None: not read or not listed)."""
    if setting is None:
        return False, "FMC lists no Logging settings for the policy: they are left as they are."
    if setting.get("inheritFromParent"):
        if asked is False:
            return False, (
                "Its Logging settings already inherit from its base and go on inheriting, from the new base: "
                "inherit_logging=False doesn't stop that (untick 'Inherit from base policy' on its Logging "
                "tab in the FMC UI)."
            )
        return False, None
    needed = logging_needed(setting, base_setting)
    if asked is True:
        return True, None
    if asked is None and needed and base_setting is not None:
        return True, (
            f"They inherit because FMC needs it: the base's Logging settings send syslog "
            f"({own_logging(base_setting)}) and this policy's own have no syslog destination, so FMC would "
            "refuse its deployment (inherit_logging=False keeps them)."
        )
    if needed:  # asked False
        return False, (
            f"Keeps its own Logging settings ({own_logging(setting)}) as asked: the base's send syslog and "
            "these have no syslog destination, so FMC refuses the deployment until this policy has one "
            "(fmc_set_access_logging use_platform_syslog=True) or inherits them (inherit_logging=True)."
        )
    if asked is None and base_setting is None:
        return False, (
            "The base's Logging settings couldn't be read (or FMC lists none): this policy's own are left "
            "as they are "
            "(inherit_logging=True makes them inherit from the base)."
        )
    return False, None


async def inherit_base_logging(app: FmcApp, policy_id: str, domain: str | None) -> dict[str, Any]:
    """PUT the policy's Logging settings to inherit from its base (after the base is set); returns
    {logging} or {logging, logging_warning}. Never raises: the base is set either way."""
    try:
        cur = await logging_setting(app, policy_id, domain)
        if cur is None or cur.get("inheritFromParent"):
            return {"logging": "inherited from the base policy" if cur else "not listed by FMC"}
        path = await app.config_path(f"{ACCESS}/{policy_id}/loggingsettings/{cur['id']}", domain)
        got = await app.api.put(path, {**editable(cur), "inheritFromParent": True})
    except UpstreamError as e:
        return {
            "logging": "its own (unchanged)",
            "logging_warning": f"FMC refused to make the policy inherit its base's Logging settings ({e}). "
            "If the base's rules send syslog, FMC refuses the deployment until this policy has a syslog "
            "destination: fmc_set_access_logging(use_platform_syslog=True), or tick 'Inherit from base "
            "policy' on its Logging tab in the FMC UI.",
        }
    finally:
        app.invalidate_cache()
    if isinstance(got, dict) and got.get("inheritFromParent"):
        src = ((got.get("metadata") or {}).get("inheritedPolicy") or {}).get("name")
        return {"logging": f"inherited from {src!r}" if src else "inherited from the base policy"}
    return {
        "logging": "its own (FMC kept it)",
        "logging_warning": "FMC answered the Logging settings change but doesn't report them inherited; "
        "check the policy's Logging tab before deploying.",
    }


def logging_change(setting: dict[str, Any], inherit: bool, base_name: str) -> dict[str, str]:
    """The preview's Logging settings line: now and after the base change."""
    if setting.get("inheritFromParent"):
        return {"now": "inherited from the base policy", "after": f"inherited from {base_name!r}"}
    now = f"its own ({own_logging(setting)})"
    return {"now": now, "after": f"inherited from {base_name!r}" if inherit else f"{now}, unchanged"}


INHERITS_FROM_NOW = (
    "Its Logging settings inherit from the base from now on (its own stay stored in FMC and come back if "
    "the base is removed)."
)
LOGGING_INHERIT_NOTE = (
    "The policy's Logging settings inherit from the base (loggingsettings inheritFromParent, as the FMC UI "
    "does for a new child): with its own defaults FMC refuses the first deployment when the base's rules "
    "send syslog."
)


def inheritance_effect(base_name: str) -> str:
    return (
        f"Traffic is checked against {base_name!r}'s Mandatory rules first, then this policy's own rules, "
        f"then {base_name!r}'s Default rules, then the default action. Devices running this policy get "
        "the base's rules on their next deployment (fmc_pending_changes shows them)."
    )


async def lock_now(
    app: FmcApp, p: dict[str, Any], domain: str | None, rows: list[dict[str, Any]] | None
) -> tuple[dict[str, Any], bool]:
    """(the policy's lock state, whether FMC reported any): its entry in the lock list (`rows`, read_locks)
    first, then the policy's own metadata.lockingStatus."""
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


async def parent_locks(
    app: FmcApp, p: dict[str, Any], domain: str | None, rows: list[dict[str, Any]] | None
) -> list[dict[str, Any]]:
    """The lock state of every base policy above `p`, nearest first ({policy, status, locked_by?}): what
    include_parents (FMC's lockParentsInHierarchy) also locks or unlocks."""
    out: list[dict[str, Any]] = []
    for ref in await base_chain(app, str(p["id"]), domain):
        try:
            rec = await resolve_policy(app, "access", str(ref["id"]), domain)
        except UpstreamError:
            out.append({"policy": ref.get("name") or ref["id"], "status": "UNKNOWN"})
            continue
        state, _ = await lock_now(app, rec, domain, rows)
        out.append({"policy": rec.get("name") or ref["id"], **state})
    return out


def _lock_plan(
    p: dict[str, Any],
    state: dict[str, Any],
    me: str | None,
    action: str,
    break_lock: bool,
    parents: list[dict[str, Any]] | None = None,
) -> tuple[list[str], list[str]]:
    """(blockers, side effects) of a lock or unlock request; `parents` (include_parents): the base
    policies' lock states, which the request changes too."""
    name = p.get("name")
    rows = [{"policy": name, **state}, *(parents or [])]
    blockers: list[str] = []
    side: list[str] = []

    def mine(r: dict[str, Any]) -> bool:
        return r.get("status") == "LOCKED" and same_user(r.get("locked_by"), me)

    def done(r: dict[str, Any]) -> bool:
        return mine(r) if action == "lock" else r.get("status") == "UNLOCKED"

    also = " and its base policies" if parents else ""
    if all(done(r) for r in rows):
        blockers.append(
            f"Nothing to change: {name!r}{also} {'are' if parents else 'is'} already locked by you ({me})."
            if action == "lock"
            else f"Nothing to change: {name!r}{also} {'are' if parents else 'is'}n't locked."
        )
    for i, r in enumerate(rows):
        if r.get("status") != "LOCKED" or mine(r):
            continue
        who = r.get("locked_by") or "another user"
        label = f"{r['policy']!r}" if i == 0 else f"Base policy {r['policy']!r}"
        if action == "lock":
            blockers.append(
                f"{label} is locked by {who}; they must unlock it first (or take it from them with "
                "action='unlock', break_lock=True)."
            )
        elif not break_lock:
            blockers.append(
                f"{label} is locked by {who}, not by {me}. Ask them to unlock it, or repeat with "
                "break_lock=True to take the lock away from them."
            )
        else:
            on = "" if i == 0 else f"on base policy {r['policy']!r} "
            side.append(
                f"Takes the lock {on}away from {who}: anyone can change the policy again, even while they "
                "are still working on it."
            )
    for r in parents or []:
        if r.get("status") == "UNKNOWN":
            side.append(f"FMC reports no lock state for base policy {r['policy']!r}.")
    if action == "lock":
        side.append(
            f"Until it is unlocked only {me} (this server's FMC account) can change {name!r}{also}; FMC "
            "refuses other users' edits."
        )
    else:
        side.append(f"Other users can change {name!r}{also} again.")
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
        inherit_logging: Annotated[
            bool | None,
            Field(
                description="With a base: True makes the policy's Logging settings (syslog) inherit from "
                "it; False leaves them as they are (it doesn't stop a policy that already inherits from "
                "inheriting). Default: they inherit only when FMC needs it (the base's Logging settings send "
                "syslog and this policy's own have no syslog destination: FMC refuses that deployment), "
                "otherwise they are left alone"
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make an access policy inherit from a base policy, change its base, or stop inheriting ('none').
        A child runs the base's Mandatory rules before its own rules and the base's Default rules after
        them, so a corporate parent's mandatory rules apply at every site. The preview shows the base chain
        before and after, what the new base hands down (rules per section, default action) and the
        devices that get it on their next deployment; a loop (the base inherits from this policy) is
        refused. Its Logging settings are left alone unless FMC needs them to inherit from the new base
        (the base's send syslog, its own have none) or inherit_logging=True."""
        app: FmcApp = get_client(ctx)
        if inherit_logging is not None and base.strip().lower() == "none":
            raise InvalidRequest("inherit_logging goes with a base policy, not base='none'.")
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
        devices, below, scan_notes = await assigned_to(app, str(p["id"]), domain)
        reached = sorted({d for b in below for d in b["devices"]} - set(devices))
        chain_from = [str(p.get("name"))] + named(before, names)
        chain_to = [str(p.get("name"))] + ([str(new.get("name"))] + named(above, names) if new else [])
        details: dict[str, Any] = {
            "policy": p.get("name"),
            "base": {"from": chain_from[1] if len(chain_from) > 1 else None, "to": (new or {}).get("name")},
            "chain": {"from": chain_from, "to": chain_to},
            "assigned_to": devices,
        }
        side = ["Takes effect on devices after the next deployment."]
        if below:
            details["inherited_by"] = below
            side.insert(
                0,
                f"Policies that inherit from {p.get('name')!r} change too: "
                + "; ".join(f"{b['policy']} ({', '.join(b['devices'])})" for b in below)
                + ".",
            )
        side += scan_notes
        logging: dict[str, Any] | None = None
        base_logging: dict[str, Any] | None = None
        inherit = False
        if new and not blockers:
            details["inherited_from_base"] = await rules_summary(app, new, domain)
            details["own_default_action"] = (p.get("defaultAction") or {}).get("action")
            side.insert(0, inheritance_effect(str(new.get("name"))))
            try:
                logging = await logging_setting(app, str(p["id"]), domain)
            except UpstreamError as e:
                side.append(
                    f"The policy's Logging settings couldn't be read ({e}): they are left as they are."
                )
            else:
                if logging is not None and not logging.get("inheritFromParent"):
                    try:
                        base_logging = await logging_setting(app, str(new["id"]), domain)
                    except UpstreamError:
                        base_logging = None
                inherit, note = logging_plan(logging, base_logging, inherit_logging)
                if logging is not None:
                    details["logging"] = logging_change(logging, inherit, str(new.get("name")))
                if inherit:
                    side.append(INHERITS_FROM_NOW)
                if note:
                    side.append(note)
        elif not new and current:
            side.insert(0, f"The policy stops getting {chain_from[1]!r}'s rules.")
        target = {"id": new["id"], "name": new.get("name")} if new else None
        summary = (
            f"Set the base policy of {p.get('name')!r} to {new.get('name')!r}"
            if new
            else f"Remove the base policy of {p.get('name')!r}"
        )

        async def apply() -> Any:
            out = await put_base(app, str(p["id"]), target, domain)
            if inherit:
                done = await inherit_base_logging(app, str(p["id"]), domain)
                out["logging"] = done["logging"]
                if done.get("logging_warning"):
                    out["warning"] = " ".join(w for w in (out.get("warning"), done["logging_warning"]) if w)
            return out

        args: dict[str, Any] = {"policy": policy, "base": base, "domain": domain}
        if inherit_logging is not None:
            args["inherit_logging"] = inherit_logging
        return await fmc_preview(
            ctx,
            tool="fmc_set_base_policy",
            owned=[p],
            args=args,
            confirm=confirm,
            plan=Plan(
                summary,
                details={**details, "body": base_body(str(p["id"]), target)},
                fingerprint={
                    "policy": p["id"],
                    "before": before,
                    "to": (new or {}).get("id"),
                    "logging": editable(logging) if logging else None,
                    "base_logging": editable(base_logging) if base_logging else None,
                },
                blockers=blockers,
                side_effects=side,
                blast_radius=len(devices) + len(reached),
            ),
            apply=apply,
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
        held by someone else is refused, and unlocking it needs break_lock=True; with include_parents the
        same goes for each base policy above it. Access policies only (FMC 7.6+). Who holds a lock is also
        shown by fmc_get_access_policy and in every access policy write preview."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        me = getattr(app.settings, "username", None)
        rows = await read_locks(app, domain)
        state, known = await lock_now(app, p, domain, rows)
        above = await parent_locks(app, p, domain, rows) if include_parents else []
        blockers, side = _lock_plan(p, state, me, action, break_lock, above)
        if not known:
            blockers.insert(0, NO_LOCKS)
        parents = [str(r["policy"]) for r in above]
        if include_parents:
            side.append(
                f"The base policies above it are {action}ed too: {', '.join(parents)}."
                if parents
                else "The policy has no base policy: include_parents adds nothing."
            )
        entry: dict[str, Any] = {"policy": {"id": p["id"], "type": "AccessPolicy"}}
        if include_parents:
            # lockParentsInHierarchy carries the value itself: true locks the policy and every base above
            # it, false unlocks them all (10.0.1 spec; its request example sends it without `lock`)
            entry["lockParentsInHierarchy"] = action == "lock"
        else:
            entry["lock"] = action == "lock"
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
                details={
                    "policy": p.get("name"),
                    "lock_now": state,
                    **({"base_policies": above} if include_parents else {}),
                    "api_user": me,
                    "body": body,
                },
                fingerprint={"policy": p["id"], "state": state, "parents": above},
                blockers=blockers,
                side_effects=side,
            ),
            apply=apply,
        )

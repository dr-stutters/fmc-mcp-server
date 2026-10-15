"""Intrusion (Snort 3) policy tuning (F13, first slice): read a policy and its rule overrides, find rules,
change a rule's state per policy, create a policy, and manage custom (local) rules."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from stutters_mcp_core.http import Page

from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, ref_label, resolve_in
from fmc_mcp.tools.object_writes import applied, editable

IPS = "policy/intrusionpolicies"
RULES = "object/intrusionrules"
GROUPS = "object/intrusionrulegroups"
MAX_OVERRIDES = 500
MIN_CUSTOM_SID = 1_000_000  # lower SIDs are Talos rules

RuleState = Literal["ALERT", "BLOCK", "DROP", "REJECT", "PASS", "DISABLE", "DEFAULT"]
PolicyRef = Annotated[
    str, Field(description="Intrusion policy name or UUID (fmc_list_policies kind=intrusion)")
]
RULE_RE = re.compile(r"^\s*(?:(\d+)\s*:\s*)?(\d+)\s*$")


def rule_filter(ref: str) -> str | None:
    """'1:2000' -> 'gid:1;sid:2000', '2000' -> 'sid:2000'; None for free text."""
    m = RULE_RE.match(ref)
    if not m:
        return None
    gid, sid = m.groups()
    return f"gid:{gid};sid:{sid}" if gid else f"sid:{sid}"


def matches(rule: dict[str, Any], ref: str) -> bool:
    m = RULE_RE.match(ref)
    if not m:
        return False
    gid, sid = m.groups()
    return str(rule.get("sid")) == sid and (gid is None or str(rule.get("gid")) == gid)


def rule_row(r: dict[str, Any], *, text: bool = False) -> dict[str, Any]:
    row: dict[str, Any] = {
        "rule": r.get("name") or f"{r.get('gid')}:{r.get('sid')}",
        "msg": r.get("msg"),
        "default_state": r.get("defaultState"),
        "override_state": r.get("overrideState"),
        "custom": True if r.get("isSystemDefined") is False else None,
        "groups": [g.get("name") for g in (r.get("ruleGroups") or [])][:4] or None,
        "id": r.get("id"),
    }
    if text:
        row["rule_text"] = r.get("ruleData")
    return {k: v for k, v in row.items() if v is not None}


async def resolve_ips(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, IPS, ref, "intrusion policy", domain)


async def find_rules(
    app: FmcApp, ref: str, domain: str | None, policy_id: str | None = None, limit: int = 25
) -> tuple[list[dict[str, Any]], int]:
    """Rules matching 'gid:sid', 'sid' or text (FMC full-text search), in one policy or globally."""
    path = await app.config_path(f"{IPS}/{policy_id}/intrusionrules" if policy_id else RULES, domain)
    flt = rule_filter(ref) or f"fts:{ref.strip()}"
    page = await app.page(path, {"filter": flt}, limit=limit)
    return page.items, page.total if page.total is not None else len(page.items)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Intrusion policy summary")
    async def fmc_get_intrusion_policy(
        ctx: Context,
        policy: PolicyRef,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Summarise a Snort 3 intrusion policy: base policy, inspection mode (PREVENTION drops,
        DETECTION only alerts), how many access policies/devices use it, and every rule whose state is
        overridden in it (gid:sid, message, default vs. override). Find rules with
        fmc_find_intrusion_rules; tune them with fmc_set_intrusion_rule_state."""
        app: FmcApp = get_client(ctx)
        p = await resolve_ips(app, policy, domain)
        meta = p.get("metadata") or {}
        path = await app.config_path(f"{IPS}/{p['id']}/intrusionrules", domain)
        over = await app.all(path, {"filter": f"overrides:true;ipspolicy:{p['id']}"}, cap=MAX_OVERRIDES)
        out: dict[str, Any] = {
            "name": p.get("name"),
            "base_policy": ref_label(p.get("basePolicy") or {}) or None,
            "inspection_mode": p.get("inspectionMode"),
            "system_defined": bool(p.get("isSystemDefined")),
            "used_by": meta.get("usage"),
            "domain": (meta.get("domain") or {}).get("name"),
            "overridden_rules": [rule_row(r) for r in over.items],
            "id": p.get("id"),
        }
        if not over.complete:
            out["note"] = f"Only the first {MAX_OVERRIDES} overrides are listed."
        return object_result(out, fmt=response_format)

    @reg.read(title="Find intrusion rules")
    async def fmc_find_intrusion_rules(
        ctx: Context,
        query: Annotated[
            str,
            Field(
                description="'gid:sid' (e.g. 1:28496 or 2000:1000001 for a custom rule), a bare SID, or "
                "text matched against the rule message and body (e.g. 'Log4j')"
            ),
        ],
        policy: Annotated[
            str | None,
            Field(description="Intrusion policy: show each rule's default and override state in it"),
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=200)] = 25,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Find Snort 3 rules by gid:sid, SID or text. With `policy`, the result shows what the rule does
        in that policy (default state from the base policy, and any override). A single hit includes the
        rule text."""
        app: FmcApp = get_client(ctx)
        pid = (await resolve_ips(app, policy, domain))["id"] if policy else None
        rows, total = await find_rules(app, query, domain, pid, limit)
        out = [rule_row(r, text=len(rows) == 1) for r in rows]
        return list_result(Page(items=out, offset=0, total=total), fmt=response_format)

    @reg.write(title="Set intrusion rule state")
    async def fmc_set_intrusion_rule_state(
        ctx: Context,
        policy: PolicyRef,
        rules: Annotated[
            list[str],
            Field(
                min_length=1,
                max_length=25,
                description="Rules as 'gid:sid' (or a SID unique across gids); at most 25 per call",
            ),
        ],
        state: Annotated[
            RuleState,
            Field(
                description="New state in this policy: ALERT, BLOCK (drop + block the session), DROP, "
                "REJECT, PASS, DISABLE, or DEFAULT (remove the override: back to the base policy)"
            ),
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Override the state of Snort 3 rules in one (custom) intrusion policy, e.g. disable a rule that
        causes false positives or make a rule drop. The preview lists each rule with its default and
        current override. System policies (Balanced, Security over Connectivity, ...) can't be edited:
        create a custom one on top with fmc_create_intrusion_policy. Takes effect after a deploy."""
        app: FmcApp = get_client(ctx)
        p = await resolve_ips(app, policy, domain)
        blockers: list[str] = []
        if p.get("isSystemDefined"):
            blockers.append(
                f"{p.get('name')!r} is a system intrusion policy and read-only; create a custom policy based "
                "on it (fmc_create_intrusion_policy) and use that in the access rules."
            )
        found: list[dict[str, Any]] = []
        for ref in dict.fromkeys(rules):
            if rule_filter(ref) is None:
                raise InvalidRequest(f"{ref!r} is not a rule id; use 'gid:sid' (fmc_find_intrusion_rules).")
            hits, _ = await find_rules(app, ref, domain, p["id"], limit=5)
            hits = [h for h in hits if matches(h, ref)]  # the filter can match loosely; insist on gid/sid
            if not hits:
                raise NotFound(f"No intrusion rule {ref!r} (fmc_find_intrusion_rules).", 404)
            if len(hits) > 1:
                names = ", ".join(str(h.get("name")) for h in hits)
                raise InvalidRequest(f"{ref!r} matches several rules ({names}); use 'gid:sid'.")
            found.append(hits[0])
        new = None if state == "DEFAULT" else state
        changes = [
            {
                **rule_row(r),
                "to": f"default ({r.get('defaultState')})" if new is None else new,
            }
            for r in found
        ]
        todo = [r for r in found if r.get("overrideState") != new]
        if not todo:
            blockers.append("Nothing to change: every rule already has that state.")
        base = await app.config_path(f"{IPS}/{p['id']}/intrusionrules", domain)
        usage = (p.get("metadata") or {}).get("usage") or {}

        async def apply() -> Any:
            done: list[dict[str, Any]] = []
            try:
                for i, r in enumerate(todo):
                    try:
                        # re-read: FMC's PUT replaces the whole rule, so never send a preview-time copy
                        cur = await app.api.get(f"{base}/{r['id']}")
                        body = {k: v for k, v in editable(cur).items() if k != "overrideState"}
                        if new is not None:
                            body["overrideState"] = new
                        res = await app.api.put(f"{base}/{r['id']}", body)
                        done.append(rule_row(res if isinstance(res, dict) else cur))
                    except UpstreamError as e:
                        left = [str(x.get("name")) for x in todo[i:]]
                        changed = [str(d.get("rule")) for d in done] or "none"
                        raise UpstreamError(
                            f"Partially applied: changed {changed}; not changed {left}. Cause: {e} "
                            "Preview again to finish (rules already changed show as unchanged).",
                            e.status_code,
                        ) from e
            finally:
                app.invalidate_cache()
            return {"policy": p.get("name"), "rules": done, "next": "fmc_deploy to the devices using it"}

        return await fmc_preview(
            ctx,
            tool="fmc_set_intrusion_rule_state",
            args={"policy": policy, "rules": rules, "state": state, "domain": domain},
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Set {len(found)} rule(s) to {state} in intrusion policy {p.get('name')!r}",
                details={"rules": changes, "used_by": usage or None},
                fingerprint={
                    "policy": p["id"],
                    "rules": [(r.get("id"), r.get("defaultState"), r.get("overrideState")) for r in found],
                },
                blockers=blockers,
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=apply,
        )

    @reg.write(title="Create intrusion policy")
    async def fmc_create_intrusion_policy(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New policy name")],
        base_policy: Annotated[
            str, Field(description="System or custom intrusion policy to inherit rule states from")
        ] = "Balanced Security and Connectivity",
        inspection_mode: Annotated[
            Literal["PREVENTION", "DETECTION"],
            Field(description="PREVENTION: drop/block rules drop traffic; DETECTION: everything only alerts"),
        ] = "PREVENTION",
        description: Annotated[str | None, Field(description="Description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a custom Snort 3 intrusion policy on top of a base policy, so its rules can be tuned
        with fmc_set_intrusion_rule_state. Use it on ALLOW rules with fmc_create_access_rule /
        fmc_update_access_rule (intrusion_policy=...)."""
        app: FmcApp = get_client(ctx)
        base = await resolve_ips(app, base_policy, domain)
        blockers = []
        try:
            await resolve_ips(app, name, domain)
            blockers.append(f"An intrusion policy named {name!r} already exists.")
        except NotFound:
            pass
        body: dict[str, Any] = {
            "name": name,
            "type": "IntrusionPolicy",
            "basePolicy": {"id": base["id"], "type": "IntrusionPolicy"},
            "inspectionMode": inspection_mode,
        }
        if description:
            body["description"] = description
        path = await app.config_path(IPS, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_intrusion_policy",
            args={
                "name": name,
                "base_policy": base_policy,
                "inspection_mode": inspection_mode,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create intrusion policy {name!r} based on {base.get('name')!r} ({inspection_mode})",
                details={"body": body},
                fingerprint=base["id"],
                blockers=blockers,
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Create custom intrusion rule")
    async def fmc_create_intrusion_rule(
        ctx: Context,
        rule_text: Annotated[
            str,
            Field(
                description='Snort 3 rule, e.g. \'alert tcp any any -> $HOME_NET 8080 ( msg:"..."; '
                'content:"x"; sid:1000001; rev:1; )\'. Use SIDs from 1000000 up; FMC assigns gid 2000.'
            ),
        ],
        group: Annotated[
            str, Field(description="Custom rule group (created under 'Local Rules' if it doesn't exist)")
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a custom (local) Snort 3 rule in a custom rule group. A new rule is disabled in every
        policy until you set its state there (fmc_set_intrusion_rule_state, e.g. ALERT or DROP).
        FMC validates the rule syntax when it is created."""
        app: FmcApp = get_client(ctx)
        text = rule_text.strip()
        sid = re.search(r"\bsid\s*:\s*(\d+)", text)
        if not sid or not re.search(r"\(.*\)\s*$", text, re.S):
            raise InvalidRequest("rule_text must be a full Snort 3 rule with options in (...) and a sid:N.")
        if int(sid.group(1)) < MIN_CUSTOM_SID:
            raise InvalidRequest("Custom rules need a SID of 1000000 or more (lower SIDs belong to Talos).")
        groups = await app.all(await app.config_path(GROUPS, domain), {"filter": "isSystemDefined:false"})
        grp = next((g for g in groups.items if str(g.get("name", "")).lower() == group.lower()), None)
        blockers = []
        existing, _ = await find_rules(app, sid.group(1), domain, limit=5)
        clash = [r for r in existing if r.get("isSystemDefined") is False]
        if clash:
            blockers.append(f"A custom rule with SID {sid.group(1)} exists: {clash[0].get('name')}.")
        groups_path = await app.config_path(GROUPS, domain)
        rules_path = await app.config_path(RULES, domain)

        async def apply() -> Any:
            g = grp or await app.api.post(groups_path, {"name": group, "type": "IntrusionRuleGroup"})
            ref = {"id": g["id"], "type": "IntrusionRuleGroup", "name": g.get("name")}
            res = await applied(
                app,
                lambda: app.api.post(
                    rules_path, {"type": "IntrusionRule", "ruleData": text, "ruleGroups": [ref]}
                ),
            )
            return {
                "rule": res.get("name") if isinstance(res, dict) else None,
                "group": g.get("name"),
                "next": "fmc_set_intrusion_rule_state in a custom policy, then fmc_deploy",
            }

        return await fmc_preview(
            ctx,
            tool="fmc_create_intrusion_rule",
            args={"rule_text": rule_text, "group": group, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Create custom rule sid {sid.group(1)} in group {group!r}"
                + ("" if grp else " (new group under Local Rules)"),
                details={"rule_text": text, "group": group, "group_exists": grp is not None},
                fingerprint={"group": (grp or {}).get("id"), "clash": [r.get("id") for r in clash]},
                blockers=blockers,
                side_effects=["The rule is disabled in every policy until its state is set there."]
                + (
                    []
                    if grp
                    else ["If FMC rejects the rule, the new (empty) group stays; delete it in the UI."]
                ),
            ),
            apply=apply,
        )

    @reg.write(title="Delete custom intrusion rule")
    async def fmc_delete_intrusion_rule(
        ctx: Context,
        rule: Annotated[str, Field(description="Custom rule as 'gid:sid' (e.g. 2000:1000001)")],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a custom (local) Snort 3 rule. Talos rules can't be deleted (disable them in a policy
        with fmc_set_intrusion_rule_state instead)."""
        app: FmcApp = get_client(ctx)
        if rule_filter(rule) is None:
            raise InvalidRequest(f"{rule!r} is not a rule id; use 'gid:sid'.")
        hits, _ = await find_rules(app, rule, domain, limit=5)
        if len(hits) != 1:
            raise NotFound(f"Expected one rule {rule!r}, found {len(hits)} (use 'gid:sid').", 404)
        r = hits[0]
        blockers = []
        if r.get("isSystemDefined") is not False:
            blockers.append(f"{r.get('name')} is a Talos rule; disable it in a policy instead.")
        path = await app.config_path(f"{RULES}/{r['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_intrusion_rule",
            args={"rule": rule, "domain": domain},
            confirm=confirm,
            owned=[r],
            plan=Plan(
                f"Delete custom intrusion rule {r.get('name')}",
                details={"rule": rule_row(r, text=True)},
                fingerprint=r.get("id"),
                blockers=blockers,
                side_effects=["Policies that used it stop applying it after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )

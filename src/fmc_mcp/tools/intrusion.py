"""Intrusion (Snort 3) policy tuning (F13, first slice): read a policy and its rule overrides, find rules,
change a rule's state per policy, create a policy, and manage custom (local) rules. F97: Secure Firewall
rule recommendations (ruleRecommendation on the policy, set with ?ruleRecommendationAction=...)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from fmc_mcp._core.http import Page
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, ref_label, resolve_in, resolve_object
from fmc_mcp.tools.network_analysis import access_policies_using
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.render import object_reply

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

# Rule recommendations (F97). Our action names -> FMC's ruleRecommendationAction query value; stop_using sends
# none and only clears recommendationInUse.
RecAction = Literal["generate_and_use", "generate", "use", "refresh", "stop_using", "remove"]
REC_ACTIONS: dict[str, str | None] = {
    "generate_and_use": "GENERATE_AND_ACCEPT",
    "generate": "GENERATE",
    "use": "ACCEPT",
    "refresh": "REFRESH",
    "stop_using": None,
    "remove": "REMOVE",
}
REC_NETWORK_TYPES = ["host", "network", "network_group"]
MAX_REC_NETWORKS = 50
DISCOVERY_GUI = "Policies > Network Discovery"
REC_GUI = "Policies > Intrusion > (policy) > Snort 3 Version > Recommendations"


def snort_engine(p: dict[str, Any]) -> str | None:
    """SNORT3 or SNORT2: FMC 10.0.1 puts it in metadata.snortEngine (metadata.mappedPolicy.snortEngine is
    the engine of the mapped twin policy, not this one); the spec also has a top-level snortEngine."""
    return p.get("snortEngine") or (p.get("metadata") or {}).get("snortEngine")


def rec_time(v: Any) -> str | None:
    """lastUpdatedTime (epoch seconds; milliseconds tolerated) as ISO 8601 UTC."""
    if not isinstance(v, int | float) or v <= 0:
        return None
    secs = v / 1000 if v > 10_000_000_000 else v
    return datetime.fromtimestamp(secs, UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def recommendation_row(p: dict[str, Any]) -> dict[str, Any]:
    """A policy's rule recommendation state: off, or level, networks, last generated and in use."""
    rec = p.get("ruleRecommendation")
    if not isinstance(rec, dict) or not rec:
        return {"configured": False, "in_use": False}
    level = str(rec.get("securityLevel") or "")
    row: dict[str, Any] = {
        "configured": True,
        "in_use": bool(rec.get("recommendationInUse")),
        "security_level": int(level[-1]) if level[-1:].isdigit() else level or None,
        "networks": [
            ref_label(n) or n.get("value") for n in rec.get("networks") or [] if isinstance(n, dict)
        ],
        "accept_disabled_rules": rec.get("acceptDisabledRules"),
        "last_generated": rec_time(rec.get("lastUpdatedTime")),
    }
    return {k: v for k, v in row.items() if v is not None}


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


def policy_default(r: dict[str, Any]) -> str | None:
    """The rule's default state in the policy, i.e. what its base policy sets.

    FMC 10.0.1 fills `defaultState` with that in a policy's rule list, but GET and PUT of a single rule
    (.../intrusionrules/{id}) put the rule's own keyword there (ALERT for an `alert ...` Talos rule that
    Balanced disables). `metadata.defaultSetBy` names the base policy and its action in both answers,
    so it wins when it gives one action."""
    set_by = (r.get("metadata") or {}).get("defaultSetBy") or []
    actions = {s.get("action") for s in set_by if isinstance(s, dict) and s.get("action")}
    return actions.pop() if len(actions) == 1 else r.get("defaultState")


def rule_row(r: dict[str, Any], *, text: bool = False) -> dict[str, Any]:
    row: dict[str, Any] = {
        "rule": r.get("name") or f"{r.get('gid')}:{r.get('sid')}",
        "msg": r.get("msg"),
        "default_state": policy_default(r),
        "override_state": r.get("overrideState"),
        "custom": True if r.get("isSystemDefined") is False else None,
        "groups": [g.get("name") for g in (r.get("ruleGroups") or [])][:4] or None,
        "id": r.get("id"),
    }
    if text:
        row["rule_text"] = r.get("ruleData")
    return {k: v for k, v in row.items() if v is not None}


def usage_row(p: dict[str, Any]) -> dict[str, Any] | None:
    """Who uses the policy, from FMC's metadata.usage: counts plus the access policies by name (FMC
    10.0.1 names them only in the list answer, as `asscoiatedAcPolicies`; templates and zero-trust
    policies are kept when FMC counts any)."""
    usage = (p.get("metadata") or {}).get("usage")
    if not isinstance(usage, dict):
        return None
    row = {
        "access_policies": usage.get("accesspolicy"),
        "devices": usage.get("devices"),
        "access_policy_names": access_policies_using(p) or None,
        "device_templates": usage.get("templates") or None,
        "zero_trust_policies": usage.get("zerotrustpolicy") or None,
    }
    return {k: v for k, v in row.items() if v is not None} or None


async def resolve_ips(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, IPS, ref, "intrusion policy", domain)


async def with_usage(app: FmcApp, p: dict[str, Any], ref: str, domain: str | None) -> dict[str, Any]:
    """The policy as FMC's list answers it when it was given by UUID: FMC 10.0.1's GET of one intrusion
    policy says accesspolicy 0 / devices 0 and names no access policy, its list has the real usage."""
    if not is_uuid(ref.strip()):
        return p
    page = await app.all(await app.config_path(IPS, domain))
    return next((x for x in page.items if x.get("id") == p.get("id")), p)


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
        DETECTION only alerts), how many access policies/devices use it, rule counts per state, the
        Secure Firewall rule recommendations (level, networks, last generated, in use), and every rule
        whose state is overridden in it (gid:sid, message, default vs. override). Find rules with
        fmc_find_intrusion_rules; tune them with fmc_set_intrusion_rule_state or
        fmc_set_intrusion_recommendations."""
        app: FmcApp = get_client(ctx)
        p = await with_usage(app, await resolve_ips(app, policy, domain), policy, domain)
        one = await app.config_path(f"{IPS}/{p['id']}", domain)
        try:  # only the single GET (includeCount) has ruleRecommendation and rule counts
            detail = await app.api.get(one, params={"includeCount": "true"})
        except UpstreamError:
            detail = {}
        detail = detail if isinstance(detail, dict) else {}
        meta = p.get("metadata") or {}
        counts = (detail.get("metadata") or {}).get("ruleCount")
        path = await app.config_path(f"{IPS}/{p['id']}/intrusionrules", domain)
        over = await app.all(path, {"filter": f"overrides:true;ipspolicy:{p['id']}"}, cap=MAX_OVERRIDES)
        out: dict[str, Any] = {
            "name": p.get("name"),
            "base_policy": ref_label(p.get("basePolicy") or {}) or None,
            "inspection_mode": p.get("inspectionMode"),
            "system_defined": bool(p.get("isSystemDefined")),
            "used_by": usage_row(p),
            "domain": (meta.get("domain") or {}).get("name"),
            "snort_engine": snort_engine(detail) or snort_engine(p),
            "rule_counts": counts if isinstance(counts, dict) else None,
            "recommendations": recommendation_row(detail or p),
            "overridden_rules": [rule_row(r) for r in over.items],
            "id": p.get("id"),
        }
        for k in ("snort_engine", "rule_counts"):
            if out[k] is None:
                del out[k]
        if not over.complete:
            out["note"] = f"Only the first {MAX_OVERRIDES} overrides are listed."
        return object_reply(out, fmt=response_format)

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
        p = await with_usage(app, await resolve_ips(app, policy, domain), policy, domain)
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
                "to": f"default ({policy_default(r)})" if new is None else new,
            }
            for r in found
        ]
        todo = [r for r in found if r.get("overrideState") != new]
        if not todo:
            blockers.append("Nothing to change: every rule already has that state.")
        base = await app.config_path(f"{IPS}/{p['id']}/intrusionrules", domain)

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
                        row = rule_row(res if isinstance(res, dict) else cur)
                        if default := policy_default(r):
                            # the single-rule answer may lack defaultSetBy; the list read is right
                            row["default_state"] = default
                        done.append(row)
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
                details={"rules": changes, "used_by": usage_row(p)},
                fingerprint={
                    "policy": p["id"],
                    "rules": [(r.get("id"), r.get("defaultState"), r.get("overrideState")) for r in found],
                },
                blockers=blockers,
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=apply,
        )

    @reg.write(title="Set intrusion rule recommendations")
    async def fmc_set_intrusion_recommendations(
        ctx: Context,
        policy: PolicyRef,
        action: Annotated[
            RecAction,
            Field(
                description="generate_and_use (default): generate for the networks and level, then use them; "
                "generate: generate only (review, then action='use'); use: start using the generated ones; "
                "refresh: regenerate with the stored networks and level; stop_using: keep them but stop "
                "applying them; remove: delete the recommendations and their configuration"
            ),
        ] = "generate_and_use",
        networks: Annotated[
            list[str] | None,
            Field(
                max_length=MAX_REC_NETWORKS,
                description="Protected networks: host, network or network group objects (name or UUID). "
                "generate/generate_and_use only; default: the networks already stored on the policy",
            ),
        ] = None,
        security_level: Annotated[
            int | None,
            Field(
                ge=1,
                le=4,
                description="1 (fewest rules) to 4 (most; may enable rules that drop). generate/"
                "generate_and_use only; default: the stored level, else 2",
            ),
        ] = None,
        accept_disabled: Annotated[
            bool | None,
            Field(
                description="Also accept recommendations that DISABLE rules (fewer rules, less protection). "
                "generate/generate_and_use only; default: the stored setting, else false",
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Turn on Cisco Secure Firewall rule recommendations in a custom Snort 3 intrusion policy: FMC
        enables the rules that match the OS, services and applications network discovery saw on the
        protected networks, at a security level (1-4), and can disable rules for things they don't run.
        This is Cisco's recommended tuning step after choosing a base policy. The preview shows the
        current and new recommendation settings and the access policies/devices using the policy.
        Refused for system and Snort 2 policies. Check with fmc_get_intrusion_policy (recommendations,
        rule_counts); takes effect after a deploy."""
        app: FmcApp = get_client(ctx)
        p = await with_usage(app, await resolve_ips(app, policy, domain), policy, domain)
        one = await app.config_path(f"{IPS}/{p['id']}", domain)
        cur = await app.api.get(one)
        cur = cur if isinstance(cur, dict) else {}
        rec = cur.get("ruleRecommendation")
        stored: dict[str, Any] = rec if isinstance(rec, dict) else {}
        builds = action in ("generate_and_use", "generate")
        if not builds and (networks is not None or security_level is not None or accept_disabled is not None):
            raise InvalidRequest(
                f"networks, security_level and accept_disabled go with generate(_and_use), not {action!r}."
            )
        blockers: list[str] = []
        if p.get("isSystemDefined") or cur.get("isSystemDefined"):
            blockers.append(
                f"{p.get('name')!r} is a system intrusion policy and read-only; create a custom policy based "
                "on it (fmc_create_intrusion_policy) and use that in the access rules."
            )
        if (snort_engine(cur) or snort_engine(p)) == "SNORT2":
            blockers.append(
                f"{p.get('name')!r} is a Snort 2 policy; this tool sets Snort 3 rule recommendations only "
                "(Snort 2 'Firepower Recommendations' are set in the UI)."
            )
        refs: list[dict[str, Any]] = []
        for ref in dict.fromkeys(networks or []):
            _, obj = await resolve_object(app, ref, domain, REC_NETWORK_TYPES)
            refs.append({"id": obj["id"], "type": obj.get("type"), "name": obj.get("name")})
        new: dict[str, Any] = {}
        if builds:
            nets = refs or [
                {k: n.get(k) for k in ("id", "type", "name") if n.get(k)}
                for n in stored.get("networks") or []
                if isinstance(n, dict)
            ]
            if not nets:
                blockers.append("Name the protected networks (networks=[...]): the policy has none stored.")
            level = security_level or int(str(stored.get("securityLevel") or "LEVEL_2")[-1])
            new = {
                "securityLevel": f"LEVEL_{level}",
                "networks": nets,
                "acceptDisabledRules": bool(
                    accept_disabled
                    if accept_disabled is not None
                    else stored.get("acceptDisabledRules", False)
                ),
                "recommendationInUse": action == "generate_and_use"
                or (action == "generate" and bool(stored.get("recommendationInUse"))),
            }
        elif not stored:
            blockers.append(
                f"{p.get('name')!r} has no rule recommendations to {action.replace('_', ' ')}; generate them "
                "first (action='generate_and_use' with networks)."
            )
        elif action == "use":
            new = {**stored, "recommendationInUse": True}
        elif action == "stop_using":
            if not stored.get("recommendationInUse"):
                blockers.append("Nothing to change: the recommendations are not in use.")
            new = {**stored, "recommendationInUse": False}
        elif action == "refresh":
            new = dict(stored)
        new.pop("lastUpdatedTime", None)
        query = REC_ACTIONS[action]
        side_effects = ["Takes effect on devices after the next deployment."]
        if builds or action in ("use", "refresh"):
            side_effects.append(
                "Recommendations come from the host data network discovery collected (OS, services, client "
                f"apps). Without it (FMC UI: {DISCOVERY_GUI}, discover hosts and applications on these "
                "networks) FMC has little to match and changes few rules."
            )
        level_now = new.get("securityLevel") or stored.get("securityLevel")
        mode = cur.get("inspectionMode") or p.get("inspectionMode") or "PREVENTION"
        if level_now in ("LEVEL_3", "LEVEL_4") and action != "remove":
            side_effects.append(
                f"{level_now} enables more rules, including rules whose default action drops or blocks: "
                f"in a {mode} policy that can drop traffic that passes today. Review with "
                "fmc_get_intrusion_policy (rule_counts) before deploying."
            )
        if new.get("acceptDisabledRules"):
            side_effects.append(
                "acceptDisabledRules: rules FMC thinks don't apply to these hosts are disabled."
            )
        if action == "remove":
            side_effects.append(
                "The recommended rule states are removed: rules go back to the base policy's."
            )

        async def apply() -> Any:
            try:
                # re-read: FMC's PUT replaces the whole policy, so never send a preview-time copy
                fresh = await app.api.get(one)
                body = editable(fresh)
                body.pop("ruleRecommendation", None)
                if new:
                    body["ruleRecommendation"] = new
                res = await app.api.put(
                    one, body, params={"ruleRecommendationAction": query} if query else None
                )
                after = await app.api.get(one, params={"includeCount": "true"})
            finally:
                app.invalidate_cache()
            after = after if isinstance(after, dict) else res if isinstance(res, dict) else {}
            return {
                "policy": p.get("name"),
                "action": action,
                "recommendations": recommendation_row(after),
                "rule_counts": (after.get("metadata") or {}).get("ruleCount"),
                "next": "fmc_deploy to the devices using it",
            }

        return await fmc_preview(
            ctx,
            tool="fmc_set_intrusion_recommendations",
            args={
                "policy": policy,
                "action": action,
                "networks": networks,
                "security_level": security_level,
                "accept_disabled": accept_disabled,
                "domain": domain,
            },
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"{action.replace('_', ' ').capitalize()} rule recommendations in intrusion policy "
                f"{p.get('name')!r}"
                + (
                    f" (level {new['securityLevel'][-1]}, {len(new['networks'])} network(s))"
                    if builds and new.get("networks")
                    else ""
                ),
                details={
                    "current": recommendation_row(cur),
                    "new": recommendation_row({"ruleRecommendation": new}) if new else None,
                    "fmc_action": query or "(none: recommendationInUse=false)",
                    "used_by": usage_row(p),
                    "ui": REC_GUI,
                },
                fingerprint={"policy": p["id"], "stored": stored, "refs": [r["id"] for r in refs]},
                blockers=blockers,
                side_effects=side_effects,
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

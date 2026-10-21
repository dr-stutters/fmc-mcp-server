"""Bulk access-rule edits in one preview, and clearing hit counts (F67).

FMC 10.0.1 behaviour this relies on (recorded 2026-10-20 on an unassigned probe policy):
- `PUT accessrules?bulk=true&partialUpdate=true` with `[{id, type, <changed fields>}]` changes only the
  fields sent: name, action, conditions, the other logging flags, variable set, comments, section, category
  and position stay. `action` is not needed in a partial body; `newComments` appends to the history.
- FMC validates each merged rule ("Provide at least one destination for Connection Events to be logged
  to." when logEnd is set on a rule without sendEventsToFMC/syslog), so log= also sends sendEventsToFMC.
- A bulk PUT is atomic and its error names no rule: one bad rule rejects the whole chunk. A chunk FMC
  rejects (4xx) is split in halves until the rule is found, so every rule before it is applied and none
  after it, then the tool stops. Other errors (5xx, timeouts) stop at once: that chunk may or may not have
  been applied, and resending could append its comments twice.
- The PUT answer lists the rules in request order with metadata.ruleIndex 1 for all: positions come from
  the GET before the change.
- FMC can answer 200 and keep a field (recorded live 2026-10-21): log='none' on a MONITOR rule left logEnd and
  sendEventsToFMC on (MONITOR rules always log the connection end to FMC; its timestamp didn't move). So the
  preview leaves those two fields of MONITOR rules alone, and after the PUTs one GET of the rules checks
  every sent field: rules FMC left unchanged are reported in `kept_by_fmc`, not as applied.
- Hit counts: `DELETE policy/{accesspolicies|prefilterpolicies}/{id}/operational/hitcounts?filter=
  deviceId:{uuid};ids:{..}` (no body) answers `{}`. Without ids it clears every rule of the policy on that
  device, and the default action's counter too (recorded live 2026-10-21).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, ConfigDict, Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    UpstreamError,
    ValidationFailed,
    get_client,
)
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import RefResolver
from fmc_mcp.rules import flatten_access_rule, flatten_prefilter_rule
from fmc_mcp.tools.common import Domain, block_labels, ref_label, resolve_in, rule_changes
from fmc_mcp.tools.device_config import resolve_device
from fmc_mcp.tools.devices import DeviceRef
from fmc_mcp.tools.hygiene import unused
from fmc_mcp.tools.object_writes import editable
from fmc_mcp.tools.policies import ACCESS, PREFILTER, all_rules, resolve_policy
from fmc_mcp.tools.policy_writes import BLOCKING, LogMode, RuleAction, _log_fields
from fmc_mcp.tools.troubleshoot import HIT_ID_CHUNK, is_default_action, rule_hits, to_utc

CHUNK = 50  # rules per bulk PUT
MONITOR_KEEPS = ("logEnd", "sendEventsToFMC")  # FMC keeps these on MONITOR rules whatever is sent
MONITOR_LOG_SKIP = (
    "is a MONITOR rule: FMC always logs its connections at the end to FMC and keeps that logging (FMC 10.0.1 "
    "answered 200 to log='none' and changed nothing); leave it out of the selection"
)
MONITOR_LOG_NOTE = "MONITOR rule: FMC keeps logging the connection end to FMC; only the other fields change."
MOVE_NOTE = (
    "Rules keep their section, category and position: bulk edits don't move rules (fmc_update_access_rule "
    "move_to moves one rule within its section; cross-section moves are refused there too)."
)


class RuleSelection(BaseModel):
    """Which rules of the policy to edit; every criterion given must hold (AND)."""

    model_config = ConfigDict(extra="forbid")

    ids: list[str] | None = Field(None, description="Rule UUIDs")
    names: list[str] | None = Field(None, description="Exact rule names (case-insensitive)")
    text: str | None = Field(
        None,
        description="Any field of the rule contains this (name, object, zone, app), like "
        "fmc_list_access_rules text=",
    )
    action: RuleAction | None = Field(None, description="Rules with this action")
    enabled: bool | None = Field(None, description="Only enabled (true) or disabled (false) rules")
    section: Literal["mandatory", "default"] | None = Field(None, description="Rules in this section")
    category: str | None = Field(None, description="Rules in this category")
    zero_hits_days: int | None = Field(
        None,
        ge=1,
        le=3650,
        description="Enabled rules with no hits in this many days on the devices running the policy (as "
        "fmc_policy_audit 'unused'; refreshes the counters first)",
    )


class RuleChanges(BaseModel):
    """What to change on every selected rule (fields left out stay as they are)."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = Field(None, description="Enable (true) or disable (false)")
    log: LogMode | None = Field(
        None, description="Connection logging to FMC: none, end, begin_and_end (block rules log at the start)"
    )
    action: RuleAction | None = Field(None, description="New action")
    intrusion_policy: str | None = Field(
        None,
        description="Intrusion policy (name or UUID) for the ALLOW rules among them; removing one: "
        "fmc_update_access_rule intrusion_policy=''",
    )
    add_source_zones: list[str] | None = Field(
        None,
        description="Security zones to add to each rule's source zones (a rule with any source zone is "
        "narrowed to these)",
    )
    comment: str | None = Field(None, description="Comment added to each rule's history")


def _has_any(model: BaseModel) -> bool:
    return any(v not in (None, [], "") for v in model.model_dump().values())


def rule_text(r: dict[str, Any]) -> str:
    return str({k: v for k, v in flatten_access_rule(r).items() if k != "id"}).lower()


async def select_rules(
    ctx: Context,
    app: FmcApp,
    policy: dict[str, Any],
    rules: list[dict[str, Any]],
    sel: RuleSelection,
    domain: str | None,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """(selected rules in rule order, blockers, notes)."""
    out = sorted(rules, key=lambda r: (r.get("metadata") or {}).get("ruleIndex") or 10**9)
    blockers: list[str] = []
    notes: list[str] = []
    if sel.ids:
        have = {str(r.get("id")).lower() for r in rules}
        missing = [i for i in sel.ids if i.strip().lower() not in have]
        if missing:
            blockers.append(f"No rule with id {', '.join(missing)} in {policy.get('name')!r}.")
        want = {i.strip().lower() for i in sel.ids}
        out = [r for r in out if str(r.get("id")).lower() in want]
    if sel.names:
        have = {str(r.get("name", "")).lower() for r in rules}
        missing = [n for n in sel.names if n.strip().lower() not in have]
        if missing:
            blockers.append(f"No rule named {', '.join(map(repr, missing))} in {policy.get('name')!r}.")
        want = {n.strip().lower() for n in sel.names}
        out = [r for r in out if str(r.get("name", "")).lower() in want]
    if sel.action:
        out = [r for r in out if str(r.get("action", "")).upper() == sel.action]
    if sel.enabled is not None:
        out = [r for r in out if bool(r.get("enabled", True)) is sel.enabled]
    if sel.section:
        out = [r for r in out if str((r.get("metadata") or {}).get("section", "")).lower() == sel.section]
    if sel.category:
        cat = sel.category.strip().lower()
        out = [r for r in out if str((r.get("metadata") or {}).get("category", "")).lower() == cat]
    if sel.text:
        t = sel.text.strip().lower()
        out = [r for r in out if t in rule_text(r)]
    if sel.zero_hits_days and out:
        found, devices, hit_notes = await unused(ctx, app, policy, out, sel.zero_hits_days, True, domain)
        notes += hit_notes
        if not devices:
            blockers.append(
                f"zero_hits_days needs hit counts, but {policy.get('name')!r} runs on no device yet "
                "(assign and deploy it first)."
            )
        else:
            notes.append(f"Hit counts from: {', '.join(devices)}.")
        keys = {((f.get("rule") or {}).get("index"), (f.get("rule") or {}).get("name")) for f in found}
        out = [r for r in out if ((r.get("metadata") or {}).get("ruleIndex"), r.get("name")) in keys]
    return out, blockers, notes


def rule_partial(
    rule: dict[str, Any],
    want: RuleChanges,
    zones: list[dict[str, Any]],
    ips: dict[str, Any] | None,
) -> tuple[dict[str, Any], str | None]:
    """The partial-update fields one rule needs ({} = already as asked) or why it is skipped."""
    cur = editable(rule)
    action = want.action or str(cur.get("action", ""))
    part: dict[str, Any] = {}
    if want.enabled is not None and bool(cur.get("enabled", True)) is not want.enabled:
        part["enabled"] = want.enabled
    if want.action and want.action != cur.get("action"):
        if want.action != "ALLOW" and (cur.get("ipsPolicy") or cur.get("filePolicy")):
            return {}, (
                "has an intrusion or file policy, which only ALLOW rules take; change its action with "
                "fmc_update_access_rule (it removes them), not in bulk"
            )
        part["action"] = want.action
    if want.log is not None:
        fields = _log_fields(want.log, action)
        if action == "MONITOR":
            fields = {k: v for k, v in fields.items() if k not in MONITOR_KEEPS or v}
        for k, v in fields.items():
            if bool(cur.get(k, False)) is not v:
                part[k] = v
    elif want.action and action in BLOCKING and cur.get("logEnd"):
        part.update(logEnd=False, logBegin=True)  # FMC: "LogEnd is not supported for BLOCK Action"
    if ips is not None:
        if action != "ALLOW":
            return {}, f"is a {action} rule; intrusion policies go on ALLOW rules only"
        if (cur.get("ipsPolicy") or {}).get("id") != ips["id"]:
            part["ipsPolicy"] = ips
    if zones:
        have = list((cur.get("sourceZones") or {}).get("objects") or [])
        ids = {str(z.get("id")) for z in have}
        add = [z for z in zones if str(z.get("id")) not in ids]
        if add:
            part["sourceZones"] = {"objects": have + add}
    comment_only = not any(v not in (None, [], "") for k, v in want.model_dump().items() if k != "comment")
    if not part and monitor_log_off(action, want) and not comment_only:
        return {}, MONITOR_LOG_SKIP
    if want.comment and (part or comment_only):
        part["newComments"] = [want.comment]  # with the rule's changes, or on its own
    return part, None


def monitor_log_off(action: str, want: RuleChanges) -> bool:
    """Logging turned off on a MONITOR rule, which FMC doesn't do."""
    return action == "MONITOR" and want.log == "none"


def rule_diff(rule: dict[str, Any], part: dict[str, Any]) -> dict[str, Any]:
    cur = editable(rule)
    desired = {**cur, **{k: v for k, v in part.items() if k != "newComments"}}
    changes = rule_changes(cur, desired)
    if "sourceZones" in changes:  # labels: any -> [zones]
        changes["sourceZones"] = {
            "from": block_labels(cur.get("sourceZones")) or "any",
            "to": block_labels(desired.get("sourceZones")),
        }
    if "ipsPolicy" in part:
        for k in [k for k in changes if k.startswith("ipsPolicy")]:
            changes.pop(k)
        old = cur.get("ipsPolicy")
        changes["ipsPolicy"] = {"from": ref_label(old) if old else None, "to": ref_label(part["ipsPolicy"])}
    if part.get("newComments"):
        changes["comment"] = {"add": part["newComments"][0]}
    return changes


def _is_rejection(e: UpstreamError) -> bool:
    """FMC refused the payload (4xx): nothing of the chunk was applied, so it can be split and resent."""
    return isinstance(e, ValidationFailed) or getattr(e, "status_code", None) in (400, 409, 422)


class _Stopped(Exception):
    def __init__(self, item: dict[str, Any], error: UpstreamError, certain: bool) -> None:
        super().__init__(str(error))
        self.item, self.error, self.certain = item, error, certain


def _same(field: str, sent: Any, have: Any) -> bool:
    """Whether FMC's rule holds what was sent for one partial-update field."""
    if isinstance(sent, bool):
        return bool(have or False) is sent
    if field == "ipsPolicy":
        return str((have or {}).get("id", "")).lower() == str(sent.get("id", "")).lower()
    if field == "sourceZones":
        ids = {str(z.get("id", "")).lower() for z in (have or {}).get("objects") or []}
        return all(str(z.get("id", "")).lower() in ids for z in sent.get("objects") or [])
    return bool(have == sent)


def _shown(field: str, value: Any) -> Any:
    if field == "sourceZones":
        return block_labels(value) or "any"
    if isinstance(value, dict):
        return ref_label(value)
    return value


async def kept_by_fmc(
    app: FmcApp, path: str, bodies: list[dict[str, Any]], names: dict[str, str]
) -> tuple[list[dict[str, Any]], str | None]:
    """Re-read the rules and list those FMC left (partly) unchanged although it answered 200: one row per
    rule with the fields FMC kept. The second value says why nothing could be checked."""
    try:
        after = await all_rules(app, path)
    except UpstreamError as e:
        return [], f"Not verified: re-reading the rules failed ({e}); check with fmc_list_access_rules."
    by_id = {str(r.get("id", "")).lower(): r for r in after.items}
    out: list[dict[str, Any]] = []
    for b in bodies:
        rule = by_id.get(str(b["id"]).lower())
        if rule is None:
            continue
        fields = {
            k: {"sent": _shown(k, v), "fmc_has": _shown(k, rule.get(k))}
            for k, v in b.items()
            if k not in ("id", "type", "newComments") and not _same(k, v, rule.get(k))
        }
        if fields:
            out.append({"rule": names[b["id"]], "fields": fields})
    return out, None


async def apply_chunks(
    app: FmcApp, path: str, bodies: list[dict[str, Any]], names: dict[str, str]
) -> dict[str, Any]:
    """PUT the partial bodies in chunks; on a rejected chunk find the rule by halving, stop there."""
    done: list[dict[str, Any]] = []
    puts = 0

    async def put(items: list[dict[str, Any]]) -> None:
        nonlocal puts
        puts += 1
        await app.api.put(path, items, params={"bulk": "true", "partialUpdate": "true"})
        done.extend(items)

    async def send(items: list[dict[str, Any]]) -> None:
        try:
            await put(items)
        except UpstreamError as e:
            if not _is_rejection(e):
                raise _Stopped(items[0], e, certain=False) from e
            if len(items) == 1:
                raise _Stopped(items[0], e, certain=True) from e
            mid = len(items) // 2
            await send(items[:mid])
            await send(items[mid:])

    try:
        for i in range(0, len(bodies), CHUNK):
            await send(bodies[i : i + CHUNK])
    except _Stopped as s:
        app.invalidate_cache()
        applied = [names[b["id"]] for b in done]
        left = len(bodies) - len(done)
        detail = str(s.error)
        where = (
            f"FMC refused rule {names[s.item['id']]!r}: {detail}"
            if s.certain
            else f"FMC failed on the chunk starting at rule {names[s.item['id']]!r} ({detail}); that chunk "
            "may or may not have been applied: check with fmc_list_access_rules before repeating"
        )
        raise UpstreamError(
            f"Stopped. {where}. Applied before it: {len(applied)} rule(s)"
            + (f" ({', '.join(applied[:20])}{', ...' if len(applied) > 20 else ''})" if applied else "")
            + f"; not applied: {left}. Fix that rule (fmc_update_access_rule) and repeat the bulk edit: "
            "rules already changed show no diff.",
            getattr(s.error, "status_code", None),
        ) from s.error
    app.invalidate_cache()
    kept, unverified = await kept_by_fmc(app, path, done, names)
    kept_names = {k["rule"] for k in kept}
    out: dict[str, Any] = {
        "applied": len(done) - len(kept),
        "requests": puts,
        "rules": [names[b["id"]] for b in done if names[b["id"]] not in kept_names],
    }
    if kept:
        out["kept_by_fmc"] = kept
        out["warning"] = (
            f"FMC answered 200 but left {len(kept)} rule(s) without the change (the fields under "
            "kept_by_fmc). Check them with fmc_get_access_rule; MONITOR rules always keep their "
            "end-of-connection logging."
        )
    out["verified"] = unverified or "one GET of the policy's rules after the change"
    out["next"] = "fmc_deploy (fmc_pending_changes shows the diff); fmc_list_access_rules shows the rules"
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Bulk-edit access rules")
    async def fmc_bulk_update_access_rules(
        ctx: Context,
        policy: Annotated[str, Field(description="Access control policy name or UUID")],
        select: Annotated[
            RuleSelection,
            Field(
                description="Which rules: ids, names, text, action, enabled, section, category, "
                "zero_hits_days (all given criteria must hold), e.g. {'zero_hits_days': 90} or {'names': "
                "['a', 'b']}"
            ),
        ],
        set: Annotated[
            RuleChanges,
            Field(
                description="What to change on each: enabled, log, action, intrusion_policy, "
                "add_source_zones, comment, e.g. {'enabled': false, 'comment': 'unused 90 days'} or "
                "{'log': 'end'}"
            ),
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change many rules of an access policy in one preview and one confirm: select them (names,
        ids, text, action, enabled, section, category, or no hits in N days) and set enabled, logging,
        action, an intrusion policy, extra source zones or a comment. The preview lists every selected
        rule with its diff, rules already as asked, and rules skipped with the reason. Applied in
        partial bulk PUTs of 50 rules (only the changed fields are sent); a chunk FMC rejects is split to
        name the rule, the rules before it stay applied and the tool stops. Rules are not moved. Deploy to
        take effect. fmc_policy_audit's bulk_fixes give ready calls for its grouped findings."""
        app: FmcApp = get_client(ctx)
        if not _has_any(select):
            raise InvalidRequest(
                "select needs at least one criterion (names, ids, text, zero_hits_days, ...)."
            )
        if set.intrusion_policy is not None and not set.intrusion_policy.strip():
            raise InvalidRequest(
                "Bulk edits can't remove an intrusion policy (a partial update only sets fields); use "
                "fmc_update_access_rule intrusion_policy='' per rule."
            )
        if not _has_any(set):
            raise InvalidRequest("set needs at least one change (enabled, log, action, ...).")
        p = await resolve_policy(app, "access", policy, domain)
        path = await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain)
        rules = await all_rules(app, path)
        selected, blockers, notes = await select_rules(ctx, app, p, rules.items, select, domain)
        zones = (
            ((await RefResolver(app, domain).block(set.add_source_zones, "zone")) or {}).get("objects") or []
            if set.add_source_zones
            else []
        )
        ips = None
        if set.intrusion_policy:
            found = await resolve_in(
                app, "policy/intrusionpolicies", set.intrusion_policy, "intrusion policy", domain
            )
            ips = {"id": found["id"], "type": "IntrusionPolicy", "name": found.get("name")}
        rows: list[dict[str, Any]] = []
        bodies: list[dict[str, Any]] = []
        unchanged: list[str] = []
        skipped: list[dict[str, Any]] = []
        names: dict[str, str] = {}
        for r in selected:
            meta = r.get("metadata") or {}
            part, why = rule_partial(r, set, zones, ips)
            if why:
                skipped.append({"index": meta.get("ruleIndex"), "rule": r.get("name"), "reason": why})
                continue
            if not part:
                unchanged.append(str(r.get("name")))
                continue
            names[str(r["id"])] = str(r.get("name"))
            bodies.append({"id": r["id"], "type": "AccessRule", **part})
            row = {
                "index": meta.get("ruleIndex"),
                "rule": r.get("name"),
                "section": meta.get("section"),
                "changes": rule_diff(r, part),
            }
            if monitor_log_off(set.action or str(r.get("action", "")), set):
                row["note"] = MONITOR_LOG_NOTE
            rows.append(row)
        if not rules.complete:
            blockers.append("The policy has more rules than the scan cap; narrow the selection by ids.")
        if not selected and not blockers:
            blockers.append("No rule matches the selection.")
        elif not bodies and not blockers:
            blockers.append("Nothing to change: every selected rule is already as asked (or skipped).")
        chunks = (len(bodies) + CHUNK - 1) // CHUNK
        details: dict[str, Any] = {
            "policy": p.get("name"),
            "selected": len(selected),
            "to_change": len(bodies),
            "rules": rows,
        }
        if unchanged:
            details["already_as_asked"] = unchanged
        if skipped:
            details["skipped"] = skipped
        if notes:
            details["notes"] = notes
        details["requests"] = f"{chunks} bulk PUT(s) of up to {CHUNK} rules (partialUpdate)"
        return await fmc_preview(
            ctx,
            tool="fmc_bulk_update_access_rules",
            owned=[p],
            args={
                "policy": policy,
                "select": select.model_dump(exclude_none=True),
                "set": set.model_dump(exclude_none=True),
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Change {len(bodies)} rule(s) of {p.get('name')!r}",
                details=details,
                fingerprint={
                    "policy": p["id"],
                    "rules": [(r.get("id"), editable(r)) for r in selected],
                    "bodies": bodies,
                },
                blockers=blockers,
                side_effects=[
                    "Takes effect on devices after the next deployment.",
                    "Stops at the first rule FMC refuses; the rules before it stay changed.",
                    "Afterwards the rules are read back once: a field FMC answered 200 to but kept is "
                    "reported under kept_by_fmc, not as applied.",
                    MOVE_NOTE,
                ],
            ),
            apply=lambda: apply_chunks(app, path, bodies, names),
        )

    @reg.write(title="Clear rule hit counts", destructive=True)
    async def fmc_clear_hit_counts(
        ctx: Context,
        policy: Annotated[str, Field(description="Access control (or prefilter) policy name or UUID")],
        device: DeviceRef,
        kind: Annotated[Literal["access", "prefilter"], Field(description="Policy type")] = "access",
        rules: Annotated[
            list[str] | None,
            Field(description="Rule names, UUIDs or 1-based indexes; default: every rule of the policy"),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Reset the hit counters of a policy's rules on one device, e.g. to measure fresh after a
        cleanup. The preview first pulls the current counters from the device and lists what is lost
        (hits and last hit per rule, total). Needs a connected device; nothing in the configuration
        changes, but the history fmc_policy_audit's 'unused' check and fmc_get_hit_counts rely on is
        gone."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, kind, policy, domain)
        dev = await resolve_device(app, device, domain)
        coll, sub = (ACCESS, "accessrules") if kind == "access" else (PREFILTER, "prefilterrules")
        listing = await all_rules(app, await app.config_path(f"{coll}/{p['id']}/{sub}", domain))
        ordered = sorted(listing.items, key=lambda r: (r.get("metadata") or {}).get("ruleIndex") or 10**9)
        blockers: list[str] = []
        if rules:
            picked: list[dict[str, Any]] = []
            for ref in rules:
                t = str(ref).strip()
                hit = next(
                    (
                        r
                        for r in ordered
                        if str(r.get("id")).lower() == t.lower()
                        or str(r.get("name", "")).lower() == t.lower()
                        or (t.isdigit() and (r.get("metadata") or {}).get("ruleIndex") == int(t))
                    ),
                    None,
                )
                if hit is None:
                    blockers.append(f"No rule {t!r} in {p.get('name')!r}.")
                elif hit not in picked:
                    picked.append(hit)
            targets = picked
        else:
            targets = ordered
        if not targets and not blockers:
            blockers.append(f"{p.get('name')!r} has no rules.")
        hc_path = await app.config_path(f"{coll}/{p['id']}/operational/hitcounts", domain)
        hits: dict[str, dict[str, Any]] = {}
        notes: list[str] = []
        last = None
        # Without rule ids FMC clears "every rule of the policy on that device", and the default action's
        # counter too (recorded on 10.0.1, 2026-10-21), so the preview shows it as well.
        every_rule = kind == "access" and not rules
        if targets:
            hits, last, notes = await rule_hits(
                ctx,
                app,
                hc_path,
                [r["id"] for r in targets],
                dev["id"],
                domain,
                refresh=True,
                include_default=every_rule,
                default_action_id=(p.get("defaultAction") or {}).get("id"),
            )
        flatten = flatten_access_rule if kind == "access" else flatten_prefilter_rule
        offset = app.local_offset
        lost: list[dict[str, Any]] = []
        for r in targets:
            h = hits.get(str(r["id"])) or {}
            lost.append(
                {
                    "index": flatten(r).get("index"),
                    "rule": r.get("name"),
                    "hits": int(h.get("hitCount") or 0),
                    "last_hit": to_utc(h.get("lastHitTimeStamp"), offset),
                }
            )
        total = sum(int(x["hits"]) for x in lost)
        ids = [str(r["id"]) for r in targets]

        async def apply() -> dict[str, Any]:
            if rules:
                for i in range(0, len(ids), HIT_ID_CHUNK):
                    flt = f"deviceId:{dev['id']};ids:{','.join(ids[i : i + HIT_ID_CHUNK])}"
                    await app.api.delete(hc_path, params={"filter": flt})
            else:
                await app.api.delete(hc_path, params={"filter": f"deviceId:{dev['id']}"})
            return {
                "cleared": len(ids),
                "device": dev.get("name"),
                "next": "fmc_get_hit_counts shows the counters from zero",
            }

        details: dict[str, Any] = {
            "policy": p.get("name"),
            "device": dev.get("name"),
            "rules": len(lost),
            "hits_lost": total,
            "rules_with_hits": sum(1 for x in lost if x["hits"]),
            "counters": lost,
            "counters_fetched": to_utc(last, offset),
        }
        default = next((h for h in hits.values() if is_default_action(h)), None) if every_rule else None
        if default is not None:
            details["default_action"] = {
                "hits": int(default.get("hitCount") or 0),
                "last_hit": to_utc(default.get("lastHitTimeStamp"), offset),
                "note": "Clearing every rule resets the default action's counter too (FMC 10.0.1, seen "
                "live; not counted in hits_lost). Pass rules=[...] to keep it.",
            }
        if notes:
            details["notes"] = notes
        return await fmc_preview(
            ctx,
            tool="fmc_clear_hit_counts",
            owned=[p],
            args={"policy": policy, "device": device, "kind": kind, "rules": rules, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Clear the hit counts of {len(ids)} rule(s) of {p.get('name')!r} on {dev.get('name')}",
                details=details,
                fingerprint={"policy": p["id"], "device": dev["id"], "ids": ids, "all": not rules},
                blockers=blockers,
                side_effects=[
                    "The counters restart from zero on the device; the old values can't be restored.",
                    "fmc_policy_audit's 'unused' check judges these rules from the new counters only.",
                ],
            ),
            apply=apply,
        )

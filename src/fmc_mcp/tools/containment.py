"""Rapid threat containment: block a host by mapping its IP into a quarantine dynamic object.

Contract (used by ise-mcp-server's `ise_quarantine_host` prompt after ANC and CoA):
- `fmc_contain_host(ip, reason, confirm)` maps the IP into the quarantine dynamic object
  (FMC_QUARANTINE_OBJECT, default `mcp-quarantine`). If the object doesn't exist it is created; if no
  enabled BLOCK rule references it as a source, the preview proposes two rules at the top of the
  device's access policy (`<object>-out`: source = object, `<object>-in`: destination = object). Only
  then does the change need a deployment, and the preview says so. Mapping changes themselves reach
  the devices within seconds with no deployment.
- `fmc_release_host(ip, confirm)` removes the mapping. The object and rules stay for the next host.
- Both are idempotent: containing a contained host or releasing a free one changes nothing.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

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
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, ref_label
from fmc_mcp.tools.deploy import deployable
from fmc_mcp.tools.dynamic_objects import (
    DYNAMIC,
    NO_DEPLOY,
    mappings_of,
    normalize_ips,
    resolve_dynamic,
)
from fmc_mcp.tools.object_writes import applied
from fmc_mcp.tools.policies import ACCESS, all_rules, policy_assignments, resolve_policy

DEFAULT_OBJECT = "mcp-quarantine"
EFFECTIVE_ACTIONS = {"BLOCK", "BLOCK_RESET"}  # interactive blocks can be bypassed by the user
POLICY_SCAN_CAP = 50
# Rule conditions that would narrow a quarantine rule (it must match everything from/to the object).
CRITERIA = (
    "sourceZones",
    "destinationZones",
    "sourceNetworks",
    "destinationNetworks",
    "sourcePorts",
    "destinationPorts",
    "applications",
    "urls",
    "users",
    "vlanTags",
    "sourceSecurityGroupTags",
    "destinationSecurityGroupTags",
    "timeRangeObjects",
)

HostIp = Annotated[
    str, Field(description="IPv4/IPv6 address (or CIDR network) of the host, e.g. 10.99.1.10", min_length=2)
]
QuarantineObject = Annotated[
    str | None,
    Field(description="Quarantine dynamic object name; default FMC_QUARANTINE_OBJECT or 'mcp-quarantine'"),
]


def _one_ip(ip: str) -> str:
    ips = normalize_ips([ip])
    if len(ips) != 1:
        raise InvalidRequest("Give one IP address or network.")
    return ips[0]


def _object_name(app: FmcApp, given: str | None) -> str:
    name = (given or app.settings.quarantine_object or DEFAULT_OBJECT).strip()
    if not name or len(name) > 45:
        raise InvalidRequest("The quarantine object name must be 1-45 characters (rules add '-out'/'-in').")
    return name


def _refs(rule: dict[str, Any], field: str, obj_id: str) -> bool:
    return any(o.get("id") == obj_id for o in (rule.get(field) or {}).get("objects") or [])


def _narrowed(rule: dict[str, Any], own_field: str) -> list[str]:
    """Conditions besides the object itself that limit what the rule matches."""
    out = [f for f in CRITERIA if (rule.get(f) or {}) not in ({}, [], None)]
    other = "destinationDynamicObjects" if own_field == "sourceDynamicObjects" else "sourceDynamicObjects"
    if rule.get(other):
        out.append(other)
    return out


async def scan_quarantine(app: FmcApp, obj_id: str | None, domain: str | None) -> dict[str, Any]:
    """Fresh (uncached) scan of every access policy for rules that reference the object, with
    whether each one really blocks everything from (out) / to (in) the object: enabled, BLOCK or
    BLOCK_RESET, no other conditions, and no enabled non-block rule above it."""
    policies = await app.all(await app.config_path(ACCESS, domain), expanded=False, cap=POLICY_SCAN_CAP)
    complete = policies.complete
    rules_out: list[dict[str, Any]] = []
    names: dict[str, list[str]] = {}
    firsts: dict[str, str | None] = {}
    for pol in policies.items:
        rules = await all_rules(app, await app.config_path(f"{ACCESS}/{pol['id']}/accessrules", domain))
        complete = complete and rules.complete
        names[pol["id"]] = [str(r.get("name")) for r in rules.items]
        firsts[pol["id"]] = ((rules.items[0].get("metadata") or {}).get("section")) if rules.items else None
        open_above = False  # an enabled non-block rule sits above
        for r in rules.items:
            action = str(r.get("action", "")).upper()
            for field, side in (("sourceDynamicObjects", "out"), ("destinationDynamicObjects", "in")):
                if obj_id and _refs(r, field, obj_id):
                    problems = []
                    if not r.get("enabled", True):
                        problems.append("disabled")
                    if action not in EFFECTIVE_ACTIONS:
                        problems.append(f"action {action}")
                    if narrowed := _narrowed(r, field):
                        problems.append("also conditioned on " + ", ".join(narrowed))
                    if open_above:
                        problems.append("below an enabled non-block rule")
                    rules_out.append(
                        {
                            "policy": pol.get("name"),
                            "policy_id": pol["id"],
                            "rule": r.get("name"),
                            "index": (r.get("metadata") or {}).get("ruleIndex"),
                            "action": action,
                            "direction": side,
                            "effective": not problems,
                            "problems": problems,
                        }
                    )
            if r.get("enabled", True) and action not in EFFECTIVE_ACTIONS:
                open_above = True
    return {"rules": rules_out, "complete": complete, "rule_names": names, "first_section": firsts}


async def _assignments(app: FmcApp, domain: str | None) -> dict[str, dict[str, Any]]:
    """Access policy id -> {name, devices} for every assigned access policy."""
    out: dict[str, dict[str, Any]] = {}
    for a in await policy_assignments(app, domain):
        pol = a.get("policy") or {}
        if pol.get("type") != "AccessPolicy":
            continue
        out[pol["id"]] = {
            "name": pol.get("name"),
            "devices": [ref_label(t) for t in a.get("targets") or []],
            "device_ids": [t.get("id") for t in a.get("targets") or []],
        }
    return out


async def _deployable_ids(app: FmcApp, domain: str | None) -> set[str]:
    return {str((d.get("device") or {}).get("id")) for d in await deployable(app, domain)}


def _rule_body(name: str, reason: str) -> dict[str, Any]:
    return {
        "name": name[:50],
        "type": "AccessRule",
        "action": "BLOCK",
        "enabled": True,
        "logBegin": True,
        "logEnd": False,
        "sendEventsToFMC": True,
        "newComments": [f"Created by fmc_contain_host: {reason}"[:250]],
    }


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Contain a host (quarantine)")
    async def fmc_contain_host(
        ctx: Context,
        ip: HostIp,
        reason: Annotated[
            str,
            Field(
                description="Why (ticket, alert or ISE ANC event); shown in the preview and result",
                min_length=1,
                max_length=200,
            ),
        ],
        object: QuarantineObject = None,
        policy: Annotated[
            str | None,
            Field(
                description="Access policy for the block rules, used only if no BLOCK rule references the "
                "object yet; default: the access policy assigned to the devices (if there is exactly one)"
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Block all traffic from and to a host on the FTDs, within seconds and WITHOUT a deployment,
        by mapping its IP into the quarantine dynamic object that BLOCK rules reference (rapid threat
        containment; the FMC half of ise_quarantine_host). The preview shows the object, the rules
        and devices the mapping affects, and whether anything is missing: a missing object is created
        and missing block rules are proposed at the top of the access policy, and only that one-time
        setup needs fmc_deploy (the preview says so). Idempotent: an IP that is already contained
        changes nothing. Undo with fmc_release_host."""
        app: FmcApp = get_client(ctx)
        addr = _one_ip(ip)
        name = _object_name(app, object)
        obj: dict[str, Any] | None
        try:
            obj = await resolve_dynamic(app, name, domain)
        except NotFound:
            obj = None
        current: list[str] = []
        maps_complete = True
        if obj:
            current, maps_complete = await mappings_of(app, obj["id"], domain)
        scan = await scan_quarantine(app, obj["id"] if obj else None, domain)
        used = scan["rules"]
        blocking = [u for u in used if u["effective"]]
        blocks_out = any(u["direction"] == "out" for u in blocking)
        blocks_in = any(u["direction"] == "in" for u in blocking)
        assigned = await _assignments(app, domain)
        blockers: list[str] = []
        side_effects: list[str] = [
            f"Rule {u['policy']}/{u['rule']} references {name!r} but doesn't contain it: "
            + "; ".join(u["problems"])
            for u in used
            if not u["effective"]
        ]
        if not scan["complete"]:
            blockers.append(
                f"Only the first {POLICY_SCAN_CAP} access policies could be checked for quarantine rules; "
                "use fmc_map_dynamic_object directly."
            )
        if not maps_complete:
            blockers.append(f"{name!r} has too many mappings to check; use fmc_map_dynamic_object.")
        steps: list[str] = []
        new_rules: list[tuple[str, dict[str, Any]]] = []  # (field, body) without the object ref
        target: dict[str, Any] | None = None
        if not obj:
            steps.append(f"Create IP dynamic object {name!r}")
        if not blocks_out or not blocks_in:
            if policy:
                target = await resolve_policy(app, "access", policy, domain)
            elif len(assigned) == 1:
                pid, info = next(iter(assigned.items()))
                target = {"id": pid, "name": info["name"]}
            elif not assigned:
                blockers.append("No access policy is assigned to a device; pass `policy`.")
            else:
                names = ", ".join(str(i["name"]) for i in assigned.values())
                blockers.append(
                    f"No BLOCK rule references {name!r} and several access policies are assigned ({names}); "
                    "pass `policy` for the block rules."
                )
            if target:
                wanted = []
                if not blocks_out:
                    wanted.append(("sourceDynamicObjects", f"{name}-out"))
                if not blocks_in:
                    wanted.append(("destinationDynamicObjects", f"{name}-in"))
                taken = {n.lower() for n in scan["rule_names"].get(target["id"], [])}
                for field, rname in wanted:
                    if rname.lower() in taken:
                        blockers.append(
                            f"Policy {target['name']!r} already has a rule named {rname!r} that doesn't "
                            f"block {name!r} effectively; fix or delete it (fmc_update_access_rule / "
                            "fmc_delete_access_rule) and retry."
                        )
                        continue
                    new_rules.append((field, _rule_body(rname, reason)))
                    side = "source" if field.startswith("source") else "destination"
                    steps.append(
                        f"Add BLOCK rule {rname[:50]!r} ({side} = {name}) at the top of access policy "
                        f"{target['name']!r}"
                    )
                devs = (assigned.get(target["id"]) or {}).get("devices") or []
                side_effects.append(
                    f"The new rules need ONE deployment of {target['name']!r} "
                    f"(devices: {', '.join(devs) or 'none assigned'}) before the block works: "
                    "run fmc_deploy. "
                    "Later contain/release calls need no deployment."
                )
        already = obj is not None and addr in current
        if not already:
            steps.append(f"Map {addr} into {name!r}")
        side_effects.append(NO_DEPLOY)
        affected_policies = {u["policy"] for u in blocking} | ({target["name"]} if target else set())
        devices = sorted(
            {d for i in assigned.values() if i["name"] in affected_policies for d in i["devices"]}
        )
        if blocking:
            dev_ids = {
                d for i in assigned.values() if i["name"] in affected_policies for d in i["device_ids"]
            }
            pending = dev_ids & await _deployable_ids(app, domain)
            if pending:
                side_effects.append(
                    "Some of these devices have undeployed changes; if the block rule is among them, the "
                    "mapping has no effect there until fmc_deploy (check fmc_pending_changes)."
                )
        summary = (
            f"{addr} is already contained in {name!r}; nothing to change"
            if already and not steps
            else f"Contain {addr} ({reason})"
        )
        details: dict[str, Any] = {
            "ip": addr,
            "reason": reason,
            "object": name,
            "object_exists": obj is not None,
            "already_contained": already,
            "steps": steps or ["nothing: already contained"],
            "block_rules": blocking,
            "devices": devices,
            "deploy_needed": bool(new_rules),
        }
        if new_rules:
            details["new_rules"] = [{**body, field: {"objects": [name]}} for field, body in new_rules]
        map_path = await app.config_path("object/dynamicobjectmappings", domain)
        dyn_path = await app.config_path(DYNAMIC, domain)

        async def apply() -> Any:
            o = obj
            if o is None:
                o = await applied(
                    app,
                    lambda: app.api.post(
                        dyn_path,
                        {
                            "name": name,
                            "type": "DynamicObject",
                            "objectType": "IP",
                            "description": "Quarantine: hosts mapped here are blocked (fmc_contain_host)",
                        },
                    ),
                )
            ref = {"id": o["id"], "type": "DynamicObject", "name": name}
            created_rules: list[str] = []
            if new_rules and target:
                rules_path = await app.config_path(f"{ACCESS}/{target['id']}/accessrules", domain)
                # Top of the Mandatory section: before rule 1 if that is a Mandatory rule, else the
                # (then empty) Mandatory section. Inserted in reverse so the -out rule ends up first.
                first_mandatory = str(scan["first_section"].get(target["id"]) or "").lower() == "mandatory"
                params: dict[str, Any] = {"insertBefore": 1} if first_mandatory else {"section": "mandatory"}
                for field, body in reversed(new_rules):
                    rule = {**body, field: {"objects": [ref]}}
                    try:
                        made = await app.api.post(rules_path, rule, params=params)
                    except UpstreamError as e:
                        done = ["object " + name] if obj is None else []
                        done += [f"rule {r}" for r in created_rules]
                        raise UpstreamError(
                            f"Creating rule {body['name']!r} failed: {e}. Already created: "
                            f"{', '.join(done) or 'nothing'}. The host is NOT contained yet; fix and retry "
                            "(the retry skips what exists).",
                            e.status_code,
                        ) from e
                    app.invalidate_cache()
                    created_rules.append(str(made.get("name")))
                    params = {"insertBefore": 1}
            if not already:
                await applied(
                    app, lambda: app.api.post(map_path, {"add": [{"mappings": [addr], "dynamicObject": ref}]})
                )
            out: dict[str, Any] = {
                "ip": addr,
                "object": name,
                "contained": True,
                "already_contained": already,
                "reason": reason,
                "created_rules": list(reversed(created_rules)),
                "deploy_needed": bool(created_rules),
            }
            out["next"] = (
                f"Deploy {target['name'] if target else 'the access policy'} once (fmc_deploy); then the "
                "block is live. Verify with fmc_packet_tracer."
                if created_rules
                else "Live within seconds, no deployment. Verify with fmc_packet_tracer; undo with "
                "fmc_release_host."
            )
            return out

        return await fmc_preview(
            ctx,
            tool="fmc_contain_host",
            args={"ip": ip, "reason": reason, "object": object, "policy": policy, "domain": domain},
            confirm=confirm,
            plan=Plan(
                summary,
                details=details,
                fingerprint={
                    "object": obj and obj["id"],
                    "mapped": already,
                    "mappings": sorted(current),
                    "rules": [(u["policy_id"], u["rule"], u["direction"], u["effective"]) for u in used],
                    "target": target and target["id"],
                    "target_rules": scan["rule_names"].get(target["id"]) if target else None,
                },
                blockers=blockers,
                side_effects=side_effects,
            ),
            apply=apply,
        )

    @reg.write(title="Release a contained host")
    async def fmc_release_host(
        ctx: Context,
        ip: HostIp,
        object: QuarantineObject = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Undo fmc_contain_host: remove the host's IP from the quarantine dynamic object. Traffic is
        allowed again within seconds, with no deployment. The object and its block rules stay in
        place for the next containment. Idempotent: releasing a host that isn't contained changes
        nothing."""
        app: FmcApp = get_client(ctx)
        addr = _one_ip(ip)
        name = _object_name(app, object)
        try:
            obj: dict[str, Any] | None = await resolve_dynamic(app, name, domain)
        except NotFound:
            obj = None
        current: list[str] = []
        used: list[dict[str, Any]] = []
        if obj:
            current, _ = await mappings_of(app, obj["id"], domain)
            used = (await scan_quarantine(app, obj["id"], domain))["rules"]
        contained = obj is not None and addr in current
        map_path = await app.config_path("object/dynamicobjectmappings", domain)

        async def apply() -> Any:
            if contained and obj:
                ref = {"id": obj["id"], "type": "DynamicObject", "name": name}
                await applied(
                    app,
                    lambda: app.api.post(map_path, {"remove": [{"mappings": [addr], "dynamicObject": ref}]}),
                )
            return {"ip": addr, "object": name, "released": contained, "was_contained": contained}

        why = "no such dynamic object" if obj is None else "not mapped"
        return await fmc_preview(
            ctx,
            tool="fmc_release_host",
            args={"ip": ip, "object": object, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Release {addr} from {name!r}"
                if contained
                else f"{addr} is not contained ({why}); nothing to change",
                details={
                    "ip": addr,
                    "object": name,
                    "was_contained": contained,
                    "other_contained": [m for m in current if m != addr][:50],
                    "block_rules": used,
                },
                fingerprint={"object": obj and obj["id"], "mapped": contained},
                side_effects=[NO_DEPLOY] if contained else [],
            ),
            apply=apply,
        )

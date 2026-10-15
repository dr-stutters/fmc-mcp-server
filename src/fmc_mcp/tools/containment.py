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
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    get_client,
    preview_or_apply,
)

from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, ref_label
from fmc_mcp.tools.deploy import deployable
from fmc_mcp.tools.dynamic_objects import (
    DYNAMIC,
    NO_DEPLOY,
    mappings_of,
    normalize_ips,
    resolve_dynamic,
    rules_using,
)
from fmc_mcp.tools.object_writes import applied
from fmc_mcp.tools.policies import ACCESS, all_rules, resolve_policy
from fmc_mcp.tools.policy_writes import BLOCKING

DEFAULT_OBJECT = "mcp-quarantine"

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
    return (given or getattr(app.settings, "quarantine_object", None) or DEFAULT_OBJECT).strip()


async def _assignments(app: FmcApp, domain: str | None) -> dict[str, dict[str, Any]]:
    """Access policy id -> {name, devices} for every assigned access policy."""
    page = await app.all(await app.config_path("assignment/policyassignments", domain), cap=5000)
    out: dict[str, dict[str, Any]] = {}
    for a in page.items:
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
        used: list[dict[str, Any]] = []
        if obj:
            current, _ = await mappings_of(app, obj["id"], domain)
            used, _ = await rules_using(app, obj["id"], domain)
        blocking = [u for u in used if u["enabled"] and str(u["action"]).upper() in BLOCKING]
        blocks_out = any("source" in u["as"] for u in blocking)
        blocks_in = any("destination" in u["as"] for u in blocking)
        assigned = await _assignments(app, domain)
        blockers: list[str] = []
        side_effects: list[str] = []
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
                for field, rname in wanted:
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
            created_rules = []
            if new_rules and target:
                rules_path = await app.config_path(f"{ACCESS}/{target['id']}/accessrules", domain)
                # Insert in reverse so the -out rule ends up first.
                for field, body in reversed(new_rules):
                    existing = await all_rules(app, rules_path)
                    params: dict[str, Any] = (
                        {"insertBefore": 1} if existing.items else {"section": "mandatory"}
                    )
                    rule = {**body, field: {"objects": [ref]}}
                    made = await app.api.post(rules_path, rule, params=params)
                    app.invalidate_cache()
                    created_rules.append(made.get("name"))
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

        return await preview_or_apply(
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
                    "rules": [(u["policy"], u["rule"], u["action"], u["enabled"], u["as"]) for u in used],
                    "target": target and target["id"],
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
            used, _ = await rules_using(app, obj["id"], domain)
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
        return await preview_or_apply(
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

"""Prefilter policy writes (F20): fastpath, analyze or block traffic before Snort, and link a prefilter
policy to an access control policy."""

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
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import RefResolver
from fmc_mcp.rules import flatten_prefilter_rule
from fmc_mcp.tools.common import Domain, ref_label, resolve_in, rule_changes
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import ACCESS, PREFILTER, acp_settings_body, all_rules
from fmc_mcp.tools.policy_writes import NetsParam, PortsParam, ZonesParam

PrefilterAction = Literal["FASTPATH", "ANALYZE", "BLOCK"]
LogParam = Annotated[
    bool | None, Field(description="Log connections to FMC (at the end; BLOCK logs at the beginning)")
]
PolicyParam = Annotated[
    str, Field(description="Prefilter policy name or UUID (fmc_list_policies kind=prefilter)")
]


async def _blocks(resolver: RefResolver, given: dict[str, list[str] | None]) -> dict[str, Any]:
    """Prefilter rules match on interfaces (zones / interface groups), networks, ports and VLAN tags."""
    fields = {
        "source_interfaces": ("sourceInterfaces", "zone"),
        "destination_interfaces": ("destinationInterfaces", "zone"),
        "source_networks": ("sourceNetworks", "network"),
        "destination_networks": ("destinationNetworks", "network"),
        "source_ports": ("sourcePorts", "port"),
        "destination_ports": ("destinationPorts", "port"),
    }
    out: dict[str, Any] = {}
    for param, values in given.items():
        if values is None:
            continue
        field, kind = fields[param]
        out[field] = await resolver.block(values, kind) or {}
    return out


def _logging(log: bool | None, action: str) -> dict[str, Any]:
    if log is None:
        return {}
    if not log:
        return {"logBegin": False, "logEnd": False, "sendEventsToFMC": False}
    if action == "BLOCK":
        return {"logBegin": True, "logEnd": False, "sendEventsToFMC": True}
    return {"logBegin": False, "logEnd": True, "sendEventsToFMC": True}


async def find_prefilter_rule(
    app: FmcApp, policy: dict[str, Any], rule: str, domain: str | None
) -> dict[str, Any]:
    """One prefilter rule by UUID, name (case-insensitive) or 1-based index."""
    base = await app.config_path(f"{PREFILTER}/{policy['id']}/prefilterrules", domain)
    rules = await all_rules(app, base)
    ref = rule.strip()
    hits = [
        r
        for r in rules.items
        if r.get("id") == ref
        or str(r.get("name", "")).lower() == ref.lower()
        or (ref.isdigit() and (r.get("metadata") or {}).get("ruleIndex") == int(ref))
    ]
    if len(hits) != 1:
        raise NotFound(
            f"No single prefilter rule {rule!r} in {policy.get('name')!r} (fmc_list_prefilter_rules).", 404
        )
    return dict(hits[0])


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create prefilter policy")
    async def fmc_create_prefilter_policy(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New policy name")],
        default_action: Annotated[
            Literal["ANALYZE_TUNNELS", "BLOCK_TUNNELS"],
            Field(description="What happens to tunnel traffic (GRE, IP-in-IP, ...) no rule matches"),
        ] = "ANALYZE_TUNNELS",
        description: Annotated[str | None, Field(description="Description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a prefilter policy. Link it to an access control policy with fmc_set_prefilter_policy;
        then add rules with fmc_create_prefilter_rule."""
        app: FmcApp = get_client(ctx)
        blockers = []
        try:
            await resolve_in(app, PREFILTER, name, "prefilter policy", domain)
            blockers.append(f"A prefilter policy named {name!r} already exists.")
        except NotFound:
            pass
        body: dict[str, Any] = {
            "name": name,
            "type": "PrefilterPolicy",
            "defaultAction": {"action": default_action, "type": "PrefilterPolicyDefaultAction"},
        }
        if description:
            body["description"] = description
        path = await app.config_path(PREFILTER, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_prefilter_policy",
            args={
                "name": name,
                "default_action": default_action,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(f"Create prefilter policy {name!r}", details={"body": body}, blockers=blockers),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Link prefilter policy to access policy")
    async def fmc_set_prefilter_policy(
        ctx: Context,
        access_policy: Annotated[str, Field(description="Access control policy name or UUID")],
        prefilter_policy: PolicyParam,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make an access control policy use a prefilter policy (each ACP has exactly one; the default is
        'Default Prefilter Policy'; fmc_get_access_policy shows the current one). Takes effect on the next
        deploy of the devices using the ACP."""
        app: FmcApp = get_client(ctx)
        acp = await resolve_in(app, ACCESS, access_policy, "access policy", domain)
        pf = await resolve_in(app, PREFILTER, prefilter_policy, "prefilter policy", domain)
        path = await app.config_path(f"{ACCESS}/{acp['id']}", domain)
        cur = await app.api.get(path)
        now = cur.get("prefilterPolicySetting") or {}
        blockers = ["Nothing to change."] if now.get("id") == pf["id"] else []

        async def apply() -> Any:
            fresh = await app.api.get(path)
            body = acp_settings_body(fresh)
            body["prefilterPolicySetting"] = {
                "id": pf["id"],
                "type": "PrefilterPolicy",
                "name": pf.get("name"),
            }
            return await applied(app, lambda: app.api.put(path, body))

        return await fmc_preview(
            ctx,
            tool="fmc_set_prefilter_policy",
            args={"access_policy": access_policy, "prefilter_policy": prefilter_policy, "domain": domain},
            confirm=confirm,
            owned=[acp],
            plan=Plan(
                f"{acp.get('name')!r} uses prefilter policy {pf.get('name')!r}",
                details={"from": ref_label(now) or None, "to": pf.get("name")},
                fingerprint={"current": now.get("id"), "target": pf["id"]},
                blockers=blockers,
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=apply,
        )

    @reg.write(title="Create prefilter rule")
    async def fmc_create_prefilter_rule(
        ctx: Context,
        policy: PolicyParam,
        name: Annotated[str, Field(min_length=1, max_length=64, description="Rule name")],
        action: Annotated[
            PrefilterAction,
            Field(
                description="FASTPATH: bypass Snort (trusted elephant flows: backups, replication); "
                "ANALYZE: hand to the access policy as usual; BLOCK: drop before any inspection"
            ),
        ],
        source_interfaces: ZonesParam = None,
        destination_interfaces: ZonesParam = None,
        source_networks: NetsParam = None,
        destination_networks: NetsParam = None,
        source_ports: PortsParam = None,
        destination_ports: PortsParam = None,
        bidirectional: Annotated[
            bool, Field(description="Also match the reverse direction (FASTPATH only; needs no ports)")
        ] = False,
        log: LogParam = None,
        insert_before: Annotated[int | None, Field(ge=1, description="1-based position to insert at")] = None,
        enabled: Annotated[bool, Field(description="Create the rule enabled")] = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a prefilter rule. Prefilter runs before the access policy and Snort, on outer headers only
        (no applications, URLs or users): FASTPATH is the fast lane for trusted high-volume flows, BLOCK
        drops early. The policy must be linked to the device's access policy (fmc_set_prefilter_policy).
        Takes effect after a deploy; packet tracer then shows the PREFILTER phase."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, PREFILTER, policy, "prefilter policy", domain)
        if bidirectional and (action != "FASTPATH" or source_ports or destination_ports):
            raise InvalidRequest("bidirectional needs action FASTPATH and no ports.")
        conds = await _blocks(
            RefResolver(app, domain),
            {
                "source_interfaces": source_interfaces,
                "destination_interfaces": destination_interfaces,
                "source_networks": source_networks,
                "destination_networks": destination_networks,
                "source_ports": source_ports,
                "destination_ports": destination_ports,
            },
        )
        body: dict[str, Any] = {
            "name": name,
            "type": "PrefilterRule",
            "ruleType": "PREFILTER",
            "action": action,
            "enabled": enabled,
            "bidirectional": bidirectional,
            **{k: v for k, v in conds.items() if v},
            **_logging(log, action),
        }
        base = await app.config_path(f"{PREFILTER}/{p['id']}/prefilterrules", domain)
        existing = await all_rules(app, base)
        blockers = []
        if any(str(r.get("name", "")).lower() == name.lower() for r in existing.items):
            blockers.append(f"{p.get('name')!r} already has a rule named {name!r}.")
        if insert_before and insert_before > len(existing.items) + 1:
            blockers.append(
                f"Position {insert_before} is beyond the last rule ({len(existing.items)} rules)."
            )
        params = {"insertBefore": insert_before} if insert_before else None
        return await fmc_preview(
            ctx,
            tool="fmc_create_prefilter_rule",
            args={
                "policy": policy,
                "name": name,
                "action": action,
                "source_interfaces": source_interfaces,
                "destination_interfaces": destination_interfaces,
                "source_networks": source_networks,
                "destination_networks": destination_networks,
                "source_ports": source_ports,
                "destination_ports": destination_ports,
                "bidirectional": bidirectional,
                "log": log,
                "insert_before": insert_before,
                "enabled": enabled,
                "domain": domain,
            },
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Add prefilter rule {name!r} ({action}) to {p.get('name')!r}",
                details={
                    "rule": flatten_prefilter_rule(body),
                    "rules_now": len(existing.items),
                    "body": body,
                },
                fingerprint={"policy": p["id"], "rules": [r.get("id") for r in existing.items]},
                blockers=blockers,
                side_effects=["Takes effect on devices after the next deployment."]
                + (
                    ["FASTPATH traffic skips Snort: no intrusion or file inspection for it."]
                    if action == "FASTPATH"
                    else []
                ),
            ),
            apply=lambda: applied(app, lambda: app.api.post(base, body, params=params)),
        )

    @reg.write(title="Update prefilter rule")
    async def fmc_update_prefilter_rule(
        ctx: Context,
        policy: PolicyParam,
        rule: Annotated[str, Field(description="Rule name, UUID or 1-based index")],
        action: Annotated[PrefilterAction | None, Field(description="New action")] = None,
        enabled: Annotated[bool | None, Field(description="Enable or disable the rule")] = None,
        new_name: Annotated[str | None, Field(description="Rename the rule")] = None,
        source_interfaces: ZonesParam = None,
        destination_interfaces: ZonesParam = None,
        source_networks: NetsParam = None,
        destination_networks: NetsParam = None,
        source_ports: PortsParam = None,
        destination_ports: PortsParam = None,
        log: LogParam = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a prefilter rule: action, enabled, name, logging, or replace a condition (a given list
        replaces the old one; [] means any). The preview shows the field changes; the current rules:
        fmc_list_prefilter_rules. Takes effect after a deploy."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, PREFILTER, policy, "prefilter policy", domain)
        current = await find_prefilter_rule(app, p, rule, domain)
        desired = editable(current)
        if action:
            desired["action"] = action
        if enabled is not None:
            desired["enabled"] = enabled
        if new_name:
            desired["name"] = new_name
        conds = await _blocks(
            RefResolver(app, domain),
            {
                "source_interfaces": source_interfaces,
                "destination_interfaces": destination_interfaces,
                "source_networks": source_networks,
                "destination_networks": destination_networks,
                "source_ports": source_ports,
                "destination_ports": destination_ports,
            },
        )
        cleared: dict[str, Any] = {}
        for field, block in conds.items():
            if block:
                desired[field] = block
            elif desired.pop(field, None):  # [] = any; FMC's PUT replaces the rule, so omit the field
                cleared[field] = "any"
        act = str(desired.get("action"))
        if log is None and action and (current.get("logBegin") or current.get("logEnd")):
            log = True  # keep logging on, at the right point for the new action
        desired.update(_logging(log, act))
        blockers: list[str] = []
        if desired.get("bidirectional") and (
            act != "FASTPATH" or desired.get("sourcePorts") or desired.get("destinationPorts")
        ):
            desired["bidirectional"] = False  # FMC allows bidirectional only for FASTPATH without ports
        if new_name and new_name.lower() != str(current.get("name", "")).lower():
            base = await app.config_path(f"{PREFILTER}/{p['id']}/prefilterrules", domain)
            if any(
                str(r.get("name", "")).lower() == new_name.lower() for r in (await all_rules(app, base)).items
            ):
                blockers.append(f"{p.get('name')!r} already has a rule named {new_name!r}.")
        changes = {**rule_changes(editable(current), desired), **cleared}
        if not changes:
            blockers.append("Nothing to change.")
        path = await app.config_path(f"{PREFILTER}/{p['id']}/prefilterrules/{current['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_update_prefilter_rule",
            args={
                "policy": policy,
                "rule": rule,
                "action": action,
                "enabled": enabled,
                "new_name": new_name,
                "source_interfaces": source_interfaces,
                "destination_interfaces": destination_interfaces,
                "source_networks": source_networks,
                "destination_networks": destination_networks,
                "source_ports": source_ports,
                "destination_ports": destination_ports,
                "log": log,
                "domain": domain,
            },
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Update prefilter rule {current.get('name')!r} in {p.get('name')!r}",
                details={"changes": changes},
                fingerprint=editable(current),
                blockers=blockers,
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.put(path, desired)),
        )

    @reg.write(title="Delete prefilter rule", destructive=True)
    async def fmc_delete_prefilter_rule(
        ctx: Context,
        policy: PolicyParam,
        rule: Annotated[str, Field(description="Rule name, UUID or 1-based index")],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a prefilter rule (fmc_list_prefilter_rules shows them). Matching traffic then goes to the
        access policy (or the prefilter default action for tunnels) after the next deploy."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, PREFILTER, policy, "prefilter policy", domain)
        current = await find_prefilter_rule(app, p, rule, domain)
        path = await app.config_path(f"{PREFILTER}/{p['id']}/prefilterrules/{current['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_prefilter_rule",
            args={"policy": policy, "rule": rule, "domain": domain},
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Delete prefilter rule {current.get('name')!r} from {p.get('name')!r}",
                details={"rule": flatten_prefilter_rule(current)},
                fingerprint=editable(current),
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )

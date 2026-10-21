"""Policy write tools (preview-first): access policies and rules, NAT policies and rules."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    field_changes,
    get_client,
)
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import NETWORK_TYPES, PORT_TYPES, RefResolver, network_literal
from fmc_mcp.rule_conditions import VLAN_NOTE, ExtraConditions, filter_refs_in_rules, relabel_changes
from fmc_mcp.rules import flatten_access_rule, flatten_nat_rule, url_labels
from fmc_mcp.tools.common import Domain, block_labels, ref_label, resolve_in, rule_changes
from fmc_mcp.tools.fqdn_dns import fqdn_dns_check
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import ACCESS, NAT, all_rules, find_access_rule, resolve_policy
from fmc_mcp.url_categories import (
    UrlCategoryCondition,
    category_conditions,
    category_details,
    merge_url_block,
)

PolicyRef = Annotated[str, Field(description="Policy name or UUID")]
RuleAction = Literal["ALLOW", "TRUST", "BLOCK", "BLOCK_RESET", "MONITOR", "BLOCK_INTERACTIVE"]
LogMode = Literal["none", "end", "begin_and_end"]

# Our parameter -> (FMC rule field, resolver kind)
CONDITION_PARAMS = {
    "source_zones": ("sourceZones", "zone"),
    "destination_zones": ("destinationZones", "zone"),
    "source_networks": ("sourceNetworks", "network"),
    "destination_networks": ("destinationNetworks", "network"),
    "source_ports": ("sourcePorts", "port"),
    "destination_ports": ("destinationPorts", "port"),
    "urls": ("urls", "url"),
    "source_dynamic_objects": ("sourceDynamicObjects", "dynamic"),
    "destination_dynamic_objects": ("destinationDynamicObjects", "dynamic"),
    "users": ("users", "user"),
    "vlan_tags": ("vlanTags", "vlan"),
}

ZonesParam = Annotated[list[str] | None, Field(description="Security zone / interface group names")]
NetsParam = Annotated[
    list[str] | None,
    Field(description="Network object/group names or literals (10.1.1.5, 10.1.0.0/16, 10.1.1.1-10.1.1.9)"),
]
PortsParam = Annotated[
    list[str] | None,
    Field(description="Port object/group names or literals (tcp/443, udp/53, tcp/1000-2000, icmp, icmp/8)"),
]
UrlsParam = Annotated[
    list[str] | None, Field(description="URL object/group names or literal URLs (https://...)")
]
UrlCategoriesParam = Annotated[
    list[UrlCategoryCondition] | None,
    Field(
        description="URL categories with a reputation level, e.g. [{'category': 'Gambling'}, {'category': "
        "'Malware Sites', 'reputation': 'QUESTIONABLE'}]. Needs the URL licence on the devices "
        "(fmc_set_device_licenses). On update a given list replaces the rule's categories ([] removes "
        "them) and keeps its URL objects and literals"
    ),
]
URL_LICENCE = (
    "URL categories are matched by devices with the URL licence (fmc_set_device_licenses) once FMC's URL "
    "database is downloaded."
)
DynamicParam = Annotated[
    list[str] | None,
    Field(description="Dynamic object names (fmc_list_dynamic_objects); mappings change without a deploy"),
]
UsersParam = Annotated[
    list[str] | None,
    Field(
        description="AD/LDAP users or groups downloaded from a realm (fmc_get_realm), e.g. 'mcp-contractors' "
        "or 'realm\\name'. The access policy needs an identity policy with a rule for that realm "
        "(fmc_get_identity_policy), and the device needs a user-IP mapping source (ISE/pxGrid, passive "
        "agent, captive portal) for the rule to match traffic"
    ),
]
ApplicationsParam = Annotated[
    list[str] | None,
    Field(
        description="Applications by exact name or numeric app id (fmc_find_application), e.g. ['HTTP', "
        "'Facebook']. On update a given list replaces the rule's applications ([] removes them) and keeps "
        "its application filters"
    ),
]
AppFiltersParam = Annotated[
    list[str] | None,
    Field(
        description="Application filter names or UUIDs (fmc_find_application kind=filter; new ones with "
        "fmc_create_application_filter). FMC 10.0.1 doesn't list filters created over its API, so a name "
        "resolves only for filters this server created since it started or that a rule of the policy "
        "already uses; otherwise pass the UUID. On update a given list replaces the rule's filters and "
        "keeps its applications"
    ),
]
VlanParam = Annotated[
    list[str] | None,
    Field(
        description="802.1Q VLAN tags: VLAN tag objects/groups, or literals '10' and '100-110'. They match "
        "only traffic on inline sets, never on routed or transparent interfaces"
    ),
]
TimeRangeParam = Annotated[
    str | None,
    Field(
        description="Time range object name or UUID (fmc_create_time_range): the rule matches only while "
        "it is in effect, in the device's time zone. On update '' removes it"
    ),
]
SgtsParam = Annotated[
    list[str] | None,
    Field(
        description="Security group tags by name or tag number, e.g. ['Employees'] or ['4']: ISE SGTs "
        "(downloaded over pxGrid, fmc_get_identity_sources) or custom SGTs (only while no ISE source is "
        "enabled). Shown with their tag numbers in the preview; [] on update removes them"
    ),
]


async def identity_blockers(
    app: FmcApp, acp: dict[str, Any], users: dict[str, Any] | None, domain: str | None
) -> list[str]:
    """FMC refuses a user/group condition unless the access policy's identity policy has a rule for each
    realm involved ("At least one user ... belongs to a realm that is not assigned ...")."""
    refs = (users or {}).get("objects") or []
    realms = {str((r.get("realm") or {}).get("id")): (r.get("realm") or {}).get("name") for r in refs}
    realms.pop("None", None)
    if not realms:
        return []
    full = await app.api.get(await app.config_path(f"{ACCESS}/{acp['id']}", domain))
    idp = full.get("identityPolicySetting") or {}
    if not idp.get("id"):
        return [
            f"Access policy {acp.get('name')!r} has no identity policy, so FMC refuses user/group "
            "conditions. Create one (fmc_create_identity_policy + fmc_create_identity_rule for the "
            "realm) and select it "
            "in the access policy editor (Identity step); FMC's REST API can't set that link."
        ]
    rules = await all_rules(
        app, await app.config_path(f"policy/identitypolicies/{idp['id']}/identityrules", domain)
    )
    covered = {str((r.get("realm") or {}).get("id")) for r in rules.items}
    missing = [name or rid for rid, name in realms.items() if rid not in covered]
    if missing:
        return [
            f"Identity policy {idp.get('name')!r} has no rule for realm(s) "
            f"{', '.join(map(str, missing))}; add one with fmc_create_identity_rule first "
            "(FMC refuses the condition otherwise)."
        ]
    return []


BLOCKING = {"BLOCK", "BLOCK_RESET", "BLOCK_INTERACTIVE", "BLOCK_RESET_INTERACTIVE"}
FILE_POLICIES = "policy/filepolicies"


async def file_policy_ref(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    """The {id, type, name} reference an access rule takes for a file policy (name or UUID)."""
    fp = await resolve_in(app, FILE_POLICIES, ref, "file policy", domain)
    return {"id": fp["id"], "type": "FilePolicy", "name": fp.get("name")}


def _log_fields(log: LogMode | None, action: str | None = None) -> dict[str, Any]:
    if log is None:
        return {}
    if log == "none":
        return {"logBegin": False, "logEnd": False, "sendEventsToFMC": False}
    if str(action or "").upper() in BLOCKING:
        # A blocked connection has no end: FMC rejects logEnd on block rules ("LogEnd is not supported
        # for BLOCK Action"), so 'end' and 'begin_and_end' both mean log at the beginning.
        return {"logBegin": True, "logEnd": False, "sendEventsToFMC": True}
    return {"logBegin": log == "begin_and_end", "logEnd": True, "sendEventsToFMC": True}


def _fix_block_logging(rule: dict[str, Any]) -> None:
    """A rule switched to a block action can't keep end-of-connection logging."""
    if str(rule.get("action", "")).upper() in BLOCKING and rule.get("logEnd"):
        rule["logEnd"] = False
        rule["logBegin"] = True


async def _conditions(resolver: RefResolver, values: dict[str, list[str] | None]) -> dict[str, Any]:
    """Rule fields for the condition parameters that were given ([] clears a condition = any)."""
    out: dict[str, Any] = {}
    for param, given in values.items():
        if given is None:
            continue
        field, kind = CONDITION_PARAMS[param]
        out[field] = await resolver.block(given, kind) or {}
    return out


async def applied_rule(app: FmcApp, fn: Callable[[], Awaitable[Any]]) -> Any:
    """Run an access-rule write and return the rule as one flattened row (FMC echoes the whole
    rule with ids and empty blocks); a bulk move answers with a list."""
    result = await applied(app, fn)
    items = result.get("items") if isinstance(result, dict) and "items" in result else result
    if isinstance(items, list) and len(items) == 1:
        items = items[0]
    if isinstance(items, dict) and items.get("type") == "AccessRule":
        return {"rule": flatten_access_rule(items), "next": "fmc_deploy (fmc_pending_changes shows the diff)"}
    return result


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create access control policy")
    async def fmc_create_access_policy(
        ctx: Context,
        name: Annotated[str, Field(description="New policy name", min_length=1, max_length=64)],
        default_action: Annotated[
            Literal["BLOCK", "TRUST", "PERMIT", "NETWORK_DISCOVERY"],
            Field(description="What happens to traffic no rule matches (PERMIT = intrusion prevention)"),
        ] = "BLOCK",
        description: Annotated[str | None, Field(description="Optional description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an empty access control policy with a default action. Add rules with
        fmc_create_access_rule; it affects devices only once assigned and deployed."""
        app: FmcApp = get_client(ctx)
        body: dict[str, Any] = {
            "name": name,
            "type": "AccessPolicy",
            "defaultAction": {"action": default_action},
        }
        if description:
            body["description"] = description
        blockers = []
        try:
            await resolve_policy(app, "access", name, domain)
            blockers.append(f"An access policy named {name!r} already exists.")
        except NotFound:
            pass
        path = await app.config_path(ACCESS, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_access_policy",
            args={
                "name": name,
                "default_action": default_action,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(f"Create access policy {name!r}", details={"body": body}, blockers=blockers),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Create access rule")
    async def fmc_create_access_rule(
        ctx: Context,
        policy: PolicyRef,
        name: Annotated[
            str, Field(description="Rule name (unique in the policy)", min_length=1, max_length=50)
        ],
        action: Annotated[RuleAction, Field(description="Rule action")],
        source_zones: ZonesParam = None,
        destination_zones: ZonesParam = None,
        source_networks: NetsParam = None,
        destination_networks: NetsParam = None,
        source_ports: PortsParam = None,
        destination_ports: PortsParam = None,
        urls: UrlsParam = None,
        url_categories: UrlCategoriesParam = None,
        source_dynamic_objects: DynamicParam = None,
        destination_dynamic_objects: DynamicParam = None,
        users: UsersParam = None,
        applications: ApplicationsParam = None,
        application_filters: AppFiltersParam = None,
        vlan_tags: VlanParam = None,
        time_range: TimeRangeParam = None,
        source_sgts: SgtsParam = None,
        destination_sgts: SgtsParam = None,
        enabled: Annotated[bool, Field(description="Create the rule enabled")] = True,
        log: Annotated[
            LogMode,
            Field(description="Connection logging to FMC (block rules log at the connection start)"),
        ] = "end",
        intrusion_policy: Annotated[
            str | None,
            Field(description="Intrusion policy name for ALLOW rules (fmc_list_policies kind=intrusion)"),
        ] = None,
        file_policy: Annotated[
            str | None,
            Field(
                description="File policy for an ALLOW rule (fmc_get_file_policy): blocks or looks up the "
                "files the rule allows, with file events logged. Malware actions need the MALWARE_DEFENSE "
                "licence on the devices (fmc_set_device_licenses)"
            ),
        ] = None,
        section: Annotated[
            Literal["mandatory", "default"] | None, Field(description="Section to add to (default: Default)")
        ] = None,
        category: Annotated[
            str | None, Field(description="Existing category to add to (not with section)")
        ] = None,
        insert_before: Annotated[
            int | None,
            Field(ge=1, description="Insert before this 1-based rule index (see fmc_list_access_rules)"),
        ] = None,
        insert_after: Annotated[
            int | None, Field(ge=1, description="Insert after this 1-based rule index")
        ] = None,
        comment: Annotated[str | None, Field(description="Rule comment (kept in the rule's history)")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a rule to an access control policy at a chosen position. Conditions accept object
        names or literal values; omitted conditions mean 'any'. Layer-7 and identity conditions:
        applications and application filters, URL categories, users, VLAN tags, a time range, source and
        destination SGTs. Preview shows the rule as FMC will store it, where it lands, and
        fmc_rule_lookup-style context (rule count). Deploy to take effect."""
        app: FmcApp = get_client(ctx)
        if section and category:
            raise InvalidRequest("Give either section or category, not both.")
        if insert_before and insert_after:
            raise InvalidRequest("Give either insert_before or insert_after, not both.")
        p = await resolve_policy(app, "access", policy, domain)
        resolver = RefResolver(app, domain)
        body: dict[str, Any] = {"name": name, "type": "AccessRule", "action": action, "enabled": enabled}
        body.update(
            await _conditions(
                resolver,
                {
                    "source_zones": source_zones,
                    "destination_zones": destination_zones,
                    "source_networks": source_networks,
                    "destination_networks": destination_networks,
                    "source_ports": source_ports,
                    "destination_ports": destination_ports,
                    "urls": urls,
                    "source_dynamic_objects": source_dynamic_objects,
                    "destination_dynamic_objects": destination_dynamic_objects,
                    "users": users,
                    "vlan_tags": vlan_tags,
                },
            )
        )
        cats = await category_conditions(ctx, app, url_categories or [], domain)
        if cats:
            body["urls"] = merge_url_block(None, body.get("urls") or {}, cats)
        rules_path = await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain)
        existing = await all_rules(app, rules_path)
        extra = await ExtraConditions(app, domain).resolve(
            None,
            applications=applications,
            application_filters=application_filters,
            time_range=time_range or None,
            source_sgts=source_sgts,
            destination_sgts=destination_sgts,
            known_filters=filter_refs_in_rules(existing.items) if application_filters else None,
        )
        body.update(extra.fields)
        body = {k: v for k, v in body.items() if v not in ({}, [])}
        body.update(_log_fields(log, action))
        if intrusion_policy:
            if action != "ALLOW":
                raise InvalidRequest("An intrusion policy can only be set on ALLOW rules.")
            ips = await resolve_in(
                app, "policy/intrusionpolicies", intrusion_policy, "intrusion policy", domain
            )
            body["ipsPolicy"] = {"id": ips["id"], "type": "IntrusionPolicy", "name": ips.get("name")}
        if file_policy:
            if action != "ALLOW":
                raise InvalidRequest("A file policy can only be set on ALLOW rules.")
            body["filePolicy"] = await file_policy_ref(app, file_policy, domain)
            body["logFiles"] = log != "none"
        if comment:
            body["newComments"] = [comment]
        params: dict[str, Any] = {}
        if section:
            params["section"] = section
        if category:
            params["category"] = category
        if insert_before:
            params["insertBefore"] = insert_before
        elif insert_after:
            params["insertAfter"] = insert_after
        blockers = await identity_blockers(app, p, body.get("users"), domain)
        if any(str(r.get("name", "")).lower() == name.lower() for r in existing.items):
            blockers.append(f"Policy {p.get('name')!r} already has a rule named {name!r}.")
        count = len(existing.items)
        for idx in (insert_before, insert_after):
            if idx and idx > count:
                blockers.append(f"Position {idx} is beyond the last rule ({count} rules).")
        where = (
            f"before rule {insert_before}"
            if insert_before
            else f"after rule {insert_after}"
            if insert_after
            else f"at the end of the {category or section or 'default'} section"
        )
        details: dict[str, Any] = {
            "rule": flatten_access_rule(body, extra.tags),
            "position": where,
            "rules_now": count,
        }
        if cats:
            details["url_categories"] = category_details(cats, action)
        details.update(extra.details)
        details.update(await fqdn_dns_check(app, body, domain, policy=p))
        plan = Plan(
            f"Add {action} rule {name!r} to {p.get('name')!r} {where}",
            details={**details, "body": body},
            fingerprint={"policy": p["id"], "rules": [r.get("id") for r in existing.items], "body": body},
            blockers=blockers,
            side_effects=extra.warnings
            + ["Takes effect on devices after the next deployment."]
            + ([URL_LICENCE] if cats else [])
            + extra.notes
            + ([VLAN_NOTE] if body.get("vlanTags") else []),
        )
        return await fmc_preview(
            ctx,
            tool="fmc_create_access_rule",
            owned=[p],
            args={
                "policy": policy,
                "name": name,
                "action": action,
                "source_zones": source_zones,
                "destination_zones": destination_zones,
                "source_networks": source_networks,
                "destination_networks": destination_networks,
                "source_ports": source_ports,
                "destination_ports": destination_ports,
                "urls": urls,
                "url_categories": _dump(url_categories),
                "source_dynamic_objects": source_dynamic_objects,
                "destination_dynamic_objects": destination_dynamic_objects,
                "users": users,
                "applications": applications,
                "application_filters": application_filters,
                "vlan_tags": vlan_tags,
                "time_range": time_range,
                "source_sgts": source_sgts,
                "destination_sgts": destination_sgts,
                "enabled": enabled,
                "log": log,
                "intrusion_policy": intrusion_policy,
                "file_policy": file_policy,
                "section": section,
                "category": category,
                "insert_before": insert_before,
                "insert_after": insert_after,
                "comment": comment,
                "domain": domain,
            },
            confirm=confirm,
            plan=plan,
            apply=lambda: applied_rule(app, lambda: app.api.post(rules_path, body, params=params)),
        )

    @reg.write(title="Update access rule")
    async def fmc_update_access_rule(
        ctx: Context,
        policy: PolicyRef,
        rule: Annotated[str, Field(description="Rule name, UUID or 1-based index")],
        new_name: Annotated[str | None, Field(description="Rename the rule")] = None,
        action: Annotated[RuleAction | None, Field(description="New action")] = None,
        enabled: Annotated[bool | None, Field(description="Enable or disable the rule")] = None,
        source_zones: ZonesParam = None,
        destination_zones: ZonesParam = None,
        source_networks: NetsParam = None,
        destination_networks: NetsParam = None,
        source_ports: PortsParam = None,
        destination_ports: PortsParam = None,
        urls: UrlsParam = None,
        url_categories: UrlCategoriesParam = None,
        source_dynamic_objects: DynamicParam = None,
        destination_dynamic_objects: DynamicParam = None,
        users: UsersParam = None,
        applications: ApplicationsParam = None,
        application_filters: AppFiltersParam = None,
        vlan_tags: VlanParam = None,
        time_range: TimeRangeParam = None,
        source_sgts: SgtsParam = None,
        destination_sgts: SgtsParam = None,
        log: Annotated[LogMode | None, Field(description="Connection logging to FMC")] = None,
        intrusion_policy: Annotated[
            str | None,
            Field(
                description="Intrusion policy for an ALLOW rule (name or UUID); '' removes it. The devices "
                "need the IPS licence (fmc_set_device_licenses)."
            ),
        ] = None,
        file_policy: Annotated[
            str | None,
            Field(
                description="File policy for an ALLOW rule (name or UUID, fmc_get_file_policy); '' removes "
                "it. File events are logged unless log='none'. Malware actions need the MALWARE_DEFENSE "
                "licence."
            ),
        ] = None,
        move_to: Annotated[
            int | None, Field(ge=1, description="Move the rule so it sits at this 1-based index")
        ] = None,
        comment: Annotated[str | None, Field(description="Add a comment to the rule's history")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change an access rule: rename, action, enable/disable, logging, replace any condition (a
        given list replaces the old one; [] means any) including applications, application filters, URL
        categories, users, VLAN tags, the time range ('' removes it) and SGTs, add a comment, or move it to
        another position. Preview shows the field changes and the old/new index."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        current = await find_access_rule(app, p, rule, domain)
        desired = editable(current)
        if new_name:
            desired["name"] = new_name
        if action:
            desired["action"] = action
            if action != "ALLOW":
                desired.pop("ipsPolicy", None)
                if desired.pop("filePolicy", None):
                    desired["logFiles"] = False  # no file policy, no file events
        if enabled is not None:
            desired["enabled"] = enabled
        removed_ips = desired.pop("ipsPolicy", None) if intrusion_policy == "" else None
        if intrusion_policy:
            if desired.get("action") != "ALLOW":
                raise InvalidRequest("An intrusion policy can only be set on ALLOW rules.")
            ips = await resolve_in(
                app, "policy/intrusionpolicies", intrusion_policy, "intrusion policy", domain
            )
            desired["ipsPolicy"] = {"id": ips["id"], "type": "IntrusionPolicy", "name": ips.get("name")}
        removed_file = desired.pop("filePolicy", None) if file_policy == "" else None
        if removed_file:
            desired["logFiles"] = False
        if file_policy:
            if desired.get("action") != "ALLOW":
                raise InvalidRequest("A file policy can only be set on ALLOW rules.")
            desired["filePolicy"] = await file_policy_ref(app, file_policy, domain)
            desired["logFiles"] = log != "none"
        new_conditions = await _conditions(
            RefResolver(app, domain),
            {
                "source_zones": source_zones,
                "destination_zones": destination_zones,
                "source_networks": source_networks,
                "destination_networks": destination_networks,
                "source_ports": source_ports,
                "destination_ports": destination_ports,
                "urls": urls,
                "source_dynamic_objects": source_dynamic_objects,
                "destination_dynamic_objects": destination_dynamic_objects,
                "users": users,
                "vlan_tags": vlan_tags,
            },
        )
        cats = None if url_categories is None else await category_conditions(ctx, app, url_categories, domain)
        extra = await ExtraConditions(app, domain).resolve(
            current,
            applications=applications,
            application_filters=application_filters,
            time_range=time_range,
            source_sgts=source_sgts,
            destination_sgts=destination_sgts,
        )
        for field, value in extra.fields.items():
            if value:
                desired[field] = value
            else:  # nothing left = any: FMC's PUT replaces the rule, so omit the field
                desired.pop(field, None)
        if cats is not None or "urls" in new_conditions:
            # objects/literals and categories share the urls block: replace only the part that was given
            new_conditions["urls"] = merge_url_block(current.get("urls"), new_conditions.get("urls"), cats)
        cleared: dict[str, Any] = {}
        if removed_ips:
            cleared["ipsPolicy"] = {"from": ref_label(removed_ips), "to": None, "removed": True}
        if removed_file:
            cleared["filePolicy"] = {"from": ref_label(removed_file), "to": None, "removed": True}
        for field, block in new_conditions.items():
            if block:
                desired[field] = block
            elif desired.pop(field, None):  # [] = any: FMC's PUT replaces the rule, so omit the field
                labels = url_labels if field == "urls" else block_labels
                cleared[field] = {"from": labels(current.get(field)), "to": "any"}
        desired.update(_log_fields(log, desired.get("action")))
        _fix_block_logging(desired)
        desired.pop("commentHistoryList", None)
        if comment:
            desired["newComments"] = [comment]
        old_index = (current.get("metadata") or {}).get("ruleIndex")
        base = await app.config_path(f"{ACCESS}/{p['id']}/accessrules", domain)
        changes = relabel_changes(
            {**rule_changes(editable(current), desired), **cleared}, editable(current), desired, extra.tags
        )
        changes.pop("commentHistoryList", None)
        details: dict[str, Any] = {"rule": current.get("name"), "index": old_index, "changes": changes}
        if cats:
            details["url_categories"] = category_details(cats, desired.get("action"))
        details.update(extra.details)
        blockers = await identity_blockers(app, p, new_conditions.get("users"), domain)
        order = await all_rules(app, base)
        if move_to:
            total = len(order.items)
            if move_to > total:
                blockers.append(f"move_to {move_to} is beyond the last rule ({total} rules).")
            else:
                target = next(
                    (r for r in order.items if (r.get("metadata") or {}).get("ruleIndex") == move_to), None
                )
                here = (current.get("metadata") or {}).get("section")
                there = (target or {}).get("metadata", {}).get("section")
                if target is not None and here != there:
                    blockers.append(
                        f"Rule {move_to} is in the {there} section and this rule is in {here}; moves stay "
                        "within a section (delete and re-create the rule to change section)."
                    )
            details["move"] = f"{old_index} -> {move_to}"
        if not changes and not (move_to and move_to != old_index):
            blockers.append("Nothing to change.")

        async def apply() -> Any:
            if move_to and move_to != old_index:
                # FMC moves rules through the bulk PUT with an insert position.
                params: dict[str, Any] = {"bulk": "true"}
                if old_index is not None and move_to > old_index:
                    params["insertAfter"] = move_to
                else:
                    params["insertBefore"] = move_to
                return await app.api.put(base, [desired], params=params)
            return await app.api.put(f"{base}/{current['id']}", desired)

        details.update(await fqdn_dns_check(app, desired, domain, policy=p))
        return await fmc_preview(
            ctx,
            tool="fmc_update_access_rule",
            owned=[p],
            args={
                "policy": policy,
                "rule": rule,
                "new_name": new_name,
                "action": action,
                "enabled": enabled,
                "source_zones": source_zones,
                "destination_zones": destination_zones,
                "source_networks": source_networks,
                "destination_networks": destination_networks,
                "source_ports": source_ports,
                "destination_ports": destination_ports,
                "urls": urls,
                "url_categories": _dump(url_categories),
                "source_dynamic_objects": source_dynamic_objects,
                "destination_dynamic_objects": destination_dynamic_objects,
                "users": users,
                "applications": applications,
                "application_filters": application_filters,
                "vlan_tags": vlan_tags,
                "time_range": time_range,
                "source_sgts": source_sgts,
                "destination_sgts": destination_sgts,
                "log": log,
                "intrusion_policy": intrusion_policy,
                "file_policy": file_policy,
                "move_to": move_to,
                "comment": comment,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Update rule {current.get('name')!r} in {p.get('name')!r}",
                details=details,
                # rule content, its position and the policy's rule order: a move is index-based
                fingerprint={
                    "rule": editable(current),
                    "index": old_index,
                    "order": [r.get("id") for r in order.items],
                    "desired": desired,
                },
                blockers=blockers,
                side_effects=extra.warnings
                + ["Takes effect on devices after the next deployment."]
                + ([URL_LICENCE] if cats else [])
                + extra.notes
                + ([VLAN_NOTE] if new_conditions.get("vlanTags") else []),
            ),
            apply=lambda: applied_rule(app, apply),
        )

    @reg.write(title="Delete access rule", destructive=True)
    async def fmc_delete_access_rule(
        ctx: Context,
        policy: PolicyRef,
        rule: Annotated[str, Field(description="Rule name, UUID or 1-based index")],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete one rule from an access control policy. Preview shows the rule being removed; traffic
        it matched falls through to later rules after the next deployment."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "access", policy, domain)
        current = await find_access_rule(app, p, rule, domain)
        path = await app.config_path(f"{ACCESS}/{p['id']}/accessrules/{current['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_access_rule",
            owned=[p],
            args={"policy": policy, "rule": rule, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete rule {current.get('name')!r} from {p.get('name')!r}",
                details={"rule": flatten_access_rule(current)},
                fingerprint=editable(current),
                side_effects=["Matching traffic falls through to later rules after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )

    @reg.write(title="Create NAT policy")
    async def fmc_create_nat_policy(
        ctx: Context,
        name: Annotated[
            str, Field(description="New Threat Defense NAT policy name", min_length=1, max_length=64)
        ],
        description: Annotated[str | None, Field(description="Optional description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an empty Threat Defense NAT policy. Add rules with fmc_create_nat_rule; assign it to
        devices and deploy for it to take effect."""
        app: FmcApp = get_client(ctx)
        body: dict[str, Any] = {"name": name, "type": "FTDNatPolicy"}
        if description:
            body["description"] = description
        blockers = []
        try:
            await resolve_policy(app, "nat", name, domain)
            blockers.append(f"A NAT policy named {name!r} already exists.")
        except NotFound:
            pass
        path = await app.config_path(NAT, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_nat_policy",
            args={"name": name, "description": description, "domain": domain},
            confirm=confirm,
            plan=Plan(f"Create NAT policy {name!r}", details={"body": body}, blockers=blockers),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Create NAT rule")
    async def fmc_create_nat_rule(
        ctx: Context,
        policy: PolicyRef,
        kind: Annotated[
            Literal["auto", "manual"], Field(description="auto (object) NAT or manual (twice) NAT")
        ],
        original_source: Annotated[
            str, Field(description="Original source network object name/UUID (or literal)")
        ],
        translated_source: Annotated[
            str | None,
            Field(
                description="Translated source object, or 'interface' for interface PAT; omit for identity"
            ),
        ] = None,
        nat_type: Annotated[
            Literal["STATIC", "DYNAMIC"], Field(description="Static or dynamic NAT")
        ] = "STATIC",
        original_destination: Annotated[
            str | None, Field(description="Manual NAT: original destination")
        ] = None,
        translated_destination: Annotated[
            str | None, Field(description="Manual NAT: translated destination")
        ] = None,
        original_port: Annotated[
            str | None,
            Field(description="Auto NAT: 'tcp/80'; manual NAT: original destination port object"),
        ] = None,
        translated_port: Annotated[
            str | None,
            Field(description="Auto NAT: 'tcp/8080'; manual NAT: translated destination port object"),
        ] = None,
        source_interface: Annotated[
            str | None, Field(description="Source security zone / interface group")
        ] = None,
        destination_interface: Annotated[
            str | None, Field(description="Destination security zone / interface group")
        ] = None,
        section: Annotated[
            Literal["before_auto", "after_auto"], Field(description="Manual NAT section")
        ] = "before_auto",
        target_index: Annotated[
            int | None, Field(ge=1, description="Manual NAT: position in the section")
        ] = None,
        enabled: Annotated[bool, Field(description="Manual NAT: create enabled")] = True,
        description: Annotated[str | None, Field(description="Manual NAT: rule description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add an auto (object) NAT or manual (twice) NAT rule to a Threat Defense NAT policy. Network
        fields take object names/UUIDs (create objects for raw addresses first); 'interface' as the
        translated source means interface PAT (requires a destination interface). Preview
        shows the rule as FMC will store it."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "nat", policy, domain)
        res = RefResolver(app, domain)

        async def net(v: str | None, what: str) -> dict[str, Any] | None:
            if not v:
                return None
            if network_literal(v) is not None and not is_uuid(v):
                raise InvalidRequest(f"{what}: NAT rules need network objects; create one for {v!r} first.")
            return await res.single(v, NETWORK_TYPES, what)

        body: dict[str, Any] = {"natType": nat_type}
        if source_interface:
            body["sourceInterface"] = await res.single(
                source_interface, ["security_zone", "interface_group"], "zone"
            )
        if destination_interface:
            body["destinationInterface"] = await res.single(
                destination_interface, ["security_zone", "interface_group"], "zone"
            )
        iface = (translated_source or "").lower() == "interface"
        if iface and not destination_interface:
            raise InvalidRequest("Interface PAT needs destination_interface.")
        if kind == "auto":
            body["type"] = "FTDAutoNatRule"
            body["originalNetwork"] = await net(original_source, "original_source")
            if iface:
                body["interfaceInTranslatedNetwork"] = True
            elif translated_source:
                body["translatedNetwork"] = await net(translated_source, "translated_source")
            if original_port or translated_port:
                if not (original_port and translated_port):
                    raise InvalidRequest(
                        "Auto NAT port translation needs both original_port and translated_port."
                    )
                (op, oport), (tp, tport) = _proto_port(original_port), _proto_port(translated_port)
                if op != tp:
                    raise InvalidRequest("original_port and translated_port must use the same protocol.")
                body.update(serviceProtocol=op, originalPort=oport, translatedPort=tport)
            path = await app.config_path(f"{NAT}/{p['id']}/autonatrules", domain)
            params: dict[str, Any] = {}
        else:
            body.update(type="FTDManualNatRule", enabled=enabled)
            body["originalSource"] = await net(original_source, "original_source")
            if iface:
                body["interfaceInTranslatedSource"] = True
            elif translated_source:
                body["translatedSource"] = await net(translated_source, "translated_source")
            if original_destination:
                body["originalDestination"] = await net(original_destination, "original_destination")
            if translated_destination:
                body["translatedDestination"] = await net(translated_destination, "translated_destination")
            if original_port:
                body["originalDestinationPort"] = await res.single(original_port, PORT_TYPES, "original_port")
            if translated_port:
                body["translatedDestinationPort"] = await res.single(
                    translated_port, PORT_TYPES, "translated_port"
                )
            if description:
                body["description"] = description
            path = await app.config_path(f"{NAT}/{p['id']}/manualnatrules", domain)
            params = {"section": section}
            if target_index:
                params["targetIndex"] = target_index
        if kind == "auto" and not (iface or translated_source):
            raise InvalidRequest("Auto NAT needs translated_source (an object or 'interface').")
        where = (
            f"{section} section" + (f" at {target_index}" if target_index else "")
            if kind == "manual"
            else "auto NAT"
        )
        return await fmc_preview(
            ctx,
            tool="fmc_create_nat_rule",
            owned=[p],
            args={
                "policy": policy,
                "kind": kind,
                "original_source": original_source,
                "translated_source": translated_source,
                "nat_type": nat_type,
                "original_destination": original_destination,
                "translated_destination": translated_destination,
                "original_port": original_port,
                "translated_port": translated_port,
                "source_interface": source_interface,
                "destination_interface": destination_interface,
                "section": section,
                "target_index": target_index,
                "enabled": enabled,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Add {kind} {nat_type} NAT rule to {p.get('name')!r} ({where})",
                details={"rule": flatten_nat_rule(body), "body": body},
                fingerprint={"policy": p["id"], "body": body},
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body, params=params)),
        )

    @reg.write(title="Update NAT rule")
    async def fmc_update_nat_rule(
        ctx: Context,
        policy: PolicyRef,
        rule_id: Annotated[str, Field(description="NAT rule UUID (from fmc_list_nat_rules)")],
        enabled: Annotated[bool | None, Field(description="Manual NAT: enable or disable")] = None,
        translated_source: Annotated[str | None, Field(description="New translated source object")] = None,
        original_source: Annotated[str | None, Field(description="New original source object")] = None,
        description: Annotated[str | None, Field(description="Manual NAT: new description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a NAT rule: enable/disable or describe a manual rule, or point it at a different
        original/translated source object. Preview shows the field changes."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "nat", policy, domain)
        current, path = await _nat_rule(app, p, rule_id, domain)
        auto = current.get("type") == "FTDAutoNatRule"
        desired = editable(current)
        res = RefResolver(app, domain)
        if enabled is not None:
            if auto:
                raise InvalidRequest("Auto NAT rules can't be disabled; delete the rule instead.")
            desired["enabled"] = enabled
        if description is not None:
            desired["description"] = description
        if original_source:
            desired["originalNetwork" if auto else "originalSource"] = await res.single(
                original_source, NETWORK_TYPES, "original_source"
            )
        if translated_source:
            desired["translatedNetwork" if auto else "translatedSource"] = await res.single(
                translated_source, NETWORK_TYPES, "translated_source"
            )
        changes = field_changes(editable(current), desired, replace=True)
        return await fmc_preview(
            ctx,
            tool="fmc_update_nat_rule",
            owned=[p],
            args={
                "policy": policy,
                "rule_id": rule_id,
                "enabled": enabled,
                "translated_source": translated_source,
                "original_source": original_source,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Update NAT rule {rule_id} in {p.get('name')!r}",
                details={"rule": flatten_nat_rule(current), "changes": changes},
                fingerprint=editable(current),
                blockers=[] if changes else ["Nothing to change."],
            ),
            apply=lambda: applied(app, lambda: app.api.put(path, desired)),
        )

    @reg.write(title="Delete NAT rule", destructive=True)
    async def fmc_delete_nat_rule(
        ctx: Context,
        policy: PolicyRef,
        rule_id: Annotated[str, Field(description="NAT rule UUID (from fmc_list_nat_rules)")],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete one NAT rule from a Threat Defense NAT policy. Preview shows the rule being removed."""
        app: FmcApp = get_client(ctx)
        p = await resolve_policy(app, "nat", policy, domain)
        current, path = await _nat_rule(app, p, rule_id, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_nat_rule",
            owned=[p],
            args={"policy": policy, "rule_id": rule_id, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete NAT rule {rule_id} from {p.get('name')!r}",
                details={"rule": flatten_nat_rule(current)},
                fingerprint=editable(current),
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )


def _dump(items: list[UrlCategoryCondition] | None) -> list[dict[str, Any]] | None:
    return None if items is None else [i.model_dump() for i in items]


def _proto_port(text: str) -> tuple[str, int]:
    proto, _, port = text.strip().lower().partition("/")
    if proto not in ("tcp", "udp") or not port.isdigit():
        raise InvalidRequest(f"Use 'tcp/80' or 'udp/53' for NAT ports, got {text!r}")
    return proto.upper(), int(port)


async def _nat_rule(
    app: FmcApp, policy: dict[str, Any], rule_id: str, domain: str | None
) -> tuple[dict[str, Any], str]:
    """A NAT rule (auto or manual) by UUID and the path to PUT/DELETE it."""
    if not is_uuid(rule_id):
        raise InvalidRequest("NAT rules have no names; pass the rule UUID from fmc_list_nat_rules.")
    for kind in ("manualnatrules", "autonatrules"):
        path = await app.config_path(f"{NAT}/{policy['id']}/{kind}/{rule_id}", domain)
        try:
            rule: dict[str, Any] = await app.api.get(path)
        except NotFound:
            continue
        return rule, path
    raise NotFound(f"No NAT rule {rule_id} in {policy.get('name')!r}.", 404)

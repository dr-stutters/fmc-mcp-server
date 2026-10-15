"""Decryption policy (F13, slice 2): read decryption policies and their rules, create a policy, add or
delete do-not-decrypt / block rules (exempting banking or health sites is the frequent ask), and link a
decryption policy to an access control policy."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
    object_result,
)
from stutters_mcp_core.http import page_of

from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import RefResolver
from fmc_mcp.tools.common import Domain, block_labels, ref_label, resolve_in
from fmc_mcp.tools.object_writes import applied
from fmc_mcp.tools.policies import ACCESS, acp_settings_body, all_rules
from fmc_mcp.tools.policy_writes import NetsParam, PortsParam, UrlsParam, ZonesParam

DECRYPTION = "policy/decryptionpolicies"
PolicyRef = Annotated[str, Field(description="Decryption policy name or UUID")]


def rule_row(r: dict[str, Any]) -> dict[str, Any]:
    meta = r.get("metadata") or {}
    row = {
        "index": r.get("ruleIndex") or meta.get("ruleIndex"),
        "name": r.get("name"),
        "action": r.get("ruleAction"),
        "enabled": r.get("enabled"),
        "src_zones": block_labels(r.get("sourceZones")) or None,
        "dst_zones": block_labels(r.get("destinationZones")) or None,
        "src_networks": block_labels(r.get("sourceNetworks")) or None,
        "dst_networks": block_labels(r.get("destinationNetworks")) or None,
        "dst_ports": block_labels(r.get("destinationPorts")) or None,
        "urls": block_labels(r.get("urls")) or None,
        "id": r.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Decryption policies")
    async def fmc_get_decryption_policy(
        ctx: Context,
        policy: Annotated[
            str | None, Field(description="Decryption policy name or UUID; omit to list all")
        ] = None,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List decryption (TLS/SSL) policies, or show one: mode, default action, and its rules in order
        (action such as DO_NOT_DECRYPT, DECRYPT_RESIGN or BLOCK, with zones, networks, ports and URLs)."""
        app: FmcApp = get_client(ctx)
        if not policy:
            page = await app.all(await app.config_path(DECRYPTION, domain))
            rows = [
                {
                    "name": p.get("name"),
                    "mode": p.get("mode"),
                    "default_action": (p.get("defaultAction") or {}).get("policyAction"),
                    "id": p.get("id"),
                }
                for p in page.items
            ]
            return list_result(page_of(rows, limit=1000, offset=0), fmt=response_format)
        p = await resolve_in(app, DECRYPTION, policy, "decryption policy", domain)
        rules = await all_rules(
            app, await app.config_path(f"{DECRYPTION}/{p['id']}/decryptionpolicyrules", domain)
        )
        out = {
            "name": p.get("name"),
            "mode": p.get("mode"),
            "default_action": (p.get("defaultAction") or {}).get("policyAction"),
            "rules": [rule_row(r) for r in rules.items],
            "id": p.get("id"),
        }
        return object_result(out, fmt=response_format)

    @reg.write(title="Create decryption policy")
    async def fmc_create_decryption_policy(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New policy name")],
        description: Annotated[str | None, Field(description="Description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a decryption policy (expert mode, default action do-not-decrypt, Cisco trusted CAs). Add
        rules with fmc_create_decryption_rule and link it with fmc_set_decryption_policy. Decrypt-resign
        rules need an internal CA on FMC and are left to the FMC UI."""
        app: FmcApp = get_client(ctx)
        blockers = []
        try:
            await resolve_in(app, DECRYPTION, name, "decryption policy", domain)
            blockers.append(f"A decryption policy named {name!r} already exists.")
        except NotFound:
            pass
        body: dict[str, Any] = {
            "name": name,
            "type": "DecryptionPolicy",
            "defaultAction": {"policyAction": "DO_NOT_DECRYPT", "eventLogAction": "LOG_NONE"},
        }
        if description:
            body["description"] = description
        path = await app.config_path(DECRYPTION, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_decryption_policy",
            args={"name": name, "description": description, "domain": domain},
            confirm=confirm,
            plan=Plan(f"Create decryption policy {name!r}", details={"body": body}, blockers=blockers),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Create decryption rule")
    async def fmc_create_decryption_rule(
        ctx: Context,
        policy: PolicyRef,
        name: Annotated[str, Field(min_length=1, max_length=50, description="Rule name")],
        action: Annotated[
            Literal["DO_NOT_DECRYPT", "BLOCK", "BLOCK_WITH_RESET", "MONITOR"],
            Field(description="DO_NOT_DECRYPT exempts the traffic (banking, health, pinned apps)"),
        ] = "DO_NOT_DECRYPT",
        source_zones: ZonesParam = None,
        destination_zones: ZonesParam = None,
        source_networks: NetsParam = None,
        destination_networks: NetsParam = None,
        destination_ports: PortsParam = None,
        urls: UrlsParam = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a rule to the end of a decryption policy. Takes effect after a deploy of the devices whose
        access policy uses the decryption policy."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, DECRYPTION, policy, "decryption policy", domain)
        resolver = RefResolver(app, domain)
        body: dict[str, Any] = {
            "name": name,
            "type": "DecryptionPolicyRule",
            "ruleAction": action,
            "enabled": True,
        }
        for field, values, kind in (
            ("sourceZones", source_zones, "zone"),
            ("destinationZones", destination_zones, "zone"),
            ("sourceNetworks", source_networks, "network"),
            ("destinationNetworks", destination_networks, "network"),
            ("destinationPorts", destination_ports, "port"),
            ("urls", urls, "url"),
        ):
            block = await resolver.block(values, kind)
            if block:
                body[field] = block
        base = await app.config_path(f"{DECRYPTION}/{p['id']}/decryptionpolicyrules", domain)
        existing = await all_rules(app, base)
        blockers = []
        if any(str(r.get("name", "")).lower() == name.lower() for r in existing.items):
            blockers.append(f"{p.get('name')!r} already has a rule named {name!r}.")
        match_all = not any(
            (source_zones, destination_zones, source_networks, destination_networks, destination_ports, urls)
        )
        if match_all and action != "DO_NOT_DECRYPT":
            blockers.append(
                f"A {action} rule without conditions would match all TLS traffic; add a condition."
            )
        return await fmc_preview(
            ctx,
            tool="fmc_create_decryption_rule",
            args={
                "policy": policy,
                "name": name,
                "action": action,
                "source_zones": source_zones,
                "destination_zones": destination_zones,
                "source_networks": source_networks,
                "destination_networks": destination_networks,
                "destination_ports": destination_ports,
                "urls": urls,
                "domain": domain,
            },
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Add decryption rule {name!r} ({action}) to {p.get('name')!r}",
                details={"rule": rule_row(body), "rules_now": len(existing.items)},
                fingerprint={"policy": p["id"], "rules": [r.get("id") for r in existing.items]},
                blockers=blockers,
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.post(base, body)),
        )

    @reg.write(title="Delete decryption rule", destructive=True)
    async def fmc_delete_decryption_rule(
        ctx: Context,
        policy: PolicyRef,
        rule: Annotated[str, Field(description="Rule name or UUID")],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a decryption rule (after the next deploy, matching traffic follows the next rule or the
        default action)."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, DECRYPTION, policy, "decryption policy", domain)
        base = await app.config_path(f"{DECRYPTION}/{p['id']}/decryptionpolicyrules", domain)
        rules = await all_rules(app, base)
        hits = [
            r for r in rules.items if r.get("id") == rule or str(r.get("name", "")).lower() == rule.lower()
        ]
        if len(hits) != 1:
            raise NotFound(f"No single rule {rule!r} in {p.get('name')!r}.", 404)
        r = hits[0]
        return await fmc_preview(
            ctx,
            tool="fmc_delete_decryption_rule",
            args={"policy": policy, "rule": rule, "domain": domain},
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Delete decryption rule {r.get('name')!r} from {p.get('name')!r}",
                details={"rule": rule_row(r)},
                fingerprint=r.get("id"),
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(f"{base}/{r['id']}")),
        )

    @reg.write(title="Link decryption policy to access policy")
    async def fmc_set_decryption_policy(
        ctx: Context,
        access_policy: Annotated[str, Field(description="Access control policy name or UUID")],
        decryption_policy: Annotated[
            str,
            Field(
                description="Decryption policy name or UUID (FMC's API can't remove the link: '' is refused)"
            ),
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make an access control policy use a decryption policy. Takes effect on the next deploy. FMC's
        API can't remove the link again ('' is refused with an explanation); a policy whose default action
        is DO_NOT_DECRYPT and has no rules decrypts nothing."""
        app: FmcApp = get_client(ctx)
        acp = await resolve_in(app, ACCESS, access_policy, "access policy", domain)
        target = (
            await resolve_in(app, DECRYPTION, decryption_policy, "decryption policy", domain)
            if decryption_policy
            else None
        )
        path = await app.config_path(f"{ACCESS}/{acp['id']}", domain)
        cur = await app.api.get(path)
        now = cur.get("decryptionPolicySetting") or {}
        blockers = ["Nothing to change."] if now.get("id") == (target or {}).get("id") else []
        if target is None and now:
            blockers = [
                "FMC's REST API can't remove an access policy's decryption policy (null is refused, "
                "omitting it keeps it). Link a policy whose default action is DO_NOT_DECRYPT instead, "
                "or remove it in the UI."
            ]

        async def apply() -> Any:
            fresh = await app.api.get(path)
            body = acp_settings_body(fresh)
            body["decryptionPolicySetting"] = (
                {"id": target["id"], "type": "DecryptionPolicy", "name": target.get("name")}
                if target
                else None
            )
            return await applied(app, lambda: app.api.put(path, body))

        return await fmc_preview(
            ctx,
            tool="fmc_set_decryption_policy",
            args={"access_policy": access_policy, "decryption_policy": decryption_policy, "domain": domain},
            confirm=confirm,
            owned=[acp],
            plan=Plan(
                f"{acp.get('name')!r} uses decryption policy {(target or {}).get('name') or 'none'}",
                details={"from": ref_label(now) if now else None, "to": (target or {}).get("name")},
                fingerprint={"current": now.get("id"), "target": (target or {}).get("id")},
                blockers=blockers,
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=apply,
        )

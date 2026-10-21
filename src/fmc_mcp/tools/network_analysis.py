"""Network analysis policies (F43): read the Snort 3 network analysis policies (NAPs: preprocessing,
normalisation and decoder settings that run before the intrusion rules) and create a custom one on a base
policy. Inspector-level settings are left to fmc_api_call (.../inspectoroverrideconfigs)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, ref_label, resolve_in
from fmc_mcp.tools.object_writes import applied
from fmc_mcp.tools.render import object_reply

NAP = "policy/networkanalysispolicies"
# FMC 10.0.1 has no REST field for an access policy's default network analysis policy (the AccessPolicy
# schema has none and no sub-resource sets it), so the link is made in the UI.
LINK_IN_UI = (
    "Select it in the access policy editor (Advanced > Network Analysis and Intrusion Policies > Default "
    "Network Analysis Policy) and deploy; FMC's REST API has no field for that link."
)


def access_policies_using(p: dict[str, Any]) -> list[str]:
    """Names of the access policies whose analysis uses this NAP (FMC spells the key 'asscoiated')."""
    usage = (p.get("metadata") or {}).get("usage") or {}
    refs = usage.get("asscoiatedAcPolicies") or usage.get("associatedAcPolicies") or []
    return [str(r.get("name") or r.get("id")) for r in refs if isinstance(r, dict)]


def nap_row(p: dict[str, Any]) -> dict[str, Any]:
    meta = p.get("metadata") or {}
    usage = meta.get("usage") or {}
    row = {
        "name": p.get("name"),
        "base_policy": ref_label(p["basePolicy"]) if p.get("basePolicy") else None,
        "inspection_mode": p.get("inspectionMode"),
        "system_defined": bool(p.get("isSystemDefined")),
        "access_policies": usage.get("accesspolicy"),
        "devices": usage.get("devices"),
        "id": p.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


async def resolve_nap(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, NAP, ref, "network analysis policy", domain)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Network analysis policies")
    async def fmc_get_network_analysis_policy(
        ctx: Context,
        policy: Annotated[
            str | None,
            Field(description="Network analysis policy name or UUID; omit to list them all"),
        ] = None,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the network analysis policies (NAPs) or show one: base policy, inspection mode (PREVENTION
        lets the preprocessors drop malformed traffic, DETECTION only reports), which access policies use
        it and on how many devices, and for a custom policy the inspectors it overrides. Use it to check
        which NAP an access policy runs before changing preprocessing, or before creating a custom one
        (fmc_create_network_analysis_policy); fmc_threat_posture names one access policy's NAP."""
        app: FmcApp = get_client(ctx)
        if not policy:
            page = await app.all(await app.config_path(NAP, domain))
            rows = [nap_row(p) for p in page.items]
            return list_result(page_of(rows, limit=1000, offset=0), fmt=response_format)
        p = await resolve_nap(app, policy, domain)
        meta = p.get("metadata") or {}
        out: dict[str, Any] = {
            **nap_row(p),
            "description": p.get("description") or None,
            "snort_engine": meta.get("snortEngine"),
            "used_by_access_policies": access_policies_using(p) or None,
            "domain": (meta.get("domain") or {}).get("name"),
        }
        if not p.get("isSystemDefined"):
            path = await app.config_path(f"{NAP}/{p['id']}/inspectoroverrideconfigs", domain)
            page = await app.all(path)
            overridden: list[str] = []
            for item in page.items:
                conf = item.get("inspectorOverrideConfig")
                if isinstance(conf, dict):
                    overridden += [str(k) for k in conf]
            out["inspector_overrides"] = sorted(set(overridden))
            if not access_policies_using(p):
                out["note"] = "No access policy uses it yet. " + LINK_IN_UI
        out["id"] = p.get("id")
        return object_reply({k: v for k, v in out.items() if v is not None}, fmt=response_format)

    @reg.write(title="Create network analysis policy")
    async def fmc_create_network_analysis_policy(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New policy name")],
        base_policy: Annotated[
            str,
            Field(description="System or custom network analysis policy to inherit the inspector settings"),
        ] = "Balanced Security and Connectivity",
        inspection_mode: Annotated[
            Literal["PREVENTION", "DETECTION"],
            Field(description="PREVENTION: preprocessors may drop malformed traffic; DETECTION: only report"),
        ] = "PREVENTION",
        description: Annotated[str | None, Field(description="Description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a custom Snort 3 network analysis policy on top of a base policy (for example to run
        detection-only preprocessing on one access policy). Inspector settings are not edited here (use
        fmc_api_call on .../inspectoroverrideconfigs). FMC's REST API can't make an access policy use it:
        select it in the access policy's Advanced settings in the UI, then deploy."""
        app: FmcApp = get_client(ctx)
        base = await resolve_nap(app, base_policy, domain)
        blockers = []
        try:
            await resolve_nap(app, name, domain)
            blockers.append(f"A network analysis policy named {name!r} already exists.")
        except NotFound:
            pass
        body: dict[str, Any] = {
            "name": name,
            "type": "NetworkAnalysisPolicy",
            "basePolicy": {"id": base["id"], "type": "NetworkAnalysisPolicy"},
            "inspectionMode": inspection_mode,
        }
        if description:
            body["description"] = description
        path = await app.config_path(NAP, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_network_analysis_policy",
            args={
                "name": name,
                "base_policy": base_policy,
                "inspection_mode": inspection_mode,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create network analysis policy {name!r} based on {base.get('name')!r} ({inspection_mode})",
                details={"body": body},
                fingerprint=base["id"],
                blockers=blockers,
                side_effects=["No traffic uses it until an access policy selects it. " + LINK_IN_UI],
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

"""Dynamic objects: named IP sets whose mappings FMC pushes to devices without a deployment.

Access rules reference a dynamic object once (and that rule needs one deployment); after that, adding
or removing IP mappings takes effect on the devices within seconds. This is the building block for
rapid threat containment (block a host by mapping it into a quarantine object).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any

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
    get_client,
    list_result,
    preview_or_apply,
)
from stutters_mcp_core.http import page_of

from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, resolve_in
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import ACCESS, all_rules

DYNAMIC = "object/dynamicobjects"
MAPPING_CAP = 50_000
POLICY_SCAN_CAP = 50  # access policies scanned for rules that reference a dynamic object
NO_DEPLOY = "Mapping changes reach the devices without a deployment (usually within seconds)."

DynamicRef = Annotated[str, Field(description="Dynamic object name or UUID (fmc_list_dynamic_objects)")]
IpList = Annotated[
    list[str] | None,
    Field(description="IPv4/IPv6 addresses or CIDR networks, e.g. ['10.99.1.10', '10.50.0.0/16']"),
]


def normalize_ips(values: list[str] | None) -> list[str]:
    """Validated, de-duplicated addresses or networks as FMC stores them (host addresses without /32)."""
    out: dict[str, None] = {}
    for raw in values or []:
        v = str(raw).strip()
        if not v:
            continue
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise InvalidRequest(f"{raw!r} is not an IP address or CIDR network.") from None
        if net.num_addresses == 1:
            out[str(net.network_address)] = None
        else:
            if str(net) != v and "/" in v:
                raise InvalidRequest(f"{raw!r} has host bits set; did you mean {net}?")
            out[str(net)] = None
    return list(out)


async def resolve_dynamic(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, DYNAMIC, ref, "dynamic object", domain)


async def mappings_of(app: FmcApp, obj_id: str, domain: str | None) -> tuple[list[str], bool]:
    """(mappings, complete) of one dynamic object."""
    page = await app.all(
        await app.config_path(f"{DYNAMIC}/{obj_id}/mappings", domain), expanded=False, cap=MAPPING_CAP
    )
    return [str(m.get("mapping")) for m in page.items if m.get("mapping")], page.complete


async def rules_using(app: FmcApp, obj_id: str, domain: str | None) -> tuple[list[dict[str, Any]], bool]:
    """Access rules that reference the dynamic object (FMC's usage API doesn't cover this type).
    Returns (rules, complete)."""
    policies = await app.all(await app.config_path(ACCESS, domain), expanded=False, cap=POLICY_SCAN_CAP)
    found: list[dict[str, Any]] = []
    complete = policies.complete
    for pol in policies.items:
        rules = await all_rules(app, await app.config_path(f"{ACCESS}/{pol['id']}/accessrules", domain))
        complete = complete and rules.complete
        for r in rules.items:
            sides = [
                side
                for side, field in (
                    ("source", "sourceDynamicObjects"),
                    ("destination", "destinationDynamicObjects"),
                )
                if any(o.get("id") == obj_id for o in (r.get(field) or {}).get("objects") or [])
            ]
            if sides:
                found.append(
                    {
                        "policy": pol.get("name"),
                        "rule": r.get("name"),
                        "index": (r.get("metadata") or {}).get("ruleIndex"),
                        "action": r.get("action"),
                        "enabled": r.get("enabled", True),
                        "as": sides,
                    }
                )
    return found, complete


def _row(obj: dict[str, Any], mappings: list[str] | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {
        "name": obj.get("name"),
        "object_type": obj.get("objectType"),
        "description": obj.get("description"),
        "id": obj.get("id"),
    }
    if mappings is not None:
        row["mapping_count"] = len(mappings)
        row["mappings"] = mappings[:50] + (["..."] if len(mappings) > 50 else [])
    return row


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List dynamic objects")
    async def fmc_list_dynamic_objects(
        ctx: Context,
        name: Annotated[str | None, Field(description="Filter: name contains (case-insensitive)")] = None,
        with_mappings: Annotated[
            bool,
            Field(description="Include each object's current IP mappings (one request per object; max 25)"),
        ] = True,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 25,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List dynamic objects (named IP sets used in access rules as source/destination dynamic
        objects) with their current IP mappings. Mapping changes (fmc_map_dynamic_object) take effect
        on devices without a deployment, which makes dynamic objects the tool for quick host blocks."""
        app: FmcApp = get_client(ctx)
        everything = await app.all(await app.config_path(DYNAMIC, domain), cap=5000)
        items = [o for o in everything.items if not name or name.lower() in str(o.get("name", "")).lower()]
        page = page_of(items, limit=limit, offset=offset)
        rows = []
        for i, o in enumerate(page.items):
            if with_mappings and i < 25:
                maps, _ = await mappings_of(app, o["id"], domain)
                rows.append(_row(o, maps))
            else:
                rows.append(_row(o))
        page.items = rows
        return list_result(page, fmt=response_format)

    @reg.write(title="Create dynamic object")
    async def fmc_create_dynamic_object(
        ctx: Context,
        name: Annotated[str, Field(description="New dynamic object name", min_length=1, max_length=64)],
        description: Annotated[str | None, Field(description="Optional description")] = None,
        mappings: IpList = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an IP dynamic object, optionally with initial IP mappings. Reference it in an access
        rule (fmc_create_access_rule source_dynamic_objects / destination_dynamic_objects) and deploy
        once; later mapping changes need no deployment."""
        app: FmcApp = get_client(ctx)
        ips = normalize_ips(mappings)
        body: dict[str, Any] = {"name": name, "type": "DynamicObject", "objectType": "IP"}
        if description:
            body["description"] = description
        blockers = []
        try:
            await resolve_dynamic(app, name, domain)
            blockers.append(f"A dynamic object named {name!r} already exists.")
        except NotFound:
            pass
        path = await app.config_path(DYNAMIC, domain)
        map_path = await app.config_path("object/dynamicobjectmappings", domain)

        async def apply() -> Any:
            created = await applied(app, lambda: app.api.post(path, body))
            if ips:
                ref = {"id": created["id"]}
                await app.api.post(map_path, {"add": [{"mappings": ips, "dynamicObject": ref}]})
            return {**created, "mappings": ips}

        return await preview_or_apply(
            ctx,
            tool="fmc_create_dynamic_object",
            args={"name": name, "description": description, "mappings": mappings, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Create dynamic object {name!r}" + (f" with {len(ips)} mapping(s)" if ips else ""),
                details={"body": body, "mappings": ips},
                blockers=blockers,
            ),
            apply=apply,
        )

    @reg.write(title="Delete dynamic object", destructive=True)
    async def fmc_delete_dynamic_object(
        ctx: Context,
        object: DynamicRef,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a dynamic object and its mappings. Blocked while an access rule references it (the
        preview lists the rules; remove the reference and deploy first)."""
        app: FmcApp = get_client(ctx)
        obj = await resolve_dynamic(app, object, domain)
        maps, _ = await mappings_of(app, obj["id"], domain)
        used, complete = await rules_using(app, obj["id"], domain)
        blockers = []
        if used:
            names = ", ".join(f"{u['policy']}/{u['rule']}" for u in used)
            blockers.append(f"Still used by access rules: {names}. Remove it from those rules first.")
        details: dict[str, Any] = {"object": _row(obj, maps)}
        if not complete:
            details["note"] = f"Only the first {POLICY_SCAN_CAP} access policies were checked for references."
        path = await app.config_path(f"{DYNAMIC}/{obj['id']}", domain)
        return await preview_or_apply(
            ctx,
            tool="fmc_delete_dynamic_object",
            args={"object": object, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete dynamic object {obj.get('name')!r} ({len(maps)} mapping(s))",
                details=details,
                fingerprint={"object": editable(obj), "mappings": sorted(maps)},
                blockers=blockers,
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )

    @reg.write(title="Map IPs to a dynamic object")
    async def fmc_map_dynamic_object(
        ctx: Context,
        object: DynamicRef,
        add: IpList = None,
        remove: IpList = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add or remove IP mappings of a dynamic object. Takes effect on the devices WITHOUT a
        deployment, so every access rule that references the object starts or stops matching these
        addresses within seconds (e.g. map a host into a quarantine object used by a BLOCK rule). The
        preview shows the current mappings, the change and the rules that reference the object."""
        app: FmcApp = get_client(ctx)
        to_add, to_remove = normalize_ips(add), normalize_ips(remove)
        if not to_add and not to_remove:
            raise InvalidRequest("Give addresses to add and/or remove.")
        if both := set(to_add) & set(to_remove):
            raise InvalidRequest(f"In both add and remove: {', '.join(sorted(both))}.")
        obj = await resolve_dynamic(app, object, domain)
        current, complete = await mappings_of(app, obj["id"], domain)
        have = set(current)
        new_adds = [ip for ip in to_add if ip not in have] if complete else to_add
        new_removes = [ip for ip in to_remove if ip in have] if complete else to_remove
        used, _ = await rules_using(app, obj["id"], domain)
        blockers = []
        if not new_adds and not new_removes:
            blockers.append(
                "Nothing to change: the addresses to add are already mapped and those to remove aren't."
            )
        side_effects = [NO_DEPLOY]
        if used:
            side_effects.append(
                "Rules affected immediately: "
                + "; ".join(
                    f"{u['policy']}/{u['rule']} ({u['action']}, as {'+'.join(u['as'])})" for u in used
                )
            )
        else:
            side_effects.append(
                "No access rule references this object yet, so the mappings have no effect on traffic until "
                "one does (adding the reference needs one deployment)."
            )
        body: dict[str, Any] = {}
        ref = {"id": obj["id"]}
        if new_adds:
            body["add"] = [{"mappings": new_adds, "dynamicObject": ref}]
        if new_removes:
            body["remove"] = [{"mappings": new_removes, "dynamicObject": ref}]
        path = await app.config_path("object/dynamicobjectmappings", domain)
        return await preview_or_apply(
            ctx,
            tool="fmc_map_dynamic_object",
            args={"object": object, "add": add, "remove": remove, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Update mappings of dynamic object {obj.get('name')!r}",
                details={
                    "current": current[:200],
                    "current_count": len(current),
                    "add": new_adds,
                    "remove": new_removes,
                    "rules": used,
                },
                fingerprint={"id": obj["id"], "mappings": sorted(current)},
                blockers=blockers,
                side_effects=side_effects,
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

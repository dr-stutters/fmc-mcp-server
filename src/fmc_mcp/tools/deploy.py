"""Deployment tools: what is pending, what changed, deployment history (deploy itself is dangerous)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
import time
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import ResponseFormat, ToolRegistrar, get_client, list_result
from stutters_mcp_core.http import page_of

from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, ref_label, resolve_in
from fmc_mcp.tools.devices import DEVICES, DeviceRef
from fmc_mcp.tools.system import iso

DEPLOYABLE = "deployment/deployabledevices"
JOBS = "deployment/jobhistories"


def deployable_row(d: dict[str, Any]) -> dict[str, Any]:
    dev = d.get("device") or {}
    policies = []
    for ps in d.get("policyStatusList") or []:
        pol = ps.get("policy") or {}
        if ps.get("upToDate") is False:
            policies.append(f"{pol.get('type', '')}:{pol.get('name', '')}")
    return {
        "device": d.get("name") or dev.get("name"),
        "can_be_deployed": d.get("canBeDeployed"),
        "deploying": d.get("isDeploying"),
        "traffic_interruption": d.get("trafficInterruption"),
        "out_of_date_policies": policies or None,
        "version": d.get("version"),
        "device_id": dev.get("id"),
    }


SECRET_FIELD = re.compile(r"password|secret|key|community|psk", re.I)


def _change_text(v: dict[str, Any], verb: str) -> str:
    field = v.get("fieldName") or "?"
    old, new = v.get("oldValue"), v.get("newValue")
    if SECRET_FIELD.search(str(field)):  # FMC shows encrypted secrets here (e.g. BGP neighbor passwords)
        old = "********" if old not in (None, "") else old
        new = "********" if new not in (None, "") else new
    if verb == "deleted":
        return f"-{field}: {old if old is not None else new}"
    if old is not None and new is not None:
        return f"{field}: {old} -> {new}"
    return f"{field}: {new if new is not None else old}"


def pending_row(c: dict[str, Any]) -> dict[str, Any]:
    """One pending change with its field values flattened to 'Field: old -> new' strings."""
    changes: list[str] = []
    for key, verb in (("valueAdded", "added"), ("valueUpdated", "updated"), ("valueDeleted", "deleted")):
        for v in c.get(key) or []:
            if isinstance(v, dict):
                changes.append(_change_text(v, verb))
    row = {
        "entity": c.get("entityName"),
        "type": c.get("entityType"),
        "action": c.get("action"),
        "changed_by": ", ".join(ref_label(u) for u in c.get("lastUpdatedByUsers") or []) or None,
        "changes": changes or None,
        "message": c.get("message"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


async def deployable(app: FmcApp, domain: str | None) -> list[dict[str, Any]]:
    page = await app.all(await app.config_path(DEPLOYABLE, domain), cap=5000)
    return page.items


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List devices with undeployed changes")
    async def fmc_list_deployable_devices(
        ctx: Context,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List devices that have configuration changes waiting to be deployed, with the
        out-of-date policies, whether a deploy is possible and whether it interrupts traffic. Empty
        means everything is deployed (or no devices are managed). Details per device:
        fmc_pending_changes."""
        app: FmcApp = get_client(ctx)
        rows = [deployable_row(d) for d in await deployable(app, domain)]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="Pending changes for a device")
    async def fmc_pending_changes(
        ctx: Context,
        device: DeviceRef,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Show what the next deployment would push to one device: each changed entity (policy,
        rule, object) with the action (added/updated/deleted), who changed it and the changed
        values. Use before fmc_deploy to review the blast radius."""
        app: FmcApp = get_client(ctx)
        d = await resolve_in(app, DEVICES, device, "device", domain)
        path = await app.config_path(f"{DEPLOYABLE}/{d['id']}/pendingchanges", domain)
        everything = await app.all(path, cap=5000)
        rows = [pending_row(c) for c in everything.items]
        # FMC also lists empty container entries ("Interface UPDATE", "Routing UPDATE") that only
        # group the real changes; drop them.
        rows = [r for r in rows if r.get("entity") or r.get("changes") or r.get("message")]
        extra: dict[str, Any] = {"device": d.get("name")}
        if not everything.complete:
            extra["note"] = "Only the first 5000 change entries were read."
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.read(title="Deployment history")
    async def fmc_list_deployments(
        ctx: Context,
        device: Annotated[
            str | None, Field(description="Only deployments to this device (name or UUID)")
        ] = None,
        since_hours: Annotated[int, Field(ge=1, le=8760, description="Look back this many hours")] = 168,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List past deployment jobs, newest first: when, by whom, status, devices and message. Use it
        to answer 'when was this last deployed and did it succeed?'."""
        app: FmcApp = get_client(ctx)
        now = int(time.time())
        filters = [f"startTime:{now - since_hours * 3600}", f"endTime:{now + 60}"]
        if device:
            d = await resolve_in(app, DEVICES, device, "device", domain)
            filters.insert(0, f"deviceUUID:{d['id']}")
        page = await app.page(
            await app.config_path(JOBS, domain), {"filter": ";".join(filters)}, limit=limit, offset=offset
        )
        page.items = [
            {
                "started": iso(j.get("startTime")),
                "ended": iso(j.get("endTime")),
                "job": j.get("jobName"),
                "type": j.get("jobType"),
                "user": j.get("user"),
                "status": j.get("jobStatus"),
                "devices": [
                    f"{x.get('deviceName')}: {x.get('deploymentStatus')}"
                    if x.get("deploymentStatus")
                    else str(x.get("deviceName"))
                    for x in j.get("deviceList") or []
                ]
                or None,
                "note": j.get("deploymentNote"),
                "id": j.get("id"),
            }
            for j in page.items
        ]
        return list_result(page, fmt=response_format)

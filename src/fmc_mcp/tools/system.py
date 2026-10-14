"""System tools: domains, audit log, background tasks, licensing."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import time
from datetime import UTC, datetime
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import ResponseFormat, ToolRegistrar, get_client, list_result, object_result
from stutters_mcp_core.http import page_of

from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, slim


def iso(ts: Any) -> str | None:
    """FMC timestamps are epoch seconds or milliseconds."""
    if isinstance(ts, str) and "T" in ts:
        return ts  # already ISO 8601
    try:
        n = float(ts)
    except (TypeError, ValueError):
        return None
    if n > 10**11:
        n /= 1000
    return datetime.fromtimestamp(n, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List FMC domains")
    async def fmc_list_domains(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="Filter: domain name contains (case-insensitive)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the FMC domains this API account can see (name like 'Global/Child' and UUID), marking
        the default one. Pass a name or UUID from here as `domain` to other tools on multi-domain FMCs."""
        app: FmcApp = get_client(ctx)
        default = await app.domain_uuid(None)
        data = await app.api.get("/api/fmc_platform/v1/info/domain", {"limit": 1000, "expanded": "true"})
        rows = [
            {
                "name": d.get("name"),
                "uuid": d.get("uuid"),
                "default": d.get("uuid") == default,
                "parent_uuid": d.get("parentUUID") if d.get("parentUUID") != d.get("uuid") else None,
            }
            for d in (data or {}).get("items", [])
        ]
        if name:
            rows = [r for r in rows if name.lower() in str(r["name"]).lower()]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.read(title="FMC audit records")
    async def fmc_list_audit_records(
        ctx: Context,
        since_minutes: Annotated[
            int, Field(ge=1, le=525_600, description="Look back this many minutes (default 24 hours)")
        ] = 1440,
        user: Annotated[str | None, Field(description="Filter: username contains")] = None,
        subsystem: Annotated[
            str | None, Field(description="Filter: subsystem contains, e.g. 'API', 'Login', 'Access Control'")
        ] = None,
        text: Annotated[str | None, Field(description="Filter: message contains (case-insensitive)")] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List FMC audit-log records, newest first: who did what and when (logins, policy edits, API
        calls, deployments). Use it to answer 'who changed this rule/object?' or 'what changed today?'.
        Filters on user, subsystem and message text are applied after fetching the time window."""
        app: FmcApp = get_client(ctx)
        now = int(time.time())
        # endtime in the future is rejected ("Invalid start or end time"), so send only starttime.
        params = {"starttime": now - since_minutes * 60}
        path = await app.platform_path("audit/auditrecords", domain)
        filtering = any((user, subsystem, text))
        if not filtering:
            page = await app.page(path, params, limit=limit, offset=offset)
            rows = [_audit_row(r) for r in page.items]
            page.items = rows
            return list_result(page, fmt=response_format)
        everything = await app.all(path, params, cap=5000)
        rows = []
        for r in everything.items:
            if user and user.lower() not in str(r.get("username", "")).lower():
                continue
            if subsystem and subsystem.lower() not in str(r.get("subSystem", "")).lower():
                continue
            if text and text.lower() not in str(r.get("message", "")).lower():
                continue
            rows.append(_audit_row(r))
        extra = None if everything.complete else {"note": "Scanned only the newest 5000 records."}
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.read(title="Get FMC task status")
    async def fmc_get_task(
        ctx: Context,
        task_id: Annotated[str, Field(description="Task id returned by a deploy/registration/other job")],
        domain: Domain = None,
    ) -> ToolResult:
        """Get the status of an FMC background task (deployment, device registration, pending-changes
        report, backup): status, message and per-device sub-tasks. Use it to follow up on a tool that
        returned a task id instead of waiting."""
        app: FmcApp = get_client(ctx)
        path = await app.config_path(f"job/taskstatuses/{task_id.strip()}", domain)
        data = await app.api.get(path, {"showDetailedDeviceStatus": "true"})
        return object_result(slim(data))

    @reg.read(title="FMC licensing status")
    async def fmc_license_status(ctx: Context) -> dict[str, Any]:
        """Smart Licensing registration status of the FMC (registered/unregistered, evaluation use,
        export control) and the per-device license entitlements FMC knows about."""
        app: FmcApp = get_client(ctx)
        smart = await app.api.get("/api/fmc_platform/v1/license/smartlicenses")
        devices = await app.all("/api/fmc_platform/v1/license/devicelicenses", expanded=False, cap=1000)
        return {
            "smart_license": [slim(i) for i in (smart or {}).get("items", [])],
            "device_licenses": [slim(i) for i in devices.items],
        }


def _audit_row(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "time": iso(r.get("time")),
        "user": r.get("username"),
        "subsystem": r.get("subSystem"),
        "source": r.get("source"),
        "message": r.get("message"),
    }

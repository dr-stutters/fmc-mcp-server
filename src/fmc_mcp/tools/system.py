"""System tools: domains, audit log, background tasks, licensing."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import time
from datetime import UTC, datetime
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import (
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
    object_result,
)
from stutters_mcp_core.http import page_of

from fmc_mcp.audit import AUDIT_NOISE, compact_message, coverage_note, fetch_audit, is_read
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
        """List the FMC domains this API account can see as a tree (name like 'Global/Child', UUID,
        parent, leaf or not, and the devices each one holds), marking the default one. Devices live only
        in leaf domains; objects and policies defined in a domain are inherited (read-only) by the domains
        below it. Pass a name or UUID from here as `domain` to other tools on multi-domain FMCs."""
        app: FmcApp = get_client(ctx)
        default = await app.domain_uuid(None)
        data = await app.api.get("/api/fmc_platform/v1/info/domain", {"limit": 1000, "expanded": "true"})
        items = [d for d in (data or {}).get("items", []) if d.get("uuid")]
        parents = {d["uuid"]: d.get("parentUUID") for d in items if d.get("parentUUID") != d["uuid"]}
        # Devices with their owning domain, read once from the top-most visible domain (ancestors
        # see their descendants' devices).
        top = min(items, key=lambda d: str(d.get("name", "")).count("/"), default=None)
        per_domain: dict[str, list[str]] = {}
        if top is not None:
            try:
                devs = await app.all(await app.config_path("devices/devicerecords", top["uuid"]))
                for dev in devs.items:
                    dom = ((dev.get("metadata") or {}).get("domain") or {}).get("id") or top["uuid"]
                    per_domain.setdefault(str(dom), []).append(str(dev.get("name")))
            except UpstreamError:
                per_domain = {}
        rows = [
            {
                "name": d.get("name"),
                "uuid": d.get("uuid"),
                "default": d.get("uuid") == default,
                "parent_uuid": parents.get(d["uuid"]),
                "leaf": d["uuid"] not in parents.values(),
                "devices": sorted(per_domain.get(d["uuid"], [])) or None,
            }
            for d in sorted(items, key=lambda d: str(d.get("name", "")).lower())
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
            str | None,
            Field(
                description="Filter: subsystem contains, e.g. 'Access Control', 'Object Management', 'Login'"
            ),
        ] = None,
        text: Annotated[
            str | None,
            Field(description="Filter: message contains (case-insensitive), e.g. a rule or object name"),
        ] = None,
        changes_only: Annotated[
            bool | None,
            Field(
                description="Skip reads: API GETs, page views, logins, logouts, session expiry. Default: on, "
                "unless `subsystem` asks for them (e.g. 'Login')"
            ),
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List FMC audit-log records, newest first: who changed what and when (policy and object edits,
        API writes, deployments; logins and reads with changes_only=false). Use it to answer 'who changed
        this object?' (text=<object name>) or 'what changed today?'. FMC logs an access or NAT rule edit
        as 'Save Policy <policy>:<revision>' without the rule name, so search rules by their policy
        name (fmc_pending_changes names the rules not yet deployed). FMC returns only 100 records per
        request and logs every API read, so the window is read in slices (up to 2500 records); a note
        says how far back it got when the window holds more. API URLs are shortened
        ('PUT fmc_config/policy/...')."""
        app: FmcApp = get_client(ctx)
        start = int(time.time()) - since_minutes * 60
        if changes_only is None:
            changes_only = not (subsystem and AUDIT_NOISE.match(subsystem.strip()))
        scan = await fetch_audit(app, start, domain)
        rows = []
        for r in scan.items:
            if changes_only and is_read(r):
                continue
            if user and user.lower() not in str(r.get("username", "")).lower():
                continue
            if subsystem and subsystem.lower() not in str(r.get("subSystem", "")).lower():
                continue
            if text and text.lower() not in str(r.get("message", "")).lower():
                continue
            rows.append(_audit_row(r))
        extra: dict[str, Any] = {"records_read": len(scan.items)}
        note = coverage_note(scan)
        if note:
            extra["note"] = note
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
        "message": compact_message(r.get("message")),
    }

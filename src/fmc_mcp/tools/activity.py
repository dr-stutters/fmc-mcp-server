"""On-demand activity lookups (pull-only, ADR-003): health alerts over a window, and one merged
timeline of health alerts, audit records and deployments. Every call queries FMC; nothing is
collected in the background."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import html
import re
import time
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import ResponseFormat, ToolRegistrar, UpstreamError, get_client, list_result
from stutters_mcp_core.http import page_of

from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, resolve_in
from fmc_mcp.tools.deploy import JOBS
from fmc_mcp.tools.devices import DEVICES
from fmc_mcp.tools.system import iso

ALERTS = "health/alerts"
ALERT_FETCH = 1000  # newest raw alerts read per call (FMC re-reports each module every few minutes)
AUDIT_FETCH = 500
DEPLOY_FETCH = 100
FMC_DEVICE = "0"  # health alerts about the FMC itself use deviceUUID "0"
Status = Literal["RED", "YELLOW", "GREEN", "RECOVERED"]
# Levels for the activity timeline: problems and FMC's explicit recovery rows (GREEN repeats are noise).
ACTIVITY_STATUSES = ["RED", "YELLOW", "RECOVERED"]
AUDIT_NOISE = re.compile(r"^(GET|Page View|Login|Logout|Session Expiration)\b", re.I)
_TAGS = re.compile(r"<[^>]+>")


def clean_details(text: Any) -> str:
    """Health alert details carry HTML lists; flatten them to one line."""
    t = html.unescape(_TAGS.sub(" ", str(text or "")))
    return re.sub(r"\s+", " ", t).strip()


def _same_details(text: str) -> tuple[str, ...]:
    """Comparable form of alert details: FMC lists the failed items in a different order each run."""
    return tuple(sorted(p.strip() for p in text.split("*")))


def collapse_alerts(raw: list[dict[str, Any]], names: dict[str, str]) -> list[dict[str, Any]]:
    """FMC repeats every module's alert on each health run. Collapse runs of the same (device,
    module, status, details) into one row with first/last seen and a count; newest first."""
    rows: list[dict[str, Any]] = []
    last: dict[tuple[str, str], dict[str, Any]] = {}
    for a in sorted(raw, key=lambda x: int(x.get("timestamp") or 0)):
        dev = str(a.get("deviceUUID", ""))
        module = str(a.get("moduleID", ""))
        status = str(a.get("status", ""))
        details = clean_details(a.get("details"))
        ts = int(a.get("timestamp") or 0)
        prev = last.get((dev, module))
        if prev and prev["status"] == status and _same_details(prev["details"]) == _same_details(details):
            prev["_last"] = ts
            prev["count"] += 1
            continue
        row = {
            "device": names.get(dev) or ("FMC" if dev == FMC_DEVICE else dev),
            "module": module,
            "status": status,
            "details": details,
            "count": 1,
            "_first": ts,
            "_last": ts,
            "changed_from": prev["status"] if prev else None,
        }
        last[(dev, module)] = row
        rows.append(row)
    for r in rows:
        r["first_seen"], r["last_seen"] = iso(r.pop("_first")), iso(r.pop("_last"))
    rows.sort(key=lambda r: str(r["last_seen"]), reverse=True)
    return rows


async def device_names(app: FmcApp, domain: str | None) -> dict[str, str]:
    page = await app.all(await app.config_path(DEVICES, domain), expanded=False, cap=2000)
    return {str(d.get("id")): str(d.get("name")) for d in page.items}


async def fetch_alerts(
    app: FmcApp,
    start: int,
    end: int,
    device_id: str | None,
    statuses: list[str] | None,
    module: str | None,
    domain: str | None,
) -> tuple[list[dict[str, Any]], int]:
    """The newest (up to ALERT_FETCH) raw alerts in the window, and how many FMC holds in total.
    FMC returns them oldest first, so read the count, then the tail."""
    filters = [f"startTime:{start}", f"endTime:{end}"]
    if device_id:
        # FMC reports some device problems (heartbeat lost) as alerts on itself (device "0").
        filters.append(f"deviceUUIDs:{device_id},{FMC_DEVICE}")
    if statuses:
        filters.append("status:" + ",".join(statuses))
    if module:
        filters.append(f"moduleIDs:{module.strip().upper()}")
    params = {"filter": ";".join(filters)}
    path = await app.config_path(ALERTS, domain)
    head = await app.page(path, params, limit=1)
    total = head.total if head.total is not None else 0
    if total <= 1:
        return list(head.items), total
    tail = await app.page(path, params, limit=ALERT_FETCH, offset=max(0, total - ALERT_FETCH))
    return list(tail.items), total


def for_device(raw: list[dict[str, Any]], device_id: str | None, name: str | None) -> list[dict[str, Any]]:
    """The device's own alerts plus FMC alerts that name it."""
    if not device_id:
        return raw
    low = (name or "").lower()
    return [
        a
        for a in raw
        if str(a.get("deviceUUID")) == device_id or (low and low in str(a.get("details", "")).lower())
    ]


def _window(since_minutes: int) -> tuple[int, int]:
    now = int(time.time())
    return now - since_minutes * 60, now + 60


SinceMinutes = Annotated[int, Field(ge=1, le=43_200, description="Look back this many minutes")]
DeviceFilter = Annotated[str | None, Field(description="Only this device (name or UUID)")]


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List health alerts")
    async def fmc_list_health_alerts(
        ctx: Context,
        since_minutes: SinceMinutes = 60,
        device: DeviceFilter = None,
        status: Annotated[
            list[Status] | None,
            Field(description="Alert levels (default RED and YELLOW; RECOVERED marks a return to normal)"),
        ] = None,
        module: Annotated[
            str | None, Field(description="Health module id, e.g. APPLIANCE_HEARTBEAT, INTERFACE, CPU")
        ] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 50,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Health alerts across all managed devices and the FMC itself over a time window, newest
        first. FMC re-reports each module on every health run, so repeats are collapsed into one row
        with first/last seen and a count; `changed_from` marks a status change (e.g. GREEN -> RED).
        'device disconnected' shows up as module APPLIANCE_HEARTBEAT. For one device's current state
        use fmc_device_health; for alerts together with audit and deployments use fmc_recent_activity."""
        app: FmcApp = get_client(ctx)
        start, end = _window(since_minutes)
        names = await device_names(app, domain)
        dev_id = None
        if device:
            dev_id = str((await resolve_in(app, DEVICES, device, "device", domain))["id"])
        statuses = list(dict.fromkeys(status or ["RED", "YELLOW"]))
        raw, total = await fetch_alerts(app, start, end, dev_id, statuses, module, domain)
        fetched = len(raw)
        raw = for_device(raw, dev_id, names.get(dev_id or ""))
        rows = collapse_alerts(raw, names)
        extra: dict[str, Any] = {"window": f"{iso(start)} .. now", "raw_alerts": total}
        if total > fetched:
            extra["note"] = f"Only the newest {fetched} of {total} raw alerts were read; narrow the window."
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.read(title="Recent activity (health, audit, deployments)")
    async def fmc_recent_activity(
        ctx: Context,
        since_minutes: SinceMinutes = 60,
        device: DeviceFilter = None,
        include_audit_reads: Annotated[
            bool,
            Field(description="Also list read-only API calls, page views, logins and session expiry (noise)"),
        ] = False,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """What changed or broke recently? One timeline, newest first, merged from three FMC sources
        queried now: health alerts (RED, YELLOW and RECOVERED), audit records (who
        changed what; logins and API writes) and deployments. Each row has time, source
        (health/audit/deploy), device, summary and user. With `device`, health and deployments are
        filtered to it (plus FMC's own alerts that name it, such as lost heartbeats) and audit records
        to messages that name it (a policy edit names the policy, not the device: drop `device` to
        see it). A failing source is reported in `errors` and the others are still returned."""
        app: FmcApp = get_client(ctx)
        start, end = _window(since_minutes)
        names = await device_names(app, domain)
        dev_id = dev_name = None
        if device:
            d = await resolve_in(app, DEVICES, device, "device", domain)
            dev_id, dev_name = str(d["id"]), str(d.get("name"))
        rows: list[dict[str, Any]] = []
        errors: dict[str, str] = {}

        try:
            raw, total = await fetch_alerts(app, start, end, dev_id, ACTIVITY_STATUSES, None, domain)
            partial = total > len(raw)
            fetched = len(raw)
            raw = for_device(raw, dev_id, dev_name)
            for r in collapse_alerts(raw, names):
                change = f"{r['changed_from']} -> {r['status']}" if r["changed_from"] else r["status"]
                rows.append(
                    {
                        "time": r["first_seen"],
                        "source": "health",
                        "device": r["device"],
                        "summary": f"{r['module']} {change}: {r['details']}"[:300],
                        "user": None,
                        "status": r["status"],
                    }
                )
            if partial:
                errors["health"] = f"partial: newest {fetched} of {total} raw alerts"
        except UpstreamError as e:
            errors["health"] = str(e)

        try:
            path = await app.platform_path("audit/auditrecords", domain)
            page = await app.page(path, {"starttime": start}, limit=AUDIT_FETCH)
            for a in page.items:
                msg = str(a.get("message") or "")
                sub = str(a.get("subSystem") or "")
                if not include_audit_reads and (AUDIT_NOISE.match(msg) or AUDIT_NOISE.match(sub)):
                    continue
                if dev_name and dev_id and dev_name.lower() not in msg.lower() and dev_id not in msg:
                    continue
                rows.append(
                    {
                        "time": iso(a.get("time")),
                        "source": "audit",
                        "device": None,
                        "summary": f"{a.get('subSystem')}: {msg}"[:300],
                        "user": a.get("username"),
                        "status": None,
                    }
                )
            if not page.complete:
                errors["audit"] = f"partial: newest {AUDIT_FETCH} records only"
        except UpstreamError as e:
            errors["audit"] = str(e)

        try:
            filters = [f"startTime:{start}", f"endTime:{end}"]
            if dev_id:
                filters.insert(0, f"deviceUUID:{dev_id}")
            page = await app.page(
                await app.config_path(JOBS, domain), {"filter": ";".join(filters)}, limit=DEPLOY_FETCH
            )
            for j in page.items:
                devs = ", ".join(str(x.get("deviceName")) for x in j.get("deviceList") or []) or None
                note = f" ({j.get('deploymentNote')})" if j.get("deploymentNote") else ""
                rows.append(
                    {
                        "time": iso(j.get("startTime")),
                        "source": "deploy",
                        "device": devs,
                        "summary": f"{j.get('jobType') or 'DEPLOYMENT'} {j.get('jobStatus')}{note}"[:300],
                        "user": j.get("user"),
                        "status": j.get("jobStatus"),
                    }
                )
        except UpstreamError as e:
            errors["deploy"] = str(e)

        rows.sort(key=lambda r: str(r["time"] or ""), reverse=True)
        extra: dict[str, Any] = {"window": f"{iso(start)} .. now"}
        if dev_name:
            extra["device"] = dev_name
        if errors:
            extra["errors"] = errors
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

"""Deployment tools: what is pending, what changed, deployment history (deploy itself is dangerous)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import re
import time
from datetime import UTC, datetime
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import ResponseFormat, ToolRegistrar, UpstreamError, get_client, list_result
from fmc_mcp._core.http import page_of
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, ref_label, resolve_in
from fmc_mcp.tools.devices import DEVICES, DeviceRef
from fmc_mcp.tools.system import iso

DEPLOYABLE = "deployment/deployabledevices"
JOBS = "deployment/jobhistories"
STUCK_AFTER_MINUTES = 30  # a deployment running longer than this is probably stuck
RUNNING_JOB = re.compile(r"DEPLOYING|RUNNING|PROGRESS|QUEUED|PENDING|STARTED", re.I)
JOB_LOOKBACK_DAYS = 30  # how far back the running job of an in-progress device is looked for
IN_PROGRESS_CAP = 10  # in-progress devices whose job history is read
NOT_DEPLOYABLE_NOTE = (
    "FMC does not count this device as deployable (its deployment status is {status} and it is not in "
    "fmc_list_deployable_devices): FMC decides that from the device's out-of-date policies, so these "
    "entries (e.g. a certificate or object changed in an ancestor domain) are pushed with the device's "
    "next deployment, not on their own."
)


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
        **({"message": d["message"]} if d.get("message") else {}),
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


def _epoch(ts: Any) -> float | None:
    """A job time (ISO 8601 or epoch seconds/milliseconds) as epoch seconds."""
    text = iso(ts)
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
    except ValueError:
        return None


def _age(seconds: float) -> str:
    minutes = int(seconds // 60)
    days, rest = divmod(minutes, 1440)
    hours, mins = divmod(rest, 60)
    return " ".join(p for p in (f"{days}d" if days else "", f"{hours}h" if hours else "", f"{mins}m") if p)


async def in_progress(
    app: FmcApp, domain: str | None, pending: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Devices with a deployment in progress (the device record's DEPLOYMENT_IN_PROGRESS, or the deployable
    list's isDeploying), each with its running job from the job history, the job's age, and
    probably_stuck when it has run longer than STUCK_AFTER_MINUTES. (rows, notes)"""
    notes: list[str] = []
    found: dict[str, dict[str, Any]] = {}
    try:
        records = (await app.all(await app.config_path(DEVICES, domain), cap=1000)).items
    except UpstreamError as e:
        records = []
        notes.append(f"Device records not readable ({e}): only the deployable list's isDeploying was used.")
    for d in records:
        if str(d.get("deploymentStatus") or "").upper() == "DEPLOYMENT_IN_PROGRESS" and d.get("id"):
            found[str(d["id"]).lower()] = {"device": d.get("name"), "device_id": d["id"]}
    for p in pending:
        dev = p.get("device") or {}
        if p.get("isDeploying") and dev.get("id"):
            row = found.setdefault(
                str(dev["id"]).lower(), {"device": dev.get("name"), "device_id": dev["id"]}
            )
            name = p.get("name") or dev.get("name")
            if name and name != row["device"]:
                row["device"] = f"{name} ({row['device']})"  # an HA pair or cluster, by its unit
            if p.get("message"):
                row["message"] = p["message"]
    now = time.time()
    rows = []
    for key, row in list(found.items())[:IN_PROGRESS_CAP]:
        since = int(now) - JOB_LOOKBACK_DAYS * 86400
        filters = f"deviceUUID:{row['device_id']};startTime:{since};endTime:{int(now) + 60}"
        try:
            jobs = (await app.page(await app.config_path(JOBS, domain), {"filter": filters}, limit=25)).items
        except UpstreamError as e:
            notes.append(f"Job history of {row['device']} not readable ({e}).")
            jobs = []
        job = next((j for j in jobs if RUNNING_JOB.search(str(j.get("jobStatus") or ""))), None)
        if job is None:
            row["job"] = None
            row["note"] = (
                f"FMC says a deployment is in progress but its job history of the last {JOB_LOOKBACK_DAYS} "
                "days has no running job"
            )
            row["probably_stuck"] = True
            rows.append(row)
            continue
        started = _epoch(job.get("startTime"))
        age = now - started if started is not None else None
        unit: dict[str, Any] = next(
            (x for x in job.get("deviceList") or [] if str(x.get("deviceUUID", "")).lower() == key), {}
        )
        row.update(
            job=job.get("jobName"),
            job_status=job.get("jobStatus"),
            job_note=job.get("deploymentNote"),
            user=job.get("user"),
            started=iso(job.get("startTime")),
            running_for=_age(age) if age is not None else None,
            device_status=unit.get("deploymentStatus"),
            probably_stuck=age is not None and age > STUCK_AFTER_MINUTES * 60,
            job_id=job.get("id"),
        )
        rows.append({k: v for k, v in row.items() if v is not None})
    if len(found) > IN_PROGRESS_CAP:
        notes.append(f"Only the first {IN_PROGRESS_CAP} of {len(found)} in-progress devices were looked up.")
    return rows, notes


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
        out-of-date policies, whether a deploy is possible and whether it interrupts traffic, plus
        `in_progress`: every device whose deployment is running, with the job (name, note, user,
        start), how long it has run, and probably_stuck when that is over 30 minutes ('is a
        deployment stuck?'; stuck ones are in `probably_stuck`). Empty results mean nothing is
        waiting (or no devices are managed). FMC decides 'deployable' from out-of-date policies:
        fmc_pending_changes can list entries (e.g. a certificate changed in an ancestor domain) for a
        device that is not listed here; it says so. Details per device: fmc_pending_changes; history:
        fmc_list_deployments."""
        app: FmcApp = get_client(ctx)
        pending = await deployable(app, domain)
        rows = [deployable_row(d) for d in pending]
        running, notes = await in_progress(app, domain, pending)
        extra: dict[str, Any] = {}
        if running:
            extra["in_progress"] = running
            stuck = [str(r["device"]) for r in running if r.get("probably_stuck")]
            if stuck:
                extra["probably_stuck"] = stuck
        if notes:
            extra["note"] = " ".join(notes)
        return list_result(
            page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra or None
        )

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
        notes = []
        if not everything.complete:
            notes.append("Only the first 5000 change entries were read.")
        status = str(d.get("deploymentStatus") or "")
        if rows and status and status.upper() not in ("DEPLOYMENT_PENDING", "DEPLOYMENT_IN_PROGRESS"):
            notes.append(NOT_DEPLOYABLE_NOTE.format(status=status))
        if notes:
            extra["note"] = " ".join(notes)
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

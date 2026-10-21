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
from fmc_mcp.acp_structure import base_chain, locked, read_locks
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
    "FMC does not list this device in its deployable devices (fmc_list_deployable_devices), yet lists "
    "these pending entries: FMC decides 'deployable' from the device's out-of-date policies, and these "
    "entries (e.g. a certificate or object changed in an ancestor domain) have not made it out of date."
)


LOCKED_NOTE = (
    "An access policy in this deployment is locked (policy_locks): its holder may be in the middle of a "
    "change, and the deploy pushes what is saved now. Ask them, or wait for the unlock (fmc_policy_lock)."
)
ACP_ENTITY = re.compile(r"access(control)?policy", re.I)


async def pending_locks(
    app: FmcApp, device: dict[str, Any], rows: list[dict[str, Any]], domain: str | None
) -> list[dict[str, Any]]:
    """The locked access policies that matter to this deployment: the device's own access policy, its base
    policies, and any access policy among the pending rows (by name), each such row marked with
    `locked_by`. One read of FMC's lock list (plus the device policy's base chain when something is
    locked); nothing when the list can't be read or nothing is locked."""
    held = locked(await read_locks(app, domain))
    if not held:
        return []
    acp = device.get("accessPolicy") or {}
    by_name = {str(r.get("policy") or "").lower(): r for r in held if r.get("policy")}
    by_id = {str(r.get("policy_id") or "").lower(): r for r in held}
    out: dict[str, dict[str, Any]] = {}
    if acp.get("id"):
        mine = by_id.get(str(acp["id"]).lower())
        if mine:
            out[str(acp["id"]).lower()] = {**mine, "why": "the device's access policy"}
        try:
            chain = await base_chain(app, str(acp["id"]), domain)
        except UpstreamError:
            chain = []
        for base in chain:
            lock = by_id.get(str(base["id"]).lower())
            if lock:
                why = f"a base policy of the device's access policy {acp.get('name')!r}"
                out.setdefault(str(base["id"]).lower(), {**lock, "why": why})
    for row in rows:
        lock = by_name.get(str(row.get("entity") or "").lower())
        if lock is None or not ACP_ENTITY.search(str(row.get("type") or "").replace(" ", "")):
            continue
        row["locked_by"] = lock.get("locked_by") or "unknown"
        out.setdefault(str(lock.get("policy_id")).lower(), {**lock, "why": "pending in this deployment"})
    return [{k: v for k, v in r.items() if k != "policy_id" and v is not None} for r in out.values()]


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
# One pending change can be huge: FMC 10.0.1 listed a Snort 3 network analysis policy UPDATE whose
# inspectorData value was 115 KB (seen live 2026-10-21), over the response budget on its own; the list
# result only drops whole rows, so each row's change lines are capped here.
CHANGE_TEXT_CAP = 400  # characters of a change line's one value (added / deleted)
VALUE_CAP = CHANGE_TEXT_CAP // 2  # characters of each side of an 'old -> new' line: both stay visible
CHANGES_PER_ROW = 30  # change lines per row
CUT_MARK = " more characters]"


def _cut(value: Any, cap: int) -> str:
    text = str(value)
    if len(text) <= cap:
        return text
    return f"{text[:cap]}... [{len(text) - cap:,}{CUT_MARK}"


def _change_text(v: dict[str, Any], verb: str) -> str:
    """'Field: old -> new' with each side cut at VALUE_CAP (a long old value no longer hides the new one),
    or 'Field: value' / '-Field: value' cut at CHANGE_TEXT_CAP."""
    field = v.get("fieldName") or "?"
    old, new = v.get("oldValue"), v.get("newValue")
    if SECRET_FIELD.search(str(field)):  # FMC shows encrypted secrets here (e.g. BGP neighbor passwords)
        old = "********" if old not in (None, "") else old
        new = "********" if new not in (None, "") else new
    if verb == "deleted":
        return f"-{field}: {_cut(old if old is not None else new, CHANGE_TEXT_CAP)}"
    if old is not None and new is not None:
        return f"{field}: {_cut(old, VALUE_CAP)} -> {_cut(new, VALUE_CAP)}"
    return f"{field}: {_cut(new if new is not None else old, CHANGE_TEXT_CAP)}"


def cut_note(rows: list[dict[str, Any]]) -> str | None:
    """What was cut from pending_row rows, for the answer's note (None when nothing was)."""
    if not any(r.get("changes_total") or any(CUT_MARK in t for t in r.get("changes") or []) for r in rows):
        return None
    return (
        f"Long change values are cut (each side of 'old -> new' at {VALUE_CAP} characters, a single value "
        f"at {CHANGE_TEXT_CAP}) and rows at {CHANGES_PER_ROW} changes (changes_total counts them); the FMC "
        "UI's deployment preview shows them whole."
    )


def pending_row(c: dict[str, Any]) -> dict[str, Any]:
    """One pending change with its field values flattened to 'Field: old -> new' strings, each value cut
    (_change_text) and the row at CHANGES_PER_ROW lines (`changes_total` then counts them)."""
    changes: list[str] = []
    for key, verb in (("valueAdded", "added"), ("valueUpdated", "updated"), ("valueDeleted", "deleted")):
        for v in c.get(key) or []:
            if isinstance(v, dict):
                changes.append(_change_text(v, verb))
    shown = changes[:CHANGES_PER_ROW]
    row = {
        "entity": c.get("entityName"),
        "type": c.get("entityType"),
        "action": c.get("action"),
        "changed_by": ", ".join(ref_label(u) for u in c.get("lastUpdatedByUsers") or []) or None,
        "changes": shown or None,
        "changes_total": len(changes) if len(changes) > CHANGES_PER_ROW else None,
        "message": c.get("message"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


async def deployable(app: FmcApp, domain: str | None) -> list[dict[str, Any]]:
    page = await app.all(await app.config_path(DEPLOYABLE, domain), cap=5000)
    return page.items


async def is_deployable(app: FmcApp, device_id: str, domain: str | None) -> bool:
    """Whether FMC's deployable list has the device (itself, or as a member of an HA pair or cluster).
    True when the list can't be read: no claim either way."""
    try:
        pending = await deployable(app, domain)
    except UpstreamError:
        return True
    want = device_id.lower()
    for p in pending:
        ids = [
            (p.get("device") or {}).get("id"),
            *((m or {}).get("id") for m in p.get("deviceMembers") or []),
        ]
        if want in {str(i).lower() for i in ids if i}:
            return True
    return False


def _epoch(ts: Any) -> float | None:
    """A job time as epoch seconds: ISO 8601 in any form (fractional seconds, Z or an offset; no zone
    means UTC) or epoch seconds/milliseconds. None when it can't be read."""
    if isinstance(ts, str) and "T" in ts:
        try:
            when = datetime.fromisoformat(ts.strip())
        except ValueError:
            return None
        return (when if when.tzinfo else when.replace(tzinfo=UTC)).timestamp()
    try:
        n = float(ts)
    except (TypeError, ValueError):
        return None
    return n / 1000 if n > 10**11 else n


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
            rows.append({**row, "probably_stuck": None, "note": f"job history not readable ({e})"})
            continue
        job = next((j for j in jobs if RUNNING_JOB.search(str(j.get("jobStatus") or ""))), None)
        if job is None:
            note = (
                f"FMC records a deployment in progress but lists no running job for this device in the last "
                f"{JOB_LOOKBACK_DAYS} days: it may have finished between the two reads, or an HA pair's or "
                "cluster's job may be filed under another unit (fmc_list_deployments)"
            )
            rows.append({**row, "probably_stuck": None, "note": note})
            continue
        started = _epoch(job.get("startTime"))
        age = now - started if started is not None else None
        stuck = None if age is None else age > STUCK_AFTER_MINUTES * 60
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
            job_id=job.get("id"),
        )
        row = {k: v for k, v in row.items() if v is not None}
        row["probably_stuck"] = stuck
        if stuck is None:
            row["note"] = f"the job's start time {job.get('startTime')!r} could not be read: age unknown"
        rows.append(row)
    if len(found) > IN_PROGRESS_CAP:
        notes.append(f"Only the first {IN_PROGRESS_CAP} of {len(found)} in-progress devices were looked up.")
    return rows, notes


DEPLOYABLE_DESCRIPTION = (
    "List devices that have configuration changes waiting to be deployed, with the out-of-date "
    "policies, whether a deploy is possible and whether it interrupts traffic, plus `in_progress`: every "
    "device whose deployment is running, with the job (name, note, user, start), how long it has run, and "
    f"probably_stuck: true when that is over {STUCK_AFTER_MINUTES} minutes, false when under, null when "
    "unknown (job history unreadable, no running job found, or a start time FMC wrote differently); "
    "`probably_stuck` names the stuck ones ('is a deployment stuck?'). Empty results mean nothing is "
    "waiting (or no devices are managed). FMC decides 'deployable' from out-of-date policies: "
    "fmc_pending_changes can list entries (e.g. a certificate changed in an ancestor domain) for a device "
    "that is not listed here; it says so. Details per device: fmc_pending_changes; history: "
    "fmc_list_deployments."
)


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List devices with undeployed changes", description=DEPLOYABLE_DESCRIPTION)
    async def fmc_list_deployable_devices(
        ctx: Context,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
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
        values (long values cut, e.g. a Snort 3 policy's inspector data). Use before fmc_deploy to
        review the blast radius. A locked access policy (the device's, or one in the list) is named with
        its holder (`policy_locks`): someone may be mid-change, and the deploy pushes what is saved now."""
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
        cut = cut_note(rows)
        if cut:
            notes.append(cut)
        if rows and not await is_deployable(app, str(d["id"]), domain):
            notes.append(NOT_DEPLOYABLE_NOTE)
        if rows:
            locks = await pending_locks(app, d, rows, domain)
            if locks:
                extra["policy_locks"] = locks
                notes.append(LOCKED_NOTE)
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

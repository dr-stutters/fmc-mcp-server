"""Register several FTDs in one call (F74): fmc_register_devices.

One preview covers every row. On confirm the rows go to FMC in one bulk request (POST
devicerecords?bulk=true; one POST per device, sent concurrently, where FMC refuses bulk), then one
polling loop under one deadline follows every registration task and every device's initial deployment.
With MCP_TASKS=true the tool is an MCP background task (core C12): a client that supports tasks gets a
handle at once and polls it for progress; others call it synchronously as usual.

The single-device logic (key, body, failure hints, job times) is shared with fmc_register_device
(tools/dangerous.py)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import contextlib
import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastmcp import Context
from pydantic import BaseModel, Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    ValidationFailed,
    get_client,
    get_settings,
)
from fmc_mcp._core import formatting as _formatting
from fmc_mcp._core.secrets import mask_values, register_secret, scrub_text
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.rails import check_deploy_window, deploy_window_blockers
from fmc_mcp.tools.common import Domain, resolve_in, slim
from fmc_mcp.tools.dangerous import (
    FAILED_WORDS,
    SERVER_KEY,
    job_epoch,
    registration_body,
    registration_hint,
    registration_key,
    registration_key_problem,
    task_id_of,
    task_state,
)
from fmc_mcp.tools.deploy import JOBS
from fmc_mcp.tools.devices import DEVICES
from fmc_mcp.tools.policies import POLICY_KINDS

TOOL = "fmc_register_devices"
DEVICE_GROUPS = "devicegroups/devicegrouprecords"
MAX_DEVICES = 32
SINGLE_CONCURRENCY = 8  # one POST per device; the client's own FMC_MAX_CONCURRENCY applies as well
BULK_UNSUPPORTED = {404, 405, 415}  # FMC doesn't take ?bulk=true for devicerecords here
DEPLOYED = {"DEPLOYED", "SUCCEEDED", "SUCCESS"}
FINAL = {"deployed", "registered", "failed", "refused", "skipped", "unknown"}
POLL_FIRST, POLL_MAX = 10.0, 30.0  # seconds between polling rounds (backs off)
REQUESTS_PER_MINUTE = 40  # this loop's own pace: FMC allows ~120/min for everyone
MAX_POLL_ERRORS = 3  # consecutive failed polling rounds before giving up the wait


def _mask_registration_keys() -> None:
    """TODO(core): core's secret-key pattern has no `reg_key` / `regKey`, so a registration key passed as
    an argument (fmc_register_device's reg_key, a row override here) reached the audit log's tool_call
    event (and a two-person preview) in clear. Extend the pattern until core covers it (CORE-REQUESTS.md,
    fmc F74). Masks `reg_key`, `regKey`, `ftd_reg_key`; leaves `registration_key` (a preview's 'from ...'
    note) alone."""
    if not _formatting.is_secret_key("reg_key"):
        _formatting.SECRET_KEY_RE = re.compile(
            _formatting.SECRET_KEY_RE.pattern + r"|reg_?key", re.IGNORECASE
        )


_mask_registration_keys()


class DeviceRow(BaseModel):
    """One FTD to register. Fields left out take the call's defaults."""

    name: str = Field(
        min_length=1, max_length=128, description="Display name in FMC, e.g. mcp-sdwan-t1-spoke1"
    )
    host: str | None = Field(
        default=None, description="Management IP or hostname of the FTD (omit only with nat_id)"
    )
    access_policy: str | None = Field(
        default=None, description="Access control policy name/UUID (default: the call's access_policy)"
    )
    license_caps: list[str] | None = Field(
        default=None, description="Licences, e.g. ESSENTIALS, IPS, MALWARE_DEFENSE, URL (default: the call's)"
    )
    group: str | None = Field(default=None, description="Device group name/UUID (default: the call's group)")
    performance_tier: str | None = Field(
        default=None, description="FTDv performance tier, e.g. FTDv5 (default: the call's)"
    )
    nat_id: str | None = Field(default=None, description="NAT ID, if the FTD was configured with one")
    reg_key: str | None = Field(
        default=None,
        description="Registration key for this FTD only. Omit it: the server's FMC_FTD_REG_KEY is used for "
        "every row, so keys never pass through the conversation.",
    )


@dataclass
class _Row:
    n: int
    name: str
    host: str | None
    body: dict[str, Any]
    status: str = "pending"  # registering -> deploying -> deployed / registered, or a failure state
    task_id: str | None = None
    device_id: str | None = None
    registration: str | None = None
    deployment: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    seconds: int | None = None

    def end(self, status: str, began: float, error: str | None = None) -> None:
        self.status = status
        if error:
            self.error = error
        self.seconds = int(time.monotonic() - began)


def bulk_task_ids(resp: Any) -> list[str]:
    """Task ids in a bulk registration answer. The spec's example is one TaskStatus for the whole batch
    (`{"items": [{"id": ..., "type": "TaskStatus", "name": "DEVICE_REGISTRATION"}]}`); a per-device
    `metadata.task` is read too."""
    found: list[str] = []
    entries: list[Any] = []
    if isinstance(resp, dict):
        entries = list(resp.get("items") or []) or [resp]
    elif isinstance(resp, list):
        entries = resp
    for e in entries:
        if not isinstance(e, dict):
            continue
        tid = task_id_of(e) or (e.get("id") if str(e.get("type") or "") == "TaskStatus" else None)
        if tid and str(tid) not in found:
            found.append(str(tid))
    return found


def _task_text(t: dict[str, Any]) -> str:
    return ": ".join(str(t[k]) for k in ("status", "message") if t.get(k)) or "unknown"


def _row_out(r: _Row) -> dict[str, Any]:
    out = {
        "row": r.n,
        "name": r.name,
        "host": r.host,
        "status": r.status,
        "device_id": r.device_id,
        "task_id": r.task_id,
        "registration": r.registration,
        "initial_deployment": r.deployment or None,
        "seconds": r.seconds,
        "error": r.error,
    }
    return {k: v for k, v in out.items() if v not in (None, "")}


@dataclass
class _Group:
    """Rows FMC follows with the same registration task(s): one row per task for single POSTs, every row
    for a bulk request. No task ids: the device list alone tells when a row is registered."""

    tasks: list[str]
    rows: list[_Row]
    done: bool = False
    failures: list[str] = field(default_factory=list)
    text: str | None = None


class _Run:
    """One confirmed fmc_register_devices call: submit, then follow every row under one deadline."""

    def __init__(
        self,
        ctx: Context,
        app: FmcApp,
        rows: list[_Row],
        keys: list[str],
        *,
        domain: str | None,
        skip_deployment: bool,
        stop_on_failure: bool,
    ) -> None:
        self.ctx, self.app, self.rows, self.keys = ctx, app, rows, keys
        self.domain = domain
        self.skip_deployment = skip_deployment
        self.stop_on_failure = stop_on_failure
        self.began = time.monotonic()
        self.started = int(time.time())  # wall clock, for FMC's job history filter
        self.groups: list[_Group] = []
        self.finished: dict[str, tuple[bool, str | None, str]] = {}  # task id -> (done, failure, text)
        self.method = "single"
        self.bulk_tasks: list[str] = []
        self.bulk_answer: Any = None
        self.calls = 0
        self.poll_error: str | None = None

    def clean(self, text: str) -> str:
        """An FMC message for the result: credential shapes and every key in use masked."""
        return mask_values(scrub_text(text), [k for k in self.keys if len(k) >= 4])

    def _failed(self, r: _Row, failure: str) -> None:
        hint = registration_hint(failure)
        r.end("failed", self.began, self.clean(failure + (f" {hint}" if hint else "")))

    def _registered(self, r: _Row) -> None:
        if self.skip_deployment:
            r.end("registered", self.began)
        else:
            r.status = "deploying"

    # --- submit ---------------------------------------------------------------------------------

    async def submit(self, bulk: bool) -> None:
        path = await self.app.config_path(DEVICES, self.domain)
        if not (bulk and len(self.rows) > 1):
            await self._submit_each(path)
            return
        try:
            resp = await self.app.api.post(path, [r.body for r in self.rows], params={"bulk": "true"})
        except UpstreamError as e:
            code = e.status_code
            message = self.clean(str(e))
            unsupported = code in BULK_UNSUPPORTED  # not by message text: device names often say "bulk"
            if code not in (400, 409, 422) and not unsupported:
                raise UpstreamError(
                    f"{message} FMC may have accepted part of the batch: check fmc_list_devices before "
                    "registering again.",
                    code,
                ) from None
            if not unsupported and self.stop_on_failure:
                for r in self.rows:
                    r.end("refused", self.began, f"FMC refused the bulk registration: {message}")
                return
            self.method = f"single (FMC refused the bulk request: {message})"
            await self._submit_each(path)
            return
        self.method = "bulk"
        self.bulk_tasks = bulk_task_ids(resp)
        # FMC's own answer, masked (the spec's single-device answer echoes regKey): shows its shape live
        self.bulk_answer = json.loads(self.clean(json.dumps(slim(resp), default=str)))
        for r in self.rows:
            r.status = "registering"
            if len(self.bulk_tasks) == 1:
                r.task_id = self.bulk_tasks[0]
        self.groups = [_Group(tasks=list(self.bulk_tasks), rows=list(self.rows))]

    async def _submit_each(self, path: str) -> None:
        gate = asyncio.Semaphore(SINGLE_CONCURRENCY)
        stop = asyncio.Event()

        async def one(r: _Row) -> None:
            async with gate:
                if stop.is_set():
                    r.end("skipped", self.began, "Not sent: an earlier row failed (stop_on_failure).")
                    return
                try:
                    resp = await self.app.api.post(path, r.body)
                except UpstreamError as e:
                    sure = e.status_code in (400, 404, 409, 422)  # refused before anything was done
                    note = "" if sure else " FMC may still have accepted it: check fmc_list_devices."
                    r.end("refused" if sure else "unknown", self.began, self.clean(str(e)) + note)
                    if self.stop_on_failure:
                        stop.set()
                    return
                r.task_id = task_id_of(resp)
                r.status = "registering"
                self.groups.append(_Group(tasks=[r.task_id] if r.task_id else [], rows=[r]))

        await asyncio.gather(*(one(r) for r in self.rows))
        self.groups.sort(key=lambda g: g.rows[0].n)

    # --- follow ---------------------------------------------------------------------------------

    async def follow(self, timeout_s: float) -> str:
        """Poll until every row is final ('done'), a row failed with stop_on_failure ('stopped'), the
        deadline passed ('timeout') or FMC kept failing the status checks ('errors')."""
        deadline = self.began + timeout_s
        wait = POLL_FIRST
        errors = 0
        while True:
            self.calls = 0
            try:
                await self._poll_tasks()
                await self._poll_devices()
                if not self.skip_deployment:
                    await self._poll_deployments()
                errors = 0
            except UpstreamError as e:  # one transient FMC error must not lose the whole batch
                errors += 1
                if errors >= MAX_POLL_ERRORS:
                    self.poll_error = self.clean(str(e))
                    return "errors"
            if self.stop_on_failure and any(r.status in ("failed", "refused", "unknown") for r in self.rows):
                return "stopped"
            if all(r.status in FINAL for r in self.rows):
                return "done"
            now = time.monotonic()
            if now >= deadline:
                return "timeout"
            await self._progress()
            pace = self.calls * 60.0 / REQUESTS_PER_MINUTE
            await asyncio.sleep(min(max(wait, pace), max(0.0, deadline - now)))
            wait = min(POLL_MAX, wait * 1.5)

    async def _get(self, suffix: str, params: dict[str, Any] | None = None) -> Any:
        self.calls += 1
        return await self.app.api.get(await self.app.config_path(suffix, self.domain), params)

    async def _task(self, tid: str) -> tuple[bool, str | None, str]:
        if tid not in self.finished:
            t = await self._get(f"job/taskstatuses/{tid}")
            t = t if isinstance(t, dict) else {}
            done, failure = task_state(t)
            if not done:
                return False, None, _task_text(t)
            self.finished[tid] = (True, failure, self.clean(_task_text(t)))
        return self.finished[tid]

    async def _poll_tasks(self) -> None:
        for g in self.groups:
            if g.done or not g.tasks:
                continue
            states = [await self._task(tid) for tid in g.tasks]
            if not all(done for done, _, _ in states):
                continue
            g.done = True
            g.failures = [f for _, f, _ in states if f]
            g.text = "; ".join(text for _, _, text in states)
            waiting = [r for r in g.rows if r.status == "registering"]
            for r in waiting:
                r.registration = g.text
            if len(g.rows) == 1:  # one row, one task: its outcome is the row's
                for r in waiting:
                    if g.failures:
                        self._failed(r, "; ".join(g.failures))
                    else:
                        self._registered(r)
            else:  # a bulk task covers every row: the device list says which rows made it
                for r in waiting:
                    r.status = "listed?"

    async def _poll_devices(self) -> None:
        untracked = {id(r) for g in self.groups if not g.tasks for r in g.rows}
        need = [
            r
            for r in self.rows
            if r.device_id is None
            and (
                r.status in ("listed?", "deploying", "registered")
                or (r.status == "registering" and id(r) in untracked)
            )
        ]
        if not need:
            return
        self.calls += 1
        page = await self.app.all(await self.app.config_path(DEVICES, self.domain))
        by_name = {str(d.get("name", "")).lower(): d for d in page.items}
        for r in need:
            d = by_name.get(r.name.lower())
            if d is not None:
                r.device_id = str(d.get("id"))
                if r.status in ("listed?", "registering"):
                    r.registration = r.registration or "registered (the device is listed)"
                    self._registered(r)
            elif r.status == "listed?":
                group = next(g for g in self.groups if any(x is r for x in g.rows))
                self._failed(
                    r,
                    "; ".join(group.failures)
                    or "FMC's bulk registration task finished but this device is not listed.",
                )

    async def _poll_deployments(self) -> None:
        watch = {r.device_id: r for r in self.rows if r.status == "deploying" and r.device_id}
        if not watch:
            return
        now = int(time.time())
        self.calls += 1
        page = await self.app.page(
            await self.app.config_path(JOBS, self.domain),
            {"filter": f"startTime:{self.started - 60};endTime:{now + 60}"},
            limit=100,
        )
        latest: dict[str, tuple[int, dict[str, Any], dict[str, Any]]] = {}
        for job in page.items:
            at = job_epoch(job.get("startTime"))
            if at < self.started - 5:
                continue  # an older job (a re-registered device has some)
            for entry in job.get("deviceList") or []:
                dev = str(entry.get("deviceUUID") or "")
                if dev in watch and (dev not in latest or at >= latest[dev][0]):
                    latest[dev] = (at, job, entry)
        for dev, (_, job, entry) in latest.items():
            r = watch[dev]
            status = str(entry.get("deploymentStatus") or job.get("jobStatus") or "").upper()
            r.deployment = {
                k: v
                for k, v in {
                    "job": job.get("jobName"),
                    "status": status or None,
                    "note": job.get("deploymentNote"),
                }.items()
                if v
            }
            if status in DEPLOYED:
                r.end("deployed", self.began)
            elif any(w.upper() in status for w in FAILED_WORDS):
                r.end(
                    "failed",
                    self.began,
                    "The initial deployment did not succeed; check fmc_list_deployments, then fmc_deploy.",
                )

    async def _progress(self) -> None:
        counts = Counter("registering" if r.status == "listed?" else r.status for r in self.rows)
        done = sum(1 for r in self.rows if r.status in FINAL)
        message = ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
        with contextlib.suppress(Exception):  # progress is best-effort
            await self.ctx.report_progress(progress=done, total=len(self.rows), message=message)

    # --- result ---------------------------------------------------------------------------------

    def result(self, ended: str | None, timeout_s: float) -> dict[str, Any]:
        reason = {
            "timeout": f"still running after {int(timeout_s // 60)} min",
            "stopped": "not waited for (another row failed and stop_on_failure is on)",
            "errors": f"not followed: FMC kept failing the status checks ({self.poll_error})",
        }.get(ended or "", "still running")
        for r in self.rows:
            if r.status in FINAL:
                continue
            if ended is None:  # wait=false
                r.status = "submitted"
                continue
            deploying = r.status == "deploying"
            phase = "the initial deployment" if deploying else "the registration"
            follow = "fmc_list_deployments" if deploying or not r.task_id else f"fmc_get_task {r.task_id}"
            r.status = "running"
            r.error = f"{phase} is {reason}; check {follow}."
        counts = Counter(r.status for r in self.rows)
        out: dict[str, Any] = {
            "method": self.method,
            "summary": dict(sorted(counts.items())),
            "wall_clock_seconds": int(time.monotonic() - self.began),
            "devices": [_row_out(r) for r in self.rows],
        }
        if self.bulk_tasks:
            out["bulk_tasks"] = self.bulk_tasks
        if self.bulk_answer is not None:
            out["bulk_answer"] = self.bulk_answer
        if ended is None:
            out["note"] = (
                "Submitted; follow each task with fmc_get_task and the initial deployments with "
                "fmc_list_deployments."
            )
        if any(r.status in ("deployed", "registered") for r in self.rows):
            out["next_steps"] = (
                "Per device: fmc_apply_device_template (a branch template) or fmc_update_interface + "
                "fmc_create_static_route + fmc_assign_policy, then fmc_deploy and verify with "
                "fmc_run_show_command."
            )
        if any(r.status in ("failed", "refused", "unknown", "skipped") for r in self.rows):
            out["retry"] = (
                "Rows that did not register can go again in a new fmc_register_devices call with only those "
                "rows (devices that registered are refused as duplicates)."
            )
        return out


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Register several devices", task=True)
    async def fmc_register_devices(
        ctx: Context,
        devices: Annotated[
            list[DeviceRow],
            Field(
                min_length=1,
                max_length=MAX_DEVICES,
                description="The FTDs: name and host each (from a recipe's FMC hand-off), optionally their "
                "own access_policy, license_caps, group, performance_tier, nat_id",
            ),
        ],
        access_policy: Annotated[
            str | None,
            Field(description="Access control policy for every row that names none (name or UUID)"),
        ] = None,
        license_caps: Annotated[
            list[str] | None,
            Field(description="Licences for rows that name none (default ESSENTIALS)"),
        ] = None,
        performance_tier: Annotated[
            str | None, Field(description="FTDv performance tier for rows that name none, e.g. FTDv5")
        ] = None,
        group: Annotated[
            str | None, Field(description="Device group for rows that name none (name or UUID)")
        ] = None,
        skip_deployment: Annotated[
            bool,
            Field(
                description="Register without FMC's initial deployment (skipDeployment); deploy later with "
                "fmc_deploy, e.g. after fmc_apply_device_template"
            ),
        ] = False,
        bulk: Annotated[
            bool,
            Field(
                description="One bulk request (default). false: one request per device, sent concurrently "
                "(also the automatic fallback when FMC refuses bulk)"
            ),
        ] = True,
        stop_on_failure: Annotated[
            bool,
            Field(
                description="Stop at the first failure: a refused bulk request registers nothing, and the "
                "wait ends when one row fails (the others keep running on FMC). false: register every "
                "valid row and wait for all of them"
            ),
        ] = True,
        wait: Annotated[
            bool,
            Field(description="Wait for every registration and initial deployment (else return task ids)"),
        ] = True,
        timeout_minutes: Annotated[
            int, Field(ge=1, le=120, description="One deadline for the whole batch")
        ] = 30,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Register (onboard) several FTDs in one call: one preview for all rows, one bulk registration
        request, then one wait under one deadline for every registration task and every initial deployment,
        with a result per device (deployed / registered / failed / refused / running) and the wall-clock
        time. Each FTD must already point at this FMC (`configure manager add <fmc> <key>`, e.g. a CML
        recipe's day-0); FMC needs Smart Licensing or evaluation mode. Every row uses the server's
        FMC_FTD_REG_KEY unless it carries its own reg_key; keys are never shown. The preview blocks duplicate
        names or hosts (in the rows or already in FMC), unknown policies or groups, and a closed deploy
        window. Runs as an MCP background task when the server has MCP_TASKS=true. One FTD:
        fmc_register_device. Device templates are a separate step (fmc_apply_device_template per device)."""
        app: FmcApp = get_client(ctx)
        settings = get_settings(ctx)
        problems: list[str] = []
        keys: list[tuple[str, str]] = []
        no_key = []
        for n, row in enumerate(devices, 1):
            try:
                keys.append(registration_key(settings, row.reg_key, what="the row's reg_key"))
            except InvalidRequest:
                no_key.append(f"row {n} ({row.name!r})")
        if no_key:
            raise InvalidRequest(
                f"No registration key for {', '.join(no_key)}: set FMC_FTD_REG_KEY (or _FILE / _REF) on the "
                "server so the key stays out of the conversation, or give the row its own reg_key."
            )
        for key, source in keys:
            if source != SERVER_KEY:
                register_secret(key)  # masked in later log lines and tool errors
        for n, (key, source) in enumerate(keys, 1):
            problem = registration_key_problem(key, source)
            if problem and source != SERVER_KEY:
                problems.append(f"row {n} ({devices[n - 1].name!r}): {problem}")
            elif problem and problem not in problems:
                problems.append(problem)  # the server's key: once for every row

        async def resolve_all(path: str, refs: set[str], what: str) -> dict[str, dict[str, Any] | None]:
            found: dict[str, dict[str, Any] | None] = {}
            for ref in sorted(refs):
                try:
                    found[ref] = await resolve_in(app, path, ref, what, domain)
                except NotFound as e:
                    found[ref] = None
                    problems.append(str(e))
            return found

        def policy_of(row: DeviceRow) -> str | None:
            return (row.access_policy or access_policy or "").strip() or None

        def group_of(row: DeviceRow) -> str | None:
            return (row.group or group or "").strip() or None

        acps = await resolve_all(
            POLICY_KINDS["access"],
            {p for p in (policy_of(r) for r in devices) if p},
            "access policy",
        )
        groups = await resolve_all(
            DEVICE_GROUPS, {g for g in (group_of(r) for r in devices) if g}, "device group"
        )
        existing = await app.all(await app.config_path(DEVICES, domain))
        fmc_names = {str(d.get("name", "")).lower(): d for d in existing.items}
        fmc_hosts = {str(d.get("hostName", "")).lower(): d for d in existing.items if d.get("hostName")}

        rows: list[_Row] = []
        shown: list[dict[str, Any]] = []
        seen_names: dict[str, int] = {}
        seen_hosts: dict[str, int] = {}
        for n, (row, (key, source)) in enumerate(zip(devices, keys, strict=True), 1):
            where = f"row {n} ({row.name!r})"
            name = row.name.strip()
            host = (row.host or "").strip() or None
            if not host and not row.nat_id:
                problems.append(f"{where}: give host (the FTD's management address), or nat_id behind NAT.")
            if name.lower() in seen_names:
                problems.append(f"{where}: the name is also row {seen_names[name.lower()]}.")
            seen_names.setdefault(name.lower(), n)
            if host and host.lower() in seen_hosts:
                problems.append(f"{where}: host {host} is also row {seen_hosts[host.lower()]}.")
            if host:
                seen_hosts.setdefault(host.lower(), n)
            if name.lower() in fmc_names:
                problems.append(f"{where}: a device named {name!r} is already registered.")
            if host and host.lower() in fmc_hosts:
                problems.append(
                    f"{where}: host {host} is already registered as {fmc_hosts[host.lower()].get('name')!r}."
                )
            acp_ref, group_ref = policy_of(row), group_of(row)
            acp = acps.get(acp_ref) if acp_ref else None
            if acp_ref is None:
                problems.append(f"{where}: no access_policy (give one for the call or for the row).")
            grp = groups.get(group_ref) if group_ref else None
            body = registration_body(
                name=name,
                host=host,
                key=key,
                access_policy_id=str((acp or {}).get("id", "")),
                license_caps=row.license_caps or license_caps,
                nat_id=row.nat_id,
                performance_tier=row.performance_tier or performance_tier,
            )
            if grp:
                body["deviceGroup"] = {"id": grp["id"], "type": "DeviceGroup"}
            if skip_deployment:
                body["skipDeployment"] = True
            rows.append(_Row(n=n, name=name, host=host, body=body))
            entry = {
                "row": n,
                "name": name,
                "host": host,
                "access_policy": (acp or {}).get("name") or acp_ref,
                "license_caps": body["license_caps"],
                "group": (grp or {}).get("name") or group_ref,
                "performance_tier": body.get("performanceTier"),
                "nat_id": "********" if row.nat_id else None,
                "registration_key": f"from {source}",
            }
            shown.append({k: v for k, v in entry.items() if v is not None})

        window, window_blockers = deploy_window_blockers(settings, TOOL)
        count = len(rows)
        names = ", ".join(r.name for r in rows[:6]) + (f" and {count - 6} more" if count > 6 else "")
        side_effects = [
            f"Consumes licences on {count} device(s).",
            "FMC registers them in parallel; a row that fails doesn't undo the others (they stay).",
        ]
        if skip_deployment:
            side_effects.append("No initial deployment: the devices stay undeployed until fmc_deploy.")
        else:
            side_effects.append("FMC deploys each device's access policy right after registering it.")
        timeout_s = float(timeout_minutes * 60)
        all_keys = [k for k, _ in keys]

        async def apply() -> Any:
            check_deploy_window(get_settings(ctx), TOOL)
            run = _Run(
                ctx,
                app,
                rows,
                all_keys,
                domain=domain,
                skip_deployment=skip_deployment,
                stop_on_failure=stop_on_failure,
            )
            await run.submit(bulk)
            app.invalidate_cache()
            app.forget_devices()  # new devices: their owning domain is looked up again
            if all(r.status in ("refused", "skipped") for r in rows):
                raise ValidationFailed(
                    "Nothing was registered: "
                    + "; ".join(f"row {r.n} ({r.name!r}) {r.status}: {r.error}" for r in rows[:5])
                    + (" ..." if count > 5 else ""),
                    400,
                )
            ended = await run.follow(timeout_s) if wait else None
            return run.result(ended, timeout_s)

        return await fmc_preview(
            ctx,
            tool=TOOL,
            args={
                "devices": [r.model_dump() for r in devices],
                "access_policy": access_policy,
                "license_caps": license_caps,
                "performance_tier": performance_tier,
                "group": group,
                "skip_deployment": skip_deployment,
                "bulk": bulk,
                "stop_on_failure": stop_on_failure,
                "wait": wait,
                "timeout_minutes": timeout_minutes,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Register {count} device(s): {names}",
                details={
                    "devices": shown,
                    "request": (
                        "one bulk POST devicerecords?bulk=true (one POST per device if FMC refuses bulk)"
                        if bulk and count > 1
                        else "one POST per device, sent concurrently"
                    ),
                    "initial_deployment": "skipped (skipDeployment)" if skip_deployment else "by FMC",
                    "wait": f"up to {timeout_minutes} min for the batch" if wait else "no: returns task ids",
                    "stop_on_failure": stop_on_failure,
                    **({"deploy_window": window} if window else {}),
                },
                fingerprint={
                    "access_policies": sorted(str(a["id"]) for a in acps.values() if a),
                    "groups": sorted(str(g["id"]) for g in groups.values() if g),
                },
                blockers=problems + window_blockers,
                blast_radius=count,
                side_effects=side_effects,
            ),
            apply=apply,
        )

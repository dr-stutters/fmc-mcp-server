"""Dangerous-tier tools: deploy, device registration/removal, HA form/break/switch, policy deletion."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import re
import time
from datetime import datetime
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    TaskFailed,
    ToolRegistrar,
    Unreachable,
    UpstreamError,
    UpstreamTimeout,
    ValidationFailed,
    get_client,
    get_settings,
    poll_until,
)
from fmc_mcp._core.secrets import register_secret
from fmc_mcp.client import FmcApp
from fmc_mcp.config import Settings
from fmc_mcp.preview import fmc_preview
from fmc_mcp.rails import (
    check_deploy_window,
    deploy_window_blockers,
    recorded_warnings,
    remember_warnings,
    split_warnings,
    units_of,
)
from fmc_mcp.tools.common import Domain, ref_label, resolve_in, slim
from fmc_mcp.tools.deploy import JOBS, deployable, deployable_row
from fmc_mcp.tools.device_groups import expand_devices
from fmc_mcp.tools.devices import DEVICES, HA_PAIRS, DeviceRef
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import POLICY_KINDS, PolicyKind, all_rules, policy_assignments
from fmc_mcp.tools.system import iso

DONE = {"deployed", "succeeded", "success", "completed", "complete"}
Wait = Annotated[bool, Field(description="Wait for the FMC task to finish (otherwise return the task id)")]


FAILED_WORDS = ("fail", "cancel", "error", "interrupt", "abort")
# FMC validates every pending change before it answers a deployment request (live, FMC 10.0.1: four FTDs
# after an LSP update took longer than the client's default 30 s), so the request gets this long.
DEPLOY_POST_TIMEOUT = 180.0
# A dropped connection or a gateway error (502/504) this long after the request was sent may follow a request
# FMC received and is still validating; a faster one is an ordinary error.
DEPLOY_LONG_WAIT = 20.0
GATEWAY_CODES = (502, 504)


def deploy_unanswered(err: UpstreamError, waited: float) -> bool:
    """Whether a failed deployment request may still have reached FMC: a timeout, or a dropped connection /
    502 / 504 after a long wait."""
    if isinstance(err, UpstreamTimeout):
        return True
    late = waited >= DEPLOY_LONG_WAIT
    return late and (isinstance(err, Unreachable) or err.status_code in GATEWAY_CODES)


async def deploy_timeout(
    app: FmcApp, err: UpstreamError, device_ids: list[str], domain: str | None, waited: float
) -> UpstreamError:
    """What a deployment request without an answer means: FMC may have refused it or may still start it (the
    validation is what took so long; the job can appear after the request gave up). One read of the
    deployable list says whether a target is deploying now; nothing there yet proves nothing."""
    try:
        rows = await deployable(app, domain)
    except UpstreamError:
        rows = None
    wanted = {i.lower() for i in device_ids}
    busy = sorted(
        str(r.get("name") or (r.get("device") or {}).get("name"))
        for r in rows or []
        if r.get("isDeploying") and str((r.get("device") or {}).get("id", "")).lower() in wanted
    )
    if isinstance(err, UpstreamTimeout):
        why = f"no answer in {DEPLOY_POST_TIMEOUT:.0f} s; FMC validates the pending changes before it answers"
    else:
        why = f"after {waited:.0f} s; FMC may have received the request and still be validating it"
    if rows is None:
        now = "FMC's deployable list could not be read either, and FMC may still start a deployment"
    elif busy:
        now = f"FMC lists {', '.join(busy)} as deploying now: a deployment did start"
    else:
        now = "No deployment visible yet; FMC may still start it"
    return type(err)(
        f"{err} ({why}). {now}: re-check fmc_list_deployable_devices (deploying) / "
        "fmc_list_deployments(since_hours=1) before deploying again, then preview again: the confirm token "
        "was used.",
        err.status_code,
    )


def task_state(task: dict[str, Any]) -> tuple[bool, str | None]:
    """(finished, failure message) for an FMC task status. Matches by word so variants such as
    'Deployed with warnings' or 'Deploy Failed' are recognised."""
    status = str(task.get("status") or "").strip()
    low = status.lower()
    if any(w in low for w in FAILED_WORDS):
        # FMC puts the reason in `description` (e.g. registration: "...register this console with the
        # Smart Licensing Server") and only a code in `message` (REGISTRATION_FAILED).
        parts = [str(task.get(k)).strip() for k in ("message", "description") if task.get(k)]
        return True, f"{status}: {' - '.join(parts)}".strip(": ")
    return low in DONE or any(low.startswith(w) for w in DONE), None


async def wait_task(
    ctx: Context, app: FmcApp, task_id: str, domain: str | None, what: str, limit_s: float | None = None
) -> dict[str, Any]:
    path = await app.config_path(f"job/taskstatuses/{task_id}", domain)
    timeout = limit_s or float(get_settings(ctx).mcp_task_timeout)

    async def fetch() -> dict[str, Any]:
        data: dict[str, Any] = await app.api.get(path)
        return data

    result = await poll_until(
        fetch,
        done=lambda t: task_state(t)[0],
        failed=lambda t: task_state(t)[1],
        describe=lambda t: f"{t.get('status')}: {t.get('message') or ''}",
        timeout=timeout,
        interval=5.0,
        max_interval=20.0,  # FMC allows ~120 requests/minute; poll gently
        ctx=ctx,
        what=what,
    )
    out: dict[str, Any] = slim(result)
    return out


def _as_int(v: Any) -> int:
    try:
        return int(str(v))
    except ValueError:
        return 0


def job_epoch(v: Any) -> int:
    """A deployment job's startTime as epoch seconds. FMC 10.0.1 sends ISO 8601 strings
    ("2026-10-19T00:04:08Z"); older releases (and the spec) epoch seconds or milliseconds. 0 if unknown."""
    if isinstance(v, str) and "T" in v:
        try:
            return int(datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp())
        except ValueError:
            return 0
    n = _as_int(v)
    return n // 1000 if n > 10**11 else n


# --- device registration (shared by fmc_register_device and fmc_register_devices) -------------

# FMC refuses anything else: "Registration key contains invalid characters. Only alphanumerics and
# hyphen (-) are allowed." (FMC 10.0.1, seen in the SD-WAN run with a key carrying a stray character).
REG_KEY_OK = re.compile(r"[A-Za-z0-9-]+")
SERVER_KEY = "server config (FMC_FTD_REG_KEY)"


def registration_key(settings: Settings, reg_key: str | None, what: str = "argument") -> tuple[str, str]:
    """(key, where it comes from) for a registration: the caller's key, else FMC_FTD_REG_KEY. Surrounding
    whitespace is dropped (an env file or _FILE often leaves a newline). Raises when there is neither.
    The key is registered as a secret: later log lines and tool errors mask it (core masks the configured
    value as given, which is not this one when it was stripped, and knows nothing of an argument's key)."""
    if reg_key and reg_key.strip():
        key, source = reg_key.strip(), what
    elif settings.ftd_reg_key is not None:
        key, source = settings.ftd_reg_key.get_secret_value().strip(), SERVER_KEY
    else:
        raise InvalidRequest(
            "No registration key: pass reg_key, or set FMC_FTD_REG_KEY (or _FILE / _REF) on the server "
            "so the key stays out of the conversation."
        )
    register_secret(key)
    return key, source


def registration_key_problem(key: str, source: str) -> str | None:
    """A blocker when FMC would refuse the key (never shows the key itself)."""
    if REG_KEY_OK.fullmatch(key):
        return None
    if not key:
        return f"The registration key from {source} is empty: set it on the server and preview again."
    return (
        f"The registration key from {source} has characters FMC refuses (only letters, digits and '-' are "
        "allowed): fix it on the server (and in the FTDs' `configure manager add`) and preview again."
    )


def registration_body(
    *,
    name: str,
    host: str | None,
    key: str,
    access_policy_id: str,
    license_caps: list[str] | None,
    nat_id: str | None,
    performance_tier: str | None,
) -> dict[str, Any]:
    """The devicerecords POST body for one FTD."""
    body: dict[str, Any] = {
        "name": name,
        "hostName": host or "",
        "regKey": key,
        "type": "Device",
        "license_caps": [c.strip().upper() for c in license_caps or ["ESSENTIALS"]],
        "accessPolicy": {"id": access_policy_id, "type": "AccessPolicy"},
    }
    if nat_id:
        body["natID"] = nat_id
    if performance_tier:
        body["performanceTier"] = performance_tier
    return body


def registration_hint(message: str) -> str | None:
    """What to check after a failed registration task, from FMC's message."""
    low = message.lower()
    if "timed out" in low:
        return (
            "Check on the FTD that 'show managers' lists this FMC as Pending with the same registration key "
            "(configure manager add) and that it can reach FMC on TCP 8305."
        )
    if "smart licens" in low:
        return (
            "FMC must be registered with Smart Licensing or be in evaluation mode first (fmc_license_status "
            "shows it)."
        )
    return None


def task_id_of(resp: Any) -> str | None:
    if isinstance(resp, dict):
        task = (resp.get("metadata") or {}).get("task") or {}
        return task.get("id")
    return None


async def _deploy_target(
    app: FmcApp, ref: str, pending: list[dict[str, Any]], by_id: dict[Any, dict[str, Any]], domain: str | None
) -> dict[str, Any]:
    """The deployable entry for a device, HA pair or cluster name/UUID. FMC lists an HA pair as
    one deployable container, so a unit's name maps to its pair."""
    low = ref.strip().lower()
    if not low:
        raise InvalidRequest("Empty device name.")
    for d in pending:
        dev = d.get("device") or {}
        if low in {
            str(dev.get("id", "")).lower(),
            str(dev.get("name", "")).lower(),
            str(d.get("name", "")).lower(),
        }:
            return d
    dev = await resolve_in(app, DEVICES, ref, "device", domain)
    if dev["id"] in by_id:
        return by_id[dev["id"]]
    pairs = await app.all(await app.config_path(HA_PAIRS, domain))
    for h in pairs.items:
        units = {(h.get("primary") or {}).get("id"), (h.get("secondary") or {}).get("id")}
        if dev["id"] in units and h.get("id") in by_id:
            return by_id[h["id"]]
    raise InvalidRequest(f"{dev.get('name')!r} has no pending changes (see fmc_list_deployable_devices).")


def _link_net(active: str, standby: str, mask: str, what: str) -> ipaddress.IPv4Network:
    """The subnet of an HA link, after checking its two addresses are distinct IPv4 hosts in it."""
    try:
        a, b = ipaddress.IPv4Address(active.strip()), ipaddress.IPv4Address(standby.strip())
        net = ipaddress.IPv4Network(f"{a}/{mask.strip()}", strict=False)
    except ValueError as e:
        raise InvalidRequest(
            f"The {what} needs IPv4 addresses and a mask such as 255.255.255.252: {e}"
        ) from None
    if a == b:
        raise InvalidRequest(f"The {what}'s active and standby addresses must differ.")
    if b not in net:
        raise InvalidRequest(f"The {what}'s standby address {b} is not in {net} (active {a}).")
    if net.prefixlen < 31 and (
        a in (net.network_address, net.broadcast_address) or b in (net.network_address, net.broadcast_address)
    ):
        raise InvalidRequest(f"The {what}'s addresses must be host addresses of {net}.")
    return net


async def finish(ctx: Context, app: FmcApp, resp: Any, wait: bool, domain: str | None, what: str) -> Any:
    app.invalidate_cache()
    app.forget_devices()  # registrations, deletes and HA changes can change which domain owns a device
    tid = task_id_of(resp)
    if tid is None:
        return slim(resp) if isinstance(resp, dict) else resp
    if not wait:
        return {"task_id": tid, "note": "Started; check progress with fmc_get_task."}
    try:
        return {"task_id": tid, "task": await wait_task(ctx, app, tid, domain, what)}
    except (UpstreamTimeout, TaskFailed) as e:
        # The change was submitted; say which task to follow up on instead of inviting a retry.
        raise type(e)(f"{e} The request was submitted as task {tid}; check it with fmc_get_task.") from e


async def _delete_and_finish(ctx: Context, app: FmcApp, path: str, domain: str | None, what: str) -> Any:
    resp = await app.api.delete(path)
    return await finish(ctx, app, resp, False, domain, what)


async def _wait_initial_deploy(
    ctx: Context, app: FmcApp, name: str, since: int, domain: str | None
) -> dict[str, Any]:
    """After a registration task succeeds FMC still runs the first deployment ("Deployment after
    registration"); wait for that job so the device is really ready."""
    timeout = float(get_settings(ctx).mcp_task_timeout)
    jobs = await app.config_path(JOBS, domain)

    async def fetch() -> dict[str, Any]:
        try:
            dev = await resolve_in(app, DEVICES, name, "device", domain)
        except NotFound:
            return {}
        flt = f"deviceUUID:{dev['id']};startTime:{since - 60};endTime:{int(time.time()) + 60}"
        page = await app.page(jobs, {"filter": flt}, limit=25)
        # Only jobs started after the registration request, newest first (a re-registered device
        # also has older jobs).
        fresh = [j for j in page.items if job_epoch(j.get("startTime")) >= since - 5]
        fresh.sort(key=lambda j: job_epoch(j.get("startTime")), reverse=True)
        job = fresh[0] if fresh else {}
        return {
            "device_id": dev["id"],
            "job": job.get("jobName"),
            "status": job.get("jobStatus"),
            "note": job.get("deploymentNote"),
        }

    def done(s: dict[str, Any]) -> bool:
        st = str(s.get("status") or "").upper()  # DEPLOYING -> DEPLOYED / FAILED
        return st in ("DEPLOYED", "SUCCEEDED", "SUCCESS") or any(w.upper() in st for w in FAILED_WORDS)

    try:
        state = await poll_until(
            fetch,
            done=done,
            describe=lambda s: str(s.get("status") or "waiting for the first deployment"),
            timeout=timeout,
            interval=10.0,
            max_interval=30.0,
            ctx=ctx,
            what="initial deployment",
        )
    except UpstreamTimeout:
        return {"status": "still running", "note": "Check fmc_list_deployments for the device."}
    out = {k: v for k, v in state.items() if v}
    status = str(out.get("status", "")).upper()
    out["ok"] = status in ("DEPLOYED", "SUCCEEDED", "SUCCESS")
    if not out["ok"]:
        out["note"] = (
            "The initial deployment did not succeed; check fmc_list_deployments and fmc_deploy again."
        )
    return out


async def _windowed(ctx: Context, tool: str, work: Any) -> Any:
    try:
        check_deploy_window(get_settings(ctx), tool)
    except InvalidRequest:
        work.close()  # the coroutine never runs
        raise
    return await work


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Deploy configuration")
    async def fmc_deploy(
        ctx: Context,
        devices: Annotated[
            list[str] | None,
            Field(
                description="Device names/UUIDs to deploy, or device groups ('group:<name>'; members without "
                "pending changes are skipped); default: every device with pending changes"
            ),
        ] = None,
        note: Annotated[
            str | None, Field(description="Deployment note shown in the deployment history")
        ] = None,
        ignore_warning: Annotated[bool, Field(description="Deploy despite FMC validation warnings")] = False,
        wait: Wait = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Push pending configuration to devices (FMC deployment). Preview lists each target device,
        its out-of-date policies and whether traffic will be interrupted; review details first with
        fmc_pending_changes. With wait, polls the deployment task until it finishes."""
        app: FmcApp = get_client(ctx)
        pending = await deployable(app, domain)
        by_id = {(d.get("device") or {}).get("id"): d for d in pending}
        targets: list[dict[str, Any]] = []
        fleet = await expand_devices(app, devices, domain)
        skipped: list[str] = []
        if devices:
            for ref in fleet.refs:
                try:
                    t = await _deploy_target(app, ref, pending, by_id, domain)
                except (InvalidRequest, NotFound):
                    if not fleet.from_group(ref):
                        raise
                    # a group member with nothing pending (an HA pair not pending is no device record)
                    skipped.append(fleet.grouped[ref.lower()])
                    continue
                if all(t is not x for x in targets):  # an HA unit and its pair are one target
                    targets.append(t)
        else:
            targets = [d for d in pending if d.get("canBeDeployed", True)]
        blockers = [] if targets else ["Nothing to deploy: no device has pending changes."]
        for d in targets:
            if d.get("isDeploying"):
                blockers.append(f"{d.get('name')!r} is already being deployed.")
            elif d.get("canBeDeployed") is False:
                blockers.append(
                    f"{d.get('name')!r} can't be deployed right now (see fmc_list_deployable_devices)."
                )
        version = str(max((_as_int(d.get("version")) for d in targets), default=0))
        device_ids = [i for d in targets if (i := (d.get("device") or {}).get("id"))]
        settings: Settings = get_settings(ctx)
        units = [await units_of(app, d.get("device") or {}, domain) for d in targets]
        window, window_blockers = deploy_window_blockers(settings, "fmc_deploy")
        blockers += window_blockers
        ignored: list[str] | None = None
        if ignore_warning:
            if not settings.allow_ignore_warning:
                blockers.append(
                    "ignore_warning is disabled on this server (FMC_ALLOW_IGNORE_WARNING=false): fix the "
                    "warnings FMC reports, or ask the operator to allow ignoring them."
                )
            else:
                ignored = recorded_warnings(app, device_ids, version)
                if not ignored:
                    blockers.append(
                        "ignore_warning needs the warnings it ignores: deploy without ignore_warning first "
                        "(FMC refuses with its warnings and nothing is deployed), then preview again "
                        "with ignore_warning=true to see them listed here."
                    )
        body: dict[str, Any] = {
            "type": "DeploymentRequest",
            "version": version,
            "forceDeploy": False,
            "ignoreWarning": ignore_warning,
            "deviceList": device_ids,
        }
        if note:
            body["deploymentNote"] = note
        rows = [deployable_row(d) for d in targets]
        for r, n in zip(rows, units, strict=True):
            if n > 1:
                r["units"] = n
        interrupts = [
            r["device"] for r in rows if r.get("traffic_interruption") not in (None, False, "NO", "No")
        ]
        details: dict[str, Any] = {
            "domain": await app.domain_name(await app.domain_uuid(domain)),
            "devices": rows,
            "device_count": sum(units),
        }
        if window:
            details["deploy_window"] = window
        if fleet.groups:
            details["groups"] = fleet.groups
        if skipped:
            details["skipped_no_pending_changes"] = skipped
        if ignored:
            details["warnings_ignored"] = ignored
        path = await app.config_path("deployment/deploymentrequests", domain)

        async def post(payload: dict[str, Any]) -> Any:
            sent = time.monotonic()
            try:
                return await app.api.post(path, payload, timeout=DEPLOY_POST_TIMEOUT)
            except UpstreamError as e:  # a 400 (warnings, validation) is FMC's answer and passes through
                waited = time.monotonic() - sent
                if not deploy_unanswered(e, waited):
                    raise
                raise await deploy_timeout(app, e, device_ids, domain, waited) from e

        async def apply() -> Any:
            check_deploy_window(settings, "fmc_deploy")
            # Always try without ignoring warnings first: when FMC has none, that is the deploy.
            try:
                resp = await post({**body, "ignoreWarning": False})
            except ValidationFailed as e:
                if "warning" not in str(e).lower():
                    raise
                seen = split_warnings(str(e))
                remember_warnings(app, device_ids, version, seen)
                if not ignore_warning:
                    hint = (
                        "Review them; to deploy anyway, preview again with ignore_warning=true (the "
                        "preview lists these warnings)."
                        if settings.allow_ignore_warning
                        else "Fix them and deploy again (ignoring warnings is disabled on this server)."
                    )
                    raise ValidationFailed(
                        f"{e} FMC's pre-deployment validation raised warnings; nothing was deployed. {hint}",
                        e.status_code,
                    ) from e
                if seen != ignored:
                    # Only warnings the user saw in the preview may be ignored.
                    raise ValidationFailed(
                        "FMC's warnings changed since the preview, so nothing was deployed. Now: "
                        + " | ".join(seen)
                        + ". Preview again with ignore_warning=true to review them.",
                        e.status_code,
                    ) from e
                resp = await post(body)
            return await finish(ctx, app, resp, wait, domain, "deployment")

        return await fmc_preview(
            ctx,
            tool="fmc_deploy",
            args={
                "devices": devices,
                "note": note,
                "ignore_warning": ignore_warning,
                "wait": wait,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Deploy to {sum(units)} device(s)",
                details=details,
                fingerprint={"targets": [(r["device_id"], r["version"]) for r in rows], "ignored": ignored},
                blockers=blockers,
                blast_radius=sum(units),
                side_effects=(
                    [f"Traffic interruption expected on: {', '.join(map(str, interrupts))}"]
                    if interrupts
                    else []
                )
                + ["Pushes every pending policy/object change to the listed devices."],
            ),
            apply=apply,
        )

    @reg.dangerous(title="Roll back a deployment")
    async def fmc_rollback_deployment(
        ctx: Context,
        device: DeviceRef,
        to_job: Annotated[
            str | None,
            Field(
                description="Deployment job to return to (name like Deploy_Job_3 or UUID, from "
                "fmc_list_deployments); default: the successful deployment before the latest one"
            ),
        ] = None,
        wait: Wait = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Roll a device back to the configuration of an earlier successful deployment (FMC rollback).
        The preview lists the device's recent deployments, the one it returns to and the policy types
        involved. FMC redeploys that snapshot, so later changes stay in FMC as pending changes until
        you fix or redeploy them. With wait, polls the rollback task."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_in(app, DEVICES, device, "device", domain)
        now = int(time.time())
        page = await app.all(
            await app.config_path(f"deployment/deployabledevices/{dev['id']}/deployments", domain),
            {"filter": f"startTime:{now - 90 * 86400};endTime:{now + 60}"},
            cap=500,
        )
        history = sorted(page.items, key=lambda j: _as_int(j.get("startTime")), reverse=True)
        notes: dict[str, str] = {}
        try:  # the per-device list has no notes; the job history does (same job ids)
            jobs = await app.page(
                await app.config_path("deployment/jobhistories", domain),
                {"filter": f"deviceUUID:{dev['id']};startTime:{now - 90 * 86400};endTime:{now + 60}"},
                limit=100,
            )
            notes = {
                str(j.get("id")): str(j["deploymentNote"]) for j in jobs.items if j.get("deploymentNote")
            }
        except UpstreamError:
            pass
        ok = [j for j in history if str(j.get("status", "")).upper() in ("SUCCEEDED", "DEPLOYED", "SUCCESS")]
        blockers: list[str] = []
        target: dict[str, Any] | None = None
        if to_job:
            want = to_job.strip().lower()
            target = next(
                (
                    j
                    for j in history
                    if str(j.get("id", "")).lower() == want or str(j.get("name", "")).lower() == want
                ),
                None,
            )
            if target is None:
                raise NotFound(f"No deployment {to_job!r} for {dev.get('name')} in the last 90 days.", 404)
            if target not in ok:
                blockers.append(
                    f"{target.get('name')} did not succeed ({target.get('status')}); pick a successful one."
                )
        elif len(ok) >= 2:
            target = ok[1]  # the successful deployment before the one the device runs now
        else:
            blockers.append("No earlier successful deployment to roll back to.")
        if target is not None and history and target is history[0]:
            blockers.append(f"{target.get('name')} is already the latest deployment on this device.")
        window, window_blockers = deploy_window_blockers(get_settings(ctx), "fmc_rollback_deployment")
        blockers += window_blockers
        undone = [j.get("name") for j in ok[: ok.index(target)]] if target in ok else []

        def row(j: dict[str, Any]) -> dict[str, Any]:
            return {
                "job": j.get("name"),
                "status": j.get("status"),
                "started": iso(j.get("startTime")),
                "policies": [str(p.get("type", "")).split(".")[-1] for p in j.get("policyList") or []][:12],
                **({"note": notes[str(j.get("id"))]} if str(j.get("id")) in notes else {}),
                "id": j.get("id"),
            }

        body = {
            "type": "RollbackRequest",
            "rollbackDeviceList": [{"deploymentJobId": (target or {}).get("id"), "deviceList": [dev["id"]]}],
        }
        path = await app.config_path("deployment/rollbackrequests", domain)

        async def apply() -> Any:
            check_deploy_window(get_settings(ctx), "fmc_rollback_deployment")
            resp = await app.api.post(path, body)
            return await finish(ctx, app, resp, wait, domain, "rollback")

        return await fmc_preview(
            ctx,
            tool="fmc_rollback_deployment",
            args={"device": device, "to_job": to_job, "wait": wait, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Roll {dev.get('name')} back to {(target or {}).get('name') or '?'}",
                details={
                    "domain": await app.domain_name(await app.domain_uuid(domain)),
                    "device_runs": ok[0].get("name") if ok else None,
                    "roll_back_to": row(target) if target else None,
                    "undoes_deployments": undone,
                    "recent_deployments": [row(j) for j in history[:5]],
                    **({"deploy_window": window} if window else {}),
                },
                fingerprint={
                    "target": (target or {}).get("id"),
                    "recent": [j.get("id") for j in history[:5]],
                },
                blockers=blockers,
                blast_radius=1,
                side_effects=[
                    "Redeploys the earlier configuration snapshot to the device (traffic may be affected).",
                    "Changes made after that deployment remain in FMC and show as pending again.",
                ]
                + (
                    [
                        f"Undoes {len(undone)} successful deployments, not only the latest: "
                        + ", ".join(map(str, undone))
                    ]
                    if len(undone) > 1
                    else []
                ),
            ),
            apply=apply,
        )

    @reg.dangerous(title="Register device")
    async def fmc_register_device(
        ctx: Context,
        name: Annotated[str, Field(description="Display name for the device in FMC")],
        host: Annotated[
            str, Field(description="Device management IP or hostname (or omit with nat_id only)")
        ],
        access_policy: Annotated[str, Field(description="Access control policy name/UUID to assign")],
        reg_key: Annotated[
            str | None,
            Field(
                description="Registration key configured on the device (configure manager). Omit it to use "
                "the server's FMC_FTD_REG_KEY, so the key never passes through the conversation."
            ),
        ] = None,
        nat_id: Annotated[
            str | None, Field(description="NAT ID, if the device was configured with one")
        ] = None,
        license_caps: Annotated[
            list[str] | None,
            Field(description="Licenses, e.g. ESSENTIALS, IPS, MALWARE_DEFENSE, URL (default: ESSENTIALS)"),
        ] = None,
        performance_tier: Annotated[
            str | None, Field(description="FTDv performance tier, e.g. FTDv5, FTDv30, FTDv50, Legacy")
        ] = None,
        wait: Wait = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Register (onboard) an FTD with this FMC. The device must already point at the FMC with the
        same registration key (and NAT ID), e.g. `configure manager add <fmc> <key>`, and FMC needs
        Smart Licensing or evaluation mode. With wait, polls the registration task and then FMC's
        initial deployment to the device (several minutes). The registration key is not echoed
        back; without reg_key the server's FMC_FTD_REG_KEY is used. Next steps: fmc_update_interface,
        fmc_create_static_route, fmc_assign_policy, fmc_deploy."""
        app: FmcApp = get_client(ctx)
        key, key_source = registration_key(get_settings(ctx), reg_key)
        acp = await resolve_in(app, POLICY_KINDS["access"], access_policy, "access policy", domain)
        body = registration_body(
            name=name,
            host=host,
            key=key,
            access_policy_id=acp["id"],
            license_caps=license_caps,
            nat_id=nat_id,
            performance_tier=performance_tier,
        )
        blockers = [p for p in [registration_key_problem(key, key_source)] if p]
        try:
            await resolve_in(app, DEVICES, name, "device", domain)
            blockers.append(f"A device named {name!r} is already registered.")
        except NotFound:
            pass
        path = await app.config_path(DEVICES, domain)

        async def apply() -> Any:
            check_deploy_window(get_settings(ctx), "fmc_register_device")
            started = int(time.time())
            resp = await app.api.post(path, body)
            try:
                result = await finish(ctx, app, resp, wait, domain, "device registration")
            except TaskFailed as e:
                hint = registration_hint(str(e))
                if hint:
                    raise TaskFailed(f"{e} {hint}") from e
                raise
            if wait and isinstance(result, dict) and "task" in result:
                result["initial_deployment"] = await _wait_initial_deploy(ctx, app, name, started, domain)
            return result

        shown = slim(body)
        window, window_blockers = deploy_window_blockers(get_settings(ctx), "fmc_register_device")
        return await fmc_preview(
            ctx,
            tool="fmc_register_device",
            args={
                "name": name,
                "host": host,
                "reg_key": reg_key,
                "access_policy": access_policy,
                "nat_id": nat_id,
                "license_caps": license_caps,
                "performance_tier": performance_tier,
                "wait": wait,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Register device {name!r} ({host})",
                details={
                    "domain": await app.domain_name(await app.domain_uuid(domain)),
                    "body": shown,
                    "registration_key": f"from {key_source}",
                    "access_policy": acp.get("name"),
                    **({"deploy_window": window} if window else {}),
                },
                fingerprint=acp["id"],
                blockers=blockers + window_blockers,
                blast_radius=1,
                side_effects=["Consumes licenses; FMC deploys the assigned policy as part of registration."],
            ),
            apply=apply,
        )

    @reg.dangerous(title="Delete (unregister) device")
    async def fmc_delete_device(
        ctx: Context, device: DeviceRef, domain: Domain = None, confirm: Confirm = None
    ) -> dict[str, Any]:
        """Unregister a device from FMC. The device keeps running its last deployed configuration but is
        no longer managed; HA members must be broken out of the pair first (fmc_ha_action action=break)."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_in(app, DEVICES, device, "device", domain)
        path = await app.config_path(f"{DEVICES}/{dev['id']}", domain)
        window, window_blockers = deploy_window_blockers(get_settings(ctx), "fmc_delete_device")
        return await fmc_preview(
            ctx,
            tool="fmc_delete_device",
            args={"device": device, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Unregister device {dev.get('name')!r}",
                details={
                    "domain": await app.domain_name(await app.domain_uuid(domain)),
                    "device": {k: dev.get(k) for k in ("name", "hostName", "model", "sw_version", "id")},
                    **({"deploy_window": window} if window else {}),
                },
                fingerprint=dev.get("id"),
                blockers=window_blockers,
                blast_radius=1,
                side_effects=[
                    "The device stops being managed by FMC; its events stop arriving.",
                    "The FTD forgets this manager ('show managers' -> none): registering it again needs "
                    "`configure manager add <fmc> <reg_key>` on the device CLI first.",
                ],
            ),
            apply=lambda: _windowed(
                ctx, "fmc_delete_device", _delete_and_finish(ctx, app, path, domain, "device removal")
            ),
        )

    @reg.dangerous(title="Form HA pair")
    async def fmc_create_ha_pair(
        ctx: Context,
        name: Annotated[str, Field(description="HA pair name")],
        primary: Annotated[str, Field(description="Primary device name/UUID")],
        secondary: Annotated[str, Field(description="Secondary device name/UUID (same model and version)")],
        failover_interface: Annotated[
            str, Field(description="Physical interface name for the failover link, e.g. GigabitEthernet0/7")
        ],
        active_ip: Annotated[str, Field(description="Failover link IP on the primary")],
        standby_ip: Annotated[str, Field(description="Failover link IP on the secondary")],
        subnet_mask: Annotated[str, Field(description="Failover link mask, e.g. 255.255.255.252")],
        logical_name: Annotated[str, Field(description="Failover link logical name")] = "FAILOVER-LINK",
        state_interface: Annotated[
            str | None,
            Field(
                description="Physical interface for a separate stateful failover (state) link, e.g. "
                "GigabitEthernet0/8; omit to replicate state over the failover link"
            ),
        ] = None,
        state_active_ip: Annotated[
            str | None, Field(description="State link IP on the primary (with state_interface)")
        ] = None,
        state_standby_ip: Annotated[
            str | None, Field(description="State link IP on the secondary (with state_interface)")
        ] = None,
        state_subnet_mask: Annotated[
            str | None,
            Field(description="State link mask (with state_interface); default: the failover link's mask"),
        ] = None,
        state_logical_name: Annotated[
            str, Field(description="State link logical name (with state_interface)")
        ] = "STATE-LINK",
        wait: Wait = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Join two registered FTDs into an active/standby HA pair. The failover link carries the
        units' hello and configuration sync; connection state is replicated over it too, or over a
        separate state link (state_interface + its two addresses, recommended when traffic is heavy).
        Neither link can be changed after the pair is formed (break and form it again). The
        secondary's configuration is replaced by the primary's. With wait, polls the HA task; check
        the result with fmc_get_ha_status."""
        app: FmcApp = get_client(ctx)
        failover_net = _link_net(active_ip, standby_ip, subnet_mask, "failover link")
        state_given = [
            k
            for k, v in (
                ("state_active_ip", state_active_ip),
                ("state_standby_ip", state_standby_ip),
                ("state_subnet_mask", state_subnet_mask),
            )
            if v
        ]
        if state_interface is None and state_given:
            raise InvalidRequest(
                f"{', '.join(state_given)} need state_interface (the state link's interface)."
            )
        if state_interface is not None:
            if state_interface.strip().lower() == failover_interface.strip().lower():
                raise InvalidRequest(
                    "state_interface is the failover interface: omit state_interface (and its addresses) "
                    "to replicate state over the failover link."
                )
            if not state_active_ip or not state_standby_ip:
                raise InvalidRequest("A separate state link needs state_active_ip and state_standby_ip.")
            if state_logical_name.strip().lower() == logical_name.strip().lower():
                raise InvalidRequest("state_logical_name must differ from the failover link's logical_name.")
            state_net = _link_net(
                state_active_ip, state_standby_ip, state_subnet_mask or subnet_mask, "state link"
            )
            if state_net.overlaps(failover_net):
                raise InvalidRequest(
                    f"The state link {state_net} overlaps the failover link {failover_net}: "
                    "give it its own subnet."
                )
        p = await resolve_in(app, DEVICES, primary, "device", domain)
        s = await resolve_in(app, DEVICES, secondary, "device", domain)
        if p["id"] == s["id"]:
            raise InvalidRequest("primary and secondary must be different devices.")
        ifaces = await app.all(await app.config_path(f"{DEVICES}/{p['id']}/physicalinterfaces", domain))

        def phys(wanted: str) -> dict[str, Any]:
            for i in ifaces.items:
                if str(i.get("name", "")).lower() == wanted.lower():
                    found: dict[str, Any] = i
                    return found
            raise InvalidRequest(f"{p.get('name')!r} has no physical interface {wanted!r}.")

        iface = phys(failover_interface)
        link = {
            "useIPv6Address": False,
            "subnetMask": subnet_mask,
            "interfaceObject": {"id": iface["id"], "type": "PhysicalInterface", "name": iface.get("name")},
            "standbyIP": standby_ip,
            "activeIP": active_ip,
            "logicalName": logical_name,
        }
        state_link = link
        state_iface: dict[str, Any] | None = None
        if state_interface is not None:
            state_iface = phys(state_interface)
            state_link = {
                "useIPv6Address": False,
                "subnetMask": state_subnet_mask or subnet_mask,
                "interfaceObject": {
                    "id": state_iface["id"],
                    "type": "PhysicalInterface",
                    "name": state_iface.get("name"),
                },
                "standbyIP": state_standby_ip,
                "activeIP": state_active_ip,
                "logicalName": state_logical_name,
            }
        body = {
            "name": name,
            "type": "DeviceHAPair",
            "primary": {"id": p["id"]},
            "secondary": {"id": s["id"]},
            "ftdHABootstrap": {
                "isEncryptionEnabled": False,
                "useSameLinkForFailovers": state_iface is None,
                "lanFailover": link,
                "statefulFailover": state_link,
            },
        }
        path = await app.config_path(HA_PAIRS, domain)
        window, window_blockers = deploy_window_blockers(get_settings(ctx), "fmc_create_ha_pair")

        async def apply() -> Any:
            check_deploy_window(get_settings(ctx), "fmc_create_ha_pair")
            resp = await app.api.post(path, body)
            return await finish(ctx, app, resp, wait, domain, "HA formation")

        return await fmc_preview(
            ctx,
            tool="fmc_create_ha_pair",
            args={
                "name": name,
                "primary": primary,
                "secondary": secondary,
                "failover_interface": failover_interface,
                "active_ip": active_ip,
                "standby_ip": standby_ip,
                "subnet_mask": subnet_mask,
                "logical_name": logical_name,
                "state_interface": state_interface,
                "state_active_ip": state_active_ip,
                "state_standby_ip": state_standby_ip,
                "state_subnet_mask": state_subnet_mask,
                "state_logical_name": state_logical_name,
                "wait": wait,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Form HA pair {name!r}: {p.get('name')} (primary) + {s.get('name')} (secondary)",
                details={
                    "domain": await app.domain_name(await app.domain_uuid(domain)),
                    "failover_link": f"{iface.get('name')} {logical_name} {active_ip}/{standby_ip}",
                    "state_link": (
                        f"{state_iface.get('name')} {state_logical_name} {state_active_ip}/{state_standby_ip}"
                        if state_iface
                        else "same as the failover link"
                    ),
                    "body": body,
                    **({"deploy_window": window} if window else {}),
                },
                fingerprint=[p["id"], s["id"], iface["id"], state_iface and state_iface["id"]],
                blockers=window_blockers,
                blast_radius=2,
                side_effects=[
                    "The secondary's configuration is overwritten; both devices sync and may reload.",
                    "The failover and state links are fixed once the pair exists: changing them means "
                    "breaking the pair (fmc_ha_action action=break) and forming it again.",
                ],
            ),
            apply=apply,
        )

    @reg.dangerous(title="Break, switch or delete HA pair")
    async def fmc_ha_action(
        ctx: Context,
        ha_pair: Annotated[str, Field(description="HA pair name/UUID (from fmc_list_ha_pairs)")],
        action: Annotated[
            Literal["break", "switch", "delete"],
            Field(
                description="break: split into two standalone devices; switch: fail over to the standby; "
                "delete: remove the pair (and its devices) from FMC"
            ),
        ],
        force: Annotated[bool, Field(description="break: force even if the peer is unreachable")] = False,
        wait: Wait = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Break an FTD HA pair into standalone devices, switch the active unit (failover), or delete
        the pair from FMC. All are disruptive; the preview states the effect. Before a switch,
        fmc_get_ha_status (ready_for_switch, its checks) says whether the standby can take over; the
        fmc_ha_failover_check prompt runs the checks, the switch and the verification."""
        app: FmcApp = get_client(ctx)
        if force and action != "break":
            raise InvalidRequest("force only applies to action='break'.")
        ha = await resolve_in(app, HA_PAIRS, ha_pair, "HA pair", domain)
        meta = ha.get("metadata") or {}
        state = {
            "primary_status": (meta.get("primaryStatus") or {}).get("currentStatus"),
            "secondary_status": (meta.get("secondaryStatus") or {}).get("currentStatus"),
        }
        path = await app.config_path(f"{HA_PAIRS}/{ha['id']}", domain)
        window, window_blockers = deploy_window_blockers(get_settings(ctx), "fmc_ha_action")
        effects = {
            "break": "Both units become standalone; the standby's interfaces are shut until reconfigured.",
            "switch": "The standby becomes active; connections without stateful failover drop.",
            "delete": "The pair and both devices are removed from FMC management.",
        }

        async def apply() -> Any:
            check_deploy_window(get_settings(ctx), "fmc_ha_action")
            if action == "delete":
                resp = await app.api.delete(path)
            else:
                body: dict[str, Any] = {
                    "id": ha["id"],
                    "action": "HABREAK" if action == "break" else "SWITCH",
                }
                if action == "break":
                    body["forceBreak"] = force
                resp = await app.api.put(path, body)
            return await finish(ctx, app, resp, wait, domain, f"HA {action}")

        return await fmc_preview(
            ctx,
            tool="fmc_ha_action",
            args={"ha_pair": ha_pair, "action": action, "force": force, "wait": wait, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"HA {action} on {ha.get('name')!r}",
                details={
                    "domain": await app.domain_name(await app.domain_uuid(domain)),
                    "primary": ref_label(ha.get("primary") or {}),
                    "secondary": ref_label(ha.get("secondary") or {}),
                    **{k: v for k, v in state.items() if v},
                    **({"deploy_window": window} if window else {}),
                },
                fingerprint={"id": ha.get("id"), **state},
                blockers=window_blockers,
                blast_radius=2,
                side_effects=[effects[action]],
            ),
            apply=apply,
        )

    @reg.dangerous(title="Delete policy")
    async def fmc_delete_policy(
        ctx: Context,
        kind: Annotated[PolicyKind, Field(description="Policy type")],
        policy: Annotated[str, Field(description="Policy name or UUID")],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a whole policy (access, NAT, prefilter, ...). Preview shows its rule count and the
        devices it is assigned to; FMC refuses to delete a policy that is still assigned."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, POLICY_KINDS[kind], policy, f"{kind} policy", domain)
        details: dict[str, Any] = {"policy": p.get("name"), "id": p["id"]}
        sub = {
            "access": "accessrules",
            "nat": "natrules",
            "prefilter": "prefilterrules",
            "file": "filerules",
        }.get(kind)
        if sub:
            rules = await all_rules(
                app, await app.config_path(f"{POLICY_KINDS[kind]}/{p['id']}/{sub}", domain)
            )
            details["rules"] = len(rules.items)
        targets = [
            ref_label(t)
            for a in await policy_assignments(app, domain)
            if (a.get("policy") or {}).get("id") == p["id"]
            for t in a.get("targets") or []
        ]
        details["assigned_to"] = targets
        blockers = (
            [f"Still assigned to: {', '.join(targets)}. Reassign those devices first."] if targets else []
        )
        if p.get("isSystemDefined"):
            blockers.append("System-defined policies can't be deleted.")
        path = await app.config_path(f"{POLICY_KINDS[kind]}/{p['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_policy",
            owned=[p],
            args={"kind": kind, "policy": policy, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete {kind} policy {p.get('name')!r}",
                details=details,
                fingerprint=editable(p),
                blockers=blockers,
                side_effects=["Irreversible: the policy and all of its rules are removed."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )

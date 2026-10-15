"""Dangerous-tier tools: deploy, device registration/removal, HA form/break/switch, policy deletion."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import time
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    TaskFailed,
    ToolRegistrar,
    UpstreamTimeout,
    ValidationFailed,
    get_client,
    get_settings,
    poll_until,
    preview_or_apply,
)

from fmc_mcp.client import FmcApp
from fmc_mcp.config import Settings
from fmc_mcp.rails import (
    deploy_window_blockers,
    recorded_warnings,
    remember_warnings,
    split_warnings,
    units_of,
)
from fmc_mcp.tools.common import Domain, ref_label, resolve_in, slim
from fmc_mcp.tools.deploy import JOBS, deployable, deployable_row
from fmc_mcp.tools.devices import DEVICES, HA_PAIRS, DeviceRef
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import POLICY_KINDS, PolicyKind, all_rules
from fmc_mcp.tools.system import iso

DONE = {"deployed", "succeeded", "success", "completed", "complete"}
Wait = Annotated[bool, Field(description="Wait for the FMC task to finish (otherwise return the task id)")]


FAILED_WORDS = ("fail", "cancel", "error", "interrupt", "abort")


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


async def finish(ctx: Context, app: FmcApp, resp: Any, wait: bool, domain: str | None, what: str) -> Any:
    app.invalidate_cache()
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
        fresh = [j for j in page.items if _as_int(j.get("startTime")) >= since - 5]
        fresh.sort(key=lambda j: _as_int(j.get("startTime")), reverse=True)
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


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Deploy configuration")
    async def fmc_deploy(
        ctx: Context,
        devices: Annotated[
            list[str] | None,
            Field(description="Device names/UUIDs to deploy; default: every device with pending changes"),
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
        if devices:
            for ref in devices:
                targets.append(await _deploy_target(app, ref, pending, by_id, domain))
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
        device_ids = [(d.get("device") or {}).get("id") for d in targets]
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
        if ignored:
            details["warnings_ignored"] = ignored
        path = await app.config_path("deployment/deploymentrequests", domain)

        async def apply() -> Any:
            try:
                resp = await app.api.post(path, body)
            except ValidationFailed as e:
                if "warning" in str(e).lower() and not ignore_warning:
                    remember_warnings(app, device_ids, version, split_warnings(str(e)))
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
                raise
            return await finish(ctx, app, resp, wait, domain, "deployment")

        return await preview_or_apply(
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
                "id": j.get("id"),
            }

        body = {
            "type": "RollbackRequest",
            "rollbackDeviceList": [{"deploymentJobId": (target or {}).get("id"), "deviceList": [dev["id"]]}],
        }
        path = await app.config_path("deployment/rollbackrequests", domain)

        async def apply() -> Any:
            resp = await app.api.post(path, body)
            return await finish(ctx, app, resp, wait, domain, "rollback")

        return await preview_or_apply(
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
        reg_key: Annotated[
            str, Field(description="Registration key configured on the device (configure manager)")
        ],
        access_policy: Annotated[str, Field(description="Access control policy name/UUID to assign")],
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
        back. Next steps: fmc_update_interface, fmc_create_static_route, fmc_assign_policy, fmc_deploy."""
        app: FmcApp = get_client(ctx)
        acp = await resolve_in(app, POLICY_KINDS["access"], access_policy, "access policy", domain)
        body: dict[str, Any] = {
            "name": name,
            "hostName": host,
            "regKey": reg_key,
            "type": "Device",
            "license_caps": license_caps or ["ESSENTIALS"],
            "accessPolicy": {"id": acp["id"], "type": "AccessPolicy"},
        }
        if nat_id:
            body["natID"] = nat_id
        if performance_tier:
            body["performanceTier"] = performance_tier
        blockers = []
        try:
            await resolve_in(app, DEVICES, name, "device", domain)
            blockers.append(f"A device named {name!r} is already registered.")
        except NotFound:
            pass
        path = await app.config_path(DEVICES, domain)

        async def apply() -> Any:
            started = int(time.time())
            resp = await app.api.post(path, body)
            try:
                result = await finish(ctx, app, resp, wait, domain, "device registration")
            except TaskFailed as e:
                if "timed out" in str(e).lower():
                    raise TaskFailed(
                        f"{e} Check on the FTD that 'show managers' lists this FMC as Pending with the same "
                        "registration key (configure manager add) and that it can reach FMC on TCP 8305."
                    ) from e
                if "smart licens" in str(e).lower():
                    raise TaskFailed(
                        f"{e} FMC must be registered with Smart Licensing or be in evaluation mode first "
                        "(fmc_license_status shows it)."
                    ) from e
                raise
            if wait and isinstance(result, dict) and "task" in result:
                result["initial_deployment"] = await _wait_initial_deploy(ctx, app, name, started, domain)
            return result

        shown = slim(body)
        window, window_blockers = deploy_window_blockers(get_settings(ctx), "fmc_register_device")
        return await preview_or_apply(
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
        no longer managed; HA members must be broken out of the pair first (fmc_break_ha_pair)."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_in(app, DEVICES, device, "device", domain)
        path = await app.config_path(f"{DEVICES}/{dev['id']}", domain)
        window, window_blockers = deploy_window_blockers(get_settings(ctx), "fmc_delete_device")
        return await preview_or_apply(
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
            apply=lambda: _delete_and_finish(ctx, app, path, domain, "device removal"),
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
        wait: Wait = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Join two registered FTDs into an active/standby HA pair over one failover/stateful link.
        The secondary's configuration is replaced by the primary's. With wait, polls the HA task."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, DEVICES, primary, "device", domain)
        s = await resolve_in(app, DEVICES, secondary, "device", domain)
        if p["id"] == s["id"]:
            raise InvalidRequest("primary and secondary must be different devices.")
        ifaces = await app.all(await app.config_path(f"{DEVICES}/{p['id']}/physicalinterfaces", domain))
        iface = next(
            (i for i in ifaces.items if str(i.get("name", "")).lower() == failover_interface.lower()), None
        )
        if iface is None:
            raise InvalidRequest(f"{p.get('name')!r} has no physical interface {failover_interface!r}.")
        link = {
            "useIPv6Address": False,
            "subnetMask": subnet_mask,
            "interfaceObject": {"id": iface["id"], "type": "PhysicalInterface", "name": iface.get("name")},
            "standbyIP": standby_ip,
            "activeIP": active_ip,
            "logicalName": logical_name,
        }
        body = {
            "name": name,
            "type": "DeviceHAPair",
            "primary": {"id": p["id"]},
            "secondary": {"id": s["id"]},
            "ftdHABootstrap": {
                "isEncryptionEnabled": False,
                "useSameLinkForFailovers": True,
                "lanFailover": link,
                "statefulFailover": link,
            },
        }
        path = await app.config_path(HA_PAIRS, domain)
        window, window_blockers = deploy_window_blockers(get_settings(ctx), "fmc_create_ha_pair")

        async def apply() -> Any:
            resp = await app.api.post(path, body)
            return await finish(ctx, app, resp, wait, domain, "HA formation")

        return await preview_or_apply(
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
                "wait": wait,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Form HA pair {name!r}: {p.get('name')} (primary) + {s.get('name')} (secondary)",
                details={
                    "domain": await app.domain_name(await app.domain_uuid(domain)),
                    "body": body,
                    **({"deploy_window": window} if window else {}),
                },
                fingerprint=[p["id"], s["id"], iface["id"]],
                blockers=window_blockers,
                blast_radius=2,
                side_effects=[
                    "The secondary's configuration is overwritten; both devices sync and may reload."
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
        the pair from FMC. All are disruptive; the preview states the effect."""
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

        return await preview_or_apply(
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
        sub = {"access": "accessrules", "nat": "natrules", "prefilter": "prefilterrules"}.get(kind)
        if sub:
            rules = await all_rules(
                app, await app.config_path(f"{POLICY_KINDS[kind]}/{p['id']}/{sub}", domain)
            )
            details["rules"] = len(rules.items)
        assigned = await app.all(await app.config_path("assignment/policyassignments", domain), cap=5000)
        targets = [
            ref_label(t)
            for a in assigned.items
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
        return await preview_or_apply(
            ctx,
            tool="fmc_delete_policy",
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

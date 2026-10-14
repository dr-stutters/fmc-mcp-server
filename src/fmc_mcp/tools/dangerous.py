"""Dangerous-tier tools: deploy, device registration/removal, HA form/break/switch, policy deletion."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    get_client,
    get_settings,
    poll_until,
    preview_or_apply,
)

from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, ref_label, resolve_in, slim
from fmc_mcp.tools.deploy import deployable, deployable_row
from fmc_mcp.tools.devices import DEVICES, HA_PAIRS, DeviceRef
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.policies import POLICY_KINDS, PolicyKind, all_rules

DONE = {"deployed", "succeeded", "success", "completed", "complete"}
Wait = Annotated[bool, Field(description="Wait for the FMC task to finish (otherwise return the task id)")]


def task_state(task: dict[str, Any]) -> tuple[bool, str | None]:
    """(finished, failure message) for an FMC task status."""
    status = str(task.get("status") or "").strip()
    low = status.lower()
    if "fail" in low or low in ("cancelled", "canceled", "error"):
        return True, f"{status}: {task.get('message') or ''}".strip(": ")
    return low in DONE, None


async def wait_task(ctx: Context, app: FmcApp, task_id: str, domain: str | None, what: str) -> dict[str, Any]:
    path = await app.config_path(f"job/taskstatuses/{task_id}", domain)
    timeout = float(get_settings(ctx).mcp_task_timeout)

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


def task_id_of(resp: Any) -> str | None:
    if isinstance(resp, dict):
        task = (resp.get("metadata") or {}).get("task") or {}
        return task.get("id")
    return None


async def finish(ctx: Context, app: FmcApp, resp: Any, wait: bool, domain: str | None, what: str) -> Any:
    app.invalidate_cache()
    tid = task_id_of(resp)
    if tid is None:
        return slim(resp) if isinstance(resp, dict) else resp
    if not wait:
        return {"task_id": tid, "note": "Started; check progress with fmc_get_task."}
    return {"task_id": tid, "task": await wait_task(ctx, app, tid, domain, what)}


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
                dev = await resolve_in(app, DEVICES, ref, "device", domain)
                if dev["id"] not in by_id:
                    raise InvalidRequest(
                        f"{dev.get('name')!r} has no pending changes (see fmc_list_deployable_devices)."
                    )
                targets.append(by_id[dev["id"]])
        else:
            targets = [d for d in pending if d.get("canBeDeployed", True)]
        blockers = [] if targets else ["Nothing to deploy: no device has pending changes."]
        version = max((str(d.get("version") or "0") for d in targets), default="0", key=int)
        body: dict[str, Any] = {
            "type": "DeploymentRequest",
            "version": version,
            "forceDeploy": False,
            "ignoreWarning": ignore_warning,
            "deviceList": [(d.get("device") or {}).get("id") for d in targets],
        }
        if note:
            body["deploymentNote"] = note
        rows = [deployable_row(d) for d in targets]
        interrupts = [
            r["device"] for r in rows if r.get("traffic_interruption") not in (None, False, "NO", "No")
        ]
        path = await app.config_path("deployment/deploymentrequests", domain)

        async def apply() -> Any:
            resp = await app.api.post(path, body)
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
                f"Deploy to {len(targets)} device(s)",
                details={"devices": rows},
                fingerprint=[(r["device_id"], r["version"]) for r in rows],
                blockers=blockers,
                side_effects=(
                    [f"Traffic interruption expected on: {', '.join(map(str, interrupts))}"]
                    if interrupts
                    else []
                )
                + ["Pushes every pending policy/object change to the listed devices."],
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
        same registration key (and NAT ID). With wait, polls the registration task (several minutes).
        The registration key is not echoed back."""
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
            resp = await app.api.post(path, body)
            return await finish(ctx, app, resp, wait, domain, "device registration")

        shown = slim(body)
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
                details={"body": shown, "access_policy": acp.get("name")},
                blockers=blockers,
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
        return await preview_or_apply(
            ctx,
            tool="fmc_delete_device",
            args={"device": device, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Unregister device {dev.get('name')!r}",
                details={
                    "device": {k: dev.get(k) for k in ("name", "hostName", "model", "sw_version", "id")}
                },
                fingerprint=dev.get("id"),
                side_effects=["The device stops being managed by FMC; its events stop arriving."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
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
                details={"body": body},
                fingerprint=[p["id"], s["id"]],
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
        ha = await resolve_in(app, HA_PAIRS, ha_pair, "HA pair", domain)
        path = await app.config_path(f"{HA_PAIRS}/{ha['id']}", domain)
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
                    "primary": ref_label(ha.get("primary") or {}),
                    "secondary": ref_label(ha.get("secondary") or {}),
                },
                fingerprint=ha.get("id"),
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

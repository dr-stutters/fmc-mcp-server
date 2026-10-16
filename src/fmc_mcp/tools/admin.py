"""Admin operations (F14): backups, upgrade/version status, health policies, FMC users, object overrides."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    AuthError,
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    ValidationFailed,
    get_client,
    list_result,
    object_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, ref_label, resolve_in, resolve_object, slim
from fmc_mcp.tools.dangerous import Wait, finish
from fmc_mcp.tools.devices import DEVICES, DeviceRef
from fmc_mcp.tools.object_writes import applied, editable, value_fields

HEALTH = "policy/healthpolicies"
LOWER_IS_WORSE = {"hm_chm"}  # modules whose critical threshold sits below the warning one (FMC 10.0.1)
BACKUP_FILES = "backup/files"
UPGRADE_INFO = "/api/fmc_platform/v1/updates/deviceupgradeinfo"
UPGRADE_PACKAGES = "/api/fmc_platform/v1/updates/upgradepackages"

ObjectRef = Annotated[str, Field(description="Object name or UUID")]
TypeRef = Annotated[
    str | None, Field(description="Object type (host, network, range, ...) if the name is ambiguous")
]


def backup_row(b: dict[str, Any]) -> dict[str, Any]:
    row = {
        "target": b.get("targetId"),
        "device_type": b.get("deviceType"),
        "file": b.get("fileName"),
        "created": b.get("creationDate"),
        "location": b.get("location"),
        "size_mb": b.get("size"),
        "system": b.get("systemInformation"),
        "version": b.get("backupVersion"),
    }
    return {k: v for k, v in row.items() if v not in (None, "")}


def module_row(m: dict[str, Any]) -> dict[str, Any]:
    row = {
        "module": m.get("moduleId"),
        "enabled": m.get("enabled"),
        "applies_to": m.get("type"),
        "warning": m.get("warningThreshold"),
        "critical": m.get("criticalThreshold"),
    }
    return {k: v for k, v in row.items() if v is not None}


def _with_thresholds(m: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """The module with the new enabled/threshold values; per-alert thresholds (alertConfig, yellow/red)
    that equalled the old module thresholds follow the new ones, as in the FMC UI."""
    changed: dict[str, Any] = {
        k: new[k] for k in ("enabled", "warningThreshold", "criticalThreshold") if k in new
    }
    out: dict[str, Any] = {**m, **changed}
    follow: dict[str, tuple[str, Any]] = {
        "yellow": ("warningThreshold", m.get("warningThreshold")),
        "red": ("criticalThreshold", m.get("criticalThreshold")),
    }
    alerts = []
    for a in m.get("alertConfig") or []:
        ths = []
        for t in a.get("thresholds") or []:
            key, old = follow.get(str(t.get("type")), (None, None))
            if key and old is not None and t.get("value") == old and key in new:
                t = {**t, "value": new[key]}
            ths.append(t)
        alerts.append({**a, "thresholds": ths} if a.get("thresholds") is not None else a)
    if m.get("alertConfig") is not None:
        out["alertConfig"] = alerts
    return out


async def _no_file_is_empty(app: FmcApp, path: str) -> list[dict[str, Any]]:
    """FMC answers 400 'File not found.' when there is no backup at all."""
    try:
        page = await app.all(path, expanded=False, cap=1000)
    except ValidationFailed as e:
        if "file not found" in str(e).lower():
            return []
        raise
    return page.items


def register(reg: ToolRegistrar) -> None:
    # --- backups -------------------------------------------------------------------------------

    @reg.read(title="List backups")
    async def fmc_list_backups(
        ctx: Context,
        device: Annotated[str | None, Field(description="Only this device's backups (name or UUID)")] = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the backups FMC holds (FMC itself and devices): file, date, location, size and version.
        device='manager' lists only FMC's own backups.
        Answers "when was the last backup?". Empty means FMC has no backup files. Downloads and restores
        stay in the FMC UI."""
        app: FmcApp = get_client(ctx)
        suffix = BACKUP_FILES
        if device:
            if device.strip().lower() in ("manager", "fmc"):
                suffix = f"{BACKUP_FILES}/manager"
            else:
                dev = await resolve_in(app, DEVICES, device, "device", domain)
                suffix = f"{BACKUP_FILES}/{dev['id']}"
        items = await _no_file_is_empty(app, await app.config_path(suffix, domain))
        rows = sorted((backup_row(b) for b in items), key=lambda r: str(r.get("created", "")), reverse=True)
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    @reg.dangerous(title="Back up devices")
    async def fmc_backup_devices(
        ctx: Context,
        devices: Annotated[
            list[str], Field(min_length=1, max_length=20, description="Device names or UUIDs to back up")
        ],
        wait: Wait = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Back up the configuration of managed devices to FMC (retrieved to the management center).
        Runs as an FMC task; with wait, polls it. FTDv and some models don't support device backup; FMC
        then answers "No devices found". List the result with fmc_list_backups."""
        app: FmcApp = get_client(ctx)
        refs = []
        for d in dict.fromkeys(devices):
            dev = await resolve_in(app, DEVICES, d, "device", domain)
            refs.append({"type": "Device", "id": dev["id"], "name": dev.get("name")})
        # the backup API looks devices up in its own domain (a leaf domain on multi-domain FMCs)
        where = {await app.device_domain(DEVICES, r["id"], await app.domain_uuid(domain)) for r in refs}
        if len(where) > 1:
            raise InvalidRequest("These devices are in different domains; back them up per domain.")
        path = f"/api/fmc_config/v1/domain/{where.pop()}/backup/operational/devicebackup"
        body = {
            "devices": [{"type": r["type"], "id": r["id"]} for r in refs],
            "retrieveToManagementCenter": "true",
        }

        async def apply() -> Any:
            try:
                resp = await app.api.post(path, body)
            except NotFound as e:
                raise NotFound(
                    f"{e} FMC finds no device it can back up: device backup is not supported on every model "
                    "(e.g. Threat Defense Virtual).",
                    404,
                ) from e
            return await finish(ctx, app, resp, wait, domain, "device backup")

        return await fmc_preview(
            ctx,
            tool="fmc_backup_devices",
            args={"devices": devices, "wait": wait, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Back up {len(refs)} device(s): {', '.join(str(r['name']) for r in refs)}",
                details={"devices": [r["name"] for r in refs]},
                fingerprint=[r["id"] for r in refs],
                blast_radius=len(refs),
                side_effects=["Runs a backup task on each device and stores the files on FMC (disk space)."],
            ),
            apply=apply,
        )

    # --- versions / upgrades ---------------------------------------------------------------------

    @reg.read(title="Version and upgrade status")
    async def fmc_upgrade_status(
        ctx: Context, domain: Domain = None, response_format: ResponseFormat = "markdown"
    ) -> ToolResult:
        """Software versions at a glance: FMC version, VDB and rule-update (SRU/LSP) versions, each
        device's version, upgrade history and maintenance mode, and the upgrade packages FMC holds. Read
        only: upgrades themselves stay in the FMC UI."""
        app: FmcApp = get_client(ctx)
        info = ((await app.api.get("/api/fmc_platform/v1/info/serverversion")) or {}).get("items") or [{}]
        devs = await app.all(await app.config_path(DEVICES, domain))
        out: dict[str, Any] = {
            "fmc": {
                "version": info[0].get("serverVersion"),
                "vdb": info[0].get("vdbVersion"),
                "sru": info[0].get("sruVersion"),
                "lsp": info[0].get("lspVersion"),
            },
            "devices": [
                {
                    "name": d.get("name"),
                    "version": d.get("sw_version"),
                    "model": d.get("model"),
                    "snort": d.get("snortEngine"),
                    "lsp": d.get("lspVersion"),
                }
                for d in devs.items
            ],
        }
        notes: list[str] = []
        try:
            hist = await app.all(UPGRADE_INFO)
            by_id = {}
            for item in hist.items:
                for di in item.get("deviceInfo") or []:
                    by_id[(di.get("device") or {}).get("id")] = di
            for row, d in zip(out["devices"], devs.items, strict=True):
                di = by_id.get(d.get("id")) or {}
                if di:
                    row["maintenance_mode"] = di.get("maintenanceMode")
                    row["upgrade_history"] = [h.get("version") for h in di.get("upgradeHistory") or []]
        except UpstreamError as e:
            notes.append(f"upgrade history unavailable: {e}")
        try:
            pkgs = await app.api.get(UPGRADE_PACKAGES, {"expanded": "true", "limit": 100}, timeout=30)
            out["upgrade_packages"] = [
                {"name": p.get("name"), "version": p.get("upgradePackageVersion") or p.get("version")}
                for p in (pkgs or {}).get("items", [])
            ]
        except UpstreamError as e:
            notes.append(f"upgrade packages unavailable: {e}")
        if notes:
            out["notes"] = notes
        return object_result(out, fmt=response_format)

    # --- health policies ---------------------------------------------------------------------------

    @reg.read(title="Health policies")
    async def fmc_get_health_policy(
        ctx: Context,
        policy: Annotated[
            str | None, Field(description="Health policy name or UUID; omit to list them all")
        ] = None,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List health policies (FMC and device policies, which one is the default, and which devices use
        each), or show one policy's modules with enabled state and warning/critical thresholds. Change a
        threshold with fmc_update_health_policy."""
        app: FmcApp = get_client(ctx)
        devs = await app.all(await app.config_path(DEVICES, domain))
        users: dict[str, list[str]] = {}
        for d in devs.items:
            hp = (d.get("healthPolicy") or {}).get("id")
            if hp:
                users.setdefault(hp, []).append(str(d.get("name")))
        if not policy:
            page = await app.all(await app.config_path(HEALTH, domain), expanded=False)
            rows = [
                {
                    "name": p.get("name"),
                    "type": p.get("policyType"),
                    "default": p.get("defaultPolicy"),
                    "devices": users.get(p.get("id", "")),
                    "id": p.get("id"),
                }
                for p in page.items
            ]
            return list_result(page_of(rows, limit=1000, offset=0), fmt=response_format)
        p = await resolve_in(app, HEALTH, policy, "health policy", domain)
        out = {
            "name": p.get("name"),
            "type": p.get("policyType"),
            "default": p.get("defaultPolicy"),
            "description": p.get("description"),
            "devices": users.get(p.get("id", "")),
            "modules": [module_row(m) for m in p.get("healthModules") or []],
            "id": p.get("id"),
        }
        return object_result(out, fmt=response_format)

    @reg.write(title="Update health policy module")
    async def fmc_update_health_policy(
        ctx: Context,
        policy: Annotated[str, Field(description="Health policy name or UUID")],
        module: Annotated[str, Field(description="Module id from fmc_get_health_policy, e.g. hm_cpu")],
        enabled: Annotated[bool | None, Field(description="Turn the module on or off")] = None,
        warning: Annotated[
            int | None, Field(ge=0, description="Warning threshold (module's unit, often %)")
        ] = None,
        critical: Annotated[int | None, Field(ge=0, description="Critical threshold")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Turn one health module on or off or change its warning/critical thresholds. The preview shows
        the old and new values and the devices using the policy. Omitted values stay as they are;
        thresholds are in the module's unit (mostly percent)."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, HEALTH, policy, "health policy", domain)
        path = await app.config_path(f"{HEALTH}/{p['id']}", domain)
        cur = await app.api.get(path)
        mods = cur.get("healthModules") or []
        target = next((m for m in mods if str(m.get("moduleId", "")).lower() == module.lower()), None)
        if target is None:
            known = ", ".join(sorted(str(m.get("moduleId")) for m in mods))
            raise NotFound(f"No module {module!r} in {p.get('name')!r}. Modules: {known}", 404)
        new = dict(target)
        if enabled is not None:
            new["enabled"] = enabled
        if warning is not None:
            new["warningThreshold"] = warning
        if critical is not None:
            new["criticalThreshold"] = critical
        blockers = []
        if new == target:
            blockers.append("Nothing to change.")
        w, c = new.get("warningThreshold"), new.get("criticalThreshold")
        user_set = warning is not None or critical is not None
        lower_is_worse = str(target.get("moduleId", "")).lower() in LOWER_IS_WORSE
        if user_set and isinstance(w, int) and isinstance(c, int) and not lower_is_worse and w > c:
            blockers.append(
                f"warning ({w}) is above critical ({c}); for this module critical should be higher."
            )

        async def apply() -> Any:
            now = await app.api.get(path)  # full-object PUT: start from the current policy
            mods_now = now.get("healthModules") or []
            if not any(str(m.get("moduleId", "")).lower() == module.lower() for m in mods_now):
                raise NotFound(f"Module {module!r} is gone from {p.get('name')!r}; nothing was changed.", 404)
            body = editable(now)
            body["healthModules"] = [
                _with_thresholds(m, new) if str(m.get("moduleId", "")).lower() == module.lower() else m
                for m in now.get("healthModules") or []
            ]
            return await applied(app, lambda: app.api.put(path, body))

        return await fmc_preview(
            ctx,
            tool="fmc_update_health_policy",
            args={
                "policy": policy,
                "module": module,
                "enabled": enabled,
                "warning": warning,
                "critical": critical,
                "domain": domain,
            },
            confirm=confirm,
            owned=[cur],
            plan=Plan(
                f"Health policy {p.get('name')!r}: module {target.get('moduleId')}",
                details={"from": module_row(target), "to": module_row(new)},
                fingerprint=module_row(target),  # FMC returns alertConfig in random order
                blockers=blockers,
            ),
            apply=apply,
        )

    # --- users -----------------------------------------------------------------------------------

    @reg.read(title="FMC users")
    async def fmc_list_users(
        ctx: Context,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List FMC user accounts with their roles, authentication method (internal/external), whether
        they are enabled and the password lifetime. Read only: FMC's API can't create or change users.
        Needs an account with User Management rights (the least-privilege roles don't have them)."""
        app: FmcApp = get_client(ctx)
        try:
            page = await app.all(await app.config_path("users/users", domain))
        except AuthError as e:
            raise AuthError(
                f"{e} Listing users needs FMC's User Management permission, which the least-privilege "
                "roles mcp-ro/mcp-rw deliberately don't have (docs/least-privilege.md).",
                e.status_code,
            ) from e
        rows = [
            {
                "username": u.get("username") or u.get("name"),
                "roles": [r.get("name") for r in u.get("roles") or []],
                "auth": u.get("authenticationMethod"),
                "enabled": u.get("isUserEnabled"),
                "password_lifetime": u.get("passwordLifetime"),
                "id": u.get("id"),
            }
            for u in page.items
        ]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

    # --- object overrides --------------------------------------------------------------------------

    @reg.read(title="Object overrides")
    async def fmc_list_object_overrides(
        ctx: Context,
        object: ObjectRef,
        type: TypeRef = None,
        domain: Domain = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """Show the per-device overrides of an overridable object (e.g. a host whose address differs on
        one FTD), so a deploy holds no surprises: device, overridden value and the default value."""
        app: FmcApp = get_client(ctx)
        t, obj = await resolve_object(app, object, domain, [type] if type else None)
        path = await app.config_path(f"{t.path}/{obj['id']}/overrides", domain)
        page = await app.all(path)
        rows = [
            {
                "device": ref_label((o.get("overrides") or {}).get("target") or {}),
                "value": o.get("value") or o.get("literals") or o.get("objects"),
                "id": o.get("id"),
            }
            for o in page.items
        ]
        extra = {
            "object": obj.get("name"),
            "default_value": obj.get("value"),
            "overridable": obj.get("overridable"),
        }
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format, extra=extra)

    @reg.write(title="Set object override")
    async def fmc_set_object_override(
        ctx: Context,
        object: ObjectRef,
        device: DeviceRef,
        value: Annotated[
            str | None, Field(description="The value on this device (host IP, network, range, FQDN, port)")
        ] = None,
        remove: Annotated[bool, Field(description="Remove the device's override instead")] = False,
        type: TypeRef = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Give a value object (host, network, range, FQDN) a different value on one device (an override),
        or remove that override. Makes the object overridable first when needed (a separate change).
        Every other device keeps the default value. Takes effect on the next deploy to that device."""
        app: FmcApp = get_client(ctx)
        if remove == (value is not None):
            raise InvalidRequest("Pass either value (set an override) or remove=true.")
        t, obj = await resolve_object(app, object, domain, [type] if type else None)
        if "value" not in obj:
            raise InvalidRequest(
                f"{obj.get('name')!r} is a {obj.get('type')}; overrides here support value objects only."
            )
        fields = value_fields(t, value, None) if value is not None else {}  # validates and normalises
        new_value = fields.get("value", value)
        dev = await resolve_in(app, DEVICES, device, "device", domain)
        base = await app.config_path(f"{t.path}/{obj['id']}", domain)
        existing = await app.all(f"{base}/overrides")
        mine = next(
            (
                o
                for o in existing.items
                if ((o.get("overrides") or {}).get("target") or {}).get("id") == dev["id"]
            ),
            None,
        )
        blockers = []
        if remove and mine is None:
            blockers.append(f"{obj.get('name')!r} has no override for {dev.get('name')!r}.")
        if not remove and mine is not None and mine.get("value") == new_value:
            blockers.append("Nothing to change.")

        async def apply() -> Any:
            if remove:
                return await applied(
                    app, lambda: app.api.delete(base, params={"overrideTargetId": dev["id"]})
                )
            cur = await app.api.get(base)
            core = {k: v for k, v in editable(cur).items() if k != "overrides"}  # full PUT: keep every field
            if not cur.get("overridable"):
                await app.api.put(base, {**core, "overridable": True})
            body = {
                **core,
                **fields,
                "overridable": True,
                "overrides": {
                    "parent": {"id": cur["id"], "type": cur.get("type")},
                    "target": {"id": dev["id"], "type": "Device", "name": dev.get("name")},
                },
            }
            try:
                return await applied(app, lambda: app.api.put(base, body))
            except UpstreamError as e:
                note = (
                    " The object was made overridable first and stays so."
                    if not cur.get("overridable")
                    else ""
                )
                raise UpstreamError(f"Setting the override failed: {e}{note}", e.status_code) from e

        return await fmc_preview(
            ctx,
            tool="fmc_set_object_override",
            args={
                "object": object,
                "device": device,
                "value": value,
                "remove": remove,
                "type": type,
                "domain": domain,
            },
            confirm=confirm,
            owned=[obj],
            plan=Plan(
                (f"Remove the override of {obj.get('name')!r} on {dev.get('name')!r}")
                if remove
                else f"Override {obj.get('name')!r} on {dev.get('name')!r}: {value}",
                details={
                    "default_value": obj.get("value"),
                    "current_override": (mine or {}).get("value"),
                    "new_override": None if remove else new_value,
                    "makes_overridable": not obj.get("overridable") and not remove,
                },
                fingerprint={"object": slim(editable(obj)), "override": (mine or {}).get("value")},
                blockers=blockers,
                side_effects=[f"Takes effect on {dev.get('name')} after the next deployment."]
                + (
                    [f"First marks {obj.get('name')!r} overridable (a separate change to the object)."]
                    if not obj.get("overridable") and not remove
                    else []
                ),
            ),
            apply=apply,
        )

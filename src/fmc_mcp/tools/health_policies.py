"""F100: create, assign and delete health policies (fmc_get_health_policy / fmc_update_health_policy read and
change one module in place, F14).

Bodies follow the FMC 10.0.1 OpenAPI: POST policy/healthpolicies takes `basePolicyID` (request example 1:
"create a new policy with any existing policy as base policy"); the HealthPolicy schema has no device field,
so a device gets its policy through its device record's `healthPolicy` (IDevice). When FMC ignores that
field, the tool falls back to a policy assignment (assignment/policyassignments, policy type HealthPolicy)
and says which route took effect."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from pydantic import BaseModel, ConfigDict, Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    ValidationFailed,
    get_client,
)
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.admin import HEALTH, LOWER_IS_WORSE, _with_thresholds, module_row, module_rows
from fmc_mcp.tools.common import Domain, resolve_in
from fmc_mcp.tools.device_groups import expand_devices
from fmc_mcp.tools.devices import DEVICES
from fmc_mcp.tools.object_writes import applied, editable

ASSIGNMENTS = "assignment/policyassignments"
DEVICE_POLICY = "DevicePolicy"


class ModuleSettings(BaseModel):
    """New values for one health module; omitted values stay as in the base policy."""

    model_config = ConfigDict(extra="forbid")
    warning: int | None = Field(default=None, ge=0, description="Warning threshold (module's unit, often %)")
    critical: int | None = Field(default=None, ge=0, description="Critical threshold")
    enabled: bool | None = Field(default=None, description="Turn the module on or off")


Modules = Annotated[
    dict[str, ModuleSettings] | None,
    Field(
        description="Module overrides by module id (fmc_get_health_policy lists them), e.g. "
        '{"hm_cpu": {"warning": 60, "critical": 85}, "hm_du": {"warning": 80}}'
    ),
]
DeviceList = Annotated[
    list[str] | None,
    Field(
        description="Devices to put on the policy (names or UUIDs), or a device group as 'group:<name>' "
        "(every device in it)"
    ),
]


def _key(m: dict[str, Any]) -> str:
    return str(m.get("moduleId", "")).lower()


def apply_modules(
    modules: list[dict[str, Any]], overrides: dict[str, ModuleSettings]
) -> tuple[list[dict[str, Any]], list[str]]:
    """The base policy's modules with the overrides applied (per-alert thresholds follow, as in
    fmc_update_health_policy), and the blockers (unknown module, warning above critical)."""
    by_id = {_key(m): m for m in modules}
    blockers: list[str] = []
    new_by_id: dict[str, dict[str, Any]] = {}
    for mid, s in overrides.items():
        cur = by_id.get(mid.strip().lower())
        if cur is None:
            known = ", ".join(sorted(str(m.get("moduleId")) for m in modules))
            blockers.append(f"No module {mid!r} in the base policy. Modules: {known}")
            continue
        new: dict[str, Any] = {}
        if s.enabled is not None:
            new["enabled"] = s.enabled
        if s.warning is not None:
            new["warningThreshold"] = s.warning
        if s.critical is not None:
            new["criticalThreshold"] = s.critical
        if not new:
            blockers.append(f"Module {mid!r}: give warning, critical or enabled.")
            continue
        out = _with_thresholds(cur, new)
        w, c = out.get("warningThreshold"), out.get("criticalThreshold")
        if (
            (s.warning is not None or s.critical is not None)
            and isinstance(w, int)
            and isinstance(c, int)
            and _key(cur) not in LOWER_IS_WORSE
            and w > c
        ):
            blockers.append(
                f"Module {cur.get('moduleId')}: warning ({w}) is above critical ({c}); critical should be "
                "higher."
            )
        new_by_id[_key(cur)] = out
    return [new_by_id.get(_key(m), m) for m in modules], blockers


def module_diff(old: list[dict[str, Any]], new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Modules whose enabled state or thresholds differ, as {module, from, to} rows, sorted by module id
    (FMC's healthModules order changes from one GET to the next)."""
    before = {_key(m): module_row(m) for m in old}
    rows = []
    for m in sorted(new, key=_key):
        to = module_row(m)
        frm = before.get(_key(m))
        if frm != to:
            rows.append({"module": m.get("moduleId"), "from": frm, "to": to})
    return rows


async def health_policies(app: FmcApp, domain: str | None) -> list[dict[str, Any]]:
    page = await app.all(await app.config_path(HEALTH, domain), expanded=False)
    return list(page.items)


async def default_device_policy(app: FmcApp, domain: str | None) -> dict[str, Any]:
    rows = [p for p in await health_policies(app, domain) if p.get("policyType") == DEVICE_POLICY]
    pick = next((p for p in rows if p.get("defaultPolicy")), None) or next(
        (p for p in rows if str(p.get("name", "")).startswith("Initial_Health_Policy")), None
    )
    if pick is None:
        raise NotFound("FMC has no default device health policy; name a base policy.", 404)
    return pick


async def full_policy(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    """A health policy with its modules (the list is not expanded)."""
    if ref.strip().lower() == "default":
        p = await default_device_policy(app, domain)
    else:
        p = await resolve_in(app, HEALTH, ref, "health policy", domain)
    if p.get("healthModules") is None:
        p = await app.api.get(await app.config_path(f"{HEALTH}/{p['id']}", domain))
    return p


async def policy_users(app: FmcApp, domain: str | None) -> dict[str, list[str]]:
    """Health policy UUID (lower case) -> names of the devices on it."""
    devs = await app.all(await app.config_path(DEVICES, domain))
    users: dict[str, list[str]] = {}
    for d in devs.items:
        hp = str((d.get("healthPolicy") or {}).get("id") or "").lower()
        if hp:
            users.setdefault(hp, []).append(str(d.get("name")))
    return users


async def device_records(
    app: FmcApp, refs: list[str], domain: str | None
) -> tuple[list[dict[str, Any]], str | None]:
    """The device records named by `refs` (groups expanded to their units), and the group's name if any."""
    fleet = await expand_devices(app, refs, domain, units=True)
    recs: list[dict[str, Any]] = []
    for ref in fleet.refs:
        if fleet.from_group(ref):
            recs.append(await app.api.get(await app.config_path(f"{DEVICES}/{ref}", domain)))
        else:
            d = await resolve_in(app, DEVICES, ref, "device", domain)
            recs.append(await app.api.get(await app.config_path(f"{DEVICES}/{d['id']}", domain)))
    if not recs:
        raise InvalidRequest(f"No devices to assign (group {next(iter(fleet.groups), '')!r} is empty).")
    return recs, next(iter(fleet.groups), None)


class Assignment:
    """Per-device moves onto one health policy, with the threshold diff against each device's current one."""

    def __init__(self, app: FmcApp, domain: str | None) -> None:
        self.app, self.domain = app, domain
        self._policies: dict[str, dict[str, Any]] = {}

    async def policy(self, pid: str) -> dict[str, Any]:
        k = pid.lower()
        if k not in self._policies:
            self._policies[k] = await self.app.api.get(
                await self.app.config_path(f"{HEALTH}/{pid}", self.domain)
            )
        return self._policies[k]

    async def rows(
        self, recs: list[dict[str, Any]], target_id: str | None, target_modules: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        out = []
        for d in recs:
            cur = d.get("healthPolicy") or {}
            cur_id = str(cur.get("id") or "")
            row: dict[str, Any] = {"device": d.get("name"), "from": cur.get("name") or cur_id or None}
            if target_id and cur_id.lower() == target_id.lower():
                row["unchanged"] = True
            else:
                old = ((await self.policy(cur_id)).get("healthModules") or []) if cur_id else []
                row["threshold_changes"] = module_diff(old, target_modules)
            out.append(row)
        return out

    async def move(self, rec: dict[str, Any], pol: dict[str, Any]) -> str:
        """Put one device on `pol`; returns the route that worked ('device_record' or 'policy_assignment')."""
        path = await self.app.config_path(f"{DEVICES}/{rec['id']}", self.domain)
        ref = {"id": pol["id"], "name": pol.get("name"), "type": "HealthPolicy"}
        now = await self.app.api.get(path)  # rebuilt from the current record: the PUT replaces it
        body: dict[str, Any] = {
            "id": now["id"],
            "type": "Device",
            "name": now.get("name"),
            "hostName": now.get("hostName"),
            "license_caps": now.get("license_caps") or [],
            "healthPolicy": ref,
        }
        if now.get("performanceTier"):
            body["performanceTier"] = now["performanceTier"]
        refused: str | None = None
        try:
            await applied(self.app, lambda: self.app.api.put(path, body))
        except ValidationFailed as e:  # FMC refuses the field on this record: try the assignment route
            refused = str(e)
        else:
            if self._on(await self.app.api.get(path), pol):
                return "device_record"
        # FMC kept the old policy: assign it the way other device policies are assigned
        assign = {
            "type": "PolicyAssignment",
            "policy": ref,
            "targets": [{"id": now["id"], "type": "Device", "name": now.get("name")}],
        }
        apath = await self.app.config_path(ASSIGNMENTS, self.domain)
        await applied(self.app, lambda: self.app.api.post(apath, assign))
        if self._on(await self.app.api.get(path), pol):
            return "policy_assignment"
        why = f" (the device record PUT was refused: {refused})" if refused else ""
        raise UpstreamError(
            f"FMC accepted the change but {now.get('name')!r} still shows its old health policy{why}.", None
        )

    @staticmethod
    def _on(rec: dict[str, Any], pol: dict[str, Any]) -> bool:
        return str((rec.get("healthPolicy") or {}).get("id") or "").lower() == str(pol["id"]).lower()

    async def move_all(self, recs: list[dict[str, Any]], pol: dict[str, Any]) -> list[dict[str, Any]]:
        done: list[dict[str, Any]] = []
        for rec in recs:
            if self._on(rec, pol):
                continue
            try:
                via = await self.move(rec, pol)
            except Exception as e:  # say which devices already moved (one request per device)
                moved = [str(d["device"]) for d in done] or "none"
                raise UpstreamError(
                    f"Assigning {pol.get('name')!r} to {rec.get('name')!r} failed ({e}). Moved: {moved}. "
                    "Check with fmc_get_health_policy, then repeat the call.",
                    getattr(e, "status_code", None),
                ) from e
            done.append({"device": rec.get("name"), "via": via})
        return done


SIDE = (
    "The device's health alerts follow the new policy's thresholds from its next evaluation (the policy's "
    "alert interval, 5 minutes by default). If fmc_pending_changes lists the health policy for the device, "
    "deploy it."
)


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create health policy")
    async def fmc_create_health_policy(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, description="Name of the new health policy, e.g. edge-ftd")],
        base: Annotated[
            str,
            Field(description="Policy to copy (name or UUID); 'default' = the default device health policy"),
        ] = "default",
        modules: Modules = None,
        devices: DeviceList = None,
        description: Annotated[str | None, Field(description="Policy description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a health policy from a base policy (the default device policy unless named), with
        per-module threshold overrides (tighter CPU, memory or disk limits for edge FTDs, say), and
        optionally put devices or a device group on it. The preview lists the module changes against
        the base and, per device, the threshold changes against the policy it uses now. Change a module
        later with fmc_update_health_policy; move devices with fmc_assign_health_policy."""
        app: FmcApp = get_client(ctx)
        name = name.strip()
        base_pol = await full_policy(app, base, domain)
        base_mods = base_pol.get("healthModules") or []
        new_mods, blockers = apply_modules(base_mods, modules or {})
        existing = await health_policies(app, domain)
        if any(str(p.get("name", "")).lower() == name.lower() for p in existing):
            blockers.append(
                f"A health policy named {name!r} exists; pick another name or use fmc_update_health_policy."
            )
        recs: list[dict[str, Any]] = []
        group = None
        if devices:
            if base_pol.get("policyType") != DEVICE_POLICY:
                blockers.append(
                    f"{base_pol.get('name')!r} is a {base_pol.get('policyType')}; only device policies go "
                    "on devices."
                )
            recs, group = await device_records(app, devices, domain)
        asg = Assignment(app, domain)
        dev_rows = await asg.rows(recs, None, new_mods)
        modules_args = {k: v.model_dump(exclude_none=True) for k, v in (modules or {}).items()}

        async def apply() -> Any:
            body: dict[str, Any] = {
                "name": name,
                "type": "HealthPolicy",
                "policyType": base_pol.get("policyType") or DEVICE_POLICY,
                "basePolicyID": base_pol["id"],
            }
            if description:
                body["description"] = description
            hp_path = await app.config_path(HEALTH, domain)
            created = await app.api.post(hp_path, body)
            pid = str((created or {}).get("id") or "")
            if not pid:
                raise UpstreamError(f"FMC created no id for health policy {name!r}.", None)
            out: dict[str, Any] = {"created": {"name": name, "id": pid, "base": base_pol.get("name")}}
            path = await app.config_path(f"{HEALTH}/{pid}", domain)
            if modules:
                try:
                    now = await app.api.get(path)  # full-object PUT: start from what FMC made
                    mods_now, errs = apply_modules(now.get("healthModules") or [], modules)
                    if errs:
                        raise InvalidRequest("; ".join(errs))
                    put = {**editable(now), "healthModules": mods_now}
                    await applied(app, lambda: app.api.put(path, put))
                except Exception as e:
                    raise UpstreamError(
                        f"Health policy {name!r} was created (id {pid}) as a copy of "
                        f"{base_pol.get('name')!r}, but the module thresholds were not set ({e}). Set them "
                        "with fmc_update_health_policy or delete it with fmc_delete_health_policy.",
                        getattr(e, "status_code", None),
                    ) from e
                wanted = {k.strip().lower() for k in modules}
                out["modules"] = [
                    r for r in module_rows(mods_now) if str(r.get("module", "")).lower() in wanted
                ]
            app.invalidate_cache()
            if recs:
                pol = await app.api.get(path)
                try:
                    out["assigned"] = await asg.move_all(recs, pol)
                except UpstreamError as e:
                    raise UpstreamError(
                        f"Health policy {name!r} was created (id {pid}). {e}", e.status_code
                    ) from e
            return out

        details: dict[str, Any] = {
            "name": name,
            "base": base_pol.get("name"),
            "type": base_pol.get("policyType"),
            "module_changes": module_diff(base_mods, new_mods),
        }
        if group:
            details["group"] = group
        if dev_rows:
            details["devices"] = dev_rows
        return await fmc_preview(
            ctx,
            tool="fmc_create_health_policy",
            args={
                "name": name,
                "base": base,
                "modules": modules_args,
                "devices": devices,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create health policy {name!r} from {base_pol.get('name')!r}"
                + (f" and assign it to {len(recs)} device(s)" if recs else ""),
                details=details,
                fingerprint={
                    "base": module_rows(base_mods),
                    "devices": [(d.get("id"), (d.get("healthPolicy") or {}).get("id")) for d in recs],
                },
                blockers=blockers,
                side_effects=[SIDE] if recs else [],
                blast_radius=len(recs) or None,
            ),
            apply=apply,
        )

    @reg.write(title="Assign health policy")
    async def fmc_assign_health_policy(
        ctx: Context,
        policy: Annotated[
            str, Field(description="Device health policy name or UUID; 'default' = the default one")
        ],
        devices: Annotated[
            list[str],
            Field(
                min_length=1,
                description="Devices (names or UUIDs) or a device group as 'group:<name>' (all its devices)",
            ),
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Put devices (or every device in a device group) on a health policy. The preview shows, per
        device, the policy it uses now and the module thresholds that change; devices already on the
        policy are left alone. Moving devices back to the initial policy before deleting one:
        policy='default'."""
        app: FmcApp = get_client(ctx)
        pol = await full_policy(app, policy, domain)
        blockers: list[str] = []
        if pol.get("policyType") != DEVICE_POLICY:
            blockers.append(
                f"{pol.get('name')!r} is a {pol.get('policyType')}; only device policies go on devices."
            )
        recs, group = await device_records(app, devices, domain)
        asg = Assignment(app, domain)
        rows = await asg.rows(recs, pol["id"], pol.get("healthModules") or [])
        moving = [d for d in recs if not Assignment._on(d, pol)]
        if not moving:
            blockers.append(f"Every device is already on {pol.get('name')!r}; nothing to change.")

        async def apply() -> Any:
            fresh = [await app.api.get(await app.config_path(f"{DEVICES}/{d['id']}", domain)) for d in moving]
            return {"policy": pol.get("name"), "assigned": await asg.move_all(fresh, pol)}

        details: dict[str, Any] = {"policy": pol.get("name"), "devices": rows}
        if group:
            details["group"] = group
        return await fmc_preview(
            ctx,
            tool="fmc_assign_health_policy",
            args={"policy": policy, "devices": devices, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Assign health policy {pol.get('name')!r} to {len(moving)} of {len(recs)} device(s)",
                details=details,
                fingerprint={
                    "policy": module_rows(pol.get("healthModules") or []),
                    "devices": [(d.get("id"), (d.get("healthPolicy") or {}).get("id")) for d in recs],
                },
                blockers=blockers,
                side_effects=[SIDE],
                blast_radius=len(moving),
            ),
            apply=apply,
        )

    @reg.write(title="Delete health policy")
    async def fmc_delete_health_policy(
        ctx: Context,
        policy: Annotated[str, Field(description="Health policy name or UUID")],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a health policy. Refused while any device uses it (the preview names them: move them
        first with fmc_assign_health_policy, e.g. policy='default'), and for the default policy and the
        FMC's own policy."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, HEALTH, policy, "health policy", domain)
        users = (await policy_users(app, domain)).get(str(p["id"]).lower(), [])
        blockers: list[str] = []
        if p.get("defaultPolicy"):
            blockers.append(f"{p.get('name')!r} is the default health policy; FMC keeps it.")
        if p.get("policyType") and p.get("policyType") != DEVICE_POLICY:
            blockers.append(
                f"{p.get('name')!r} is the {p.get('policyType')} (FMC's own); it can't be deleted."
            )
        if users:
            blockers.append(
                f"{p.get('name')!r} is assigned to {', '.join(sorted(users))}. Move them first: "
                f"fmc_assign_health_policy(policy='default', devices=[...])."
            )
        path = await app.config_path(f"{HEALTH}/{p['id']}", domain)

        async def apply() -> Any:
            await applied(app, lambda: app.api.delete(path))
            return {"deleted": {"name": p.get("name"), "id": p["id"]}}

        return await fmc_preview(
            ctx,
            tool="fmc_delete_health_policy",
            args={"policy": policy, "domain": domain},
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Delete health policy {p.get('name')!r}",
                details={"policy": p.get("name"), "type": p.get("policyType"), "devices": users or None},
                fingerprint={"id": p["id"], "devices": sorted(users)},
                blockers=blockers,
            ),
            apply=apply,
        )

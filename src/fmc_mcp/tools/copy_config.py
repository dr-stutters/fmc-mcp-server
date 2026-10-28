"""F93: fmc_copy_device_config, FMC's Copy Configuration (an RMA, or a branch cloned onto a new box).

POST devices/copyconfigrequests (DeviceCopyConfigRequest: sourceDevice, targetDeviceList,
copySharedPolicies) copies one FTD's (or HA pair's) device configuration onto standalone FTDs of the same
model and version. FMC answers with a task, which is followed to completion like a registration. The
preview reads each target's current interfaces, routes and (with copy_shared_policies) assigned policies
from the device export (F72), so the user sees what the target loses before confirming.

Cisco source: Secure Firewall Management Center Device Configuration Guide 10.0, 'Device Management' >
'Copy a Configuration to Another Threat Defense'. The prompt fmc_replace_device chains the RMA."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import Confirm, InvalidRequest, NotFound, Plan, ToolRegistrar, UpstreamError, get_client
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, resolve_in
from fmc_mcp.tools.dangerous import Wait, finish
from fmc_mcp.tools.device_export import export_target, resolve_target
from fmc_mcp.tools.devices import CLUSTERS, DEVICES, HA_PAIRS, memberships

COPY_REQUESTS = "devices/copyconfigrequests"
MAX_TARGETS = 10  # one copy per maintenance window is the norm; FMC takes a list, the preview reads each
MAX_LISTED = 40  # interfaces / routes listed per target in the preview (the rest are counted)


def request_body(
    source: dict[str, Any], kind: str, targets: list[dict[str, Any]], shared: bool
) -> dict[str, Any]:
    """The DeviceCopyConfigRequest body: the source device or HA container, the standalone targets."""
    return {
        "sourceDevice": {"id": source["id"], "type": kind},
        "targetDeviceList": [{"id": t["id"], "type": "Device"} for t in targets],
        "copySharedPolicies": shared,
    }


def _capped(rows: list[str]) -> list[str]:
    if len(rows) <= MAX_LISTED:
        return rows
    return [*rows[:MAX_LISTED], f"... and {len(rows) - MAX_LISTED} more"]


def _interface_label(name: str, entry: dict[str, Any]) -> str | None:
    """'GigabitEthernet0/0 (outside, zone outside-zone)' for an interface with a logical name; None for
    an unconfigured one (copying over it loses nothing)."""
    ifname = entry.get("ifname")
    if not ifname:
        return None
    zone = entry.get("securityZone")
    return f"{name} ({ifname}{f', zone {zone}' if zone else ''})"


def losses(doc: dict[str, Any], shared: bool) -> dict[str, Any]:
    """What the copy replaces on one target, from its export: configured interfaces, routing entries and
    (copy_shared_policies) the assigned policies."""
    interfaces = [
        label
        for name, entry in sorted((doc.get("interfaces") or {}).items())
        if isinstance(entry, dict) and (label := _interface_label(name, entry))
    ]
    routing = sorted((doc.get("routing") or {}).keys())
    out: dict[str, Any] = {
        "interfaces": _capped(interfaces),
        "routing": _capped(routing),
        "counts": {"interfaces": len(interfaces), "routing": len(routing)},
    }
    if shared:
        pols = doc.get("policies") or {}
        out["policies"] = {k: v.get("name") if isinstance(v, dict) else v for k, v in sorted(pols.items())}
    errors = (doc.get("meta") or {}).get("errors")
    if errors:
        out["not_read"] = errors
    return out


async def _container_named(app: FmcApp, ref: str, domain: str | None) -> str | None:
    """'HA pair' / 'cluster' when `ref` names one (a target must be a standalone device)."""
    for path, what in ((HA_PAIRS, "HA pair"), (CLUSTERS, "cluster")):
        try:
            await resolve_in(app, path, ref, what, domain)
            return what
        except (NotFound, UpstreamError):
            continue
    return None


def _brief(d: dict[str, Any]) -> dict[str, Any]:
    return {k: d.get(k) for k in ("name", "model", "sw_version", "hostName", "id") if d.get(k)}


def register(reg: ToolRegistrar) -> None:
    @reg.dangerous(title="Copy device configuration (RMA / clone)")
    async def fmc_copy_device_config(
        ctx: Context,
        source: Annotated[
            str,
            Field(description="Device or HA pair (name or UUID) to copy from, e.g. the failed unit's record"),
        ],
        targets: Annotated[
            list[str],
            Field(
                description="Standalone FTDs (names or UUIDs) to copy onto: registered, same model and "
                "software version as the source; not an HA member or cluster node"
            ),
        ],
        copy_shared_policies: Annotated[
            bool,
            Field(
                description="Also assign the source's shared policies (access control, NAT, platform "
                "settings, QoS, FlexConfig) to the targets"
            ),
        ] = True,
        wait: Wait = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Copy one FTD's (or HA pair's) device configuration onto standalone FTDs: FMC's Copy
        Configuration, the RMA step after registering the replacement (prompt fmc_replace_device). The
        target's interfaces, routes and other device settings are replaced by the source's; with
        copy_shared_policies its policies too. The preview checks that model and version match, refuses
        an HA member or cluster node as a target, and lists what each target loses. With wait, follows
        FMC's task to the end. Nothing reaches the device until fmc_deploy; then compare the two with
        fmc_diff_device_config."""
        app: FmcApp = get_client(ctx)
        wanted = list(dict.fromkeys(t.strip() for t in targets if t and t.strip()))
        if not wanted:
            raise InvalidRequest("Name at least one target device.")
        if len(wanted) > MAX_TARGETS:
            raise InvalidRequest(f"At most {MAX_TARGETS} targets per call (got {len(wanted)}).")

        src_dev, src_ha = await resolve_target(app, source, domain)
        src = src_ha or src_dev
        kind = "DeviceHAPair" if src_ha else "Device"
        blockers: list[str] = []
        target_recs: list[dict[str, Any]] = []
        for ref in wanted:
            try:
                rec = await resolve_in(app, DEVICES, ref, "device", domain)
            except NotFound:
                what = await _container_named(app, ref, domain)
                if what is None:
                    raise
                blockers.append(
                    f"{ref!r} is an {what}: copy configuration targets standalone devices only (break the "
                    "pair or remove the node first)."
                )
                continue
            if not rec.get("model") and rec.get("id"):
                rec = await app.api.get(await app.config_path(f"{DEVICES}/{rec['id']}", domain))
            target_recs.append(dict(rec))

        src_ids = {str(src.get("id")).lower(), str(src_dev.get("id")).lower()}
        if src_ha:
            src_ids |= {str((src_ha.get(s) or {}).get("id")).lower() for s in ("primary", "secondary")}
        members = await memberships(app, [src_dev, *target_recs], domain)
        if not src_ha and (m := members.get(str(src_dev.get("id")).lower())):
            if m.kind == "ha":
                blockers.append(
                    f"Source {src_dev.get('name')!r} is a unit of HA pair {m.container!r}: give the pair "
                    f"(source={m.container!r}) as the source."
                )
            else:
                blockers.append(
                    f"Source {src_dev.get('name')!r} is a node of cluster {m.container!r}: FMC copies only "
                    "from a standalone device or an HA pair."
                )
        model, version = src_dev.get("model"), src_dev.get("sw_version")
        seen: set[str] = set()
        checked: list[dict[str, Any]] = []
        for t in target_recs:
            tid = str(t.get("id")).lower()
            name = t.get("name")
            if tid in seen:
                continue
            seen.add(tid)
            checked.append(t)
            if tid in src_ids:
                blockers.append(f"Target {name!r} is the source (or a unit of it).")
                continue
            if m := members.get(tid):
                what = "a unit of HA pair" if m.kind == "ha" else "a node of cluster"
                blockers.append(
                    f"Target {name!r} is {what} {m.container!r}: copy configuration targets standalone "
                    "devices only."
                )
            if t.get("model") != model:
                blockers.append(f"Target {name!r} is a {t.get('model')!r}; the source is a {model!r}.")
            if t.get("sw_version") != version:
                blockers.append(
                    f"Target {name!r} runs {t.get('sw_version')!r}; the source runs {version!r}: upgrade "
                    "one of them so the versions match."
                )

        sections = ["interfaces", "routing", *(["policies"] if copy_shared_policies else [])]
        shared_cache: dict[str, Any] = {}
        loses: dict[str, Any] = {}
        warnings: list[str] = []
        for t in checked:
            if str(t.get("id")).lower() in src_ids:
                continue
            doc, warn = await export_target(app, t, None, domain, sections, shared_cache, ctx)
            loses[str(t.get("name"))] = losses(doc, copy_shared_policies)
            warnings += warn

        body = request_body(src, kind, checked, copy_shared_policies)
        path = await app.config_path(COPY_REQUESTS, domain)

        async def apply() -> Any:
            resp = await app.api.post(path, body)
            # Some releases answer with the TaskStatus itself rather than the request + metadata.task.
            if (
                isinstance(resp, dict)
                and not (resp.get("metadata") or {}).get("task")
                and str(resp.get("type") or "").lower() == "taskstatus"
                and resp.get("id")
            ):
                resp = {**resp, "metadata": {"task": {"id": resp["id"]}}}
            result = await finish(ctx, app, resp, wait, domain, "copy configuration")
            if isinstance(result, dict):
                result["next"] = (
                    "Check the targets' licences (fmc_get_device; fmc_set_device_licenses to match the "
                    "source), fmc_deploy the targets, then fmc_diff_device_config(source, target)."
                )
            return result

        src_label = f"HA pair {src.get('name')!r}" if src_ha else f"{src.get('name')!r}"
        names = ", ".join(repr(t.get("name")) for t in checked)
        side_effects = [
            "Replaces each target's interfaces, routes and other device-level settings with the source's "
            "(the target keeps its name, management address and registration).",
            "Nothing reaches the device until fmc_deploy; after the deploy the target runs the source's "
            "configuration (same interface addresses: keep the old unit off the network).",
        ]
        if copy_shared_policies:
            side_effects.append("Assigns the source's shared policies to the targets.")
        details: dict[str, Any] = {
            "source": {**_brief(src_dev), **({"ha_pair": src.get("name")} if src_ha else {})},
            "targets": [_brief(t) for t in checked],
            "copy_shared_policies": copy_shared_policies,
            "targets_lose": loses,
            "body": body,
        }
        if warnings:
            details["warnings"] = warnings
        return await fmc_preview(
            ctx,
            tool="fmc_copy_device_config",
            args={
                "source": source,
                "targets": targets,
                "copy_shared_policies": copy_shared_policies,
                "wait": wait,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Copy the configuration of {src_label} onto {names}",
                details=details,
                fingerprint={
                    "source": [src.get("id"), model, version],
                    "targets": [[t.get("id"), t.get("model"), t.get("sw_version")] for t in checked],
                    "loses": loses,
                },
                blockers=blockers,
                blast_radius=len(checked),
                side_effects=side_effects,
            ),
            apply=apply,
            lock_check=False,
        )

"""SLA monitor objects and the static routes that track them (write tier, preview-first).

Dual-ISP failover as the FMC Device Configuration Guide 10.0 builds it ('Static and Default Routes' > route
tracking): an SLA monitor pings the primary ISP's next hop, the primary default route tracks it
(fmc_create_static_route track=...), and a floating default route through the second ISP with a higher
metric takes over while the monitor is down. FMC 10.0.1 spec: SLAMonitor / ISLAMonitorModel
(object/slamonitors; slaId, monitorAddress and interfaceObjects required) and
IPv4StaticRouteModel.routeTracking (IPv4 routes only).
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import Confirm, InvalidRequest, NotFound, Plan, ToolRegistrar, Undo, get_client
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import ZONE_TYPES, RefResolver
from fmc_mcp.tools.common import Domain, ref_label, resolve_object
from fmc_mcp.tools.device_config import ROUTE_TABLE_CAP, route_row
from fmc_mcp.tools.devices import DEVICES
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.undo import ResultId, not_reversible, ref_ids, without_none

SLA_MONITORS = "object/slamonitors"
SLA_ID_MAX = 2147483647


def sla_ref(m: dict[str, Any]) -> dict[str, Any]:
    """The routeTracking reference FMC takes on an IPv4 static route."""
    out = {"id": m["id"], "type": "SLAMonitor"}
    if m.get("name"):
        out["name"] = m["name"]
    return out


def monitor_row(m: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": m.get("name"),
        "sla_id": m.get("slaId"),
        "monitor_address": m.get("monitorAddress"),
        "interfaces": [ref_label(i) for i in m.get("interfaceObjects") or []] or m.get("interfaceNames"),
        "description": m.get("description") or None,
        "frequency_s": m.get("frequency"),
        "threshold_ms": m.get("threshold"),
        "timeout_ms": m.get("timeout"),
        "tos": m.get("tos"),
        "packets": m.get("noOfPackets"),
        "data_size": m.get("dataSize"),
        "id": m.get("id"),
    }


def monitor_recreate_undo(m: dict[str, Any], domain: str | None) -> Undo | str:
    """The back-out step of deleting an SLA monitor: fmc_create_sla_monitor with its values and SLA ID."""
    zones = ref_ids(m.get("interfaceObjects"))
    if not zones or not m.get("monitorAddress"):  # inline interface names only: no zone to give back
        return not_reversible("SLA monitor", "fmc_create_sla_monitor", monitor_row(m))
    args = {
        "name": m.get("name"),
        "monitor_address": m.get("monitorAddress"),
        "interfaces": zones,
        "sla_id": m.get("slaId"),
        "frequency": m.get("frequency"),
        "threshold_ms": m.get("threshold"),
        "timeout_ms": m.get("timeout"),
        "tos": m.get("tos"),
        "packets": m.get("noOfPackets"),
        "data_size": m.get("dataSize"),
        "description": m.get("description") or None,
        "domain": domain,
    }
    return Undo("fmc_create_sla_monitor", without_none(args))


async def resolve_monitor(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    _, m = await resolve_object(app, ref, domain, ["sla_monitor"])
    return m


async def routes_tracking(
    app: FmcApp, monitor_id: str, domain: str | None, device: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Every IPv4 static route (global table and each virtual router, on every device of the domain, or
    only on `device`) whose routeTracking is this SLA monitor. FMC's usage API doesn't report route
    tracking, so the routes are read."""
    found: list[dict[str, Any]] = []
    if device is not None:
        devs = [device]
    else:
        devs = (await app.all(await app.config_path(DEVICES, domain), expanded=False, cap=2000)).items
    for dev in devs:
        base = f"{DEVICES}/{dev['id']}/routing"
        tables: list[tuple[str, str | None]] = [(base, None)]
        try:
            vrs = await app.all(await app.config_path(f"{base}/virtualrouters", domain), expanded=False)
            tables += [
                (f"{base}/virtualrouters/{v['id']}", str(v.get("name")))
                for v in vrs.items
                if str(v.get("name", "")).lower() != "global"
            ]
        except (NotFound, InvalidRequest):
            pass
        for path, vr in tables:
            try:
                page = await app.all(
                    await app.config_path(f"{path}/ipv4staticroutes", domain), cap=ROUTE_TABLE_CAP
                )
            except (NotFound, InvalidRequest):
                continue
            for r in page.items:
                if str((r.get("routeTracking") or {}).get("id", "")) == monitor_id:
                    row = route_row("static4", r)
                    found.append({"device": dev.get("name"), "table": vr or "global", **row})
    return found


def describe_route(r: dict[str, Any]) -> str:
    nets = ", ".join(r.get("networks") or [])
    return (
        f"{r.get('device')} ({r.get('table')}): {nets} via {r.get('gateway')} on {r.get('interface')} "
        f"(id {r.get('id')})"
    )


def leftover_warning(sla_id: Any, where: str) -> str:
    """FMC 10.0 removes a tracked route but not the 'sla monitor' it pushed for it (fmc #364, seen live):
    the probe keeps running on the device after the deploy."""
    sid = sla_id if sla_id is not None else "<id>"
    return (
        f"FMC leaves 'sla monitor {sid}' (and its schedule) on {where} after the deploy: the probe keeps "
        f"running, harmless as nothing tracks it. Remove it with a FlexConfig 'no sla monitor {sid}', or "
        f"accept it and reuse SLA ID {sid} for the next monitor on that device, which overwrites it."
    )


def probe_timing_blockers(frequency: int, threshold_ms: int, timeout_ms: int) -> list[str]:
    blockers = []
    if threshold_ms > timeout_ms:
        blockers.append(f"threshold_ms ({threshold_ms}) can't exceed timeout_ms ({timeout_ms}).")
    if timeout_ms > frequency * 1000:
        blockers.append(
            f"timeout_ms ({timeout_ms}) can't exceed the frequency ({frequency} s): the next probe would "
            "start before the last one timed out."
        )
    return blockers


def probe_address(monitor_address: str) -> tuple[str, list[str]]:
    """The probe target as FMC stores it, and why it can't be one."""
    try:
        addr = ipaddress.ip_address(monitor_address.strip())
    except ValueError:
        raise InvalidRequest(f"monitor_address must be an IPv4 address, got {monitor_address!r}.") from None
    if addr.version != 4:
        return str(addr), ["SLA monitors probe IPv4 addresses only (route tracking is IPv4 only)."]
    if addr.is_multicast or addr.is_unspecified or addr.is_loopback:
        return str(addr), [f"{addr} can't answer an echo probe; use the ISP next hop or a host beyond it."]
    return str(addr), []


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create SLA monitor")
    async def fmc_create_sla_monitor(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New SLA monitor name")],
        monitor_address: Annotated[
            str, Field(description="IPv4 address the device pings, usually the primary ISP's next hop")
        ],
        interfaces: Annotated[
            list[str],
            Field(
                min_length=1,
                description="Security zones or interface groups (names/UUIDs) holding the interface the "
                "probes leave through, e.g. the ISP-1 outside zone",
            ),
        ],
        sla_id: Annotated[
            int | None,
            Field(ge=1, le=SLA_ID_MAX, description="SLA operation ID; default the lowest one not in use"),
        ] = None,
        frequency: Annotated[int, Field(ge=1, le=604800, description="Seconds between probes")] = 60,
        threshold_ms: Annotated[
            int, Field(ge=0, le=2147483647, description="Milliseconds above which a reply counts as late")
        ] = 5000,
        timeout_ms: Annotated[
            int, Field(ge=0, le=604800000, description="Milliseconds to wait for a reply")
        ] = 5000,
        tos: Annotated[int, Field(ge=0, le=255, description="Type of service byte in the probes")] = 0,
        packets: Annotated[int, Field(ge=1, le=100, description="Echo packets per probe")] = 1,
        data_size: Annotated[int, Field(ge=0, le=16384, description="Probe payload size in bytes")] = 28,
        description: Annotated[str | None, Field(description="Description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an SLA monitor object: the device pings monitor_address through the interface in the
        given zone or interface group and marks the monitor down when replies stop. A static route
        tracks it with fmc_create_static_route(track=<name>) (dual-ISP failover: tracked primary route plus
        a floating backup with a higher metric). Takes effect after fmc_deploy; check with
        fmc_run_show_command('show sla monitor operational-state')."""
        app: FmcApp = get_client(ctx)
        warnings: list[str] = []
        addr, blockers = probe_address(monitor_address)
        res = RefResolver(app, domain)
        objs = [await res.single(i, ZONE_TYPES, "security zone or interface group") for i in interfaces]
        existing = (await app.all(await app.config_path(SLA_MONITORS, domain), cap=5000)).items
        if any(str(m.get("name", "")).lower() == name.strip().lower() for m in existing):
            blockers.append(f"An SLA monitor named {name!r} already exists.")
        used = {int(m["slaId"]) for m in existing if isinstance(m.get("slaId"), int)}
        asked_id = sla_id  # the args the confirm call repeats: the chosen ID is in the fingerprint
        if sla_id is None:
            sla_id = next(i for i in range(1, len(used) + 2) if i not in used)
        elif sla_id in used:
            other = next(m.get("name") for m in existing if m.get("slaId") == sla_id)
            blockers.append(f"SLA ID {sla_id} is already used by {other!r}; pick another or omit sla_id.")
        blockers += probe_timing_blockers(frequency, threshold_ms, timeout_ms)
        if frequency > 300:
            warnings.append(
                f"A probe every {frequency} s means failover can take that long; branch designs use 5-60 s."
            )
        body: dict[str, Any] = {
            "name": name.strip(),
            "type": "SLAMonitor",
            "slaId": sla_id,
            "monitorAddress": addr,
            "interfaceObjects": objs,
            "frequency": frequency,
            "threshold": threshold_ms,
            "timeout": timeout_ms,
            "tos": tos,
            "noOfPackets": packets,
            "dataSize": data_size,
        }
        if description:
            body["description"] = description
        path = await app.config_path(SLA_MONITORS, domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_sla_monitor",
            args={
                "name": name,
                "monitor_address": monitor_address,
                "interfaces": interfaces,
                "sla_id": asked_id,
                "frequency": frequency,
                "threshold_ms": threshold_ms,
                "timeout_ms": timeout_ms,
                "tos": tos,
                "packets": packets,
                "data_size": data_size,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create SLA monitor {name!r} (SLA ID {sla_id}) probing {addr}",
                details={
                    "monitor": monitor_row(body),
                    "body": body,
                    **({"warnings": warnings} if warnings else {}),
                },
                fingerprint={"body": body, "used_ids": sorted(used)},
                blockers=blockers,
                undo=Undo(
                    "fmc_delete_sla_monitor", without_none({"monitor": ResultId("id"), "domain": domain})
                ),
                side_effects=[
                    "Nothing changes on a device until a static route tracks it "
                    "(fmc_create_static_route track=...) and fmc_deploy runs."
                ],
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Update SLA monitor")
    async def fmc_update_sla_monitor(
        ctx: Context,
        monitor: Annotated[str, Field(description="SLA monitor name or UUID")],
        monitor_address: Annotated[
            str | None,
            Field(description="New IPv4 address to probe (e.g. the ISP's next hop, or a host beyond it)"),
        ] = None,
        interfaces: Annotated[
            list[str] | None,
            Field(
                min_length=1,
                description="Replace the security zones or interface groups (names/UUIDs) the probes leave "
                "through",
            ),
        ] = None,
        frequency: Annotated[int | None, Field(ge=1, le=604800, description="Seconds between probes")] = None,
        threshold_ms: Annotated[
            int | None,
            Field(ge=0, le=2147483647, description="Milliseconds above which a reply counts as late"),
        ] = None,
        timeout_ms: Annotated[
            int | None, Field(ge=0, le=604800000, description="Milliseconds to wait for a reply")
        ] = None,
        description: Annotated[str | None, Field(description="New description ('' clears it)")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change an SLA monitor: the probe target, the zones/interface groups it leaves through, and its
        timing (frequency, threshold, timeout). Fields not given keep their value; the SLA ID stays (a new
        ID would leave the old 'sla monitor' on the devices). Reads the monitor and PUTs the full object.
        The preview lists the static routes that track it: their devices pick the change up on the next
        fmc_deploy, and a target that stops answering withdraws those routes (the floating backup takes
        over), which is how an ISP cut-over test is run. Check with fmc_run_show_command('show sla monitor
        operational-state')."""
        app: FmcApp = get_client(ctx)
        current = await resolve_monitor(app, monitor, domain)
        body = editable(current)
        blockers: list[str] = []
        warnings: list[str] = []
        if monitor_address is not None:
            body["monitorAddress"], bad = probe_address(monitor_address)
            blockers += bad
        if interfaces is not None:
            res = RefResolver(app, domain)
            body["interfaceObjects"] = [
                await res.single(i, ZONE_TYPES, "security zone or interface group") for i in interfaces
            ]
            body.pop("interfaceNames", None)  # inline names can only be removed in a PUT (spec)
        for key, value in (("frequency", frequency), ("threshold", threshold_ms), ("timeout", timeout_ms)):
            if value is not None:
                body[key] = value
        if description is not None:
            if description:
                body["description"] = description
            else:
                body.pop("description", None)
        timing = [body.get(k) for k in ("frequency", "threshold", "timeout")]
        if all(isinstance(v, int) for v in timing):
            blockers += probe_timing_blockers(*timing)  # type: ignore[arg-type]
        if frequency is not None and frequency > 300:
            warnings.append(
                f"A probe every {frequency} s means failover can take that long; branch designs use 5-60 s."
            )
        before, after = monitor_row(current), monitor_row(body)
        changes = {k: {"from": before[k], "to": after[k]} for k in after if before.get(k) != after[k]}
        if not changes:
            blockers.append("Nothing to change: the monitor already has these settings.")
        tracked = await routes_tracking(app, str(current["id"]), domain)
        devices = sorted({str(r.get("device")) for r in tracked})
        side = (
            [
                f"Pushed to {', '.join(devices)} on the next fmc_deploy (static routes tracking it: "
                + "; ".join(describe_route(r) for r in tracked)
                + ")."
            ]
            if tracked
            else ["No static route tracks this monitor: nothing changes on a device."]
        )
        if tracked and "monitor_address" in changes:
            side.append(
                "If the new target doesn't answer, the monitor goes down and those routes are withdrawn: "
                "traffic moves to the floating backup route (or is lost without one)."
            )
        path = await app.config_path(f"{SLA_MONITORS}/{current['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_update_sla_monitor",
            owned=[current],
            args={
                "monitor": monitor,
                "monitor_address": monitor_address,
                "interfaces": interfaces,
                "frequency": frequency,
                "threshold_ms": threshold_ms,
                "timeout_ms": timeout_ms,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Update SLA monitor {current.get('name')!r} (SLA ID {current.get('slaId')})",
                details={
                    "changes": changes,
                    "monitor": after,
                    "tracked_by_routes": tracked,
                    **({"warnings": warnings} if warnings else {}),
                },
                fingerprint={
                    "monitor": editable(current),
                    "body": body,
                    "routes": [r["id"] for r in tracked],
                },
                blockers=blockers,
                side_effects=side,
                undo=Undo(
                    "fmc_update_sla_monitor",
                    without_none(
                        {
                            "monitor": current["id"],
                            "monitor_address": current.get("monitorAddress")
                            if monitor_address is not None
                            else None,
                            "interfaces": (ref_ids(current.get("interfaceObjects")) or None)
                            if interfaces is not None
                            else None,
                            "frequency": current.get("frequency") if frequency is not None else None,
                            "threshold_ms": current.get("threshold") if threshold_ms is not None else None,
                            "timeout_ms": current.get("timeout") if timeout_ms is not None else None,
                            "description": (current.get("description") or "")
                            if description is not None
                            else None,
                            "domain": domain,
                        }
                    ),
                ),
            ),
            apply=lambda: applied(app, lambda: app.api.put(path, body)),
        )

    @reg.write(title="Delete SLA monitor", destructive=True)
    async def fmc_delete_sla_monitor(
        ctx: Context,
        monitor: Annotated[str, Field(description="SLA monitor name or UUID")],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete an SLA monitor object. Blocked while a static route tracks it: the preview names each
        route (device, table, networks, gateway, id) to delete with fmc_delete_static_route or recreate
        without track first."""
        app: FmcApp = get_client(ctx)
        current = await resolve_monitor(app, monitor, domain)
        tracked = await routes_tracking(app, str(current["id"]), domain)
        blockers = []
        if tracked:
            blockers.append(
                f"Still tracked by {len(tracked)} static route(s): "
                + "; ".join(describe_route(r) for r in tracked)
                + ". Delete those routes (fmc_delete_static_route) or recreate them without track first."
            )
        path = await app.config_path(f"{SLA_MONITORS}/{current['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_sla_monitor",
            owned=[current],
            args={"monitor": monitor, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete SLA monitor {current.get('name')!r}",
                details={"monitor": monitor_row(current), "tracked_by_routes": tracked},
                fingerprint={"monitor": editable(current), "routes": [r["id"] for r in tracked]},
                blockers=blockers,
                undo=monitor_recreate_undo(current, domain),
                side_effects=[
                    leftover_warning(current.get("slaId"), "each device whose route tracked this monitor"),
                    "Nothing else changes on a device: no route tracks it any more.",
                ],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )

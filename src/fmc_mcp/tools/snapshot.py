"""Change-check snapshots on core's snapshot contract (F89, core C53): `fmc_snapshot(site)` and
`fmc_compare_snapshot(before, after)`, the FMC leg of the suite prompt `suite_change_check`.

A snapshot is a small, versioned JSON blob the client keeps; nothing is stored on the server. Sections (one
FMC read each, plus one show command per connected unit for the interfaces), item keys and sources:

    deployment  device:<name>             status, out-of-date policies      deployment/deployabledevices
    ha          pair:<name>               each unit's failover state        devicehapairs/ftddevicehapairs
    interfaces  <device>|<interface>      link status of addressed ones     show interface ip brief
    vpn         <topology>|<peer>|<peer>  tunnel state                      health/tunnelstatuses
    health      device:<name>             connected, FMC health status      device records
                alert:<device>|<module>   non-green health modules          health/alerts

`site` is an FMC device group (its members; HA pairs as their units) or else a device name filter (case-
insensitive substring); empty = every device of the domain. Volatile values (versions and timestamps of
the deployable list, tunnel change times, alert timestamps and readings such as CPU percentages) are left
out, so two snapshots of an unchanged estate compare as "No change". See stutters-mcp-core docs/SNAPSHOTS.md.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from fastmcp import Context

from fmc_mcp._core import InvalidRequest, ToolRegistrar, UpstreamError, get_client
from fmc_mcp._core.snapshot import Section, Snapshot, register_snapshot_tools
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.deploy import DEPLOYABLE
from fmc_mcp.tools.device_groups import as_group, member_refs, unit_refs
from fmc_mcp.tools.device_snapshot import (
    ALERTS,
    INTERFACES,
    TUNNELS,
    alert_text,
    parse_ip_brief,
    without_readings,
)
from fmc_mcp.tools.devices import DEVICES, HA_PAIRS
from fmc_mcp.tools.fleet import run_fleet

PREFIX = "fmc"
SERVER = "fmc-mcp-server"
TEXT_CAP = 160  # characters of a compared text field (pending policies, an alert's message)
ACTIVE_STANDBY = {"active", "standby"}


def _version() -> str | None:
    try:
        return version(SERVER)
    except PackageNotFoundError:
        return None


def _cap(text: str) -> str:
    return text if len(text) <= TEXT_CAP else text[: TEXT_CAP - 3] + "..."


def _key(*parts: Any) -> str:
    return "|".join(str(p) for p in parts)[:200]


def _add(sec: Section, key: str, **fields: Any) -> None:
    """Section.item, with a ' #2' suffix where FMC lists the same name twice (two rows of one module)."""
    n, k = 1, key
    while k in sec.items:
        n += 1
        k = f"{key[:195]} #{n}"
    sec.item(k, **fields)


# --- scope ----------------------------------------------------------------------------------------


async def scope_devices(app: FmcApp, site: str, domain: str | None) -> list[dict[str, Any]]:
    """The device records (expanded) a snapshot covers: a device group's members (HA pairs and clusters
    as their units), else the devices whose name contains `site`; every device when `site` is empty."""
    records: list[dict[str, Any]] = (await app.all(await app.config_path(DEVICES, domain), cap=2000)).items
    site = site.strip()
    if not site:
        return records
    group = await as_group(app, site, domain, records=records)
    if group is not None:
        ids = {str(m["id"]).lower() for m in await unit_refs(app, member_refs(group), domain, records)}
        return [d for d in records if str(d.get("id")).lower() in ids]
    want = site.lower()
    hits = [d for d in records if want in str(d.get("name", "")).lower()]
    if not hits:
        names = ", ".join(sorted(str(d.get("name")) for d in records)) or "none in this domain"
        raise InvalidRequest(f"No device group or device name matches {site!r}. Devices: {names}.")
    return hits


# --- sections -------------------------------------------------------------------------------------


def deployment_section(sec: Section, devices: list[dict[str, Any]], pending: list[dict[str, Any]]) -> None:
    by_id: dict[str, dict[str, Any]] = {}
    for p in pending:
        for i in [
            (p.get("device") or {}).get("id"),
            *((m or {}).get("id") for m in p.get("deviceMembers") or []),
        ]:
            if i:
                by_id[str(i).lower()] = p
    for d in devices:
        hit = by_id.get(str(d.get("id")).lower())
        status = str(d.get("deploymentStatus") or ("DEPLOYMENT_PENDING" if hit else "DEPLOYED"))
        out_of_date = sorted(
            str(pol.get("name") or pol.get("type") or "?").strip()
            for ps in (hit or {}).get("policyStatusList") or []
            if ps.get("upToDate") is False
            for pol in [ps.get("policy") or {}]
        )
        _add(
            sec,
            f"device:{d.get('name')}",
            ok=hit is None and "FAIL" not in status.upper(),
            state=status,
            pending=hit is not None,
            out_of_date=_cap("; ".join(out_of_date)) if out_of_date else None,
        )


def ha_section(sec: Section, pairs: list[dict[str, Any]], ids: set[str] | None) -> None:
    for p in pairs:
        units = [p.get("primary") or {}, p.get("secondary") or {}]
        if ids is not None and not ids & {str(u.get("id")).lower() for u in units}:
            continue
        meta = p.get("metadata") or {}
        states = {
            side: str((meta.get(f"{side}Status") or {}).get("currentStatus") or "unknown")
            for side in ("primary", "secondary")
        }
        names = {side: str((p.get(side) or {}).get("name") or side) for side in ("primary", "secondary")}
        _add(
            sec,
            f"pair:{p.get('name')}",
            ok={s.lower() for s in states.values()} == ACTIVE_STANDBY,
            state=", ".join(f"{names[s]} {states[s]}" for s in ("primary", "secondary")),
            primary=names["primary"],
            secondary=names["secondary"],
            config_status=meta.get("configStatus"),
        )


def interfaces_section(sec: Section, rows: list[dict[str, Any]]) -> None:
    """One item per interface with an address (FTD's internal interfaces left out by parse_ip_brief);
    any unit whose command failed makes the section unreadable rather than its interfaces 'gone'."""
    failed = [f"{r.get('device')}: {r.get('error')}" for r in rows if not r.get("ok")]
    if failed:
        sec.fail(f"'{INTERFACES}' failed on " + "; ".join(failed))
        return
    for r in rows:
        for i in parse_ip_brief(str(r.get("text") or "")):
            if str(i.get("ip") or "unassigned").lower() == "unassigned":
                continue
            status, protocol = str(i.get("status")), str(i.get("protocol"))
            _add(
                sec,
                _key(r.get("device"), i.get("interface")),
                ok=status == "up" and protocol == "up",
                state=status,
                protocol=protocol,
                ip=i.get("ip"),
            )


def _peer(p: dict[str, Any] | None) -> str:
    p = p or {}
    return str((p.get("device") or {}).get("name") or (p.get("extranet") or {}).get("name") or "?")


def vpn_section(sec: Section, tunnels: list[dict[str, Any]], ids: set[str] | None) -> None:
    for t in tunnels:
        ends = {str(((t.get(s) or {}).get("device") or {}).get("id")).lower() for s in ("peerA", "peerB")}
        if ids is not None and not ids & ends:
            continue
        state = str(t.get("state") or "UNKNOWN")
        up = state.upper()
        a, b = sorted((_peer(t.get("peerA")), _peer(t.get("peerB"))))
        _add(
            sec,
            _key((t.get("vpnTopology") or {}).get("name"), a, b),
            ok=True if up.endswith("UP") else False if up.endswith("DOWN") else None,
            state=state,
        )


def health_section(sec: Section, devices: list[dict[str, Any]], alerts: list[dict[str, Any]] | None) -> None:
    """Each device's connection and FMC health status, then its non-green health modules: RED is
    unhealthy, YELLOW a warning (no `ok`), DISABLED left out (a disconnected device has every module
    disabled, and its device item already says so)."""
    names = {str(d.get("id")).lower(): str(d.get("name")) for d in devices}
    for d in devices:
        connected = d.get("isConnected")
        health = str(d.get("healthStatus") or "unknown")
        _add(
            sec,
            f"device:{d.get('name')}",
            ok=connected is not False and health.lower() not in ("red", "disabled"),
            state=health,
            connected=connected,
        )
    bad = []
    for a in alerts or []:
        name = names.get(str(a.get("deviceUUID")).lower())
        status = str(a.get("status") or "").upper()
        if name is None or status not in ("RED", "YELLOW"):
            continue
        bad.append(
            (name, str(a.get("moduleID") or "?"), status, without_readings(alert_text(a.get("details"))))
        )
    for name, module, status, detail in sorted(bad):
        _add(
            sec,
            _key(f"alert:{name}", module),
            ok=False if status == "RED" else None,
            state=status,
            detail=_cap(detail) if detail else None,
        )


# --- take ------------------------------------------------------------------------------------------


async def _items(app: FmcApp, suffix: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = (await app.all(await app.config_path(suffix), cap=5000)).items
    return items


async def take(ctx: Context, site: str) -> Snapshot:
    app: FmcApp = get_client(ctx)
    devices = await scope_devices(app, site, None)
    ids = {str(d.get("id")).lower() for d in devices} if site.strip() else None
    snap = Snapshot(PREFIX, SERVER, scope={"site": site.strip()}, server_version=_version())

    deployment = snap.section("deployment", "Deployment state")
    try:
        deployment_section(deployment, devices, await _items(app, DEPLOYABLE))
    except UpstreamError as e:
        deployment.fail(str(e))

    ha = snap.section("ha", "HA pairs")
    try:
        ha_section(ha, await _items(app, HA_PAIRS), ids)
    except UpstreamError as e:
        ha.fail(str(e))

    interfaces = snap.section("interfaces", "Interfaces")
    live = [d for d in devices if d.get("isConnected") is not False]
    if live:
        try:
            run = await run_fleet(ctx, app, live, [INTERFACES], None)
            interfaces_section(interfaces, run.rows)
        except UpstreamError as e:
            interfaces.fail(str(e))

    vpn = snap.section("vpn", "VPN tunnels")
    try:
        vpn_section(vpn, await _items(app, TUNNELS), ids)
    except UpstreamError as e:
        vpn.fail(str(e))

    health = snap.section("health", "Device health")
    try:
        alerts: list[dict[str, Any]] | None = await _items(app, ALERTS)
    except UpstreamError as e:
        health.fail(f"health alerts: {e}")
        alerts = None
    if alerts is not None:
        health_section(health, devices, alerts)
    return snap


def register(reg: ToolRegistrar) -> None:
    register_snapshot_tools(
        reg,
        take,
        product="Secure Firewall Management Center",
        covers="deployment state (pending changes per device), HA pair roles, interface link status, VPN "
        "tunnel state, device health and non-green health modules",
        site_doc="FMC device group (its members; HA pairs as their units) or a device name filter "
        "(case-insensitive substring); empty = every device in the domain",
    )

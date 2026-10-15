"""FTD HA depth: the pair's live state, monitored interfaces (standby IPs, failure monitoring) and
failover virtual MAC addresses. Forming, switching and breaking the pair are in dangerous.py."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import re
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    Plan,
    ToolRegistrar,
    get_client,
    object_result,
    preview_or_apply,
)

from fmc_mcp.client import FmcApp
from fmc_mcp.tools.common import Domain, ref_label, resolve_in, slim
from fmc_mcp.tools.devices import HA_PAIRS
from fmc_mcp.tools.object_writes import applied, editable

HaRef = Annotated[str, Field(description="HA pair name or UUID (fmc_list_ha_pairs)")]
MAC_RE = re.compile(r"^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$")


def _mac(value: str | None, what: str) -> str | None:
    """A MAC in FMC's H.H.H form (accepts aa:bb:cc:dd:ee:ff and aabb.ccdd.eeff)."""
    if value is None:
        return None
    v = value.strip().lower()
    if MAC_RE.match(v):
        return v
    hexes = re.sub(r"[^0-9a-f]", "", v)
    if len(hexes) != 12 or not re.fullmatch(r"[0-9a-f:\-.]+", v):
        raise InvalidRequest(
            f"{what} {value!r} is not a MAC address (use 0050.56aa.0001 or 00:50:56:aa:00:01)."
        )
    return f"{hexes[0:4]}.{hexes[4:8]}.{hexes[8:12]}"


def _monitored_row(m: dict[str, Any]) -> dict[str, Any]:
    v4 = m.get("ipv4Configuration") or {}
    row = {
        "interface": m.get("name"),
        "monitored": m.get("monitorForFailures"),
        "active_ip": v4.get("activeIPv4Address"),
        "mask": v4.get("activeIPv4Mask"),
        "standby_ip": v4.get("standbyIPv4Address"),
        "id": m.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


def _mac_row(m: dict[str, Any]) -> dict[str, Any]:
    return {
        "interface": ref_label(m.get("physicalInterface") or {}),
        "active_mac": m.get("failoverActiveMac"),
        "standby_mac": m.get("failoverStandbyMac"),
        "id": m.get("id"),
    }


async def _pair(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    return await resolve_in(app, HA_PAIRS, ref, "HA pair", domain)


def _status(ha: dict[str, Any]) -> dict[str, Any]:
    meta = ha.get("metadata") or {}
    out = {}
    for side in ("primary", "secondary"):
        st = meta.get(f"{side}Status") or {}
        out[side] = {
            "device": ref_label(ha.get(side) or {}),
            "state": st.get("currentStatus"),
        }
    return out


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Get HA pair status")
    async def fmc_get_ha_status(ctx: Context, ha_pair: HaRef, domain: Domain = None) -> Any:
        """One FTD HA pair in detail: which unit is active/standby, the failover link, the failover
        trigger criteria, every monitored interface (monitored for failures, active and standby IP)
        and any failover virtual MAC addresses. Live failover state on the device:
        fmc_run_show_command('show failover')."""
        app: FmcApp = get_client(ctx)
        ha = await _pair(app, ha_pair, domain)
        base = await app.config_path(f"{HA_PAIRS}/{ha['id']}", domain)
        monitored = await app.all(f"{base}/monitoredinterfaces")
        macs = await app.all(f"{base}/failoverinterfacemacaddressconfigs")
        boot = ha.get("ftdHABootstrap") or {}
        link = boot.get("lanFailover") or {}
        return object_result(
            {
                "name": ha.get("name"),
                "id": ha.get("id"),
                "units": _status(ha),
                "failover_link": {
                    "interface": ref_label(link.get("interfaceObject") or {}),
                    "logical_name": link.get("logicalName"),
                    "active_ip": link.get("activeIP"),
                    "standby_ip": link.get("standbyIP"),
                    "mask": link.get("subnetMask"),
                    "same_link_for_state": boot.get("useSameLinkForFailovers"),
                    "encryption": boot.get("isEncryptionEnabled"),
                },
                "trigger_criteria": slim(ha.get("ftdHAFailoverTriggerCriteria")),
                "monitored_interfaces": [_monitored_row(m) for m in monitored.items],
                "failover_macs": [_mac_row(m) for m in macs.items],
            },
            shape=False,
        )

    @reg.write(title="Configure HA monitored interface")
    async def fmc_configure_ha_monitoring(
        ctx: Context,
        ha_pair: HaRef,
        interface: Annotated[
            str, Field(description="Interface logical name (e.g. inside) as listed by fmc_get_ha_status")
        ],
        monitored: Annotated[
            bool | None,
            Field(
                description="Monitor the interface for failures (a failure triggers failover); omit to keep"
            ),
        ] = None,
        standby_ip: Annotated[
            str | None,
            Field(description="Standby unit's IPv4 address on this interface ('none' clears it)"),
        ] = None,
        active_mac: Annotated[
            str | None, Field(description="Failover virtual MAC for the active unit, e.g. 0050.56aa.0001")
        ] = None,
        standby_mac: Annotated[
            str | None, Field(description="Failover virtual MAC for the standby unit (with active_mac)")
        ] = None,
        clear_mac: Annotated[bool, Field(description="Remove the interface's virtual MAC setting")] = False,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Configure one interface of an FTD HA pair: whether a failure on it triggers failover, the
        standby unit's IP address (needed for the standby to answer on that network and for
        interface monitoring), and the failover virtual MAC addresses (so the active MAC stays the
        same after a failover). Preview shows before/after; takes effect after fmc_deploy."""
        app: FmcApp = get_client(ctx)
        if clear_mac and (active_mac or standby_mac):
            raise InvalidRequest("Give active_mac/standby_mac or clear_mac, not both.")
        if (active_mac is None) != (standby_mac is None):
            raise InvalidRequest("Give both active_mac and standby_mac.")
        amac, smac = _mac(active_mac, "active_mac"), _mac(standby_mac, "standby_mac")
        if monitored is None and standby_ip is None and amac is None and not clear_mac:
            raise InvalidRequest("Nothing to change: give monitored, standby_ip, the MACs or clear_mac.")
        ha = await _pair(app, ha_pair, domain)
        base = await app.config_path(f"{HA_PAIRS}/{ha['id']}", domain)
        monitored_all = await app.all(f"{base}/monitoredinterfaces")
        mon = next(
            (m for m in monitored_all.items if str(m.get("name", "")).lower() == interface.lower()), None
        )
        if mon is None:
            names = ", ".join(str(m.get("name")) for m in monitored_all.items) or "none"
            raise InvalidRequest(
                f"HA pair {ha.get('name')!r} has no monitored interface {interface!r} (have: {names}). "
                "Only named data interfaces are listed."
            )
        blockers: list[str] = []
        changes: dict[str, Any] = {}
        new_mon = editable(mon)
        if monitored is not None and monitored != mon.get("monitorForFailures"):
            new_mon["monitorForFailures"] = monitored
            changes["monitored"] = {"from": mon.get("monitorForFailures"), "to": monitored}
        v4 = dict(mon.get("ipv4Configuration") or {})
        if standby_ip is not None:
            want = None if standby_ip.strip().lower() == "none" else standby_ip.strip()
            if want is not None:
                try:
                    addr = ipaddress.IPv4Address(want)
                except ValueError:
                    raise InvalidRequest(f"standby_ip {standby_ip!r} is not an IPv4 address.") from None
                active, mask = v4.get("activeIPv4Address"), v4.get("activeIPv4Mask")
                if not active:
                    blockers.append(
                        f"Interface {interface!r} has no IPv4 address; set one first (fmc_update_interface)."
                    )
                elif mask:
                    net = ipaddress.IPv4Network(f"{active}/{mask}", strict=False)
                    if addr not in net:
                        blockers.append(f"{addr} is not in the interface network {net}.")
                    elif str(addr) == active:
                        blockers.append(f"{addr} is the active unit's address.")
                want = str(addr)
            if want != v4.get("standbyIPv4Address"):
                if want is None:
                    v4.pop("standbyIPv4Address", None)
                else:
                    v4["standbyIPv4Address"] = want
                new_mon["ipv4Configuration"] = v4
                was = (mon.get("ipv4Configuration") or {}).get("standbyIPv4Address")
                changes["standby_ip"] = {"from": was, "to": want}
        macs = await app.all(f"{base}/failoverinterfacemacaddressconfigs")
        mac_cfg = next(
            (
                m
                for m in macs.items
                if str((m.get("physicalInterface") or {}).get("name", "")).lower()
                in {interface.lower(), str(mon.get("name", "")).lower()}
                or str((m.get("physicalInterface") or {}).get("ifname", "")).lower() == interface.lower()
            ),
            None,
        )
        mac_body: dict[str, Any] | None = None
        mac_method = None
        if amac is not None:
            have = mac_cfg and (mac_cfg.get("failoverActiveMac"), mac_cfg.get("failoverStandbyMac"))
            if have != (amac, smac):
                if amac == smac:
                    blockers.append("active_mac and standby_mac must differ.")
                phys = await _physical(app, ha, interface, domain)
                if phys is None:
                    blockers.append(f"Couldn't find the physical interface behind {interface!r}.")
                mac_body = {
                    "type": "FailoverInterfaceMacAddressConfig",
                    "physicalInterface": phys,
                    "failoverActiveMac": amac,
                    "failoverStandbyMac": smac,
                }
                mac_method = "PUT" if mac_cfg else "POST"
                if mac_cfg:
                    mac_body["id"] = mac_cfg["id"]
                changes["mac"] = {
                    "from": _mac_row(mac_cfg) if mac_cfg else None,
                    "to": {"active_mac": amac, "standby_mac": smac},
                }
        elif clear_mac and mac_cfg:
            mac_method = "DELETE"
            changes["mac"] = {"from": _mac_row(mac_cfg), "to": None}
        if not changes:
            blockers.append("Nothing to change: the interface already has these settings.")
        mon_path = f"{base}/monitoredinterfaces/{mon['id']}"
        mac_path = f"{base}/failoverinterfacemacaddressconfigs"

        async def apply() -> Any:
            out: dict[str, Any] = {}
            if "monitored" in changes or "standby_ip" in changes:
                out["monitored_interface"] = _monitored_row(
                    await applied(app, lambda: app.api.put(mon_path, new_mon))
                )
            if mac_method == "POST":
                out["mac"] = _mac_row(await applied(app, lambda: app.api.post(mac_path, mac_body)))
            elif mac_method == "PUT" and mac_cfg:
                out["mac"] = _mac_row(
                    await applied(app, lambda: app.api.put(f"{mac_path}/{mac_cfg['id']}", mac_body))
                )
            elif mac_method == "DELETE" and mac_cfg:
                await applied(app, lambda: app.api.delete(f"{mac_path}/{mac_cfg['id']}"))
                out["mac"] = None
            out["next"] = "Deploy the pair (fmc_deploy) and check fmc_run_show_command('show failover')."
            return out

        return await preview_or_apply(
            ctx,
            tool="fmc_configure_ha_monitoring",
            args={
                "ha_pair": ha_pair,
                "interface": interface,
                "monitored": monitored,
                "standby_ip": standby_ip,
                "active_mac": active_mac,
                "standby_mac": standby_mac,
                "clear_mac": clear_mac,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Update HA interface {interface!r} on {ha.get('name')!r}",
                details={"changes": changes, "current": _monitored_row(mon)},
                fingerprint={"mon": editable(mon), "mac": mac_cfg and editable(mac_cfg)},
                blockers=blockers,
                side_effects=["Takes effect on both units after the next deployment of the HA pair."],
            ),
            apply=apply,
        )


async def _physical(
    app: FmcApp, ha: dict[str, Any], ifname: str, domain: str | None
) -> dict[str, Any] | None:
    """The {id, type, name} of the primary's physical interface with this logical name (or name)."""
    prim = (ha.get("primary") or {}).get("id")
    if not prim:
        return None
    rows = await app.all(await app.config_path(f"devices/devicerecords/{prim}/physicalinterfaces", domain))
    for i in rows.items:
        if ifname.lower() in {str(i.get("ifname", "")).lower(), str(i.get("name", "")).lower()}:
            return {"id": i["id"], "type": i.get("type", "PhysicalInterface"), "name": i.get("name")}
    return None

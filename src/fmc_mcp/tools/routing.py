"""Dynamic routing on FTDs (F6): one readable view of BGP, OSPF, ECMP, PBR, BFD and VRFs, plus
preview-first edits for the common cases (BGP neighbors and networks, OSPF areas, VRFs).

FMC's BGP and OSPF models are large nested objects that FMC replaces as a whole on PUT; these tools
read the current object, change only the requested parts and send it back. Changes reach the device
after fmc_deploy; check with fmc_run_show_command('show route') and the peer's CLI.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field
from stutters_mcp_core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
)

from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import NETWORK_TYPES, RefResolver
from fmc_mcp.tools.common import Domain, ref_label, ref_of
from fmc_mcp.tools.device_config import (
    device_interfaces,
    network_by_value,
    pick_interface,
    resolve_device,
    routing_base,
)
from fmc_mcp.tools.devices import DeviceRef
from fmc_mcp.tools.object_writes import applied, editable

VrfParam = Annotated[
    str | None, Field(description="Virtual router (VRF) name/UUID; default the global table")
]
NetList = Annotated[
    list[str] | None,
    Field(description="Network/host object names or CIDRs matching an existing object (e.g. 10.99.1.0/24)"),
]
# Defaults FMC 10.0.1 requires when an OSPF process is created (it rejects the POST without them).
OSPF_PROCESS_DEFAULTS: dict[str, Any] = {
    "rfc1583Compatible": False,
    "ignoreLsaMospf": False,
    "administrativeDistance": {"interArea": 110, "intraArea": 110, "external": 110},
    "timers": {"lsaGroup": 240},
}


# --- helpers -------------------------------------------------------------------------------------


def check_as(value: str | None, what: str) -> str | None:
    """An AS number as FMC takes it: 1-4294967295 (asplain) or x.y (asdot)."""
    if value is None:
        return None
    v = str(value).strip()
    parts = v.split(".")
    ok = (len(parts) == 1 and v.isdigit() and 1 <= int(v) <= 4_294_967_295) or (
        len(parts) == 2 and all(p.isdigit() and int(p) <= 65535 for p in parts)
    )
    if not ok:
        raise InvalidRequest(f"{what} {value!r} is not an AS number (1-4294967295 or x.y).")
    return v


def check_router_id(value: str | None) -> str | None:
    if value is None or value.strip().upper() == "AUTOMATIC":
        return None
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ValueError:
        raise InvalidRequest(f"router_id must be an IPv4 address or AUTOMATIC, got {value!r}.") from None


def area_key(value: Any) -> int:
    """OSPF area ids compare by value: '0' and '0.0.0.0' are the same area."""
    v = str(value).strip()
    try:
        return int(v) if v.isdigit() else int(ipaddress.IPv4Address(v))
    except ValueError:
        raise InvalidRequest(f"OSPF area {value!r} must be a number or dotted quad.") from None


async def _items(app: FmcApp, path: str, domain: str | None) -> list[dict[str, Any]]:
    # One big page, de-duplicated: FMC 10.0.1 reports `count: 2` for a single OSPFv2 process and
    # returns it again at offset 1, so paging through these collections never ends.
    try:
        page = await app.page(await app.config_path(path, domain), limit=1000)
    except (NotFound, InvalidRequest):
        return []
    except UpstreamError as e:
        if e.status_code in (404, 405):
            return []
        raise
    seen: dict[str, dict[str, Any]] = {}
    for item in page.items:
        seen.setdefault(str(item.get("id") or len(seen)), item)
    return list(seen.values())


def _names(refs: Any) -> list[str]:
    out = []
    for r in refs or []:
        if isinstance(r, dict):
            inner = r.get("ipv4Address") or r.get("ipv6Address") or r
            out.append(ref_label(inner) if isinstance(inner, dict) else str(inner))
    return out


def neighbor_row(n: dict[str, Any]) -> dict[str, Any]:
    gen = n.get("neighborGeneral") or {}
    adv = n.get("neighborAdvanced") or {}
    return {
        "address": n.get("ipv4Address") or n.get("ipv6Address"),
        "remote_as": n.get("remoteAs"),
        "enabled": gen.get("enableAddress", True) and not gen.get("shutdown", False),
        "description": gen.get("description"),
        "bfd": gen.get("fallOverBFD") if gen.get("fallOverBFD") not in (None, "NONE") else None,
        "update_source": ref_label(gen["updateSource"]) if gen.get("updateSource") else None,
        "ebgp_multihop": (adv.get("neighborHops") or {}).get("maxHopCount"),
        "password_set": bool(adv.get("neighborSecret")) or None,
    }


def af_summary(af: dict[str, Any] | None) -> dict[str, Any] | None:
    if not af:
        return None
    return {
        "neighbors": [neighbor_row(n) for n in af.get("neighbors") or []],
        "networks": _names(af.get("networks")),
        "redistribute": [str(r.get("type")) for r in af.get("redistributeProtocols") or []] or None,
        "maximum_paths": [m.get("value") for m in af.get("maximumPaths") or []] or None,
        "default_originate": af.get("defaultInformationOrginate") or None,
    }


def bgp_summary(general: dict[str, Any] | None, bgp: dict[str, Any] | None) -> dict[str, Any] | None:
    if not general and not bgp:
        return None
    return {
        "as": (bgp or {}).get("asNumber") or (general or {}).get("asNumber"),
        "router_id": (general or {}).get("routerId") or (bgp or {}).get("routerId"),
        "ipv4": af_summary((bgp or {}).get("addressFamilyIPv4")),
        "ipv6": af_summary((bgp or {}).get("addressFamilyIPv6")),
        "id": (bgp or {}).get("id"),
    }


def ospf_summary(p: dict[str, Any]) -> dict[str, Any]:
    conf = p.get("processConfiguration") or {}
    return {
        "process": p.get("processId"),
        "enabled_as": p.get("enableProcess"),
        "router_id": conf.get("routerId"),
        "areas": [
            {
                "area": a.get("areaId"),
                "type": (a.get("areaType") or {}).get("type"),
                "networks": _names(a.get("areaNetworks")),
                "authentication": a.get("authentication"),
            }
            for a in p.get("areas") or []
        ],
        "redistribute": [str(r.get("type")) for r in p.get("redistributeProtocols") or []] or None,
        "id": p.get("id"),
    }


async def network_refs(app: FmcApp, values: list[str] | None, domain: str | None) -> list[dict[str, Any]]:
    out = []
    res = RefResolver(app, domain)
    for v in values or []:
        text = v.strip()
        try:
            ipaddress.ip_network(text, strict=False)
            obj = await network_by_value(app, text, domain)
            if obj is None:
                raise InvalidRequest(
                    f"No network object with value {text}; create one with fmc_create_object first."
                )
            out.append(ref_of(obj))
        except ValueError:
            out.append(await res.single(text, NETWORK_TYPES, "network"))
    return out


# --- tools ---------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Get device routing")
    async def fmc_get_routing(
        ctx: Context, device: DeviceRef, virtual_router: VrfParam = None, domain: Domain = None
    ) -> dict[str, Any]:
        """One view of the dynamic routing FMC holds for a device (or one VRF): BGP (AS, router id,
        neighbors with remote AS/state/BFD, advertised networks, redistribution, per address family),
        OSPFv2 processes (areas, networks, redistribution), OSPF interface settings, ECMP zones,
        policy-based routes, BFD policies, VRFs and the static route count. Configuration, not the
        live state: use fmc_run_show_command('show route') and the peer's CLI for that. Static routes
        in detail: fmc_list_routes."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        base, vr_name = await routing_base(app, dev, virtual_router, domain)
        root = f"{base.split('/routing')[0]}/routing"
        general = (
            None
            if virtual_router
            else next(iter(await _items(app, f"{root}/bgpgeneralsettings", domain)), None)
        )
        bgp = next(iter(await _items(app, f"{base}/bgp", domain)), None)
        ospf = await _items(app, f"{base}/ospfv2routes", domain)
        out: dict[str, Any] = {
            "device": dev.get("name"),
            "table": vr_name or "global",
            "bgp": bgp_summary(general, bgp),
            "ospfv2": [ospf_summary(p) for p in ospf] or None,
        }
        statics = len(await _items(app, f"{base}/ipv4staticroutes", domain)) + len(
            await _items(app, f"{base}/ipv6staticroutes", domain)
        )
        out["static_routes"] = statics
        if not virtual_router:
            ifaces = await _items(app, f"{root}/ospfinterface", domain)
            out["ospf_interfaces"] = [
                {
                    "interface": ref_label(i.get("deviceInterface") or {}),
                    "settings": {
                        k: v
                        for k, v in (i.get("ospfProtocolConfiguration") or {}).items()
                        if k not in ("type", "authentication") and v not in (None, "", [], {})
                    },
                }
                for i in ifaces
            ] or None
            out["ecmp_zones"] = [
                {"name": z.get("name"), "interfaces": _names(z.get("interfaces"))}
                for z in await _items(app, f"{root}/ecmpzones", domain)
            ] or None
            out["policy_based_routes"] = len(await _items(app, f"{root}/policybasedroutes", domain)) or None
            out["bfd_policies"] = len(await _items(app, f"{root}/bfdpolicies", domain)) or None
            out["ospfv3_processes"] = len(await _items(app, f"{root}/ospfv3routes", domain)) or None
            vrs = await _items(app, f"{root}/virtualrouters", domain)
            out["vrfs"] = [
                {"name": v.get("name"), "interfaces": _names(v.get("interfaces")), "id": v.get("id")}
                for v in vrs
                if str(v.get("name", "")).lower() != "global"
            ] or None
        return {k: v for k, v in out.items() if v is not None}

    @reg.write(title="Configure BGP")
    async def fmc_configure_bgp(
        ctx: Context,
        device: DeviceRef,
        neighbor: Annotated[
            str | None, Field(description="Neighbor IPv4 address to add, change or remove")
        ] = None,
        remote_as: Annotated[
            str | None, Field(description="Neighbor's AS number (adding or changing)")
        ] = None,
        remove_neighbor: Annotated[bool, Field(description="Remove `neighbor` instead of adding it")] = False,
        neighbor_description: Annotated[str | None, Field(description="Neighbor description")] = None,
        neighbor_password: Annotated[
            str | None,
            Field(
                description="MD5 password for `neighbor` (FMC never returns it; required again when the "
                "neighbor already has one and BGP is edited)"
            ),
        ] = None,
        advertise: NetList = None,
        withdraw: NetList = None,
        local_as: Annotated[
            str | None, Field(description="This device's AS; needed when BGP isn't configured on it yet")
        ] = None,
        router_id: Annotated[
            str | None, Field(description="BGP router id (IPv4) when BGP is first set up; default AUTOMATIC")
        ] = None,
        remove_bgp: Annotated[
            bool, Field(description="Remove BGP from the device/VRF entirely (neighbors, networks, settings)")
        ] = False,
        virtual_router: VrfParam = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Edit BGP (IPv4 unicast) on an FTD: add, change or remove a neighbor (remote AS, MD5
        password), and advertise or withdraw networks (network objects). Sets up BGP first (local AS,
        router id) when the device has none; the AS and router id are device-wide, so a VRF uses them
        too. remove_bgp deletes the whole BGP configuration. The preview shows the
        neighbor and network lists before and after. Deploy to apply; verify with
        fmc_run_show_command('show route') and the peer ('show bgp summary')."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        base, vr_name = await routing_base(app, dev, virtual_router, domain)
        root = f"{base.split('/routing')[0]}/routing"
        general = next(iter(await _items(app, f"{root}/bgpgeneralsettings", domain)), None)
        bgp = next(iter(await _items(app, f"{base}/bgp", domain)), None)
        where = f"{dev.get('name')} ({vr_name or 'global table'})"
        blockers: list[str] = []
        steps: list[tuple[str, str, str, dict[str, Any] | None]] = []
        bgp_path = await app.config_path(f"{base}/bgp", domain)
        gen_path = await app.config_path(f"{root}/bgpgeneralsettings", domain)

        if remove_bgp:
            if any(
                (
                    neighbor,
                    remote_as,
                    advertise,
                    withdraw,
                    local_as,
                    router_id,
                    remove_neighbor,
                    neighbor_description,
                )
            ):
                raise InvalidRequest("remove_bgp can't be combined with other changes.")
            if bgp:
                steps.append(("delete bgp", "DELETE", f"{bgp_path}/{bgp['id']}", None))
            if general and not virtual_router:
                steps.append(("delete bgp general settings", "DELETE", f"{gen_path}/{general['id']}", None))
            if not steps:
                blockers.append(f"BGP isn't configured on {where}.")
            before = bgp_summary(general, bgp)
            after = None
        else:
            if not any((neighbor, advertise, withdraw)):
                raise InvalidRequest("Give a neighbor, networks to advertise/withdraw, or remove_bgp.")
            if remove_neighbor and not neighbor:
                raise InvalidRequest("remove_neighbor needs the neighbor address.")
            remote_as = check_as(remote_as, "remote_as")
            local_as = check_as(local_as, "local_as")
            rid = check_router_id(router_id)
            if general is None:
                if not local_as:
                    blockers.append(
                        f"BGP isn't set up on {dev.get('name')}: give local_as (and optionally router_id)."
                    )
                else:
                    body = {
                        "type": "BGPGeneralSetting",
                        "name": "AsaBGPGeneralTable",
                        "asNumber": str(local_as),
                        "routerId": rid or "AUTOMATIC",
                        "logNeighborChanges": True,
                    }
                    steps.append(("create bgp general settings", "POST", gen_path, body))
            elif local_as and str(general.get("asNumber")) != str(local_as):
                blockers.append(
                    f"{dev.get('name')} already runs BGP AS {general.get('asNumber')}; "
                    "changing the AS isn't supported here."
                )
            desired: dict[str, Any] = (
                editable(bgp)
                if bgp
                else {"type": "bgp", "asNumber": str(local_as or (general or {}).get("asNumber") or "")}
            )
            af = dict(desired.get("addressFamilyIPv4") or {"type": "afipv4"})
            neighbors = list(af.get("neighbors") or [])
            networks = list(af.get("networks") or [])
            if neighbor:
                try:
                    addr = str(ipaddress.IPv4Address(neighbor.strip()))
                except ValueError:
                    raise InvalidRequest(f"neighbor must be an IPv4 address, got {neighbor!r}.") from None
                existing = next((n for n in neighbors if n.get("ipv4Address") == addr), None)
                if remove_neighbor:
                    if existing is None:
                        blockers.append(f"No BGP neighbor {addr} on {where}.")
                    neighbors = [n for n in neighbors if n is not existing]
                else:
                    if not remote_as and existing is None:
                        raise InvalidRequest("remote_as is required to add a neighbor.")
                    if existing is None:
                        n: dict[str, Any] = {
                            "type": "neighboripv4",
                            "ipv4Address": addr,
                            "remoteAs": str(remote_as),
                            "neighborGeneral": {"enableAddress": True, "shutdown": False},
                        }
                        if neighbor_description:
                            n["neighborGeneral"]["description"] = neighbor_description
                        neighbors.append(n)
                    else:
                        changed = dict(existing)
                        if remote_as:
                            changed["remoteAs"] = str(remote_as)
                        if neighbor_description:
                            changed["neighborGeneral"] = {
                                **(existing.get("neighborGeneral") or {}),
                                "description": neighbor_description,
                            }
                        if changed == existing:
                            blockers.append(f"Neighbor {addr} is already configured that way.")
                        neighbors = [changed if x is existing else x for x in neighbors]
            have = {str((x.get("ipv4Address") or {}).get("id")) for x in networks}
            for ref in await network_refs(app, advertise, domain):
                if ref["id"] in have:
                    blockers.append(f"{ref.get('name')} is already advertised.")
                    continue
                networks.append({"ipv4Address": ref})
                have.add(ref["id"])
            drop = {r["id"]: r for r in await network_refs(app, withdraw, domain)}
            for rid, ref in drop.items():
                if rid not in have:
                    blockers.append(f"{ref.get('name')} isn't advertised.")
            networks = [x for x in networks if str((x.get("ipv4Address") or {}).get("id")) not in drop]
            if neighbor and neighbor_password and not remove_neighbor:
                addr = str(ipaddress.IPv4Address(neighbor.strip()))
                neighbors = [
                    {
                        **x,
                        "neighborAdvanced": {
                            **(x.get("neighborAdvanced") or {}),
                            "neighborSecret": neighbor_password,
                        },
                    }
                    if x.get("ipv4Address") == addr
                    else x
                    for x in neighbors
                ]
            for x in neighbors:
                secret = (x.get("neighborAdvanced") or {}).get("neighborSecret")
                if secret and set(str(secret)) == {"*"}:
                    # FMC returns MD5 passwords masked; a PUT with the mask sets the mask as the password
                    # and one without it removes authentication (both seen live). Refuse to break peering.
                    blockers.append(
                        f"Neighbor {x.get('ipv4Address')} has an MD5 password that FMC only returns masked; "
                        "editing BGP would replace it. Pass neighbor=<that address> with neighbor_password, "
                        "or change it in the FMC UI."
                    )
            af.pop("maximumPaths", None)  # FMC 10.0.1 echoes it on GET but rejects it on PUT (use ebgp/ibgp)
            af["neighbors"] = neighbors
            af["networks"] = networks
            desired["addressFamilyIPv4"] = af
            before = bgp_summary(general, bgp)
            after = {"neighbors": [neighbor_row(x) for x in neighbors], "networks": _names(networks)}
            if bgp:
                steps.append(("update bgp", "PUT", f"{bgp_path}/{bgp['id']}", desired))
            else:
                steps.append(("create bgp", "POST", bgp_path, desired))

        async def apply() -> Any:
            done: list[str] = []
            try:
                for name, method, path, body in steps:
                    try:
                        if method == "DELETE":
                            await app.api.delete(path)
                        elif method == "POST":
                            await app.api.post(path, body)
                        else:
                            await app.api.put(path, body)
                    except Exception as e:
                        raise UpstreamError(
                            f"{name} failed ({e}); already applied: {done or 'nothing'}.",
                            getattr(e, "status_code", None),
                        ) from e
                    done.append(name)
            finally:
                app.invalidate_cache()
            return {"applied": done, "next": "fmc_deploy, then check 'show route' on the device"}

        return await fmc_preview(
            ctx,
            tool="fmc_configure_bgp",
            args={
                "device": device,
                "neighbor": neighbor,
                "remote_as": remote_as,
                "remove_neighbor": remove_neighbor,
                "neighbor_description": neighbor_description,
                "neighbor_password": neighbor_password,
                "advertise": advertise,
                "withdraw": withdraw,
                "local_as": local_as,
                "router_id": router_id,
                "remove_bgp": remove_bgp,
                "virtual_router": virtual_router,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"{'Remove' if remove_bgp else 'Change'} BGP on {where}",
                details={"steps": [s[0] for s in steps], "before": before, "after": after},
                fingerprint={"general": general and editable(general), "bgp": bgp and editable(bgp)},
                blockers=blockers,
                side_effects=["Takes effect on the device after the next deployment."],
            ),
            apply=apply,
        )

    @reg.write(title="Configure OSPF")
    async def fmc_configure_ospf(
        ctx: Context,
        device: DeviceRef,
        process_id: Annotated[int, Field(ge=1, le=65535, description="OSPF process id")] = 1,
        area: Annotated[str, Field(description="Area id, e.g. 0 or 0.0.0.1")] = "0",
        add_networks: NetList = None,
        remove_networks: NetList = None,
        router_id: Annotated[
            str | None, Field(description="Router id when the process is created (default automatic)")
        ] = None,
        remove_process: Annotated[bool, Field(description="Delete the whole OSPF process")] = False,
        virtual_router: VrfParam = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Edit OSPFv2 on an FTD: add or remove networks (network objects) in an area, creating the
        process and area when needed, or delete a whole process. Interfaces whose address falls in an
        area network run OSPF in that area. The preview shows the areas before and after. Deploy to
        apply; verify with fmc_run_show_command('show route') (O routes) and the neighbor's CLI."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        base, vr_name = await routing_base(app, dev, virtual_router, domain)
        where = f"{dev.get('name')} ({vr_name or 'global table'})"
        procs = await _items(app, f"{base}/ospfv2routes", domain)
        proc = next((p for p in procs if str(p.get("processId")) == str(process_id)), None)
        path = await app.config_path(f"{base}/ospfv2routes", domain)
        blockers: list[str] = []
        method, target, body = "PUT", "", None
        if remove_process:
            if add_networks or remove_networks:
                raise InvalidRequest("remove_process can't be combined with network changes.")
            if proc is None:
                blockers.append(f"No OSPF process {process_id} on {where}.")
            method, target = "DELETE", f"{path}/{(proc or {}).get('id')}"
            after = None
        else:
            if not add_networks and not remove_networks:
                raise InvalidRequest("Give add_networks or remove_networks (or remove_process).")
            if proc is None:
                if len(procs) >= 2:
                    blockers.append(f"{where} already has two OSPFv2 processes (the FTD maximum).")
                used = {p.get("enableProcess") for p in procs}
                conf = dict(OSPF_PROCESS_DEFAULTS)
                if router_id:
                    conf["routerId"] = check_router_id(router_id) or "AUTOMATIC"
                desired: dict[str, Any] = {
                    "type": "OspfRoute",
                    "processId": str(process_id),
                    "enableProcess": "PROCESS_2" if "PROCESS_1" in used else "PROCESS_1",
                    "logAdjacencyChanges": {"logType": "DEFAULT"},
                    "processConfiguration": conf,
                    "areas": [],
                }
                method, target = "POST", path
            else:
                desired = editable(proc)
                target = f"{path}/{proc['id']}"
            areas = [dict(a) for a in desired.get("areas") or []]
            want_area = area_key(area)
            entry = next((a for a in areas if area_key(a.get("areaId")) == want_area), None)
            if entry is None:
                entry = {"areaId": str(area), "areaType": {"type": "normal"}, "areaNetworks": []}
                areas.append(entry)
            nets = list(entry.get("areaNetworks") or [])
            have = {str(x.get("id")) for x in nets}
            for ref in await network_refs(app, add_networks, domain):
                if ref["id"] in have:
                    blockers.append(f"{ref.get('name')} is already in area {area}.")
                    continue
                nets.append(ref)
                have.add(ref["id"])
            drop = {r["id"]: r for r in await network_refs(app, remove_networks, domain)}
            for rid, ref in drop.items():
                if rid not in have:
                    blockers.append(f"{ref.get('name')} isn't in area {area}.")
            nets = [x for x in nets if str(x.get("id")) not in drop]
            entry["areaNetworks"] = nets
            if not nets and not any(entry.get(k) for k in ("areaRanges", "virtualLinks", "filterList")):
                areas = [a for a in areas if a is not entry]  # the edited area is now empty: drop it
            if not areas:
                blockers.append("That would leave the process with no networks; use remove_process instead.")
            desired["areas"] = areas
            body = desired
            after = ospf_summary(desired)
        before = ospf_summary(proc) if proc else None

        async def apply() -> Any:
            if method == "DELETE":
                return await applied(app, lambda: app.api.delete(target))
            if method == "POST":
                return await applied(app, lambda: app.api.post(target, body))
            return await applied(app, lambda: app.api.put(target, body))

        return await fmc_preview(
            ctx,
            tool="fmc_configure_ospf",
            args={
                "device": device,
                "process_id": process_id,
                "area": area,
                "add_networks": add_networks,
                "remove_networks": remove_networks,
                "router_id": router_id,
                "remove_process": remove_process,
                "virtual_router": virtual_router,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"{'Delete' if remove_process else 'Change'} OSPF process {process_id} on {where}",
                details={"before": before, "after": after},
                fingerprint={"process": proc and editable(proc), "others": [p.get("id") for p in procs]},
                blockers=blockers,
                side_effects=["Takes effect on the device after the next deployment."],
            ),
            apply=apply,
        )

    @reg.write(title="Create VRF")
    async def fmc_create_vrf(
        ctx: Context,
        device: DeviceRef,
        name: Annotated[str, Field(description="Virtual router name", min_length=1, max_length=48)],
        interfaces: Annotated[
            list[str] | None,
            Field(description="Named interfaces to move into the VRF (logical or hardware name, or UUID)"),
        ] = None,
        description: Annotated[str | None, Field(description="Optional description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a user-defined virtual router (VRF) on an FTD and move interfaces into it. Those
        interfaces leave the global routing table: routes, BGP and OSPF for them then live in the VRF
        (virtual_router=... on the routing tools). Deploy to apply. Remove with fmc_delete_vrf."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        root = f"{(await routing_base(app, dev, None, domain))[0]}"
        vrs = await _items(app, f"{root}/virtualrouters", domain)
        blockers: list[str] = []
        if any(str(v.get("name", "")).lower() == name.lower() for v in vrs):
            blockers.append(f"{dev.get('name')} already has a virtual router named {name!r}.")
        refs: list[dict[str, Any]] = []
        if interfaces:
            items = await device_interfaces(app, dev["id"], domain)
            taken = {
                str(i.get("id")): str(v.get("name"))
                for v in vrs
                for i in v.get("interfaces") or []
                if str(v.get("name", "")).lower() != "global"
            }
            for ref in interfaces:
                _, iface = pick_interface(items, ref, str(dev.get("name")))
                if not iface.get("ifname"):
                    blockers.append(
                        f"{iface.get('name')} has no logical name; name it first (fmc_update_interface)."
                    )
                if str(iface.get("id")) in taken:
                    blockers.append(f"{iface.get('name')} is already in VRF {taken[str(iface['id'])]}.")
                refs.append({"id": iface["id"], "type": iface.get("type"), "name": iface.get("name")})
        body: dict[str, Any] = {"type": "VirtualRouter", "name": name, "interfaces": refs}
        if description:
            body["description"] = description
        path = await app.config_path(f"{root}/virtualrouters", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_create_vrf",
            args={
                "device": device,
                "name": name,
                "interfaces": interfaces,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create VRF {name!r} on {dev.get('name')}",
                details={"body": body},
                fingerprint={"vrs": [editable(v) for v in vrs]},
                blockers=blockers,
                side_effects=[
                    "The interfaces leave the global routing table on the next deployment; "
                    "routes that use them must be recreated in the VRF."
                ]
                if refs
                else ["Takes effect on the device after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.post(path, body)),
        )

    @reg.write(title="Delete VRF", destructive=True)
    async def fmc_delete_vrf(
        ctx: Context,
        device: DeviceRef,
        name: Annotated[str, Field(description="Virtual router name or UUID")],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a user-defined virtual router; its interfaces return to the global table and its
        routes and routing processes are removed. Deploy to apply."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        root = (await routing_base(app, dev, None, domain))[0]
        vrs = await _items(app, f"{root}/virtualrouters", domain)
        vr = next(
            (
                v
                for v in vrs
                if name.strip().lower() in (str(v.get("name", "")).lower(), str(v.get("id")).lower())
            ),
            None,
        )
        if vr is None:
            raise NotFound(f"No virtual router {name!r} on {dev.get('name')}.", 404)
        blockers = (
            ["The global table can't be deleted."] if str(vr.get("name", "")).lower() == "global" else []
        )
        path = await app.config_path(f"{root}/virtualrouters/{vr['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_vrf",
            args={"device": device, "name": name, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Delete VRF {vr.get('name')!r} on {dev.get('name')}",
                details={"vrf": {"name": vr.get("name"), "interfaces": _names(vr.get("interfaces"))}},
                fingerprint=editable(vr),
                blockers=blockers,
                side_effects=["Takes effect on the device after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )

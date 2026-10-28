"""Dynamic routing on FTDs (F6): one readable view of BGP, OSPF, ECMP, PBR, BFD and VRFs, plus
preview-first edits for the common cases (BGP neighbors and networks, OSPF areas, VRFs) and, since F77,
route policy on them (neighbor route maps and prefix lists, maximum prefix, default-originate,
redistribution; the objects themselves are in route_policy). Application routes, ECMP zones and WAN
interface settings are in app_routing.

FMC's BGP and OSPF models are large nested objects that FMC replaces as a whole on PUT; these tools
read the current object, change only the requested parts and send it back. Changes reach the device
after fmc_deploy; check with fmc_run_show_command('show route') and the peer's CLI.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import copy
import ipaddress
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ToolRegistrar,
    UpstreamError,
    get_client,
)
from fmc_mcp._core.formatting import MASK, is_secret_key
from fmc_mcp._core.secrets import scrub_text
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import NETWORK_TYPES, RefResolver
from fmc_mcp.tools.app_routing import pbr_summary, wan_interfaces
from fmc_mcp.tools.bfd import FALL_OVER, BfdMode, neighbor_bfd_warnings
from fmc_mcp.tools.common import Domain, ref_label, ref_of
from fmc_mcp.tools.device_config import (
    device_interfaces,
    network_by_value,
    pick_interface,
    resolve_device,
    routing_base,
)
from fmc_mcp.tools.devices import DeviceRef
from fmc_mcp.tools.eigrp import eigrp_summary
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.route_policy import (
    NeighborFilters,
    PolicyRefs,
    Redistribution,
    apply_filters,
    apply_redistribution,
    fill_names,
    missing_filters,
    neighbor_diff,
    neighbor_filters,
    redistribution_row,
    resolve_filters,
)

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


# The create path's second step (F77-6): FMC 10.0.1 answers OK to a BGP create whose new neighbour has
# default-originate (with its route map) and stores neighborFiltering {}; an update keeps it.
FILTER_STEP = "update bgp: neighbor filters FMC left out of the create"
NEW_MODEL = "<id of the new BGP model>"

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
        **neighbor_filters(n),  # route maps, prefix lists, max prefix: only keys that are set
    }


def af_summary(af: dict[str, Any] | None) -> dict[str, Any] | None:
    if not af:
        return None
    out = {
        "neighbors": [neighbor_row(n) for n in af.get("neighbors") or []],
        "networks": _names(af.get("networks")),
        "redistribute": [str(r.get("type")) for r in af.get("redistributeProtocols") or []] or None,
        "maximum_paths": [m.get("value") for m in af.get("maximumPaths") or []] or None,
        "default_originate": af.get("defaultInformationOrginate") or None,
    }
    if af.get("redistributeProtocols"):  # F77: route map, metric, process per source
        out["redistribution"] = [redistribution_row(r) for r in af["redistributeProtocols"]]
    return out


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
        **(
            {"redistribution": [redistribution_row(r) for r in p["redistributeProtocols"]]}
            if p.get("redistributeProtocols")
            else {}
        ),
    }


OSPF_STEPS = {"POST": "create ospf process", "PUT": "update ospf process", "DELETE": "delete ospf process"}


# Routing secrets in FMC 10.0.1's BGP and OSPF bodies: a BGP neighbor's MD5 password, OSPF MD5 keys and
# passwords (areas, virtual links, interfaces). Masked in a preview body whatever their value.
ROUTING_SECRETS = frozenset({"neighborSecret", "md5Key", "authKey", "passwdAuth"})


def _mask_every_leaf(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _mask_every_leaf(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_mask_every_leaf(x) for x in v]
    return v if v is None or v == "" else MASK


def mask_body(v: Any) -> Any:
    """A request body as a preview shows it: every value under a secret-named field (ROUTING_SECRETS or
    one core's SECRET_KEY_RE matches) masked, even one that looks like a flag. Core's mask_secrets leaves
    'on', 'off', 'true', 'yes', ... in clear, but a BGP password 'on' is still a password
    (CORE-REQUESTS.md). Nothing else changes."""
    if isinstance(v, list):
        return [mask_body(x) for x in v]
    if not isinstance(v, dict):
        return v
    return {
        k: _mask_every_leaf(x) if k in ROUTING_SECRETS or is_secret_key(str(k)) else mask_body(x)
        for k, x in v.items()
    }


def requests_shown(steps: list[tuple[str, str, str, dict[str, Any] | None]]) -> list[dict[str, Any]]:
    """The requests a confirm sends, in order, as the preview shows them: method, path and body, with
    secrets (a BGP neighbor's MD5 password, OSPF keys) masked whatever their value. The bodies are what
    goes on the wire, so a change can be checked or repeated by hand (W6N live-B rebuilt them from the
    code for a preview-parity run)."""
    out = []
    for name, method, path, body in steps:
        row: dict[str, Any] = {"step": name, "method": method, "path": path}
        if body is not None:
            row["body"] = mask_body(body)
        out.append(row)
    return out


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


def created_body(steps: list[tuple[str, str, str, dict[str, Any] | None]]) -> dict[str, Any]:
    """The body of the plan's "create bgp" step ({} without one)."""
    return next((b or {} for name, _m, _p, b in steps if name == "create bgp"), {})


def sent_filters(model: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """{neighbour address: neighborFiltering} of the neighbours a BGP body sends with filters."""
    return {
        str(n.get("ipv4Address")): dict(n["neighborFiltering"])
        for n in (model.get("addressFamilyIPv4") or {}).get("neighbors") or []
        if n.get("neighborFiltering")
    }


def _stored_neighbors(model: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    return {
        str(n.get("ipv4Address")): n
        for n in ((model or {}).get("addressFamilyIPv4") or {}).get("neighbors") or []
    }


def not_kept(stored: dict[str, Any] | None, sent: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    """{address: neighborFiltering keys} FMC's re-read model lacks (a neighbour that is missing
    altogether: every key it was sent with)."""
    have = _stored_neighbors(stored)
    out: dict[str, list[str]] = {}
    for addr, nf in sent.items():
        keys = missing_filters(nf, (have.get(addr) or {}).get("neighborFiltering"))
        if keys:
            out[addr] = keys
    return out


def filter_repair(
    stored: dict[str, Any], sent: dict[str, Any], missing: dict[str, list[str]]
) -> tuple[dict[str, Any], list[str]]:
    """The update that puts missing neighbour filters back: FMC's stored model (everything else sent back
    as stored; maximumPaths left out, as on every BGP update) with each listed neighbour's missing
    neighborFiltering keys taken from the create body. FMC returns MD5 passwords masked (or may leave them
    out), and a PUT with the mask sets the mask as the password while one without it removes
    authentication, so the password the call gave goes back in whenever the stored one is masked or
    absent; the second value lists the neighbours with a masked password the call didn't give (an update
    would replace it)."""
    body = copy.deepcopy(editable(stored))
    af = body.get("addressFamilyIPv4") or {}
    af.pop("maximumPaths", None)
    mine = _stored_neighbors(sent)
    unsafe: list[str] = []
    for n in af.get("neighbors") or []:
        addr = str(n.get("ipv4Address"))
        asked = mine.get(addr) or {}
        if addr in missing:
            nf = dict(n.get("neighborFiltering") or {})
            for k in missing[addr]:
                nf[k] = copy.deepcopy(asked["neighborFiltering"][k])
            n["neighborFiltering"] = nf
        secret = (n.get("neighborAdvanced") or {}).get("neighborSecret")
        masked = bool(secret) and set(str(secret)) == {"*"}
        given = (asked.get("neighborAdvanced") or {}).get("neighborSecret")
        if given and (masked or not secret):
            n["neighborAdvanced"] = {**(n.get("neighborAdvanced") or {}), "neighborSecret": given}
        elif masked:
            unsafe.append(addr)
    return body, unsafe


async def keep_filters(
    app: FmcApp,
    created: Any,
    sent: dict[str, Any],
    bgp_path: str,
    list_path: str,
    domain: str | None,
) -> dict[str, Any]:
    """F77-6, after a BGP create (POST) whose new neighbour has filters: re-read the new model; when a
    sent filter is missing (FMC 10.0.1 leaves default-originate out of a create), send it again in one
    update (PUT) and re-read once more. Returns `stored: True` when the update made FMC keep them, plus
    `verified`, or `not_stored` (readable, per neighbour) and a plain `warning`. Never raises: the create
    has already been applied, so anything that goes wrong in the check (a re-read FMC answers in another
    shape, ...) is a "Not verified" warning next to it."""
    progress = {"update": ""}  # "sending" while the PUT is out, "answered" once FMC answered OK
    try:
        return await _keep_filters(app, created, sent, bgp_path, list_path, domain, progress)
    except Exception as e:  # noqa: BLE001 - the create is applied; report, don't fail the call
        why = f"{type(e).__name__}: {scrub_text(str(e))[:200]}"
        update = {
            "sending": " An update sending the filters again had been started (its outcome is unknown).",
            "answered": " An update had sent the filters again (answered OK) before that.",
        }.get(progress["update"], "")
        return {
            "warning": f"Not verified: checking the new BGP model's neighbor filters after the create failed "
            f"({why}).{update} FMC 10.0.1 can leave a neighbor's default-originate out of a create: check "
            "the neighbor with fmc_get_routing."
        }


async def _keep_filters(
    app: FmcApp,
    created: Any,
    sent: dict[str, Any],
    bgp_path: str,
    list_path: str,
    domain: str | None,
    progress: dict[str, str],
) -> dict[str, Any]:
    filters = sent_filters(sent)

    async def reread(model_id: Any) -> dict[str, Any] | None:
        if model_id:
            got = await app.api.get(f"{bgp_path}/{model_id}")
            return got if isinstance(got, dict) else None
        return next(iter(await _items(app, list_path, domain)), None)

    def shown(missing: dict[str, list[str]]) -> list[dict[str, Any]]:
        return [
            {
                "neighbor": addr,
                "filters": neighbor_filters({"neighborFiltering": {k: filters[addr][k] for k in keys}}),
            }
            for addr, keys in missing.items()
        ]

    def named(missing: dict[str, list[str]]) -> str:
        return "; ".join(f"{r['neighbor']}: {', '.join(r['filters'])}" for r in shown(missing))

    def lost(missing: dict[str, list[str]], why: str) -> dict[str, Any]:
        return {
            "not_stored": shown(missing),
            "warning": f"FMC answered OK but didn't store these neighbor filters ({named(missing)}) {why}: "
            "a deploy won't put them on the device. The rest of BGP was created. Check with "
            "fmc_get_routing, then repeat the call for that neighbor (now an update) or set them in the "
            "FMC UI.",
        }

    created_id = created.get("id") if isinstance(created, dict) else None
    try:
        stored = await reread(created_id)
    except (UpstreamError, InvalidRequest) as e:
        return {
            "warning": f"Not verified: re-reading the new BGP model failed ({e}). FMC 10.0.1 can leave a "
            "neighbor's default-originate out of a create: check the neighbor with fmc_get_routing."
        }
    missing = not_kept(stored, filters)
    if not missing:
        return {"verified": "re-read after the create: the neighbor filters are stored as sent"}
    if stored is None or not stored.get("id"):
        return {
            "warning": "Not verified: the re-read after the create found no BGP model, so the neighbor "
            f"filters ({named(missing)}) couldn't be checked or sent again. FMC 10.0.1 can leave a "
            "neighbor's default-originate out of a create: check the neighbor with fmc_get_routing."
        }
    gone = [a for a in missing if a not in _stored_neighbors(stored)]
    if gone:
        return lost(missing, f"in the create, and the re-read has no neighbor {', '.join(gone)} to update")
    body, unsafe = filter_repair(stored, sent, missing)
    if unsafe:
        return lost(
            missing,
            f"in the create; not sent again because neighbor {', '.join(unsafe)} has an MD5 password FMC "
            "only returns masked (an update would replace it)",
        )
    progress["update"] = "sending"
    try:
        await app.api.put(f"{bgp_path}/{stored['id']}", body)
    except (UpstreamError, InvalidRequest) as e:
        return lost(missing, f"in the create, and the update that sent them again failed ({e})")
    progress["update"] = "answered"
    try:
        again = await reread(stored["id"])
    except (UpstreamError, InvalidRequest) as e:
        return {
            "warning": f"FMC left these neighbor filters out of the create ({named(missing)}); an update "
            f"sent them again (answered OK), but re-reading it failed ({e}), so it isn't verified: check "
            "with fmc_get_routing."
        }
    still = not_kept(again, filters)
    if still:
        return lost(still, "in the create, nor in the update that sent them again (both answered OK)")
    return {
        "stored": True,
        "verified": f"FMC 10.0.1 left these neighbor filters out of the create ({named(missing)}); the "
        "update sent them again and the re-read shows them stored",
    }


# --- tools ---------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Get device routing")
    async def fmc_get_routing(
        ctx: Context, device: DeviceRef, virtual_router: VrfParam = None, domain: Domain = None
    ) -> dict[str, Any]:
        """One view of the dynamic routing FMC holds for a device (or one VRF): BGP (AS, router id,
        neighbors with remote AS/state/BFD and their route maps, prefix lists, maximum prefix and
        default-originate, advertised networks, redistribution with route map and metric, per address
        family), OSPFv2 processes (areas, networks, redistribution), EIGRP (AS, networks, passive and
        per-interface timers/MD5 key ids (keys never shown), static neighbors, summaries, redistribution
        with route map and metric, stub), OSPF interface settings, ECMP zones,
        policy-based routes (application routes: match, egress interfaces and how one is picked), WAN
        interfaces (priority, path monitoring, HTTP application monitoring), BFD policies, VRFs and
        the static route count. Configuration, not the
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
        eigrp = await _items(app, f"{base}/eigrproutes", domain)
        await fill_names(PolicyRefs(app, domain), bgp, ospf, eigrp)  # route-map / prefix-list names
        out: dict[str, Any] = {
            "device": dev.get("name"),
            "table": vr_name or "global",
            "bgp": bgp_summary(general, bgp),
            "ospfv2": [ospf_summary(p) for p in ospf] or None,
            "eigrp": [eigrp_summary(p) for p in eigrp] or None,
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
            out["policy_based_routes"] = [
                pbr_summary(p) for p in await _items(app, f"{root}/policybasedroutes", domain)
            ] or None
            out["wan_interfaces"] = await wan_interfaces(app, dev["id"], domain) or None
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
        neighbor_route_map_in: Annotated[
            str | None,
            Field(description="Route map (name/UUID) on routes received from `neighbor`; 'none' removes it"),
        ] = None,
        neighbor_route_map_out: Annotated[
            str | None,
            Field(description="Route map (name/UUID) on routes sent to `neighbor`; 'none' removes it"),
        ] = None,
        neighbor_prefix_list_in: Annotated[
            str | None,
            Field(
                description="IPv4 prefix list (name/UUID) on routes received from `neighbor`; 'none' "
                "removes it"
            ),
        ] = None,
        neighbor_prefix_list_out: Annotated[
            str | None,
            Field(description="IPv4 prefix list (name/UUID) on routes sent to `neighbor`; 'none' removes it"),
        ] = None,
        max_prefix: Annotated[
            int | None,
            Field(
                ge=0,
                le=2147483647,
                description="Most prefixes `neighbor` may send: past it the session is torn down (warning at "
                "75%); 0 removes the limit",
            ),
        ] = None,
        max_prefix_warning_only: Annotated[
            bool | None,
            Field(description="With max_prefix: only log past the limit instead of tearing the session down"),
        ] = None,
        default_originate: Annotated[
            bool | None,
            Field(
                description="Send `neighbor` a default route (neighbor default-originate) with "
                "default_originate_route_map (FMC 10.0.1 keeps it only with a route map); false stops it"
            ),
        ] = None,
        default_originate_route_map: Annotated[
            str | None,
            Field(
                description="Route map (name/UUID) for default_originate: the default route is sent while it "
                "matches (one permit entry with no match = always); turns default-originate on"
            ),
        ] = None,
        bfd: Annotated[
            BfdMode | None,
            Field(
                description="Fall-over BFD on `neighbor`: single_hop (directly connected peer, with a "
                "single-hop BFD policy on the interface: fmc_configure_bfd), multi_hop (loopback peering), "
                "auto (FMC detects the hop type) or none (off)"
            ),
        ] = None,
        redistribute: Annotated[
            list[Redistribution] | None,
            Field(
                description="Redistribute into BGP, e.g. [{'protocol': 'connected', 'route_map': 'rm', "
                "'metric': 10}] (ospf needs process_id); [{'protocol': 'static', 'remove': true}] stops one. "
                "Sources not named are kept"
            ),
        ] = None,
        virtual_router: VrfParam = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Edit BGP (IPv4 unicast) on an FTD: add, change or remove a neighbor (remote AS, MD5
        password), and advertise or withdraw networks (network objects). Sets up BGP first (local AS,
        router id) when the device has none; the AS and router id are device-wide, so a VRF uses them
        too. remove_bgp deletes the whole BGP configuration. The preview shows the
        neighbor and network lists before and after, and each request it sends (`requests`: method, path,
        body; an MD5 password masked). Deploy to apply; verify with
        fmc_run_show_command('show route') and the peer ('show bgp summary').
        `bfd` sets fall-over BFD; the preview warns without a matching BFD policy (fmc_configure_bfd).

        Route policy on a neighbor (F77): inbound/outbound route maps and prefix lists (objects from
        fmc_create_route_map / fmc_create_prefix_list), a maximum-prefix limit and default-originate
        (with a route map: FMC 10.0.1 drops it without one, and leaves it out of a BGP create: on a device
        without BGP the server re-reads the new model and sends a missing neighbor filter again in an
        update; the result names any FMC still didn't keep);
        redistribution of connected, static or OSPF routes into BGP with a route map and metric. FMC
        replaces the whole BGP model on every change, so only the named neighbor and sources change and
        the preview shows just that diff. Check with fmc_get_routing, then after the deploy
        fmc_run_show_command('show route bgp') here and the peer's BGP table for outbound filters."""
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
        filters = NeighborFilters(
            route_map_in=neighbor_route_map_in,
            route_map_out=neighbor_route_map_out,
            prefix_list_in=neighbor_prefix_list_in,
            prefix_list_out=neighbor_prefix_list_out,
            max_prefix=max_prefix,
            max_prefix_warning_only=max_prefix_warning_only,
            default_originate=default_originate,
            default_originate_route_map=default_originate_route_map,
        )
        policy = filters.given() or bool(redistribute)  # F77 route policy in this call
        refs = PolicyRefs(app, domain)
        resolved: dict[str, Any] = {}
        touched: tuple[dict[str, Any] | None, str] | None = None  # (neighbor before, its address)
        redist_diff: dict[str, Any] = {}

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
                    policy,
                    bfd,
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
            view: dict[str, Any] = {"before": before, "after": after}
        else:
            if filters.given() and (not neighbor or remove_neighbor):
                raise InvalidRequest(
                    "neighbor_route_map_*, neighbor_prefix_list_*, max_prefix and default_originate* "
                    "apply to `neighbor` (added or kept, not removed)."
                )
            if not any((neighbor, advertise, withdraw, redistribute)):
                raise InvalidRequest(
                    "Give a neighbor, networks to advertise/withdraw, redistribute, or remove_bgp."
                )
            if remove_neighbor and not neighbor:
                raise InvalidRequest("remove_neighbor needs the neighbor address.")
            if bfd is not None and (not neighbor or remove_neighbor):
                raise InvalidRequest("bfd applies to `neighbor` (added or kept, not removed).")
            if filters.given():
                resolved = await resolve_filters(refs, filters)
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
                        if bfd is not None:
                            n["neighborGeneral"]["fallOverBFD"] = FALL_OVER[bfd]
                        if filters.given():
                            n = apply_filters(n, filters, resolved)
                            touched = (None, addr)
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
                        if bfd is not None:
                            changed["neighborGeneral"] = {
                                **(changed.get("neighborGeneral") or {}),
                                "fallOverBFD": FALL_OVER[bfd],
                            }
                        if filters.given():
                            changed = apply_filters(changed, filters, resolved)
                            touched = (existing, addr)
                        if changed == existing and not redistribute:
                            # with redistribute, the redistribution is the change (and blocks itself
                            # when it changes nothing)
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
            if redistribute:
                redist, redist_diff, more = await apply_redistribution(
                    list(af.get("redistributeProtocols") or []), redistribute, refs, target="bgp"
                )
                blockers += more
                if redist:
                    af["redistributeProtocols"] = redist
                else:
                    af.pop("redistributeProtocols", None)  # FMC leaves the key out when there are none
            af.pop("maximumPaths", None)  # FMC 10.0.1 echoes it on GET but rejects it on PUT (use ebgp/ibgp)
            af["neighbors"] = neighbors
            af["networks"] = networks
            desired["addressFamilyIPv4"] = af
            before = bgp_summary(general, bgp)
            after = {"neighbors": [neighbor_row(x) for x in neighbors], "networks": _names(networks)}
            view = {"before": before, "after": after}
            if policy:
                extra: dict[str, Any] = {}
                if touched is not None:
                    old, addr = touched
                    new: dict[str, Any] = next((x for x in neighbors if x.get("ipv4Address") == addr), {})
                    extra["neighbor_changes"] = {
                        "neighbor": addr,
                        "changes": neighbor_diff(old and neighbor_row(old), neighbor_row(new)),
                    }
                if redistribute:
                    extra["redistribute_changes"] = redist_diff
                classic = any(
                    (
                        remote_as,
                        remove_neighbor,
                        neighbor_description,
                        neighbor_password,
                        advertise,
                        withdraw,
                        local_as,
                        router_id,
                        bfd,
                    )
                ) or bool(touched and touched[0] is None)
                if classic:
                    view.update(extra)
                else:  # only route policy: show the touched neighbor/sources, not the whole model
                    view = {
                        **extra,
                        "unchanged": {
                            "other_neighbors": len(neighbors) - (1 if touched else 0),
                            "networks": len(networks),
                        },
                    }
            if bfd in ("single_hop", "multi_hop") and neighbor and not blockers:
                bfd_warnings = await neighbor_bfd_warnings(
                    app, dev, base, str(ipaddress.IPv4Address(neighbor.strip())), bfd, domain
                )
                if bfd_warnings:
                    view["bfd_warnings"] = bfd_warnings
            if bgp:
                steps.append(("update bgp", "PUT", f"{bgp_path}/{bgp['id']}", desired))
            else:
                steps.append(("create bgp", "POST", bgp_path, desired))
                if sent_filters(desired):  # F77-6: checked after the create, sent again if FMC left them out
                    steps.append((FILTER_STEP, "PUT", f"{bgp_path}/{NEW_MODEL}", None))

        async def apply() -> Any:
            done: list[str] = []
            check: dict[str, Any] = {}
            created: Any = None
            try:
                for name, method, path, body in steps:
                    if name == FILTER_STEP:
                        check = await keep_filters(
                            app, created, created_body(steps), bgp_path, f"{base}/bgp", domain
                        )
                        if check.pop("stored", False):
                            done.append(name)
                        continue
                    try:
                        if method == "DELETE":
                            await app.api.delete(path)
                        elif method == "POST":
                            answer = await app.api.post(path, body)
                            if name == "create bgp":
                                created = answer
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
            return {
                "applied": done,
                **check,
                "next": "fmc_deploy, then check 'show route' on the device",
            }

        shown = requests_shown(steps)
        for row in shown:
            if row["step"] == FILTER_STEP:
                row["only_if"] = (
                    "the re-read of the new model after the create (one GET) lacks a neighbor filter "
                    "sent in it; one more GET then checks the update"
                )
                row["sends"] = {
                    "model": "FMC's re-read of the new model (maximumPaths left out, as on every BGP update)",
                    "with": [
                        {"neighbor": addr, "neighborFiltering": mask_body(nf)}
                        for addr, nf in sent_filters(created_body(steps)).items()
                    ],
                }

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
                "neighbor_route_map_in": neighbor_route_map_in,
                "neighbor_route_map_out": neighbor_route_map_out,
                "neighbor_prefix_list_in": neighbor_prefix_list_in,
                "neighbor_prefix_list_out": neighbor_prefix_list_out,
                "max_prefix": max_prefix,
                "max_prefix_warning_only": max_prefix_warning_only,
                "default_originate": default_originate,
                "default_originate_route_map": default_originate_route_map,
                "bfd": bfd,
                "redistribute": None if redistribute is None else [r.model_dump() for r in redistribute],
                "virtual_router": virtual_router,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"{'Remove' if remove_bgp else 'Change'} BGP on {where}",
                details={"steps": [s[0] for s in steps], **view} | ({} if blockers else {"requests": shown}),
                fingerprint={"general": general and editable(general), "bgp": bgp and editable(bgp)}
                | ({"policy": [resolved, [s[3] for s in steps]]} if policy else {}),
                blockers=blockers,
                side_effects=["Takes effect on the device after the next deployment."]
                + (
                    [
                        "FMC replaces the whole BGP model: the other neighbors, networks and settings are "
                        "sent back as they are."
                    ]
                    if policy
                    else []
                )
                + (
                    [
                        "FMC 10.0.1 answers OK to a BGP create but leaves a new neighbor's default-originate "
                        "out of it (an update keeps it): after the create the server re-reads the new model "
                        "and, if a neighbor filter it sent is missing, sends it again in one update and "
                        "re-reads once more. The result names any filter FMC still didn't keep."
                    ]
                    if any(st[0] == FILTER_STEP for st in steps)
                    else []
                ),
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
        redistribute: Annotated[
            list[Redistribution] | None,
            Field(
                description="Redistribute into this process, e.g. [{'protocol': 'connected', 'route_map': "
                "'rm', 'metric': 20}] (subnets on, metric type 2 unless given; bgp uses the device's AS, "
                "ospf needs process_id); [{'protocol': 'static', 'remove': true}] stops one. Sources not "
                "named are kept"
            ),
        ] = None,
        virtual_router: VrfParam = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Edit OSPFv2 on an FTD: add or remove networks (network objects) in an area, creating the
        process and area when needed, or delete a whole process. Interfaces whose address falls in an
        area network run OSPF in that area. The preview shows the areas before and after, and the request
        it sends (`requests`: method, path, body; keys masked). Deploy to apply; verify with
        fmc_run_show_command('show route') (O routes) and the neighbor's CLI.

        Redistribution (F77): connected, static, BGP or another OSPF process into this one, with a
        route map (fmc_create_route_map) and metric; the preview shows only the sources that change.
        OSPFv2 on FTD has no passive interfaces in FMC's model (only OSPFv3 processes do): to announce
        a network without forming adjacencies on its interface, leave it out of the areas and
        redistribute connected with a route map matching it."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_device(app, device, domain)
        base, vr_name = await routing_base(app, dev, virtual_router, domain)
        where = f"{dev.get('name')} ({vr_name or 'global table'})"
        procs = await _items(app, f"{base}/ospfv2routes", domain)
        proc = next((p for p in procs if str(p.get("processId")) == str(process_id)), None)
        path = await app.config_path(f"{base}/ospfv2routes", domain)
        blockers: list[str] = []
        method, target, body = "PUT", "", None
        redist_diff: dict[str, Any] = {}
        if remove_process:
            if add_networks or remove_networks:
                raise InvalidRequest("remove_process can't be combined with network changes.")
            if redistribute:
                raise InvalidRequest("remove_process can't be combined with redistribute.")
            if proc is None:
                blockers.append(f"No OSPF process {process_id} on {where}.")
            method, target = "DELETE", f"{path}/{(proc or {}).get('id')}"
            after = None
        else:
            if not add_networks and not remove_networks and not redistribute:
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
            if add_networks or remove_networks:
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
                    blockers.append(
                        "That would leave the process with no networks; use remove_process instead."
                    )
                desired["areas"] = areas
            elif proc is None:
                blockers.append(
                    f"No OSPF process {process_id} on {where}: create it with add_networks first."
                )
            if redistribute:
                bgp_as = None
                if any(r.protocol == "bgp" for r in redistribute):
                    root = f"{base.split('/routing')[0]}/routing"
                    general = next(iter(await _items(app, f"{root}/bgpgeneralsettings", domain)), None)
                    bgp_as = (general or {}).get("asNumber")
                redist, redist_diff, more = await apply_redistribution(
                    list(desired.get("redistributeProtocols") or []),
                    redistribute,
                    PolicyRefs(app, domain),
                    target="ospf",
                    own_process=process_id,
                    bgp_as=bgp_as,
                )
                blockers += more
                if redist:
                    desired["redistributeProtocols"] = redist
                else:
                    desired.pop("redistributeProtocols", None)
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
                "redistribute": None if redistribute is None else [r.model_dump() for r in redistribute],
                "virtual_router": virtual_router,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"{'Delete' if remove_process else 'Change'} OSPF process {process_id} on {where}",
                details={"before": before, "after": after}
                | ({"redistribute_changes": redist_diff} if redistribute else {})
                | (
                    {}
                    if blockers
                    else {"requests": requests_shown([(OSPF_STEPS[method], method, target, body)])}
                ),
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

"""Native EIGRP on FTDs (F98): fmc_configure_eigrp creates, edits or removes the EIGRP process of a device
(or of one VRF), and eigrp_summary is fmc_get_routing's EIGRP section. Brownfield ASA/IOS sites that run
EIGRP to the core can be migrated without FlexConfig.

Shapes, FMC 10.0.1 OpenAPI (EigrpPolicyModel request/response examples for POST, PUT, GET and DELETE; the
lab FMC had no EIGRP process to record on 2026-10-28, its eigrproutes collections answered count 0, so
tests/fixtures/eigrp_fmc10.json is spec-shaped):
- devicerecords/{id}/routing/eigrproutes and routing/virtualrouters/{vr}/eigrproutes:
  {type EigrpRoute, asNumber (string), basicConfiguration{networks[ref], autoSummary,
  passiveInterfaces{selectedInterfaces[iface], allInterfaces}}, advancedConfiguration{routerId,
  logNeighborChanges, routeMetric (default metric), stub{receiveOnly | advertise{connected, static,
  summary, redistributed}}, administrativeDistance{internal, external}, defaultRouteDistributionIn/Out,
  clusterPool}, eigrpInterfaces[{deviceInterface, eigrpProtocolConfiguration{timers{helloInterval,
  holdTime, delay}, splitHorizon, authentication{md5auth, keyId, password, pwdEncryption}}}],
  neighbors[{neighborInterface, neighborAddress(ref)}], summaryAddressList[{deviceInterface,
  summaryAddress(ref), adminDistance}], redistributeProtocols[{protocol CONNECTED|STATIC|OSPF|BGP|RIP,
  processId (OSPF process / BGP AS), routeMap(ref), routeMetric{bandwidth, delay, reliability,
  effectiveBandwidth, pathMTU}, matchInternal, ...}], distributionList[...]}.
- FMC returns interface MD5 passwords masked ('*****'); a PUT with the mask would set the mask as the key.

Keys never pass through MCP: an interface's MD5 key is read on the server from a one-line file in
FMC_PKI_DIR (`key_file`), like fmc_create_cert_enrollment's passphrase_file, and is masked in every
preview and log line.
"""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import copy
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import BaseModel, ConfigDict, Field

from fmc_mcp._core import Confirm, InvalidRequest, Plan, ToolRegistrar, get_client, get_settings
from fmc_mcp._core.formatting import MASK
from fmc_mcp._core.secrets import register_secret
from fmc_mcp._core.writes import field_changes
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, ref_label
from fmc_mcp.tools.device_config import device_interfaces, pick_interface, resolve_device, routing_base
from fmc_mcp.tools.devices import DeviceRef
from fmc_mcp.tools.object_writes import applied, editable
from fmc_mcp.tools.pki import pki_path
from fmc_mcp.tools.route_policy import NONE, PolicyRefs

KEY_FILE_OFF = (
    "EIGRP keys are read from files in FMC_PKI_DIR (key_file), so they never pass through MCP: set "
    "FMC_PKI_DIR on the server and put the key there as a one-line file."
)
STEPS = {"POST": "create eigrp process", "PUT": "update eigrp process", "DELETE": "delete eigrp process"}
PROTOCOLS = {"connected": "CONNECTED", "static": "STATIC", "ospf": "OSPF", "bgp": "BGP"}
PROTOCOL_NAMES = {v: k for k, v in PROTOCOLS.items()} | {"RIP": "rip"}
METRIC_FIELDS = {
    "bandwidth": "bandwidth",
    "delay": "delay",
    "reliability": "reliability",
    "load": "effectiveBandwidth",
    "mtu": "pathMTU",
}
StubMode = Literal["receive_only", "connected", "static", "summary", "redistributed", "none"]


# --- arguments ------------------------------------------------------------------------------------


class EigrpInterface(BaseModel):
    """Per-interface EIGRP settings: passive, timers, split horizon and MD5 authentication."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Interface (logical name, hardware name or UUID)")
    passive: bool | None = Field(None, description="True: no hellos or adjacencies on it (still advertised)")
    hello: int | None = Field(None, ge=1, le=65535, description="Hello interval, seconds (FTD default 5)")
    hold: int | None = Field(None, ge=1, le=65535, description="Hold time, seconds (FTD default 15)")
    delay: int | None = Field(None, ge=1, le=16777215, description="Interface delay, tens of microseconds")
    split_horizon: bool | None = Field(None, description="Split horizon (FTD default on)")
    key_id: int | None = Field(None, ge=0, le=255, description="MD5 key id (with key_file; default 1)")
    key_file: str | None = Field(
        None,
        description="File in FMC_PKI_DIR on the MCP server holding the MD5 key (one line, read there and "
        "sent to FMC only). Required again to edit EIGRP when the interface already has a key",
    )
    no_auth: bool = Field(False, description="Remove MD5 authentication from the interface")
    remove: bool = Field(False, description="Drop this interface's EIGRP settings (and passive)")


class EigrpNeighbor(BaseModel):
    """A static EIGRP neighbour (unicast hellos), e.g. across a link that drops multicast."""

    model_config = ConfigDict(extra="forbid")

    address: str = Field(description="Host object name/UUID, or an IPv4 address an existing host object has")
    interface: str = Field(description="Interface the neighbour is reached through")
    remove: bool = Field(False, description="Remove this neighbour")


class EigrpRedistribution(BaseModel):
    """Routes from another source to redistribute into EIGRP (or stop, remove=true)."""

    model_config = ConfigDict(extra="forbid")

    protocol: Literal["connected", "static", "ospf", "bgp"] = Field(description="Source of the routes")
    process_id: int | None = Field(None, ge=1, le=65535, description="Source OSPF process (protocol='ospf')")
    route_map: str | None = Field(None, description="Route map (name/UUID, fmc_create_route_map)")
    bandwidth: int | None = Field(None, ge=1, le=4294967295, description="Metric bandwidth, kbit/s")
    delay: int | None = Field(None, ge=0, le=4294967295, description="Metric delay, tens of microseconds")
    reliability: int | None = Field(None, ge=0, le=255, description="Metric reliability (255 = 100%)")
    load: int | None = Field(None, ge=1, le=255, description="Metric effective bandwidth / load (1-255)")
    mtu: int | None = Field(None, ge=1, le=65535, description="Metric path MTU")
    remove: bool = Field(False, description="Stop redistributing this source")


class EigrpSummary(BaseModel):
    """An interface summary address (`summary-address eigrp` on the interface)."""

    model_config = ConfigDict(extra="forbid")

    network: str = Field(description="Network object name/UUID, or a CIDR an existing object has")
    interface: str = Field(description="Interface the summary is advertised out of")
    admin_distance: int | None = Field(None, ge=1, le=255, description="Administrative distance (default 5)")
    remove: bool = Field(False, description="Remove this summary")


# --- helpers --------------------------------------------------------------------------------------


def is_masked(secret: Any) -> bool:
    return bool(secret) and set(str(secret)) == {"*"}


def _label(r: Any) -> str | None:
    return ref_label(r) if isinstance(r, dict) else None


def _iface_label(r: Any) -> str | None:
    if not isinstance(r, dict):
        return None
    return str(r.get("ifname") or r.get("name") or r.get("id"))


def _nets(refs: Any) -> list[str]:
    return [str(_label(r)) for r in refs or [] if isinstance(r, dict)]


def metric_row(m: dict[str, Any] | None) -> dict[str, Any] | None:
    if not m:
        return None
    out = {k: m[f] for k, f in METRIC_FIELDS.items() if m.get(f) is not None}
    return out or None


def redistribution_row(r: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {"protocol": PROTOCOL_NAMES.get(str(r.get("protocol")), str(r.get("protocol")))}
    if r.get("processId") not in (None, ""):
        row["process" if r.get("protocol") == "OSPF" else "as"] = r["processId"]
    if r.get("routeMap"):
        row["route_map"] = _label(r["routeMap"])
    metric = metric_row(r.get("routeMetric"))
    if metric:
        row["metric"] = metric
    return row


def stub_row(adv: dict[str, Any]) -> list[str] | None:
    stub = adv.get("stub") or {}
    if stub.get("receiveOnly"):
        return ["receive_only"]
    out = [
        k for k in ("connected", "static", "summary", "redistributed") if (stub.get("advertise") or {}).get(k)
    ]
    return out or None


def interface_row(i: dict[str, Any], passive: set[str]) -> dict[str, Any]:
    conf = i.get("eigrpProtocolConfiguration") or {}
    timers = conf.get("timers") or {}
    auth = conf.get("authentication") or {}
    dev_if = i.get("deviceInterface") or {}
    row: dict[str, Any] = {"interface": _iface_label(dev_if)}
    for k, f in (("hello", "helloInterval"), ("hold", "holdTime"), ("delay", "delay")):
        if timers.get(f) is not None:
            row[k] = timers[f]
    if conf.get("splitHorizon") is not None:
        row["split_horizon"] = conf["splitHorizon"]
    if auth.get("md5auth"):
        row["md5"] = {"key_id": auth.get("keyId"), "key_set": bool(auth.get("password"))}
    if str(dev_if.get("id")) in passive:
        row["passive"] = True
    return row


def eigrp_summary(p: dict[str, Any]) -> dict[str, Any]:
    """One EIGRP process, readable (keys never shown: md5.key_set says whether one is stored)."""
    basic = p.get("basicConfiguration") or {}
    adv = p.get("advancedConfiguration") or {}
    pas = basic.get("passiveInterfaces") or {}
    passive_ids = {str(x.get("id")) for x in pas.get("selectedInterfaces") or []}
    out: dict[str, Any] = {
        "as": p.get("asNumber"),
        "router_id": adv.get("routerId"),
        "networks": _nets(basic.get("networks")),
        "auto_summary": basic.get("autoSummary"),
        "passive_interfaces": "all"
        if pas.get("allInterfaces")
        else [_iface_label(x) for x in pas.get("selectedInterfaces") or []] or None,
        "interfaces": [interface_row(i, passive_ids) for i in p.get("eigrpInterfaces") or []] or None,
        "neighbors": [
            {
                "address": _label(n.get("neighborAddress")),
                "interface": _iface_label(n.get("neighborInterface")),
            }
            for n in p.get("neighbors") or []
        ]
        or None,
        "summary_addresses": [
            {
                "network": _label(s.get("summaryAddress")),
                "interface": _iface_label(s.get("deviceInterface")),
                **({"admin_distance": s["adminDistance"]} if s.get("adminDistance") is not None else {}),
            }
            for s in p.get("summaryAddressList") or []
        ]
        or None,
        "redistribution": [redistribution_row(r) for r in p.get("redistributeProtocols") or []] or None,
        "default_metric": metric_row(adv.get("routeMetric")),
        "stub": stub_row(adv),
        "distribution_lists": len(p.get("distributionList") or []) or None,
        "id": p.get("id"),
    }
    return {k: v for k, v in out.items() if v is not None}


def mask_body(v: Any) -> Any:
    """A request body as the preview shows it: every authentication password masked."""
    if isinstance(v, list):
        return [mask_body(x) for x in v]
    if not isinstance(v, dict):
        return v
    return {k: (MASK if k == "password" and x else mask_body(x)) for k, x in v.items()}


def read_key(pki_dir: Any, name: str) -> tuple[str, tuple[int, int, int, int]]:
    """The MD5 key in a one-line file inside FMC_PKI_DIR, registered as a secret, plus the file's stat
    (for the preview fingerprint: a confirm is refused when the file changed)."""
    path, st = pki_path(pki_dir, name, "key_file", KEY_FILE_OFF)
    try:
        value = path.read_bytes().decode("utf-8").strip("\r\n")
    except (OSError, UnicodeDecodeError):
        raise InvalidRequest(f"key_file {name!r} is not a readable UTF-8 text file.") from None
    if not value or "\n" in value:
        raise InvalidRequest(f"key_file {name!r} must hold the key on one line.")
    if len(value) > 16:
        raise InvalidRequest(f"key_file {name!r}: an EIGRP MD5 key is at most 16 characters.")
    register_secret(value)
    return value, (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def _iref(i: dict[str, Any]) -> dict[str, Any]:
    out = {"id": i["id"], "type": i.get("type"), "name": i.get("name")}
    if i.get("ifname"):
        out["ifname"] = i["ifname"]
    return out


async def _object_ref(app: FmcApp, value: str, domain: str | None, what: str) -> dict[str, Any]:
    from fmc_mcp.tools.routing import network_refs  # routing imports this module for its read view

    try:
        return (await network_refs(app, [value], domain))[0]
    except InvalidRequest as e:
        raise InvalidRequest(f"{what}: {e}") from None


# --- tool -----------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Configure EIGRP")
    async def fmc_configure_eigrp(
        ctx: Context,
        device: DeviceRef,
        as_number: Annotated[
            int | None,
            Field(ge=1, le=65535, description="EIGRP AS; required to create the process, checked on edits"),
        ] = None,
        add_networks: Annotated[
            list[str] | None,
            Field(description="Network objects (name/UUID or a CIDR an object has) to run EIGRP on"),
        ] = None,
        remove_networks: Annotated[list[str] | None, Field(description="Networks to take out")] = None,
        interfaces: Annotated[
            list[EigrpInterface] | None,
            Field(
                description="Per-interface settings, e.g. [{'name': 'inside', 'hello': 5, 'hold': 15, "
                "'key_id': 1, 'key_file': 'eigrp-inside.key'}, {'name': 'dmz', 'passive': true}]"
            ),
        ] = None,
        neighbors: Annotated[
            list[EigrpNeighbor] | None,
            Field(description="Static neighbours: [{'address': '192.0.2.2', 'interface': 'inside'}]"),
        ] = None,
        redistribute: Annotated[
            list[EigrpRedistribution] | None,
            Field(
                description="Redistribute into EIGRP: [{'protocol': 'static', 'route_map': 'mcp-rm'}]; "
                "ospf/bgp need a metric (bandwidth, delay, reliability, load, mtu) or default_metric; "
                "[{'protocol': 'static', 'remove': true}] stops one; sources not named are kept"
            ),
        ] = None,
        summary_addresses: Annotated[
            list[EigrpSummary] | None,
            Field(description="Interface summaries: [{'network': '192.0.2.0/24', 'interface': 'outside'}]"),
        ] = None,
        router_id: Annotated[
            str | None, Field(description="Router id (IPv4); 'none' clears it (automatic)")
        ] = None,
        stub: Annotated[
            list[StubMode] | None,
            Field(
                description="Make this an EIGRP stub: ['connected', 'summary'] (the IOS default), "
                "['receive_only'], or ['none'] to stop being a stub"
            ),
        ] = None,
        default_metric: Annotated[
            EigrpRedistribution | None,
            Field(
                description="Default metric for redistributed routes: protocol is ignored, give bandwidth, "
                "delay, reliability, load, mtu"
            ),
        ] = None,
        log_neighbor_changes: Annotated[bool | None, Field(description="Log adjacency changes")] = None,
        passive_all: Annotated[
            bool | None,
            Field(
                description="True: every routable interface passive (passive-interface default; FMC keeps no "
                "per-interface exceptions, so selected passive interfaces are cleared); false: back to the "
                "interfaces marked passive in `interfaces`"
            ),
        ] = None,
        remove_process: Annotated[bool, Field(description="Delete the whole EIGRP process")] = False,
        virtual_router: Annotated[
            str | None, Field(description="Virtual router (VRF) name/UUID; default the global table")
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Native EIGRP on an FTD (no FlexConfig): create the process (AS + networks), or change its
        networks, per-interface settings (passive, hello/hold/delay, split horizon, MD5 key), static
        neighbours, redistribution (connected, static, OSPF, BGP with a route map from fmc_create_route_map
        and a metric), interface summary addresses, router id, stub and passive on all interfaces
        (passive_all); or delete it. One EIGRP process per
        device or VRF. Interfaces whose address falls in a network run EIGRP. MD5 keys only as key_file
        (a file in FMC_PKI_DIR on the server): they never pass through MCP and are masked in the preview.
        The preview shows the process before and after and the request it sends (`requests`). Deploy to
        apply; verify with fmc_run_show_command('show eigrp neighbors' / 'show route eigrp') and the
        peer's CLI. Read it back with fmc_get_routing."""
        app: FmcApp = get_client(ctx)
        settings = get_settings(ctx)
        dev = await resolve_device(app, device, domain)
        base, vr_name = await routing_base(app, dev, virtual_router, domain)
        where = f"{dev.get('name')} ({vr_name or 'global table'})"
        from fmc_mcp.tools.routing import _items, check_router_id

        procs = await _items(app, f"{base}/eigrproutes", domain)
        proc = procs[0] if procs else None
        path = await app.config_path(f"{base}/eigrproutes", domain)
        blockers: list[str] = []
        warnings: list[str] = []
        key_stats: dict[str, Any] = {}
        changes = any(
            x
            for x in (
                add_networks,
                remove_networks,
                interfaces,
                neighbors,
                redistribute,
                summary_addresses,
                stub,
            )
        ) or any(x is not None for x in (router_id, default_metric, log_neighbor_changes, passive_all))
        body: dict[str, Any] | None = None
        if remove_process:
            if changes:
                raise InvalidRequest("remove_process can't be combined with other changes.")
            if proc is None:
                blockers.append(f"No EIGRP process on {where}.")
            method, target = "DELETE", f"{path}/{(proc or {}).get('id')}"
        else:
            if not changes:
                raise InvalidRequest(
                    "Nothing to change: give add_networks, interfaces, neighbors, redistribute, "
                    "summary_addresses, router_id, stub, default_metric, log_neighbor_changes or "
                    "passive_all (or remove_process)."
                )
            if proc is None:
                if as_number is None:
                    raise InvalidRequest(f"{where} has no EIGRP process: give as_number to create it.")
                if not add_networks:
                    blockers.append("A new EIGRP process needs add_networks (the networks it runs on).")
                desired: dict[str, Any] = {
                    "type": "EigrpRoute",
                    "asNumber": str(as_number),
                    "basicConfiguration": {
                        "networks": [],
                        "autoSummary": False,
                    },
                    "advancedConfiguration": {"logNeighborChanges": True},
                }
                method, target = "POST", path
            else:
                if as_number is not None and str(as_number) != str(proc.get("asNumber")):
                    blockers.append(
                        f"{where} already runs EIGRP AS {proc.get('asNumber')} (one process per device or "
                        "VRF): remove it first (remove_process) to change the AS."
                    )
                desired = copy.deepcopy(editable(proc))
                method, target = "PUT", f"{path}/{proc['id']}"
            basic = desired.setdefault("basicConfiguration", {})
            adv = desired.setdefault("advancedConfiguration", {})

            # networks
            nets = list(basic.get("networks") or [])
            have = {str(x.get("id")) for x in nets}
            for v in add_networks or []:
                ref = await _object_ref(app, v, domain, "add_networks")
                if ref["id"] in have:
                    blockers.append(f"{ref.get('name')} is already an EIGRP network.")
                    continue
                nets.append(ref)
                have.add(ref["id"])
            for v in remove_networks or []:
                ref = await _object_ref(app, v, domain, "remove_networks")
                if ref["id"] not in have:
                    blockers.append(f"{ref.get('name')} isn't an EIGRP network.")
                nets = [x for x in nets if str(x.get("id")) != ref["id"]]
            if not nets and proc is not None:
                blockers.append("That would leave EIGRP with no networks; use remove_process instead.")
            basic["networks"] = nets

            ifaces: list[tuple[str, dict[str, Any]]] = []
            if interfaces or neighbors or summary_addresses:
                ifaces = await device_interfaces(app, dev["id"], domain)

            def pick(ref: str) -> dict[str, Any]:
                _, iface = pick_interface(ifaces, ref, str(dev.get("name")))
                if not iface.get("ifname"):
                    blockers.append(
                        f"{iface.get('name')} has no logical name; name it first (fmc_update_interface)."
                    )
                return iface

            # per-interface settings and passive
            entries = [copy.deepcopy(e) for e in desired.get("eigrpInterfaces") or []]
            pas = dict(basic.get("passiveInterfaces") or {"allInterfaces": False})
            passive = list(pas.get("selectedInterfaces") or [])
            was_all = bool(pas.get("allInterfaces"))
            all_after = was_all if passive_all is None else passive_all
            new_keys: set[str] = set()
            seen_if: set[str] = set()
            for spec in interfaces or []:
                iface = pick(spec.name)
                iid = str(iface["id"])
                if iid in seen_if:
                    raise InvalidRequest(f"interfaces names {spec.name} twice.")
                seen_if.add(iid)
                idx = next(
                    (
                        n
                        for n, e in enumerate(entries)
                        if str((e.get("deviceInterface") or {}).get("id")) == iid
                    ),
                    None,
                )
                if spec.remove:
                    if any(
                        x is not None
                        for x in (spec.passive, spec.hello, spec.hold, spec.delay, spec.key_file)
                    ) or (spec.split_horizon is not None or spec.no_auth):
                        raise InvalidRequest("An interface with remove=true takes only its name.")
                    was_passive = any(str(x.get("id")) == iid for x in passive)
                    if idx is None and not was_passive:
                        blockers.append(f"{spec.name} has no EIGRP interface settings to remove.")
                    if idx is not None:
                        entries.pop(idx)
                    passive = [x for x in passive if str(x.get("id")) != iid]
                    continue
                if spec.key_file and spec.no_auth:
                    raise InvalidRequest(f"{spec.name}: key_file and no_auth contradict each other.")
                if spec.key_id is not None and not spec.key_file:
                    raise InvalidRequest(f"{spec.name}: key_id needs key_file (the key itself).")
                if spec.passive is not None and all_after:
                    blockers.append(
                        f"{spec.name}: every interface is passive (passive_all); FMC keeps no per-interface "
                        "passive or non-passive exceptions. Give passive_all=false to pick interfaces."
                    )
                elif spec.passive is not None:
                    is_p = any(str(x.get("id")) == iid for x in passive)
                    if spec.passive and not is_p:
                        passive.append(_iref(iface))
                    elif not spec.passive:
                        passive = [x for x in passive if str(x.get("id")) != iid]
                touches = (
                    any(
                        x is not None
                        for x in (spec.hello, spec.hold, spec.delay, spec.split_horizon, spec.key_file)
                    )
                    or spec.no_auth
                )
                if not touches:
                    continue
                entry = entries[idx] if idx is not None else {"deviceInterface": _iref(iface)}
                conf = dict(entry.get("eigrpProtocolConfiguration") or {})
                timers = dict(conf.get("timers") or {})
                for val, field in (
                    (spec.hello, "helloInterval"),
                    (spec.hold, "holdTime"),
                    (spec.delay, "delay"),
                ):
                    if val is not None:
                        timers[field] = val
                hello = timers.get("helloInterval")
                hold = timers.get("holdTime")
                if hello is not None and hold is not None and hold <= hello:
                    blockers.append(f"{spec.name}: hold time {hold}s must be longer than hello {hello}s.")
                elif hello is not None and hold is not None and hold < 3 * hello:
                    warnings.append(
                        f"{spec.name}: hold {hold}s is under three hellos ({hello}s); Cisco's default is "
                        "hold = 3 x hello, so a lost hello or two can drop the adjacency."
                    )
                if timers:
                    conf["timers"] = timers
                if spec.split_horizon is not None:
                    conf["splitHorizon"] = spec.split_horizon
                if spec.key_file:
                    secret, st = read_key(settings.pki_dir, spec.key_file)
                    key_stats[spec.key_file] = st
                    conf["authentication"] = {
                        "md5auth": True,
                        "keyId": 1 if spec.key_id is None else spec.key_id,
                        "password": secret,
                        "pwdEncryption": "UNENCRYPTED",
                    }
                    new_keys.add(iid)
                elif spec.no_auth:
                    if not (conf.get("authentication") or {}).get("md5auth"):
                        blockers.append(f"{spec.name} has no EIGRP authentication to remove.")
                    conf.pop("authentication", None)
                    new_keys.add(iid)
                entry["eigrpProtocolConfiguration"] = conf
                if idx is None:
                    entries.append(entry)
                else:
                    entries[idx] = entry
            # a stored key comes back masked: sending the mask would make it the key
            for e in entries:
                iid = str((e.get("deviceInterface") or {}).get("id"))
                auth = (e.get("eigrpProtocolConfiguration") or {}).get("authentication") or {}
                if (
                    iid not in new_keys
                    and auth.get("md5auth")
                    and (is_masked(auth.get("password")) or not auth.get("password"))
                ):
                    blockers.append(
                        f"Interface {_iface_label(e.get('deviceInterface'))} has an MD5 key FMC only returns "
                        "masked; editing EIGRP would replace it. Give it again: interfaces=[{'name': ..., "
                        "'key_file': ...}] (or no_auth)."
                    )
            if entries:
                desired["eigrpInterfaces"] = entries
            else:
                desired.pop("eigrpInterfaces", None)
            if passive_all is not None:
                if passive_all == was_all:
                    blockers.append(
                        "Every interface is already passive."
                        if was_all
                        else "Passive on all interfaces is already off."
                    )
                if passive_all and passive:
                    warnings.append(
                        "passive_all replaces the selected passive interfaces ("
                        + ", ".join(str(_iface_label(x)) for x in passive)
                        + "): FMC stores either all interfaces or a list."
                    )
                if passive_all:
                    warnings.append(
                        "Every EIGRP interface stops sending hellos: all adjacencies on the device/VRF drop "
                        "(networks are still advertised). Use it for a stub edge with no EIGRP peers."
                    )
            if all_after:
                passive = []
            if all_after or passive:
                pas["allInterfaces"] = all_after
                pas["selectedInterfaces"] = passive
                basic["passiveInterfaces"] = pas
            else:
                # FMC 10.0 rejects an empty block ("Device Interface is mandatory for Passive interface
                # configuration"); leaving it out is how "nothing passive" is sent.
                basic.pop("passiveInterfaces", None)

            # static neighbours
            nbrs = [copy.deepcopy(n) for n in desired.get("neighbors") or []]
            for spec_n in neighbors or []:
                iface = pick(spec_n.interface)
                addr = await _object_ref(app, spec_n.address, domain, "neighbors")
                key = (str(addr["id"]), str(iface["id"]))
                idx = next(
                    (
                        n
                        for n, x in enumerate(nbrs)
                        if (
                            str((x.get("neighborAddress") or {}).get("id")),
                            str((x.get("neighborInterface") or {}).get("id")),
                        )
                        == key
                    ),
                    None,
                )
                if spec_n.remove:
                    if idx is None:
                        blockers.append(f"{addr.get('name')} on {spec_n.interface} isn't an EIGRP neighbor.")
                    else:
                        nbrs.pop(idx)
                elif idx is not None:
                    blockers.append(f"{addr.get('name')} on {spec_n.interface} is already an EIGRP neighbor.")
                else:
                    nbrs.append({"neighborInterface": _iref(iface), "neighborAddress": addr})
            if nbrs:
                desired["neighbors"] = nbrs
            else:
                desired.pop("neighbors", None)

            # summary addresses
            sums = [copy.deepcopy(s) for s in desired.get("summaryAddressList") or []]
            for spec_s in summary_addresses or []:
                iface = pick(spec_s.interface)
                net = await _object_ref(app, spec_s.network, domain, "summary_addresses")
                key = (str(net["id"]), str(iface["id"]))
                idx = next(
                    (
                        n
                        for n, x in enumerate(sums)
                        if (
                            str((x.get("summaryAddress") or {}).get("id")),
                            str((x.get("deviceInterface") or {}).get("id")),
                        )
                        == key
                    ),
                    None,
                )
                if spec_s.remove:
                    if spec_s.admin_distance is not None:
                        raise InvalidRequest("A summary with remove=true takes no admin_distance.")
                    if idx is None:
                        blockers.append(f"{net.get('name')} isn't summarised on {spec_s.interface}.")
                    else:
                        sums.pop(idx)
                    continue
                entry_s: dict[str, Any] = {"deviceInterface": _iref(iface), "summaryAddress": net}
                if spec_s.admin_distance is not None:
                    entry_s["adminDistance"] = spec_s.admin_distance
                if idx is None:
                    sums.append(entry_s)
                elif {k: v for k, v in sums[idx].items() if k in entry_s} == entry_s:
                    blockers.append(
                        f"{net.get('name')} is already summarised on {spec_s.interface} that way."
                    )
                else:
                    sums[idx] = {**sums[idx], **entry_s}
            if sums:
                desired["summaryAddressList"] = sums
            else:
                desired.pop("summaryAddressList", None)

            # redistribution
            redist_diff: dict[str, list[Any]] = {"added": [], "changed": [], "removed": []}
            if redistribute:
                refs = PolicyRefs(app, domain)
                current = [dict(r) for r in desired.get("redistributeProtocols") or []]
                bgp_as = None
                if any(r.protocol == "bgp" for r in redistribute):
                    root = f"{base.split('/routing')[0]}/routing"
                    general = next(iter(await _items(app, f"{root}/bgpgeneralsettings", domain)), None)
                    bgp_as = (general or {}).get("asNumber")
                seen: set[tuple[str, str]] = set()
                for r in redistribute:
                    if r.protocol == "ospf" and r.process_id is None:
                        raise InvalidRequest(
                            "redistribute protocol='ospf' needs process_id (the OSPF process)."
                        )
                    if r.protocol != "ospf" and r.process_id is not None:
                        raise InvalidRequest("process_id applies to protocol='ospf' only.")
                    metric = {f: getattr(r, k) for k, f in METRIC_FIELDS.items() if getattr(r, k) is not None}
                    if r.remove and (metric or r.route_map):
                        raise InvalidRequest("remove=true takes only protocol (and process_id for ospf).")
                    sub = (
                        str(r.process_id)
                        if r.protocol == "ospf"
                        else (str(bgp_as) if r.protocol == "bgp" and bgp_as else "")
                    )
                    k = (PROTOCOLS[r.protocol], sub)
                    label = f"{r.protocol}{f' {sub}' if sub else ''}"
                    if k in seen:
                        raise InvalidRequest(f"redistribute names {label} twice.")
                    seen.add(k)
                    if r.protocol == "bgp" and not bgp_as and not r.remove:
                        blockers.append(
                            "redistribute protocol='bgp' needs BGP on the device (its AS); set it up first."
                        )
                    idx = next(
                        (
                            n
                            for n, x in enumerate(current)
                            if str(x.get("protocol")) == k[0]
                            and (k[0] not in ("OSPF", "BGP") or str(x.get("processId") or "") == sub)
                        ),
                        None,
                    )
                    if r.remove:
                        if idx is None:
                            blockers.append(f"{label} isn't redistributed into EIGRP.")
                        else:
                            redist_diff["removed"].append(redistribution_row(current.pop(idx)))
                        continue
                    entry_r: dict[str, Any] = {"protocol": k[0]}
                    if sub:
                        entry_r["processId"] = sub
                    if r.protocol == "ospf":
                        entry_r["matchInternal"] = True  # the IOS default when no match is named
                    if r.route_map and r.route_map.strip().lower() != NONE:
                        entry_r["routeMap"] = await refs.route_map(r.route_map)
                    if metric:
                        if len(metric) != len(METRIC_FIELDS):
                            raise InvalidRequest(
                                f"redistribute {label}: an EIGRP metric needs all five values "
                                "(bandwidth, delay, reliability, load, mtu)."
                            )
                        entry_r["routeMetric"] = metric
                    elif r.protocol in ("ospf", "bgp") and not (adv.get("routeMetric") or default_metric):
                        warnings.append(
                            f"{label} is redistributed without a metric and the process has no default "
                            "metric: EIGRP doesn't advertise those routes (give bandwidth, delay, "
                            "reliability, load, mtu, or default_metric)."
                        )
                    if idx is None:
                        current.append(entry_r)
                        redist_diff["added"].append(redistribution_row(entry_r))
                    else:
                        before_r = redistribution_row(current[idx])
                        after_r = redistribution_row(entry_r)
                        if before_r == after_r:
                            blockers.append(f"{label} is already redistributed that way.")
                        else:
                            redist_diff["changed"].append(
                                {"source": label, "changes": field_changes(before_r, after_r, replace=True)}
                            )
                        current[idx] = entry_r
                if current:
                    desired["redistributeProtocols"] = current
                else:
                    desired.pop("redistributeProtocols", None)

            # advanced
            if router_id is not None:
                if router_id.strip().lower() == NONE:
                    adv.pop("routerId", None)
                else:
                    rid = check_router_id(router_id)
                    if rid is None:
                        adv.pop("routerId", None)
                    else:
                        adv["routerId"] = rid
            if default_metric is not None:
                dm = {
                    f: getattr(default_metric, k)
                    for k, f in METRIC_FIELDS.items()
                    if getattr(default_metric, k) is not None
                }
                if len(dm) != len(METRIC_FIELDS):
                    raise InvalidRequest(
                        "default_metric needs all five values (bandwidth, delay, reliability, load, mtu)."
                    )
                adv["routeMetric"] = dm
            if log_neighbor_changes is not None:
                adv["logNeighborChanges"] = log_neighbor_changes
            if stub:
                modes = set(stub)
                if "none" in modes:
                    if len(modes) > 1:
                        raise InvalidRequest("stub ['none'] can't be combined with other modes.")
                    adv.pop("stub", None)
                elif "receive_only" in modes:
                    if len(modes) > 1:
                        raise InvalidRequest("stub 'receive_only' can't be combined with other modes.")
                    adv["stub"] = {"receiveOnly": True}
                else:
                    adv["stub"] = {
                        "receiveOnly": False,
                        "advertise": {
                            k: k in modes for k in ("connected", "static", "summary", "redistributed")
                        },
                    }
            body = desired
            after: dict[str, Any] | None = eigrp_summary(desired)
        if remove_process:
            after = None
            redist_diff = {}
        before = eigrp_summary(proc) if proc else None
        if any(e.get("md5") for e in (after or {}).get("interfaces") or []):
            warnings.append(
                "The peer must use the same MD5 key id and key on that link, or the adjacency drops."
            )

        async def apply() -> Any:
            if method == "DELETE":
                return await applied(app, lambda: app.api.delete(target))
            if method == "POST":
                return await applied(app, lambda: app.api.post(target, body))
            return await applied(app, lambda: app.api.put(target, body))

        details: dict[str, Any] = {"before": before, "after": after}
        if redist_diff and any(redist_diff.values()):
            details["redistribute_changes"] = {k: v for k, v in redist_diff.items() if v}
        if warnings:
            details["warnings"] = warnings
        if not blockers:
            row: dict[str, Any] = {"step": STEPS[method], "method": method, "path": target}
            if body is not None:
                row["body"] = mask_body(body)
            details["requests"] = [row]
        verb = "Delete" if remove_process else ("Create" if method == "POST" else "Change")
        as_label = (proc or {}).get("asNumber") or as_number
        return await fmc_preview(
            ctx,
            tool="fmc_configure_eigrp",
            args={
                "device": device,
                "as_number": as_number,
                "add_networks": add_networks,
                "remove_networks": remove_networks,
                "interfaces": None if interfaces is None else [i.model_dump() for i in interfaces],
                "neighbors": None if neighbors is None else [n.model_dump() for n in neighbors],
                "redistribute": None if redistribute is None else [r.model_dump() for r in redistribute],
                "summary_addresses": None
                if summary_addresses is None
                else [s.model_dump() for s in summary_addresses],
                "router_id": router_id,
                "stub": stub,
                "default_metric": None if default_metric is None else default_metric.model_dump(),
                "log_neighbor_changes": log_neighbor_changes,
                "passive_all": passive_all,
                "remove_process": remove_process,
                "virtual_router": virtual_router,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"{verb} EIGRP AS {as_label} on {where}",
                details=details,
                fingerprint={
                    "process": proc and mask_body(editable(proc)),
                    "others": [p.get("id") for p in procs],
                    "key_files": {k: list(v) for k, v in key_stats.items()},
                },
                blockers=blockers,
                side_effects=["Takes effect on the device after the next deployment."]
                + (
                    ["Every EIGRP adjacency on the device/VRF goes down and its EIGRP routes are withdrawn."]
                    if remove_process
                    else []
                ),
            ),
            apply=apply,
        )

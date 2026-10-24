"""fmc_service_chain_check (F88): does an FTD fit as the firewall of a Catalyst SD-WAN service chain?

A service chain sends a VPN's traffic from the SD-WAN edge to a service address (here an FTD interface) and
takes it back from the FTD: single-arm (one link, the FTD hands the flow back to the same edge address) or
dual-arm (the edge sends on one link and receives on another). The FTD side needs: an enabled, named
interface on each link with the address the edge's chain names, a security zone on each, routes for the
chained networks back to the edge (not out of some other interface), an access policy that lets the
chained flows through, and nothing undeployed. Each check names the tool that fixes it; the live FTD leg of
`catsdwan_trace_through_firewall` is fmc_packet_tracer(ingress_hop=..., expect_next_hop=...)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
from typing import Annotated, Any, Literal

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import InvalidRequest, ToolRegistrar, UpstreamError, get_client
from fmc_mcp.catalog import Catalog
from fmc_mcp.client import FmcApp
from fmc_mcp.flow import Address, DeviceContext, Net, access_policy_of, device_context, interface_holding
from fmc_mcp.tools.analysis import _net_match, _opaque, _port_match, _zone_match
from fmc_mcp.tools.common import PROTO_NUMBERS, Domain
from fmc_mcp.tools.deploy import deployable, deployable_row
from fmc_mcp.tools.device_config import device_interfaces, resolve_device
from fmc_mcp.tools.device_snapshot import INTERFACES, parse_ip_brief
from fmc_mcp.tools.devices import DeviceRef
from fmc_mcp.tools.policies import ACCESS, all_rules
from fmc_mcp.tools.troubleshoot import run_show

MAX_FLOWS = 4  # (source, destination) network pairs walked through the access policy
LIMITS = (
    "Read from FMC's configuration (interfaces, zones, static routes, the access policy) plus, with live, "
    "'show interface ip brief' on the device. Dynamic routes (BGP/OSPF learned from the edge), NAT, "
    "prefilter rules and the platform settings' ICMP access are not evaluated: an OSPF/BGP route back to "
    "the edge shows here as missing (check fmc_run_show_command 'show route <network>'), and a NAT rule "
    "between the chain's interfaces would hand the edge translated addresses (fmc_list_nat_rules). The "
    "access policy walk is offline and best-effort like fmc_rule_lookup (rules on applications, URLs, users, "
    "SGTs or dynamic objects are conditional); the live verdict: fmc_packet_tracer with the `trace` "
    "arguments below."
)
TRACKER = (
    "The edge tracks the service address with ICMP echo (or an IP SLA probe): the FTD answers on its "
    "interface unless the platform settings' ICMP access rules leave the edge out "
    "(fmc_get_platform_settings; fmc_configure_mgmt_access). A failed tracker takes the chain down, and "
    "the edge then forwards or drops per the chain's fail-over setting."
)
ALLOWING = {"ALLOW", "TRUST"}


def _address(value: str, what: str) -> Address:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        raise InvalidRequest(f"{what} must be an IP address, got {value!r}") from None


def _network(value: str, what: str) -> Net:
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise InvalidRequest(f"{what} must be a network such as 10.1.0.0/16, got {value!r}") from None


def sample(net: Net) -> Address:
    """A host of the network to stand for it in a rule walk or a trace (the first usable one)."""
    if net.prefixlen == 0:  # a default route stands for the internet: a documentation address
        return ipaddress.ip_address("198.51.100.10" if net.version == 4 else "2001:db8::10")
    return net.network_address + 1 if net.num_addresses > 2 else net.network_address


def gateway_ip(cat: Catalog, label: str) -> str | None:
    """A static route's gateway label (a literal or a host object's name) as an address, if known."""
    try:
        return str(ipaddress.ip_address(label))
    except ValueError:
        pass
    for o in cat.objects.values():
        if str(o.get("name")) == label and o.get("value"):
            try:
                return str(ipaddress.ip_address(str(o["value"]).split("/")[0]))
            except ValueError:
                return None
    return None


def check(name: str, ok: bool | None, detail: str, fix: str | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {"check": name, "ok": ok, "detail": detail}
    if fix:
        row["fix"] = fix
    return row


def attachment(
    role: str,
    edge: Address,
    service: Address | None,
    ifaces: list[tuple[str, dict[str, Any]]],
    raw: dict[str, dict[str, Any]],
    device: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """The FTD interface on the link to `edge` and whether it can carry the chain: (check, interface row)."""
    what = f"{role} interface"
    held = interface_holding(ifaces, edge)
    if held is None:
        off = interface_holding(ifaces, edge, enabled_only=False)
        if off is not None:
            row = off[0]
            return check(
                what,
                False,
                f"{row['name']} ({row['logical_name']}) holds {edge} in {off[1]} but is disabled.",
                f"fmc_update_interface(device={device!r}, interface={row['logical_name']!r}, enabled=true)",
            ), None
        return check(
            what,
            False,
            f"No named interface on {device} has the edge's address {edge} in its subnet: the link to the "
            "edge is not configured on the FTD (or the address is not the edge's on this link).",
            f"fmc_update_interface(device={device!r}, interface=<the port cabled to the edge>, "
            f"logical_name=..., security_zone=..., ipv4='<a free address in the edge's subnet>/<length>')",
        ), None
    row, net = held
    own = str(row.get("ipv4") or "").split("/")[0]
    problems: list[str] = []
    fix = None
    if raw.get(str(row.get("id")), {}).get("managementOnly"):
        problems.append("it is management-only, so it carries no transit traffic")
        fix = (
            f"fmc_update_interface(device={device!r}, interface={row['logical_name']!r}, ...) on a data port"
        )
    if own == str(edge):
        problems.append(f"it has the edge's own address {edge}")
    if service is not None and own != str(service):
        problems.append(
            f"its address is {own or 'not static'}, but the edge's service chain sends to {service}"
        )
        fix = fix or (
            f"fmc_update_interface(device={device!r}, interface={row['logical_name']!r}, "
            f"ipv4='{service}/{net.prefixlen}'), or point the chain's service address at {own}"
        )
    detail = f"{row['name']} ({row['logical_name']}, {row.get('ipv4')}) faces the edge at {edge}"
    if row.get("kind") == "vti":
        detail += (
            f"; a VTI ({row.get('tunnel_type') or 'tunnel'} from {row.get('tunnel_source') or '?'}): the "
            "tunnel's state is in fmc_list_vpn_tunnels"
        )
    if problems:
        return check(what, False, detail + ", but " + "; ".join(problems) + ".", fix), row
    return check(what, True, detail + "."), row


def route_check(
    dc: DeviceContext,
    cat: Catalog,
    net: Net,
    via: dict[str, Any],
    edge: Address,
    device: str,
    side: str,
) -> dict[str, Any]:
    """Does traffic to `net` leave by `via` (the interface facing the edge) to the edge's address?"""
    ifname = str(via["logical_name"])
    name = f"route to {side} {net}"
    fix = (
        f"fmc_create_static_route(device={device!r}, interface={ifname!r}, networks=[{str(net)!r}], "
        f"gateway={str(edge)!r})"
    )
    legs = [dc.leg(net.network_address), dc.leg(net.broadcast_address)]
    if any(leg is None for leg in legs):
        return check(
            name, False, f"No interface or static route on {device} covers {net}: replies can't go back.", fix
        )
    first, last = legs[0], legs[1]
    assert first is not None and last is not None
    if (first.interface, first.how) != (last.interface, last.how):
        return check(
            name,
            False,
            f"{net} is split: part leaves by {first.interface} ({first.how}), part by {last.interface} "
            f"({last.how}).",
            fix,
        )
    if first.interface != ifname:
        return check(
            name,
            False,
            f"{net} leaves by {first.interface} ({first.how}), not by {ifname} back to the edge at {edge}: "
            "the chained flow would bypass the SD-WAN edge (or come back asymmetric).",
            fix,
        )
    if first.how.startswith("connected"):
        return check(name, True, f"{net} is on {ifname} itself ({first.how}).")
    gw_label = first.how.rsplit(" via ", 1)[-1]
    gw = gateway_ip(cat, gw_label)
    if gw is None:
        return check(
            name, None, f"{net} leaves by {ifname} ({first.how}); gateway {gw_label!r} not resolved."
        )
    if gw != str(edge):
        return check(
            name,
            False,
            f"{net} leaves by {ifname} but to {gw} ({first.how}), not to the edge at {edge}.",
            fix,
        )
    return check(name, True, f"{net} leaves by {ifname} to the edge at {edge} ({first.how}).")


def walk(
    cat: Catalog,
    rules: list[dict[str, Any]],
    default: str,
    src: Address,
    dst: Address,
    proto: str,
    port: int | None,
    zin: str | None,
    zout: str | None,
) -> dict[str, Any]:
    """The first access rule that surely takes the flow, earlier conditional ones, or the default action."""
    s = (src.version, int(src), int(src))
    d = (dst.version, int(dst), int(dst))
    conditional: list[str] = []
    for r in sorted(rules, key=lambda x: (x.get("metadata") or {}).get("ruleIndex") or 10**9):
        if not r.get("enabled", True):
            continue
        tests = {
            "source_zone": _zone_match(r.get("sourceZones"), zin),
            "destination_zone": _zone_match(r.get("destinationZones"), zout),
            "source": _net_match(cat, r.get("sourceNetworks"), s),
            "destination": _net_match(cat, r.get("destinationNetworks"), d),
            "destination_port": _port_match(cat, r.get("destinationPorts"), proto, port),
            "source_port": _port_match(cat, r.get("sourcePorts"), proto, None),
        }
        if any(v is False for v in tests.values()):
            continue
        unknown = [k for k, v in tests.items() if v is None] + _opaque(r)
        index = (r.get("metadata") or {}).get("ruleIndex")
        action = str(r.get("action") or "").upper()
        if unknown:
            conditional.append(f"rule {index} {r.get('name')!r} ({action}, depends on {', '.join(unknown)})")
            continue
        if action == "MONITOR":
            continue
        return {"rule": f"rule {index} {r.get('name')!r}", "action": action, "conditional": conditional}
    return {"rule": "default action", "action": default, "conditional": conditional}


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="FTD as an SD-WAN service-chain firewall")
    async def fmc_service_chain_check(
        ctx: Context,
        device: DeviceRef,
        edge_address: Annotated[
            str,
            Field(
                description="The SD-WAN edge's address on its link to the FTD: where the edge sends the "
                "chained traffic from (single-arm: also where the FTD hands it back), e.g. 192.0.2.1"
            ),
        ],
        source_networks: Annotated[
            list[str],
            Field(description="Networks the chained traffic comes from (e.g. the branch LAN), CIDR"),
        ],
        destination_networks: Annotated[
            list[str],
            Field(description="Networks it goes to (e.g. the data centre, or 0.0.0.0/0 for internet), CIDR"),
        ],
        return_address: Annotated[
            str | None,
            Field(
                description="Dual-arm chain: the edge's address on the FTD's other link, where the FTD hands "
                "the traffic back. Omit for single-arm"
            ),
        ] = None,
        service_address: Annotated[
            str | None,
            Field(
                description="The FTD address the edge's service chain sends to and tracks (the chain's "
                "service IP); checked against the FTD interface on the edge's link"
            ),
        ] = None,
        protocol: Annotated[
            Literal["tcp", "udp", "icmp"],
            Field(description="Protocol of the flows walked through the policy"),
        ] = "tcp",
        port: Annotated[
            int | None,
            Field(
                ge=0, le=65535, description="Destination port of those flows (omit: rules on ports stay open)"
            ),
        ] = None,
        live: Annotated[
            bool, Field(description="Also read the interfaces' link state from the device (show interface)")
        ] = True,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Check that an FTD fits as the firewall of a Catalyst SD-WAN service chain (an edge sends a VPN's
        traffic to the FTD and takes it back): the interface on each link to the edge (enabled, named, not
        management-only, the address the chain sends to; up, with live), a security zone on each (single-arm:
        the rules need that zone as both source and destination), static routes for the chained source and
        destination networks back to the edge (not out of another interface: that would bypass the edge),
        the access policy's verdict for the chained flows (offline walk), the edge's tracker and undeployed
        changes. Each failed check carries `fix`, the tool call that fixes it. `trace` gives the
        fmc_packet_tracer arguments for the live FTD leg (catsdwan_trace_through_firewall). Read-only; see
        `limits`."""
        app: FmcApp = get_client(ctx)
        edge = _address(edge_address, "edge_address")
        back = _address(return_address, "return_address") if return_address else None
        service = _address(service_address, "service_address") if service_address else None
        srcs = [_network(n, "source_networks") for n in source_networks]
        dsts = [_network(n, "destination_networks") for n in destination_networks]
        if not srcs or not dsts:
            raise InvalidRequest(
                "Give at least one source and one destination network of the chained traffic."
            )
        if any(n.version != edge.version for n in srcs + dsts) or (back and back.version != edge.version):
            raise InvalidRequest("The edge addresses and the networks must all be IPv4 or all IPv6.")
        dev = await resolve_device(app, device, domain)
        name = str(dev.get("name"))
        ifaces = await device_interfaces(app, dev["id"], domain)
        raw = {str(i.get("id")): i for _, i in ifaces}
        cat = Catalog(app, domain)
        dc = await device_context(app, dev, cat, domain, interfaces=ifaces)
        await cat.load_ports()
        zones = {str(r.get("id")): r.get("zone") for r in dc.interfaces}
        mode = "dual-arm" if back else "single-arm"
        checks: list[dict[str, Any]] = []

        # --- the links to the edge ------------------------------------------------------------------
        c_in, row_in = attachment("ingress" if back else "chain", edge, service, ifaces, raw, name)
        checks.append(c_in)
        row_out = row_in
        if back is not None:
            c_out, row_out = attachment("return", back, None, ifaces, raw, name)
            checks.append(c_out)
            if row_in and row_out and row_in.get("id") == row_out.get("id"):
                checks.append(
                    check(
                        "dual-arm",
                        None,
                        f"Both edge addresses are on {row_in['logical_name']}: this is a single-arm chain.",
                    )
                )
        if live and (row_in or row_out):
            try:
                state = {
                    r["interface"]: r
                    for r in parse_ip_brief(await run_show(app, dev["id"], INTERFACES, domain))
                }
            except (UpstreamError, InvalidRequest) as e:
                checks.append(check("link state", None, f"Not read from the device ({e})."))
            else:
                for row in {str(r["id"]): r for r in (row_in, row_out) if r}.values():
                    st = state.get(str(row["name"]))
                    if st is None:
                        checks.append(
                            check(
                                f"link state {row['logical_name']}",
                                None,
                                f"{row['name']} not in {INTERFACES!r}.",
                            )
                        )
                        continue
                    up = (st["status"], st["protocol"]) == ("up", "up")
                    checks.append(
                        check(
                            f"link state {row['logical_name']}",
                            up,
                            f"{row['name']} is {st['status']}/{st['protocol']} ({st['ip']}).",
                            None
                            if up
                            else "fmc_update_interface(enabled=true) if administratively down; else "
                            "the cabling or the edge's port (catsdwan_interface_stats)",
                        )
                    )

        # --- zones ----------------------------------------------------------------------------------
        zin = zones.get(str(row_in["id"])) if row_in else None
        zout = zones.get(str(row_out["id"])) if row_out else None
        for zrow, zone in ((row_in, zin), (row_out, zout) if back else (None, None)):
            if zrow is None:
                continue
            if zone is None:
                checks.append(
                    check(
                        f"zone {zrow['logical_name']}",
                        False,
                        f"{zrow['logical_name']} has no security zone: zone-based access rules can't "
                        "match the chained traffic.",
                        f"fmc_update_interface(device={name!r}, interface={zrow['logical_name']!r}, "
                        "security_zone=<zone>) (fmc_create_security_zone for a new one)",
                    )
                )
            else:
                checks.append(
                    check(f"zone {zrow['logical_name']}", True, f"{zrow['logical_name']} is in {zone}.")
                )
        if row_in and (not back or (row_out and row_out.get("id") == row_in.get("id"))):
            checks.append(
                check(
                    "hairpin",
                    None,
                    f"Single-arm: the flow enters and leaves by {row_in['logical_name']}, so an access "
                    f"rule for it needs {zin or 'its zone'} as both source and destination zone "
                    "(or no zones).",
                )
            )
        elif zin and zout and zin == zout:
            checks.append(
                check("zones", None, f"Both links are in {zin}: rules see the chained traffic as intra-zone.")
            )

        # --- routes back to the edge ----------------------------------------------------------------
        if row_in:
            for n in srcs:
                checks.append(route_check(dc, cat, n, row_in, edge, name, "source"))
        if row_out:
            for n in dsts:
                checks.append(route_check(dc, cat, n, row_out, back or edge, name, "destination"))

        # --- the access policy ----------------------------------------------------------------------
        acp_ref = await access_policy_of(app, dev, domain)
        flows: list[dict[str, Any]] = []
        acp: dict[str, Any] | None = None
        if acp_ref is None:
            checks.append(
                check(
                    "access policy",
                    False,
                    f"{name} has no access control policy.",
                    f"fmc_assign_policy(kind='access', policy=<policy>, devices=[{name!r}])",
                )
            )
        else:
            acp = await app.api.get(await app.config_path(f"{ACCESS}/{acp_ref['id']}", domain))
            rules = await all_rules(
                app, await app.config_path(f"{ACCESS}/{acp_ref['id']}/accessrules", domain)
            )
            default = str(((acp or {}).get("defaultAction") or {}).get("action") or "?").upper()
            proto = PROTO_NUMBERS.get(protocol.upper(), protocol)
            for sn in srcs:
                for dn in dsts:
                    if len(flows) >= MAX_FLOWS:
                        break
                    s, d = sample(sn), sample(dn)
                    got = walk(cat, rules.items, default, s, d, proto, port, zin, zout if back else zin)
                    flows.append({"source": str(s), "destination": str(d), **got})
            blocked = [f for f in flows if f["action"] not in ALLOWING and f["action"] != "MONITOR"]
            open_ = [f for f in flows if f["conditional"]]
            policy_name = (acp or {}).get("name") or acp_ref.get("name")
            zone_args = (
                f"source_zones=[{zin!r}], destination_zones=[{(zout if back else zin)!r}], " if zin else ""
            )
            if blocked:
                f = blocked[0]
                checks.append(
                    check(
                        "access policy",
                        False,
                        f"{policy_name!r}: {f['source']} -> {f['destination']} is decided by {f['rule']} -> "
                        f"{f['action']}"
                        + (f" ({len(blocked)} of {len(flows)} flows blocked)" if len(flows) > 1 else "")
                        + ".",
                        f"fmc_create_access_rule(policy={policy_name!r}, name=<name>, action='ALLOW', "
                        f"{zone_args}"
                        f"source_networks={[str(n) for n in srcs]!r}, destination_networks="
                        f"{[str(n) for n in dsts]!r}, insert_before=<above {f['rule']}>), then fmc_deploy",
                    )
                )
            else:
                checks.append(
                    check(
                        "access policy",
                        None if open_ else True,
                        f"{policy_name!r} allows the chained flows"
                        + (
                            " unless an earlier conditional rule takes them first (see flows)"
                            if open_
                            else ""
                        )
                        + ".",
                    )
                )

        checks.append(check("edge tracker", None, TRACKER))

        # --- deployed -------------------------------------------------------------------------------
        try:
            pending = [deployable_row(d) for d in await deployable(app, domain)]
        except UpstreamError:
            pending = []
        mine = [d for d in pending if d.get("device_id") == dev.get("id") or d.get("device") == name]
        if mine:
            stale = ", ".join(mine[0].get("out_of_date_policies") or []) or "see fmc_pending_changes"
            checks.append(
                check(
                    "deployed",
                    False,
                    f"{name} has undeployed changes ({stale}): the device may not run what is checked here.",
                    f"fmc_deploy(devices=[{name!r}])",
                )
            )
        else:
            checks.append(check("deployed", True, f"{name} is up to date."))

        failed = [c["check"] for c in checks if c["ok"] is False]
        out: dict[str, Any] = {
            "device": name,
            "mode": mode,
            "edge": {"sends_from": str(edge), **({"receives_on": str(back)} if back else {})},
            "ready": not failed,
            "failed": failed or None,
            "checks": checks,
        }
        if flows:
            out["access_policy"] = (acp or {}).get("name")
            out["flows"] = flows
        if row_in:
            s, d = sample(srcs[0]), sample(dsts[0])
            trace: dict[str, Any] = {
                "device": name,
                "protocol": protocol,
                "source_ip": str(s),
                "destination_ip": str(d),
                "ingress_hop": str(edge),
                "expect_next_hop": str(back or edge),
            }
            if protocol != "icmp":
                trace["destination_port"] = port or 443
            out["trace"] = trace
        out["limits"] = LIMITS
        return {k: v for k, v in out.items() if v is not None}

"""F88: an FTD as the firewall of a Catalyst SD-WAN service chain (fmc_service_chain_check) and the trace
leg (fmc_packet_tracer ingress_hop / expect_next_hop).

Shapes are the recorded ones of tests/fixtures (mcp-ftd1, FMC 10.0.1 / FTDv 10.0.0: ftd_physicalinterfaces,
ftd_ipv4staticroutes, ftd_packettracer_*, fleet_show's 'show interface ip brief'); the chain's edge addresses
and networks are documentation / lab-private values: inside 10.99.1.1/24 faces the edge's 10.99.1.254,
outside 192.0.2.10/18 faces its 192.0.2.1."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from .conftest import CFG, DOMAIN, empty, fixture, items
from .test_tools_ftd import ACP, ANY4, DEVPATH, ZONES, ftd, run, server  # noqa: F401  (ftd is a fixture)

DEV_ID = fixture("ftd_device")["id"]
BRANCH = {"id": "net-branch", "name": "br1-lan", "type": "Network", "value": "10.20.0.0/16"}
EDGE_IN, EDGE_OUT = "10.99.1.254", "192.0.2.1"
BRIEF = (
    "Interface                  IP-Address      OK? Method Status                Protocol\n"
    "Ethernet0/0                192.0.2.10      YES CONFIG up                    up  \n"
    "Ethernet0/1                10.99.1.1       YES CONFIG {inside}\n"
    "Management0/0              203.0.113.130   YES unset  up                    up  \n"
)
UP = "up                    up  "


@pytest.fixture
def lab(ftd: respx.MockRouter) -> respx.MockRouter:  # noqa: F811
    """mcp-ftd1 as test_tools_ftd records it."""
    return ftd


def route(net: dict[str, Any], ifname: str, gw: str) -> dict[str, Any]:
    """An IPv4StaticRoute as ftd_ipv4staticroutes.json records it."""
    r = copy.deepcopy(fixture("ftd_ipv4staticroutes")["items"][0])
    r.update(
        interfaceName=ifname,
        selectedNetworks=[{"type": "Network", "name": net["name"], "id": net["id"]}],
        gateway={"literal": {"type": "Host", "value": gw}},
        id=f"route-{net['id']}",
    )
    return r


def chain(
    fmc: respx.MockRouter,
    routes: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    *,
    inside: str = UP,
    pending: list[dict[str, Any]] | None = None,
) -> None:
    fmc.get(f"{CFG}/object/networkaddresses").mock(return_value=items([ANY4, BRANCH]))
    for p in (
        "ranges",
        "networkgroups",
        "protocolportobjects",
        "icmpv4objects",
        "icmpv6objects",
        "portobjectgroups",
    ):
        fmc.get(f"{CFG}/object/{p}").mock(return_value=empty())
    fmc.get(f"{DEVPATH}/routing/ipv4staticroutes").mock(return_value=items(routes))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}").mock(
        return_value=httpx.Response(200, json={**ACP, "defaultAction": {"action": "BLOCK"}})
    )
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules").mock(return_value=items(rules))
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items(pending or []))
    fmc.get(f"{DEVPATH}/operational/commands").mock(
        return_value=items([{"commandOutput": BRIEF.format(inside=inside)}])
    )


def zones_rule(name: str, action: str, src: dict[str, Any], dst: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"r-{name}",
        "name": name,
        "action": action,
        "enabled": True,
        "metadata": {"ruleIndex": 1, "section": "Default"},
        "sourceZones": {"objects": [{**src, "type": "SecurityZone"}]},
        "destinationZones": {"objects": [{**dst, "type": "SecurityZone"}]},
    }


DUAL = {
    "device": "mcp-ftd1",
    "edge_address": EDGE_IN,
    "return_address": EDGE_OUT,
    "service_address": "10.99.1.1",
    "source_networks": ["10.20.0.0/16"],
    "destination_networks": ["0.0.0.0/0"],
    "port": 443,
}


def by_name(out: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["check"]: c for c in out["checks"]}


async def test_dual_arm_chain_is_ready(lab: respx.MockRouter) -> None:
    chain(
        lab,
        [route(BRANCH, "inside", EDGE_IN), route(ANY4, "outside", EDGE_OUT)],
        [zones_rule("chain-out", "ALLOW", ZONES[0], ZONES[1])],
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_service_chain_check", DUAL)
    checks = by_name(out)
    assert out["ready"] is True and out["mode"] == "dual-arm" and "failed" not in out, out
    assert checks["ingress interface"]["ok"] and "inside" in checks["ingress interface"]["detail"]
    assert checks["return interface"]["ok"] and "outside" in checks["return interface"]["detail"]
    assert checks["link state inside"]["ok"] and checks["link state outside"]["ok"]
    assert checks["zone inside"]["detail"].endswith("mcp-test-ftd-in.")
    assert checks["route to source 10.20.0.0/16"]["ok"] and checks["route to destination 0.0.0.0/0"]["ok"]
    assert checks["access policy"]["ok"] is True
    assert out["flows"][0]["rule"] == "rule 1 'chain-out'" and out["flows"][0]["action"] == "ALLOW"
    assert out["trace"] == {
        "device": "mcp-ftd1",
        "protocol": "tcp",
        "source_ip": "10.20.0.1",
        "destination_ip": "198.51.100.10",
        "ingress_hop": EDGE_IN,
        "expect_next_hop": EDGE_OUT,
        "destination_port": 443,
    }


async def test_chain_failures_name_their_fix(lab: respx.MockRouter) -> None:
    """The recorded route (default via 192.0.2.10, not the edge), no route for the branch, the inside link
    down, nothing allowing the flow, the chain's service address not the FTD's, a pending deploy."""
    pending = [{"name": "mcp-ftd1", "device": {"id": DEV_ID}, "policyStatusList": []}]
    chain(
        lab,
        fixture("ftd_ipv4staticroutes")["items"],
        [],
        inside="down                  down  ",
        pending=pending,
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_service_chain_check", {**DUAL, "service_address": "10.99.1.2"})
    checks = by_name(out)
    assert out["ready"] is False
    assert checks["ingress interface"]["ok"] is False and "10.99.1.2" in checks["ingress interface"]["fix"]
    assert checks["link state inside"]["ok"] is False and "down/down" in checks["link state inside"]["detail"]
    src = checks["route to source 10.20.0.0/16"]
    assert src["ok"] is False and "leaves by outside" in src["detail"]
    assert src["fix"] == (
        "fmc_create_static_route(device='mcp-ftd1', interface='inside', networks=['10.20.0.0/16'], "
        "gateway='10.99.1.254')"
    )
    dst = checks["route to destination 0.0.0.0/0"]
    assert dst["ok"] is False and "to 192.0.2.10" in dst["detail"] and "192.0.2.1'" in dst["fix"]
    pol = checks["access policy"]
    assert pol["ok"] is False and "default action -> BLOCK" in pol["detail"]
    assert pol["fix"].startswith("fmc_create_access_rule(policy='mcp-test-ftd-acp'")
    assert "source_zones=['mcp-test-ftd-in'], destination_zones=['mcp-test-ftd-out']" in pol["fix"]
    assert checks["deployed"]["ok"] is False
    assert set(out["failed"]) >= {"ingress interface", "access policy", "deployed"}


async def test_single_arm_needs_the_zone_both_ways_and_routes_via_the_edge(lab: respx.MockRouter) -> None:
    chain(
        lab,
        [route(BRANCH, "inside", EDGE_IN), route(ANY4, "inside", EDGE_IN)],
        [
            zones_rule("in-out", "ALLOW", ZONES[0], ZONES[1]),  # not the hairpin: skipped
            {**zones_rule("hairpin", "BLOCK", ZONES[0], ZONES[0]), "metadata": {"ruleIndex": 2}},
        ],
    )
    args = {k: v for k, v in DUAL.items() if k not in ("return_address", "service_address")}
    async with Client(server()) as c:
        out = await run(c, "fmc_service_chain_check", {**args, "live": False})
    checks = by_name(out)
    assert out["mode"] == "single-arm" and "chain interface" in checks
    assert "both source and destination zone" in checks["hairpin"]["detail"]
    assert checks["route to destination 0.0.0.0/0"]["ok"] is True
    assert out["flows"][0]["rule"] == "rule 2 'hairpin'" and checks["access policy"]["ok"] is False
    assert not any(k.startswith("link state") for k in checks)
    assert out["trace"]["expect_next_hop"] == EDGE_IN


async def test_no_interface_on_the_edge_link(lab: respx.MockRouter) -> None:
    chain(lab, [], [])
    async with Client(server()) as c:
        out = await run(c, "fmc_service_chain_check", {**DUAL, "edge_address": "172.16.5.1", "live": False})
    c_in = by_name(out)["ingress interface"]
    assert (
        c_in["ok"] is False
        and "172.16.5.1" in c_in["detail"]
        and c_in["fix"].startswith("fmc_update_interface(")
    )
    assert "trace" not in out


# --- the trace leg ----------------------------------------------------------------------------------


async def test_packet_tracer_chain_leg(lab: respx.MockRouter) -> None:
    """ingress_hop picks the interface on the edge's link although the source (a branch host) is routed
    out of another one; expect_next_hop is compared with the route lookup's next hop."""
    lab.get(f"{CFG}/object/networkaddresses").mock(return_value=items([ANY4]))
    lab.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules").mock(return_value=items([]))
    post = lab.post(f"/api/fmc_troubleshoot/v1/domain/{DOMAIN}/packettracer/traces").mock(
        return_value=httpx.Response(200, json=fixture("ftd_packettracer_allow"))
    )
    args = {
        "device": "mcp-ftd1",
        "protocol": "tcp",
        "source_ip": "10.20.0.1",
        "destination_ip": "198.51.100.10",
        "destination_port": 443,
        "ingress_hop": EDGE_IN,
    }
    async with Client(server()) as c:
        good = await run(c, "fmc_packet_tracer", {**args, "expect_next_hop": "192.0.2.10"})
        bad = await run(c, "fmc_packet_tracer", {**args, "expect_next_hop": EDGE_OUT})
    assert json.loads(post.calls.last.request.content)["interface"]["name"] == "inside"
    assert (
        good["input_interface"] == "inside" and "ingress_hop 10.99.1.254" in good["input_interface_found_by"]
    )
    leg = good["chain_leg"]
    assert leg["ingress"] == {"interface": "inside", "hop": EDGE_IN} and leg["verdict"] == "allow"
    assert leg["egress"]["ok"] is True and leg["egress"]["next_hop"] == "192.0.2.10"
    assert leg["egress"]["egress_interface"] == "outside" and "interface_state" not in leg
    assert (
        bad["chain_leg"]["egress"]["ok"] is False
        and "fmc_create_static_route" in bad["chain_leg"]["egress"]["detail"]
    )


async def test_packet_tracer_ingress_hop_not_on_the_device(lab: respx.MockRouter) -> None:
    from fastmcp.exceptions import ToolError

    async with Client(server()) as c:
        try:
            await run(
                c,
                "fmc_packet_tracer",
                {
                    "device": "mcp-ftd1",
                    "protocol": "icmp",
                    "source_ip": "10.20.0.1",
                    "destination_ip": "198.51.100.10",
                    "ingress_hop": "172.16.5.1",
                },
            )
        except ToolError as e:
            assert "fmc_service_chain_check" in str(e)
        else:
            raise AssertionError("expected a refusal")


def test_interface_state_names_a_down_interface() -> None:
    from fmc_mcp.tools.troubleshoot import interface_state, summarize_trace

    resp = copy.deepcopy(fixture("ftd_packettracer_allow"))
    assert summarize_trace(resp, verbose=False)[0].get("interface_state") is None
    resp["deviceResponse"][0]["result"].update(inputStatus="down", inputLineStatus="down")
    assert interface_state(resp["deviceResponse"][0]["result"]) == "input inside down/down"

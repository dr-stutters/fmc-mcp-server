"""F11: VPN topology view, point-to-point build/delete, SD-WAN and RA VPN read."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, items, make_settings

S2S = f"{CFG}/policy/ftds2svpns"
TOPO = {
    "id": "topo-1",
    "name": "mcp-test-s2s",
    "type": "FTDS2SVpn",
    "topologyType": "POINT_TO_POINT",
    "routeBased": False,
    "ikeV2Enabled": True,
}
EP_A = {
    "id": "ep-a",
    "name": "mcp-ftd1",
    "type": "EndPoint",
    "peerType": "PEER",
    "extranet": False,
    "device": {"id": "d1", "name": "mcp-ftd1", "type": "Device"},
    "interface": {"id": "i1", "name": "outside", "type": "PhysicalInterface"},
    "protectedNetworks": {"networks": [{"id": "n1", "name": "mcp-test-ftd-inside-net", "type": "Network"}]},
    "enableNATExempt": True,
    "insideInterface": [{"id": "z1", "name": "mcp-test-ftd-in", "type": "SecurityZone"}],
}
IKE = {
    "id": "ike-1",
    "type": "IkeSettings",
    "ikeV2Settings": {
        "authenticationType": "MANUAL_PRE_SHARED_KEY",
        "manualPreSharedKey": "super-secret-key",
        "policies": [{"id": "pol-des", "name": "DES-SHA-SHA-LATEST", "type": "IKEv2Policy"}],
    },
}
IPSEC = {
    "id": "ips-1",
    "type": "IPSecSettings",
    "cryptoMapType": "STATIC",
    "ikeV2Mode": "TUNNEL",
    "ikeV2IpsecProposal": [{"id": "prop-des", "name": "DES_SHA-1"}],
    "perfectForwardSecrecy": {"enabled": False},
    "lifetimeSeconds": 28800,
    "metadata": {"x": 1},
}
TUNNEL = {
    "id": "t1",
    "vpnTopology": {"id": "topo-1", "name": "mcp-test-s2s"},
    "peerA": {"device": {"name": "mcp-ftd1"}, "ipAddresses": {"v4": ["198.18.128.155"]}},
    "peerB": {"device": {"name": "mcp-test-ha[mcp-ftd3]"}, "ipAddresses": {"v4": ["198.18.128.163"]}},
    "state": "TUNNEL_UP",
    "lastChange": 1792066928000,
}
POLICIES = [
    {
        "id": "pol-aes",
        "name": "AES-GCM-NULL-SHA-LATEST",
        "type": "IKEv2Policy",
        "encryptionAlgorithms": ["AES-GCM"],
    },
    {"id": "pol-des", "name": "DES-SHA-SHA-LATEST", "type": "IKEv2Policy", "encryptionAlgorithms": ["DES"]},
]
PROPOSALS = [
    {"id": "prop-aes", "name": "AES-GCM", "type": "IKEv2IPsecProposal", "encryptionAlgorithms": ["AES-GCM"]},
    {"id": "prop-des", "name": "DES_SHA-1", "type": "IKEv2IPsecProposal", "encryptionAlgorithms": ["DES"]},
]


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, rate_limit=100000))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def topo(fmc: respx.MockRouter, topologies: list[Any] | None = None) -> respx.MockRouter:
    fmc.get(S2S).mock(return_value=items([TOPO] if topologies is None else topologies))
    fmc.get(f"{S2S}/topo-1/endpoints").mock(return_value=items([EP_A]))
    fmc.get(f"{S2S}/topo-1/ikesettings").mock(return_value=items([IKE]))
    fmc.get(f"{S2S}/topo-1/ipsecsettings").mock(return_value=items([IPSEC]))
    fmc.get(f"{CFG}/health/tunnelstatuses").mock(return_value=items([TUNNEL]))
    return fmc


async def test_get_topology_masks_psk(fmc: respx.MockRouter) -> None:
    topo(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_get_vpn_topology", {"topology": "mcp-test-s2s"})
    assert "super-secret-key" not in json.dumps(out)
    assert out["ike"]["ikev2"]["pre_shared_key"] == "********"
    assert out["endpoints"][0]["nat_exempt_inside"] == ["mcp-test-ftd-in"]
    assert out["ipsec"]["ikev2_proposals"] == ["DES_SHA-1"] and out["ipsec"]["pfs"] is False
    assert out["tunnels"][0]["state"] == "TUNNEL_UP" and out["tunnels"][0]["peer_b"].endswith(
        "(198.18.128.163)"
    )


async def test_list_topologies_counts_and_sdwan(fmc: respx.MockRouter) -> None:
    sdwan = {
        "id": "topo-2",
        "name": "sdwan-hub",
        "type": "FTDS2SVpn",
        "topologyType": "HUB_AND_SPOKE",
        "routeBased": True,
        "ikeV2Enabled": True,
        "autoVpnSettings": {"bgpSettings": {"enabled": True}},
    }
    topo(fmc, [TOPO, sdwan])
    async with Client(server()) as c:
        out = await run(c, "fmc_list_vpn_topologies", {"response_format": "json"})
        only = await run(c, "fmc_list_vpn_topologies", {"kind": "sdwan", "response_format": "json"})
    rows = {r["name"]: r for r in out["results"]}
    assert rows["mcp-test-s2s"]["tunnels_up"] == 1 and rows["sdwan-hub"]["kind"] == "SD-WAN (hub and spoke)"
    assert [r["name"] for r in only["results"]] == ["sdwan-hub"]


def build_mocks(fmc: respx.MockRouter, *, evaluation: bool) -> dict[str, Any]:
    fmc.get(S2S).mock(return_value=items([]))
    fmc.get(f"{CFG}/devices/devicerecords").mock(
        return_value=items([{"id": "d1", "name": "mcp-ftd1"}, {"id": "p-1", "name": "mcp-ftd2"}])
    )
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(
        return_value=items([{"id": "ha-1", "name": "mcp-test-ha", "primary": {"id": "p-1"}}])
    )
    for dev in ("d1", "p-1"):
        fmc.get(f"{CFG}/devices/devicerecords/{dev}/physicalinterfaces").mock(
            return_value=items(
                [
                    {
                        "id": f"{dev}-out",
                        "name": "Ethernet0/0",
                        "ifname": "outside",
                        "type": "PhysicalInterface",
                    }
                ]
            )
        )
        for kind in (
            "subinterfaces",
            "etherchannelinterfaces",
            "redundantinterfaces",
            "vlaninterfaces",
            "virtualtunnelinterfaces",
            "loopbackinterfaces",
            "bridgegroupinterfaces",
            "inlinesets",
            "virtualswitches",
        ):
            fmc.get(f"{CFG}/devices/devicerecords/{dev}/{kind}").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/networks").mock(
        return_value=items(
            [
                {"id": "n1", "name": "net-a", "type": "Network"},
                {"id": "n2", "name": "net-b", "type": "Network"},
            ]
        )
    )
    for coll in ("hosts", "ranges", "fqdns", "networkgroups"):
        fmc.get(f"{CFG}/object/{coll}").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/securityzones").mock(
        return_value=items([{"id": "z1", "name": "in-a", "type": "SecurityZone"}])
    )
    fmc.get(f"{CFG}/object/interfacegroups").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/ikev2policies").mock(return_value=items(POLICIES))
    fmc.get(f"{CFG}/object/ikev2ipsecproposals").mock(return_value=items(PROPOSALS))
    fmc.get("/api/fmc_platform/v1/license/smartlicenses").mock(
        return_value=items(
            [{"regStatus": "EVALUATION" if evaluation else "REGISTERED", "exportControl": not evaluation}]
        )
    )
    routes = {
        "topo": fmc.post(S2S).mock(return_value=httpx.Response(201, json=TOPO)),
        "ike_get": fmc.get(f"{S2S}/topo-1/ikesettings").mock(
            return_value=items([{"id": "ike-1", "type": "IkeSettings"}])
        ),
        "ike_put": fmc.put(f"{S2S}/topo-1/ikesettings/ike-1").mock(return_value=httpx.Response(200, json={})),
        "ips_get": fmc.get(f"{S2S}/topo-1/ipsecsettings").mock(return_value=items([IPSEC])),
        "ips_put": fmc.put(f"{S2S}/topo-1/ipsecsettings/ips-1").mock(
            return_value=httpx.Response(200, json={})
        ),
        "ep": fmc.post(f"{S2S}/topo-1/endpoints").mock(
            side_effect=lambda req: httpx.Response(201, json=json.loads(req.content) | {"id": "e"})
        ),
    }
    return routes


ARGS = {
    "name": "mcp-test-s2s",
    "device_a": "mcp-ftd1",
    "interface_a": "outside",
    "networks_a": ["net-a"],
    "nat_exempt_zone_a": "in-a",
    "device_b": "mcp-test-ha",
    "interface_b": "outside",
    "networks_b": ["net-b"],
    "pre_shared_key": "super-secret-key",
}


async def test_create_p2p_in_evaluation_mode_uses_des(fmc: respx.MockRouter) -> None:
    r = build_mocks(fmc, evaluation=True)
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_s2s_vpn", ARGS)
        assert "super-secret-key" not in json.dumps(preview)
        assert preview["preview"]["ike_v2"]["policies"][0]["name"] == "DES-SHA-SHA-LATEST"
        assert any("evaluation mode" in s for s in preview["side_effects"])
        done = await run(c, "fmc_create_s2s_vpn", {**ARGS, "confirm": preview["confirm"]})
    ike = json.loads(r["ike_put"].calls.last.request.content)
    assert ike["ikeV2Settings"]["manualPreSharedKey"] == "super-secret-key"
    ips = json.loads(r["ips_put"].calls.last.request.content)
    assert ips["ikeV2IpsecProposal"][0]["id"] == "prop-des" and "metadata" not in ips
    eps = [json.loads(call.request.content) for call in r["ep"].calls]
    assert eps[0]["device"] == {"id": "d1", "type": "Device", "name": "mcp-ftd1"}
    assert eps[0]["enableNATExempt"] and eps[0]["insideInterface"][0]["id"] == "z1"
    assert eps[1]["device"]["type"] == "DeviceHAPair" and eps[1]["interface"]["id"] == "p-1-out"
    assert "super-secret-key" not in json.dumps(done)


async def test_strong_crypto_blocked_in_evaluation(fmc: respx.MockRouter) -> None:
    build_mocks(fmc, evaluation=True)
    async with Client(server()) as c:
        out = await run(c, "fmc_create_s2s_vpn", {**ARGS, "ike_policies": ["AES-GCM-NULL-SHA-LATEST"]})
    assert out["status"] == "blocked" and "strong-crypto" in out["blockers"][0]


async def test_registered_fmc_defaults_to_aes(fmc: respx.MockRouter) -> None:
    build_mocks(fmc, evaluation=False)
    async with Client(server()) as c:
        out = await run(c, "fmc_create_s2s_vpn", ARGS)
    assert out["preview"]["ipsec"]["ikeV2IpsecProposal"][0]["name"] == "AES-GCM"


async def test_partial_failure_is_reported(fmc: respx.MockRouter) -> None:
    r = build_mocks(fmc, evaluation=True)
    r["ep"].mock(
        return_value=httpx.Response(
            400, json={"error": {"messages": [{"description": "bad super-secret-key"}]}}
        )
    )
    rollback = fmc.delete(f"{S2S}/topo-1").mock(return_value=httpx.Response(200, json={}))
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_s2s_vpn", ARGS)
        res = await c.call_tool(
            "fmc_create_s2s_vpn", {**ARGS, "confirm": preview["confirm"]}, raise_on_error=False
        )
    text = res.content[0].text  # type: ignore[union-attr]
    assert res.is_error and "IPsec settings" in text and "deleted again" in text
    assert "super-secret-key" not in text and rollback.called


@pytest.mark.parametrize(
    "bad",
    [
        {"extranet_ip": "1.2.3.4"},  # both a managed peer and an extranet
        {"networks_b": None},  # policy-based without protected networks
        {"device_b": None, "interface_b": None, "extranet_ip": "nope"},
    ],
)
async def test_create_validation(fmc: respx.MockRouter, bad: dict[str, Any]) -> None:
    build_mocks(fmc, evaluation=True)
    async with Client(server()) as c:
        r = await c.call_tool("fmc_create_s2s_vpn", {**ARGS, **bad}, raise_on_error=False)
    assert r.is_error


async def test_delete_does_not_echo_keys(fmc: respx.MockRouter) -> None:
    topo(fmc)
    fmc.delete(f"{S2S}/topo-1").mock(return_value=httpx.Response(200, json={**TOPO, "ikeSettings": IKE}))
    async with Client(server()) as c:
        preview = await run(c, "fmc_delete_s2s_vpn", {"topology": "mcp-test-s2s"})
        done = await run(c, "fmc_delete_s2s_vpn", {"topology": "mcp-test-s2s", "confirm": preview["confirm"]})
    assert done["result"] == {"deleted": "mcp-test-s2s", "id": "topo-1"}


async def test_ravpn_read(fmc: respx.MockRouter) -> None:
    pol = {"id": "ra-1", "name": "RA-VPN", "type": "RAVpn", "protocol": {"ssl": True, "ipsec_ikev2": True}}
    prof = {
        "id": "cp-1",
        "name": "Employees",
        "groupPolicy": {"name": "DfltGrpPolicy", "id": "g1"},
        "ipv4AddressPool": [{"name": "ra-pool", "id": "pool-1"}],
        "authenticationSettings": {
            "authenticationMethod": "AAA_ONLY",
            "authenticationServer": {"name": "ise", "id": "r1"},
        },
    }
    fmc.get(f"{CFG}/policy/ravpns").mock(return_value=items([pol]))
    fmc.get(f"{CFG}/policy/ravpns/ra-1/connectionprofiles").mock(return_value=items([prof]))
    fmc.get(f"{CFG}/health/ravpngateways").mock(
        return_value=items([{"device": {"name": "mcp-ftd1"}, "activeSessions": 3, "maxSessions": 250}])
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_get_ravpn", {})
    cp = out["policies"][0]["connection_profiles"][0]
    assert cp["group_policy"] == "DfltGrpPolicy" and cp["ipv4_pools"] == ["ra-pool"]
    assert cp["authentication"] == "AAA_ONLY" and cp["aaa_server"] == "ise"
    assert out["policies"][0]["protocols"] == ["SSL", "IPSEC_IKEV2"]
    assert out["gateways"][0] == {"device": "mcp-ftd1", "active_sessions": 3, "max_sessions": 250}

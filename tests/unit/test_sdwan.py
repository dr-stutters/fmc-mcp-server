"""F51a: SD-WAN topology authoring (fmc_create_sdwan_topology / fmc_update_sdwan_topology).

Fixtures: tests/fixtures/sdwan_lab.json, keyed by API path like `capture_fixtures.py --sdwan` writes it.
"""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, fixture, items, make_settings

S2S = f"{CFG}/policy/ftds2svpns"
LAB = fixture("sdwan_lab")
POLICIES = [
    {
        "id": "pol-aes",
        "name": "AES-GCM-NULL-SHA-LATEST",
        "type": "IKEv2Policy",
        "encryptionAlgorithms": ["AES"],
    },
    {"id": "pol-des", "name": "DES-SHA-SHA-LATEST", "type": "IKEv2Policy", "encryptionAlgorithms": ["DES"]},
]
PROPOSALS = [
    {"id": "prop-aes", "name": "AES-GCM", "type": "IKEv2IPsecProposal", "encryptionAlgorithms": ["AES-GCM"]},
    {"id": "prop-des", "name": "DES_SHA-1", "type": "IKEv2IPsecProposal", "encryptionAlgorithms": ["DES"]},
]
NEW_TOPO = {"id": "topo-new", "name": "mcp-sdwan-t9", "type": "FTDS2SVpn", "topologyType": "AUTO_VPN"}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, rate_limit=100000))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def lab(
    fmc: respx.MockRouter,
    *,
    evaluation: bool = False,
    topologies: bool = True,
    fail: dict[str, httpx.Response] | None = None,
) -> list[tuple[str, Any]]:
    """Mount the recorded SD-WAN lab; return the ordered log of writes (method path, body)."""
    for key, data in LAB.items():
        if not key.startswith("_"):
            fmc.get(f"{CFG}/{key}").mock(return_value=httpx.Response(200, json=data))
    if not topologies:
        fmc.get(S2S).mock(return_value=items([]))
    for did in ("d-hub", "d-sp1", "d-sp2", "d-sp3", "d-hub2"):
        for kind in ("subinterfaces", "etherchannelinterfaces", "vlaninterfaces"):
            fmc.get(f"{CFG}/devices/devicerecords/{did}/{kind}").mock(return_value=items([]))
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/interfacegroups").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/ikev2policies").mock(return_value=items(POLICIES))
    fmc.get(f"{CFG}/object/ikev2ipsecproposals").mock(return_value=items(PROPOSALS))
    fmc.get("/api/fmc_platform/v1/license/smartlicenses").mock(
        return_value=items(
            [{"regStatus": "EVALUATION" if evaluation else "REGISTERED", "exportControl": not evaluation}]
        )
    )
    log: list[tuple[str, Any]] = []
    counter = iter(range(1, 1000))

    def write(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content) if req.content else None
        path = req.url.path.removeprefix(CFG + "/")
        log.append((f"{req.method} {path}", body))
        if f"{req.method} {path}" in (fail or {}):
            return (fail or {})[f"{req.method} {path}"]
        if req.method == "POST":
            made = {**(body or {}), "id": f"new-{next(counter)}"}
            if path.endswith("loopbackinterfaces"):
                made["name"] = f"Loopback{body['loopbackId']}"
            if path.endswith("virtualtunnelinterfaces"):
                made["name"] = f"Virtual-Template{body['tunnelId']}"
            if path == "policy/ftds2svpns":
                made = {**NEW_TOPO, **body, "id": "topo-new"}
            return httpx.Response(201, json=made)
        return httpx.Response(200, json={})

    fmc.route(method__in=["POST", "PUT", "DELETE"], path__startswith=CFG).mock(side_effect=write)
    for tid in ("topo-new",):
        fmc.get(f"{S2S}/{tid}/ikesettings").mock(return_value=items([{"id": "ike-n", "type": "IkeSettings"}]))
        fmc.get(f"{S2S}/{tid}/ipsecsettings").mock(
            return_value=items([{"id": "ips-n", "type": "IPSecSettings", "metadata": {"x": 1}}])
        )
    return log


NEW = {
    "name": "mcp-sdwan-t9",
    "hub": "mcp-sdwan-t1-hub2",
    "hub_wan_interface": "outside1",
    "hub_inside_interfaces": ["inside"],
    "tunnel_zone": "mcp-sdwan-overlay",
    "spoke_pool": "10.255.250.0/24",
    "spokes": [
        {
            "device": "mcp-sdwan-t1-spoke3",
            "wan_interface": "outside1",
            "backup_wan_interface": "outside2",
            "inside_interfaces": ["inside"],
        }
    ],
}


async def test_create_builds_pool_loopback_dvti_then_topology(fmc: respx.MockRouter) -> None:
    log = lab(fmc, topologies=False)
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_sdwan_topology", NEW)
        assert preview["status"] == "preview", preview
        steps = preview["preview"]["steps"]
        assert steps[:3] == [
            "create IPv4 address pool 'mcp-sdwan-t9-pool' (10.255.250.2-10.255.250.254)",
            "create loopback 'sdwan-dvti-lo' 10.255.250.1/32 on mcp-sdwan-t1-hub2",
            "create DVTI 'sdwan-dvti' on mcp-sdwan-t1-hub2",
        ]
        assert log == []  # the preview wrote nothing
        done = await run(c, "fmc_create_sdwan_topology", {**NEW, "confirm": preview["confirm"]})
    order = [m for m, _ in log]
    assert order == [
        "POST object/ipv4addresspools",
        "POST devices/devicerecords/d-hub2/loopbackinterfaces",
        "POST devices/devicerecords/d-hub2/virtualtunnelinterfaces",
        "POST policy/ftds2svpns",
        "PUT policy/ftds2svpns/topo-new/ikesettings/ike-n",
        "PUT policy/ftds2svpns/topo-new/ipsecsettings/ips-n",
        "POST policy/ftds2svpns/topo-new/endpoints",
        "POST policy/ftds2svpns/topo-new/endpoints",
    ]
    bodies = [b for _, b in log]
    pool, loop, dvti, topo, ike, ips, hub, spoke = bodies
    assert pool["mask"] == "255.255.255.0" and pool["type"] == "IPv4AddressPool"
    assert loop["loopbackId"] == 1 and loop["ipv4"]["static"]["address"] == "10.255.250.1"
    assert dvti["tunnelType"] == "DYNAMIC" and dvti["tunnelSource"]["id"] == "d-hub2-e0"
    assert dvti["borrowIPfrom"] == {"id": "new-2", "type": "LoopbackInterface", "name": "Loopback1"}
    assert dvti["securityZone"]["id"] == "zone-overlay" and dvti["tunnelId"] == 1
    assert topo["topologyType"] == "AUTO_VPN" and topo["routeBased"] is True
    rs = topo["autoVpnSettings"]["routeSettings"]
    assert rs["enableBgp"] and rs["autonomousSystemNumber"] == 65000 and rs["communityAttribute"] == 1000
    assert rs["distributeConnectedNetwork"]["interfaceSelection"] == "INSIDE_INTERFACE"
    assert topo["autoVpnSettings"]["spokeSvtiSecurityZone"]["id"] == "zone-overlay"
    assert ike["ikeV2Settings"]["authenticationType"] == "AUTOMATIC_PRE_SHARED_KEY"
    assert ips["ikeV2IpsecProposal"][0]["id"] == "prop-aes" and "metadata" not in ips
    assert hub["peerType"] == "HUB" and hub["isPrimaryHub"] is True
    assert hub["interface"]["id"] == "new-3" and hub["ipv4PoolsForSpokeVti"][0]["id"] == "new-1"
    assert hub["insideInterface"][0]["id"] == "d-hub2-e2"
    assert spoke["peerType"] == "SPOKE" and spoke["interface"]["id"] == "d-sp3-e0"
    assert spoke["backupInterfaces"] == [
        {"interface": {"id": "d-sp3-e1", "type": "PhysicalInterface", "name": "Ethernet0/1"}}
    ]
    assert done["result"]["topology"]["kind"] == "SD-WAN (hub and spoke)"


async def test_create_reuses_dvti_and_pool_with_backup_hub(fmc: respx.MockRouter) -> None:
    log = lab(fmc, topologies=False)
    args = {
        "name": "mcp-sdwan-t9",
        "hub": "mcp-sdwan-t1-hub",
        "hub_dvti": "sdwan-dvti",
        "tunnel_zone": "mcp-sdwan-overlay",
        "spoke_pool": "mcp-sdwan-t1-pool",
        "backup_hub": "mcp-sdwan-t1-hub2",
        "backup_hub_wan_interface": "Ethernet0/0",
        "backup_spoke_pool": "10.255.255.128/25",  # overlaps the primary's 10.255.255.0/24
        "spokes": [{"device": "mcp-sdwan-t1-spoke3", "wan_interface": "outside1"}],
    }
    async with Client(server()) as c:
        blocked = await run(c, "fmc_create_sdwan_topology", args)
        assert blocked["status"] == "blocked" and "overlap" in blocked["blockers"][0]
        args["backup_spoke_pool"] = "10.255.254.0/24"
        preview = await run(c, "fmc_create_sdwan_topology", args)
        assert preview["status"] == "preview", preview
        hubs = preview["preview"]["hubs"]
        assert hubs[0]["dvti"] == "Virtual-Template1" and hubs[0]["spoke_pool"] == "mcp-sdwan-t1-pool"
        assert hubs[1]["role"] == "backup hub" and "(new" in hubs[1]["dvti"]
        await run(c, "fmc_create_sdwan_topology", {**args, "confirm": preview["confirm"]})
    order = [m for m, _ in log]
    assert order[:3] == [  # nothing created for the primary hub: its DVTI and pool exist
        "POST object/ipv4addresspools",
        "POST devices/devicerecords/d-hub2/loopbackinterfaces",
        "POST devices/devicerecords/d-hub2/virtualtunnelinterfaces",
    ]
    eps = [b for m, b in log if m.endswith("/endpoints")]
    assert eps[0]["interface"]["id"] == "dvti-hub" and eps[0]["ipv4PoolsForSpokeVti"][0]["id"] == "pool-t1"
    assert eps[1]["isPrimaryHub"] is False and eps[1]["ipv4PoolsForSpokeVti"][0]["id"] == "new-1"
    assert [e["peerType"] for e in eps] == ["HUB", "HUB", "SPOKE"]


@pytest.mark.parametrize(
    ("change", "blocker"),
    [
        ({"spokes": [{"device": "mcp-sdwan-t1-spoke3", "wan_interface": "Ethernet0/3"}]}, "no security zone"),
        ({"hub": "mcp-sdwan-t1-hub", "hub_dvti": "legacy-s2s"}, "dynamic VTI"),
        ({"name": "mcp-sdwan-t1"}, "already exists"),
    ],
)
async def test_create_blockers(fmc: respx.MockRouter, change: dict[str, Any], blocker: str) -> None:
    lab(fmc)  # the recorded topology mcp-sdwan-t1 exists
    async with Client(server()) as c:
        out = await run(c, "fmc_create_sdwan_topology", {**NEW, **change})
    assert out["status"] == "blocked" and any(blocker in b for b in out["blockers"]), out


@pytest.mark.parametrize(
    "bad",
    [
        {"backup_hub": "mcp-sdwan-t1-hub"},  # no backup pool
        {"backup_spoke_pool": "10.1.0.0/24"},  # backup settings without a backup hub
        {"backup_hub": "mcp-sdwan-t1-hub2", "backup_spoke_pool": "10.1.0.0/24"},  # same device as hub
        {"spokes": [{"device": "mcp-sdwan-t1-hub2", "wan_interface": "outside1"}]},  # the hub as a spoke
        {"spoke_pool": "10.255.250.0/30"},  # too small
        {"hub_wan_interface": None},  # no DVTI on hub2 and nothing to build one from
    ],
)
async def test_create_validation(fmc: respx.MockRouter, bad: dict[str, Any]) -> None:
    lab(fmc, topologies=False)
    async with Client(server()) as c:
        r = await c.call_tool("fmc_create_sdwan_topology", {**NEW, **bad}, raise_on_error=False)
    assert r.is_error


async def test_failure_rolls_back_newest_first_and_masks_key(fmc: respx.MockRouter) -> None:
    bad = httpx.Response(400, json={"error": {"messages": [{"description": "bad key sekrit-key-123"}]}})
    log = lab(fmc, topologies=False, fail={"POST policy/ftds2svpns/topo-new/endpoints": bad})
    args = {**NEW, "pre_shared_key": "sekrit-key-123"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_sdwan_topology", args)
        assert "sekrit-key-123" not in json.dumps(preview)
        assert preview["preview"]["ike_v2"]["manualPreSharedKey"] == "********"
        res = await c.call_tool(
            "fmc_create_sdwan_topology", {**args, "confirm": preview["confirm"]}, raise_on_error=False
        )
    text = res.content[0].text  # type: ignore[union-attr]
    assert res.is_error and "sekrit-key-123" not in text and "deleted again" in text
    deletes = [m for m, _ in log if m.startswith("DELETE")]
    assert deletes == [
        "DELETE policy/ftds2svpns/topo-new",
        "DELETE devices/devicerecords/d-hub2/virtualtunnelinterfaces/new-3",
        "DELETE devices/devicerecords/d-hub2/loopbackinterfaces/new-2",
        "DELETE object/ipv4addresspools/new-1",
    ]


async def test_evaluation_mode_and_ospf_overlay(fmc: respx.MockRouter) -> None:
    lab(fmc, evaluation=True, topologies=False)
    async with Client(server()) as c:
        out = await run(c, "fmc_create_sdwan_topology", {**NEW, "overlay": "ospf"})
    assert out["preview"]["ike_v2"]["policies"][0]["name"] == "DES-SHA-SHA-LATEST"
    assert out["preview"]["topology"]["autoVpnSettings"]["routeSettings"] == {"enableBgp": False}
    assert any("fmc_configure_ospf" in s for s in out["side_effects"])
    # FMC 10.0.1: unnumbered hub DVTI vs numbered spoke VTIs -> no OSPF routes on the spokes (R5)
    assert any("unnumbered" in s and "overlay='bgp'" in s for s in out["side_effects"])
    assert "not-reachable" in out["preview"]["warnings"][0]
    assert any("strong-crypto" in s for s in out["side_effects"])


async def test_bgp_overlay_has_no_ospf_warning(fmc: respx.MockRouter) -> None:
    lab(fmc, topologies=False)
    async with Client(server()) as c:
        out = await run(c, "fmc_create_sdwan_topology", NEW)
    assert "warnings" not in out["preview"]
    assert not any("unnumbered" in s for s in out["side_effects"])


async def test_update_adds_and_removes_spokes(fmc: respx.MockRouter) -> None:
    log = lab(fmc)
    args = {
        "topology": "mcp-sdwan-t1",
        "add_spokes": [{"device": "mcp-sdwan-t1-spoke3", "wan_interface": "outside2"}],
        "remove_spokes": ["mcp-sdwan-t1-spoke2"],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_update_sdwan_topology", args)
        assert preview["status"] == "preview", preview
        after = preview["preview"]["endpoints_after"]
        assert "mcp-sdwan-t1-spoke2 (spoke)" not in after and "mcp-sdwan-t1-spoke3 (spoke)" in after
        assert "mcp-sdwan-t1-hub" in preview["side_effects"][0]  # the hub is deployed too
        await run(c, "fmc_update_sdwan_topology", {**args, "confirm": preview["confirm"]})
    assert [m for m, _ in log] == [
        "DELETE policy/ftds2svpns/topo-t1/endpoints/ep-spoke2",
        "POST policy/ftds2svpns/topo-t1/endpoints",
    ]
    assert log[1][1]["interface"]["id"] == "d-sp3-e1"


async def test_update_backup_hub_checks_pools(fmc: respx.MockRouter) -> None:
    log = lab(fmc)
    fmc.get(f"{CFG}/object/ipv4addresspools/pool-t1").mock(
        return_value=httpx.Response(200, json=LAB["object/ipv4addresspools"]["items"][0])
    )
    args = {
        "topology": "mcp-sdwan-t1",
        "add_backup_hub": "mcp-sdwan-t1-hub2",
        "backup_hub_wan_interface": "outside1",
        "backup_spoke_pool": "10.255.255.0/24",
    }
    async with Client(server()) as c:
        blocked = await run(c, "fmc_update_sdwan_topology", args)
        assert blocked["status"] == "blocked" and "overlap" in blocked["blockers"][0]
        args["backup_spoke_pool"] = "10.255.253.0/24"
        preview = await run(c, "fmc_update_sdwan_topology", args)
        deploy = preview["side_effects"][0]
        assert all(f"mcp-sdwan-t1-{r}" in deploy for r in ("hub", "hub2", "spoke1", "spoke2"))
        await run(c, "fmc_update_sdwan_topology", {**args, "confirm": preview["confirm"]})
    ep = [b for m, b in log if m.endswith("/endpoints")][0]
    assert ep["peerType"] == "HUB" and ep["isPrimaryHub"] is False and ep["interface"]["id"] == "new-3"


async def test_update_multipath_and_guards(fmc: respx.MockRouter) -> None:
    log = lab(fmc)
    async with Client(server()) as c:
        preview = await run(c, "fmc_update_sdwan_topology", {"topology": "mcp-sdwan-t1", "multipath": False})
        await run(
            c,
            "fmc_update_sdwan_topology",
            {"topology": "mcp-sdwan-t1", "multipath": False, "confirm": preview["confirm"]},
        )
        primary = await c.call_tool(
            "fmc_update_sdwan_topology",
            {"topology": "mcp-sdwan-t1", "remove_backup_hub": "mcp-sdwan-t1-hub"},
            raise_on_error=False,
        )
        nothing = await c.call_tool(
            "fmc_update_sdwan_topology", {"topology": "mcp-sdwan-t1"}, raise_on_error=False
        )
        not_spoke = await c.call_tool(
            "fmc_update_sdwan_topology",
            {"topology": "mcp-sdwan-t1", "remove_spokes": ["mcp-sdwan-t1-spoke3"]},
            raise_on_error=False,
        )
    method, body = log[0]
    assert method == "PUT policy/ftds2svpns/topo-t1"
    assert body["autoVpnSettings"]["routeSettings"]["enableMultiPath"] is False
    assert body["autoVpnSettings"]["routeSettings"]["autonomousSystemNumber"] == 65000
    assert primary.is_error and "primary hub" in primary.content[0].text  # type: ignore[union-attr]
    assert nothing.is_error and not_spoke.is_error


async def test_update_refuses_classic_topology(fmc: respx.MockRouter) -> None:
    lab(fmc)
    fmc.get(S2S).mock(
        return_value=items(
            [{"id": "p2p", "name": "mcp-sdwan-p2p", "type": "FTDS2SVpn", "topologyType": "POINT_TO_POINT"}]
        )
    )
    async with Client(server()) as c:
        r = await c.call_tool(
            "fmc_update_sdwan_topology",
            {"topology": "mcp-sdwan-p2p", "multipath": True},
            raise_on_error=False,
        )
    assert r.is_error and "not an SD-WAN topology" in r.content[0].text  # type: ignore[union-attr]


async def test_get_topology_shows_sdwan_roles(fmc: respx.MockRouter) -> None:
    lab(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_get_vpn_topology", {"topology": "mcp-sdwan-t1"})
    eps = {e["name"]: e for e in out["endpoints"]}
    assert out["kind"] == "SD-WAN (hub and spoke)"
    assert eps["mcp-sdwan-t1-hub"]["primary_hub"] is True
    assert eps["mcp-sdwan-t1-hub"]["spoke_pools"] == ["mcp-sdwan-t1-pool"]
    assert eps["mcp-sdwan-t1-spoke1"]["backup_interfaces"] == ["Ethernet0/1"]
    assert "primary_hub" not in eps["mcp-sdwan-t1-spoke2"]

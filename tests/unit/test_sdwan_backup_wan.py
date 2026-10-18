"""SD-WAN R1: a spoke's second WAN tunnel (spokes[].backup_wan_interface).

FMC 10.0.1 drops `backupInterfaces` on AUTO_VPN spokes, refuses it on hubs and allows one endpoint per
device per topology. What works live (mcp-sdwan-t1, 2026-10-18; tests/fixtures/sdwan_backup_wan.json):
a companion AUTO_VPN topology '<name>-wan2' with the same hub on a second DVTI (second WAN, own
loopback and pool) and each spoke on its backup WAN. The spoke then has two VTIs, two IKEv2 SAs and two
iBGP sessions, and fails over to the other tunnel when one WAN goes down.
"""

from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from .conftest import fixture, items
from .test_sdwan import LAB, NEW, S2S, lab, run, server

REC = fixture("sdwan_backup_wan")
WAN2 = {
    **NEW,
    "hub_backup_wan_interface": "outside2",
    "backup_wan_pool": "10.255.249.0/24",
    "spokes": [
        {
            "device": "mcp-sdwan-t1-spoke3",
            "wan_interface": "outside1",
            "backup_wan_interface": "outside2",
            "inside_interfaces": ["inside"],
        },
        {"device": "mcp-sdwan-t1-spoke2", "wan_interface": "outside1"},  # no second WAN
    ],
}


def _spoke_fields(ep: dict[str, Any]) -> dict[str, Any]:
    """The request-side fields of a recorded spoke endpoint GET (metadata is read-only)."""
    return {k: v for k, v in ep.items() if k not in ("metadata", "links", "id")}


async def test_recorded_endpoints_show_one_vti_per_topology() -> None:
    """The recorded GETs: each topology's spoke endpoint holds exactly one VTI, sourced from the WAN
    the endpoint names; the companion's VTI is addressed from the second hub's pool."""
    main, wan2 = REC["spoke_endpoint_main"], REC["spoke_endpoint_wan2"]
    for ep in (main, wan2):
        vtis = ep["metadata"]["vtiInterfaceMetadataList"]
        assert len(vtis) == 1 and "backupInterfaces" not in ep
        assert vtis[0]["tunnelSourceInterface"]["id"] == ep["interface"]["id"]
        assert vtis[0]["hubDevice"]["id"] == "d-hub"
    assert main["interface"]["id"] != wan2["interface"]["id"]
    assert main["device"] == wan2["device"]
    addr = wan2["metadata"]["vtiInterfaceMetadataList"][0]["vtiInterface"]["ipv4"]["static"]["address"]
    assert addr.startswith("10.255.254.")
    assert "should not be configured on hub" in str(REC["refused"])


async def test_create_with_backup_wan_builds_a_companion_topology(fmc: respx.MockRouter) -> None:
    log = lab(fmc, topologies=False)
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_sdwan_topology", WAN2)
        assert preview["status"] == "preview", preview
        bw = preview["preview"]["backup_wan"]
        assert bw["topology"] == "mcp-sdwan-t9-wan2"
        assert bw["hub"]["dvti"] == "sdwan-dvti-wan2 (new)" and bw["hub"]["dvti_source"] == "Ethernet0/1"
        assert [s["device"] for s in bw["spokes"]] == ["mcp-sdwan-t1-spoke3"]
        assert any(
            "mcp-sdwan-t9-wan2" in e and "drops backupInterfaces" in e for e in preview["side_effects"]
        )
        assert preview["preview"]["steps"][-2:] == [
            "add hub mcp-sdwan-t1-hub2 on its second-WAN DVTI to 'mcp-sdwan-t9-wan2'",
            "add spoke mcp-sdwan-t1-spoke3 on its backup WAN to 'mcp-sdwan-t9-wan2'",
        ]
        assert log == []
        done = await run(c, "fmc_create_sdwan_topology", {**WAN2, "confirm": preview["confirm"]})
    assert [m for m, _ in log] == [
        "POST object/ipv4addresspools",
        "POST devices/devicerecords/d-hub2/loopbackinterfaces",
        "POST devices/devicerecords/d-hub2/virtualtunnelinterfaces",
        "POST object/ipv4addresspools",
        "POST devices/devicerecords/d-hub2/loopbackinterfaces",
        "POST devices/devicerecords/d-hub2/virtualtunnelinterfaces",
        "POST policy/ftds2svpns",
        "PUT policy/ftds2svpns/topo-new/ikesettings/ike-n",
        "PUT policy/ftds2svpns/topo-new/ipsecsettings/ips-n",
        "POST policy/ftds2svpns/topo-new/endpoints",
        "POST policy/ftds2svpns/topo-new/endpoints",
        "POST policy/ftds2svpns/topo-new/endpoints",
        "POST policy/ftds2svpns",
        "PUT policy/ftds2svpns/topo-new-wan2/ikesettings/ike-n",
        "PUT policy/ftds2svpns/topo-new-wan2/ipsecsettings/ips-n",
        "POST policy/ftds2svpns/topo-new-wan2/endpoints",
        "POST policy/ftds2svpns/topo-new-wan2/endpoints",
    ]
    b = [body for _, body in log]
    pool1, lo1, dvti1, pool2, lo2, dvti2, topo1 = b[:7]
    assert pool1["name"] == "mcp-sdwan-t9-pool" and pool2["name"] == "mcp-sdwan-t9-wan2-pool"
    assert pool2["ipAddressRange"] == "10.255.249.2-10.255.249.254"
    # two loopbacks and two DVTIs on one hub: distinct ids, each DVTI on its own WAN and loopback
    assert (lo1["loopbackId"], lo2["loopbackId"]) == (1, 2)
    assert lo2["ipv4"]["static"]["address"] == "10.255.249.1"
    assert (dvti1["tunnelId"], dvti2["tunnelId"]) == (1, 2)
    assert dvti1["tunnelSource"]["id"] == "d-hub2-e0" and dvti2["tunnelSource"]["id"] == "d-hub2-e1"
    assert dvti2["borrowIPfrom"]["id"] == "new-5" and dvti2["securityZone"]["id"] == "zone-overlay"
    topo2 = b[12]
    assert topo1["name"] == "mcp-sdwan-t9" and topo2["name"] == "mcp-sdwan-t9-wan2"
    # the same iBGP / overlay settings: both topologies feed one router bgp on each device
    assert topo1["autoVpnSettings"] == topo2["autoVpnSettings"]
    assert b[13]["ikeV2Settings"] == b[7]["ikeV2Settings"]
    hub1, sp3, sp2 = b[9:12]
    hub2, sp3_wan2 = b[15:17]
    assert hub1["interface"]["id"] == "new-3" and hub2["interface"]["id"] == "new-6"
    assert hub2["peerType"] == "HUB" and hub2["isPrimaryHub"] is True
    assert hub2["ipv4PoolsForSpokeVti"][0]["id"] == "new-4"
    assert sp3["interface"]["id"] == "d-sp3-e0" and sp3_wan2["interface"]["id"] == "d-sp3-e1"
    assert sp2["device"]["name"] == "mcp-sdwan-t1-spoke2"
    for ep in (hub1, sp3, sp2, hub2, sp3_wan2):
        assert "backupInterfaces" not in ep  # FMC 10.0.1 drops it (spokes) or refuses it (hubs)
    # the companion's spoke endpoint carries what the recorded working endpoint carries
    rec = _spoke_fields(REC["spoke_endpoint_wan2"])
    assert set(sp3_wan2) - {"insideInterface"} <= set(rec)
    assert sp3_wan2["peerType"] == rec["peerType"] and sp3_wan2["connectionType"] == rec["connectionType"]
    assert sp3_wan2["interface"]["type"] == rec["interface"]["type"] == "PhysicalInterface"
    res = done["result"]
    assert res["backup_wan_topology"]["topology"]["name"] == "mcp-sdwan-t9-wan2"
    assert len(res["backup_wan_topology"]["endpoints"]) == 2
    assert "'mcp-sdwan-t9-wan2'" in res["next"]


async def test_companion_failure_undoes_both_topologies(fmc: respx.MockRouter) -> None:
    bad = httpx.Response(400, json={"error": {"messages": [{"description": "Invalid interface"}]}})
    log = lab(fmc, topologies=False, fail={"POST policy/ftds2svpns/topo-new-wan2/endpoints": bad})
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_sdwan_topology", WAN2)
        r = await c.call_tool(
            "fmc_create_sdwan_topology", {**WAN2, "confirm": preview["confirm"]}, raise_on_error=False
        )
    assert r.is_error and "deleted again" in r.content[0].text  # type: ignore[union-attr]
    assert [m for m, _ in log if m.startswith("DELETE")] == [
        "DELETE policy/ftds2svpns/topo-new-wan2",
        "DELETE policy/ftds2svpns/topo-new",
        "DELETE devices/devicerecords/d-hub2/virtualtunnelinterfaces/new-6",
        "DELETE devices/devicerecords/d-hub2/loopbackinterfaces/new-5",
        "DELETE object/ipv4addresspools/new-4",
        "DELETE devices/devicerecords/d-hub2/virtualtunnelinterfaces/new-3",
        "DELETE devices/devicerecords/d-hub2/loopbackinterfaces/new-2",
        "DELETE object/ipv4addresspools/new-1",
    ]


async def test_backup_wan_reuses_an_existing_second_dvti(fmc: respx.MockRouter) -> None:
    """The recorded hub already has a DVTI 'sdwan-dvti' (tunnel 1, loopback 1): a new second-WAN DVTI
    takes the next free ids, and its pool must not overlap the primary's."""
    log = lab(fmc, topologies=False)
    args = {
        **WAN2,
        "hub": "mcp-sdwan-t1-hub",
        "hub_dvti": "sdwan-dvti",
        "spoke_pool": "mcp-sdwan-t1-pool",
        "backup_wan_pool": "10.255.255.128/25",  # inside the primary's 10.255.255.0/24
    }
    async with Client(server()) as c:
        blocked = await run(c, "fmc_create_sdwan_topology", args)
        assert blocked["status"] == "blocked" and any("overlap" in x for x in blocked["blockers"])
        args["backup_wan_pool"] = "10.255.249.0/24"
        preview = await run(c, "fmc_create_sdwan_topology", args)
        await run(c, "fmc_create_sdwan_topology", {**args, "confirm": preview["confirm"]})
    lo, dvti = (b for m, b in log if m.endswith(("loopbackinterfaces", "virtualtunnelinterfaces")))
    assert lo["loopbackId"] == 2 and dvti["tunnelId"] == 2  # recorded hub has tunnel 9 too: 2 is free
    assert dvti["tunnelSource"]["id"] == "d-hub-e1"


@pytest.mark.parametrize(
    "bad",
    [
        {"backup_wan_pool": None},  # backup WAN spokes but no pool for the second DVTI
        {"spokes": [{"device": "mcp-sdwan-t1-spoke3", "wan_interface": "outside1"}]},  # pool, no backup spoke
        {"hub_backup_dvti": "sdwan-dvti"},  # the same DVTI as the primary
        {"hub_backup_wan_interface": None},  # no second DVTI on hub2 and nothing to build it from
    ],
)
async def test_backup_wan_validation(fmc: respx.MockRouter, bad: dict[str, Any]) -> None:
    lab(fmc, topologies=False)
    async with Client(server()) as c:
        r = await c.call_tool("fmc_create_sdwan_topology", {**WAN2, **bad}, raise_on_error=False)
    assert r.is_error


async def test_backup_wan_with_backup_hub_is_blocked(fmc: respx.MockRouter) -> None:
    lab(fmc, topologies=False)
    args = {
        **WAN2,
        "hub": "mcp-sdwan-t1-hub",
        "hub_dvti": "sdwan-dvti",
        "spoke_pool": "mcp-sdwan-t1-pool",
        "backup_hub": "mcp-sdwan-t1-hub2",
        "backup_hub_wan_interface": "outside1",
        "backup_spoke_pool": "10.255.248.0/24",
    }
    async with Client(server()) as c:
        out = await run(c, "fmc_create_sdwan_topology", args)
    assert out["status"] == "blocked" and any("backup hub" in b for b in out["blockers"]), out


async def test_backup_wan_companion_name_taken(fmc: respx.MockRouter) -> None:
    lab(fmc)
    fmc.get(S2S).mock(
        return_value=items([{**LAB["policy/ftds2svpns"]["items"][0], "name": "mcp-sdwan-t9-wan2"}])
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_create_sdwan_topology", WAN2)
    assert out["status"] == "blocked" and any(
        "'mcp-sdwan-t9-wan2' already exists" in b for b in out["blockers"]
    )


def _with_companion(fmc: respx.MockRouter) -> None:
    """topo-t1 plus its companion 'mcp-sdwan-t1-wan2' (hub on its second DVTI, spoke1 on its 2nd WAN)."""
    t1 = LAB["policy/ftds2svpns"]["items"][0]
    wan2 = {**t1, "id": "topo-t1-wan2", "name": "mcp-sdwan-t1-wan2"}
    fmc.get(S2S).mock(return_value=items([t1, wan2]))
    rec = REC["spoke_endpoint_wan2"]
    fmc.get(f"{S2S}/topo-t1-wan2/endpoints").mock(
        return_value=items(
            [
                {
                    "id": "ep-wan2-hub",
                    "name": "mcp-sdwan-t1-hub",
                    "type": "EndPoint",
                    "peerType": "HUB",
                    "isPrimaryHub": True,
                    "device": {"id": "d-hub", "name": "mcp-sdwan-t1-hub", "type": "Device"},
                },
                {**_spoke_fields(rec), "id": rec["id"]},
            ]
        )
    )


async def test_update_adds_the_backup_wan_to_the_companion(fmc: respx.MockRouter) -> None:
    log = lab(fmc)
    _with_companion(fmc)
    args = {
        "topology": "mcp-sdwan-t1",
        "add_spokes": [
            {"device": "mcp-sdwan-t1-spoke3", "wan_interface": "outside1", "backup_wan_interface": "outside2"}
        ],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_update_sdwan_topology", args)
        assert preview["status"] == "preview", preview
        assert (
            "mcp-sdwan-t1-spoke3 (spoke, backup WAN in mcp-sdwan-t1-wan2)"
            in preview["preview"]["endpoints_after"]
        )
        await run(c, "fmc_update_sdwan_topology", {**args, "confirm": preview["confirm"]})
    assert [m for m, _ in log] == [
        "POST policy/ftds2svpns/topo-t1/endpoints",
        "POST policy/ftds2svpns/topo-t1-wan2/endpoints",
    ]
    main, wan2 = (b for _, b in log)
    assert main["interface"]["id"] == "d-sp3-e0" and wan2["interface"]["id"] == "d-sp3-e1"
    assert "backupInterfaces" not in main and "backupInterfaces" not in wan2


async def test_update_backup_wan_without_companion_is_blocked(fmc: respx.MockRouter) -> None:
    log = lab(fmc)
    args = {
        "topology": "mcp-sdwan-t1",
        "add_spokes": [
            {"device": "mcp-sdwan-t1-spoke3", "wan_interface": "outside1", "backup_wan_interface": "outside2"}
        ],
    }
    async with Client(server()) as c:
        out = await run(c, "fmc_update_sdwan_topology", args)
    assert out["status"] == "blocked" and any("mcp-sdwan-t1-wan2" in b for b in out["blockers"])
    assert log == []


async def test_update_removes_spoke_from_both_and_sets_multipath_on_both(fmc: respx.MockRouter) -> None:
    log = lab(fmc)
    _with_companion(fmc)
    args = {"topology": "mcp-sdwan-t1", "remove_spokes": ["mcp-sdwan-t1-spoke1"], "multipath": False}
    async with Client(server()) as c:
        preview = await run(c, "fmc_update_sdwan_topology", args)
        assert any("also leave" in e for e in preview["side_effects"])
        await run(c, "fmc_update_sdwan_topology", {**args, "confirm": preview["confirm"]})
    assert [m for m, _ in log] == [
        "PUT policy/ftds2svpns/topo-t1",
        "PUT policy/ftds2svpns/topo-t1-wan2",
        "DELETE policy/ftds2svpns/topo-t1-wan2/endpoints/ep-wan2-spoke1",
        "DELETE policy/ftds2svpns/topo-t1/endpoints/ep-spoke1",
    ]
    assert log[1][1]["name"] == "mcp-sdwan-t1-wan2"
    assert log[1][1]["autoVpnSettings"]["routeSettings"]["enableMultiPath"] is False


async def test_update_keeps_companion_untouched_for_other_changes(fmc: respx.MockRouter) -> None:
    log = lab(fmc)
    _with_companion(fmc)
    args = {"topology": "mcp-sdwan-t1", "remove_spokes": ["mcp-sdwan-t1-spoke2"]}  # not in the companion
    async with Client(server()) as c:
        preview = await run(c, "fmc_update_sdwan_topology", args)
        await run(c, "fmc_update_sdwan_topology", {**args, "confirm": preview["confirm"]})
    assert [m for m, _ in log] == ["DELETE policy/ftds2svpns/topo-t1/endpoints/ep-spoke2"]


async def test_delete_preview_names_the_companion(fmc: respx.MockRouter) -> None:
    lab(fmc)
    _with_companion(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_delete_s2s_vpn", {"topology": "mcp-sdwan-t1"})
        alone = await run(c, "fmc_delete_s2s_vpn", {"topology": "mcp-sdwan-t1-wan2"})
    assert any("'mcp-sdwan-t1-wan2'" in e and "stays" in e for e in out["side_effects"])
    assert len(alone["side_effects"]) == 1

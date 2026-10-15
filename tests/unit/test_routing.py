"""Routing depth (F6), with payload shapes recorded from FMC 10.0.1 + FTDv 10.0."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, empty, items, make_settings

DEV = {"id": "2c11eaca-c7e3-11f1-a7ce-a8b537b1b4bb", "name": "mcp-ftd1", "type": "Device"}
R = f"{CFG}/devices/devicerecords/{DEV['id']}/routing"
NET = {
    "id": "00000000-0000-0ed3-0000-021474848522",
    "name": "mcp-test-ftd-inside-net",
    "type": "Network",
    "value": "10.99.1.0/24",
}
GENERAL = {"id": "g1", "type": "BGPGeneralSetting", "asNumber": "65000", "routerId": "AUTOMATIC"}
BGP = {
    "id": "b1",
    "type": "bgp",
    "name": "bgp",
    "asNumber": "65000",
    "addressFamilyIPv4": {
        "type": "afipv4",
        "id": "af1",
        "neighbors": [
            {
                "type": "neighboripv4",
                "ipv4Address": "10.99.1.2",
                "remoteAs": "65001",
                "neighborGeneral": {"shutdown": False, "fallOverBFD": "NONE", "enableAddress": True},
                "neighborAdvanced": {"neighborHops": {"maxHopCount": 1}},
            }
        ],
        "networks": [{"ipv4Address": {"type": "Network", "name": NET["name"], "id": NET["id"]}}],
        "maximumPaths": [{"value": 1}],
    },
}
OSPF = {
    "id": "o1",
    "type": "OspfRoute",
    "processId": "1",
    "enableProcess": "PROCESS_1",
    "areas": [
        {
            "areaId": "0",
            "areaType": {"type": "normal"},
            "areaNetworks": [{"type": "Network", "name": NET["name"], "id": NET["id"]}],
        }
    ],
    "processConfiguration": {"rfc1583Compatible": False},
}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def _paged(rows: list[dict[str, Any]], count: int | None = None) -> httpx.Response:
    return httpx.Response(
        200, json={"items": rows, "paging": {"count": len(rows) if count is None else count}}
    )


@pytest.fixture
def rt(fmc: respx.MockRouter) -> respx.MockRouter:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get(f"{R}/bgpgeneralsettings").mock(return_value=_paged([GENERAL]))
    fmc.get(f"{R}/bgp").mock(return_value=_paged([BGP]))
    fmc.get(f"{R}/ospfv2routes").mock(return_value=_paged([OSPF], count=2))  # FMC's count is off by one
    fmc.get(f"{R}/virtualrouters").mock(return_value=_paged([{"id": "vr-g", "name": "Global"}]))
    for sub in (
        "ipv4staticroutes",
        "ipv6staticroutes",
        "ospfinterface",
        "ecmpzones",
        "policybasedroutes",
        "bfdpolicies",
        "ospfv3routes",
    ):
        fmc.get(f"{R}/{sub}").mock(return_value=empty())
    fmc.get(f"{CFG}/object/networks").mock(return_value=items([NET]))
    fmc.get(f"{CFG}/object/hosts").mock(return_value=empty())
    return fmc


async def test_get_routing(rt: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_get_routing", {"device": "mcp-ftd1"})
    assert out["bgp"]["as"] == "65000"
    assert out["bgp"]["ipv4"]["neighbors"][0] == {
        "address": "10.99.1.2",
        "remote_as": "65001",
        "enabled": True,
        "description": None,
        "bfd": None,
        "update_source": None,
        "ebgp_multihop": 1,
        "password_set": None,
    }
    assert out["bgp"]["ipv4"]["networks"] == [NET["name"]]
    assert len(out["ospfv2"]) == 1 and out["ospfv2"][0]["areas"][0]["networks"] == [NET["name"]]
    assert "vrfs" not in out


async def test_add_neighbor_keeps_the_rest(rt: respx.MockRouter) -> None:
    put = rt.put(f"{R}/bgp/b1").mock(return_value=httpx.Response(200, json={}))
    args = {"device": "mcp-ftd1", "neighbor": "10.99.1.3", "remote_as": "65002", "withdraw": ["10.99.1.0/24"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    af = json.loads(put.calls.last.request.content)["addressFamilyIPv4"]
    assert [n["ipv4Address"] for n in af["neighbors"]] == ["10.99.1.2", "10.99.1.3"]
    assert af["neighbors"][0]["neighborAdvanced"] == {"neighborHops": {"maxHopCount": 1}}  # untouched
    assert af["networks"] == [] and "maximumPaths" not in af  # FMC rejects it on PUT
    assert body_neighbors_have_no_secret(af)


def body_neighbors_have_no_secret(af: dict[str, Any]) -> bool:
    return all("neighborSecret" not in (n.get("neighborAdvanced") or {}) for n in af["neighbors"])


async def test_masked_neighbor_password_blocks_edit_until_reentered(rt: respx.MockRouter) -> None:
    masked = json.loads(json.dumps(BGP))
    masked["addressFamilyIPv4"]["neighbors"][0]["neighborAdvanced"]["neighborSecret"] = "*" * 11
    rt.get(f"{R}/bgp").mock(return_value=_paged([masked]))
    put = rt.put(f"{R}/bgp/b1").mock(return_value=httpx.Response(200, json={}))
    async with Client(server()) as c:
        out = await run(
            c, "fmc_configure_bgp", {"device": "mcp-ftd1", "advertise": ["10.99.1.0/24"], "withdraw": []}
        )
        assert out["status"] == "blocked" and any("MD5 password" in b for b in out["blockers"])
        args = {
            "device": "mcp-ftd1",
            "neighbor": "10.99.1.2",
            "neighbor_password": "S3cret!",
            "neighbor_description": "peer1",
        }
        preview = await run(c, "fmc_configure_bgp", args)
        assert "S3cret!" not in json.dumps(preview)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    n = json.loads(put.calls.last.request.content)["addressFamilyIPv4"]["neighbors"][0]
    assert n["neighborAdvanced"]["neighborSecret"] == "S3cret!"


async def test_bgp_blockers(rt: respx.MockRouter) -> None:
    async with Client(server()) as c:
        dup = await run(
            c, "fmc_configure_bgp", {"device": "mcp-ftd1", "neighbor": "10.99.1.2", "remote_as": "65001"}
        )
        other_as = await run(
            c,
            "fmc_configure_bgp",
            {"device": "mcp-ftd1", "neighbor": "10.99.1.9", "remote_as": "1", "local_as": "64512"},
        )
        gone = await run(
            c, "fmc_configure_bgp", {"device": "mcp-ftd1", "neighbor": "10.99.1.9", "remove_neighbor": True}
        )
    assert dup["status"] == other_as["status"] == gone["status"] == "blocked"
    assert "already runs BGP AS 65000" in other_as["blockers"][0]


async def test_bgp_setup_from_scratch(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get(f"{R}/bgpgeneralsettings").mock(return_value=empty())
    fmc.get(f"{R}/bgp").mock(return_value=empty())
    fmc.get(f"{CFG}/object/networks").mock(return_value=items([NET]))
    fmc.get(f"{CFG}/object/hosts").mock(return_value=empty())
    gen = fmc.post(f"{R}/bgpgeneralsettings").mock(return_value=httpx.Response(201, json={"id": "g"}))
    bgp = fmc.post(f"{R}/bgp").mock(return_value=httpx.Response(201, json={"id": "b"}))
    args = {
        "device": "mcp-ftd1",
        "neighbor": "10.99.1.2",
        "remote_as": "65001",
        "advertise": ["10.99.1.0/24"],
    }
    async with Client(server()) as c:
        blocked = await run(c, "fmc_configure_bgp", args)
        assert blocked["status"] == "blocked" and "local_as" in blocked["blockers"][0]
        preview = await run(c, "fmc_configure_bgp", {**args, "local_as": "65000"})
        done = await run(c, "fmc_configure_bgp", {**args, "local_as": "65000", "confirm": preview["confirm"]})
    assert done["result"]["applied"] == ["create bgp general settings", "create bgp"]
    assert json.loads(gen.calls.last.request.content)["asNumber"] == "65000"
    body = json.loads(bgp.calls.last.request.content)
    assert body["addressFamilyIPv4"]["networks"][0]["ipv4Address"]["id"] == NET["id"]


async def test_ospf_create_process_with_required_defaults(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get(f"{R}/ospfv2routes").mock(return_value=empty())
    fmc.get(f"{CFG}/object/networks").mock(return_value=items([NET]))
    fmc.get(f"{CFG}/object/hosts").mock(return_value=empty())
    post = fmc.post(f"{R}/ospfv2routes").mock(return_value=httpx.Response(201, json={"id": "o"}))
    args = {"device": "mcp-ftd1", "area": "0", "add_networks": [NET["name"]]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_ospf", args)
        await run(c, "fmc_configure_ospf", {**args, "confirm": preview["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["processConfiguration"]["administrativeDistance"] == {
        "interArea": 110,
        "intraArea": 110,
        "external": 110,
    }
    assert body["areas"] == [
        {
            "areaId": "0",
            "areaType": {"type": "normal"},
            "areaNetworks": [{"id": NET["id"], "type": "Network", "name": NET["name"]}],
        }
    ]


async def test_ospf_remove_last_network_needs_remove_process(rt: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_configure_ospf", {"device": "mcp-ftd1", "remove_networks": [NET["name"]]})
    assert out["status"] == "blocked" and "remove_process" in out["blockers"][0]


async def test_vrf_create_and_delete(rt: respx.MockRouter) -> None:
    post = rt.post(f"{R}/virtualrouters").mock(return_value=httpx.Response(201, json={"id": "v"}))
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_vrf", {"device": "mcp-ftd1", "name": "blue"})
        await run(c, "fmc_create_vrf", {"device": "mcp-ftd1", "name": "blue", "confirm": preview["confirm"]})
        glob = await run(c, "fmc_delete_vrf", {"device": "mcp-ftd1", "name": "Global"})
    assert json.loads(post.calls.last.request.content) == {
        "type": "VirtualRouter",
        "name": "blue",
        "interfaces": [],
    }
    assert glob["status"] == "blocked"


async def test_ospf_edit_keeps_other_areas(rt: respx.MockRouter) -> None:
    proc = json.loads(json.dumps(OSPF))
    proc["areas"].append(
        {"areaId": "1", "areaType": {"type": "stub"}, "areaNetworks": [], "areaRanges": [{"x": 1}]}
    )
    rt.get(f"{R}/ospfv2routes").mock(return_value=_paged([proc]))
    other = {"id": "n2", "name": "lab-net", "type": "Network", "value": "10.50.0.0/16"}
    rt.get(f"{CFG}/object/networks").mock(return_value=items([NET, other]))
    put = rt.put(f"{R}/ospfv2routes/o1").mock(return_value=httpx.Response(200, json={}))
    args = {"device": "mcp-ftd1", "area": "0.0.0.0", "add_networks": ["lab-net"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_ospf", args)
        await run(c, "fmc_configure_ospf", {**args, "confirm": preview["confirm"]})
    areas = json.loads(put.calls.last.request.content)["areas"]
    assert [a["areaId"] for a in areas] == ["0", "1"]  # 0.0.0.0 is area 0; the stub area survives
    assert [n["id"] for n in areas[0]["areaNetworks"]] == [NET["id"], "n2"]


async def test_bad_inputs(rt: respx.MockRouter) -> None:
    async with Client(server()) as c:
        for tool, args in (
            ("fmc_configure_bgp", {"device": "mcp-ftd1", "neighbor": "10.99.1.9", "remote_as": "abc"}),
            ("fmc_configure_bgp", {"device": "mcp-ftd1", "remove_neighbor": True, "advertise": ["x"]}),
            ("fmc_configure_bgp", {"device": "mcp-ftd1", "remove_bgp": True, "neighbor_description": "x"}),
            ("fmc_configure_ospf", {"device": "mcp-ftd1", "area": "zero", "add_networks": [NET["name"]]}),
        ):
            r = await c.call_tool(tool, args, raise_on_error=False)
            assert r.is_error, (tool, args)

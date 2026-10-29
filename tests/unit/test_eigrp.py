"""Native EIGRP (F98): fmc_configure_eigrp (create, update, delete, VRF) and the EIGRP section of
fmc_get_routing, replayed from tests/fixtures/eigrp_fmc10.json (spec-shaped: see its `_source`)."""

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server

from .conftest import CFG, empty, fixture, items, make_settings

DEV = {"id": "6a0f3c1e-0000-4000-8000-0000000e1e00", "name": "mcp-eigrp-ftd", "type": "Device"}
D = f"{CFG}/devices/devicerecords/{DEV['id']}"
R = f"{D}/routing"
FX = fixture("eigrp_fmc10")
OUTSIDE, INSIDE, UNNAMED = FX["physicalinterfaces"]["items"]
NET_INSIDE, NET_SUMMARY = FX["networks"]
PEER = FX["hosts"][0]
RM = FX["routemaps"][0]
PROC = FX["eigrp_with_md5"]
VRF = FX["vrf"]
KEY = "s3cr3t-md5"


def server(**kw: Any) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, rate_limit=100000, **kw))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def body(route: respx.Route) -> Any:
    return json.loads(route.calls.last.request.content)


def keys(tmp_path: Path) -> Path:
    d = tmp_path / "pki"
    d.mkdir()
    (d / "eigrp-inside.key").write_text(KEY + "\n")
    return d


def mount(fmc: respx.MockRouter, procs: list[dict[str, Any]] | None = None, base: str = R) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get(f"{D}/physicalinterfaces").mock(return_value=httpx.Response(200, json=FX["physicalinterfaces"]))
    for sub in (
        "subinterfaces",
        "etherchannelinterfaces",
        "virtualtunnelinterfaces",
        "loopbackinterfaces",
        "bridgegroupinterfaces",
    ):
        fmc.get(f"{D}/{sub}").mock(return_value=empty())
    fmc.get(f"{D}/vlaninterfaces").mock(return_value=httpx.Response(405, json={"error": {}}))
    fmc.get(f"{base}/eigrproutes").mock(return_value=items(copy.deepcopy(procs or [])))
    fmc.get(f"{R}/virtualrouters").mock(return_value=items([{"id": "vr-g", "name": "Global"}, VRF]))
    fmc.get(f"{R}/bgpgeneralsettings").mock(return_value=empty())
    fmc.get(f"{CFG}/object/networks").mock(return_value=items(FX["networks"]))
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items(FX["hosts"]))
    fmc.get(f"{CFG}/object/routemaps").mock(return_value=items(FX["routemaps"]))


async def test_create_with_md5_passive_and_redistribution(fmc: respx.MockRouter, tmp_path: Path) -> None:
    mount(fmc)
    post = fmc.post(f"{R}/eigrproutes").mock(return_value=httpx.Response(201, json={"id": "e-new"}))
    args = {
        "device": DEV["name"],
        "as_number": 100,
        "add_networks": ["192.0.2.0/24"],
        "interfaces": [
            {"name": "inside", "hello": 5, "hold": 15, "key_id": 1, "key_file": "eigrp-inside.key"},
            {"name": "outside", "passive": True},
        ],
        "redistribute": [{"protocol": "static", "route_map": RM["name"]}],
        "router_id": "203.0.113.1",
    }
    async with Client(server(pki_dir=keys(tmp_path))) as c:
        preview = await run(c, "fmc_configure_eigrp", args)
        p = preview["preview"]
        assert preview["action"].startswith("Create EIGRP AS 100 on mcp-eigrp-ftd (global table)")
        assert p["before"] is None
        assert p["after"]["networks"] == ["mcp-eigrp-inside"]
        assert p["after"]["passive_interfaces"] == ["outside"]
        assert p["after"]["interfaces"] == [
            {"interface": "inside", "hello": 5, "hold": 15, "md5": {"key_id": 1, "key_set": True}}
        ]
        assert p["redistribute_changes"]["added"] == [{"protocol": "static", "route_map": "mcp-rm-default"}]
        req = p["requests"][0]
        assert (req["step"], req["method"]) == ("create eigrp process", "POST")
        auth = req["body"]["eigrpInterfaces"][0]["eigrpProtocolConfiguration"]["authentication"]
        assert auth["password"] != KEY and KEY not in json.dumps(preview)
        assert any("same MD5 key id" in w for w in p["warnings"])
        done = await run(c, "fmc_configure_eigrp", {**args, "confirm": preview["confirm"]})
    assert done["status"] == "applied"
    assert body(post) == {
        "type": "EigrpRoute",
        "asNumber": "100",
        "basicConfiguration": {
            "networks": [{"id": NET_INSIDE["id"], "type": "Network", "name": "mcp-eigrp-inside"}],
            "autoSummary": False,
            "passiveInterfaces": {
                "selectedInterfaces": [
                    {
                        "id": OUTSIDE["id"],
                        "type": "PhysicalInterface",
                        "name": "Ethernet0/0",
                        "ifname": "outside",
                    }
                ],
                "allInterfaces": False,
            },
        },
        "advancedConfiguration": {"logNeighborChanges": True, "routerId": "203.0.113.1"},
        "eigrpInterfaces": [
            {
                "deviceInterface": {
                    "id": INSIDE["id"],
                    "type": "PhysicalInterface",
                    "name": "Ethernet0/1",
                    "ifname": "inside",
                },
                "eigrpProtocolConfiguration": {
                    "timers": {"helloInterval": 5, "holdTime": 15},
                    "authentication": {
                        "md5auth": True,
                        "keyId": 1,
                        "password": KEY,
                        "pwdEncryption": "UNENCRYPTED",
                    },
                },
            }
        ],
        "redistributeProtocols": [
            {"protocol": "STATIC", "routeMap": {"id": RM["id"], "type": "RouteMap", "name": "mcp-rm-default"}}
        ],
    }


async def test_new_process_needs_as_and_networks(fmc: respx.MockRouter) -> None:
    mount(fmc)
    async with Client(server()) as c:
        no_as = await c.call_tool(
            "fmc_configure_eigrp",
            {"device": DEV["name"], "add_networks": ["192.0.2.0/24"]},
            raise_on_error=False,
        )
        no_nets = await run(
            c, "fmc_configure_eigrp", {"device": DEV["name"], "as_number": 100, "router_id": "203.0.113.1"}
        )
        unnamed = await run(
            c,
            "fmc_configure_eigrp",
            {
                "device": DEV["name"],
                "as_number": 100,
                "add_networks": ["192.0.2.0/24"],
                "interfaces": [{"name": "Ethernet0/2", "passive": True}],
            },
        )
    assert no_as.is_error and "give as_number" in no_as.content[0].text  # type: ignore[union-attr]
    assert no_nets["status"] == "blocked" and "needs add_networks" in no_nets["blockers"][0]
    assert unnamed["status"] == "blocked" and "no logical name" in unnamed["blockers"][0]


async def test_key_file_needs_pki_dir(fmc: respx.MockRouter) -> None:
    mount(fmc)
    async with Client(server()) as c:
        r = await c.call_tool(
            "fmc_configure_eigrp",
            {
                "device": DEV["name"],
                "as_number": 100,
                "add_networks": ["192.0.2.0/24"],
                "interfaces": [{"name": "inside", "key_file": "eigrp-inside.key"}],
            },
            raise_on_error=False,
        )
    assert r.is_error and "FMC_PKI_DIR" in r.content[0].text  # type: ignore[union-attr]


async def test_update_with_a_masked_key_is_blocked_until_the_key_is_given(
    fmc: respx.MockRouter, tmp_path: Path
) -> None:
    mount(fmc, procs=[PROC])
    put = fmc.put(f"{R}/eigrproutes/{PROC['id']}").mock(return_value=httpx.Response(200, json={}))
    add = {
        "device": DEV["name"],
        "neighbors": [{"address": "192.0.2.2", "interface": "inside"}],
        "summary_addresses": [{"network": "198.51.100.0/24", "interface": "outside"}],
    }
    async with Client(server(pki_dir=keys(tmp_path))) as c:
        blocked = await run(c, "fmc_configure_eigrp", add)
        other_as = await run(c, "fmc_configure_eigrp", {**add, "as_number": 200})
        args = {**add, "interfaces": [{"name": "inside", "key_id": 2, "key_file": "eigrp-inside.key"}]}
        preview = await run(c, "fmc_configure_eigrp", args)
        done = await run(c, "fmc_configure_eigrp", {**args, "confirm": preview["confirm"]})
    assert blocked["status"] == "blocked"
    assert any("only returns masked" in b for b in blocked["blockers"])
    assert any("already runs EIGRP AS 100" in b for b in other_as["blockers"])
    p = preview["preview"]
    assert p["before"]["interfaces"][0]["md5"] == {"key_id": 2, "key_set": True}
    assert p["after"]["neighbors"] == [{"address": "mcp-eigrp-peer", "interface": "inside"}]
    assert p["after"]["summary_addresses"] == [{"network": "mcp-eigrp-summary", "interface": "outside"}]
    assert done["status"] == "applied"
    sent = body(put)
    assert "links" not in sent and sent["id"] == PROC["id"] and sent["asNumber"] == "100"
    conf = sent["eigrpInterfaces"][0]["eigrpProtocolConfiguration"]
    assert conf["authentication"]["password"] == KEY  # not the mask FMC returned
    assert conf["timers"] == {"delay": 10, "helloInterval": 5, "holdTime": 15}  # kept
    assert sent["redistributeProtocols"] == PROC["redistributeProtocols"]  # untouched source kept
    assert sent["neighbors"] == [
        {
            "neighborInterface": {
                "id": INSIDE["id"],
                "type": "PhysicalInterface",
                "name": "Ethernet0/1",
                "ifname": "inside",
            },
            "neighborAddress": {"id": PEER["id"], "type": "Host", "name": "mcp-eigrp-peer"},
        }
    ]
    assert sent["summaryAddressList"][0]["summaryAddress"]["id"] == NET_SUMMARY["id"]


async def test_no_auth_removes_the_key_and_redistribution_checks(fmc: respx.MockRouter) -> None:
    mount(fmc, procs=[PROC])
    put = fmc.put(f"{R}/eigrproutes/{PROC['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {
        "device": DEV["name"],
        "interfaces": [{"name": "inside", "no_auth": True}],
        "redistribute": [{"protocol": "ospf", "process_id": 1}, {"protocol": "connected", "remove": True}],
        "stub": ["connected", "summary"],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_eigrp", args)
        partial = await c.call_tool(
            "fmc_configure_eigrp",
            {"device": DEV["name"], "redistribute": [{"protocol": "static", "bandwidth": 1000}]},
            raise_on_error=False,
        )
        await run(c, "fmc_configure_eigrp", {**args, "confirm": preview["confirm"]})
    p = preview["preview"]
    assert any("without a metric" in w for w in p["warnings"])
    assert p["redistribute_changes"]["removed"] == [{"protocol": "connected"}]
    assert p["after"]["stub"] == ["connected", "summary"]
    assert partial.is_error and "all five values" in partial.content[0].text  # type: ignore[union-attr]
    sent = body(put)
    assert "authentication" not in sent["eigrpInterfaces"][0]["eigrpProtocolConfiguration"]
    assert sent["redistributeProtocols"] == [{"protocol": "OSPF", "processId": "1", "matchInternal": True}]
    assert sent["advancedConfiguration"]["stub"] == {
        "receiveOnly": False,
        "advertise": {"connected": True, "static": False, "summary": True, "redistributed": False},
    }


async def test_remove_process(fmc: respx.MockRouter) -> None:
    mount(fmc, procs=[PROC])
    delete = fmc.delete(f"{R}/eigrproutes/{PROC['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "remove_process": True}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_eigrp", args)
        done = await run(c, "fmc_configure_eigrp", {**args, "confirm": preview["confirm"]})
    assert preview["action"].startswith("Delete EIGRP AS 100")
    assert preview["preview"]["after"] is None
    assert preview["preview"]["requests"][0]["method"] == "DELETE"
    assert any("adjacency" in s for s in preview["side_effects"])
    assert done["status"] == "applied" and delete.called


async def test_vrf_uses_the_virtual_router_collection(fmc: respx.MockRouter) -> None:
    base = f"{R}/virtualrouters/{VRF['id']}"
    mount(fmc, base=base)
    post = fmc.post(f"{base}/eigrproutes").mock(return_value=httpx.Response(201, json={"id": "e-vrf"}))
    args = {
        "device": DEV["name"],
        "as_number": 200,
        "add_networks": ["192.0.2.0/24"],
        "virtual_router": VRF["name"],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_eigrp", args)
        await run(c, "fmc_configure_eigrp", {**args, "confirm": preview["confirm"]})
    assert "(mcp-vrf-blue)" in preview["action"]
    assert preview["preview"]["requests"][0]["path"].endswith(f"/virtualrouters/{VRF['id']}/eigrproutes")
    assert body(post)["asNumber"] == "200"


async def test_get_routing_shows_eigrp_without_keys(fmc: respx.MockRouter) -> None:
    mount(fmc, procs=[PROC])
    for sub in (
        "bgp",
        "ospfv2routes",
        "ipv4staticroutes",
        "ipv6staticroutes",
        "ospfinterface",
        "ecmpzones",
        "policybasedroutes",
        "bfdpolicies",
        "ospfv3routes",
    ):
        fmc.get(f"{R}/{sub}").mock(return_value=empty())
    fmc.get(f"{CFG}/object/sdwansettings").mock(return_value=empty())
    async with Client(server()) as c:
        out = await run(c, "fmc_get_routing", {"device": DEV["name"]})
    assert out["eigrp"] == [
        {
            "as": "100",
            "networks": ["mcp-eigrp-inside"],
            "auto_summary": False,
            "interfaces": [
                {
                    "interface": "inside",
                    "hello": 5,
                    "hold": 15,
                    "delay": 10,
                    "split_horizon": True,
                    "md5": {"key_id": 2, "key_set": True},
                }
            ],
            "redistribution": [{"protocol": "connected"}],
            "id": PROC["id"],
        }
    ]
    assert "*****" not in json.dumps(out)


@pytest.mark.parametrize(
    "bad",
    [{"interfaces": [{"name": "inside", "key_id": 3}]}, {"remove_process": True, "router_id": "203.0.113.1"}],
)
async def test_argument_errors(fmc: respx.MockRouter, bad: dict[str, Any]) -> None:
    mount(fmc, procs=[PROC])
    async with Client(server()) as c:
        r = await c.call_tool("fmc_configure_eigrp", {"device": DEV["name"], **bad}, raise_on_error=False)
    assert r.is_error


def plain_proc(all_interfaces: bool, selected: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """PROC without its MD5 key (an edit isn't blocked by the masked key) and a synthetic passive setting."""
    p = copy.deepcopy(PROC)
    p["eigrpInterfaces"][0]["eigrpProtocolConfiguration"].pop("authentication")
    p["basicConfiguration"]["passiveInterfaces"] = {
        "selectedInterfaces": selected or [],
        "allInterfaces": all_interfaces,
    }
    return p


def iref(i: dict[str, Any]) -> dict[str, Any]:
    return {k: i[k] for k in ("id", "type", "name", "ifname")}


async def test_passive_all_replaces_the_selected_interfaces(fmc: respx.MockRouter) -> None:
    proc = plain_proc(False, [iref(OUTSIDE)])
    mount(fmc, procs=[proc])
    put = fmc.put(f"{R}/eigrproutes/{proc['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "passive_all": True}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_eigrp", args)
        done = await run(c, "fmc_configure_eigrp", {**args, "confirm": preview["confirm"]})
    p = preview["preview"]
    assert p["before"]["passive_interfaces"] == ["outside"]
    assert p["after"]["passive_interfaces"] == "all"
    assert any("replaces the selected passive interfaces (outside)" in w for w in p["warnings"])
    assert any("all adjacencies" in w for w in p["warnings"])
    assert p["requests"][0]["body"]["basicConfiguration"]["passiveInterfaces"] == {
        "selectedInterfaces": [],
        "allInterfaces": True,
    }
    assert done["status"] == "applied"
    assert body(put)["basicConfiguration"]["passiveInterfaces"] == {
        "selectedInterfaces": [],
        "allInterfaces": True,
    }


async def test_passive_all_off_with_selected_interfaces(fmc: respx.MockRouter) -> None:
    proc = plain_proc(True)
    mount(fmc, procs=[proc])
    put = fmc.put(f"{R}/eigrproutes/{proc['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "passive_all": False, "interfaces": [{"name": "outside", "passive": True}]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_eigrp", args)
        await run(c, "fmc_configure_eigrp", {**args, "confirm": preview["confirm"]})
    p = preview["preview"]
    assert p["before"]["passive_interfaces"] == "all"
    assert p["after"]["passive_interfaces"] == ["outside"]
    assert "warnings" not in p
    assert body(put)["basicConfiguration"]["passiveInterfaces"] == {
        "selectedInterfaces": [iref(OUTSIDE)],
        "allInterfaces": False,
    }


async def test_passive_all_off_with_nothing_passive_leaves_the_block_out(fmc: respx.MockRouter) -> None:
    """#381: FMC 10.0 rejects an empty passiveInterfaces block (400 "Device Interface is mandatory for Passive
    interface configuration"); "nothing passive" is sent by leaving the key out."""
    proc = plain_proc(True)
    mount(fmc, procs=[proc])
    put = fmc.put(f"{R}/eigrproutes/{proc['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "passive_all": False}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_eigrp", args)
        done = await run(c, "fmc_configure_eigrp", {**args, "confirm": preview["confirm"]})
    p = preview["preview"]
    assert p["before"]["passive_interfaces"] == "all"
    assert p["after"].get("passive_interfaces") is None
    assert "passiveInterfaces" not in p["requests"][0]["body"]["basicConfiguration"]
    assert done["status"] == "applied"
    assert "passiveInterfaces" not in body(put)["basicConfiguration"]


async def test_unmarking_the_last_passive_interface_leaves_the_block_out(fmc: respx.MockRouter) -> None:
    proc = plain_proc(False, [iref(OUTSIDE)])
    mount(fmc, procs=[proc])
    put = fmc.put(f"{R}/eigrproutes/{proc['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "interfaces": [{"name": "outside", "passive": False}]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_eigrp", args)
        await run(c, "fmc_configure_eigrp", {**args, "confirm": preview["confirm"]})
    assert preview["preview"]["before"]["passive_interfaces"] == ["outside"]
    assert preview["preview"]["after"].get("passive_interfaces") is None
    assert "passiveInterfaces" not in body(put)["basicConfiguration"]


async def test_create_with_nothing_passive_leaves_the_block_out(fmc: respx.MockRouter) -> None:
    mount(fmc)
    post = fmc.post(f"{R}/eigrproutes").mock(return_value=httpx.Response(201, json={"id": "e-new"}))
    args = {"device": DEV["name"], "as_number": 100, "add_networks": ["192.0.2.0/24"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_eigrp", args)
        done = await run(c, "fmc_configure_eigrp", {**args, "confirm": preview["confirm"]})
    assert done["status"] == "applied"
    assert body(post)["basicConfiguration"] == {
        "networks": [{"id": NET_INSIDE["id"], "type": "Network", "name": "mcp-eigrp-inside"}],
        "autoSummary": False,
    }


@pytest.mark.parametrize(
    ("stored", "args", "blocker"),
    [
        (True, {"passive_all": True}, "already passive"),
        (False, {"passive_all": False}, "already off"),
        (True, {"interfaces": [{"name": "outside", "passive": False}]}, "no per-interface"),
        (
            False,
            {"passive_all": True, "interfaces": [{"name": "inside", "passive": True}]},
            "no per-interface",
        ),
    ],
)
async def test_passive_all_blockers(
    fmc: respx.MockRouter, stored: bool, args: dict[str, Any], blocker: str
) -> None:
    mount(fmc, procs=[plain_proc(stored)])
    async with Client(server()) as c:
        r = await run(c, "fmc_configure_eigrp", {"device": DEV["name"], **args})
    assert r["status"] == "blocked"
    assert any(blocker in b for b in r["blockers"])


async def test_passive_all_confirm_refused_when_the_process_changed(fmc: respx.MockRouter) -> None:
    mount(fmc, procs=[plain_proc(False)])
    put = fmc.put(f"{R}/eigrproutes/{PROC['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "passive_all": True}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_eigrp", args)
        fmc.get(f"{R}/eigrproutes").mock(return_value=items([plain_proc(False, [iref(OUTSIDE)])]))
        with pytest.raises(ToolError):
            await run(c, "fmc_configure_eigrp", {**args, "confirm": preview["confirm"]})
    assert not put.called

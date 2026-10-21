"""F77 on FMC 10.0.1's recorded answers (W6N live-B, 2026-10-21, the t1 iBGP pair), next to the spec-built
shapes in route_policy_fmc10.json: what FMC stores for neighbour filters, default-originate and
redistribution, and what fmc_get_routing makes of it; fmc_create_prefix_list's bodies as FMC accepted them.

Shapes: tests/fixtures/route_policy_live_fmc10.json. Where they differ from the spec-built ones:
- a neighbour's prefix-list filter row carries `type: neighborprefixlist` and the list reference has no type;
- neighborDefaultOriginate carries `type: neighbordefaultoriginate` next to its routeMap;
- a redistribution without a metric is stored with `routeMetric: {}`."""

from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.tools.route_policy import prefix_line

from .conftest import CFG, fixture, items
from .test_route_policy import DEV, R, body, mount, run, server

LIVE = fixture("route_policy_live_fmc10")
HUB, SPOKE = LIVE["hub_bgp"], LIVE["spoke1_bgp"]


def contains(actual: Any, expected: Any, where: str = "") -> None:
    """Every key the recording kept has the recorded value (the recorder trimmed the view)."""
    if isinstance(expected, dict):
        assert isinstance(actual, dict), where
        for k, v in expected.items():
            if v is None:
                assert actual.get(k) is None, f"{where}.{k}"
            else:
                assert k in actual, f"{where}.{k} missing"
                contains(actual[k], v, f"{where}.{k}")
    elif isinstance(expected, list):
        assert isinstance(actual, list) and len(actual) == len(expected), where
        for i, (a, e) in enumerate(zip(actual, expected, strict=True)):
            contains(a, e, f"{where}[{i}]")
    else:
        assert actual == expected, f"{where}: {actual!r} != {expected!r}"


def test_recorded_shapes() -> None:
    hub_nf = HUB["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]
    assert hub_nf["neighborDefaultOriginate"]["type"] == "neighbordefaultoriginate"
    assert HUB["addressFamilyIPv4"]["redistributeProtocols"][0]["routeMetric"] == {}
    (row,) = SPOKE["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]["ipv4PrefixListFilter"]
    assert row["type"] == "neighborprefixlist" and set(row["ipv4PrefixList"]) == {"name", "id"}
    assert all(
        pl["answer"]["type"] == "IPV4PrefixList" and "type" not in pl["request"]
        for pl in LIVE["prefix_lists"]
    )


async def read(fmc: respx.MockRouter, model: dict[str, Any], general: dict[str, Any]) -> Any:
    mount(fmc, model)
    fmc.get(f"{R}/bgpgeneralsettings").mock(return_value=items([general]))
    async with Client(server()) as c:
        return await run(c, "fmc_get_routing", {"device": DEV["name"]})


async def test_get_routing_on_the_recorded_hub(fmc: respx.MockRouter) -> None:
    out = await read(fmc, HUB, LIVE["hub_general"])
    contains(out["bgp"], LIVE["read_view"]["hub"]["bgp"], "hub")


async def test_get_routing_on_the_recorded_spoke(fmc: respx.MockRouter) -> None:
    general = {**LIVE["hub_general"], "routerId": LIVE["read_view"]["spoke1"]["bgp"]["router_id"]}
    out = await read(fmc, SPOKE, general)
    contains(out["bgp"], LIVE["read_view"]["spoke1"]["bgp"], "spoke1")


async def test_unrelated_edit_sends_the_stored_filters_back_as_fmc_has_them(fmc: respx.MockRouter) -> None:
    """A classic edit on the recorded spoke (a new neighbour): the stored prefix-list filter row, its typeless
    reference and the row's own type go back unchanged."""
    mount(fmc, SPOKE)
    put = fmc.put(f"{R}/bgp/{SPOKE['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "neighbor": "192.0.2.9", "remote_as": "65110"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    sent = body(put)["addressFamilyIPv4"]["neighbors"]
    assert sent[0] == SPOKE["addressFamilyIPv4"]["neighbors"][0]
    assert sent[1]["ipv4Address"] == "192.0.2.9"


async def test_create_prefix_list_sends_the_recorded_bodies(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/ipv4prefixlists").mock(return_value=items([]))
    post = fmc.post(f"{CFG}/object/ipv4prefixlists").mock(return_value=httpx.Response(201, json={"id": "p"}))
    calls = [
        {
            "name": "mcp-w6-t1-pl-conn",
            "entries": [{"prefix": "198.51.100.0/24"}, {"prefix": "203.0.113.0/24"}],
            "description": LIVE["prefix_lists"][0]["request"]["description"],
        },
        {
            "name": "mcp-w6-t1-pl-in",
            "entries": [{"prefix": "203.0.113.0/24", "action": "deny"}, {"prefix": "0.0.0.0/0", "le": 32}],
        },
    ]
    async with Client(server()) as c:
        for args, pl in zip(calls, LIVE["prefix_lists"], strict=True):
            preview = await run(c, "fmc_create_prefix_list", args)
            await run(c, "fmc_create_prefix_list", {**args, "confirm": preview["confirm"]})
            assert body(post) == pl["request"]
            # FMC's answer reads back as the lines the preview showed
            assert [prefix_line(e) for e in pl["answer"]["entries"]] == preview["preview"]["entries"]

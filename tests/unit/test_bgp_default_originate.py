"""F77 live finding (W6N live-B): FMC 10.0.1 keeps a BGP neighbour's default-originate only with a route map.

fmc_configure_bgp(default_originate=True) sent neighborDefaultOriginate {} and FMC answered 200 with
neighborFiltering {} (also for {type: neighbordefaultoriginate}), while the preview and result claimed a
default-originate the device never got. With default_originate_route_map it is stored and deployed. The tool
now refuses default-originate without a route map and names the permit-all route map that makes it
unconditional.

Shapes: tests/fixtures/bgp_default_originate_fmc10.json (recorded live 2026-10-21)."""

import copy
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from .conftest import CFG, fixture, items
from .test_route_policy import DEV, FX, RM_DEF, R, body, mount, run, server

LIVE = fixture("bgp_default_originate_fmc10")
HUB = LIVE["stored_with_route_map"]
HUB_ID = HUB["id"]
PERMIT_ALL = LIVE["route_map_permit_all"]
PEER = HUB["addressFamilyIPv4"]["neighbors"][0]["ipv4Address"]


def mount_hub(fmc: respx.MockRouter, model: dict[str, Any]) -> None:
    mount(fmc, model)
    fmc.get(f"{CFG}/object/routemaps").mock(return_value=items([*FX["route_maps"], PERMIT_ALL]))


def test_the_recorded_answers() -> None:
    """What the fix rests on: FMC stored nothing for default-originate without a route map."""
    sent = LIVE["post_without_route_map"]["request"]["addressFamilyIPv4"]["neighbors"][0]
    stored = LIVE["post_without_route_map"]["stored"]["addressFamilyIPv4"]["neighbors"][0]
    assert sent["neighborFiltering"] == {"neighborDefaultOriginate": {}}
    assert stored["neighborFiltering"] == {}
    assert LIVE["put_type_only"]["stored"] == {}
    kept = HUB["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]["neighborDefaultOriginate"]
    assert kept["routeMap"]["name"] == PERMIT_ALL["name"] and kept["type"] == "neighbordefaultoriginate"


@pytest.mark.parametrize(
    "args",
    [
        {"neighbor": "192.0.2.2", "default_originate": True},  # an existing neighbour without it
        {"neighbor": "192.0.2.7", "remote_as": "65007", "default_originate": True},  # a new neighbour
        # contradictory, on a neighbour without default-originate: still "needs a route map"
        {"neighbor": "192.0.2.2", "default_originate": True, "default_originate_route_map": "none"},
    ],
)
async def test_default_originate_without_a_route_map_is_refused(
    fmc: respx.MockRouter, args: dict[str, Any]
) -> None:
    mount(fmc)
    put = fmc.put(f"{R}/bgp/{FX['bgp_recorded']['id']}").mock(return_value=httpx.Response(200, json={}))
    async with Client(server()) as c:
        r = await c.call_tool("fmc_configure_bgp", {"device": DEV["name"], **args}, raise_on_error=False)
    text = r.content[0].text  # type: ignore[union-attr]
    assert r.is_error and "only with a route map" in text and "default_originate_route_map" in text
    assert "fmc_create_route_map(name='<name>', entries=[{'action': 'permit'}])" in text
    assert not put.calls


async def test_from_scratch_body_carries_the_route_map(fmc: respx.MockRouter) -> None:
    """The call live-B made on the hub, with the route map: the neighbour's filter is what FMC stored."""
    mount(fmc)
    fmc.get(f"{R}/bgpgeneralsettings").mock(return_value=items([]))
    fmc.get(f"{R}/bgp").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/routemaps").mock(return_value=items([PERMIT_ALL]))
    fmc.post(f"{R}/bgpgeneralsettings").mock(return_value=httpx.Response(201, json={"id": "g"}))
    post = fmc.post(f"{R}/bgp").mock(return_value=httpx.Response(201, json={"id": "b"}))
    # what FMC then does with it (left out, sent again): test_bgp_create_keeps_filters.py
    fmc.get(f"{R}/bgp/b").mock(
        side_effect=lambda request: httpx.Response(200, json={**body(post), "id": "b"})
    )
    args = {
        "device": DEV["name"],
        "local_as": "65110",
        "router_id": "198.51.100.1",
        "neighbor": PEER,
        "remote_as": "65110",
        "default_originate": True,
        "default_originate_route_map": PERMIT_ALL["name"],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    nf = body(post)["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]
    assert nf == {
        "neighborDefaultOriginate": {
            "routeMap": {"id": PERMIT_ALL["id"], "type": "RouteMap", "name": PERMIT_ALL["name"]}
        }
    }
    assert preview["preview"]["neighbor_changes"]["changes"]["default_originate"] == {
        "from": None,
        "to": {"route_map": PERMIT_ALL["name"]},
    }


async def test_route_map_alone_turns_it_on(fmc: respx.MockRouter) -> None:
    mount(fmc)
    put = fmc.put(f"{R}/bgp/{FX['bgp_recorded']['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "neighbor": "192.0.2.2", "default_originate_route_map": "rm-default"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    nf = body(put)["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]
    assert nf["neighborDefaultOriginate"] == {
        "routeMap": {"id": RM_DEF["id"], "type": "RouteMap", "name": "rm-default"}
    }


async def test_on_the_recorded_hub_model(fmc: respx.MockRouter) -> None:
    """The hub as FMC stored it ({routeMap, type: neighbordefaultoriginate}): asking for it again changes
    nothing, 'none' would drop it (refused, pointing at default_originate=false), false removes it, and
    another route map replaces only the reference."""
    mount_hub(fmc, HUB)
    put = fmc.put(f"{R}/bgp/{HUB_ID}").mock(return_value=httpx.Response(200, json={}))
    base = {"device": DEV["name"], "neighbor": PEER}
    async with Client(server()) as c:
        again = await run(c, "fmc_configure_bgp", {**base, "default_originate": True})
        none = await c.call_tool(
            "fmc_configure_bgp", {**base, "default_originate_route_map": "none"}, raise_on_error=False
        )
        off = {**base, "default_originate": False}
        preview = await run(c, "fmc_configure_bgp", off)
        await run(c, "fmc_configure_bgp", {**off, "confirm": preview["confirm"]})
        assert (
            "neighborDefaultOriginate"
            not in body(put)["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]
        )
        other = {**base, "default_originate_route_map": "rm-default"}
        preview = await run(c, "fmc_configure_bgp", other)
        await run(c, "fmc_configure_bgp", {**other, "confirm": preview["confirm"]})
    assert again["status"] == "blocked" and "already configured that way" in again["blockers"][0]
    text = none.content[0].text  # type: ignore[union-attr]
    assert none.is_error and "default_originate=false" in text
    do = body(put)["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]["neighborDefaultOriginate"]
    assert do == {
        "routeMap": {"id": RM_DEF["id"], "type": "RouteMap", "name": "rm-default"},
        "type": "neighbordefaultoriginate",  # FMC's own key, sent back as it came
    }


async def test_an_existing_route_map_less_default_originate_is_left_alone(fmc: respx.MockRouter) -> None:
    """A neighbour FMC holds with default-originate and no route map (made elsewhere): other changes send it
    back untouched; only asking for default-originate without a route map is refused."""
    model = copy.deepcopy(HUB)
    model["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"] = {
        "neighborDefaultOriginate": {"type": "neighbordefaultoriginate"}
    }
    mount_hub(fmc, model)
    put = fmc.put(f"{R}/bgp/{HUB_ID}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "neighbor": PEER, "max_prefix": 100}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    nf = body(put)["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]
    assert nf["neighborDefaultOriginate"] == {"type": "neighbordefaultoriginate"}

"""F77-6 live finding (W6N final-live, 2026-10-21): FMC 10.0.1 leaves a new neighbour's default-originate out
of a BGP create.

fmc_configure_bgp(local_as, ..., neighbor, default_originate=True, default_originate_route_map=<rm>) on the t1
hub (no BGP yet) POSTed the neighbour with neighborFiltering {neighborDefaultOriginate {routeMap {id, type
RouteMap, name}}}. FMC answered OK and stored neighborFiltering {} (re-GET), while the preview's `after` and
the result claimed the default-originate. The same block in an update (PUT) of the existing model is stored
(live-B and final-live), and an ipv4PrefixListFilter in a create is kept (spoke1, both runs).

The create path now re-reads the new model after the POST; a sent neighbour filter that is missing goes back
in one PUT of the stored model, a second re-read checks it, and a filter FMC still drops is reported under
`not_stored` with a plain warning (never in `applied`). The update path is one PUT, as before.

Shapes (recorded, documentation addresses): FMC's stored model after the create, with neighborFiltering {}, is
bgp_default_originate_fmc10.json's post_without_route_map.stored (final-live's create with the route map
stored the same {}; only that part was recorded there); the model FMC stores after the PUT is its
stored_with_route_map; the general-settings answer, network and route map are bgp_preview_parity_fmc10.json's;
the spoke's create answer with a kept prefix-list filter is route_policy_live_fmc10.json's spoke1_bgp."""

import copy
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.tools.route_policy import missing_filters
from fmc_mcp.tools.routing import FILTER_STEP

from .conftest import CFG, empty, fixture, items
from .test_route_policy import DEV, R, body, mount, run, server

ORIGINATE = fixture("bgp_default_originate_fmc10")
PARITY = fixture("bgp_preview_parity_fmc10")
PAIR = fixture("route_policy_live_fmc10")
DROPPED = ORIGINATE["post_without_route_map"]["stored"]  # neighborFiltering {} after the create
KEPT = ORIGINATE["stored_with_route_map"]  # what FMC stores from the update
MODEL_ID = DROPPED["id"]
PERMIT_ALL = ORIGINATE["route_map_permit_all"]
PEER = DROPPED["addressFamilyIPv4"]["neighbors"][0]["ipv4Address"]
RM_REF = {"id": PERMIT_ALL["id"], "type": "RouteMap", "name": PERMIT_ALL["name"]}
HUB_ARGS = {
    "device": DEV["name"],
    "local_as": "65110",
    "router_id": "198.51.100.1",
    "neighbor": PEER,
    "remote_as": "65110",
    "neighbor_description": "spoke1 transport",
    "advertise": [PARITY["network"]["name"]],
    "redistribute": [{"protocol": "connected", "route_map": PARITY["route_map"]["name"]}],
    "default_originate": True,
    "default_originate_route_map": PERMIT_ALL["name"],
}


def answers(*models: dict[str, Any]) -> list[httpx.Response]:
    return [httpx.Response(200, json=copy.deepcopy(m)) for m in models]


def mount_new_hub(fmc: respx.MockRouter) -> dict[str, respx.Route]:
    """The t1 hub before the call (no BGP) and its objects; FMC answers the create with what it stored."""
    mount(fmc)
    fmc.get(f"{R}/bgpgeneralsettings").mock(return_value=empty())
    fmc.get(f"{R}/bgp").mock(return_value=empty())
    fmc.get(f"{CFG}/object/networks").mock(return_value=items([PARITY["network"]]))
    fmc.get(f"{CFG}/object/routemaps").mock(return_value=items([PARITY["route_map"], PERMIT_ALL]))
    return {
        "general": fmc.post(f"{R}/bgpgeneralsettings").mock(
            return_value=httpx.Response(201, json=PARITY["general_answer"])
        ),
        "create": fmc.post(f"{R}/bgp").mock(return_value=httpx.Response(201, json=copy.deepcopy(DROPPED))),
        "update": fmc.put(f"{R}/bgp/{MODEL_ID}").mock(return_value=httpx.Response(200, json={})),
    }


def test_the_recorded_answers() -> None:
    """What the fix rests on: the create stored the neighbour without filters; the update kept them."""
    assert DROPPED["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"] == {}
    kept = KEPT["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]["neighborDefaultOriginate"]
    assert kept["routeMap"]["id"] == PERMIT_ALL["id"] and KEPT["id"] == MODEL_ID
    spoke = PAIR["spoke1_bgp"]["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]
    assert spoke["ipv4PrefixListFilter"][0]["ipv4PrefixList"] == {
        "name": "mcp-w6-t1-pl-in",
        "id": "00000000-0000-0ed3-0000-021475073151",
    }  # kept by the create, stored without the reference's type


def test_what_counts_as_kept() -> None:
    """References by id (FMC may store them without type), words by value, a block emptied = missing;
    numbers inside a kept block may be FMC's own (a maximum-prefix threshold it leaves out)."""
    spoke = PAIR["spoke1_bgp"]["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]
    pl = spoke["ipv4PrefixListFilter"][0]["ipv4PrefixList"]
    sent_pl = {
        "ipv4PrefixListFilter": [
            {"ipv4PrefixList": {**pl, "type": "IPV4PrefixList"}, "filterUpdateAction": "IN"}
        ]
    }
    assert missing_filters(sent_pl, spoke) == []
    out = {"ipv4PrefixListFilter": [{**sent_pl["ipv4PrefixListFilter"][0], "filterUpdateAction": "OUT"}]}
    assert missing_filters(out, spoke) == ["ipv4PrefixListFilter"]
    originate = {"neighborDefaultOriginate": {"routeMap": RM_REF}}
    assert missing_filters(originate, {}) == ["neighborDefaultOriginate"]
    assert missing_filters(originate, {"neighborDefaultOriginate": {"type": "neighbordefaultoriginate"}}) == [
        "neighborDefaultOriginate"
    ]
    assert missing_filters(originate, KEPT["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]) == []
    limit = {"neighborMaximumPrefix": {"maxPrefixLimit": 100, "thresholdValue": 75}}
    assert missing_filters(limit, {"neighborMaximumPrefix": {"maxPrefixLimit": 100}}) == []
    assert missing_filters(limit, {"neighborMaximumPrefix": {}}) == ["neighborMaximumPrefix"]


async def test_create_drops_it_and_the_update_stores_it(fmc: respx.MockRouter) -> None:
    routes = mount_new_hub(fmc)
    reread = fmc.get(f"{R}/bgp/{MODEL_ID}").mock(side_effect=answers(DROPPED, KEPT))
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", HUB_ARGS)
        done = await run(c, "fmc_configure_bgp", {**HUB_ARGS, "confirm": preview["confirm"]})
    d = preview["preview"]
    assert d["steps"] == ["create bgp general settings", "create bgp", FILTER_STEP]
    second = d["requests"][2]
    assert (second["step"], second["method"]) == (FILTER_STEP, "PUT")
    assert second["path"].endswith("/routing/bgp/<id of the new BGP model>") and "body" not in second
    assert "lacks a neighbor filter" in second["only_if"]
    assert second["sends"]["with"] == [
        {"neighbor": PEER, "neighborFiltering": {"neighborDefaultOriginate": {"routeMap": RM_REF}}}
    ]
    assert any("leaves a new neighbor's default-originate out" in s for s in preview["side_effects"])
    # the create goes out as before: the default-originate block in the POST
    create = body(routes["create"])["addressFamilyIPv4"]["neighbors"][0]
    assert create["neighborFiltering"] == {"neighborDefaultOriginate": {"routeMap": RM_REF}}
    # the update: the stored model as FMC re-read it, maximumPaths out, the block put back
    expected = copy.deepcopy(DROPPED)
    del expected["addressFamilyIPv4"]["maximumPaths"]
    expected["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"] = {
        "neighborDefaultOriginate": {"routeMap": RM_REF}
    }
    assert routes["update"].call_count == 1 and body(routes["update"]) == expected
    assert reread.call_count == 2
    result = done["result"]
    assert result["applied"] == ["create bgp general settings", "create bgp", FILTER_STEP]
    assert "left these neighbor filters out of the create" in result["verified"]
    assert f"{PEER}: default_originate" in result["verified"]
    assert "warning" not in result and "not_stored" not in result


async def test_create_and_update_both_drop_it_is_reported(fmc: respx.MockRouter) -> None:
    routes = mount_new_hub(fmc)
    fmc.get(f"{R}/bgp/{MODEL_ID}").mock(side_effect=answers(DROPPED, DROPPED))
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", HUB_ARGS)
        done = await run(c, "fmc_configure_bgp", {**HUB_ARGS, "confirm": preview["confirm"]})
    result = done["result"]
    assert routes["update"].call_count == 1  # sent once again, no loop
    assert result["applied"] == ["create bgp general settings", "create bgp"]  # never the filters
    assert result["not_stored"] == [
        {"neighbor": PEER, "filters": {"default_originate": {"route_map": PERMIT_ALL["name"]}}}
    ]
    warning = result["warning"]
    assert warning.startswith("FMC answered OK but didn't store these neighbor filters")
    assert "nor in the update that sent them again" in warning and "a deploy won't put them" in warning
    assert "verified" not in result


async def test_create_keeps_a_prefix_list_filter_one_reread_no_update(fmc: respx.MockRouter) -> None:
    """The spoke (live-B / final-live): the prefix-list filter in the create is kept, so the re-read is the
    only extra request."""
    spoke = PAIR["spoke1_bgp"]
    pl_in = PAIR["prefix_lists"][1]["answer"]
    mount(fmc)
    fmc.get(f"{R}/bgpgeneralsettings").mock(return_value=empty())
    fmc.get(f"{R}/bgp").mock(return_value=empty())
    fmc.get(f"{CFG}/object/ipv4prefixlists").mock(
        return_value=items([{"name": pl_in["name"], "id": pl_in["id"]}])  # FMC lists them without type
    )
    fmc.post(f"{R}/bgpgeneralsettings").mock(return_value=httpx.Response(201, json={"id": "g"}))
    post = fmc.post(f"{R}/bgp").mock(return_value=httpx.Response(201, json=copy.deepcopy(spoke)))
    reread = fmc.get(f"{R}/bgp/{spoke['id']}").mock(side_effect=answers(spoke))
    put = fmc.put(f"{R}/bgp/{spoke['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {
        "device": DEV["name"],
        "local_as": "65110",
        "router_id": "198.51.100.11",
        "neighbor": spoke["addressFamilyIPv4"]["neighbors"][0]["ipv4Address"],
        "remote_as": "65110",
        "neighbor_prefix_list_in": pl_in["name"],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        done = await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    sent = body(post)["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]
    assert sent["ipv4PrefixListFilter"][0]["ipv4PrefixList"]["type"] == "IPV4PrefixList"
    assert preview["preview"]["steps"][-1] == FILTER_STEP  # listed: whether it is needed shows after the POST
    assert reread.call_count == 1 and not put.called
    assert done["result"]["applied"] == ["create bgp general settings", "create bgp"]
    assert done["result"]["verified"] == "re-read after the create: the neighbor filters are stored as sent"


@pytest.mark.parametrize("stored_secret", ["********", None], ids=["masked", "absent"])
async def test_the_update_puts_the_md5_password_back(
    fmc: respx.MockRouter, stored_secret: str | None
) -> None:
    """FMC returns a neighbour's MD5 password masked (or may leave it out of the re-read); the update carries
    the one the call gave (a PUT with the mask sets the mask as the password, one without it removes
    authentication), and neither preview nor result shows it."""
    routes = mount_new_hub(fmc)
    masked = copy.deepcopy(DROPPED)
    kept = copy.deepcopy(KEPT)
    if stored_secret is not None:
        masked["addressFamilyIPv4"]["neighbors"][0]["neighborAdvanced"]["neighborSecret"] = stored_secret
        kept["addressFamilyIPv4"]["neighbors"][0]["neighborAdvanced"]["neighborSecret"] = stored_secret
    assert ("neighborSecret" in masked["addressFamilyIPv4"]["neighbors"][0]["neighborAdvanced"]) == bool(
        stored_secret
    )
    routes["create"].mock(return_value=httpx.Response(201, json=copy.deepcopy(masked)))
    fmc.get(f"{R}/bgp/{MODEL_ID}").mock(side_effect=answers(masked, kept))
    args = {**HUB_ARGS, "neighbor_password": "md5-Throwaway-1"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        done = await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    neighbor = body(routes["update"])["addressFamilyIPv4"]["neighbors"][0]
    assert neighbor["neighborAdvanced"]["neighborSecret"] == "md5-Throwaway-1"
    assert "md5-Throwaway-1" not in str(preview) and "md5-Throwaway-1" not in str(done)
    assert done["result"]["applied"][-1] == FILTER_STEP


MALFORMED = {"id": MODEL_ID, "addressFamilyIPv4": {"neighbors": [PEER]}}  # a shape FMC never sent


async def test_a_malformed_reread_is_not_verified(fmc: respx.MockRouter) -> None:
    """Review of #318: the create has been applied when the check runs, so a re-read in an unexpected shape
    is a "Not verified" warning next to it, not an error that hides the applied create."""
    routes = mount_new_hub(fmc)
    fmc.get(f"{R}/bgp/{MODEL_ID}").mock(side_effect=answers(MALFORMED))
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", HUB_ARGS)
        done = await run(c, "fmc_configure_bgp", {**HUB_ARGS, "confirm": preview["confirm"]})
    assert done["status"] == "applied"
    result = done["result"]
    assert result["applied"] == ["create bgp general settings", "create bgp"]
    warning = result["warning"]
    assert warning.startswith("Not verified: checking the new BGP model's neighbor filters after the create")
    assert "AttributeError" in warning and "An update had sent" not in warning
    assert "verified" not in result and "not_stored" not in result and not routes["update"].called


async def test_a_malformed_reread_after_the_update_is_not_verified(fmc: respx.MockRouter) -> None:
    routes = mount_new_hub(fmc)
    fmc.get(f"{R}/bgp/{MODEL_ID}").mock(side_effect=answers(DROPPED, MALFORMED))
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", HUB_ARGS)
        done = await run(c, "fmc_configure_bgp", {**HUB_ARGS, "confirm": preview["confirm"]})
    result = done["result"]
    assert routes["update"].call_count == 1
    assert result["applied"] == ["create bgp general settings", "create bgp"]  # the update isn't verified
    assert result["warning"].startswith("Not verified:")
    assert "An update had sent the filters again (answered OK) before that." in result["warning"]


async def test_no_model_in_the_reread_is_not_verified(fmc: respx.MockRouter) -> None:
    """A re-read without a model can't tell whether FMC kept the filters: "couldn't be checked", not
    "didn't store"."""
    routes = mount_new_hub(fmc)
    fmc.get(f"{R}/bgp/{MODEL_ID}").mock(return_value=httpx.Response(200, json={}))
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", HUB_ARGS)
        done = await run(c, "fmc_configure_bgp", {**HUB_ARGS, "confirm": preview["confirm"]})
    result = done["result"]
    assert result["applied"] == ["create bgp general settings", "create bgp"]
    assert result["warning"].startswith("Not verified: the re-read after the create found no BGP model")
    assert "couldn't be checked" in result["warning"] and "didn't store" not in result["warning"]
    assert "not_stored" not in result and not routes["update"].called


async def test_a_failed_reread_is_not_verified(fmc: respx.MockRouter) -> None:
    routes = mount_new_hub(fmc)
    fmc.get(f"{R}/bgp/{MODEL_ID}").mock(return_value=httpx.Response(500, json={"error": {}}))
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", HUB_ARGS)
        done = await run(c, "fmc_configure_bgp", {**HUB_ARGS, "confirm": preview["confirm"]})
    result = done["result"]
    assert result["applied"] == ["create bgp general settings", "create bgp"]
    assert result["warning"].startswith("Not verified: re-reading the new BGP model failed")
    assert not routes["update"].called


async def test_update_path_is_one_put_as_before(fmc: respx.MockRouter) -> None:
    """BGP already there (the hub as the create left it): default-originate is one PUT, no re-read."""
    mount(fmc, DROPPED)
    fmc.get(f"{CFG}/object/routemaps").mock(return_value=items([PERMIT_ALL]))
    put = fmc.put(f"{R}/bgp/{MODEL_ID}").mock(return_value=httpx.Response(200, json={}))
    reread = fmc.get(f"{R}/bgp/{MODEL_ID}").mock(return_value=httpx.Response(200, json=KEPT))
    args = {
        "device": DEV["name"],
        "neighbor": PEER,
        "default_originate": True,
        "default_originate_route_map": PERMIT_ALL["name"],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        done = await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    assert preview["preview"]["steps"] == ["update bgp"]
    assert [r["step"] for r in preview["preview"]["requests"]] == ["update bgp"]
    assert not any("default-originate out" in s for s in preview["side_effects"])
    assert put.call_count == 1 and not reread.called
    nf = body(put)["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]
    assert nf == {"neighborDefaultOriginate": {"routeMap": RM_REF}}
    assert done["result"] == {
        "applied": ["update bgp"],
        "next": "fmc_deploy, then check 'show route' on the device",
    }

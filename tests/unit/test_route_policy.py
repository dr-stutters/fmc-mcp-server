"""F77 route policy: prefix lists, route maps, BGP neighbour filters and redistribution.

Shapes: tests/fixtures/route_policy_fmc10.json (the BGP/OSPF models recorded from FMC 10.0.1, and the
spec/terraform-provider shapes for route maps and prefix lists, which the lab FMC had none of); their
non-expanded listings answer as FMC 10.0.1 does (route_policy_listings_fmc10.json, recorded live)."""

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools.routing import FILTER_STEP

from .conftest import CFG, empty, fixture, items, make_settings

FX = fixture("route_policy_fmc10")
DEV = {"id": "2c11eaca-c7e3-11f1-a7ce-a8b537b1b4bb", "name": "ftd-edge", "type": "Device"}
R = f"{CFG}/devices/devicerecords/{DEV['id']}/routing"
GENERAL = {"id": "g1", "type": "BGPGeneralSetting", "asNumber": "65000", "routerId": "AUTOMATIC"}
NET = FX["network"]
OTHER = {
    "id": "00000000-0000-0ed3-0000-000000000102",
    "name": "lab-net",
    "type": "Network",
    "value": "203.0.113.0/24",
}
BGP_ID = FX["bgp_recorded"]["id"]
OSPF_ID = FX["ospf_recorded"]["id"]
PL_LO2, PL_INSIDE = FX["prefix_lists"]
RM_IN, RM_DEF = FX["route_maps"]
COMPAT = Path(__file__).resolve().parent.parent / "fixtures" / "routing_compat_v015.json"
VOLATILE = {"confirm", "how_to_apply"}  # the single-use token


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, rate_limit=100000))  # mocks: no throttle


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def paged(rows: list[dict[str, Any]], count: int | None = None) -> httpx.Response:
    return httpx.Response(
        200, json={"items": rows, "paging": {"count": len(rows) if count is None else count}}
    )


def listing(rows: list[dict[str, Any]], *, typed: bool) -> Any:
    """A collection as FMC 10.0.1 lists it: the objects when expanded, else {name, id} rows, with `type`
    only where FMC sends it (route maps yes, IPv4 prefix lists no: route_policy_listings_fmc10.json)."""

    def answer(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("expanded") == "true":
            return items(copy.deepcopy(rows))
        keep = ("type", "name", "id") if typed else ("name", "id")
        return items([{k: r[k] for k in keep if k in r} for r in rows])

    return answer


def mount(fmc: respx.MockRouter, bgp: dict[str, Any] | None = None) -> respx.MockRouter:
    """The recorded device routing (or `bgp` instead of the recorded BGP model) and the route-policy
    objects."""
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get(f"{R}/bgpgeneralsettings").mock(return_value=paged([GENERAL]))
    fmc.get(f"{R}/bgp").mock(return_value=paged([copy.deepcopy(bgp or FX["bgp_recorded"])]))
    fmc.get(f"{R}/ospfv2routes").mock(return_value=paged([copy.deepcopy(FX["ospf_recorded"])], count=2))
    fmc.get(f"{R}/virtualrouters").mock(return_value=paged([{"id": "vr-g", "name": "Global"}]))
    for sub in (
        "ipv4staticroutes",
        "ipv6staticroutes",
        "ospfinterface",
        "ecmpzones",
        "policybasedroutes",
        "bfdpolicies",
        "ospfv3routes",
        "eigrproutes",
    ):
        fmc.get(f"{R}/{sub}").mock(return_value=empty())
    for kind in ("physical", "sub", "etherchannel", "vlan", "virtualtunnel"):
        fmc.get(f"{CFG}/devices/devicerecords/{DEV['id']}/{kind}interfaces").mock(return_value=empty())
    fmc.get(f"{CFG}/object/networks").mock(return_value=items([NET, OTHER]))
    fmc.get(f"{CFG}/object/hosts").mock(return_value=empty())
    fmc.get(f"{CFG}/object/ipv4prefixlists").mock(side_effect=listing(FX["prefix_lists"], typed=False))
    fmc.get(f"{CFG}/object/routemaps").mock(side_effect=listing(FX["route_maps"], typed=True))
    fmc.get(f"{CFG}/object/standardcommunitylists").mock(return_value=items(FX["standard_community_lists"]))
    fmc.get(f"{CFG}/object/expandedcommunitylists").mock(return_value=empty())
    fmc.get(f"{CFG}/object/aspathlists").mock(return_value=items(FX["as_path_lists"]))
    return fmc


def body(route: respx.Route) -> Any:
    return json.loads(route.calls.last.request.content)


def stable(out: Any) -> Any:
    return {k: v for k, v in out.items() if k not in VOLATILE} if isinstance(out, dict) else out


# --- existing callers get exactly what they got in 0.15.0 -----------------------------------------


async def compat_run(fmc: respx.MockRouter) -> dict[str, Any]:
    """Pre-F77 calls of fmc_get_routing / fmc_configure_bgp / fmc_configure_ospf on the recorded models:
    their output and request bodies. tests/fixtures/routing_compat_v015.json holds what 0.15.0 (main
    e4cb6e3) returned for the same calls."""
    mount(fmc)
    put_bgp = fmc.put(f"{R}/bgp/{BGP_ID}").mock(return_value=httpx.Response(200, json={}))
    del_bgp = fmc.delete(f"{R}/bgp/{BGP_ID}").mock(return_value=httpx.Response(200, json={}))
    fmc.delete(f"{R}/bgpgeneralsettings/g1").mock(return_value=httpx.Response(200, json={}))
    put_ospf = fmc.put(f"{R}/ospfv2routes/{OSPF_ID}").mock(return_value=httpx.Response(200, json={}))
    out: dict[str, Any] = {}
    writes = {
        "bgp_add_neighbor": (
            "fmc_configure_bgp",
            {"device": DEV["name"], "neighbor": "192.0.2.3", "remote_as": "65002", "advertise": ["lab-net"]},
            put_bgp,
        ),
        "bgp_describe": (
            "fmc_configure_bgp",
            {"device": DEV["name"], "neighbor": "192.0.2.2", "neighbor_description": "edge peer"},
            put_bgp,
        ),
        "bgp_remove_neighbor": (
            "fmc_configure_bgp",
            {"device": DEV["name"], "neighbor": "192.0.2.2", "remove_neighbor": True},
            put_bgp,
        ),
        "bgp_withdraw": ("fmc_configure_bgp", {"device": DEV["name"], "withdraw": ["inside-net"]}, put_bgp),
        "bgp_remove": ("fmc_configure_bgp", {"device": DEV["name"], "remove_bgp": True}, del_bgp),
        "ospf_add": (
            "fmc_configure_ospf",
            {"device": DEV["name"], "area": "0", "add_networks": ["lab-net"]},
            put_ospf,
        ),
        "ospf_new_area": (
            "fmc_configure_ospf",
            {"device": DEV["name"], "area": "1", "add_networks": ["lab-net"]},
            put_ospf,
        ),
    }
    async with Client(server()) as c:
        out["get_routing"] = await run(c, "fmc_get_routing", {"device": DEV["name"]})
        out["bgp_duplicate"] = stable(
            await run(
                c, "fmc_configure_bgp", {"device": DEV["name"], "neighbor": "192.0.2.2", "remote_as": "65001"}
            )
        )
        out["ospf_remove_process"] = stable(
            await run(c, "fmc_configure_ospf", {"device": DEV["name"], "remove_process": True})
        )
        for key, (tool, args, route) in writes.items():
            preview = await run(c, tool, args)
            done = await run(c, tool, {**args, "confirm": preview["confirm"]})
            out[key] = {
                "preview": stable(preview),
                "result": stable(done),
                "body": body(route) if route.calls and route.calls.last.request.content else None,
            }
    return out


def without_requests(x: Any) -> Any:
    """`x` less the previews' `requests` (method, path and body of each request; added in 0.16 after
    W6N live-B, test_routing_preview_requests.py): an added key, everything else as in 0.15.0."""
    if isinstance(x, dict):
        return {k: without_requests(v) for k, v in x.items() if k != "requests"}
    if isinstance(x, list):
        return [without_requests(v) for v in x]
    return x


async def test_existing_callers_get_what_they_got_in_015(fmc: respx.MockRouter) -> None:
    assert without_requests(await compat_run(fmc)) == json.loads(COMPAT.read_text())


async def test_existing_calls_keep_ui_made_filters_untouched(fmc: respx.MockRouter) -> None:
    """A device whose BGP already has route policy (made in the UI): adding a neighbour the old way sends
    the filters and redistribution back exactly as FMC returned them."""
    mount(fmc, FX["bgp_filtered"])
    put = fmc.put(f"{R}/bgp/{BGP_ID}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "neighbor": "192.0.2.3", "remote_as": "65002"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    af = body(put)["addressFamilyIPv4"]
    src = FX["bgp_filtered"]["addressFamilyIPv4"]
    assert af["neighbors"][0] == src["neighbors"][0]
    assert af["redistributeProtocols"] == src["redistributeProtocols"]
    assert set(preview["preview"]) == {"domain", "steps", "before", "after", "requests"}


# --- read view ---------------------------------------------------------------------------------


async def test_get_routing_names_route_policy(fmc: respx.MockRouter) -> None:
    mount(fmc, FX["bgp_filtered"])
    async with Client(server()) as c:
        out = await run(c, "fmc_get_routing", {"device": DEV["name"]})
    n = out["bgp"]["ipv4"]["neighbors"][0]
    assert n["route_map_in"] == "rm-peer-in"
    assert n["prefix_list_out"] == "pl-inside"
    assert n["max_prefix"] == {"limit": 100, "threshold_percent": 75}
    # the default-originate route map came without a name: filled from the route-map listing
    assert n["default_originate"] == {"route_map": "rm-default"}
    af = out["bgp"]["ipv4"]
    assert af["redistribute"] == ["RedistributeConnected"]  # unchanged field
    assert af["redistribution"] == [{"protocol": "connected", "route_map": "rm-peer-in", "metric": 5}]


async def test_get_routing_keeps_working_when_a_name_listing_is_refused(fmc: respx.MockRouter) -> None:
    """Names for id-only references are a nicety: a refused listing leaves the id instead of failing
    the read view."""
    mount(fmc, FX["bgp_filtered"])
    fmc.get(f"{CFG}/object/routemaps").mock(
        return_value=httpx.Response(403, json={"error": {"messages": [{"description": "denied"}]}})
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_get_routing", {"device": DEV["name"]})
    n = out["bgp"]["ipv4"]["neighbors"][0]
    assert n["route_map_in"] == "rm-peer-in"  # FMC sent that name with the reference
    assert n["default_originate"]["route_map"] != "rm-default"  # no name to fill: the reference stays


# --- prefix lists and route maps ---------------------------------------------------------------


async def test_create_prefix_list(fmc: respx.MockRouter) -> None:
    mount(fmc)
    post = fmc.post(f"{CFG}/object/ipv4prefixlists").mock(return_value=httpx.Response(201, json={"id": "p"}))
    args = {
        "name": "pl-peer-in",
        "entries": [
            {"prefix": "203.0.113.1/24", "action": "deny", "ge": 25},
            {"prefix": "0.0.0.0/0", "le": 32},
        ],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_prefix_list", args)
        await run(c, "fmc_create_prefix_list", {**args, "confirm": preview["confirm"]})
    assert preview["preview"]["entries"] == [
        "seq 5 deny 203.0.113.0/24 ge 25",
        "seq 10 permit 0.0.0.0/0 le 32",
    ]
    assert any("host bits" in s for s in preview["side_effects"])
    assert body(post) == {  # no `type`: the spec example and terraform send none (FMC: IPV4PrefixList)
        "name": "pl-peer-in",
        "entries": [
            {"sequence": 5, "action": "DENY", "ipAddress": "203.0.113.0/24", "minPrefixLenth": 25},
            {"sequence": 10, "action": "PERMIT", "ipAddress": "0.0.0.0/0", "maxPrefixLength": 32},
        ],
    }


async def test_prefix_list_exists_and_replace(fmc: respx.MockRouter) -> None:
    mount(fmc)
    put = fmc.put(f"{CFG}/object/ipv4prefixlists/{PL_LO2['id']}").mock(
        return_value=httpx.Response(200, json={})
    )
    args = {
        "name": "pl-lo2",
        "entries": [{"prefix": "203.0.113.2/32"}, {"prefix": "203.0.113.3/32", "seq": 7}],
    }
    async with Client(server()) as c:
        blocked = await run(c, "fmc_create_prefix_list", args)
        same = await run(
            c, "fmc_create_prefix_list", {**args, "entries": args["entries"][:1], "replace": True}
        )
        preview = await run(c, "fmc_create_prefix_list", {**args, "replace": True})
        await run(c, "fmc_create_prefix_list", {**args, "replace": True, "confirm": preview["confirm"]})
    assert blocked["status"] == "blocked" and "replace=true" in blocked["blockers"][0]
    assert same["status"] == "blocked" and "exactly these entries" in same["blockers"][0]
    assert preview["preview"]["changes"]["entries"] == {
        "from": ["seq 5 permit 203.0.113.2/32"],
        "to": ["seq 5 permit 203.0.113.2/32", "seq 7 permit 203.0.113.3/32"],
    }
    sent = body(put)
    assert sent["id"] == PL_LO2["id"] and sent["type"] == "IPV4PrefixList"  # FMC's own type kept
    assert "metadata" not in sent and len(sent["entries"]) == 2


@pytest.mark.parametrize(
    ("entry", "error"),
    [
        ({"prefix": "192.0.2.0/24", "ge": 24}, "longer than the prefix length"),
        ({"prefix": "192.0.2.0/24", "le": 20}, "longer than the prefix length"),
        ({"prefix": "192.0.2.0/24", "ge": 30, "le": 28}, "can't be more than"),
        ({"prefix": "2001:db8::/32"}, "not an IPv4 network"),
    ],
)
async def test_prefix_list_validation(fmc: respx.MockRouter, entry: dict[str, Any], error: str) -> None:
    mount(fmc)
    async with Client(server()) as c:
        r = await c.call_tool(
            "fmc_create_prefix_list", {"name": "pl-x", "entries": [entry]}, raise_on_error=False
        )
    assert r.is_error and error in r.content[0].text  # type: ignore[union-attr]


async def test_create_route_map(fmc: respx.MockRouter) -> None:
    mount(fmc)
    post = fmc.post(f"{CFG}/object/routemaps").mock(return_value=httpx.Response(201, json={"id": "r"}))
    args = {
        "name": "rm-transit",
        "entries": [
            {"action": "deny", "match_prefix_list": ["pl-lo2"]},
            {
                "match_community": ["cl-transit"],
                "match_as_path": ["261"],
                "set_local_pref": 200,
                "set_community": "65000:100 no-export",
                "set_community_additive": True,
                "set_prepend": [65000, 65000],
            },
            {"seq": 100, "set_metric": 50, "set_weight": 10},
        ],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_route_map", args)
        await run(c, "fmc_create_route_map", {**args, "confirm": preview["confirm"]})
    assert preview["preview"]["entries"] == [
        "seq 10 deny; match ip address prefix-list pl-lo2",
        "seq 20 permit; match community cl-transit; match as-path 261; set local-preference 200; "
        "set community 65000:100 no-export additive; set as-path prepend 65000 65000",
        "seq 100 permit; set metric 50; set weight 10",
    ]
    entries = body(post)["entries"]
    assert entries[0] == {
        "sequence": 10,
        "action": "DENY",
        "ipv4PrefixListAddresses": [{"id": PL_LO2["id"], "type": "IPV4PrefixList", "name": "pl-lo2"}],
    }
    assert entries[1]["communityLists"][0]["type"] == "StandardCommunityList"
    assert entries[1]["asPathLists"] == [
        {"id": FX["as_path_lists"][0]["id"], "type": "ASPathList", "name": 261}
    ]
    assert entries[1]["communityListSetting"] == 65000 * 65536 + 100
    assert entries[1]["communityListSettingNoExport"] is True
    assert entries[1]["addToExistingCommunity"] is True
    assert entries[1]["asPathPrependASPath"] == [65000, 65000]
    assert entries[2] == {"sequence": 100, "action": "PERMIT", "metricBandwidth": 50, "weightSetting": 10}


@pytest.mark.parametrize(
    ("entry", "error"),
    [
        ({"action": "deny", "set_local_pref": 10}, "never apply"),
        ({"set_community_additive": True}, "needs set_community"),
        ({"set_community": "65000:100 65000:200"}, "one specific community"),
        ({"set_community": "70000:1"}, "must be a number"),
        ({"match_prefix_list": ["nope"]}, "No IPv4 prefix list named"),
    ],
)
async def test_route_map_validation(fmc: respx.MockRouter, entry: dict[str, Any], error: str) -> None:
    mount(fmc)
    async with Client(server()) as c:
        r = await c.call_tool(
            "fmc_create_route_map", {"name": "rm-x", "entries": [entry]}, raise_on_error=False
        )
    assert r.is_error and error in r.content[0].text  # type: ignore[union-attr]


# --- BGP neighbour filters ---------------------------------------------------------------------


async def test_neighbor_filters_preview_shows_only_that_neighbor(fmc: respx.MockRouter) -> None:
    model = copy.deepcopy(FX["bgp_recorded"])
    second = copy.deepcopy(model["addressFamilyIPv4"]["neighbors"][0])
    second.update({"ipv4Address": "192.0.2.9", "remoteAs": "65009"})
    model["addressFamilyIPv4"]["neighbors"].append(second)
    mount(fmc, model)
    put = fmc.put(f"{R}/bgp/{BGP_ID}").mock(return_value=httpx.Response(200, json={}))
    args = {
        "device": DEV["name"],
        "neighbor": "192.0.2.2",
        "neighbor_route_map_in": "rm-peer-in",
        "neighbor_prefix_list_out": "pl-inside",
        "max_prefix": 500,
        "default_originate": True,
        "default_originate_route_map": "rm-default",  # FMC 10.0.1 drops default-originate without one
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    d = preview["preview"]
    assert "before" not in d and "after" not in d
    assert d["neighbor_changes"] == {
        "neighbor": "192.0.2.2",
        "changes": {
            "route_map_in": {"from": None, "to": "rm-peer-in"},
            "prefix_list_out": {"from": None, "to": "pl-inside"},
            "max_prefix": {"from": None, "to": {"limit": 500, "threshold_percent": 75}},
            "default_originate": {"from": None, "to": {"route_map": "rm-default"}},
        },
    }
    assert d["unchanged"] == {"other_neighbors": 1, "networks": 1}
    assert any("whole BGP model" in s for s in preview["side_effects"])
    sent = body(put)["addressFamilyIPv4"]
    assert sent["neighbors"][0]["neighborFiltering"] == {
        "neighborRouteMap": [
            {
                "routeMap": {"id": RM_IN["id"], "type": "RouteMap", "name": "rm-peer-in"},
                "filterUpdateAction": "IN",
            }
        ],
        "ipv4PrefixListFilter": [
            {
                "ipv4PrefixList": {"id": PL_INSIDE["id"], "type": "IPV4PrefixList", "name": "pl-inside"},
                "filterUpdateAction": "OUT",
            }
        ],
        "neighborMaximumPrefix": {"maxPrefixLimit": 500, "thresholdValue": 75},
        "neighborDefaultOriginate": {
            "routeMap": {"id": RM_DEF["id"], "type": "RouteMap", "name": "rm-default"}
        },
    }
    # everything else of the touched neighbour, the other neighbour and the networks: as FMC sent them
    rec = FX["bgp_recorded"]["addressFamilyIPv4"]
    assert {k: v for k, v in sent["neighbors"][0].items() if k != "neighborFiltering"} == {
        k: v for k, v in rec["neighbors"][0].items() if k != "neighborFiltering"
    }
    assert sent["neighbors"][1] == second and sent["networks"] == rec["networks"]


async def test_neighbor_filter_changes_and_removal(fmc: respx.MockRouter) -> None:
    mount(fmc, FX["bgp_filtered"])
    put = fmc.put(f"{R}/bgp/{BGP_ID}").mock(return_value=httpx.Response(200, json={}))
    args = {
        "device": DEV["name"],
        "neighbor": "192.0.2.2",
        "neighbor_route_map_in": "none",
        "neighbor_route_map_out": "rm-peer-in",
        "max_prefix_warning_only": True,
        "default_originate": False,
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
        again = await run(
            c,
            "fmc_configure_bgp",
            {"device": DEV["name"], "neighbor": "192.0.2.2", "neighbor_prefix_list_out": "pl-inside"},
        )
    nf = body(put)["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]
    assert nf["neighborRouteMap"] == [
        {
            "routeMap": {"id": RM_IN["id"], "type": "RouteMap", "name": "rm-peer-in"},
            "filterUpdateAction": "OUT",
        }
    ]
    assert nf["neighborMaximumPrefix"] == {"maxPrefixLimit": 100, "warningOnly": True}
    assert "neighborDefaultOriginate" not in nf
    assert (
        nf["ipv4PrefixListFilter"]
        == FX["bgp_filtered"]["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"][
            "ipv4PrefixListFilter"
        ]
    )
    changes = preview["preview"]["neighbor_changes"]["changes"]
    assert changes["route_map_in"] == {"from": "rm-peer-in", "to": None, "removed": True}
    assert again["status"] == "blocked" and "already configured that way" in again["blockers"][0]


async def test_max_prefix_removal_and_new_neighbor_with_filters(fmc: respx.MockRouter) -> None:
    mount(fmc, FX["bgp_filtered"])
    put = fmc.put(f"{R}/bgp/{BGP_ID}").mock(return_value=httpx.Response(200, json={}))
    async with Client(server()) as c:
        args = {"device": DEV["name"], "neighbor": "192.0.2.2", "max_prefix": 0}
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
        assert (
            "neighborMaximumPrefix" not in body(put)["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]
        )
        args = {
            "device": DEV["name"],
            "neighbor": "192.0.2.7",
            "remote_as": "65007",
            "neighbor_prefix_list_in": "pl-lo2",
            "default_originate_route_map": "rm-default",
        }
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    assert {"before", "after", "neighbor_changes"} <= set(
        preview["preview"]
    )  # a new neighbour: full view too
    n = body(put)["addressFamilyIPv4"]["neighbors"][1]
    assert n["ipv4Address"] == "192.0.2.7"
    assert n["neighborFiltering"]["ipv4PrefixListFilter"][0]["filterUpdateAction"] == "IN"
    assert n["neighborFiltering"]["neighborDefaultOriginate"] == {
        "routeMap": {"id": RM_DEF["id"], "type": "RouteMap", "name": "rm-default"}
    }


@pytest.mark.parametrize(
    ("args", "error"),
    [
        ({"neighbor_route_map_in": "rm-peer-in"}, "apply to `neighbor`"),
        ({"neighbor": "192.0.2.2", "remove_neighbor": True, "max_prefix": 5}, "apply to `neighbor`"),
        ({"neighbor": "192.0.2.2", "max_prefix_warning_only": True}, "needs max_prefix"),
        ({"neighbor": "192.0.2.2", "neighbor_route_map_in": "nope"}, "No route map named"),
        ({"remove_bgp": True, "redistribute": [{"protocol": "static"}]}, "can't be combined"),
        ({"redistribute": [{"protocol": "ospf"}]}, "needs process_id"),
        ({"redistribute": [{"protocol": "bgp"}]}, "into itself"),
        ({"redistribute": [{"protocol": "static", "metric_type": "type_1"}]}, "into OSPF only"),
        ({"redistribute": [{"protocol": "static"}, {"protocol": "static"}]}, "twice"),
    ],
)
async def test_bgp_policy_bad_inputs(fmc: respx.MockRouter, args: dict[str, Any], error: str) -> None:
    mount(fmc)
    async with Client(server()) as c:
        r = await c.call_tool("fmc_configure_bgp", {"device": DEV["name"], **args}, raise_on_error=False)
    assert r.is_error and error in r.content[0].text, r.content[0].text  # type: ignore[union-attr]


# --- redistribution ----------------------------------------------------------------------------


async def test_bgp_redistribute_connected_and_ospf(fmc: respx.MockRouter) -> None:
    mount(fmc, FX["bgp_filtered"])
    put = fmc.put(f"{R}/bgp/{BGP_ID}").mock(return_value=httpx.Response(200, json={}))
    args = {
        "device": DEV["name"],
        "redistribute": [
            {"protocol": "connected", "route_map": "rm-default", "metric": 10},
            {"protocol": "ospf", "process_id": 1, "match": ["internal", "external_2"]},
        ],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
        gone = await run(
            c,
            "fmc_configure_bgp",
            {"device": DEV["name"], "redistribute": [{"protocol": "static", "remove": True}]},
        )
    d = preview["preview"]
    assert "before" not in d and d["unchanged"] == {"other_neighbors": 1, "networks": 1}
    assert d["redistribute_changes"] == {
        "added": [{"protocol": "ospf", "process": "1", "match": ["internal", "external_2"]}],
        "changed": [
            {
                "source": "connected",
                "changes": {
                    "route_map": {"from": "rm-peer-in", "to": "rm-default"},
                    "metric": {"from": 5, "to": 10},
                },
            }
        ],
    }
    assert body(put)["addressFamilyIPv4"]["redistributeProtocols"] == [
        {
            "type": "RedistributeConnected",
            "routeMap": {"id": RM_DEF["id"], "type": "RouteMap", "name": "rm-default"},
            "routeMetric": {"metricValue": 10},
        },
        {"type": "RedistributeOSPF", "processId": "1", "matchInternal": True, "matchExternal2": True},
    ]
    assert gone["status"] == "blocked" and "static isn't redistributed" in gone["blockers"][0]


async def test_neighbor_named_with_only_redistribute_is_not_blocked(fmc: respx.MockRouter) -> None:
    """Naming the (unchanged) neighbour next to redistribute: the redistribution is the change, so the
    neighbour's 'already configured that way' doesn't block it."""
    mount(fmc)
    put = fmc.put(f"{R}/bgp/{BGP_ID}").mock(return_value=httpx.Response(200, json={}))
    args = {
        "device": DEV["name"],
        "neighbor": "192.0.2.2",
        "redistribute": [{"protocol": "static", "route_map": "rm-default"}],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
        plain = await run(c, "fmc_configure_bgp", {"device": DEV["name"], "neighbor": "192.0.2.2"})
    assert preview.get("status") != "blocked", preview
    assert preview["preview"]["redistribute_changes"] == {
        "added": [{"protocol": "static", "route_map": "rm-default"}]
    }
    af = body(put)["addressFamilyIPv4"]
    assert af["neighbors"] == FX["bgp_recorded"]["addressFamilyIPv4"]["neighbors"]
    assert af["redistributeProtocols"] == [
        {
            "type": "RedistributeStatic",
            "routeMap": {"id": RM_DEF["id"], "type": "RouteMap", "name": "rm-default"},
        }
    ]
    # without redistribute, an unchanged neighbour still blocks as in 0.15.0
    assert plain["status"] == "blocked" and "already configured that way" in plain["blockers"][0]


async def test_bgp_from_scratch_with_route_policy(fmc: respx.MockRouter) -> None:
    """A device without BGP (the Stage 2 iBGP pair): one call sets up BGP, a neighbour with
    default-originate (through a route map: FMC 10.0.1 drops it without one), an advertised network and
    redistribution through a route map."""
    mount(fmc)
    fmc.get(f"{R}/bgpgeneralsettings").mock(return_value=empty())
    fmc.get(f"{R}/bgp").mock(return_value=empty())
    gen = fmc.post(f"{R}/bgpgeneralsettings").mock(return_value=httpx.Response(201, json={"id": "g"}))
    post = fmc.post(f"{R}/bgp").mock(return_value=httpx.Response(201, json={"id": "b"}))
    # the re-read after the create (F77-6) finds the neighbour's filters as sent: no second request
    reread = fmc.get(f"{R}/bgp/b").mock(
        side_effect=lambda request: httpx.Response(200, json={**body(post), "id": "b"})
    )
    args = {
        "device": DEV["name"],
        "local_as": "65110",
        "router_id": "198.51.100.1",
        "neighbor": "192.0.2.5",
        "remote_as": "65110",
        "neighbor_description": "spoke",
        "advertise": ["inside-net"],
        "redistribute": [{"protocol": "connected", "route_map": "rm-default"}],
        "default_originate": True,
        "default_originate_route_map": "rm-default",
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        done = await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    d = preview["preview"]
    assert d["steps"] == ["create bgp general settings", "create bgp", FILTER_STEP]
    assert d["before"] is None and d["after"]["networks"] == ["inside-net"]  # the full view: BGP is new
    assert d["neighbor_changes"]["changes"]["default_originate"] == {
        "from": None,
        "to": {"route_map": "rm-default"},
    }
    assert d["redistribute_changes"] == {"added": [{"protocol": "connected", "route_map": "rm-default"}]}
    assert done["result"]["applied"] == ["create bgp general settings", "create bgp"]
    assert done["result"]["verified"] == "re-read after the create: the neighbor filters are stored as sent"
    assert reread.call_count == 1
    assert body(gen)["asNumber"] == "65110" and body(gen)["routerId"] == "198.51.100.1"
    sent = body(post)
    assert sent["asNumber"] == "65110"
    af = sent["addressFamilyIPv4"]
    assert af["neighbors"] == [
        {
            "type": "neighboripv4",
            "ipv4Address": "192.0.2.5",
            "remoteAs": "65110",
            "neighborGeneral": {"enableAddress": True, "shutdown": False, "description": "spoke"},
            "neighborFiltering": {
                "neighborDefaultOriginate": {
                    "routeMap": {"id": RM_DEF["id"], "type": "RouteMap", "name": "rm-default"}
                }
            },
        }
    ]
    assert af["networks"] == [{"ipv4Address": {"id": NET["id"], "type": "Network", "name": "inside-net"}}]
    assert af["redistributeProtocols"] == [
        {
            "type": "RedistributeConnected",
            "routeMap": {"id": RM_DEF["id"], "type": "RouteMap", "name": "rm-default"},
        }
    ]


async def test_bgp_stop_redistributing_drops_the_key(fmc: respx.MockRouter) -> None:
    mount(fmc, FX["bgp_filtered"])
    put = fmc.put(f"{R}/bgp/{BGP_ID}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "redistribute": [{"protocol": "connected", "remove": True}]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    assert preview["preview"]["redistribute_changes"] == {
        "removed": [{"protocol": "connected", "route_map": "rm-peer-in", "metric": 5}]
    }
    assert "redistributeProtocols" not in body(put)["addressFamilyIPv4"]


async def test_ospf_redistribute(fmc: respx.MockRouter) -> None:
    mount(fmc)
    put = fmc.put(f"{R}/ospfv2routes/{OSPF_ID}").mock(return_value=httpx.Response(200, json={}))
    args = {
        "device": DEV["name"],
        "redistribute": [
            {"protocol": "connected", "route_map": "rm-default"},
            {"protocol": "bgp", "metric": 20, "metric_type": "type_1"},
        ],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_ospf", args)
        await run(c, "fmc_configure_ospf", {**args, "confirm": preview["confirm"]})
        itself = await c.call_tool(
            "fmc_configure_ospf",
            {"device": DEV["name"], "redistribute": [{"protocol": "ospf", "process_id": 1}]},
            raise_on_error=False,
        )
    sent = body(put)
    assert sent["areas"] == FX["ospf_recorded"]["areas"]  # area networks untouched
    assert sent["redistributeProtocols"] == [
        {
            "type": "RedistributeConnected",
            "routeMap": {"id": RM_DEF["id"], "type": "RouteMap", "name": "rm-default"},
            "routeMetric": {"metricType": "TYPE_2"},
            "subnets": True,
        },
        {
            "type": "RedistributeBGP",
            "asNumber": 65000,
            "routeMetric": {"metricValue": 20, "metricType": "TYPE_1"},
            "subnets": True,
        },
    ]
    assert preview["preview"]["after"]["redistribution"][1] == {
        "protocol": "bgp",
        "as": 65000,
        "metric": 20,
        "metric_type": "type_1",
        "subnets": True,
    }
    assert [r["protocol"] for r in preview["preview"]["redistribute_changes"]["added"]] == [
        "connected",
        "bgp",
    ]
    assert itself.is_error and "can't redistribute itself" in itself.content[0].text  # type: ignore[union-attr]


async def test_ospf_redistribute_without_process_is_blocked(fmc: respx.MockRouter) -> None:
    mount(fmc)
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_configure_ospf",
            {"device": DEV["name"], "process_id": 2, "redistribute": [{"protocol": "static"}]},
        )
    assert out["status"] == "blocked" and "create it with add_networks first" in out["blockers"][0]


async def test_none_values_only_remove_what_is_there(fmc: respx.MockRouter) -> None:
    mount(fmc)  # the recorded model: no filters, no redistribution
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_configure_bgp",
            {"device": DEV["name"], "neighbor": "192.0.2.2", "default_originate_route_map": "none"},
        )
    assert out["status"] == "blocked" and "already configured that way" in out["blockers"][0]


async def test_redistribution_route_map_none_drops_the_map(fmc: respx.MockRouter) -> None:
    mount(fmc, FX["bgp_filtered"])
    put = fmc.put(f"{R}/bgp/{BGP_ID}").mock(return_value=httpx.Response(200, json={}))
    args = {
        "device": DEV["name"],
        "redistribute": [{"protocol": "connected", "route_map": "none", "metric": 5}],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    assert body(put)["addressFamilyIPv4"]["redistributeProtocols"] == [
        {"type": "RedistributeConnected", "routeMetric": {"metricValue": 5}}
    ]
    assert preview["preview"]["redistribute_changes"]["changed"][0]["changes"] == {
        "route_map": {"from": "rm-peer-in", "to": None, "removed": True}
    }

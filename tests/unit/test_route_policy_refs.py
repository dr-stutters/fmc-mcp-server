"""F77 live finding (W6N live-B): FMC 10.0.1's non-expanded object/ipv4prefixlists listing has no `type`,
and a route map whose prefix-list reference carries type null is refused with HTTP 500 ("Prefix lists
cannot be added inside Access Lists and vice versa ..."). References get the collection's type when FMC's
row has none.

Shapes: tests/fixtures/route_policy_listings_fmc10.json (recorded live 2026-10-21, the request FMC refused
and the one it accepted)."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, empty, fixture, items, make_settings

LIVE = fixture("route_policy_listings_fmc10")
PL = LIVE["prefix_list_listing"]["items"][0]


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, rate_limit=100000))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def body(route: respx.Route) -> Any:
    return json.loads(route.calls.last.request.content)


async def test_route_map_on_the_recorded_listing_sends_what_fmc_accepted(fmc: respx.MockRouter) -> None:
    assert all("type" not in r for r in LIVE["prefix_list_listing"]["items"])  # the recorded listing
    fmc.get(f"{CFG}/object/ipv4prefixlists").mock(
        return_value=httpx.Response(200, json=LIVE["prefix_list_listing"])
    )
    fmc.get(f"{CFG}/object/routemaps").mock(return_value=empty())  # no route map of that name yet
    post = fmc.post(f"{CFG}/object/routemaps").mock(
        return_value=httpx.Response(201, json=LIVE["route_map_accepted"]["answer"])
    )
    args = {
        "name": "mcp-w6-t1-rm-conn",
        "entries": [{"action": "permit", "match_prefix_list": [PL["name"]]}],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_route_map", args)
        await run(c, "fmc_create_route_map", {**args, "confirm": preview["confirm"]})
    assert preview["preview"]["entries"] == ["seq 10 permit; match ip address prefix-list mcp-w6-t1-pl-conn"]
    assert preview["preview"]["body"] == LIVE["route_map_accepted"]["request"]
    assert body(post) == LIVE["route_map_accepted"]["request"]
    assert body(post) != LIVE["route_map_refused"]["request"]  # type null: FMC's 500


async def test_reference_by_uuid_gets_the_type_too(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/ipv4prefixlists").mock(
        return_value=httpx.Response(200, json=LIVE["prefix_list_listing"])
    )
    fmc.get(f"{CFG}/object/routemaps").mock(return_value=empty())
    async with Client(server()) as c:
        preview = await run(
            c,
            "fmc_create_route_map",
            {"name": "mcp-w6-rm-x", "entries": [{"action": "deny", "match_prefix_list": [PL["id"]]}]},
        )
    ref = preview["preview"]["body"]["entries"][0]["ipv4PrefixListAddresses"][0]
    assert ref == {"id": PL["id"], "type": "IPV4PrefixList", "name": PL["name"]}


async def test_other_lists_get_their_collection_type_and_fmcs_own_wins(fmc: respx.MockRouter) -> None:
    """Typeless rows of the community and AS-path list collections get the spec's types; a row with a
    type keeps FMC's spelling (the spec's examples call community lists CommunityListObject)."""
    fmc.get(f"{CFG}/object/routemaps").mock(return_value=empty())
    fmc.get(f"{CFG}/object/standardcommunitylists").mock(
        return_value=items([{"name": "cl-std", "id": "00000000-0000-0ed3-0000-000000000501"}])
    )
    fmc.get(f"{CFG}/object/expandedcommunitylists").mock(
        return_value=items(
            [{"name": "cl-exp", "id": "00000000-0000-0ed3-0000-000000000502", "type": "CommunityListObject"}]
        )
    )
    fmc.get(f"{CFG}/object/aspathlists").mock(
        return_value=items([{"name": 261, "id": "00000000-0000-0ed3-0000-000000000601"}])
    )
    args = {
        "name": "mcp-w6-rm-y",
        "entries": [
            {"match_community": ["cl-std"], "match_as_path": ["261"]},
            {"match_community": ["cl-exp"]},
        ],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_route_map", args)
    first, second = preview["preview"]["body"]["entries"]
    assert first["communityLists"] == [
        {"id": "00000000-0000-0ed3-0000-000000000501", "type": "StandardCommunityList", "name": "cl-std"}
    ]
    assert first["asPathLists"] == [
        {"id": "00000000-0000-0ed3-0000-000000000601", "type": "ASPathList", "name": 261}
    ]
    assert second["communityLists"][0]["type"] == "CommunityListObject"

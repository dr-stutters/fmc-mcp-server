"""BFD (F95): fmc_configure_bfd (template + per-device BFD policy) and bfd= on fmc_configure_bgp, replayed
from tests/fixtures/bfd_fmc10.json (spec-shaped: see its `_source`)."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, empty, fixture, items, make_settings

DEV = {"id": "6a0f3c1e-0000-4000-8000-00000000bfd0", "name": "mcp-bfd-ftd", "type": "Device"}
D = f"{CFG}/devices/devicerecords/{DEV['id']}"
R = f"{D}/routing"
FX = fixture("bfd_fmc10")
OUTSIDE, INSIDE, UNNAMED = FX["physicalinterfaces"]["items"]
TEMPLATES = f"{CFG}/object/bfdtemplates"
LO_LOCAL, LO_PEER, DIRECT = FX["hosts"]


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, rate_limit=100000))  # mocks: no throttle


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def body(route: respx.Route) -> Any:
    return json.loads(route.calls.last.request.content)


def mount(fmc: respx.MockRouter, policies: list[dict[str, Any]] | None = None, bgp: Any = None) -> None:
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
    fmc.get(TEMPLATES).mock(return_value=httpx.Response(200, json=FX["bfdtemplates"]))
    fmc.get(f"{R}/bfdpolicies").mock(return_value=items(policies or []))
    fmc.get(f"{R}/bgpgeneralsettings").mock(return_value=items([FX["bgpgeneralsettings"]]))
    fmc.get(f"{R}/bgp").mock(return_value=items([FX["bgp"] if bgp is None else bgp]))
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items(FX["hosts"]))
    fmc.get(f"{CFG}/object/networks").mock(return_value=empty())
    for h in FX["hosts"]:
        fmc.get(f"{CFG}/object/hosts/{h['id']}").mock(return_value=httpx.Response(200, json=h))


@pytest.fixture
def bfd(fmc: respx.MockRouter) -> respx.MockRouter:
    mount(fmc)
    return fmc


# --- fmc_configure_bfd ----------------------------------------------------------------------------


async def test_single_hop_creates_template_and_policy(bfd: respx.MockRouter) -> None:
    post_t = bfd.post(TEMPLATES).mock(return_value=httpx.Response(201, json={"id": "bfdt-new"}))
    post_p = bfd.post(f"{R}/bfdpolicies").mock(return_value=httpx.Response(201, json={"id": "bfdp-new"}))
    args = {"device": DEV["name"], "template": "mcp-bfd-fast", "interface": "outside", "min_tx_ms": 250}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bfd", args)
        p = preview["preview"]
        assert p["steps"] == ["create bfd template", "create bfd policy"]
        assert p["template"]["after"] == {
            "name": "mcp-bfd-fast",
            "hop": "single_hop",
            "min_tx": "250 ms",
            "min_rx": "300 ms",
            "multiplier": 3,
            "echo": None,
            "authentication": None,
        }
        assert p["policy"] == {
            "before": None,
            "after": {"hop": "single_hop", "template": "mcp-bfd-fast", "interface": "Ethernet0/0"},
        }
        # the directly connected neighbour has no fall-over BFD yet
        assert any("198.51.100.2 has no fall-over BFD" in w for w in p["warnings"])
        assert any("peer must run BFD" in w for w in p["warnings"])
        assert p["requests"][1]["body"]["template"]["id"] == "<id of the new BFD template>"
        done = await run(c, "fmc_configure_bfd", {**args, "confirm": preview["confirm"]})
    assert done["result"]["applied"] == ["create bfd template", "create bfd policy"]
    assert body(post_t) == {
        "type": "BFDTemplate",
        "name": "mcp-bfd-fast",
        "hopType": "SINGLE_HOP",
        "txRxInterval": "MILLISECONDS",
        "minTransmit": 250,
        "minReceive": 300,
        "txRxMultiplier": 3,
    }
    assert body(post_p) == {
        "type": "BFDPolicy",
        "hopType": "SINGLE_HOP",
        "interface": {"id": OUTSIDE["id"], "type": "PhysicalInterface", "name": "Ethernet0/0"},
        "template": {"id": "bfdt-new", "type": "BFDTemplate", "name": "mcp-bfd-fast"},
    }


async def test_reused_template_and_same_policy_is_blocked(fmc: respx.MockRouter) -> None:
    mount(fmc, policies=[FX["bfdpolicy_single"]])
    async with Client(server()) as c:
        same = await run(
            c,
            "fmc_configure_bfd",
            {"device": DEV["name"], "template": "mcp-bfd-single", "interface": "outside"},
        )
        wrong_hop = await run(
            c,
            "fmc_configure_bfd",
            {"device": DEV["name"], "template": "mcp-bfd-multi", "interface": "inside"},
        )
        unnamed = await run(
            c,
            "fmc_configure_bfd",
            {"device": DEV["name"], "template": "mcp-bfd-single", "interface": "Ethernet0/2"},
        )
    assert same["status"] == "blocked" and "already uses BFD template 'mcp-bfd-single'" in same["blockers"][0]
    assert (
        wrong_hop["status"] == "blocked"
        and "is multi_hop; this policy is single_hop" in wrong_hop["blockers"][0]
    )
    assert unnamed["status"] == "blocked" and "no logical name" in unnamed["blockers"][0]


async def test_changing_a_shared_template_warns_and_keeps_masked_keys(fmc: respx.MockRouter) -> None:
    mount(fmc, policies=[FX["bfdpolicy_single"]])
    put = fmc.put(f"{TEMPLATES}/bfdt-single").mock(return_value=httpx.Response(200, json={}))
    args = {
        "device": DEV["name"],
        "template": "mcp-bfd-single",
        "interface": "outside",
        "multiplier": 4,
        "echo": True,
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bfd", args)
        assert preview["preview"]["steps"] == ["update bfd template"]
        assert any("shared object" in w for w in preview["preview"]["warnings"])
        await run(c, "fmc_configure_bfd", {**args, "confirm": preview["confirm"]})
        masked = await run(
            c,
            "fmc_configure_bfd",
            {
                "device": DEV["name"],
                "template": "mcp-bfd-multi",
                "hop": "multi_hop",
                "source": "mcp-bfd-lo-local",
                "destination": "mcp-bfd-lo-peer",
                "min_tx_ms": 100,
            },
        )
    sent = body(put)
    assert sent["txRxMultiplier"] == 4 and sent["echo"] == "ENABLED" and "metadata" not in sent
    assert masked["status"] == "blocked" and "only returns masked" in masked["blockers"][0]


async def test_multi_hop_new_template_masks_key_and_flags_direct_peer(bfd: respx.MockRouter) -> None:
    post_t = bfd.post(TEMPLATES).mock(return_value=httpx.Response(201, json={"id": "bfdt-m2"}))
    post_p = bfd.post(f"{R}/bfdpolicies").mock(return_value=httpx.Response(201, json={}))
    loop = {
        "device": DEV["name"],
        "template": "mcp-bfd-mh",
        "hop": "multi_hop",
        "source": "203.0.113.1",
        "destination": "mcp-bfd-lo-peer",
        "auth_key": "s3cret-key",
        "auth_type": "sha1",
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bfd", loop)
        text = json.dumps(preview)
        assert "s3cret-key" not in text
        assert preview["preview"]["template"]["after"]["authentication"] == "sha1"
        # the loopback peer 203.0.113.9 has no multi-hop fall-over yet
        assert any("203.0.113.9 has no multi-hop fall-over BFD" in w for w in preview["preview"]["warnings"])
        await run(c, "fmc_configure_bfd", {**loop, "confirm": preview["confirm"]})
        direct = await run(
            c,
            "fmc_configure_bfd",
            {**loop, "destination": "mcp-bfd-direct-peer", "auth_key": None, "auth_type": None},
        )
    assert body(post_t)["authentication"] == {
        "authType": "SHA1",
        "pwdEncryption": "UN_ENCRYPTED",
        "authKey": "s3cret-key",
        "authKeyId": 1,
    }
    assert body(post_p) == {
        "type": "BFDPolicy",
        "hopType": "MULTI_HOP",
        "sourceAddress": {"id": LO_LOCAL["id"], "type": "Host", "name": "mcp-bfd-lo-local"},
        "destinationAddress": {"id": LO_PEER["id"], "type": "Host", "name": "mcp-bfd-lo-peer"},
        "template": {"id": "bfdt-m2", "type": "BFDTemplate", "name": "mcp-bfd-mh"},
    }
    warnings = direct["preview"]["warnings"]
    assert any("198.51.100.2 is directly connected" in w and "multi-hop template" in w for w in warnings)
    assert direct["preview"]["requests"][0]["body"]["authentication"] == {"authType": "NONE"}


async def test_remove_policy_warns_about_neighbors_still_using_it(fmc: respx.MockRouter) -> None:
    bgp = copy.deepcopy(FX["bgp"])
    bgp["addressFamilyIPv4"]["neighbors"][0]["neighborGeneral"]["fallOverBFD"] = "SINGLE_HOP"
    mount(fmc, policies=[FX["bfdpolicy_single"]], bgp=bgp)
    delete = fmc.delete(f"{R}/bfdpolicies/bfdp-1").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "template": "mcp-bfd-single", "interface": "outside", "remove": True}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bfd", args)
        assert preview["preview"]["policy"]["after"] is None
        assert any("198.51.100.2 keeps fall-over BFD" in w for w in preview["preview"]["warnings"])
        await run(c, "fmc_configure_bfd", {**args, "confirm": preview["confirm"]})
        missing = await c.call_tool(
            "fmc_configure_bfd", {**args, "interface": "inside"}, raise_on_error=False
        )
    assert delete.called
    assert missing.is_error and "No BFD policy on inside" in missing.content[0].text  # type: ignore[union-attr]


async def test_bad_combinations(bfd: respx.MockRouter) -> None:
    base = {"device": DEV["name"], "template": "t"}
    async with Client(server()) as c:
        outs = [
            await c.call_tool("fmc_configure_bfd", {**base, **a}, raise_on_error=False)
            for a in (
                {"source": "203.0.113.1"},
                {"hop": "multi_hop", "interface": "outside"},
                {"hop": "multi_hop", "source": "a", "destination": "b", "echo": True},
                {"interface": "outside", "auth_type": "md5"},
                {"interface": "outside", "remove": True, "multiplier": 5},
            )
        ]
    texts = [o.content[0].text for o in outs]  # type: ignore[union-attr]
    assert all(o.is_error for o in outs)
    assert "takes `interface`" in texts[0] and "takes `source` and `destination`" in texts[1]
    assert "single-hop only" in texts[2] and "needs auth_key" in texts[3] and "can't be combined" in texts[4]


# --- fmc_configure_bgp(bfd=...) -------------------------------------------------------------------


async def test_bgp_bfd_sets_fall_over_and_warns_without_a_policy(bfd: respx.MockRouter) -> None:
    put = bfd.put(f"{R}/bgp/b1").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "neighbor": "198.51.100.2", "bfd": "single_hop"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        w = preview["preview"]["bfd_warnings"]
        assert any("No single-hop BFD policy on outside" in x for x in w)
        assert preview["preview"]["after"]["neighbors"][0]["bfd"] == "SINGLE_HOP"
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
        multi = await run(c, "fmc_configure_bgp", {**args, "bfd": "multi_hop"})
        far = await run(c, "fmc_configure_bgp", {**args, "neighbor": "203.0.113.9"})
        removing = await c.call_tool(
            "fmc_configure_bgp", {**args, "remove_neighbor": True}, raise_on_error=False
        )
    sent = body(put)["addressFamilyIPv4"]["neighbors"]
    assert sent[0]["neighborGeneral"] == {
        "shutdown": False,
        "fallOverBFD": "SINGLE_HOP",
        "enableAddress": True,
    }
    assert sent[1]["neighborGeneral"]["fallOverBFD"] == "NONE"  # the other neighbour is sent back as it was
    assert any("is directly connected" in x for x in multi["preview"]["bfd_warnings"])
    assert any("isn't in a subnet of any interface" in x for x in far["preview"]["bfd_warnings"])
    assert removing.is_error and "bfd applies to `neighbor`" in removing.content[0].text  # type: ignore[union-attr]


async def test_bgp_bfd_with_a_matching_policy_only_reminds_about_the_peer(fmc: respx.MockRouter) -> None:
    mount(fmc, policies=[FX["bfdpolicy_single"]])
    async with Client(server()) as c:
        preview = await run(
            c, "fmc_configure_bgp", {"device": DEV["name"], "neighbor": "198.51.100.2", "bfd": "single_hop"}
        )
        off = await run(
            c, "fmc_configure_bgp", {"device": DEV["name"], "neighbor": "198.51.100.2", "bfd": "none"}
        )
    assert preview["preview"]["bfd_warnings"] == [
        "The peer must run BFD too ('bfd interval' or a BFD template, and 'neighbor 198.51.100.2 fall-over "
        "bfd'), or the session stays down."
    ]
    assert off["status"] == "blocked" and "already configured that way" in off["blockers"][0]


async def test_microsecond_template_keeps_its_unit_unless_both_intervals_are_given(
    fmc: respx.MockRouter,
) -> None:
    mount(fmc, policies=[FX["bfdpolicy_single"]])
    tpls = copy.deepcopy(FX["bfdtemplates"])
    us = tpls["items"][0]
    us.update({"txRxInterval": "MICROSECONDS", "minTransmit": 50000, "minReceive": 50000})
    fmc.get(TEMPLATES).mock(return_value=httpx.Response(200, json=tpls))
    base = {"device": DEV["name"], "template": "mcp-bfd-single", "interface": "outside"}
    async with Client(server()) as c:
        mult = await run(c, "fmc_configure_bfd", {**base, "multiplier": 4})
        half = await run(c, "fmc_configure_bfd", {**base, "min_tx_ms": 300})
        both = await run(c, "fmc_configure_bfd", {**base, "min_tx_ms": 300, "min_rx_ms": 300})
    sent = mult["preview"]["requests"][0]["body"]
    assert (
        sent["txRxInterval"] == "MICROSECONDS"
        and sent["minTransmit"] == 50000
        and sent["txRxMultiplier"] == 4
    )
    assert half["status"] == "blocked" and "microseconds" in half["blockers"][0]
    after = both["preview"]["requests"][0]["body"]
    assert (
        after["txRxInterval"] == "MILLISECONDS" and after["minTransmit"] == 300 and after["minReceive"] == 300
    )

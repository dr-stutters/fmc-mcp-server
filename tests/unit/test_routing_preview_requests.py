"""F77 live finding (W6N live-B): fmc_configure_bgp's preview listed its steps but no request bodies, so a
preview-parity run had to rebuild them from the code. The BGP and OSPF previews now show each request
(`requests`: step, method, path, body), exactly what the confirm sends, with an MD5 password masked.

Shapes: tests/fixtures/bgp_preview_parity_fmc10.json (the two requests live-B sent on the t1 hub,
2026-10-21)."""

import copy
from typing import Any

import httpx
import respx
from fastmcp import Client

from .conftest import CFG, empty, fixture, items
from .test_route_policy import DEV, FX, GENERAL, OSPF_ID, R, body, mount, run, server

LIVE = fixture("bgp_preview_parity_fmc10")
BGP_ID = FX["bgp_recorded"]["id"]


async def test_from_scratch_requests_are_what_the_confirm_sends(fmc: respx.MockRouter) -> None:
    """live-B's hub call (less default_originate, see test_bgp_default_originate.py on main): the preview's
    requests are the recorded bodies and the confirm sends exactly those."""
    mount(fmc)
    fmc.get(f"{R}/bgpgeneralsettings").mock(return_value=empty())
    fmc.get(f"{R}/bgp").mock(return_value=empty())
    fmc.get(f"{CFG}/object/networks").mock(return_value=items([LIVE["network"]]))
    fmc.get(f"{CFG}/object/routemaps").mock(return_value=items([LIVE["route_map"]]))
    gen = fmc.post(f"{R}/bgpgeneralsettings").mock(
        return_value=httpx.Response(201, json=LIVE["general_answer"])
    )
    post = fmc.post(f"{R}/bgp").mock(return_value=httpx.Response(201, json={"id": "b"}))
    args = {
        "device": DEV["name"],
        "local_as": "65110",
        "router_id": "198.51.100.1",
        "neighbor": "192.0.2.2",
        "remote_as": "65110",
        "neighbor_description": "spoke1 transport",
        "advertise": [LIVE["network"]["name"]],
        "redistribute": [{"protocol": "connected", "route_map": LIVE["route_map"]["name"]}],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    shown = preview["preview"]["requests"]
    assert [(r["step"], r["method"]) for r in shown] == [
        ("create bgp general settings", "POST"),
        ("create bgp", "POST"),
    ]
    assert shown[0]["path"].endswith(f"/devices/devicerecords/{DEV['id']}/routing/bgpgeneralsettings")
    assert shown[1]["path"].endswith(f"/devices/devicerecords/{DEV['id']}/routing/bgp")
    recorded = copy.deepcopy(LIVE["bgp_request"])
    del recorded["addressFamilyIPv4"]["neighbors"][0]["neighborFiltering"]  # default_originate's part
    assert shown[0]["body"] == LIVE["general_request"] == body(gen)
    assert shown[1]["body"] == recorded == body(post)


async def test_md5_password_is_masked_in_the_preview_only(fmc: respx.MockRouter) -> None:
    mount(fmc)
    put = fmc.put(f"{R}/bgp/{BGP_ID}").mock(return_value=httpx.Response(200, json={}))
    args = {
        "device": DEV["name"],
        "neighbor": "192.0.2.2",
        "neighbor_description": "edge peer",
        "neighbor_password": "md5-Secret-1",
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", args)
        await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
    (req,) = preview["preview"]["requests"]
    assert req["method"] == "PUT" and req["path"].endswith(f"/routing/bgp/{BGP_ID}")
    shown = req["body"]["addressFamilyIPv4"]["neighbors"][0]["neighborAdvanced"]
    assert shown["neighborSecret"] == "********" and "md5-Secret-1" not in str(preview)
    wire = body(put)
    assert wire["addressFamilyIPv4"]["neighbors"][0]["neighborAdvanced"]["neighborSecret"] == "md5-Secret-1"
    masked = copy.deepcopy(wire)
    masked["addressFamilyIPv4"]["neighbors"][0]["neighborAdvanced"]["neighborSecret"] = "********"
    assert req["body"] == masked  # nothing else differs


async def test_remove_bgp_lists_the_deletes(fmc: respx.MockRouter) -> None:
    mount(fmc)
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_bgp", {"device": DEV["name"], "remove_bgp": True})
    assert [(r["step"], r["method"], "body" in r) for r in preview["preview"]["requests"]] == [
        ("delete bgp", "DELETE", False),
        ("delete bgp general settings", "DELETE", False),
    ]
    assert preview["preview"]["requests"][1]["path"].endswith(f"/routing/bgpgeneralsettings/{GENERAL['id']}")


async def test_blocked_preview_has_no_requests(fmc: respx.MockRouter) -> None:
    mount(fmc)
    async with Client(server()) as c:
        out = await run(
            c, "fmc_configure_bgp", {"device": DEV["name"], "neighbor": "192.0.2.2", "remote_as": "65001"}
        )
    assert out["status"] == "blocked" and "requests" not in out["preview"]


async def test_ospf_preview_shows_its_request(fmc: respx.MockRouter) -> None:
    mount(fmc)
    put = fmc.put(f"{R}/ospfv2routes/{OSPF_ID}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "area": "0", "add_networks": ["lab-net"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_ospf", args)
        await run(c, "fmc_configure_ospf", {**args, "confirm": preview["confirm"]})
    (req,) = preview["preview"]["requests"]
    assert (req["step"], req["method"]) == ("update ospf process", "PUT")
    assert req["path"].endswith(f"/routing/ospfv2routes/{OSPF_ID}")
    assert req["body"] == body(put)


# Review of #307: core's mask_secrets leaves a secret-named value that looks like a flag ('on', 'off', 'true',
# ...) in clear. A routing password or key is masked in the preview body whatever its value.


async def test_a_flag_looking_md5_password_is_masked_too(fmc: respx.MockRouter) -> None:
    for password in ("on", "true", "off", "Yes"):
        mount(fmc)
        put = fmc.put(f"{R}/bgp/{BGP_ID}").mock(return_value=httpx.Response(200, json={}))
        args = {
            "device": DEV["name"],
            "neighbor": "192.0.2.2",
            "neighbor_description": "edge peer",
            "neighbor_password": password,
        }
        async with Client(server()) as c:
            preview = await run(c, "fmc_configure_bgp", args)
            assert preview["status"] == "preview", preview
            await run(c, "fmc_configure_bgp", {**args, "confirm": preview["confirm"]})
        (req,) = preview["preview"]["requests"]
        shown = req["body"]["addressFamilyIPv4"]["neighbors"][0]["neighborAdvanced"]
        assert shown["neighborSecret"] == "********", password
        wire = body(put)["addressFamilyIPv4"]["neighbors"][0]["neighborAdvanced"]
        assert wire["neighborSecret"] == password


def ospf_with_keys() -> dict[str, Any]:
    """The recorded OSPF process with a virtual link that authenticates with a password and MD5 keys
    (IOspfAuthentication in the FMC 10.0.1 spec), values that look like flags among them."""
    proc = copy.deepcopy(FX["ospf_recorded"])
    proc["areas"][0]["virtualLinks"] = [
        {
            "routerId": "198.51.100.7",
            "helloInterval": 10,
            "authentication": {
                "passwdAuth": {"authKey": "on", "authType": "PASSWORD"},
                "md5AuthList": [
                    {"md5KeyId": 1, "md5Key": "true", "authType": "MESSAGE_DIGEST"},
                    {"md5KeyId": 2, "md5Key": "ospf-K3y-2", "authType": "MESSAGE_DIGEST"},
                ],
                "areaAuth": {"md5AuthList": [{"md5KeyId": 3, "md5Key": "off"}]},
            },
        }
    ]
    return proc


async def test_ospf_keys_are_masked_in_the_preview_body(fmc: respx.MockRouter) -> None:
    mount(fmc)
    fmc.get(f"{R}/ospfv2routes").mock(return_value=items([ospf_with_keys()]))
    put = fmc.put(f"{R}/ospfv2routes/{OSPF_ID}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "area": "0", "add_networks": ["lab-net"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_ospf", args)
        await run(c, "fmc_configure_ospf", {**args, "confirm": preview["confirm"]})
    (req,) = preview["preview"]["requests"]
    auth = req["body"]["areas"][0]["virtualLinks"][0]["authentication"]
    assert auth["passwdAuth"] == {"authKey": "********", "authType": "********"}
    assert [k["md5Key"] for k in auth["md5AuthList"]] == ["********", "********"]
    assert auth["areaAuth"]["md5AuthList"][0]["md5Key"] == "********"
    for secret in ("ospf-K3y-2", "'on'", "'off'"):
        assert secret not in str(req["body"]), secret
    wire = body(put)["areas"][0]["virtualLinks"][0]
    assert wire["authentication"] == ospf_with_keys()["areas"][0]["virtualLinks"][0]["authentication"]
    assert req["body"]["areas"][0]["virtualLinks"][0]["helloInterval"] == 10  # nothing else masked

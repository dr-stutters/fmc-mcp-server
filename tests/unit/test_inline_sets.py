"""F96: fmc_create_inline_set / fmc_update_inline_set / fmc_delete_inline_set, fmc_update_interface mode,
and the inline sets in fmc_get_device and the device export.

The device and its routed interfaces are the ones recorded from mcp-ftd1 (tests/fixtures/ftd_*.json,
FMC 10.0.1 / FTDv 10.0.0); the lab's FTDs answer the inlinesets collection with an empty page (recorded
live 2026-10-28). The spare interfaces and the inline sets follow the FMC 10.0.1 spec (InlineSet, its
POST example: inlinepairs [{first, second}] of interface refs, tapMode, failOpenSnortDown/Busy,
propogateLinkState, strictTCPEnforcement, mtu)."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.tools.device_export import parse_export
from fmc_mcp.tools.devices import inline_set_row

from .conftest import CFG, empty, items
from .test_tools_ftd import DEVPATH, PHYS, ZONES, confirm, ftd, preview_of, run, server  # noqa: F401  (ftd is a fixture)

INLINE_ZONE = {"id": "zone-inline", "name": "mcp-ips-in", "type": "SecurityZone", "interfaceMode": "INLINE"}
ROUTED_ZONES = [{**z, "interfaceMode": "ROUTED"} for z in ZONES]


def spare(name: str, n: int, **kw: Any) -> dict[str, Any]:
    """A spare FTDv data interface (as unconfigured ones are recorded: mode NONE, no name or address)."""
    return {
        "type": "PhysicalInterface",
        "name": name,
        "id": f"00000000-0000-0ed3-0000-02147483760{n}",
        "enabled": True,
        "mode": "NONE",
        "MTU": 1500,
        "managementOnly": False,
        **kw,
    }


def inline(name: str, n: int, ifname: str, zone: dict[str, Any] | None = INLINE_ZONE) -> dict[str, Any]:
    out = spare(name, n, mode="INLINE", ifname=ifname)
    if zone:
        out["securityZone"] = {"id": zone["id"], "type": "SecurityZone"}
    return out


E2 = inline("Ethernet0/2", 2, "ips-a")
E3 = inline("Ethernet0/3", 3, "ips-b")
E4 = inline("Ethernet0/4", 4, "ips-c")
E5 = inline("Ethernet0/5", 5, "ips-d")


def ref(i: dict[str, Any]) -> dict[str, Any]:
    return {"id": i["id"], "type": "PhysicalInterface", "name": i["name"]}


EXISTING = {
    "id": "iset-1",
    "name": "mcp-ips-pilot",
    "type": "InlineSet",
    "inlinepairs": [{"first": ref(E2), "second": ref(E3)}],
    "tapMode": True,
    "failOpenSnortDown": True,
    "failOpenSnortBusy": False,
    "propogateLinkState": True,
    "strictTCPEnforcement": False,
    "mtu": 1500,
    "metadata": {"timestamp": 1},
    "links": {"self": "x"},
}


@pytest.fixture
def ips(ftd: respx.MockRouter) -> respx.MockRouter:  # noqa: F811
    """mcp-ftd1 with Ethernet0/2-0/5 spare as inline interfaces and no inline set."""
    phys = [*copy.deepcopy(PHYS), E2, E3, E4, E5]
    ftd.get(f"{DEVPATH}/physicalinterfaces").mock(return_value=items(phys))
    for i in phys:
        ftd.get(f"{DEVPATH}/physicalinterfaces/{i['id']}").mock(return_value=httpx.Response(200, json=i))
    ftd.get(f"{CFG}/object/securityzones").mock(return_value=items([*ROUTED_ZONES, INLINE_ZONE]))
    for z in [*ROUTED_ZONES, INLINE_ZONE]:
        ftd.get(f"{CFG}/object/securityzones/{z['id']}").mock(return_value=httpx.Response(200, json=z))
    ftd.get(f"{DEVPATH}/inlinesets").mock(return_value=empty())
    return ftd


def with_set(fmc: respx.MockRouter, s: dict[str, Any] = EXISTING) -> None:
    fmc.get(f"{DEVPATH}/inlinesets").mock(return_value=items([s]))
    fmc.get(f"{DEVPATH}/inlinesets/{s['id']}").mock(return_value=httpx.Response(200, json=s))


# --- create --------------------------------------------------------------------------------------


async def test_create_inline_set_body_follows_the_spec(ips: respx.MockRouter) -> None:
    post = ips.post(f"{DEVPATH}/inlinesets").mock(return_value=httpx.Response(201, json={"id": "new"}))
    preview, done = await confirm(
        "fmc_create_inline_set",
        {"device": "mcp-ftd1", "name": "mcp-ips", "pairs": [["Ethernet0/2", "ips-b"]], "tap_mode": True},
    )
    assert preview["action"].startswith("Create inline set mcp-ips on mcp-ftd1 (tap mode, 1 pair)")
    assert any("drops nothing" in w for w in preview["preview"]["warnings"])
    assert [m["interface"] for m in preview["preview"]["members"]] == ["Ethernet0/2", "Ethernet0/3"]
    body = json.loads(post.calls.last.request.content)
    assert body == {
        "type": "InlineSet",
        "name": "mcp-ips",
        "inlinepairs": [{"first": ref(E2), "second": ref(E3)}],
        "tapMode": True,
        "failOpenSnortDown": True,
        "failOpenSnortBusy": False,
        "propogateLinkState": True,
        "strictTCPEnforcement": False,
    }
    assert done["status"] == "applied"


async def test_create_inline_set_inline_note_and_mtu(ips: respx.MockRouter) -> None:
    post = ips.post(f"{DEVPATH}/inlinesets").mock(return_value=httpx.Response(201, json={"id": "new"}))
    preview, _ = await confirm(
        "fmc_create_inline_set",
        {
            "device": "mcp-ftd1",
            "name": "mcp-ips",
            "pairs": [["Ethernet0/2", "Ethernet0/3"], ["Ethernet0/4", "Ethernet0/5"]],
            "fail_open_snort_down": False,
            "propagate_link_state": False,
            "mtu": 1518,
        },
    )
    warnings = preview["preview"]["warnings"]
    assert any("dropped" in w for w in warnings) and not any("drops nothing" in w for w in warnings)
    assert any("Snort restarts" in w for w in warnings) and any("Link-state" in w for w in warnings)
    body = json.loads(post.calls.last.request.content)
    assert len(body["inlinepairs"]) == 2 and body["mtu"] == 1518 and body["propogateLinkState"] is False


async def test_create_blocks_routed_interfaces(ips: respx.MockRouter) -> None:
    out = await preview_of(
        "fmc_create_inline_set",
        {"device": "mcp-ftd1", "name": "mcp-ips", "pairs": [["inside", "Ethernet0/2"]]},
    )
    assert out["status"] == "blocked"
    text = " ".join(out["blockers"])
    assert "has an IP address (10.99.1.1/24)" in text
    assert "mode NONE (routed)" in text and "mode='inline'" in text
    assert "ROUTED zone 'mcp-test-ftd-in'" in text


async def test_create_blocks_management_duplicates_and_same_interface(ips: respx.MockRouter) -> None:
    out = await preview_of(
        "fmc_create_inline_set",
        {
            "device": "mcp-ftd1",
            "name": "mcp-ips",
            "pairs": [["Ethernet0/2", "Ethernet0/2"], ["Management0/0", "Ethernet0/3"]],
        },
    )
    text = " ".join(out["blockers"])
    assert "not Ethernet0/2 twice" in text and "Ethernet0/2 is named twice" in text
    assert "Management0/0 is a management interface" in text


async def test_create_blocks_unnamed_inline_and_already_paired(ips: respx.MockRouter) -> None:
    unnamed = spare("Ethernet0/6", 6, mode="INLINE")
    phys = [*copy.deepcopy(PHYS), E2, E3, E4, E5, unnamed]
    ips.get(f"{DEVPATH}/physicalinterfaces").mock(return_value=items(phys))
    with_set(ips)
    out = await preview_of(
        "fmc_create_inline_set",
        {"device": "mcp-ftd1", "name": "mcp-ips-pilot", "pairs": [["Ethernet0/2", "Ethernet0/6"]]},
    )
    text = " ".join(out["blockers"])
    assert "Ethernet0/2 is already in inline set 'mcp-ips-pilot'" in text
    assert "Ethernet0/6 needs a logical name" in text
    assert "already has an inline set named 'mcp-ips-pilot'" in text


async def test_create_blocks_subinterface_member_and_parent(ips: respx.MockRouter) -> None:
    sub = {"type": "SubInterface", "name": "Ethernet0/4", "id": "sub-1", "subIntfId": 10, "vlanId": 10}
    ips.get(f"{DEVPATH}/subinterfaces").mock(return_value=items([sub]))
    out = await preview_of(
        "fmc_create_inline_set",
        {"device": "mcp-ftd1", "name": "mcp-ips", "pairs": [["Ethernet0/4", "Ethernet0/4.10"]]},
    )
    text = " ".join(out["blockers"])
    assert "Ethernet0/4.10 is a subinterface" in text and "Ethernet0/4 has subinterfaces" in text


# --- update / delete -----------------------------------------------------------------------------


async def test_update_leaves_tap_mode(ips: respx.MockRouter) -> None:
    with_set(ips)
    put = ips.put(f"{DEVPATH}/inlinesets/iset-1").mock(return_value=httpx.Response(200, json=EXISTING))
    preview, done = await confirm(
        "fmc_update_inline_set", {"device": "mcp-ftd1", "inline_set": "mcp-ips-pilot", "tap_mode": False}
    )
    assert preview["preview"]["changes"] == {"tap_mode": {"from": True, "to": False}}
    assert preview["preview"]["warnings"][0].startswith("Leaving tap mode")
    body = json.loads(put.calls.last.request.content)
    assert body["tapMode"] is False and "metadata" not in body and "links" not in body
    assert body["inlinepairs"] == EXISTING["inlinepairs"]
    assert done["status"] == "applied"


async def test_update_pairs_and_noop(ips: respx.MockRouter) -> None:
    with_set(ips)
    put = ips.put(f"{DEVPATH}/inlinesets/iset-1").mock(return_value=httpx.Response(200, json=EXISTING))
    preview, _ = await confirm(
        "fmc_update_inline_set",
        {
            "device": "mcp-ftd1",
            "inline_set": "iset-1",
            "add_pairs": [["Ethernet0/4", "Ethernet0/5"]],
            "remove_pairs": ["Ethernet0/3"],
        },
    )
    assert preview["preview"]["changes"]["pairs"]["to"] == [["Ethernet0/4", "Ethernet0/5"]]
    assert json.loads(put.calls.last.request.content)["inlinepairs"] == [
        {"first": ref(E4), "second": ref(E5)}
    ]
    out = await preview_of(
        "fmc_update_inline_set", {"device": "mcp-ftd1", "inline_set": "mcp-ips-pilot", "tap_mode": True}
    )
    assert out["status"] == "blocked" and any("Nothing to change" in b for b in out["blockers"])
    out = await preview_of(
        "fmc_update_inline_set",
        {"device": "mcp-ftd1", "inline_set": "mcp-ips-pilot", "add_pairs": [["Ethernet0/3", "Ethernet0/4"]]},
    )
    assert any("Ethernet0/3 is already in inline set" in b for b in out["blockers"])
    out = await preview_of(
        "fmc_update_inline_set",
        {"device": "mcp-ftd1", "inline_set": "mcp-ips-pilot", "remove_pairs": ["Ethernet0/2"]},
    )
    assert any("at least one pair" in b for b in out["blockers"])


async def test_delete_inline_set(ips: respx.MockRouter) -> None:
    with_set(ips)
    delete = ips.delete(f"{DEVPATH}/inlinesets/iset-1").mock(return_value=httpx.Response(200, json=EXISTING))
    preview, done = await confirm(
        "fmc_delete_inline_set", {"device": "mcp-ftd1", "inline_set": "mcp-ips-pilot"}
    )
    assert any("Ethernet0/2 and Ethernet0/3 no longer passes" in s for s in preview["side_effects"])
    assert delete.called and done["status"] == "applied"


# --- fmc_update_interface mode -------------------------------------------------------------------


async def test_update_interface_to_inline(ips: respx.MockRouter) -> None:
    e6 = spare("Ethernet0/6", 6)
    phys = [*copy.deepcopy(PHYS), e6]
    ips.get(f"{DEVPATH}/physicalinterfaces").mock(return_value=items(phys))
    ips.get(f"{DEVPATH}/physicalinterfaces/{e6['id']}").mock(return_value=httpx.Response(200, json=e6))
    put = ips.put(f"{DEVPATH}/physicalinterfaces/{e6['id']}").mock(return_value=httpx.Response(200, json=e6))
    preview, _ = await confirm(
        "fmc_update_interface",
        {
            "device": "mcp-ftd1",
            "interface": "Ethernet0/6",
            "mode": "inline",
            "logical_name": "ips-e",
            "security_zone": "mcp-ips-in",
        },
    )
    assert preview["preview"]["changes"]["mode"] == {"from": "NONE", "to": "INLINE"}
    body = json.loads(put.calls.last.request.content)
    assert (
        body["mode"] == "INLINE" and body["ifname"] == "ips-e" and body["securityZone"]["id"] == "zone-inline"
    )


async def test_update_interface_inline_blocks_address_and_routed_zone(ips: respx.MockRouter) -> None:
    out = await preview_of(
        "fmc_update_interface", {"device": "mcp-ftd1", "interface": "inside", "mode": "inline"}
    )
    text = " ".join(out["blockers"])
    assert "An inline interface takes no IP address" in text
    assert "'mcp-test-ftd-in' is ROUTED" in text
    out = await preview_of(
        "fmc_update_interface",
        {
            "device": "mcp-ftd1",
            "interface": "inside",
            "mode": "inline",
            "ipv4": "none",
            "security_zone": "none",
        },
    )
    assert out["status"] == "preview", out


# --- reads ---------------------------------------------------------------------------------------


def test_inline_set_row() -> None:
    row = inline_set_row(EXISTING)
    assert row["pairs"] == [["Ethernet0/2", "Ethernet0/3"]] and row["tap_mode"] is True
    assert row["propagate_link_state"] is True and "metadata" not in row


async def test_get_device_lists_inline_sets(ips: respx.MockRouter) -> None:
    with_set(ips)
    out = await preview_of("fmc_get_device", {"device": "mcp-ftd1"})
    assert out["inline_sets"][0]["name"] == "mcp-ips-pilot"
    assert out["inline_sets"][0]["pairs"] == [["Ethernet0/2", "Ethernet0/3"]]


async def test_get_device_without_inline_sets(ips: respx.MockRouter) -> None:
    ips.get(f"{DEVPATH}/inlinesets").mock(return_value=httpx.Response(405, json={"error": {"messages": []}}))
    out = await preview_of("fmc_get_device", {"device": "mcp-ftd1"})
    assert "inline_sets" not in out


async def test_export_inline_sets_section(ips: respx.MockRouter) -> None:
    with_set(ips)
    async with Client(server()) as c:
        out = await run(c, "fmc_export_device_config", {"device": "mcp-ftd1", "sections": ["inline_sets"]})
    doc = parse_export(out["export"], None)
    assert doc["inline_sets"] == {
        "mcp-ips-pilot": {
            "fail_open_snort_busy": False,
            "fail_open_snort_down": True,
            "mtu": 1500,
            "pairs": [["Ethernet0/2", "Ethernet0/3"]],
            "propagate_link_state": True,
            "strict_tcp": False,
            "tap_mode": True,
        }
    }

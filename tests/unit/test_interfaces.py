"""F58: fmc_create_interface (loopback, VTI, EtherChannel, BVI) and how fmc_update_interface /
fmc_delete_interface handle those kinds. The device's interfaces are the ones recorded from mcp-ftd1
(tests/fixtures/ftd_interface_kinds.json, FMC 10.0.1, FTDv 10.0.0); the logical interfaces added on top
follow the FMC 10.0.1 spec examples kept in that file under `created`."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp._core import InvalidRequest
from fmc_mcp.server import create_server
from fmc_mcp.tools.device_config import LOGICAL_KINDS, plan_logical_interface
from fmc_mcp.tools.devices import INTERFACE_KINDS, interface_row

from .conftest import CFG, fixture, items, make_settings

REC = fixture("ftd_interface_kinds")
DEV = {**REC["device"], "id": REC["device"]["id"]}
DEVPATH = f"{CFG}/devices/devicerecords/{DEV['id']}"
ZONES = [
    {"id": "d1686144-c9d6-11f1-a4e0-98786f180443", "name": "mcp-test-ftd-out", "type": "SecurityZone"},
    {"id": "d06d930e-c9d6-11f1-a4e0-98786f180443", "name": "mcp-test-ftd-in", "type": "SecurityZone"},
    {"id": "aaaaaaaa-0000-0000-0000-00000000000a", "name": "mcp-fw-overlay", "type": "SecurityZone"},
]
COLLECTION = {v: k for k, v in INTERFACE_KINDS.items()}  # loopbackinterfaces -> loopback


def recorded() -> dict[str, list[dict[str, Any]]]:
    """kind -> interfaces, as on mcp-ftd1 (the collections FTDv supports)."""
    out: dict[str, list[dict[str, Any]]] = {}
    for coll, kind in COLLECTION.items():
        page = REC.get(coll) or {}
        if "status" not in page:
            out[kind] = copy.deepcopy(page.get("items") or [])
    return out


def unconfigured(name: str, n: int, enabled: bool = True) -> dict[str, Any]:
    """A spare FTDv data interface: no name, zone or address."""
    return {
        "type": "PhysicalInterface",
        "name": name,
        "id": f"00000000-0000-0ed3-0000-02147483753{n}",
        "enabled": enabled,
        "mode": "NONE",
        "MTU": 1500,
        "managementOnly": False,
    }


LOOPBACK = {
    "type": "LoopbackInterface",
    "name": "Loopback1",
    "id": "lo-1",
    "loopbackId": 1,
    "enabled": True,
    "ifname": "vti-lo",
    "ipv4": {"static": {"address": "198.51.100.201", "netmask": "32"}},
}
VTI = {  # a spoke VTI an SD-WAN topology created: borrows Loopback1, sourced from outside
    "type": "VTIInterface",
    "name": "Tunnel1",
    "id": "vti-1",
    "tunnelId": 1,
    "tunnelType": "STATIC",
    "enabled": True,
    "ifname": "sdwan-vti1",
    "tunnelSource": {
        "id": "00000000-0000-0ed3-0000-021474837527",
        "name": "Ethernet0/0",
        "type": "PhysicalInterface",
    },
    "ipAddressAssignmentType": "BORROW_IP_FROM_INTERFACE",
    "borrowIPfrom": {"id": "lo-1", "name": "Loopback1", "type": "LoopbackInterface"},
    "ipsecMode": "ipv4",
    "managementOnly": False,
    "metadata": {"vpnTopologyName": "mcp-fw-t1"},
}


def as_items(kinds: dict[str, list[dict[str, Any]]]) -> list[tuple[str, dict[str, Any]]]:
    return [(k, i) for k, rows in kinds.items() for i in rows]


def plan(kind: str, kinds: dict[str, list[dict[str, Any]]] | None = None, **kw: Any) -> Any:
    args: dict[str, Any] = {
        "logical_name": None,
        "number": None,
        "members": [],
        "zone": None,
        "ipv4": None,
        "tunnel_source": None,
        "tunnel_type": "static",
        "borrow_ip_from": None,
        "lacp_mode": "active",
        "mtu": None,
        "description": None,
        "enabled": True,
        **kw,
    }
    return plan_logical_interface(kind, DEV, as_items(kinds or recorded()), **args)


# --- the planner (pure) ---------------------------------------------------------------------------


def test_loopback_body_follows_the_spec_example() -> None:
    p = plan("loopback", logical_name="bgp-lo", ipv4="198.51.100.1/32")
    assert p.hardware_name == "Loopback1" and not p.blockers
    assert p.body == {
        "type": "LoopbackInterface",
        "loopbackId": 1,
        "enabled": True,
        "ifname": "bgp-lo",
        "ipv4": {"static": {"address": "198.51.100.1", "netmask": "32"}},
    }
    spec = REC["created"]["loopbackinterfaces"]
    assert set(p.body) <= set(spec) and p.body["type"] == spec["type"]
    assert plan("loopback", logical_name="lo5", number=5).hardware_name == "Loopback5"


def test_loopback_overlap_name_and_id_clashes_block() -> None:
    kinds = {**recorded(), "loopback": [LOOPBACK]}
    p = plan("loopback", kinds, logical_name="inside", number=1, ipv4="10.99.1.5/32")
    assert any("overlaps Ethernet0/1 (10.99.1.1/24)" in b for b in p.blockers)
    assert any("'inside' is already used by Ethernet0/1" in b for b in p.blockers)
    assert any("id 1 is already Loopback1" in b for b in p.blockers)
    assert plan("loopback", kinds, logical_name="lo2").hardware_name == "Loopback2"  # next free id


@pytest.mark.parametrize(
    ("kind", "kw", "message"),
    [
        ("loopback", {"logical_name": "lo", "zone": {"id": "z"}}, "takes no security zone"),
        ("loopback", {"logical_name": "lo", "ipv4": "dhcp"}, "static address only"),
        ("loopback", {"logical_name": "lo", "mtu": 1400}, "no MTU"),
        ("loopback", {}, "needs a logical_name"),
        ("loopback", {"logical_name": "lo", "members": ["Ethernet0/1"]}, "members are for"),
        ("loopback", {"logical_name": "lo", "tunnel_source": "outside"}, "are for vti"),
        ("vti", {"logical_name": "t", "ipv4": "198.51.100.5/30"}, "needs tunnel_source"),
        ("vti", {"logical_name": "t", "tunnel_source": "outside"}, "exactly one of ipv4"),
        (
            "vti",
            {
                "logical_name": "t",
                "tunnel_source": "outside",
                "ipv4": "198.51.100.5/30",
                "borrow_ip_from": "x",
            },
            "exactly one of ipv4",
        ),
        ("vti", {"logical_name": "t", "tunnel_source": "outside", "tunnel_type": "dynamic"}, "borrows its"),
        ("vti", {"logical_name": "t", "tunnel_source": "outside", "ipv4": "dhcp"}, "static address only"),
        (
            "vti",
            {"logical_name": "t", "tunnel_source": "o", "ipv4": "198.51.100.5/30", "lacp_mode": "on"},
            "lacp",
        ),
        ("etherchannel", {}, "needs members"),
        ("etherchannel", {"members": ["Ethernet0/2"], "number": 49}, "ids run 1-48"),
        ("bvi", {"members": ["Ethernet0/2"], "zone": {"id": "z"}}, "zone its member interfaces"),
        ("bvi", {"members": [f"Ethernet0/{n}" for n in range(65)]}, "at most 64"),
    ],
)
def test_arguments_that_dont_fit_the_kind(kind: str, kw: dict[str, Any], message: str) -> None:
    with pytest.raises(InvalidRequest, match=message):
        plan(kind, **kw)


def test_static_vti_sourced_from_the_wan() -> None:
    zone = {"id": ZONES[2]["id"], "type": "SecurityZone", "name": "mcp-fw-overlay"}
    p = plan("vti", logical_name="s2s-1", tunnel_source="outside", ipv4="169.254.100.1/30", zone=zone)
    assert p.hardware_name == "Tunnel1" and not p.blockers
    b = p.body
    assert b["type"] == "VTIInterface" and b["tunnelType"] == "STATIC" and b["tunnelId"] == 1
    assert b["tunnelSource"] == {
        "id": "00000000-0000-0ed3-0000-021474837527",
        "type": "PhysicalInterface",
        "name": "Ethernet0/0",
    }
    assert b["ipsecMode"] == "ipv4" and b["securityZone"] == zone
    assert b["ipv4"] == {"static": {"address": "169.254.100.1", "netmask": "30"}}
    assert "borrowIPfrom" not in b
    assert set(b) <= set(REC["created"]["virtualtunnelinterfaces"]) | {"description", "MTU"}


def test_dynamic_vti_borrows_a_loopback() -> None:
    kinds = {**recorded(), "loopback": [LOOPBACK]}
    p = plan(
        "vti",
        kinds,
        logical_name="hub-dvti",
        tunnel_source="Ethernet0/0",
        tunnel_type="dynamic",
        borrow_ip_from="vti-lo",
    )
    assert p.hardware_name == "Virtual-Template1" and not p.blockers
    assert p.body["tunnelType"] == "DYNAMIC"
    assert p.body["ipAddressAssignmentType"] == "BORROW_IP_FROM_INTERFACE"
    assert p.body["borrowIPfrom"] == {"id": "lo-1", "type": "LoopbackInterface", "name": "Loopback1"}
    assert "ipv4" not in p.body


def test_vti_source_and_borrow_problems_block() -> None:
    kinds = recorded()
    p = plan("vti", kinds, logical_name="t", tunnel_source="Management0/0", borrow_ip_from="Management0/0")
    assert any("management interface" in b for b in p.blockers)
    assert any("no static IPv4 address for the tunnel to borrow" in b for b in p.blockers)
    p = plan("vti", kinds, logical_name="t", tunnel_source="Ethernet0/7", ipv4="169.254.1.1/30")
    assert any(b.startswith("tunnel_source: No interface 'Ethernet0/7'") for b in p.blockers)


def test_transparent_mode_blocks_loopback_and_vti() -> None:
    p = plan_logical_interface(
        "loopback",
        {**DEV, "ftdMode": "TRANSPARENT"},
        as_items(recorded()),
        logical_name="lo",
        number=None,
        members=[],
        zone=None,
        ipv4=None,
        tunnel_source=None,
        tunnel_type="static",
        borrow_ip_from=None,
        lacp_mode="active",
        mtu=None,
        description=None,
        enabled=True,
    )
    assert any("transparent mode" in b for b in p.blockers)


def test_etherchannel_from_spare_physical_interfaces() -> None:
    kinds = recorded()
    kinds["physical"] += [unconfigured("Ethernet0/2", 0), unconfigured("Ethernet0/3", 1, enabled=False)]
    zone = {"id": ZONES[1]["id"], "type": "SecurityZone"}
    p = plan(
        "etherchannel",
        kinds,
        members=["Ethernet0/2", "Ethernet0/3"],
        logical_name="lan-pc",
        zone=zone,
        ipv4="10.98.0.1/24",
        lacp_mode="on",
    )
    assert p.hardware_name == "Port-channel1" and not p.blockers
    b = p.body
    assert b["type"] == "EtherChannelInterface" and b["etherChannelId"] == 1 and b["mode"] == "NONE"
    assert b["lacpMode"] == "ON" and [m["name"] for m in b["selectedInterfaces"]] == [
        "Ethernet0/2",
        "Ethernet0/3",
    ]
    assert b["selectedInterfaces"][0]["type"] == "PhysicalInterface"
    assert any("Ethernet0/3 is disabled" in s for s in p.side_effects)
    assert any("(static, mode on)" in s for s in p.side_effects)
    assert set(b) <= set(REC["created"]["etherchannelinterfaces"]) | {"description"}


def test_etherchannel_members_must_be_free_and_unconfigured() -> None:
    kinds = recorded()
    kinds["physical"] += [unconfigured("Ethernet0/2", 0)]
    kinds["bridge_group"] = [
        {
            "type": "BridgeGroupInterface",
            "name": "BVI1",
            "id": "bvi-1",
            "bridgeGroupId": 1,
            "selectedInterfaces": [{"id": "00000000-0000-0ed3-0000-021474837530", "name": "Ethernet0/2"}],
        }
    ]
    p = plan(
        "etherchannel",
        kinds,
        members=["outside", "Ethernet0/1", "Ethernet0/2", "Ethernet0/2", "Management0/0", "lo9"],
    )
    text = "\n".join(p.blockers)
    assert "Ethernet0/0 is configured" in text  # outside: name, zone, address
    assert "Ethernet0/1 has subinterfaces (Ethernet0/1.100)" in text
    assert "Ethernet0/2 is already a member of BVI1" in text
    assert "Member Ethernet0/2 is listed twice" in text
    assert "Management0/0 is a management interface" in text
    assert "member: No interface 'lo9'" in text


def test_bvi_members_take_no_address_and_need_names() -> None:
    kinds = recorded()
    kinds["physical"] += [unconfigured("Ethernet0/2", 0)]
    p = plan(
        "bvi",
        kinds,
        members=["Ethernet0/2", "mcp-dmz", "inside"],
        logical_name="bvi-lan",
        ipv4="10.97.0.1/24",
    )
    assert p.hardware_name == "BVI1"
    assert [m["type"] for m in p.body["selectedInterfaces"]] == [
        "PhysicalInterface",
        "SubInterface",
        "PhysicalInterface",
    ]
    assert p.body["ipAddress"] == "10.97.0.1" and p.body["bridgeGroupId"] == 1 and "mode" not in p.body
    assert any("Ethernet0/1.100 has its own IPv4 address" in b for b in p.blockers)
    assert any("Ethernet0/1 has its own IPv4 address" in b for b in p.blockers)
    assert any("Member Ethernet0/2 has no logical name" in s for s in p.side_effects)
    assert set(p.body) <= set(REC["created"]["bridgegroupinterfaces"]) | {"description"}


def test_zone_or_address_need_a_name() -> None:
    kinds = recorded()
    kinds["physical"] += [unconfigured("Ethernet0/2", 0)]
    p = plan("etherchannel", kinds, members=["Ethernet0/2"], ipv4="10.98.0.1/24")
    assert any("needs a logical_name before" in b for b in p.blockers)


def test_interface_rows_show_logical_details() -> None:
    row = interface_row("vti", VTI)
    assert row["tunnel_type"] == "static" and row["tunnel_source"] == "Ethernet0/0"
    assert row["borrows_from"] == "Loopback1" and row["vpn_topology"] == "mcp-fw-t1"
    ec = interface_row("etherchannel", REC["created"]["etherchannelinterfaces"])
    assert ec["members"] == ["Ethernet1/1"] and ec["lacp"] == "active"
    phys = interface_row("physical", REC["physicalinterfaces"]["items"][0])
    assert "members" not in phys and "tunnel_type" not in phys


# --- the tools against the recorded device --------------------------------------------------------


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def confirm(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    async with Client(server()) as c:
        preview = await run(c, name, args)
        assert preview["status"] == "preview", preview
        return preview, await run(c, name, {**args, "confirm": preview["confirm"]})


async def preview_of(name: str, args: dict[str, Any]) -> Any:
    async with Client(server()) as c:
        return await run(c, name, args)


def mock_device(fmc: respx.MockRouter, kinds: dict[str, list[dict[str, Any]]]) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get(DEVPATH).mock(return_value=httpx.Response(200, json=DEV))
    for kind, coll in INTERFACE_KINDS.items():
        if kind == "vlan":
            fmc.get(f"{DEVPATH}/{coll}").mock(
                return_value=httpx.Response(405, json={"error": {"messages": [REC["vlaninterfaces"]]}})
            )
            continue
        rows = kinds.get(kind, [])
        fmc.get(f"{DEVPATH}/{coll}").mock(return_value=items(rows))
        for i in rows:
            fmc.get(f"{DEVPATH}/{coll}/{i['id']}").mock(return_value=httpx.Response(200, json=i))
    fmc.get(f"{DEVPATH}/routing/ipv4staticroutes").mock(return_value=items([]))
    fmc.get(f"{DEVPATH}/routing/ipv6staticroutes").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/securityzones").mock(return_value=items(ZONES))


async def test_create_loopback_posts_the_planned_body(fmc: respx.MockRouter) -> None:
    mock_device(fmc, recorded())
    post = fmc.post(f"{DEVPATH}/loopbackinterfaces").mock(
        return_value=httpx.Response(201, json=REC["created"]["loopbackinterfaces"])
    )
    preview, done = await confirm(
        "fmc_create_interface",
        {"device": "mcp-ftd1", "kind": "loopback", "logical_name": "bgp-lo", "ipv4": "198.51.100.1/32"},
    )
    assert preview["action"].startswith("Create loopback Loopback1 (bgp-lo) on mcp-ftd1")
    assert preview["preview"]["interface"]["name"] == "Loopback1"
    assert preview["preview"]["interface"]["ipv4"] == "198.51.100.1/32"
    body = json.loads(post.calls.last.request.content)
    assert body == preview["preview"]["body"] and body["loopbackId"] == 1
    assert done["status"] == "applied"


async def test_create_vti_resolves_zone_and_source(fmc: respx.MockRouter) -> None:
    mock_device(fmc, recorded())
    post = fmc.post(f"{DEVPATH}/virtualtunnelinterfaces").mock(
        return_value=httpx.Response(201, json=REC["created"]["virtualtunnelinterfaces"])
    )
    preview, _ = await confirm(
        "fmc_create_interface",
        {
            "device": "mcp-ftd1",
            "kind": "vti",
            "logical_name": "s2s-1",
            "tunnel_source": "outside",
            "ipv4": "169.254.100.1/30",
            "security_zone": "mcp-fw-overlay",
        },
    )
    assert preview["preview"]["interface"]["zone"] == "mcp-fw-overlay"
    assert preview["preview"]["interface"]["tunnel_source"] == "Ethernet0/0"
    body = json.loads(post.calls.last.request.content)
    assert body["securityZone"]["id"] == ZONES[2]["id"] and body["tunnelSource"]["name"] == "Ethernet0/0"


async def test_create_etherchannel_blocked_on_a_configured_member(fmc: respx.MockRouter) -> None:
    mock_device(fmc, recorded())
    out = await preview_of(
        "fmc_create_interface", {"device": "mcp-ftd1", "kind": "etherchannel", "members": ["inside"]}
    )
    assert out["status"] == "blocked"
    assert any("Ethernet0/1 is configured" in b for b in out["blockers"])
    with pytest.raises(ToolError, match="needs members"):
        await preview_of("fmc_create_interface", {"device": "mcp-ftd1", "kind": "bvi"})


async def test_update_handles_the_logical_kinds(fmc: respx.MockRouter) -> None:
    kinds = {**recorded(), "loopback": [LOOPBACK], "vti": [VTI]}
    bvi = {**REC["created"]["bridgegroupinterfaces"], "id": "bvi-1"}
    kinds["bridge_group"] = [bvi]
    mock_device(fmc, kinds)
    put = fmc.put(f"{DEVPATH}/virtualtunnelinterfaces/vti-1").mock(return_value=httpx.Response(200, json=VTI))
    preview, _ = await confirm(
        "fmc_update_interface", {"device": "mcp-ftd1", "interface": "sdwan-vti1", "ipv4": "169.254.7.1/30"}
    )
    assert preview["preview"]["changes"]["borrows_from"] == {"from": "Loopback1", "to": None}
    body = json.loads(put.calls.last.request.content)
    assert "borrowIPfrom" not in body and body["ipAddressAssignmentType"] == "MANUAL_IP"
    assert body["ipv4"] == {"static": {"address": "169.254.7.1", "netmask": "30"}}
    assert "managementOnly" not in body and "metadata" not in body  # GET-only for a VTI

    put = fmc.put(f"{DEVPATH}/bridgegroupinterfaces/bvi-1").mock(return_value=httpx.Response(200, json=bvi))
    await confirm("fmc_update_interface", {"device": "mcp-ftd1", "interface": "BVI1", "ipv4": "10.97.0.1/24"})
    body = json.loads(put.calls.last.request.content)
    assert body["ipAddress"] == "10.97.0.1" and body["ipv4"]["static"]["address"] == "10.97.0.1"

    out = await preview_of(
        "fmc_update_interface",
        {"device": "mcp-ftd1", "interface": "vti-lo", "security_zone": "mcp-test-ftd-in"},
    )
    assert any("loopback interface takes no security zone" in b for b in out["blockers"])
    out = await preview_of(
        "fmc_update_interface", {"device": "mcp-ftd1", "interface": "Tunnel1", "ipv4": "dhcp"}
    )
    assert any("static address only" in b for b in out["blockers"])


async def test_delete_checks_what_still_uses_a_logical_interface(fmc: respx.MockRouter) -> None:
    ec = {**REC["created"]["etherchannelinterfaces"], "id": "pc-1"}
    kinds = {**recorded(), "loopback": [LOOPBACK], "vti": [VTI], "etherchannel": [ec]}
    kinds["subinterface"] = kinds["subinterface"] + [
        {"type": "SubInterface", "name": "Port-channel1", "subIntfId": 5, "vlanId": 5, "id": "pc-sub"}
    ]
    mock_device(fmc, kinds)
    out = await preview_of("fmc_delete_interface", {"device": "mcp-ftd1", "interface": "vti-lo"})
    assert any("VTI sdwan-vti1 borrows Loopback1's address" in b for b in out["blockers"])
    out = await preview_of("fmc_delete_interface", {"device": "mcp-ftd1", "interface": "sdwan-vti1"})
    assert any("belongs to VPN topology 'mcp-fw-t1'" in b for b in out["blockers"])
    out = await preview_of("fmc_delete_interface", {"device": "mcp-ftd1", "interface": "Port-channel1"})
    assert any("still has subinterfaces (Port-channel1.5)" in b for b in out["blockers"])
    assert any("members (Ethernet1/1) are released" in s for s in out["side_effects"])


async def test_delete_a_free_loopback(fmc: respx.MockRouter) -> None:
    mock_device(fmc, {**recorded(), "loopback": [LOOPBACK]})
    delete = fmc.delete(f"{DEVPATH}/loopbackinterfaces/lo-1").mock(
        return_value=httpx.Response(200, json=LOOPBACK)
    )
    _, done = await confirm("fmc_delete_interface", {"device": "mcp-ftd1", "interface": "Loopback1"})
    assert delete.called and done["status"] == "applied"


def test_every_kind_maps_to_a_collection() -> None:
    for lk in LOGICAL_KINDS.values():
        assert lk.collection in INTERFACE_KINDS
        assert INTERFACE_KINDS[lk.collection] in REC  # recorded on FTDv

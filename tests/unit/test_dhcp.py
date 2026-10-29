"""F94 fmc_configure_dhcp: DHCP server pools and relay on FTD interfaces, and the DHCP read side of
fmc_get_device / fmc_export_device_config.

FMC 10.0.1 answers both settings collections of a device with nothing configured with one item
{type, id} (recorded on an FTDv 10.0.0, 2026-10-28: dhcpserver -> DHCPServerSettings, dhcprelaysettings
-> DHCPRelaySettings, id = the device's). The configured bodies are synthetic, from the spec's
DeviceDHCPServerSettings / DeviceDHCPRelaySettings request examples, in the 10.0 shape (#362): interface
references carry the hardware name (Ethernet0/3), which FMC 10.0.1 returns on GET and requires on PUT
(it refuses the logical name with 400 "Invalid 'name' ... for Interface"). A subinterface is referenced by
its own id, type SubInterface and its PARENT's hardware name (#370, recorded on FMC 10.0.1: GET returns
{"id": <subinterface id>, "type": "SubInterface", "name": "Ethernet0/3"} for a pool on Ethernet0/3.3999,
and PUT refuses "Ethernet0/3.3999")."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp._core import InvalidRequest
from fmc_mcp.server import create_server
from fmc_mcp.tools.dhcp import dhcp_summary, fill_hosts, hw_name, iface_ref, pool_blockers, same_iface

from .conftest import CFG, empty, items, make_settings

DEV_ID = "00000000-0000-4000-8000-0000000000d1"
DEVICE = {"id": DEV_ID, "name": "mcp-branch-ftd", "model": "FTDv", "type": "Device"}
DEVPATH = f"{CFG}/devices/devicerecords/{DEV_ID}"
SERVER_PATH = f"{DEVPATH}/dhcp/dhcpserver"
RELAY_PATH = f"{DEVPATH}/dhcp/dhcprelaysettings"
EMPTY_SERVER = {"type": "DHCPServerSettings", "id": DEV_ID}
EMPTY_RELAY = {"type": "DHCPRelaySettings", "id": DEV_ID}


def phys(n: int, name: str, ifname: str | None, ipv4: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "type": "PhysicalInterface",
        "id": f"00000000-0000-0ed3-0000-00000000000{n}",
        "name": name,
        "enabled": True,
        "mode": "NONE",
    }
    if ifname:
        out["ifname"] = ifname
    if ipv4:
        out["ipv4"] = ipv4
    return out


INSIDE = phys(1, "Ethernet0/1", "inside", {"static": {"address": "192.0.2.1", "netmask": "24"}})
OUTSIDE = phys(2, "Ethernet0/0", "outside", {"dhcp": {"enableDefaultRouteDHCP": True}})
DC = phys(3, "Ethernet0/2", "dc", {"static": {"address": "198.51.100.1", "netmask": "255.255.255.0"}})
GUEST = phys(4, "Ethernet0/3", "guest", {"static": {"address": "203.0.113.1", "netmask": "25"}})
SPARE = phys(5, "Ethernet0/4", None, None)
# A VLAN subinterface of GUEST's port: FMC's record names the parent (Ethernet0/3) and carries subIntfId
# apart, as in the #370 capture (a physical pool and a subinterface pool on one parent).
IOT = {
    "type": "SubInterface",
    "id": "00000000-0000-0ed3-0000-000000000006",
    "name": "Ethernet0/3",
    "subIntfId": 3999,
    "vlanId": 3999,
    "ifname": "iot",
    "enabled": True,
    "mode": "NONE",
    "ipv4": {"static": {"address": "203.0.113.129", "netmask": "26"}},
}


def iref(i: dict[str, Any]) -> dict[str, Any]:
    """The reference FMC 10.0 takes and returns: the hardware name, never the logical one; a subinterface
    by its own id and the parent's hardware name (#370)."""
    return {"id": i["id"], "type": i["type"], "name": i["name"]}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args, raise_on_error=False)
    if r.is_error:
        return {"error": r.content[0].text}  # type: ignore[union-attr]
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def mock_device(
    fmc: respx.MockRouter,
    dhcp_server: dict[str, Any] | None = None,
    relay: dict[str, Any] | None = None,
    hosts: list[dict[str, Any]] | None = None,
) -> dict[str, respx.Route]:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEVICE]))
    fmc.get(DEVPATH).mock(return_value=httpx.Response(200, json=DEVICE))
    fmc.get(f"{DEVPATH}/physicalinterfaces").mock(return_value=items([INSIDE, OUTSIDE, DC, GUEST, SPARE]))
    fmc.get(f"{DEVPATH}/subinterfaces").mock(return_value=items([IOT]))
    for coll in ("etherchannelinterfaces", "bridgegroupinterfaces"):
        fmc.get(f"{DEVPATH}/{coll}").mock(return_value=empty())
    fmc.get(f"{DEVPATH}/inlinesets").mock(return_value=empty())  # F96: no inline sets
    fmc.get(f"{DEVPATH}/vlaninterfaces").mock(
        return_value=httpx.Response(405, json={"error": {"messages": [{"description": "not supported"}]}})
    )
    cur_s = dhcp_server or EMPTY_SERVER
    cur_r = relay or EMPTY_RELAY
    fmc.get(SERVER_PATH).mock(return_value=items([{"type": cur_s["type"], "id": DEV_ID}]))
    fmc.get(RELAY_PATH).mock(return_value=items([{"type": cur_r["type"], "id": DEV_ID}]))
    fmc.get(f"{SERVER_PATH}/{DEV_ID}").mock(return_value=httpx.Response(200, json=cur_s))
    fmc.get(f"{RELAY_PATH}/{DEV_ID}").mock(return_value=httpx.Response(200, json=cur_r))
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items(hosts or []))
    fmc.get(f"{CFG}/object/networks").mock(return_value=empty())
    return {
        "server_put": fmc.put(f"{SERVER_PATH}/{DEV_ID}").mock(return_value=httpx.Response(200, json=cur_s)),
        "relay_put": fmc.put(f"{RELAY_PATH}/{DEV_ID}").mock(return_value=httpx.Response(200, json=cur_r)),
        "server_post": fmc.post(SERVER_PATH).mock(return_value=httpx.Response(500)),
        "relay_post": fmc.post(RELAY_PATH).mock(return_value=httpx.Response(500)),
        "host_post": fmc.post(f"{CFG}/object/hosts").mock(
            side_effect=lambda req: httpx.Response(
                201, json={**json.loads(req.content), "id": "00000000-0000-0ed3-0000-0000000000aa"}
            )
        ),
    }


# --- server mode -------------------------------------------------------------------------------


async def test_server_pool_put_on_the_singleton(fmc: respx.MockRouter) -> None:
    routes = mock_device(fmc)
    args = {
        "device": "mcp-branch-ftd",
        "interface": "inside",
        "pool": "192.0.2.100-192.0.2.150",
        "dns_servers": ["198.51.100.53"],
        "search_domain": "branch.example.com",
        "lease_seconds": 7200,
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_dhcp", args)
        assert p["status"] == "preview", p
        assert p["preview"]["creates_host_objects"] == [
            {"name": "dhcp-dns-198.51.100.53", "type": "Host", "value": "198.51.100.53"}
        ]
        after = p["preview"]["after"]["server"]
        assert after["pools"] == [{"interface": "inside", "pool": "192.0.2.100-192.0.2.150", "enabled": True}]
        done = await run(c, "fmc_configure_dhcp", {**args, "confirm": p["confirm"]})
    assert done["result"]["applied"] == ["host dhcp-dns-198.51.100.53", "dhcp server"], done
    assert not routes["server_post"].called and not routes["relay_post"].called
    assert not routes["relay_put"].called
    body = json.loads(routes["server_put"].calls.last.request.content)
    assert body["id"] == DEV_ID and body["type"] == "DHCPServerSettings"
    assert body["dhcpServers"] == [
        {"interface": iref(INSIDE), "addressPool": "192.0.2.100-192.0.2.150", "enableDHCP": True}
    ]
    assert body["primaryDNSServer"] == {
        "id": "00000000-0000-0ed3-0000-0000000000aa",
        "type": "Host",
        "name": "dhcp-dns-198.51.100.53",
    }
    assert body["searchDomain"] == "branch.example.com" and body["leaseLengthInSec"] == "7200"


async def test_server_existing_host_object_and_auto_config(fmc: respx.MockRouter) -> None:
    dns = {"id": "h-dns", "name": "corp-dns", "type": "Host", "value": "198.51.100.53"}
    routes = mock_device(fmc, hosts=[dns])
    args = {
        "device": "mcp-branch-ftd",
        "interface": "inside",
        "pool": "192.0.2.10-192.0.2.20",
        "dns_servers": ["198.51.100.53"],
        "auto_config_interface": "outside",
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_dhcp", args)
        assert p["status"] == "preview" and p["preview"]["creates_host_objects"] is None, p
        await run(c, "fmc_configure_dhcp", {**args, "confirm": p["confirm"]})
    assert not routes["host_post"].called
    body = json.loads(routes["server_put"].calls.last.request.content)
    assert body["primaryDNSServer"] == {"id": "h-dns", "type": "Host", "name": "corp-dns"}
    assert body["autoConfigInterface"] == iref(OUTSIDE)


@pytest.mark.parametrize(
    ("pool", "why"),
    [
        ("192.0.3.10-192.0.3.20", "is not inside inside (Ethernet0/1)'s subnet 192.0.2.0/24"),
        ("192.0.2.1-192.0.2.20", "includes inside (Ethernet0/1)'s own address 192.0.2.1"),
        ("192.0.2.200-192.0.2.255", "includes the network or broadcast address"),
    ],
)
async def test_server_pool_blocked(fmc: respx.MockRouter, pool: str, why: str) -> None:
    routes = mock_device(fmc)
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_dhcp", {"device": DEV_ID, "interface": "inside", "pool": pool})
    assert p["status"] == "blocked" and "confirm" not in p
    assert any(why in b for b in p["blockers"]), p["blockers"]
    assert not routes["server_put"].called


async def test_server_blocked_on_relay_interface(fmc: respx.MockRouter) -> None:
    relay = {
        **EMPTY_RELAY,
        "dhcpRelayAgent": [{"interface": iref(INSIDE), "enableDHCPIPv4Relay": True, "setRoute": False}],
        "dhcpRelayServers": [
            {"interface": iref(DC), "server": {"id": "h1", "type": "Host", "name": "dc-dhcp"}}
        ],
    }
    mock_device(fmc, relay=relay)
    async with Client(server()) as c:
        p = await run(
            c,
            "fmc_configure_dhcp",
            {"device": DEV_ID, "interface": "inside", "pool": "192.0.2.10-192.0.2.20"},
        )
    assert p["status"] == "blocked"
    assert any("can't be DHCP server and relay" in b and "mode='off'" in b for b in p["blockers"])


async def test_server_replaces_its_own_pool(fmc: respx.MockRouter) -> None:
    cur = {
        **EMPTY_SERVER,
        "dhcpServers": [
            {"interface": iref(GUEST), "addressPool": "203.0.113.10-203.0.113.50", "enableDHCP": True}
        ],
    }
    mock_device(fmc, dhcp_server=cur)
    guest_args = {"device": DEV_ID, "interface": "guest", "pool": "203.0.113.20-203.0.113.30"}
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_dhcp", guest_args)
    assert p["status"] == "preview", p
    assert p["preview"]["after"]["server"]["pools"] == [
        {"interface": "guest", "pool": "203.0.113.20-203.0.113.30", "enabled": True}
    ]


async def test_server_needs_static_address_and_name(fmc: respx.MockRouter) -> None:
    mock_device(fmc)
    async with Client(server()) as c:
        dyn = await run(
            c,
            "fmc_configure_dhcp",
            {"device": DEV_ID, "interface": "outside", "pool": "192.0.2.10-192.0.2.20"},
        )
        unnamed = await run(
            c,
            "fmc_configure_dhcp",
            {"device": DEV_ID, "interface": "Ethernet0/4", "pool": "192.0.2.10-192.0.2.20"},
        )
        wrong = await run(
            c,
            "fmc_configure_dhcp",
            {"device": DEV_ID, "interface": "inside", "mode": "relay", "pool": "192.0.2.10-192.0.2.20"},
        )
    assert dyn["status"] == "blocked" and "no static IPv4 address" in dyn["blockers"][0]
    assert "no logical name" in unnamed["error"]
    assert "server-mode settings" in wrong["error"]


# --- relay mode --------------------------------------------------------------------------------


async def test_relay_picks_the_server_interface(fmc: respx.MockRouter) -> None:
    routes = mock_device(fmc)
    args = {"device": DEV_ID, "interface": "inside", "mode": "relay", "relay_servers": ["198.51.100.10"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_dhcp", args)
        assert p["status"] == "preview", p
        assert p["preview"]["after"]["relay"]["servers"] == [
            {"server": "dhcp-relay-198.51.100.10", "interface": "dc"}
        ]
        done = await run(c, "fmc_configure_dhcp", {**args, "confirm": p["confirm"]})
    assert done["result"]["applied"] == ["host dhcp-relay-198.51.100.10", "dhcp relay"]
    assert not routes["server_put"].called and not routes["relay_post"].called
    body = json.loads(routes["relay_put"].calls.last.request.content)
    assert body["id"] == DEV_ID and body["type"] == "DHCPRelaySettings"
    assert body["dhcpRelayAgent"] == [
        {
            "interface": iref(INSIDE),
            "enableDHCPIPv4Relay": True,
            "enableDHCPIPv6Relay": False,
            "setRoute": False,
        }
    ]
    assert body["dhcpRelayServers"] == [
        {
            "interface": iref(DC),
            "server": {
                "id": "00000000-0000-0ed3-0000-0000000000aa",
                "type": "Host",
                "name": "dhcp-relay-198.51.100.10",
            },
        }
    ]


async def test_relay_blocked_on_server_interface(fmc: respx.MockRouter) -> None:
    cur = {
        **EMPTY_SERVER,
        "dhcpServers": [
            {"interface": iref(INSIDE), "addressPool": "192.0.2.10-192.0.2.20", "enableDHCP": True}
        ],
    }
    routes = mock_device(fmc, dhcp_server=cur)
    async with Client(server()) as c:
        p = await run(
            c,
            "fmc_configure_dhcp",
            {"device": DEV_ID, "interface": "inside", "mode": "relay", "relay_servers": ["198.51.100.10"]},
        )
    assert p["status"] == "blocked"
    assert any("has a DHCP server pool (192.0.2.10-192.0.2.20)" in b for b in p["blockers"])
    assert not routes["relay_put"].called and not routes["host_post"].called


async def test_relay_server_unreachable_needs_server_interface(fmc: respx.MockRouter) -> None:
    mock_device(fmc)
    base = {"device": DEV_ID, "interface": "inside", "mode": "relay", "relay_servers": ["192.0.2.200"]}
    async with Client(server()) as c:
        on_inside = await run(c, "fmc_configure_dhcp", base)
        far = await run(c, "fmc_configure_dhcp", {**base, "relay_servers": ["233.252.0.10"]})
        given = await run(
            c, "fmc_configure_dhcp", {**base, "relay_servers": ["233.252.0.10"], "server_interface": "dc"}
        )
    assert on_inside["status"] == "blocked" and "is on inside" in on_inside["blockers"][0]
    assert far["status"] == "blocked" and "give server_interface" in far["blockers"][0]
    assert given["status"] == "preview", given


# --- off ---------------------------------------------------------------------------------------


async def test_off_removes_the_pool_then_relay_can_follow(fmc: respx.MockRouter) -> None:
    cur = {
        **EMPTY_SERVER,
        "leaseLengthInSec": "3600",
        "dhcpServers": [
            {"interface": iref(INSIDE), "addressPool": "192.0.2.10-192.0.2.20", "enableDHCP": True},
            {"interface": iref(GUEST), "addressPool": "203.0.113.10-203.0.113.20", "enableDHCP": True},
        ],
    }
    routes = mock_device(fmc, dhcp_server=cur)
    args = {"device": DEV_ID, "interface": "inside", "mode": "off"}
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_dhcp", args)
        assert p["status"] == "preview", p
        await run(c, "fmc_configure_dhcp", {**args, "confirm": p["confirm"]})
    body = json.loads(routes["server_put"].calls.last.request.content)
    assert [x["interface"]["name"] for x in body["dhcpServers"]] == ["Ethernet0/3"]
    assert body["leaseLengthInSec"] == "3600" and not routes["relay_put"].called


async def test_off_with_nothing_configured_is_blocked(fmc: respx.MockRouter) -> None:
    mock_device(fmc)
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_dhcp", {"device": DEV_ID, "interface": "inside", "mode": "off"})
    assert p["status"] == "blocked" and "nothing to remove" in p["blockers"][0]


# --- read side ---------------------------------------------------------------------------------


async def test_get_device_shows_dhcp(fmc: respx.MockRouter) -> None:
    cur = {
        **EMPTY_SERVER,
        "leaseLengthInSec": "7200",
        "primaryDNSServer": {"id": "h-dns", "type": "Host", "name": "corp-dns"},
        "dhcpServers": [
            {
                "interface": {"id": INSIDE["id"], "type": "PhysicalInterface"},
                "addressPool": "192.0.2.10-192.0.2.20",
                "enableDHCP": True,
            }
        ],
    }
    mock_device(fmc, dhcp_server=cur)
    async with Client(server()) as c:
        out = (await c.call_tool("fmc_get_device", {"device": DEV_ID})).structured_content
    assert out is not None
    assert out["dhcp"] == {
        "server": {
            "pools": [{"interface": "inside", "pool": "192.0.2.10-192.0.2.20", "enabled": True}],
            "dns_servers": ["corp-dns"],
            "lease_seconds": 7200,
        }
    }


async def test_get_device_without_dhcp(fmc: respx.MockRouter) -> None:
    mock_device(fmc)
    async with Client(server()) as c:
        out = (await c.call_tool("fmc_get_device", {"device": DEV_ID})).structured_content
    assert out is not None and "dhcp" not in out


def test_summary_and_helpers() -> None:
    assert dhcp_summary({"type": "DHCPServerSettings", "id": "x"}, {"type": "DHCPRelaySettings"}) is None
    relay = {
        "dhcpRelayAgent": [
            {"interface": {"id": "i1", "name": "inside"}, "enableDHCPIPv4Relay": True, "setRoute": True}
        ],
        "dhcpRelayServers": [
            {"interface": {"id": "i2", "name": "dc"}, "server": {"name": "dc-dhcp", "type": "Host"}}
        ],
        "ipv4TimeoutInSec": 60,
    }
    assert dhcp_summary(None, relay) == {
        "relay": {
            "agents": [{"interface": "inside", "ipv4": True, "set_route": True}],
            "servers": [{"server": "dc-dhcp", "interface": "dc"}],
            "ipv4_timeout_seconds": 60,
        }
    }
    import ipaddress

    net = ipaddress.IPv4Interface("10.10.0.1/16")
    assert any("allows 256" in b for b in pool_blockers("10.10.1.0-10.10.2.255", net, "inside"))
    assert pool_blockers("10.10.1.1-10.10.1.254", net, "inside") == []
    with pytest.raises(InvalidRequest):
        pool_blockers("10.10.1.20-10.10.1.10", net, "inside")
    with pytest.raises(InvalidRequest):
        pool_blockers("10.10.1.20", net, "inside")
    made = {"dhcp-dns-192.0.2.53": {"id": "n", "type": "Host", "name": "dhcp-dns-192.0.2.53"}}
    assert fill_hosts({"a": [{"type": "Host", "name": "dhcp-dns-192.0.2.53"}]}, made) == {
        "a": [made["dhcp-dns-192.0.2.53"]]
    }


async def test_export_has_a_dhcp_section(fmc: respx.MockRouter) -> None:
    from .test_device_export import SP1, export, recorded, t1

    data = recorded()
    pool = {"interface": {"id": "i1", "type": "PhysicalInterface", "name": "inside"}}
    data[f"devices/devicerecords/{SP1}/dhcp/dhcpserver"] = {
        "items": [
            {
                "id": SP1,
                "type": "DHCPServerSettings",
                "leaseLengthInSec": "7200",
                "dhcpServers": [{**pool, "addressPool": "192.0.2.10-192.0.2.20", "enableDHCP": True}],
            }
        ],
        "paging": {"count": 1},
    }
    data[f"devices/devicerecords/{SP1}/dhcp/dhcprelaysettings"] = {
        "items": [{"id": SP1, "type": "DHCPRelaySettings"}],
        "paging": {"count": 1},
    }
    t1(fmc, data)
    out, doc = await export()
    assert doc["dhcp"] == {
        "pool inside": {
            "addressPool": "192.0.2.10-192.0.2.20",
            "enableDHCP": True,
            "interface": {"name": "inside", "type": "PhysicalInterface"},
        },
        "server settings": {"leaseLengthInSec": "7200"},
    }
    assert "dhcp" in doc["meta"]["sections"]


# --- #362: hardware names in the bodies -------------------------------------------------------


async def test_server_body_names_the_hardware_interface(fmc: respx.MockRouter) -> None:
    """FMC 10.0 refuses interface.name 'iot' (the logical name) and 'Ethernet0/3.3999' (#370), and takes
    the parent's hardware name with the subinterface's id and type; the preview's label names the
    subinterface, not its parent, and its summary still speaks logical names."""
    routes = mock_device(fmc)
    args = {"device": DEV_ID, "interface": "iot", "pool": "203.0.113.140-203.0.113.150"}
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_dhcp", args)
        assert p["status"] == "preview", p
        assert "iot (Ethernet0/3.3999)" in p["action"], p["action"]
        assert p["preview"]["after"]["server"]["pools"] == [
            {"interface": "iot", "pool": "203.0.113.140-203.0.113.150", "enabled": True}
        ]
        done = await run(c, "fmc_configure_dhcp", {**args, "confirm": p["confirm"]})
    assert done["result"]["dhcp"]["server"]["pools"][0]["interface"] == "iot"
    body = json.loads(routes["server_put"].calls.last.request.content)
    assert body["dhcpServers"] == [
        {
            "interface": {"id": IOT["id"], "type": "SubInterface", "name": "Ethernet0/3"},
            "addressPool": "203.0.113.140-203.0.113.150",
            "enableDHCP": True,
        }
    ]


async def test_relay_body_names_the_hardware_interfaces(fmc: respx.MockRouter) -> None:
    """Both the relay agent (a subinterface) and the relay server's interface go by hardware name."""
    routes = mock_device(fmc)
    args = {"device": DEV_ID, "interface": "iot", "mode": "relay", "relay_servers": ["198.51.100.10"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_dhcp", args)
        assert p["status"] == "preview", p
        assert "iot (Ethernet0/3.3999)" in p["action"]
        assert p["preview"]["after"]["relay"] == {
            "agents": [{"interface": "iot", "ipv4": True, "ipv6": False, "set_route": False}],
            "servers": [{"server": "dhcp-relay-198.51.100.10", "interface": "dc"}],
        }
        await run(c, "fmc_configure_dhcp", {**args, "confirm": p["confirm"]})
    body = json.loads(routes["relay_put"].calls.last.request.content)
    assert body["dhcpRelayAgent"][0]["interface"] == {
        "id": IOT["id"],
        "type": "SubInterface",
        "name": "Ethernet0/3",
    }
    assert [x["interface"]["name"] for x in body["dhcpRelayServers"]] == ["Ethernet0/2"]
    assert body["dhcpRelayServers"][0]["interface"] == iref(DC)


@pytest.mark.parametrize("name", ["iot", "Ethernet0/3.3999"])
async def test_existing_pool_matched_by_either_name(fmc: respx.MockRouter, name: str) -> None:
    """A pool referenced without an id, by the logical name or the full hardware name (older bodies), is
    the interface's own pool: replaced in place, and rewritten in the 10.0 shape."""
    cur = {
        **EMPTY_SERVER,
        "dhcpServers": [
            {
                "interface": {"type": "SubInterface", "name": name},
                "addressPool": "203.0.113.140-203.0.113.150",
                "enableDHCP": True,
            }
        ],
    }
    routes = mock_device(fmc, dhcp_server=cur)
    args = {"device": DEV_ID, "interface": "iot", "pool": "203.0.113.160-203.0.113.170"}
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_dhcp", args)
        assert p["status"] == "preview", p
        await run(c, "fmc_configure_dhcp", {**args, "confirm": p["confirm"]})
    body = json.loads(routes["server_put"].calls.last.request.content)
    assert body["dhcpServers"] == [
        {"interface": iref(IOT), "addressPool": "203.0.113.160-203.0.113.170", "enableDHCP": True}
    ]


def test_hw_name_and_same_iface() -> None:
    assert hw_name(INSIDE) == "Ethernet0/1"
    assert hw_name(IOT) == "Ethernet0/3.3999"
    assert hw_name({**IOT, "name": "Ethernet0/3.3999"}) == "Ethernet0/3.3999"  # already full: unchanged
    assert iface_ref(IOT) == {"id": IOT["id"], "type": "SubInterface", "name": "Ethernet0/3"}
    assert iface_ref({**IOT, "name": "Ethernet0/3.3999"})["name"] == "Ethernet0/3"  # suffix stripped
    assert iface_ref(GUEST) == {"id": GUEST["id"], "type": "PhysicalInterface", "name": "Ethernet0/3"}
    assert same_iface({"name": "ethernet0/3.3999"}, IOT) and same_iface({"name": "IOT"}, IOT)
    assert not same_iface({"name": "Ethernet0/3"}, IOT)  # the parent's name is not the subinterface
    assert not same_iface({"name": ""}, IOT) and not same_iface(None, IOT)
    assert same_iface({"id": IOT["id"].upper(), "name": "other"}, IOT)
    assert not same_iface({"id": INSIDE["id"], "name": "iot"}, IOT)
    # The 10.0 GET shape: one parent name for both, told apart by id (and type when there is no id).
    sub_ref = {"id": IOT["id"], "type": "SubInterface", "name": "Ethernet0/3"}
    assert same_iface(sub_ref, IOT) and not same_iface(sub_ref, GUEST)
    assert not same_iface({"type": "SubInterface", "name": "Ethernet0/3"}, GUEST)
    assert same_iface(iface_ref(GUEST), GUEST) and not same_iface(iface_ref(GUEST), IOT)


# --- #370: subinterfaces by parent name, server or relay per device ----------------------------

# FMC 10.0.1's GET of a server with a physical pool and a subinterface pool on one parent (#370).
TWO_POOLS = {
    **EMPTY_SERVER,
    "dhcpServers": [
        {
            "interface": {"id": GUEST["id"], "type": "PhysicalInterface", "name": "Ethernet0/3"},
            "addressPool": "203.0.113.10-203.0.113.20",
            "enableDHCP": True,
        },
        {
            "interface": {"id": IOT["id"], "type": "SubInterface", "name": "Ethernet0/3"},
            "addressPool": "203.0.113.140-203.0.113.150",
            "enableDHCP": True,
        },
    ],
}


async def test_subinterface_pool_on_the_parent_name_is_told_apart(fmc: respx.MockRouter) -> None:
    """Two pools named Ethernet0/3 (a physical port and its subinterface): changing the subinterface's
    pool replaces that one only, the summary speaks logical names, and off removes only it."""
    routes = mock_device(fmc, dhcp_server=TWO_POOLS)
    args = {"device": DEV_ID, "interface": "iot", "pool": "203.0.113.160-203.0.113.170"}
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_dhcp", args)
        assert p["status"] == "preview", p
        assert p["preview"]["after"]["server"]["pools"] == [
            {"interface": "guest", "pool": "203.0.113.10-203.0.113.20", "enabled": True},
            {"interface": "iot", "pool": "203.0.113.160-203.0.113.170", "enabled": True},
        ]
        await run(c, "fmc_configure_dhcp", {**args, "confirm": p["confirm"]})
        body = json.loads(routes["server_put"].calls.last.request.content)
        assert body["dhcpServers"] == [
            TWO_POOLS["dhcpServers"][0],
            {"interface": iref(IOT), "addressPool": "203.0.113.160-203.0.113.170", "enableDHCP": True},
        ]
        off = {"device": DEV_ID, "interface": "iot", "mode": "off"}
        p = await run(c, "fmc_configure_dhcp", off)
        assert p["status"] == "preview", p
        await run(c, "fmc_configure_dhcp", {**off, "confirm": p["confirm"]})
    body = json.loads(routes["server_put"].calls.last.request.content)
    assert body["dhcpServers"] == [TWO_POOLS["dhcpServers"][0]]


async def test_overlap_blocker_names_the_subinterface(fmc: respx.MockRouter) -> None:
    """FMC's reference names the subinterface's pool after the parent: the blocker uses the logical name."""
    mock_device(fmc, dhcp_server={**EMPTY_SERVER, "dhcpServers": [TWO_POOLS["dhcpServers"][1]]})
    async with Client(server()) as c:
        p = await run(
            c,
            "fmc_configure_dhcp",
            {"device": DEV_ID, "interface": "guest", "pool": "203.0.113.100-203.0.113.145"},
        )
    assert p["status"] == "blocked"
    assert any("overlaps the pool 203.0.113.140-203.0.113.150 on iot." in b for b in p["blockers"]), p


async def test_relay_blocked_while_the_device_has_server_pools(fmc: respx.MockRouter) -> None:
    """FMC: 'Conflict Between DHCP Server and DHCP Relay ... configure either DHCP Server or DHCP Relay but
    not both' - per device, so a pool on another interface blocks relay here."""
    routes = mock_device(fmc, dhcp_server=TWO_POOLS)
    async with Client(server()) as c:
        p = await run(
            c,
            "fmc_configure_dhcp",
            {"device": DEV_ID, "interface": "inside", "mode": "relay", "relay_servers": ["198.51.100.10"]},
        )
    assert p["status"] == "blocked" and "confirm" not in p
    msg = next(b for b in p["blockers"] if "DHCP server or relay on a device" in b)
    assert "pools on guest, iot" in msg and "Turn the pools off first" in msg and "mode='off'" in msg
    assert not routes["relay_put"].called and not routes["host_post"].called


async def test_relay_allowed_when_pools_are_disabled(fmc: respx.MockRouter) -> None:
    cur = {
        **EMPTY_SERVER,
        "dhcpServers": [{**TWO_POOLS["dhcpServers"][0], "enableDHCP": False}],
    }
    mock_device(fmc, dhcp_server=cur)
    async with Client(server()) as c:
        p = await run(
            c,
            "fmc_configure_dhcp",
            {"device": DEV_ID, "interface": "inside", "mode": "relay", "relay_servers": ["198.51.100.10"]},
        )
    assert p["status"] == "preview", p


async def test_server_blocked_while_the_device_relays(fmc: respx.MockRouter) -> None:
    relay = {
        **EMPTY_RELAY,
        "dhcpRelayAgent": [
            {
                "interface": {"id": IOT["id"], "type": "SubInterface", "name": "Ethernet0/3"},
                "enableDHCPIPv4Relay": True,
                "enableDHCPIPv6Relay": False,
                "setRoute": False,
            }
        ],
        "dhcpRelayServers": [
            {"interface": iref(DC), "server": {"id": "h1", "type": "Host", "name": "dc-dhcp"}}
        ],
    }
    routes = mock_device(fmc, relay=relay)
    async with Client(server()) as c:
        p = await run(
            c,
            "fmc_configure_dhcp",
            {"device": DEV_ID, "interface": "inside", "pool": "192.0.2.10-192.0.2.20"},
        )
        same = await run(
            c,
            "fmc_configure_dhcp",
            {"device": DEV_ID, "interface": "iot", "pool": "203.0.113.140-203.0.113.150"},
        )
    assert p["status"] == "blocked"
    msg = next(b for b in p["blockers"] if "DHCP server or relay on a device" in b)
    assert "relay on iot" in msg and "Turn the relay off first" in msg
    assert same["status"] == "blocked"  # the interface's own agent: the per-interface blocker, once
    assert sum("relay" in b for b in same["blockers"]) == 1, same["blockers"]
    assert not routes["server_put"].called


async def test_export_keys_a_subinterface_pool_by_its_full_name(fmc: respx.MockRouter) -> None:
    from .test_device_export import SP1, export, recorded, t1

    data = recorded()
    sub_id = "00000000-0000-0ed3-0000-0000000000f6"
    data[f"devices/devicerecords/{SP1}/subinterfaces"] = {
        "items": [
            {"id": sub_id, "type": "SubInterface", "name": "Ethernet0/3", "subIntfId": 3999, "ifname": "iot"}
        ],
        "paging": {"count": 1},
    }
    pools = [
        {
            "interface": {"id": "i3", "type": "PhysicalInterface", "name": "Ethernet0/3"},
            "addressPool": "203.0.113.10-203.0.113.20",
            "enableDHCP": True,
        },
        {
            "interface": {"id": sub_id, "type": "SubInterface", "name": "Ethernet0/3"},
            "addressPool": "203.0.113.140-203.0.113.150",
            "enableDHCP": True,
        },
    ]
    data[f"devices/devicerecords/{SP1}/dhcp/dhcpserver"] = {
        "items": [{"id": SP1, "type": "DHCPServerSettings", "dhcpServers": pools}],
        "paging": {"count": 1},
    }
    data[f"devices/devicerecords/{SP1}/dhcp/dhcprelaysettings"] = {
        "items": [{"id": SP1, "type": "DHCPRelaySettings"}],
        "paging": {"count": 1},
    }
    t1(fmc, data)
    _, doc = await export()
    assert set(doc["dhcp"]) == {"pool Ethernet0/3", "pool Ethernet0/3.3999"}, doc["dhcp"]
    assert doc["dhcp"]["pool Ethernet0/3.3999"]["addressPool"] == "203.0.113.140-203.0.113.150"

"""Application-aware routing (F51b): WAN interfaces, ECMP zones and application routes, replayed from
tests/fixtures/sdwan_app_routing.json (see its `_source` for what is recorded and what is spec-shaped)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, empty, fixture, items, make_settings

DEV = {"id": "6a0f3c1e-0000-4000-8000-000000000b01", "name": "mcp-sdwan-t1-spoke1", "type": "Device"}
D = f"{CFG}/devices/devicerecords/{DEV['id']}"
R = f"{D}/routing"
FX = fixture("sdwan_app_routing")
WAN1, WAN2, INSIDE, MGMT = FX["physicalinterfaces"]["items"]
PBR = FX["policybasedroutes"]["items"][0]
ZONE = FX["ecmpzones"]["items"][0]
ACL = FX["extendedaccesslists"][0]
APPS = FX["applications_page"]["items"]
ACLS = f"{CFG}/object/extendedaccesslists"


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def body(route: respx.Route) -> Any:
    return json.loads(route.calls.last.request.content)


@pytest.fixture
def sd(fmc: respx.MockRouter) -> respx.MockRouter:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get(f"{D}/physicalinterfaces").mock(return_value=httpx.Response(200, json=FX["physicalinterfaces"]))
    for i in (WAN1, WAN2, INSIDE, MGMT):
        fmc.get(f"{D}/physicalinterfaces/{i['id']}").mock(return_value=httpx.Response(200, json=i))
    fmc.get(f"{D}/virtualtunnelinterfaces").mock(
        return_value=httpx.Response(200, json=FX["virtualtunnelinterfaces"])
    )
    for sub in ("subinterfaces", "etherchannelinterfaces"):
        fmc.get(f"{D}/{sub}").mock(return_value=empty())
    fmc.get(f"{D}/vlaninterfaces").mock(return_value=httpx.Response(405, json={"error": {}}))
    fmc.get(f"{R}/policybasedroutes").mock(return_value=items([PBR]))
    fmc.get(f"{R}/ecmpzones").mock(return_value=items([ZONE]))
    fmc.get(f"{CFG}/object/applications").mock(return_value=items(APPS))
    fmc.get(ACLS).mock(return_value=empty())
    for sub in (
        "bgpgeneralsettings",
        "bgp",
        "ospfv2routes",
        "ipv4staticroutes",
        "ipv6staticroutes",
        "ospfinterface",
        "bfdpolicies",
        "ospfv3routes",
        "virtualrouters",
    ):
        fmc.get(f"{R}/{sub}").mock(return_value=empty())
    return fmc


# --- fmc_get_routing ------------------------------------------------------------------------------


async def test_get_routing_shows_app_routes_and_wan_interfaces(sd: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_get_routing", {"device": DEV["name"]})
    assert out["policy_based_routes"] == [
        {
            "name": "mcp-sdwan-lan",
            "ingress": ["Ethernet0/2 (inside)"],
            "routes": [
                {
                    "match": "mcp-sdwan-voice",
                    "order_by": "jitter",
                    "egress": ["Ethernet0/0 (wan1)", "Ethernet0/1 (wan2)"],
                    "next_hops": None,
                }
            ],
            "id": PBR["id"],
        }
    ]
    wan = {w["logical_name"]: w for w in out["wan_interfaces"]}
    assert set(wan) == {"wan1", "wan2"}  # inside has priority 0 and no monitoring; management is skipped
    assert wan["wan1"]["path_monitoring"] == "auto" and wan["wan1"]["priority"] == 1
    assert wan["wan2"]["path_monitoring"] == "off" and wan["wan2"]["priority"] == 2
    assert out["ecmp_zones"] == [{"name": "mcp-sdwan-wan", "interfaces": ["Ethernet0/0", "Ethernet0/1"]}]


# --- fmc_configure_wan_interface ------------------------------------------------------------------


async def test_wan_interface_monitored_ip_keeps_the_rest(sd: respx.MockRouter) -> None:
    put = sd.put(f"{D}/physicalinterfaces/{WAN2['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "interface": "wan2", "priority": 5, "monitored_ip": "198.51.100.1"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_wan_interface", args)
        assert preview["preview"]["changes"] == {
            "priority": {"from": 2, "to": 5},
            "path_monitoring": {"from": "off", "to": "ip"},
            "monitored_ip": {"from": None, "to": "198.51.100.1"},
        }
        await run(c, "fmc_configure_wan_interface", {**args, "confirm": preview["confirm"]})
    sent = body(put)
    assert sent["pathMonitoring"] == {"enable": True, "type": "PEER_IPV4", "monitoredIp": "198.51.100.1"}
    assert sent["priority"] == 5
    assert sent["ifname"] == "wan2" and sent["ipv4"] == WAN2["ipv4"] and "metadata" not in sent


# A spoke's static VTI as the FMC 10.0.1 GET returns it (spec-shaped: FTDVTIInterface), including
# managementOnly, which FMC refuses back in a VTI PUT.
SPOKE_VTI = {
    "metadata": {"timestamp": 1792212000000, "domain": {"name": "mcp-test-leaf", "type": "Domain"}},
    "links": {"self": "https://fmc/api/.../virtualtunnelinterfaces/vti-sp1"},
    "id": "00000000-0000-0ed3-0000-021474851101",
    "type": "VTIInterface",
    "name": "Tunnel1",
    "ifname": "mpls_static_vti_1",
    "tunnelType": "STATIC",
    "tunnelId": 1,
    "enabled": True,
    "managementOnly": False,
    "MTU": 1500,
    "priority": 0,
    "pathMonitoring": {"enable": False},
    "tunnelSource": {"id": WAN1["id"], "name": "Ethernet0/0", "type": "PhysicalInterface"},
    "ipv4": {"static": {"address": "10.255.1.2", "netmask": "255.255.255.0"}},
    "ipsecMode": "ipv4",
}


def vti_put_mock(sd: respx.MockRouter) -> respx.Route:
    """Mock FMC 10.0.1: a VTI PUT that echoes managementOnly gets the live 400."""
    sd.get(f"{D}/virtualtunnelinterfaces").mock(return_value=items([SPOKE_VTI]))
    sd.get(f"{D}/virtualtunnelinterfaces/{SPOKE_VTI['id']}").mock(
        return_value=httpx.Response(200, json=SPOKE_VTI)
    )

    def put(request: httpx.Request) -> httpx.Response:
        if "managementOnly" in json.loads(request.content):
            return httpx.Response(
                400,
                json={
                    "error": {
                        "category": "FRAMEWORK",
                        "messages": [
                            {"description": "Fields: { managementOnly } must be excluded from json payload."}
                        ],
                        "severity": "ERROR",
                    }
                },
            )
        return httpx.Response(200, json={})

    return sd.put(f"{D}/virtualtunnelinterfaces/{SPOKE_VTI['id']}").mock(side_effect=put)


async def test_wan_interface_on_a_vti_drops_management_only(sd: respx.MockRouter) -> None:
    put = vti_put_mock(sd)
    args = {
        "device": DEV["name"],
        "interface": "mpls_static_vti_1",
        "priority": 1,
        "path_monitoring": "ip",
        "monitored_ip": "10.255.1.1",
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_wan_interface", args)
        assert preview["status"] == "preview", preview
        await run(c, "fmc_configure_wan_interface", {**args, "confirm": preview["confirm"]})
    sent = body(put)
    assert "managementOnly" not in sent and "metadata" not in sent and "links" not in sent
    assert sent["pathMonitoring"] == {"enable": True, "type": "PEER_IPV4", "monitoredIp": "10.255.1.1"}
    assert sent["priority"] == 1
    assert sent["tunnelSource"] == SPOKE_VTI["tunnelSource"] and sent["ipv4"] == SPOKE_VTI["ipv4"]


async def test_update_interface_on_a_vti_drops_management_only(sd: respx.MockRouter) -> None:
    put = vti_put_mock(sd)
    for extra in (f"{D}/loopbackinterfaces", f"{D}/bridgegroupinterfaces", f"{CFG}/object/securityzones"):
        sd.get(extra).mock(return_value=empty())
    args = {"device": DEV["name"], "interface": "mpls_static_vti_1", "mtu": 1400}
    async with Client(server()) as c:
        preview = await run(c, "fmc_update_interface", args)
        assert preview["status"] == "preview", preview
        await run(c, "fmc_update_interface", {**args, "confirm": preview["confirm"]})
    sent = body(put)
    assert "managementOnly" not in sent and sent["MTU"] == 1400


async def test_physical_interface_put_keeps_management_only(sd: respx.MockRouter) -> None:
    """Only VTIs refuse the field; a physical interface PUT still echoes it (FMC requires the full body)."""
    put = sd.put(f"{D}/physicalinterfaces/{WAN2['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "interface": "wan2", "priority": 5}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_wan_interface", args)
        await run(c, "fmc_configure_wan_interface", {**args, "confirm": preview["confirm"]})
    assert body(put).get("managementOnly") == WAN2.get("managementOnly")


async def test_wan_interface_http_monitoring_with_applications(sd: respx.MockRouter) -> None:
    put = sd.put(f"{D}/physicalinterfaces/{WAN1['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "interface": "Ethernet0/0", "monitored_applications": ["buffer"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_wan_interface", args)
        await run(c, "fmc_configure_wan_interface", {**args, "confirm": preview["confirm"]})
    assert body(put)["applicationMonitoring"] == {
        "enable": True,
        "monitoredApplications": [{"id": "2428", "type": "Application", "name": "Buffer"}],
    }
    assert body(put)["pathMonitoring"] == WAN1["pathMonitoring"]  # untouched


async def test_wan_interface_blockers_and_errors(sd: respx.MockRouter) -> None:
    async with Client(server()) as c:
        same = await run(
            c, "fmc_configure_wan_interface", {"device": DEV["name"], "interface": "wan1", "priority": 1}
        )
        mgmt = await run(
            c,
            "fmc_configure_wan_interface",
            {"device": DEV["name"], "interface": "Management0/0", "path_monitoring": "auto"},
        )
        no_ip = await c.call_tool(
            "fmc_configure_wan_interface",
            {"device": DEV["name"], "interface": "wan1", "path_monitoring": "ip"},
            raise_on_error=False,
        )
        bad_app = await c.call_tool(
            "fmc_configure_wan_interface",
            {"device": DEV["name"], "interface": "wan1", "monitored_applications": ["Bufer"]},
            raise_on_error=False,
        )
    assert same["status"] == "blocked" and "Nothing to change" in same["blockers"][0]
    assert mgmt["status"] == "blocked" and any("Management" in b for b in mgmt["blockers"])
    assert no_ip.is_error and "monitored_ip" in no_ip.content[0].text
    assert bad_app.is_error and "Close: Buffer" in bad_app.content[0].text


# --- fmc_configure_ecmp_zone ----------------------------------------------------------------------


async def test_ecmp_zone_create_update_delete(sd: respx.MockRouter) -> None:
    post = sd.post(f"{R}/ecmpzones").mock(return_value=httpx.Response(201, json={"id": "z2"}))
    put = sd.put(f"{R}/ecmpzones/{ZONE['id']}").mock(return_value=httpx.Response(200, json={}))
    delete = sd.delete(f"{R}/ecmpzones/{ZONE['id']}").mock(return_value=httpx.Response(200, json={}))
    async with Client(server()) as c:
        taken = await run(
            c,
            "fmc_configure_ecmp_zone",
            {"device": DEV["name"], "name": "z2", "interfaces": ["wan1", "inside"]},
        )
        assert taken["status"] == "blocked" and "already in ECMP zone mcp-sdwan-wan" in taken["blockers"][0]
        args: dict[str, Any] = {"device": DEV["name"], "name": "z2", "interfaces": ["inside"]}
        preview = await run(c, "fmc_configure_ecmp_zone", args)
        await run(c, "fmc_configure_ecmp_zone", {**args, "confirm": preview["confirm"]})
        args = {"device": DEV["name"], "name": "mcp-sdwan-wan", "interfaces": ["wan2"]}
        preview = await run(c, "fmc_configure_ecmp_zone", args)
        assert preview["preview"]["after"]["interfaces"] == ["Ethernet0/1 (wan2)"]
        await run(c, "fmc_configure_ecmp_zone", {**args, "confirm": preview["confirm"]})
        args = {"device": DEV["name"], "name": "mcp-sdwan-wan", "remove": True}
        preview = await run(c, "fmc_configure_ecmp_zone", args)
        await run(c, "fmc_configure_ecmp_zone", {**args, "confirm": preview["confirm"]})
    assert body(post) == {
        "type": "ecmpzones",
        "name": "z2",
        "interfaces": [
            {"id": INSIDE["id"], "type": "PhysicalInterface", "name": "Ethernet0/2", "ifname": "inside"}
        ],
    }
    assert [i["ifname"] for i in body(put)["interfaces"]] == ["wan2"] and body(put)["id"] == ZONE["id"]
    assert delete.called


# --- fmc_create_app_route -------------------------------------------------------------------------

ROUTE = {
    "device": DEV["name"],
    "name": "mcp-sdwan-web",
    "ingress_interfaces": ["inside"],
    "egress_interfaces": ["wan1", "wan2"],
    "applications": ["Bublup"],
    "destinations": ["203.0.113.0/24"],
    "ports": ["tcp/443"],
}


async def test_app_route_appends_to_the_ingress_pbr(sd: respx.MockRouter) -> None:
    new_acl = {"id": "acl-new", "type": "ExtendedAccessList", "name": "mcp-sdwan-web"}
    acl_post = sd.post(ACLS).mock(return_value=httpx.Response(201, json=new_acl))
    put = sd.put(f"{R}/policybasedroutes/{PBR['id']}").mock(return_value=httpx.Response(200, json={}))
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_app_route", ROUTE)
        assert preview["preview"]["steps"] == ["create extended access list", "update policy-based route"]
        assert [e["priority"] for e in preview["preview"]["egress"]] == [1, 2]
        done = await run(c, "fmc_create_app_route", {**ROUTE, "confirm": preview["confirm"]})
    assert done["result"]["extended_access_list"] == {"id": "acl-new", "name": "mcp-sdwan-web"}
    entry = body(acl_post)["entries"][0]
    assert entry["action"] == "PERMIT"
    assert entry["applications"] == {
        "applications": [{"id": "5878", "type": "Application", "name": "Bublup"}]
    }
    assert entry["destinationNetworks"] == {"literals": [{"type": "Network", "value": "203.0.113.0/24"}]}
    assert entry["destinationPorts"]["literals"][0]["port"] == "443"
    actions = body(put)["forwardingActions"]
    assert actions[0] == PBR["forwardingActions"][0]  # the existing route stays first
    assert actions[1] == {
        "forwardingActionType": "SET_EGRESS_INTF_BY_PRIORITY",
        "matchCriteria": {"id": "acl-new", "type": "ExtendedAccessList", "name": "mcp-sdwan-web"},
        "egressInterfaces": [
            {"id": WAN1["id"], "type": "PhysicalInterface", "name": "Ethernet0/0", "ifname": "wan1"},
            {"id": WAN2["id"], "type": "PhysicalInterface", "name": "Ethernet0/1", "ifname": "wan2"},
        ],
    }


async def test_app_route_new_pbr_and_rollback(sd: respx.MockRouter) -> None:
    sd.get(f"{R}/policybasedroutes").mock(return_value=empty())
    sd.post(ACLS).mock(return_value=httpx.Response(201, json={"id": "acl-new", "name": "mcp-sdwan-web"}))
    undo = sd.delete(f"{ACLS}/acl-new").mock(return_value=httpx.Response(200, json={}))
    post = sd.post(f"{R}/policybasedroutes").mock(
        return_value=httpx.Response(422, json={"error": {"messages": [{"description": "bad egress"}]}})
    )
    args = {**ROUTE, "order_by": "order"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_app_route", args)
        assert preview["preview"]["policy_based_route"] == "(new)"
        res = await c.call_tool(
            "fmc_create_app_route", {**args, "confirm": preview["confirm"]}, raise_on_error=False
        )
    sent = body(post)
    assert sent["name"] == "mcp-sdwan-web" and sent["type"] == "PolicyBasedRoutes"
    assert [i["ifname"] for i in sent["ingressInterfaces"]] == ["inside"]
    assert sent["forwardingActions"][0]["forwardingActionType"] == "SET_EGRESS_INTF_BY_ORDER"
    text = res.content[0].text
    assert res.is_error and "deleted the new extended access list again" in text
    assert undo.called


async def test_app_route_metric_order_needs_path_monitoring(sd: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_create_app_route", {**ROUTE, "order_by": "mos"})
    assert out["status"] == "blocked"
    assert out["blockers"] == [
        "order_by='mos' needs path monitoring on Ethernet0/1 (wan2) "
        "(fmc_configure_wan_interface path_monitoring='auto')."
    ]


async def test_app_route_ingress_clash_and_existing_acl(sd: respx.MockRouter) -> None:
    sd.get(ACLS).mock(return_value=items([ACL]))
    async with Client(server()) as c:
        clash = await run(
            c,
            "fmc_create_app_route",
            {
                **ROUTE,
                "name": "x",
                "ingress_interfaces": ["inside", "Management0/0"],
                "egress_interfaces": ["wan1"],
            },
        )
        dup = await run(
            c,
            "fmc_create_app_route",
            {
                "device": DEV["name"],
                "name": "mcp-sdwan-voice",
                "ingress_interfaces": ["inside"],
                "egress_interfaces": ["wan1", "wan2"],
            },
        )
        taken = await run(c, "fmc_create_app_route", {**ROUTE, "name": "mcp-sdwan-voice"})
    assert clash["status"] == "blocked"
    assert any("already is an ingress of policy-based route 'mcp-sdwan-lan'" in b for b in clash["blockers"])
    assert any("One egress interface" in w for w in clash["preview"]["warnings"])
    assert dup["status"] == "blocked" and "already routed" in dup["blockers"][0]
    assert dup["preview"]["match"] == {"extended_access_list": "mcp-sdwan-voice", "reused": True}
    assert taken["status"] == "blocked" and "already exists" in taken["blockers"][0]


async def test_app_route_needs_a_match(sd: respx.MockRouter) -> None:
    args = {k: v for k, v in ROUTE.items() if k not in ("applications", "destinations", "ports")}
    async with Client(server()) as c:
        r = await c.call_tool("fmc_create_app_route", args, raise_on_error=False)
    assert r.is_error and "what to match" in r.content[0].text


# --- fmc_delete_app_route -------------------------------------------------------------------------


async def test_delete_last_route_removes_pbr_and_acl(sd: respx.MockRouter) -> None:
    del_pbr = sd.delete(f"{R}/policybasedroutes/{PBR['id']}").mock(return_value=httpx.Response(200, json={}))
    del_acl = sd.delete(f"{ACLS}/{ACL['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "name": "mcp-sdwan-voice"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_delete_app_route", args)
        assert preview["preview"]["steps"] == [
            "delete policy-based route mcp-sdwan-lan",
            "delete extended access list mcp-sdwan-voice",
        ]
        done = await run(c, "fmc_delete_app_route", {**args, "confirm": preview["confirm"]})
    assert del_pbr.called and del_acl.called and len(done["result"]["applied"]) == 2


async def test_delete_one_of_two_routes_keeps_the_pbr(sd: respx.MockRouter) -> None:
    second = {
        **PBR["forwardingActions"][0],
        "matchCriteria": {"id": "acl-2", "name": "web", "type": "ExtendedAccessList"},
    }
    sd.get(f"{R}/policybasedroutes").mock(
        return_value=items([{**PBR, "forwardingActions": [*PBR["forwardingActions"], second]}])
    )
    put = sd.put(f"{R}/policybasedroutes/{PBR['id']}").mock(return_value=httpx.Response(200, json={}))
    del_acl = sd.delete(f"{ACLS}/acl-2").mock(return_value=httpx.Response(200, json={}))
    args = {"device": DEV["name"], "name": "web", "keep_access_list": True}
    async with Client(server()) as c:
        preview = await run(c, "fmc_delete_app_route", args)
        await run(c, "fmc_delete_app_route", {**args, "confirm": preview["confirm"]})
        missing = await c.call_tool(
            "fmc_delete_app_route", {"device": DEV["name"], "name": "nope"}, raise_on_error=False
        )
    assert body(put)["forwardingActions"] == PBR["forwardingActions"]
    assert not del_acl.called
    assert missing.is_error and "Routes: mcp-sdwan-voice, web" in missing.content[0].text

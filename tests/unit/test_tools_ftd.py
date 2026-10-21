"""Device configuration and troubleshooting tools, against responses recorded from a real FTDv 10.0
managed by FMC 10.0.1 (tests/fixtures/ftd_*.json, captured by scripts/capture_fixtures.py --ftd)."""

import asyncio
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server
from fmc_mcp.tools import dangerous
from fmc_mcp.tools.deploy import pending_row
from fmc_mcp.tools.device_config import ipv4_block
from fmc_mcp.tools.troubleshoot import filter_lines, redact, split_command, summarize_trace

from .conftest import CFG, DOMAIN, empty, fixture, items, make_settings

DEV = fixture("ftd_device")
DEV_ID = DEV["id"]
DEVPATH = f"{CFG}/devices/devicerecords/{DEV_ID}"
ACP = {"id": "00000000-0000-0ed3-0000-021474847655", "name": "mcp-test-ftd-acp", "type": "AccessPolicy"}
NATP = {"id": "00000000-0000-0ed3-0000-021474848751", "name": "mcp-test-ftd-nat", "type": "FTDNatPolicy"}
ZONES = [
    {"id": "4fcc07ce-c7e9-11f1-88b7-6dea5174bd84", "name": "mcp-test-ftd-in", "type": "SecurityZone"},
    {"id": "51015f2c-c7e9-11f1-88b7-6dea5174bd84", "name": "mcp-test-ftd-out", "type": "SecurityZone"},
    {"id": "903de6d6-c7eb-11f1-874c-6cea5174bd84", "name": "mcp-test-ftd-dmz", "type": "SecurityZone"},
]
PHYS = fixture("ftd_physicalinterfaces")["items"]
INSIDE = next(i for i in PHYS if i.get("ifname") == "inside")
OUTSIDE = next(i for i in PHYS if i.get("ifname") == "outside")
ANY4 = {
    "id": "cb7116e8-66a6-480b-8f9b-295191a0940a",
    "name": "any-ipv4",
    "type": "Network",
    "value": "0.0.0.0/0",
}


def server(**kw: Any) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, **kw))


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


@pytest.fixture
def ftd(fmc: respx.MockRouter) -> respx.MockRouter:
    """One registered FTD with the interfaces, route and zones from the lab."""
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get(DEVPATH).mock(return_value=httpx.Response(200, json=DEV))
    fmc.get(f"{DEVPATH}/physicalinterfaces").mock(
        return_value=httpx.Response(200, json=fixture("ftd_physicalinterfaces"))
    )
    for i in PHYS:  # the full objects (the PUT starts from these)
        fmc.get(f"{DEVPATH}/physicalinterfaces/{i['id']}").mock(
            return_value=httpx.Response(200, json={**i, "fragmentReassembly": False})
        )
    for kind in (
        "subinterfaces",
        "etherchannelinterfaces",
        "virtualtunnelinterfaces",
        "loopbackinterfaces",
        "bridgegroupinterfaces",  # FTDv answers 200 (empty) here (ftd_interface_kinds.json)
    ):
        fmc.get(f"{DEVPATH}/{kind}").mock(return_value=empty())
    fmc.get(f"{DEVPATH}/vlaninterfaces").mock(  # FTDv: not supported on this model
        return_value=httpx.Response(
            405, json={"error": {"messages": [{"description": "VLAN Interface type is not supported"}]}}
        )
    )
    fmc.get(f"{DEVPATH}/routing/ipv4staticroutes").mock(
        return_value=httpx.Response(200, json=fixture("ftd_ipv4staticroutes"))
    )
    fmc.get(f"{DEVPATH}/routing/ipv6staticroutes").mock(return_value=empty())
    fmc.get(f"{DEVPATH}/routing/virtualrouters").mock(
        return_value=items([{"id": "vr-global", "name": "Global"}])
    )
    for sub in ("bgp", "ospfv2routes", "eigrproutes", "policybasedroutes", "ospfv3routes", "ecmpzones"):
        fmc.get(f"{DEVPATH}/routing/{sub}").mock(return_value=empty())
    fmc.get(f"{CFG}/object/securityzones").mock(return_value=items(ZONES))
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    fmc.get(f"{CFG}/policy/ftdnatpolicies").mock(return_value=items([NATP]))
    return fmc


# --- pure helpers ---------------------------------------------------------------------------------


def test_ipv4_block() -> None:
    assert ipv4_block("10.1.1.1/24") == {"static": {"address": "10.1.1.1", "netmask": "24"}}
    assert ipv4_block("10.1.1.1/255.255.255.0") == {"static": {"address": "10.1.1.1", "netmask": "24"}}
    assert ipv4_block("dhcp") == {"dhcp": {"enableDefaultRouteDHCP": False, "dhcpRouteMetric": 1}}
    assert ipv4_block("none") is None
    for bad in ("10.1.1.1", "10.1.1.0/24", "nonsense", "10.1.1.255/24"):
        with pytest.raises(ToolError):
            ipv4_block(bad)


def test_split_command() -> None:
    assert split_command("show route") == ("show route", None)
    assert split_command("  show running-config   access-group ") == ("show running-config", "access-group")
    assert split_command("show interface ip brief") == ("show interface", "ip brief")
    for bad in ("configure terminal", "show run | include x", "show route; reload", "ping 1.1.1.1"):
        with pytest.raises(ToolError):
            split_command(bad)


def test_filter_lines() -> None:
    out, total, truncated = filter_lines("a\nB route\nc route\nd", "ROUTE", 1)
    assert out == "B route" and total == 2 and truncated


def test_summarize_trace_names_the_blocking_rule() -> None:
    (res,) = summarize_trace(fixture("ftd_packettracer_drop"), verbose=False)
    assert res["action"] == "drop" and "acl-drop" in res["drop_reason"]
    assert res["matched_rules"][0] == {
        "type": "ACCESS-LIST",
        "rule_id": "268434475",
        "rule": "mcp-test-block-telnet",
        "policy": "mcp-test-ftd-acp - Default",
        "result": "DROP",
    }
    assert res["dropped_at"].startswith("phase 3 ACCESS-LIST (rule 'mcp-test-block-telnet'")
    # Routine phases are hidden, the drop and the route lookup are kept.
    assert {p["type"] for p in res["phases"]} == {"ACCESS-LIST", "ROUTE-LOOKUP"}
    assert res["hidden_phases"] >= 1
    full = summarize_trace(fixture("ftd_packettracer_drop"), verbose=True)[0]
    assert "hidden_phases" not in full and all("info" in p or "config" in p for p in full["phases"])


def test_pending_row_flattens_values() -> None:
    row = pending_row(
        {
            "entityName": "Ethernet0/1",
            "entityType": "PixF1InterfaceTable",
            "action": "UPDATE",
            "lastUpdatedByUsers": [{"name": "admin"}],
            "valueUpdated": [
                {"fieldName": "Enabled", "oldValue": "false", "newValue": "true"},
                {"fieldName": "Name", "newValue": "inside"},
            ],
            "valueDeleted": [{"fieldName": "Description", "oldValue": "old"}],
        }
    )
    assert row == {
        "entity": "Ethernet0/1",
        "type": "PixF1InterfaceTable",
        "action": "UPDATE",
        "changed_by": "admin",
        "changes": ["Enabled: false -> true", "Name: inside", "-Description: old"],
    }


# --- device configuration ---------------------------------------------------------------------------


async def test_list_interfaces_names_zones_and_skips_unsupported(ftd: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_list_device_interfaces",
            {"device": "mcp-ftd1", "kinds": ["physical", "vlan"], "response_format": "json"},
        )
    rows = {r["logical_name"]: r for r in out["results"]}
    assert rows["inside"]["zone"] == "mcp-test-ftd-in" and rows["inside"]["ipv4"] == "10.99.1.1/24"
    assert "vlan: not supported" in out["note"]


async def test_list_routes(ftd: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_list_routes", {"device": "mcp-ftd1", "response_format": "json"})
    assert out["results"] == [
        {
            "kind": "static4",
            "networks": ["any-ipv4"],
            "interface": "outside",
            "gateway": "192.0.2.10",
            "metric": 1,
            "id": fixture("ftd_ipv4staticroutes")["items"][0]["id"],
        }
    ]
    assert "other_routing" not in out  # the Global virtual router alone is not reported


async def test_update_interface_diff_and_body(ftd: respx.MockRouter) -> None:
    put = ftd.put(f"{DEVPATH}/physicalinterfaces/{INSIDE['id']}").mock(
        return_value=httpx.Response(200, json=INSIDE)
    )
    preview, done = await confirm(
        "fmc_update_interface",
        {
            "device": "mcp-ftd1",
            "interface": "inside",
            "security_zone": "mcp-test-ftd-dmz",
            "ipv4": "10.99.2.1/24",
        },
    )
    assert preview["preview"]["changes"] == {
        "zone": {"from": "mcp-test-ftd-in", "to": "mcp-test-ftd-dmz"},
        "ipv4": {"from": "10.99.1.1/24", "to": "10.99.2.1/24"},
    }
    body = json.loads(put.calls.last.request.content)
    assert body["securityZone"]["id"] == ZONES[2]["id"] and body["ifname"] == "inside"
    assert body["ipv4"] == {"static": {"address": "10.99.2.1", "netmask": "24"}}
    assert "metadata" not in body and "links" not in body
    assert body["fragmentReassembly"] is False and body["ipv6"] == INSIDE["ipv6"]  # untouched fields kept
    assert done["status"] == "applied"


async def test_update_interface_needs_name_and_refuses_management(ftd: respx.MockRouter) -> None:
    out = await preview_of(
        "fmc_update_interface", {"device": "mcp-ftd1", "interface": "Ethernet0/0", "logical_name": "none"}
    )
    assert out["status"] == "blocked" and any("logical_name" in b for b in out["blockers"])
    out = await preview_of(
        "fmc_update_interface", {"device": "mcp-ftd1", "interface": "Management0/0", "mtu": 1400}
    )
    assert any("Management" in b for b in out["blockers"])
    with pytest.raises(ToolError, match="No interface 'Ethernet0/9'"):
        await preview_of(
            "fmc_update_interface", {"device": "mcp-ftd1", "interface": "Ethernet0/9", "mtu": 1400}
        )


async def test_create_subinterface(ftd: respx.MockRouter) -> None:
    post = ftd.post(f"{DEVPATH}/subinterfaces").mock(return_value=httpx.Response(201, json={"id": "s1"}))
    preview, _ = await confirm(
        "fmc_create_subinterface",
        {
            "device": "mcp-ftd1",
            "parent": "Ethernet0/1",
            "vlan_id": 100,
            "logical_name": "dmz",
            "security_zone": "mcp-test-ftd-dmz",
            "ipv4": "10.99.100.1/24",
        },
    )
    assert preview["preview"]["interface"]["name"] == "Ethernet0/1.100"
    body = json.loads(post.calls.last.request.content)
    assert body["name"] == "Ethernet0/1" and body["subIntfId"] == 100 and body["vlanId"] == 100
    out = await preview_of(
        "fmc_create_subinterface",
        {"device": "mcp-ftd1", "parent": "Ethernet0/1", "vlan_id": 101, "logical_name": "inside"},
    )
    assert any("already used by Ethernet0/1" in b for b in out["blockers"])


async def test_delete_interface_only_logical(ftd: respx.MockRouter) -> None:
    out = await preview_of("fmc_delete_interface", {"device": "mcp-ftd1", "interface": "inside"})
    assert out["status"] == "blocked"
    assert any("only logical interfaces" in b for b in out["blockers"])
    assert any("route any-ipv4 via inside" in b for b in out["blockers"]) is False  # route is on outside


async def test_create_static_route_resolves_cidr_and_gateway(ftd: respx.MockRouter) -> None:
    ftd.get(f"{CFG}/object/networks").mock(return_value=items([ANY4]))
    ftd.get(f"{CFG}/object/hosts").mock(return_value=empty())
    post = ftd.post(f"{DEVPATH}/routing/ipv4staticroutes").mock(
        return_value=httpx.Response(201, json={"id": "r1"})
    )
    preview, _ = await confirm(
        "fmc_create_static_route",
        {"device": "mcp-ftd1", "interface": "outside", "networks": ["0.0.0.0/0"], "gateway": "198.18.128.1"},
    )
    assert preview["preview"]["route"]["networks"] == ["any-ipv4"]
    body = json.loads(post.calls.last.request.content)
    assert body["type"] == "IPv4StaticRoute" and body["interfaceName"] == "outside"
    assert body["selectedNetworks"] == [{"id": ANY4["id"], "type": "Network", "name": "any-ipv4"}]
    assert body["gateway"] == {"literal": {"type": "Host", "value": "198.18.128.1"}}


async def test_create_static_route_blockers(ftd: respx.MockRouter) -> None:
    ftd.get(f"{CFG}/object/networks").mock(return_value=empty())
    ftd.get(f"{CFG}/object/hosts").mock(return_value=empty())
    out = await preview_of(
        "fmc_create_static_route",
        {"device": "mcp-ftd1", "interface": "dmz", "networks": ["10.50.0.0/16"], "gateway": "10.99.1.254"},
    )
    assert out["status"] == "blocked"
    text = " ".join(out["blockers"])
    assert "No network object with value 10.50.0.0/16" in text and "no interface named 'dmz'" in text


async def test_create_static_route_blocks_exact_duplicate(ftd: respx.MockRouter) -> None:
    ftd.get(f"{CFG}/object/networks").mock(return_value=items([ANY4]))
    ftd.get(f"{CFG}/object/hosts").mock(return_value=empty())
    post = ftd.post(f"{DEVPATH}/routing/ipv4staticroutes")
    args = {"device": "mcp-ftd1", "interface": "OUTSIDE", "networks": ["0.0.0.0/0"], "gateway": "192.0.2.10"}
    out = await preview_of("fmc_create_static_route", {**args, "metric": 5})
    assert out["status"] == "blocked" and not post.called
    assert any("already has this route" in b for b in out["blockers"])
    # another gateway is a different route
    out = await preview_of("fmc_create_static_route", {**args, "gateway": "192.0.2.11"})
    assert out["status"] == "preview"


async def test_delete_static_route(ftd: respx.MockRouter) -> None:
    rid = fixture("ftd_ipv4staticroutes")["items"][0]["id"]
    ftd.get(f"{DEVPATH}/routing/ipv4staticroutes/{rid}").mock(
        return_value=httpx.Response(200, json=fixture("ftd_ipv4staticroutes")["items"][0])
    )
    delete = ftd.delete(f"{DEVPATH}/routing/ipv4staticroutes/{rid}").mock(
        return_value=httpx.Response(200, json={})
    )
    preview, _ = await confirm("fmc_delete_static_route", {"device": "mcp-ftd1", "route_id": rid})
    assert preview["preview"]["route"]["gateway"] == "192.0.2.10"
    assert delete.called


async def test_assign_policy_adds_target_to_existing_assignment(ftd: respx.MockRouter) -> None:
    other = {"id": "00000000-0000-0000-0000-00000000dev2", "type": "Device", "name": "ftd2"}
    assignment = {"id": NATP["id"], "type": "PolicyAssignment", "policy": NATP, "targets": [other]}
    old = {"id": "a2", "policy": {"id": "n-old", "name": "old-nat", "type": "FTDNatPolicy"}, "targets": [DEV]}
    ftd.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([assignment, old]))
    put = ftd.put(f"{CFG}/assignment/policyassignments/{NATP['id']}").mock(
        return_value=httpx.Response(200, json=assignment)
    )
    preview, _ = await confirm(
        "fmc_assign_policy", {"kind": "nat", "policy": "mcp-test-ftd-nat", "devices": ["mcp-ftd1"]}
    )
    assert preview["preview"]["changes"] == [
        {"device": "mcp-ftd1", "from": "old-nat", "to": "mcp-test-ftd-nat"}
    ]
    body = json.loads(put.calls.last.request.content)
    assert [t["id"] for t in body["targets"]] == [other["id"], DEV_ID]


async def test_assign_policy_new_assignment_and_noop(ftd: respx.MockRouter) -> None:
    ftd.get(f"{CFG}/assignment/policyassignments").mock(return_value=empty())
    post = ftd.post(f"{CFG}/assignment/policyassignments").mock(return_value=httpx.Response(201, json={}))
    await confirm("fmc_assign_policy", {"kind": "nat", "policy": "mcp-test-ftd-nat", "devices": ["mcp-ftd1"]})
    body = json.loads(post.calls.last.request.content)
    assert body["policy"]["id"] == NATP["id"] and body["targets"] == [{"id": DEV_ID, "type": "Device"}]


# --- troubleshooting --------------------------------------------------------------------------------


async def test_run_show_command(ftd: respx.MockRouter) -> None:
    route = ftd.get(f"{DEVPATH}/operational/commands").mock(
        return_value=httpx.Response(200, json=fixture("ftd_show_route"))
    )
    async with Client(server()) as c:
        out = await run(
            c, "fmc_run_show_command", {"device": "mcp-ftd1", "command": "show route", "match": "S*"}
        )
        with pytest.raises(ToolError, match="Only 'show"):
            await run(c, "fmc_run_show_command", {"device": "mcp-ftd1", "command": "clear conn"})
    assert route.calls.last.request.url.params["command"] == "show route"
    assert out["output"].startswith("S*") and "outside" in out["output"] and out["matched_lines"] == 1


async def test_run_show_command_checks_fmc_allowlist_first(ftd: respx.MockRouter) -> None:
    """Commands FMC's command API doesn't list are refused with alternatives before FMC is called; longer
    commands go out as two words + parameters ('show route' + 'bgp')."""
    cmd = ftd.get(f"{DEVPATH}/operational/commands").mock(
        return_value=items([{"commandOutput": "B 10.20.1.0 255.255.255.0 [200/0] via 10.255.20.1"}])
    )
    async with Client(server()) as c:
        for bad, hint in (
            ("show bgp summary", "show route bgp"),
            ("show path-monitoring", "fmc_sdwan_status"),
        ):
            with pytest.raises(ToolError, match="not supported by FMC's command API") as e:
                await run(c, "fmc_run_show_command", {"device": "nonexistent-device", "command": bad})
            assert hint in str(e.value) and "Supported (FMC 10.0.1 list)" in str(e.value)
        assert cmd.call_count == 0
        out = await run(c, "fmc_run_show_command", {"device": "mcp-ftd1", "command": "show route bgp"})
    params = cmd.calls.last.request.url.params
    assert (params["command"], params["parameters"]) == ("show route", "bgp")
    assert out["command"] == "show route bgp" and "10.20.1.0" in out["output"]


async def test_run_show_command_reads_the_allowlist_from_the_spec(ftd: respx.MockRouter) -> None:
    from fmc_mcp.client import SPEC_PATH

    from .test_show_commands import SPEC_DESCRIPTION, spec_doc

    newer = SPEC_DESCRIPTION.replace("show banner", "show banner, show path-monitoring")
    spec = ftd.get(SPEC_PATH).mock(return_value=httpx.Response(200, json=spec_doc(newer)))
    cmd = ftd.get(f"{DEVPATH}/operational/commands").mock(return_value=items([{"commandOutput": "ok"}]))
    async with Client(server()) as c:
        out = await run(c, "fmc_run_show_command", {"device": "mcp-ftd1", "command": "show path-monitoring"})
        with pytest.raises(ToolError, match="from the FMC API spec"):
            await run(c, "fmc_run_show_command", {"device": "mcp-ftd1", "command": "show bgp summary"})
    assert out["output"] == "ok" and cmd.calls.last.request.url.params["command"] == "show path-monitoring"
    assert spec.call_count == 1 and cmd.call_count == 1


async def test_show_command_invalid_vs_not_found(ftd: respx.MockRouter) -> None:
    def reply(req: httpx.Request) -> httpx.Response:
        msg = (
            "The input command is invalid. Please enter a valid command" if "ntp" in str(req.url) else "gone"
        )
        return httpx.Response(404, json={"error": {"messages": [{"description": msg}]}})

    ftd.get(f"{DEVPATH}/operational/commands").mock(side_effect=reply)
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="rejects 'show running-config ntp' as invalid"):
            await run(c, "fmc_run_show_command", {"device": "mcp-ftd1", "command": "show running-config ntp"})
        with pytest.raises(ToolError, match="404 for 'show route': gone"):
            await run(c, "fmc_run_show_command", {"device": "mcp-ftd1", "command": "show route"})


async def test_packet_tracer_request_and_summary(ftd: respx.MockRouter) -> None:
    post = ftd.post(f"/api/fmc_troubleshoot/v1/domain/{DOMAIN}/packettracer/traces").mock(
        return_value=httpx.Response(200, json=fixture("ftd_packettracer_drop"))
    )
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_packet_tracer",
            {
                "device": "mcp-ftd1",
                "input_interface": "inside",
                "protocol": "tcp",
                "source_ip": "10.99.1.10",
                "destination_ip": "198.18.134.76",
                "destination_port": 23,
            },
        )
        with pytest.raises(ToolError, match="destination_port is required"):
            await run(
                c,
                "fmc_packet_tracer",
                {
                    "device": "mcp-ftd1",
                    "input_interface": "inside",
                    "protocol": "udp",
                    "source_ip": "10.99.1.10",
                    "destination_ip": "198.18.134.76",
                },
            )
    body = json.loads(post.calls.last.request.content)
    assert body["device"] == {"id": DEV_ID, "type": "Device", "name": "mcp-ftd1"}
    assert body["interface"]["id"] == INSIDE["id"] and body["interface"]["name"] == "inside"
    assert body["protocol"] == "TCP" and body["destinationPort"] == "23" and body["sourcePort"] == "40000"
    assert out["flow"] == "tcp 10.99.1.10:40000 -> 198.18.134.76:23"
    assert out["results"][0]["matched_rules"][0]["rule"] == "mcp-test-block-telnet"


async def test_hit_counts_lists_rule_ids_and_default(ftd: respx.MockRouter) -> None:
    rules = [
        {"id": "00000000-0000-0ed3-0000-000268434474", "name": "mcp-test-allow-out", "type": "AccessRule"},
        {"id": "00000000-0000-0ed3-0000-000268434475", "name": "mcp-test-block-telnet", "type": "AccessRule"},
    ]
    ftd.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules").mock(return_value=items(rules))
    hc = f"{CFG}/policy/accesspolicies/{ACP['id']}/operational/hitcounts"
    refresh = ftd.put(hc).mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "hc1"}}, "type": "HitCount"})
    )
    ftd.get(f"{CFG}/job/taskstatuses/hc1").mock(
        return_value=httpx.Response(200, json={"id": "hc1", "status": "SUCCESS"})
    )

    def hitcounts(request: httpx.Request) -> httpx.Response:
        flt = request.url.params["filter"]
        return httpx.Response(
            200, json=fixture("ftd_hitcounts" if "ids:" in flt else "ftd_hitcounts_default")
        )

    get = ftd.get(hc).mock(side_effect=hitcounts)
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_get_hit_counts",
            {"policy": "mcp-test-ftd-acp", "device": "mcp-ftd1", "response_format": "json"},
        )
        zero = await run(
            c,
            "fmc_get_hit_counts",
            {
                "policy": "mcp-test-ftd-acp",
                "device": "mcp-ftd1",
                "only_zero": True,
                "refresh": False,
                "response_format": "json",
            },
        )
    assert refresh.calls.last.request.url.params["filter"] == f"deviceId:{DEV_ID}"
    flts = [call.request.url.params["filter"] for call in get.calls]
    assert any(f"ids:{rules[0]['id']},{rules[1]['id']}" in f for f in flts)
    names = [r["rule"] for r in out["results"]]
    assert names == ["mcp-test-allow-out", "mcp-test-block-telnet", "Default Action"]
    assert out["results"][1]["device_rule_id"] == "268434475" and out["results"][1]["hits"] > 0
    assert [r["rule"] for r in zero["results"]] == ["Default Action"]


def fmc_hitcounts(rows: list[dict[str, Any]]) -> Any:
    """FMC 10.0.1's hit-count GET as recorded: `ids` picks rows (fetchZeroHitCount ignored), `name`
    matches rule names, and without ids fetchZeroHitCount:true keeps only rows that were never hit."""

    def answer(request: httpx.Request) -> httpx.Response:
        flt = dict(p.split(":", 1) for p in request.url.params["filter"].split(";"))
        if "ids" in flt:
            out = [r for r in rows if r["rule"]["id"] in flt["ids"].split(",")]
        elif "name" in flt:
            out = [r for r in rows if flt["name"].lower() in r["rule"]["name"].lower()]
        elif flt.get("fetchZeroHitCount") == "true":
            out = [r for r in rows if not r["hitCount"]]
        else:
            out = rows
        return items(out)

    return answer


async def test_hit_counts_show_a_default_action_that_was_hit(ftd: respx.MockRouter) -> None:
    """Live finding (F62 proof): the default action had blocked one flow, so the no-ids
    fetchZeroHitCount:true query left it out and the tool showed no default-action row."""
    rows = fixture("ftd_hitcounts_default_hit")["items"]
    default_id = rows[3]["rule"]["id"]
    acp = {**ACP, "defaultAction": {"action": "BLOCK", "type": "AccessPolicyDefaultAction", "id": default_id}}
    ftd.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([acp]))
    # a rule added at the top after the last deploy has no hit-count row yet (as live)
    rules = [{"id": "00000000-0000-0ed3-0000-000268434499", "name": "mcp-fw-new", "type": "AccessRule"}]
    rules += [r["rule"] for r in rows[:3]]
    ftd.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules").mock(return_value=items(rules))
    get = ftd.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/operational/hitcounts").mock(
        side_effect=fmc_hitcounts(rows)
    )
    args = {"policy": "mcp-test-ftd-acp", "device": "mcp-ftd1", "refresh": False, "response_format": "json"}
    async with Client(server()) as c:
        out = await run(c, "fmc_get_hit_counts", args)
        zero = await run(c, "fmc_get_hit_counts", {**args, "only_zero": True})
    got = [(r["index"], r["rule"], r["hits"]) for r in out["results"]]
    assert got == [
        (2, "mcp-fw-baseline", 34),
        (3, "mcp-fw-lab-extra", 8),
        (4, "mcp-fw-find-client", 0),
        ("default", "Default Action", 1),
    ]
    assert out["results"][3]["device_rule_id"] == "268434483"
    assert all("ids:" in c.request.url.params["filter"] for c in get.calls)  # default id rides along
    assert [r["rule"] for r in zero["results"]] == ["mcp-fw-find-client"]


async def test_hit_counts_find_the_default_action_by_name(ftd: respx.MockRouter) -> None:
    """Without the policy's defaultAction id (not in the record), the row is asked for by name."""
    rows = fixture("ftd_hitcounts_default_hit")["items"]
    ftd.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules").mock(
        return_value=items([r["rule"] for r in rows[:3]])
    )
    get = ftd.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/operational/hitcounts").mock(
        side_effect=fmc_hitcounts(rows)
    )
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_get_hit_counts",
            {"policy": "mcp-test-ftd-acp", "device": "mcp-ftd1", "refresh": False, "response_format": "json"},
        )
    assert out["results"][-1]["rule"] == "Default Action" and out["results"][-1]["hits"] == 1
    assert any("name:Default Action" in c.request.url.params["filter"] for c in get.calls)


async def test_device_health(ftd: respx.MockRouter) -> None:
    alerts = fixture("ftd_health_alerts")
    alerts["items"][0] = {**alerts["items"][0], "status": "YELLOW", "details": "disk 85%"}
    ftd.get(f"{CFG}/health/alerts").mock(return_value=httpx.Response(200, json=alerts))

    def metrics(request: httpx.Request) -> httpx.Response:
        if "metric:mem" in request.url.params["filter"]:
            return httpx.Response(200, json=fixture("ftd_health_metrics_mem"))
        return httpx.Response(400, json={"error": {"messages": [{"description": "bad metric"}]}})

    ftd.get(f"{CFG}/health/metrics").mock(side_effect=metrics)
    async with Client(server()) as c:
        out = await run(c, "fmc_device_health", {"device": "mcp-ftd1"})
    assert out["module_counts"]["YELLOW"] == 1
    assert out["modules"] == [
        {
            "module": alerts["items"][0]["moduleID"],
            "status": "YELLOW",
            "details": "disk 85%",
            "time": out["modules"][0]["time"],
        }
    ]
    assert set(out["resources"]) == {"mem_system_pct", "mem_data_plane_pct", "mem_snort_pct"}


# --- dangerous ---------------------------------------------------------------------------------------


async def test_rollback_defaults_to_previous_success(ftd: respx.MockRouter) -> None:
    jobs = fixture("ftd_deployments")
    ftd.get(f"{CFG}/deployment/jobhistories").mock(return_value=items([{"id": "j-none"}]))
    ftd.get(f"{CFG}/deployment/deployabledevices/{DEV_ID}/deployments").mock(
        return_value=httpx.Response(200, json=jobs)
    )
    post = ftd.post(f"{CFG}/deployment/rollbackrequests").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "rb1"}}})
    )
    ftd.get(f"{CFG}/job/taskstatuses/rb1").mock(
        return_value=httpx.Response(
            200, json={"id": "rb1", "status": "Deployed", "taskType": "DEVICE_ROLLBACK"}
        )
    )
    preview, done = await confirm("fmc_rollback_deployment", {"device": "mcp-ftd1"})
    ordered = sorted(jobs["items"], key=lambda j: j["startTime"], reverse=True)
    assert preview["preview"]["roll_back_to"]["job"] == ordered[1]["name"]
    body = json.loads(post.calls.last.request.content)
    assert body == {
        "type": "RollbackRequest",
        "rollbackDeviceList": [{"deploymentJobId": ordered[1]["id"], "deviceList": [DEV_ID]}],
    }
    assert done["result"]["task"]["taskType"] == "DEVICE_ROLLBACK"
    latest = await preview_of("fmc_rollback_deployment", {"device": "mcp-ftd1", "to_job": ordered[0]["name"]})
    assert latest["status"] == "blocked" and "already the latest" in latest["blockers"][0]


async def test_register_failure_explains_licensing(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    fmc.post(f"{CFG}/devices/devicerecords").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "r1"}}})
    )
    fmc.get(f"{CFG}/job/taskstatuses/r1").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "r1",
                "status": "FAILED",
                "message": "REGISTRATION_FAILED",
                "description": "To add Firepower Threat Defense devices, register this console with the "
                "Smart Licensing Server.",
            },
        )
    )
    args = {"name": "ftd9", "host": "10.0.0.9", "reg_key": "k", "access_policy": "mcp-test-ftd-acp"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_register_device", args)
        with pytest.raises(ToolError, match="evaluation mode") as err:
            await run(c, "fmc_register_device", {**args, "confirm": preview["confirm"]})
    assert "REGISTRATION_FAILED - To add Firepower" in str(err.value)


async def test_register_waits_for_initial_deployment(
    fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The wall clock frozen (#274): the job used to say time.time() + 1 at setup, and a registration sent
    # more than ~6 s later on a slow runner took it for an older job and polled until the task timeout.
    frozen = 1792368000
    monkeypatch.setattr(dangerous, "wall_clock", lambda: frozen)
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    post = fmc.post(f"{CFG}/devices/devicerecords").mock(
        return_value=httpx.Response(202, json={"metadata": {"task": {"id": "r2"}}})
    )
    fmc.get(f"{CFG}/job/taskstatuses/r2").mock(
        return_value=httpx.Response(
            200, json={"id": "r2", "status": "SUCCESS", "message": "DISCOVERY_SUCCESS"}
        )
    )

    def devices(request: httpx.Request) -> httpx.Response:
        return items([DEV] if post.called else [])  # the device appears once registered

    fmc.get(f"{CFG}/devices/devicerecords").mock(side_effect=devices)
    fmc.get(f"{CFG}/deployment/jobhistories").mock(
        return_value=items(
            [
                {
                    "jobName": "Deploy_Job_0",
                    "jobStatus": "DEPLOYED",
                    "startTime": 1000,
                },  # before registration
                {
                    "jobName": "Deploy_Job_1",
                    "jobStatus": "DEPLOYED",
                    "deploymentNote": "after reg",
                    "startTime": frozen + 1,
                },
            ]
        )
    )
    args = {"name": "mcp-ftd1", "host": "10.0.0.9", "reg_key": "k", "access_policy": "mcp-test-ftd-acp"}
    async with asyncio.timeout(60):  # a hang fails fast instead of waiting out the task timeout
        _, done = await confirm("fmc_register_device", args)
    assert done["result"]["initial_deployment"] == {
        "device_id": DEV_ID,
        "job": "Deploy_Job_1",
        "status": "DEPLOYED",
        "note": "after reg",
        "ok": True,
    }


async def test_deploy_validation_warning_hint(fmc: respx.MockRouter) -> None:
    pending = {
        "name": "mcp-ftd1",
        "version": "1",
        "canBeDeployed": True,
        "device": {"id": DEV_ID, "name": "mcp-ftd1", "type": "Device"},
    }
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([pending]))
    fmc.post(f"{CFG}/deployment/deploymentrequests").mock(
        return_value=httpx.Response(
            400,
            json={
                "error": {
                    "messages": [
                        {
                            "description": "Errors or warnings present in Device committed "
                            "policies: | The changes to Virtual Routers may "
                            "cause traffic disruption."
                        }
                    ]
                }
            },
        )
    )
    async with Client(server(allow_ignore_warning=True)) as c:
        preview = await run(c, "fmc_deploy", {})
        with pytest.raises(ToolError, match="ignore_warning=true"):
            await run(c, "fmc_deploy", {"confirm": preview["confirm"]})
        # F18: the warnings FMC gave are now listed verbatim when ignoring them
        again = await run(c, "fmc_deploy", {"ignore_warning": True})
        assert again["status"] == "preview", again
        assert again["preview"]["warnings_ignored"] == [
            "Errors or warnings present in Device committed policies:",
            "The changes to Virtual Routers may cause traffic disruption.",
        ]


async def test_vpn_tunnels_down_first(ftd: respx.MockRouter) -> None:
    def tunnel(name: str, state: str) -> dict[str, Any]:  # shape from the FMC 10.0.1 spec example
        return {
            "id": f"t-{name}",
            "peerA": {"device": {"name": "hub", "type": "Device"}, "ipAddresses": {"v4": ["192.0.2.1"]}},
            "peerB": {"device": {"name": name, "type": "Device"}, "ipAddresses": {"v4": ["198.51.100.7"]}},
            "state": state,
            "message": "Tunnel is up" if state == "TUNNEL_UP" else "Tunnel is down",
            "vpnTopology": {"id": "topo", "name": "Topology-1", "type": "FTDS2SVPNTopology"},
            "type": "TunnelStatus",
        }

    route = ftd.get(f"{CFG}/health/tunnelstatuses").mock(
        return_value=items([tunnel("branch1", "TUNNEL_UP"), tunnel("branch2", "TUNNEL_DOWN")])
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_list_vpn_tunnels", {"device": "mcp-ftd1", "response_format": "json"})
    assert route.calls.last.request.url.params["filter"] == f"deviceId:{DEV_ID}"
    assert [r["peer_b"] for r in out["results"]] == ["branch2 (198.51.100.7)", "branch1 (198.51.100.7)"]
    assert out["states"] == {"TUNNEL_DOWN": 1, "TUNNEL_UP": 1}


def test_redact_secrets() -> None:
    text = (
        "username admin password AbC123 encrypted privilege 15\n"
        "snmp-server host outside 192.0.2.1 community 0 s3cr3t version 2c\n"
        "snmp-server user u grp v3 encrypted auth sha256 AA:BB priv aes 256 CC:DD\n"
        " ikev2 remote-authentication pre-shared-key mypsk\n"
        " key *****\n"
        "route outside 0.0.0.0 0.0.0.0 192.0.2.1 1"
    )
    out, n = redact(text)
    for secret in ("AbC123", "s3cr3t", "AA:BB", "CC:DD", "mypsk"):
        assert secret not in out
    assert n == 5 and "route outside 0.0.0.0 0.0.0.0 192.0.2.1 1" in out


def test_redact_skips_qualifiers_before_the_secret() -> None:
    """A key id, hash, format or EIGRP AS between the keyword and the value is no secret: the value is
    (it used to mask 'md5' and print the key)."""
    text = (
        " ospf message-digest-key 1 md5 k3y0spf\n"
        "ntp authentication-key 1 md5 k3yntp\n"
        "failover key hex 0a1b2c3d\n"
        " authentication key eigrp 100 k3yeigrp\n"
        " ospf message-digest-key 2 md5 *****"
    )
    out, n = redact(text)
    for secret in ("k3y0spf", "k3yntp", "0a1b2c3d", "k3yeigrp"):
        assert secret not in out
    assert "message-digest-key 1 md5 ********" in out and "eigrp 100 ********" in out
    assert n == 4 and "message-digest-key 2 md5 *****" in out  # masked by the device already


async def test_show_command_output_is_redacted(ftd: respx.MockRouter) -> None:
    ftd.get(f"{DEVPATH}/operational/commands").mock(
        return_value=items(
            [{"commandOutput": "snmp-server host inside 192.0.2.9 community public", "type": "command"}]
        )
    )
    async with Client(server()) as c:
        out = await run(
            c, "fmc_run_show_command", {"device": "mcp-ftd1", "command": "show running-config snmp-server"}
        )
    assert "public" not in out["output"] and out["redacted"].startswith("1 secret")


async def test_delete_static_route_needs_uuid(ftd: respx.MockRouter) -> None:
    with pytest.raises(ToolError, match="route UUID"):
        await preview_of(
            "fmc_delete_static_route", {"device": "mcp-ftd1", "route_id": "x/../../object/hosts"}
        )


async def test_rollback_preview_states_current_and_target(ftd: respx.MockRouter) -> None:
    jobs = fixture("ftd_deployments")
    ftd.get(f"{CFG}/deployment/jobhistories").mock(return_value=items([{"id": "j-none"}]))
    ftd.get(f"{CFG}/deployment/deployabledevices/{DEV_ID}/deployments").mock(
        return_value=httpx.Response(200, json=jobs)
    )
    ordered = sorted(jobs["items"], key=lambda j: j["startTime"], reverse=True)
    out = await preview_of("fmc_rollback_deployment", {"device": "mcp-ftd1", "to_job": ordered[3]["name"]})
    assert out["preview"]["device_runs"] == ordered[0]["name"]
    assert out["preview"]["roll_back_to"]["job"] == ordered[3]["name"]


def test_hit_count_times_are_converted_from_fmc_local_time() -> None:
    from datetime import UTC, datetime

    from fmc_mcp.tools.troubleshoot import learn_local_offset, to_utc

    now = datetime(2026, 10, 15, 19, 14, 55, tzinfo=UTC).timestamp()
    off = learn_local_offset("2026-10-15T15:14:51Z", now)  # FMC in UTC-4 labels local time 'Z'
    assert off == -4 * 3600
    assert to_utc("2026-10-15T15:14:30Z", off) == "2026-10-15T19:14:30Z"
    assert to_utc("2026-10-15T15:14:30Z", None) == "2026-10-15T15:14:30 (FMC local time)"
    assert learn_local_offset("2026-10-15T19:14:50Z", now) == 0
    assert learn_local_offset("2026-10-14T01:00:00Z", now) is None  # stale counters: don't guess


# --- flow context, dynamic objects, NAT by address (F28, F30, F31) ---------------------------------

INSIDE_NET = {
    "id": "net-inside",
    "name": "mcp-test-ftd-inside-net",
    "type": "Network",
    "value": "10.99.1.0/24",
}
QUAR = {"id": "dyn-q", "name": "mcp-quarantine", "type": "DynamicObject"}


def _catalog(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/networkaddresses").mock(return_value=items([ANY4, INSIDE_NET]))
    for p in (
        "ranges",
        "networkgroups",
        "protocolportobjects",
        "icmpv4objects",
        "icmpv6objects",
        "portobjectgroups",
    ):
        fmc.get(f"{CFG}/object/{p}").mock(return_value=empty())


def _flow_rules(fmc: respx.MockRouter, mapped: list[str]) -> None:
    zin, zout = ({"objects": [{"id": z["id"], "name": z["name"], "type": "SecurityZone"}]} for z in ZONES[:2])
    rules = [
        {
            "id": "r1",
            "name": "mcp-quarantine-out",
            "action": "BLOCK",
            "enabled": True,
            "metadata": {"ruleIndex": 1, "section": "Default"},
            "sourceDynamicObjects": {"objects": [QUAR]},
        },
        {
            "id": "r2",
            "name": "allow-out",
            "action": "ALLOW",
            "enabled": True,
            "metadata": {"ruleIndex": 2, "section": "Default"},
            "sourceZones": zin,
            "destinationZones": zout,
        },
    ]
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules").mock(return_value=items(rules))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}").mock(
        return_value=httpx.Response(200, json={**ACP, "defaultAction": {"action": "BLOCK"}})
    )
    fmc.get(f"{CFG}/object/dynamicobjects/{QUAR['id']}/mappings").mock(
        return_value=items([{"mapping": m} for m in mapped])
    )


async def test_rule_lookup_from_device_derives_policy_zones_and_dynamic_mappings(
    ftd: respx.MockRouter,
) -> None:
    _catalog(ftd)
    _flow_rules(ftd, mapped=[])
    args = {"device": "mcp-ftd1", "source": "10.99.1.10", "destination": "8.8.8.8", "port": 443}
    async with Client(server()) as c:
        out = await run(c, "fmc_rule_lookup", args)
    assert out["policy"] == "mcp-test-ftd-acp"
    assert (
        out["device"]["ingress"]["interface"] == "inside"
        and out["device"]["egress"]["interface"] == "outside"
    )
    assert (
        out["flow"]["source_zone"] == "mcp-test-ftd-in"
        and out["flow"]["destination_zone"] == "mcp-test-ftd-out"
    )
    assert "route 0.0.0.0/0" in out["device"]["egress"]["found_by"]
    assert out["matched_rule"]["name"] == "allow-out" and "may_match_first" not in out  # empty quarantine


async def test_rule_lookup_contained_host_matches_the_quarantine_rule(ftd: respx.MockRouter) -> None:
    _catalog(ftd)
    _flow_rules(ftd, mapped=["10.99.1.10"])
    args = {"device": "mcp-ftd1", "source": "10.99.1.10", "destination": "8.8.8.8", "port": 443}
    async with Client(server()) as c:
        out = await run(c, "fmc_rule_lookup", args)
    assert out["matched_rule"]["name"] == "mcp-quarantine-out" and out["verdict"].endswith("BLOCK")


async def test_packet_tracer_picks_the_ingress_interface_from_the_source(ftd: respx.MockRouter) -> None:
    _catalog(ftd)
    post = ftd.post(f"/api/fmc_troubleshoot/v1/domain/{DOMAIN}/packettracer/traces").mock(
        return_value=httpx.Response(200, json=fixture("ftd_packettracer_drop"))
    )
    args = {"device": "mcp-ftd1", "protocol": "tcp", "source_ip": "10.99.1.10", "destination_ip": "8.8.8.8"}
    async with Client(server()) as c:
        out = await run(c, "fmc_packet_tracer", {**args, "destination_port": 23})
    assert json.loads(post.calls.last.request.content)["interface"]["id"] == INSIDE["id"]
    assert out["input_interface"] == "inside" and out["input_interface_found_by"].startswith("connected")


async def test_nat_rules_by_address_resolve_objects(ftd: respx.MockRouter) -> None:
    _catalog(ftd)
    rule = {
        "id": "n1",
        "type": "FTDAutoNatRule",
        "natType": "DYNAMIC",
        "originalNetwork": {"id": INSIDE_NET["id"], "name": INSIDE_NET["name"], "type": "Network"},
        "interfaceInTranslatedNetwork": True,
        "metadata": {"section": "AUTO"},
    }
    ftd.get(f"{CFG}/policy/ftdnatpolicies/{NATP['id']}/natrules").mock(return_value=items([rule]))
    ftd.get(f"{CFG}/policy/ftdnatpolicies/{NATP['id']}").mock(return_value=httpx.Response(200, json=NATP))
    ftd.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items([{"policy": NATP, "targets": [{"id": DEV_ID, "type": "Device"}]}])
    )
    async with Client(server()) as c:
        hit = await run(
            c,
            "fmc_list_nat_rules",
            {"device": "mcp-ftd1", "address": "10.99.1.10", "response_format": "json"},
        )
        miss = await run(
            c,
            "fmc_list_nat_rules",
            {"device": "mcp-ftd1", "address": "10.99.2.10", "response_format": "json"},
        )
    assert hit["policy"] == "mcp-test-ftd-nat"
    assert hit["results"][0]["original_source"] == "mcp-test-ftd-inside-net (10.99.1.0/24)"
    assert miss["results"] == []


def test_rule_columns_show_dynamic_objects_and_drop_empty_ones() -> None:
    from fmc_mcp.tools.policies import rule_columns

    rows = [{"index": 1, "name": "q", "action": "BLOCK", "enabled": True, "src_dynamic": ["mcp-quarantine"]}]
    assert rule_columns(rows) == ["index", "name", "action", "enabled", "src_dynamic"]


def test_flow_leg_prefers_longest_match_then_connected_then_metric() -> None:
    import ipaddress as ipa

    from fmc_mcp.flow import DeviceContext

    rows = [
        {"logical_name": "inside", "zone": "in", "enabled": True, "_nets": [ipa.ip_network("10.0.0.0/16")]},
        {"logical_name": "dmz", "zone": "dmz", "enabled": True, "_nets": []},
        {"logical_name": "off", "zone": "x", "enabled": False, "_nets": [ipa.ip_network("10.9.0.0/24")]},
        {"logical_name": "v6", "zone": "z6", "enabled": True, "_nets": [ipa.ip_network("2001:db8::/64")]},
    ]
    routes = [
        (ipa.ip_network("10.0.5.0/24"), "dmz", "10.0.0.9", 1),
        (ipa.ip_network("0.0.0.0/0"), "outside", "gw2", 10),
        (ipa.ip_network("0.0.0.0/0"), "dmz", "gw1", 1),
    ]
    dc = DeviceContext(rows, routes)  # type: ignore[arg-type]
    assert dc.leg(ipa.ip_address("10.0.5.7")).interface == "dmz"  # type: ignore[union-attr]
    assert dc.leg(ipa.ip_address("10.0.1.1")).interface == "inside"  # type: ignore[union-attr]
    assert dc.leg(ipa.ip_address("10.9.0.5")).interface == "dmz"  # disabled iface skipped; best default
    assert dc.leg(ipa.ip_address("2001:db8::5")).zone == "z6"  # type: ignore[union-attr]


def test_show_route_legend_is_stripped() -> None:
    from fmc_mcp.tools.troubleshoot import ROUTE_LEGEND

    text = (
        "\nCodes: L - local, C - connected, S - static\n       D - EIGRP, EX - EIGRP external\n"
        "Gateway of last resort is 198.18.128.1 to network 0.0.0.0\n\n"
        "S*  0.0.0.0 0.0.0.0 via 198.18.128.1, outside\n"
    )
    out = ROUTE_LEGEND.sub("", text)
    assert "Codes:" not in out and "EIGRP" not in out and "Gateway of last resort" in out and "S*" in out

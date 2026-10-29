"""C81 (core 0.20.0 `Plan.undo`): the main write tools say how to back each change out. The preview shows
'back-out: <tool>(<args>)' (a created object's id as `<from the result: ...>`), the applied result carries
`undo` {tool, args, back_out} with the new id filled in, and a delete that one call can't reverse says
'not reversible' with the definition read before it. Mocks reuse the recorded fixtures of the neighbouring
tests (test_tools_write, test_tools_ftd, test_interfaces, test_sla_monitors, test_admin)."""

import copy
import json

import httpx
import respx

from fmc_mcp._core.testing import undo_problems
from fmc_mcp.server import create_server
from fmc_mcp.tools.policy_writes import _log_mode, access_rule_undo
from fmc_mcp.undo import ResultId, block_refs, literal_text

from . import test_interfaces as ti
from .conftest import ACP_ID, CFG, NAT_ID, empty, fixture, items, make_settings
from .test_admin import HP, HP_ID
from .test_sla_monitors import MON, OUT_ZONE, ROUTE, monitor_by_id, monitors, network_mocks, routes
from .test_tools_ftd import DEV_ID, DEVPATH, INSIDE, ZONES, confirm, ftd, preview_of  # noqa: F401
from .test_tools_write import HOST, preview_apply

# The tools this item adopts Plan.undo on (C81): none of them may be left in the UndoWarning list.
ADOPTED = [
    "fmc_create_object",
    "fmc_update_object",
    "fmc_delete_object",
    "fmc_create_group",
    "fmc_update_group",
    "fmc_create_security_zone",
    "fmc_create_access_rule",
    "fmc_update_access_rule",
    "fmc_delete_access_rule",
    "fmc_create_nat_rule",
    "fmc_update_nat_rule",
    "fmc_delete_nat_rule",
    "fmc_create_static_route",
    "fmc_delete_static_route",
    "fmc_create_interface",
    "fmc_create_subinterface",
    "fmc_update_interface",
    "fmc_delete_interface",
    "fmc_create_sla_monitor",
    "fmc_update_sla_monitor",
    "fmc_delete_sla_monitor",
    "fmc_create_health_policy",
    "fmc_update_health_policy",
    "fmc_delete_health_policy",
]


def test_contract_no_undo_warning_for_the_adopted_tools() -> None:
    mcp = create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))
    missing = undo_problems(mcp, "fmc")
    assert not [t for t in ADOPTED if t in missing]
    assert all(t in mcp._stutters_tiers for t in ADOPTED)  # type: ignore[attr-defined]


def test_result_id_and_literal_texts() -> None:
    assert ResultId("rule.id").resolve({"rule": {"id": "r1"}}) == "r1"
    assert ResultId("rule.id").resolve({"id": "r2", "name": "x"}) == "r2"  # FMC's answer as it came
    assert literal_text({"type": "PortLiteral", "protocol": "6", "port": "443"}) == "tcp/443"
    assert literal_text({"type": "PortLiteral", "protocol": "17"}) == "udp"
    assert literal_text({"type": "ICMPv4PortLiteral", "protocol": "1", "icmpType": "Any"}) == "icmp"
    assert literal_text({"type": "ICMPv4PortLiteral", "protocol": "1", "icmpType": "8"}) == "icmp/8"
    assert literal_text({"type": "VlanTagLiteral", "startTag": 100, "endTag": 110}) == "100-110"
    assert literal_text({"type": "Network", "value": "10.9.0.0/16"}) == "10.9.0.0/16"
    block = {"objects": [{"id": "o1", "name": "web"}], "literals": [{"type": "Host", "value": "10.0.0.1"}]}
    assert block_refs(block) == ["o1", "10.0.0.1"]


# --- objects ---------------------------------------------------------------------------------------


async def test_create_object_backs_out_with_delete(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(return_value=empty())
    fmc.post(f"{CFG}/object/hosts").mock(return_value=httpx.Response(201, json={**HOST, "links": {}}))
    preview, done = await preview_apply(
        "fmc_create_object", {"type": "host", "name": "h1", "value": "10.0.0.1"}
    )
    assert preview["undo"] == 'back-out: fmc_delete_object(object=<from the result: id>, type="host")'
    assert done["undo"]["tool"] == "fmc_delete_object"
    assert done["undo"]["args"] == {"object": HOST["id"], "type": "host"}
    assert done["undo"]["back_out"] == f'fmc_delete_object(object="{HOST["id"]}", type="host")'


async def test_update_object_backs_out_with_the_old_value(fmc: respx.MockRouter) -> None:
    current = {**HOST, "description": "web"}
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([current]))
    fmc.get(f"{CFG}/object/operational/usage").mock(return_value=empty())
    fmc.put(f"{CFG}/object/hosts/{HOST['id']}").mock(return_value=httpx.Response(200, json=HOST))
    preview, done = await preview_apply(
        "fmc_update_object", {"object": "h1", "type": "host", "value": "10.0.0.9", "new_name": "h9"}
    )
    want = {"object": HOST["id"], "type": "host", "new_name": "h1", "value": "10.0.0.1"}
    assert done["undo"]["args"] == want
    assert preview["undo"].startswith("back-out: fmc_update_object(") and '"10.0.0.1"' in preview["undo"]


async def test_delete_unused_object_backs_out_with_create(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([{**HOST, "description": "web"}]))
    fmc.get(f"{CFG}/object/operational/usage").mock(return_value=empty())
    fmc.delete(f"{CFG}/object/hosts/{HOST['id']}").mock(return_value=httpx.Response(200, json=HOST))
    preview, done = await preview_apply("fmc_delete_object", {"object": "h1", "type": "host"})
    assert preview["undo"].startswith("back-out: fmc_create_object(")
    assert done["undo"]["args"] == {"type": "host", "name": "h1", "value": "10.0.0.1", "description": "web"}


async def test_update_group_backs_out_with_the_reverse_members(fmc: respx.MockRouter) -> None:
    group = {
        "id": "00000000-0000-0000-0000-0000000000b1",
        "name": "g1",
        "type": "NetworkGroup",
        "objects": [{"id": HOST["id"], "type": "Host", "name": "h1"}],
        "literals": [{"type": "Network", "value": "10.9.0.0/16"}],
    }
    fmc.get(f"{CFG}/object/networkgroups").mock(return_value=items([group]))
    fmc.get(f"{CFG}/object/operational/usage").mock(return_value=empty())
    fmc.put(f"{CFG}/object/networkgroups/{group['id']}").mock(return_value=httpx.Response(200, json=group))
    _, done = await preview_apply(
        "fmc_update_group", {"group": "g1", "add": ["10.8.0.0/16"], "remove": ["h1"]}
    )
    assert done["undo"]["tool"] == "fmc_update_group"
    assert done["undo"]["args"] == {
        "group": group["id"],
        "kind": "network",
        "add": [HOST["id"]],
        "remove": ["10.8.0.0/16"],
    }


# --- access rules ----------------------------------------------------------------------------------


async def test_create_access_rule_backs_out_with_delete_of_the_new_rule(lab: respx.MockRouter) -> None:
    new = {"id": "0050568a-0c0b-0ed3-0000-021474899001", "name": "mcp-undo", "type": "AccessRule"}
    lab.post(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=httpx.Response(201, json=new)
    )
    preview, done = await preview_apply(
        "fmc_create_access_rule",
        {"policy": "mcp-test-acp", "name": "mcp-undo", "action": "BLOCK", "destination_ports": ["tcp/23"]},
    )
    assert preview["undo"] == (
        f'back-out: fmc_delete_access_rule(policy="{ACP_ID}", rule=<from the result: rule.id>)'
    )
    assert done["result"]["rule"]["id"] == new["id"]
    assert done["undo"] == {
        "tool": "fmc_delete_access_rule",
        "args": {"policy": ACP_ID, "rule": new["id"]},
        "back_out": f'fmc_delete_access_rule(policy="{ACP_ID}", rule="{new["id"]}")',
    }


async def test_update_access_rule_backs_out_with_the_values_read(lab: respx.MockRouter) -> None:
    rule = next(r for r in fixture("accessrules")["items"] if r["name"] == "mcp-test-ssh-admin")
    lab.put(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules/{rule['id']}").mock(
        return_value=httpx.Response(200, json=rule)
    )
    _, done = await preview_apply(
        "fmc_update_access_rule",
        {"policy": "mcp-test-acp", "rule": "mcp-test-ssh-admin", "enabled": False, "destination_ports": []},
    )
    args = done["undo"]["args"]
    assert done["undo"]["tool"] == "fmc_update_access_rule"
    assert args["policy"] == ACP_ID and args["rule"] == rule["id"] and args["enabled"] is True
    assert args["destination_ports"] == block_refs(rule.get("destinationPorts")) != []


def test_update_access_rule_url_categories_are_by_hand() -> None:
    rule = next(r for r in fixture("accessrules")["items"] if r["name"] == "mcp-test-ssh-admin")
    policy = {"id": ACP_ID, "name": "mcp-test-acp"}
    out = access_rule_undo(policy, rule, {"url_categories": [], "enabled": False}, None)
    assert isinstance(out, str) and out.startswith("by hand:") and "url_categories" in out
    undo = access_rule_undo(policy, rule, {"enabled": False, "new_name": "x", "log": "none"}, None)
    assert not isinstance(undo, str)
    assert undo.args == {
        "policy": ACP_ID,
        "rule": rule["id"],
        "new_name": "mcp-test-ssh-admin",
        "enabled": rule["enabled"],
        "log": _log_mode(rule),
    }


async def test_delete_access_rule_is_not_reversible_with_the_old_rule(lab: respx.MockRouter) -> None:
    rule = next(r for r in fixture("accessrules")["items"] if r["name"] == "mcp-test-ssh-admin")
    lab.delete(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules/{rule['id']}").mock(
        return_value=httpx.Response(200, json=rule)
    )
    preview, done = await preview_apply(
        "fmc_delete_access_rule", {"policy": "mcp-test-acp", "rule": rule["name"]}
    )
    assert preview["undo"].startswith("back-out: not reversible: FMC can't restore a deleted access rule")
    assert "fmc_create_access_rule" in preview["undo"] and "mcp-test-ssh-admin" in preview["undo"]
    assert done["undo"]["back_out"].startswith("not reversible:") and "tool" not in done["undo"]


# --- NAT rules -------------------------------------------------------------------------------------


async def test_create_nat_rule_backs_out_with_delete(lab: respx.MockRouter) -> None:
    addrs = fixture("networkaddresses")["items"]
    web = next(i for i in addrs if i["name"] == "mcp-test-web")
    db = next(i for i in addrs if i["name"] == "mcp-test-db")
    lab.get(f"{CFG}/object/hosts").mock(side_effect=lambda req: items([web, db]))
    lab.post(f"{CFG}/policy/ftdnatpolicies/{NAT_ID}/autonatrules").mock(
        return_value=httpx.Response(
            201, json={"id": "0050568a-0c0b-0ed3-0000-021474899002", "type": "FTDAutoNatRule"}
        )
    )
    preview, done = await preview_apply(
        "fmc_create_nat_rule",
        {
            "policy": "mcp-test-nat",
            "kind": "auto",
            "original_source": "mcp-test-web",
            "translated_source": "mcp-test-db",
        },
    )
    assert (
        preview["undo"] == f'back-out: fmc_delete_nat_rule(policy="{NAT_ID}", rule_id=<from the result: id>)'
    )
    assert done["undo"]["args"] == {"policy": NAT_ID, "rule_id": "0050568a-0c0b-0ed3-0000-021474899002"}


async def test_update_nat_rule_backs_out_with_the_old_state(lab: respx.MockRouter) -> None:
    rule = fixture("natrules")["items"][0]  # the manual rule, enabled, 'mcp live tests'
    path = f"{CFG}/policy/ftdnatpolicies/{NAT_ID}/manualnatrules/{rule['id']}"
    lab.get(path).mock(return_value=httpx.Response(200, json=rule))
    lab.put(path).mock(return_value=httpx.Response(200, json=rule))
    _, done = await preview_apply(
        "fmc_update_nat_rule",
        {"policy": "mcp-test-nat", "rule_id": rule["id"], "enabled": False, "description": "off"},
    )
    assert done["undo"]["args"] == {
        "policy": NAT_ID,
        "rule_id": rule["id"],
        "enabled": True,
        "description": "mcp live tests",
    }


async def test_delete_nat_rule_is_not_reversible(lab: respx.MockRouter) -> None:
    rule = fixture("natrules")["items"][0]
    path = f"{CFG}/policy/ftdnatpolicies/{NAT_ID}/manualnatrules/{rule['id']}"
    lab.get(path).mock(return_value=httpx.Response(200, json=rule))
    lab.delete(path).mock(return_value=httpx.Response(200, json=rule))
    out = await preview_apply("fmc_delete_nat_rule", {"policy": "mcp-test-nat", "rule_id": rule["id"]})
    assert out[0]["undo"].startswith("back-out: not reversible:") and "fmc_create_nat_rule" in out[0]["undo"]


# --- static routes, interfaces ---------------------------------------------------------------------


async def test_create_static_route_backs_out_with_delete(ftd: respx.MockRouter) -> None:  # noqa: F811
    network_mocks(ftd)
    routes(ftd)
    ftd.post(f"{DEVPATH}/routing/ipv4staticroutes").mock(
        return_value=httpx.Response(201, json={"id": "0050568a-0c0b-0ed3-0000-021474899003"})
    )
    preview, done = await confirm(
        "fmc_create_static_route",
        {"device": "mcp-ftd1", "interface": "outside", "networks": ["0.0.0.0/0"], "gateway": "192.0.2.1"},
    )
    assert preview["undo"] == (
        f'back-out: fmc_delete_static_route(device="{DEV_ID}", route_id=<from the result: id>)'
    )
    assert done["undo"]["args"] == {"device": DEV_ID, "route_id": "0050568a-0c0b-0ed3-0000-021474899003"}


async def test_delete_static_route_backs_out_with_create(ftd: respx.MockRouter) -> None:  # noqa: F811
    tracked = {
        **copy.deepcopy(ROUTE),
        "routeTracking": {"id": MON["id"], "type": "SLAMonitor", "name": MON["name"]},
    }
    ftd.get(f"{DEVPATH}/routing/ipv4staticroutes/{tracked['id']}").mock(
        return_value=httpx.Response(200, json=tracked)
    )
    routes(ftd, tracked, {**tracked, "id": "0050568a-0c0b-0ed3-0000-021474899004"})
    monitors(ftd, MON)
    monitor_by_id(ftd, MON)
    out = await preview_of("fmc_delete_static_route", {"device": "mcp-ftd1", "route_id": tracked["id"]})
    assert out["status"] == "preview", out
    assert out["undo"].startswith("back-out: fmc_create_static_route(")
    for part in (f'device="{DEV_ID}"', f'interface="{ROUTE["interfaceName"]}"', f'track="{MON["id"]}"'):
        assert part in out["undo"]
    assert json.dumps([n["id"] for n in ROUTE["selectedNetworks"]]) in out["undo"]


async def test_update_interface_backs_out_with_the_old_settings(ftd: respx.MockRouter) -> None:  # noqa: F811
    ftd.put(f"{DEVPATH}/physicalinterfaces/{INSIDE['id']}").mock(
        return_value=httpx.Response(200, json=INSIDE)
    )
    _, done = await confirm(
        "fmc_update_interface",
        {
            "device": "mcp-ftd1",
            "interface": "inside",
            "security_zone": "mcp-test-ftd-dmz",
            "ipv4": "10.99.2.1/24",
        },
    )
    assert done["undo"]["tool"] == "fmc_update_interface"
    assert done["undo"]["args"] == {
        "device": DEV_ID,
        "interface": INSIDE["id"],
        "security_zone": ZONES[0]["id"],
        "ipv4": "10.99.1.1/24",
    }


async def test_create_subinterface_backs_out_with_delete_interface(ftd: respx.MockRouter) -> None:  # noqa: F811
    ftd.post(f"{DEVPATH}/subinterfaces").mock(
        return_value=httpx.Response(201, json={"id": "0050568a-0c0b-0ed3-0000-021474899005"})
    )
    preview, done = await confirm(
        "fmc_create_subinterface",
        {"device": "mcp-ftd1", "parent": "Ethernet0/1", "vlan_id": 100, "logical_name": "dmz"},
    )
    assert (
        preview["undo"]
        == f'back-out: fmc_delete_interface(device="{DEV_ID}", interface=<from the result: id>)'
    )
    assert done["undo"]["args"] == {"device": DEV_ID, "interface": "0050568a-0c0b-0ed3-0000-021474899005"}


async def test_create_loopback_backs_out_with_delete_interface(fmc: respx.MockRouter) -> None:
    ti.mock_device(fmc, ti.recorded())
    created = ti.REC["created"]["loopbackinterfaces"]
    fmc.post(f"{ti.DEVPATH}/loopbackinterfaces").mock(return_value=httpx.Response(201, json=created))
    preview, done = await ti.confirm(
        "fmc_create_interface",
        {"device": "mcp-ftd1", "kind": "loopback", "logical_name": "bgp-lo", "ipv4": "198.51.100.1/32"},
    )
    assert preview["undo"].startswith("back-out: fmc_delete_interface(")
    assert done["undo"]["args"] == {"device": ti.DEV["id"], "interface": created["id"]}


async def test_delete_interface_is_not_reversible(ftd: respx.MockRouter) -> None:  # noqa: F811
    sub = {"type": "SubInterface", "name": "Ethernet0/3", "subIntfId": 3999, "vlanId": 3999, "id": "sub-3999"}
    ftd.get(f"{DEVPATH}/subinterfaces").mock(return_value=items([sub]))
    out = await preview_of("fmc_delete_interface", {"device": "mcp-ftd1", "interface": "Ethernet0/3.3999"})
    assert out["undo"].startswith("back-out: not reversible:") and "fmc_create_subinterface" in out["undo"]


# --- SLA monitors, health policies -----------------------------------------------------------------


async def test_create_sla_monitor_backs_out_with_delete(ftd: respx.MockRouter) -> None:  # noqa: F811
    monitors(ftd, MON)
    ftd.post(f"{CFG}/object/slamonitors").mock(
        return_value=httpx.Response(201, json={"id": "0050568a-0c0b-0ed3-0000-021474899006"})
    )
    args = {"name": "mcp-sla-isp2", "monitor_address": "198.51.100.1", "interfaces": [OUT_ZONE["name"]]}
    preview, done = await confirm("fmc_create_sla_monitor", args)
    assert preview["undo"] == "back-out: fmc_delete_sla_monitor(monitor=<from the result: id>)"
    assert done["undo"]["args"] == {"monitor": "0050568a-0c0b-0ed3-0000-021474899006"}


async def test_update_sla_monitor_backs_out_with_the_old_values(ftd: respx.MockRouter) -> None:  # noqa: F811
    current = {**MON, "description": "ISP-1"}
    monitors(ftd, current)
    monitor_by_id(ftd, current)
    routes(ftd)
    ftd.put(f"{CFG}/object/slamonitors/{MON['id']}").mock(return_value=httpx.Response(200, json=MON))
    _, done = await confirm(
        "fmc_update_sla_monitor",
        {"monitor": "mcp-sla-isp1", "monitor_address": "203.0.113.99", "frequency": 10, "description": ""},
    )
    assert done["undo"]["args"] == {
        "monitor": MON["id"],
        "monitor_address": "192.0.2.10",
        "frequency": 60,
        "description": "ISP-1",
    }


async def test_delete_sla_monitor_backs_out_with_create(ftd: respx.MockRouter) -> None:  # noqa: F811
    monitors(ftd, MON)
    routes(ftd)
    out = await preview_of("fmc_delete_sla_monitor", {"monitor": "mcp-sla-isp1"})
    assert out["undo"].startswith("back-out: fmc_create_sla_monitor(")
    assert '"sla_id": 1' not in out["undo"] and "sla_id=1" in out["undo"]
    assert f'interfaces=["{OUT_ZONE["id"]}"]' in out["undo"]


async def test_update_health_policy_backs_out_with_the_old_threshold(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/healthpolicies").mock(return_value=items([HP]))
    fmc.get(f"{CFG}/policy/healthpolicies/{HP_ID}").mock(return_value=httpx.Response(200, json=HP))
    fmc.put(f"{CFG}/policy/healthpolicies/{HP_ID}").mock(return_value=httpx.Response(200, json=HP))
    args = {"policy": "Initial_Health_Policy", "module": "hm_cpu", "warning": 70}
    _, done = await preview_apply("fmc_update_health_policy", args)
    assert done["undo"]["args"] == {"policy": HP_ID, "module": "hm_cpu", "warning": 80}

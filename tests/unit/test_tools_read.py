import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError
from stutters_mcp_core.testing import call_tool

from fmc_mcp.server import create_server

from .conftest import ACP_ID, CFG, empty, fixture, items, make_settings


async def call(name: str, args: dict[str, Any] | None = None) -> Any:
    return await call_tool(create_server(make_settings()), name, args or {})


async def test_list_access_rules_flattens_names(lab: respx.MockRouter) -> None:
    data = await call("fmc_list_access_rules", {"policy": "mcp-test-acp", "response_format": "json"})
    rows = {r["name"]: r for r in data["results"]}
    assert rows["mcp-test-ssh-admin"]["src_zones"] == ["mcp-test-inside"]
    assert rows["mcp-test-ssh-admin"]["dst_ports"] == ["TCP/22"]
    assert rows["mcp-test-allow-web"]["dst_networks"] == ["mcp-test-servers"]
    assert rows["mcp-test-url-rule"]["urls"] == ["mcp-test-url"]
    assert [r["index"] for r in data["results"]] == list(range(1, 8))


async def test_list_access_rules_filters(lab: respx.MockRouter) -> None:
    data = await call(
        "fmc_list_access_rules", {"policy": "mcp-test-acp", "action": "block", "response_format": "json"}
    )
    assert [r["name"] for r in data["results"]] == ["mcp-test-block-app"]
    data = await call(
        "fmc_list_access_rules", {"policy": "mcp-test-acp", "enabled": False, "response_format": "json"}
    )
    assert [r["name"] for r in data["results"]] == ["mcp-test-disabled"]
    data = await call(
        "fmc_list_access_rules", {"policy": "mcp-test-acp", "text": "mcp-test-db", "response_format": "json"}
    )
    assert {r["name"] for r in data["results"]} == {"mcp-test-ssh-admin", "mcp-test-shadowed"}


async def test_unknown_policy_suggests(lab: respx.MockRouter) -> None:
    with pytest.raises(ToolError, match="Did you mean: mcp-test-acp"):
        await call("fmc_list_access_rules", {"policy": "mcp-test-acpp"})


async def test_get_access_policy_summary(lab: respx.MockRouter) -> None:
    data = await call("fmc_get_access_policy", {"policy": "mcp-test-acp", "include_rules": True})
    assert data["default_action"] == "BLOCK"
    assert data["rules"]["total"] == 7 and data["rules"]["enabled"] == 6
    assert data["rules"]["by_action"] == {"ALLOW": 6, "BLOCK": 1}
    assert len(data["rule_list"]) == 7


async def test_get_access_rule_by_index(lab: respx.MockRouter) -> None:
    data = await call("fmc_get_access_rule", {"policy": ACP_ID, "rule": "4"})
    assert data["summary"]["name"] == "mcp-test-block-app"
    assert "links" not in json.dumps(data)


async def test_nat_rules_ordered(lab: respx.MockRouter) -> None:
    data = await call("fmc_list_nat_rules", {"policy": "mcp-test-nat", "response_format": "json"})
    rows = data["results"]
    assert [r["section"] for r in rows] == ["BEFORE_AUTO", "AUTO"]
    assert rows[1]["kind"] == "auto" and rows[1]["original_source"] == "mcp-test-web"


async def test_rule_lookup_definite_match(lab: respx.MockRouter) -> None:
    data = await call(
        "fmc_rule_lookup",
        {"policy": "mcp-test-acp", "source": "192.0.2.1", "destination": "10.10.10.80", "port": 443},
    )
    assert data["matched_rule"]["name"] == "mcp-test-allow-web"
    assert "may_match_first" not in data


async def test_rule_lookup_zone_unknown_is_conditional(lab: respx.MockRouter) -> None:
    data = await call(
        "fmc_rule_lookup",
        {"policy": "mcp-test-acp", "source": "10.1.1.1", "destination": "10.10.20.5", "port": 22},
    )
    assert data["matched_rule"]["name"] == "mcp-test-block-app"
    assert data["may_match_first"][0]["name"] == "mcp-test-ssh-admin"
    assert data["may_match_first"][0]["depends_on"] == ["source_zone"]
    data = await call(
        "fmc_rule_lookup",
        {
            "policy": "mcp-test-acp",
            "source": "10.1.1.1",
            "destination": "10.10.20.5",
            "port": 22,
            "source_zone": "mcp-test-inside",
        },
    )
    assert data["matched_rule"]["name"] == "mcp-test-ssh-admin"


async def test_rule_lookup_default_action(lab: respx.MockRouter) -> None:
    data = await call(
        "fmc_rule_lookup",
        {
            "policy": "mcp-test-acp",
            "source": "1.1.1.1",
            "destination": "8.8.8.8",
            "port": 53,
            "protocol": "udp",
        },
    )
    assert data["default_action"] == "BLOCK"
    assert [r["name"] for r in data["may_match_first"]] == ["mcp-test-url-rule"]


async def test_rule_lookup_wrong_protocol_does_not_match_port_rule(lab: respx.MockRouter) -> None:
    data = await call(
        "fmc_rule_lookup",
        {"policy": "mcp-test-acp", "source": "1.1.1.1", "destination": "10.10.10.80", "protocol": "udp"},
    )
    # rule 1 only allows TCP ports, so a UDP flow to the web host falls through to the default
    assert "matched_rule" not in data


async def test_rule_lookup_bad_ip(lab: respx.MockRouter) -> None:
    with pytest.raises(ToolError, match="single IP address"):
        await call(
            "fmc_rule_lookup", {"policy": "mcp-test-acp", "source": "10.0.0.0/8", "destination": "1.1.1.1"}
        )


async def test_shadowed_rules(lab: respx.MockRouter) -> None:
    data = await call("fmc_shadowed_rules", {"policy": "mcp-test-acp"})
    found = {f["rule"]["name"]: (f["covered_by"]["name"], f["kind"]) for f in data["findings"]}
    assert found == {
        "mcp-test-redundant": ("mcp-test-allow-web", "redundant"),
        "mcp-test-shadowed": ("mcp-test-block-app", "shadowed"),
    }


async def test_find_object_by_port(lab: respx.MockRouter) -> None:
    data = await call("fmc_find_object", {"value": "tcp/8443", "response_format": "json"})
    names = {r["name"] for r in data["results"]}
    assert {"mcp-test-tcp-8443", "mcp-test-web-ports", "TCP_high_ports"} <= names
    data = await call("fmc_find_object", {"value": "udp/5050", "response_format": "json"})
    assert [r["name"] for r in data["results"]] == ["mcp-test-udp-5000s"]


async def test_find_object_by_ip_uses_fmc_search(lab: respx.MockRouter) -> None:
    route = lab.get(f"{CFG}/search/object").mock(return_value=httpx.Response(200, json=fixture("search_ip")))
    data = await call("fmc_find_object", {"value": "10.10.20.5", "response_format": "json"})
    assert route.calls.last.request.url.params["filter"] == "text:10.10.20.5"
    assert "mcp-test-db" in {r["name"] for r in data["results"]}


async def test_where_used_drills_into_rules(lab: respx.MockRouter) -> None:
    db = next(i for i in fixture("networkaddresses")["items"] if i["name"] == "mcp-test-db")
    lab.get(f"{CFG}/object/hosts").mock(return_value=items([db]))
    lab.get(f"{CFG}/object/operational/usage").mock(
        return_value=httpx.Response(200, json=fixture("usage_db"))
    )
    data = await call("fmc_where_used", {"object": "mcp-test-db", "type": "host"})
    assert data["in_use"] is True
    assert {(r["policy"], r.get("name")) for r in data["rules"]} == {
        ("mcp-test-acp", "mcp-test-ssh-admin"),
        ("mcp-test-acp", "mcp-test-shadowed"),
        ("mcp-test-nat", None),
    }


async def test_list_objects_hides_system(lab: respx.MockRouter) -> None:
    data = await call(
        "fmc_list_objects", {"type": "network_group", "include_system": False, "response_format": "json"}
    )
    assert [r["name"] for r in data["results"]] == ["mcp-test-servers"]
    assert data["results"][0]["members"] == ["mcp-test-web", "mcp-test-app-net", "10.10.40.0/24"]


async def test_unused_objects(fmc: respx.MockRouter) -> None:
    lab = fmc
    unused = next(i for i in fixture("networkaddresses")["items"] if i["name"] == "mcp-test-unused")
    sys_obj = next(i for i in fixture("networkaddresses")["items"] if i["name"] == "any-ipv6")
    route = lab.get(f"{CFG}/object/hosts").mock(return_value=items([unused, sys_obj]))
    for path in (
        "networks",
        "ranges",
        "fqdns",
        "networkgroups",
        "protocolportobjects",
        "portobjectgroups",
        "urls",
        "urlgroups",
    ):
        lab.get(f"{CFG}/object/{path}", params={"filter": "unusedOnly:true"}).mock(return_value=empty())
    data = await call("fmc_unused_objects", {"response_format": "json"})
    assert [r["name"] for r in data["results"]] == ["mcp-test-unused"]
    assert route.calls.last.request.url.params["filter"] == "unusedOnly:true"


async def test_empty_device_lists(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=empty())
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=empty())
    for tool in ("fmc_list_devices", "fmc_list_ha_pairs", "fmc_list_deployable_devices"):
        data = await call(tool, {"response_format": "json"})
        assert data["results"] == [] and data["returned"] == 0


async def test_device_rows(fmc: respx.MockRouter) -> None:
    dev = {
        "id": "d1",
        "name": "ftd1",
        "hostName": "10.0.0.1",
        "model": "FTDv",
        "sw_version": "10.0.1",
        "healthStatus": "green",
        "accessPolicy": {"name": "mcp-test-acp", "id": ACP_ID, "type": "AccessPolicy"},
        "regKey": "secret-key",
    }
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([dev]))
    data = await call("fmc_list_devices", {"response_format": "json"})
    assert data["results"][0]["access_policy"] == "mcp-test-acp"
    assert "secret-key" not in json.dumps(data)


async def test_audit_records_filtering(fmc: respx.MockRouter) -> None:
    recs = [
        {"time": 1791980000, "username": "admin", "subSystem": "Login", "message": "Login Success"},
        {"time": 1791980001, "username": "bob", "subSystem": "API", "message": "POST ... Created"},
    ]
    route = fmc.get(f"/api/fmc_platform/v1/domain/{CFG.split('/')[-1]}/audit/auditrecords").mock(
        return_value=items(recs)
    )
    data = await call("fmc_list_audit_records", {"user": "bob", "response_format": "json"})
    assert [r["user"] for r in data["results"]] == ["bob"]
    assert data["results"][0]["time"].startswith("2026-")
    assert "endtime" not in route.calls.last.request.url.params


async def test_deployment_history_rows(fmc: respx.MockRouter) -> None:
    job = {
        "id": "j1",
        "jobName": "Deploy_Job_6",
        "jobStatus": "Deployed",
        "jobType": "DEPLOYMENT",
        "startTime": "2020-05-16T10:29:01Z",
        "user": "admin",
        "deviceList": [{"deviceName": "ftd1", "deploymentStatus": "SUCCEEDED"}],
    }
    fmc.get(f"{CFG}/deployment/jobhistories").mock(return_value=items([job]))
    data = await call("fmc_list_deployments", {"response_format": "json"})
    row = data["results"][0]
    assert row["devices"] == ["ftd1: SUCCEEDED"] and row["started"] == "2020-05-16T10:29:01Z"


async def test_get_device_masks_reg_key(fmc: respx.MockRouter) -> None:
    dev = {"id": "d1", "name": "ftd1", "model": "FTDv", "regKey": "secret-key", "natID": "nat-secret"}
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([dev]))
    data = await call("fmc_get_device", {"device": "ftd1"})
    text = json.dumps(data)
    assert "secret-key" not in text and "nat-secret" not in text and data["name"] == "ftd1"


async def test_monitor_rule_does_not_stop_lookup(fmc: respx.MockRouter) -> None:
    acp = {"id": ACP_ID, "name": "p", "type": "AccessPolicy", "defaultAction": {"action": "BLOCK"}}
    rules = [
        {"id": "r1", "name": "watch", "action": "MONITOR", "enabled": True, "metadata": {"ruleIndex": 1}},
        {
            "id": "r2",
            "name": "icmp-echo-code",
            "action": "ALLOW",
            "enabled": True,
            "metadata": {"ruleIndex": 2},
            "destinationPorts": {"objects": [{"id": "ic1", "type": "ICMPV4Object"}]},
        },
        {"id": "r3", "name": "any", "action": "TRUST", "enabled": True, "metadata": {"ruleIndex": 3}},
    ]
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([acp]))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(return_value=items(rules))
    for name in (
        "networkaddresses",
        "ranges",
        "networkgroups",
        "protocolportobjects",
        "portobjectgroups",
        "icmpv6objects",
    ):
        fmc.get(f"{CFG}/object/{name}").mock(return_value=empty())
    fmc.get(f"{CFG}/object/icmpv4objects").mock(
        return_value=items(
            [{"id": "ic1", "type": "ICMPV4Object", "name": "echo", "icmpType": "8", "code": 0}]
        )
    )
    data = await call(
        "fmc_rule_lookup",
        {"policy": "p", "source": "1.1.1.1", "destination": "2.2.2.2", "protocol": "icmp", "port": 8},
    )
    assert [r["name"] for r in data["monitor_rules_logged"]] == ["watch"]
    assert data["may_match_first"][0]["name"] == "icmp-echo-code"
    assert data["matched_rule"]["name"] == "any"
    shadow = await call("fmc_shadowed_rules", {"policy": "p"})
    assert all(f["covered_by"]["name"] != "watch" for f in shadow["findings"])

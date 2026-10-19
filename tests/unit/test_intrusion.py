"""F13 intrusion tuning tools (shapes recorded from FMC 10.0.1, Snort 3)."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools.intrusion import rule_filter

from .conftest import CFG, items, make_settings

GLOBAL = {"name": "Global", "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f", "type": "Domain"}
IPS = {
    "id": "00000000-0000-0ed3-0000-021474918104",
    "name": "mcp-test-ips",
    "type": "intrusionpolicy",
    "basePolicy": {"name": "Balanced Security and Connectivity", "id": "6c66b83c", "type": "intrusionpolicy"},
    "inspectionMode": "PREVENTION",
    "isSystemDefined": False,
    "metadata": {"domain": GLOBAL, "usage": {"accesspolicy": 1, "devices": 1}},
}
BALANCED = {
    "id": "6c66b83c-bc23-55b6-879d-c4d847443503",
    "name": "Balanced Security and Connectivity",
    "type": "intrusionpolicy",
    "isSystemDefined": True,
    "metadata": {"domain": GLOBAL},
}
RULE = {
    "type": "IntrusionRule",
    "id": "00000000-0000-0ed3-0000-021474918175",
    "name": "2000:1000001",
    "gid": 2000,
    "sid": 1000001,
    "revision": 1,
    "isSystemDefined": False,
    "msg": "mcp-test icmp echo",
    "ruleData": (
        'alert icmp any any -> any any ( msg:"mcp-test icmp echo"; itype:8; sid:1000001; gid:2000; rev:1; )'
    ),
    "metadata": {"domain": GLOBAL},
    "defaultState": "DISABLE",
    "ruleGroups": [{"name": "mcp-test-rules", "id": "g1", "type": "IntrusionRuleGroup"}],
}
RULES = f"{CFG}/policy/intrusionpolicies/{IPS['id']}/intrusionrules"


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def test_rule_filter() -> None:
    assert rule_filter("1:28496") == "gid:1;sid:28496"
    assert rule_filter(" 2000 : 1000001 ") == "gid:2000;sid:1000001"
    assert rule_filter("28496") == "sid:28496"
    assert rule_filter("Log4j") is None


async def test_policy_summary_lists_overrides(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/intrusionpolicies").mock(return_value=items([IPS, BALANCED]))
    route = fmc.get(RULES).mock(return_value=items([{**RULE, "overrideState": "DROP"}]))
    async with Client(server()) as c:
        out = await run(c, "fmc_get_intrusion_policy", {"policy": "mcp-test-ips", "response_format": "json"})
    assert route.calls.last.request.url.params["filter"] == f"overrides:true;ipspolicy:{IPS['id']}"
    assert out["base_policy"] == "Balanced Security and Connectivity"
    assert out["overridden_rules"][0]["rule"] == "2000:1000001"
    assert out["overridden_rules"][0]["override_state"] == "DROP"


async def test_find_by_text_uses_full_text_search(fmc: respx.MockRouter) -> None:
    route = fmc.get(f"{CFG}/object/intrusionrules").mock(return_value=items([RULE], total=7))
    async with Client(server()) as c:
        out = await run(c, "fmc_find_intrusion_rules", {"query": "icmp echo", "response_format": "json"})
    assert route.calls.last.request.url.params["filter"] == "fts:icmp echo"
    assert out["results"][0]["rule"] == "2000:1000001" and "rule_text" in out["results"][0]


async def test_set_state_drop_then_default(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/intrusionpolicies").mock(return_value=items([IPS]))
    fmc.get(RULES).mock(return_value=items([RULE]))
    one = fmc.get(f"{RULES}/{RULE['id']}").mock(return_value=httpx.Response(200, json=RULE))
    put = fmc.put(f"{RULES}/{RULE['id']}").mock(
        side_effect=lambda req: httpx.Response(200, json=json.loads(req.content))
    )
    async with Client(server()) as c:
        args = {"policy": "mcp-test-ips", "rules": ["2000:1000001"], "state": "DROP"}
        preview = await run(c, "fmc_set_intrusion_rule_state", args)
        assert preview["status"] == "preview", preview
        assert preview["preview"]["rules"][0]["to"] == "DROP" and preview["preview"]["domain"] == "Global"
        done = await run(c, "fmc_set_intrusion_rule_state", {**args, "confirm": preview["confirm"]})
        body = json.loads(put.calls.last.request.content)
        assert body["overrideState"] == "DROP" and body["ruleData"] == RULE["ruleData"]
        assert done["result"]["rules"][0]["override_state"] == "DROP"
        # DEFAULT removes the override (FMC: omit overrideState in the full-object PUT)
        fmc.get(RULES).mock(return_value=items([{**RULE, "overrideState": "DROP"}]))
        one.mock(return_value=httpx.Response(200, json={**RULE, "overrideState": "DROP"}))
        args = {**args, "state": "DEFAULT"}
        preview = await run(c, "fmc_set_intrusion_rule_state", args)
        assert preview["preview"]["rules"][0]["to"] == "default (DISABLE)"
        await run(c, "fmc_set_intrusion_rule_state", {**args, "confirm": preview["confirm"]})
        assert "overrideState" not in json.loads(put.calls.last.request.content)


# Talos 1:498 in a custom policy on Balanced (FMC 10.0.1, live run 2026-10-18; domain/policy ids scrubbed).
# The policy's rule list says defaultState DISABLE (what Balanced sets); GET and PUT of the single rule say
# ALERT (the rule's `alert` keyword). metadata.defaultSetBy carries DISABLE in both.
T498_SET_BY = [
    {"name": BALANCED["name"], "id": BALANCED["id"], "type": "IntrusionPolicy", "action": "DISABLE"}
]
T498 = {
    "type": "IntrusionRule",
    "id": "071203ae-609f-59e8-b4fc-e6e02395fb7b",
    "name": "1:498",
    "gid": 1,
    "sid": 498,
    "revision": 11,
    "isSystemDefined": True,
    "msg": "INDICATOR-COMPROMISE id check returned root",
    "ruleData": (
        'alert ip any any -> any any ( msg:"INDICATOR-COMPROMISE id check returned root"; '
        'content:"uid=0|28|root|29|"; metadata:ruleset community; classtype:bad-unknown; sid:498; rev:11; )'
    ),
    "metadata": {"domain": GLOBAL, "defaultSetBy": T498_SET_BY},
    "defaultState": "DISABLE",
    "ruleGroups": [
        {"name": "Application Layer Protocol", "id": "d169ad20", "type": "IntrusionRuleGroup"},
        {"name": "Compromise", "id": "d0ae8e7a", "type": "IntrusionRuleGroup"},
    ],
}
T498_ONE = {**T498, "defaultState": "ALERT"}  # GET .../intrusionrules/{id}


async def test_set_state_reports_the_policy_default_not_the_rule_keyword(fmc: respx.MockRouter) -> None:
    """Live finding: the preview said default DISABLE, the result default_state ALERT (same rule)."""
    fmc.get(f"{CFG}/policy/intrusionpolicies").mock(return_value=items([IPS]))
    fmc.get(RULES).mock(return_value=items([T498]))
    fmc.get(f"{RULES}/{T498['id']}").mock(return_value=httpx.Response(200, json=T498_ONE))
    put = fmc.put(f"{RULES}/{T498['id']}").mock(
        return_value=httpx.Response(200, json={**T498_ONE, "overrideState": "BLOCK"})
    )
    async with Client(server()) as c:
        args = {"policy": "mcp-test-ips", "rules": ["1:498"], "state": "BLOCK"}
        preview = await run(c, "fmc_set_intrusion_rule_state", args)
        row = preview["preview"]["rules"][0]
        assert (row["default_state"], row["to"]) == ("DISABLE", "BLOCK")
        done = await run(c, "fmc_set_intrusion_rule_state", {**args, "confirm": preview["confirm"]})
        assert done["result"]["rules"][0]["default_state"] == "DISABLE"
        assert done["result"]["rules"][0]["override_state"] == "BLOCK"
        assert json.loads(put.calls.last.request.content)["overrideState"] == "BLOCK"
        # a single-rule answer without metadata (echoed body): the list read's default still wins
        put.mock(side_effect=lambda req: httpx.Response(200, json=json.loads(req.content)))
        fmc.get(RULES).mock(return_value=items([{**T498, "overrideState": "BLOCK"}]))
        args = {**args, "state": "DEFAULT"}
        preview = await run(c, "fmc_set_intrusion_rule_state", args)
        assert preview["preview"]["rules"][0]["to"] == "default (DISABLE)"
        done = await run(c, "fmc_set_intrusion_rule_state", {**args, "confirm": preview["confirm"]})
        assert done["result"]["rules"][0]["default_state"] == "DISABLE"
        assert "override_state" not in done["result"]["rules"][0]


async def test_find_and_summary_use_default_set_by(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/intrusionpolicies").mock(return_value=items([IPS]))
    fmc.get(RULES).mock(return_value=items([{**T498_ONE, "overrideState": "BLOCK"}]))
    async with Client(server()) as c:
        found = await run(
            c,
            "fmc_find_intrusion_rules",
            {"query": "1:498", "policy": "mcp-test-ips", "response_format": "json"},
        )
        summary = await run(
            c, "fmc_get_intrusion_policy", {"policy": "mcp-test-ips", "response_format": "json"}
        )
    assert found["results"][0]["default_state"] == "DISABLE"
    assert summary["overridden_rules"][0]["default_state"] == "DISABLE"


async def test_system_policy_is_read_only(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/intrusionpolicies").mock(return_value=items([BALANCED]))
    fmc.get(f"{CFG}/policy/intrusionpolicies/{BALANCED['id']}/intrusionrules").mock(
        return_value=items([RULE])
    )
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_set_intrusion_rule_state",
            {"policy": BALANCED["name"], "rules": ["2000:1000001"], "state": "DISABLE"},
        )
    assert out["status"] == "blocked" and "fmc_create_intrusion_policy" in out["blockers"][0]


async def test_create_custom_rule_creates_group(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/intrusionrulegroups").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/intrusionrules").mock(return_value=items([]))
    grp = fmc.post(f"{CFG}/object/intrusionrulegroups").mock(
        return_value=httpx.Response(
            201, json={"id": "g1", "name": "mcp-test-rules", "type": "IntrusionRuleGroup"}
        )
    )
    post = fmc.post(f"{CFG}/object/intrusionrules").mock(return_value=httpx.Response(201, json=RULE))
    args = {"rule_text": RULE["ruleData"], "group": "mcp-test-rules"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_intrusion_rule", args)
        assert preview["status"] == "preview" and preview["preview"]["group_exists"] is False
        done = await run(c, "fmc_create_intrusion_rule", {**args, "confirm": preview["confirm"]})
    assert grp.called and json.loads(post.calls.last.request.content)["ruleGroups"][0]["id"] == "g1"
    assert done["result"]["rule"] == "2000:1000001"


async def test_custom_rule_needs_high_sid() -> None:
    async with Client(server()) as c:
        r = await c.call_tool(
            "fmc_create_intrusion_rule",
            {"rule_text": 'alert ip any any -> any any ( msg:"x"; sid:500; )', "group": "g"},
            raise_on_error=False,
        )
    assert r.is_error and "1000000" in r.content[0].text  # type: ignore[union-attr]


async def test_talos_rule_cannot_be_deleted(fmc: respx.MockRouter) -> None:
    talos = {**RULE, "name": "1:28496", "gid": 1, "sid": 28496, "isSystemDefined": True}
    fmc.get(f"{CFG}/object/intrusionrules").mock(return_value=items([talos]))
    async with Client(server()) as c:
        out = await run(c, "fmc_delete_intrusion_rule", {"rule": "1:28496"})
    assert out["status"] == "blocked" and "Talos" in out["blockers"][0]


async def test_set_device_licenses_keeps_host_and_tier(fmc: respx.MockRouter) -> None:
    dev = {
        "id": "11111111-0000-0000-0000-000000000001",
        "name": "ftd1",
        "type": "Device",
        "hostName": "10.0.0.1",
        "license_caps": ["ESSENTIALS"],
        "performanceTier": "FTDv5",
    }
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([dev]))
    fmc.get(f"{CFG}/devices/devicerecords/{dev['id']}").mock(return_value=httpx.Response(200, json=dev))
    put = fmc.put(f"{CFG}/devices/devicerecords/{dev['id']}").mock(return_value=httpx.Response(200, json=dev))
    async with Client(server()) as c:
        args = {"device": "ftd1", "add": ["IPS"]}
        preview = await run(c, "fmc_set_device_licenses", args)
        assert preview["preview"]["to"] == ["ESSENTIALS", "IPS"]
        await run(c, "fmc_set_device_licenses", {**args, "confirm": preview["confirm"]})
        r = await c.call_tool(
            "fmc_set_device_licenses", {"device": "ftd1", "remove": ["ESSENTIALS"]}, raise_on_error=False
        )
    body = json.loads(put.calls.last.request.content)
    assert body["license_caps"] == ["ESSENTIALS", "IPS"] and body["hostName"] == "10.0.0.1"
    assert body["performanceTier"] == "FTDv5"
    assert r.is_error and "ESSENTIALS" in r.content[0].text  # type: ignore[union-attr]

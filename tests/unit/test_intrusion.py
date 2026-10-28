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
# GET .../intrusionpolicies/{id}?includeCount=true (FMC 10.0.1, live 2026-10-28 on Balanced: snortEngine and
# ruleCount sit in metadata; metadata.mappedPolicy is the Snort 2 twin). No recommendations configured.
RULE_COUNT = {
    "disabled": 43060,
    "alert": 479,
    "block": 9880,
    "rewrite": 0,
    "reject": 0,
    "pass": 0,
    "drop": 0,
    "overridden": 0,
}
IPS_DETAIL = {
    **IPS,
    "inlineDrop": 1,
    "metadata": {
        **IPS["metadata"],
        "mappedPolicy": {"snortEngine": "SNORT2"},
        "snortEngine": "SNORT3",
        "ruleCount": RULE_COUNT,
    },
}


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
    one = fmc.get(f"{CFG}/policy/intrusionpolicies/{IPS['id']}").mock(
        return_value=httpx.Response(200, json=IPS_DETAIL)
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_get_intrusion_policy", {"policy": "mcp-test-ips", "response_format": "json"})
    assert one.calls.last.request.url.params["includeCount"] == "true"
    assert out["snort_engine"] == "SNORT3" and out["rule_counts"]["block"] == 9880
    assert out["recommendations"] == {"configured": False, "in_use": False}
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
    fmc.get(f"{CFG}/policy/intrusionpolicies/{IPS['id']}").mock(return_value=httpx.Response(200, json=IPS))
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


# --- F97 rule recommendations (ruleRecommendation from the FMC spec: IRuleRecommendation) ---------------
ONE = f"{CFG}/policy/intrusionpolicies/{IPS['id']}"
INSIDE = {
    "id": "00000000-0000-0ed3-0000-021474900001",
    "name": "mcp-inside",
    "type": "Network",
    "value": "192.0.2.0/24",
}
REC = {
    "securityLevel": "LEVEL_2",
    "acceptDisabledRules": False,
    "lastUpdatedTime": 1793145600,  # 2026-10-28T00:00:00Z
    "networks": [{"id": INSIDE["id"], "type": "Network", "name": "mcp-inside"}],
    "recommendationInUse": True,
}


def rec_routes(fmc: respx.MockRouter, detail: dict[str, Any]) -> respx.Route:
    """The policy (list + single GET) and a PUT that stores ruleRecommendation like FMC does."""
    state = {"p": detail}
    fmc.get(f"{CFG}/policy/intrusionpolicies").mock(return_value=items([IPS, BALANCED]))
    fmc.get(ONE).mock(side_effect=lambda req: httpx.Response(200, json=state["p"]))

    def put(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        rec = body.get("ruleRecommendation")
        if req.url.params.get("ruleRecommendationAction") == "REMOVE":
            body.pop("ruleRecommendation", None)
        elif rec is not None:
            body["ruleRecommendation"] = {**rec, "lastUpdatedTime": 1793145600}
        state["p"] = {**body, "metadata": detail.get("metadata")}
        return httpx.Response(200, json=state["p"])

    return fmc.put(ONE).mock(side_effect=put)


async def test_get_policy_shows_recommendations(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/intrusionpolicies").mock(return_value=items([IPS]))
    fmc.get(RULES).mock(return_value=items([]))
    fmc.get(ONE).mock(return_value=httpx.Response(200, json={**IPS_DETAIL, "ruleRecommendation": REC}))
    async with Client(server()) as c:
        out = await run(c, "fmc_get_intrusion_policy", {"policy": "mcp-test-ips", "response_format": "json"})
    assert out["recommendations"] == {
        "configured": True,
        "in_use": True,
        "security_level": 2,
        "networks": ["mcp-inside"],
        "accept_disabled_rules": False,
        "last_generated": "2026-10-28T00:00:00Z",
    }


async def test_generate_and_use_sends_rule_recommendation(fmc: respx.MockRouter) -> None:
    put = rec_routes(fmc, IPS_DETAIL)
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([]))
    nets = fmc.get(f"{CFG}/object/networks").mock(return_value=items([INSIDE]))
    async with Client(server()) as c:
        args = {"policy": "mcp-test-ips", "networks": ["mcp-inside"], "security_level": 2}
        preview = await run(c, "fmc_set_intrusion_recommendations", args)
        assert preview["status"] == "preview", preview
        assert nets.calls.last.request.url.params["filter"] == "nameOrValue:mcp-inside"
        pv = preview["preview"]
        assert pv["current"] == {"configured": False, "in_use": False}
        assert pv["new"]["security_level"] == 2 and pv["new"]["networks"] == ["mcp-inside"]
        assert pv["fmc_action"] == "GENERATE_AND_ACCEPT"
        effects = " ".join(preview["side_effects"])
        assert (
            "Policies > Network Discovery" in effects and "drops" not in effects
        )  # level 2: no drop warning
        done = await run(c, "fmc_set_intrusion_recommendations", {**args, "confirm": preview["confirm"]})
    req = put.calls.last.request
    assert req.url.params["ruleRecommendationAction"] == "GENERATE_AND_ACCEPT"
    body = json.loads(req.content)
    assert "metadata" not in body and body["inspectionMode"] == "PREVENTION"
    assert body["ruleRecommendation"] == {
        "securityLevel": "LEVEL_2",
        "networks": [{"id": INSIDE["id"], "type": "Network", "name": "mcp-inside"}],
        "acceptDisabledRules": False,
        "recommendationInUse": True,
    }
    assert done["result"]["recommendations"]["in_use"] is True
    assert done["result"]["recommendations"]["last_generated"] == "2026-10-28T00:00:00Z"


async def test_level_4_warns_about_drops_and_stored_networks_are_reused(fmc: respx.MockRouter) -> None:
    rec_routes(fmc, {**IPS_DETAIL, "ruleRecommendation": REC})
    async with Client(server()) as c:
        args = {"policy": "mcp-test-ips", "action": "generate", "security_level": 4, "accept_disabled": True}
        preview = await run(c, "fmc_set_intrusion_recommendations", args)
    assert preview["status"] == "preview", preview
    assert preview["preview"]["new"]["networks"] == ["mcp-inside"]  # stored networks kept
    assert preview["preview"]["fmc_action"] == "GENERATE"
    effects = " ".join(preview["side_effects"])
    assert "LEVEL_4" in effects and "drop" in effects and "acceptDisabledRules" in effects


async def test_stop_using_then_remove(fmc: respx.MockRouter) -> None:
    put = rec_routes(fmc, {**IPS_DETAIL, "ruleRecommendation": REC})
    async with Client(server()) as c:
        args = {"policy": "mcp-test-ips", "action": "stop_using"}
        preview = await run(c, "fmc_set_intrusion_recommendations", args)
        assert preview["status"] == "preview", preview
        await run(c, "fmc_set_intrusion_recommendations", {**args, "confirm": preview["confirm"]})
        req = put.calls.last.request
        assert "ruleRecommendationAction" not in req.url.params
        sent = json.loads(req.content)["ruleRecommendation"]
        assert sent["recommendationInUse"] is False and "lastUpdatedTime" not in sent
        # stop_using again: nothing to change
        again = await run(c, "fmc_set_intrusion_recommendations", args)
        assert again["status"] == "blocked" and "not in use" in again["blockers"][0]
        args = {"policy": "mcp-test-ips", "action": "remove"}
        preview = await run(c, "fmc_set_intrusion_recommendations", args)
        done = await run(c, "fmc_set_intrusion_recommendations", {**args, "confirm": preview["confirm"]})
    assert put.calls.last.request.url.params["ruleRecommendationAction"] == "REMOVE"
    assert done["result"]["recommendations"] == {"configured": False, "in_use": False}


async def test_recommendations_refused_for_system_snort2_and_unconfigured(fmc: respx.MockRouter) -> None:
    snort2 = {**IPS_DETAIL, "metadata": {**IPS_DETAIL["metadata"], "snortEngine": "SNORT2"}}
    rec_routes(fmc, snort2)
    bal = f"{CFG}/policy/intrusionpolicies/{BALANCED['id']}"
    fmc.get(bal).mock(return_value=httpx.Response(200, json=BALANCED))
    async with Client(server()) as c:
        out = await run(
            c, "fmc_set_intrusion_recommendations", {"policy": BALANCED["name"], "action": "refresh"}
        )
        assert out["status"] == "blocked"
        assert any("system intrusion policy" in b for b in out["blockers"])
        assert any("no rule recommendations" in b for b in out["blockers"])
        out = await run(c, "fmc_set_intrusion_recommendations", {"policy": "mcp-test-ips"})
        assert out["status"] == "blocked"
        assert any("Snort 2" in b for b in out["blockers"])
        assert any("networks=[...]" in b for b in out["blockers"])
        r = await c.call_tool(
            "fmc_set_intrusion_recommendations",
            {"policy": "mcp-test-ips", "action": "use", "security_level": 3},
            raise_on_error=False,
        )
    assert r.is_error and "generate(_and_use)" in r.content[0].text  # type: ignore[union-attr]

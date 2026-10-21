"""#272: inline application filters in fmc_create_access_rule / fmc_update_access_rule.

FMC 10.0.1 doesn't list or GET application filters created over its API (#268), so a rule can carry the
attributes itself: `applications.inlineApplicationFilters`, a list of IAppCondition (the shape of a named
filter's `appConditions` entry). `inline_app_filter={risks, business_relevance, categories, tags, types}`
resolves the names like fmc_create_application_filter and shows the condition as a label
('inline-filter:risk High or Very High') in previews, rule lists and fmc_rule_lookup."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.rule_conditions import app_labels
from fmc_mcp.rules import flatten_access_rule
from fmc_mcp.server import create_server

from .conftest import ACP_ID, CFG, empty, fixture, items, make_settings

FX = fixture("inline_app_filters")
CONDS = fixture("rule_conditions")
RULES = f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules"
RULE = FX["rule_with_inline_filter"]
SSH = {"id": "846", "type": "Application", "name": "SSH"}
HIGH = {"id": "HIGH", "type": "ApplicationRisk", "name": "High"}
VERY_HIGH = {"id": "VERY_HIGH", "type": "ApplicationRisk", "name": "Very High"}
FILE_SHARING = {"id": "90101", "type": "ApplicationCategory", "name": "file sharing"}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def confirm(c: Client[Any], name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    preview = await run(c, name, args)
    assert preview["status"] == "preview", preview
    return preview, await run(c, name, {**args, "confirm": preview["confirm"]})


def body(fx: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json={k: v for k, v in fx.items() if k != "_source"})


def rules_plus(*extra: dict[str, Any]) -> httpx.Response:
    data = fixture("accessrules")
    data["items"] += [copy.deepcopy(r) for r in extra]
    return httpx.Response(200, json=data)


@pytest.fixture
def inline(lab: respx.MockRouter) -> respx.MockRouter:
    lab.get(f"{CFG}/object/applications").mock(return_value=body(CONDS["applications_page"]))
    lab.get(f"{CFG}/object/applicationfilters").mock(return_value=empty())  # FMC 10.0.1: none listed
    lab.get(f"{CFG}/object/applicationcategories").mock(return_value=body(CONDS["applicationcategories"]))
    lab.get(f"{CFG}/object/applicationtags").mock(return_value=body(CONDS["applicationtags"]))
    return lab


def mount_rule(lab: respx.MockRouter, rule: dict[str, Any]) -> respx.Route:
    lab.get(RULES).mock(return_value=rules_plus(rule))
    lab.get(f"{RULES}/{rule['id']}").mock(return_value=httpx.Response(200, json=rule))
    return lab.put(f"{RULES}/{rule['id']}").mock(return_value=httpx.Response(200, json=rule))


def test_labels_read_the_recorded_condition_shape() -> None:
    """FMC's condition carries a `search` text next to the refs; the label is built from the refs."""
    assert app_labels(RULE["applications"]) == ["inline-filter:risk High or Very High"]
    assert flatten_access_rule(RULE)["applications"] == ["inline-filter:risk High or Very High"]
    spec = {"inlineApplicationFilters": [FX["spec_example_inline_filter"]]}
    assert app_labels(spec) == [
        "inline-filter:risk Very Low and business relevance Medium and category collaboration and tag "
        "edonkey and type Client Application"
    ]


async def test_create_sends_one_inline_condition(inline: respx.MockRouter) -> None:
    post = inline.post(RULES).mock(return_value=httpx.Response(201, json={"id": "r-new", "name": "x"}))
    args = {
        "policy": "mcp-test-acp",
        "name": "mcp-w6-inline",
        "action": "ALLOW",
        "enabled": False,
        "inline_app_filter": {"risks": ["high", "Very High"], "categories": ["File Sharing"]},
    }
    async with Client(server()) as c:
        preview, _ = await confirm(c, "fmc_create_access_rule", args)
    label = "inline-filter:risk High or Very High and category file sharing"
    assert preview["preview"]["rule"]["applications"] == [label]
    assert preview["preview"]["inline_app_filter"]["matches"] == (
        "every application with risk High or Very High and category file sharing"
    )
    assert "no filter object" in preview["preview"]["inline_app_filter"]["note"]
    assert any("Snort has identified the application" in s for s in preview["side_effects"])
    sent = json.loads(post.calls.last.request.content)
    assert sent["applications"] == {
        "inlineApplicationFilters": [{"risks": [HIGH, VERY_HIGH], "categories": [FILE_SHARING]}]
    }
    assert sent["enabled"] is False


async def test_create_with_applications_and_an_inline_filter(inline: respx.MockRouter) -> None:
    post = inline.post(RULES).mock(return_value=httpx.Response(201, json={"id": "r-new", "name": "x"}))
    args = {
        "policy": "mcp-test-acp",
        "name": "x",
        "action": "BLOCK",
        "applications": ["SSH"],
        "inline_app_filter": {
            "tags": ["opens port"],
            "types": ["webapp"],
            "business_relevance": ["Very Low"],
        },
    }
    async with Client(server()) as c:
        await confirm(c, "fmc_create_access_rule", args)
    apps = json.loads(post.calls.last.request.content)["applications"]
    assert apps["applications"] == [SSH]
    assert apps["inlineApplicationFilters"] == [
        {
            "productivities": [{"id": "VERY_LOW", "type": "ApplicationProductivity", "name": "Very Low"}],
            "applicationTypes": [{"id": "WEBAPP", "type": "ApplicationType", "name": "Webapp"}],
            "tags": [{"id": "98", "type": "ApplicationTag", "name": "opens port"}],
        }
    ]


async def test_create_refuses_an_empty_or_unknown_filter(inline: respx.MockRouter) -> None:
    base = {"policy": "mcp-test-acp", "name": "x", "action": "ALLOW"}
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="needs at least one attribute"):
            await run(c, "fmc_create_access_rule", {**base, "inline_app_filter": {}})
        with pytest.raises(ToolError, match="Unknown risk 'severe'; choose from Very Low, Low"):
            await run(c, "fmc_create_access_rule", {**base, "inline_app_filter": {"risks": ["severe"]}})
        with pytest.raises(
            ToolError, match="No application category 'file shareing'. Did you mean: file sharing"
        ):
            await run(
                c, "fmc_create_access_rule", {**base, "inline_app_filter": {"categories": ["file shareing"]}}
            )
    assert not any(
        call.request.method == "POST" and "accessrules" in str(call.request.url) for call in inline.calls
    )


async def test_update_replaces_the_inline_filter_and_keeps_applications(inline: respx.MockRouter) -> None:
    rule = copy.deepcopy(RULE)
    rule["applications"]["applications"] = [SSH]
    put = mount_rule(inline, rule)
    args = {"policy": "mcp-test-acp", "rule": rule["name"], "inline_app_filter": {"risks": ["Very High"]}}
    async with Client(server()) as c:
        preview, _ = await confirm(c, "fmc_update_access_rule", args)
    assert preview["preview"]["changes"]["applications"] == {
        "from": ["SSH", "inline-filter:risk High or Very High"],
        "to": ["SSH", "inline-filter:risk Very High"],
    }
    apps = json.loads(put.calls.last.request.content)["applications"]
    assert apps["applications"] == [SSH] and apps["inlineApplicationFilters"] == [{"risks": [VERY_HIGH]}]
    assert apps["applicationDefaultPort"] is False  # the block's other settings stay


async def test_update_with_an_empty_filter_removes_it(inline: respx.MockRouter) -> None:
    rule = copy.deepcopy(RULE)
    put = mount_rule(inline, rule)
    args = {"policy": "mcp-test-acp", "rule": rule["name"], "inline_app_filter": {}}
    async with Client(server()) as c:
        preview, _ = await confirm(c, "fmc_update_access_rule", args)
    assert preview["preview"]["changes"]["applications"] == {
        "from": ["inline-filter:risk High or Very High"],
        "to": "any",
    }
    assert "applications" not in json.loads(put.calls.last.request.content)  # nothing left: any


async def test_update_of_other_conditions_keeps_the_inline_filter(inline: respx.MockRouter) -> None:
    rule = copy.deepcopy(RULE)
    put = mount_rule(inline, rule)
    args = {"policy": "mcp-test-acp", "rule": rule["name"], "applications": ["SSH"]}
    async with Client(server()) as c:
        preview, _ = await confirm(c, "fmc_update_access_rule", args)
    assert preview["preview"]["changes"]["applications"]["to"] == [
        "SSH",
        "inline-filter:risk High or Very High",
    ]
    apps = json.loads(put.calls.last.request.content)["applications"]
    assert apps["inlineApplicationFilters"] == RULE["applications"]["inlineApplicationFilters"]


async def test_same_inline_filter_again_is_nothing_to_change(inline: respx.MockRouter) -> None:
    mount_rule(inline, copy.deepcopy(RULE))
    args = {
        "policy": "mcp-test-acp",
        "rule": RULE["name"],
        "inline_app_filter": {"risks": ["High", "Very High"]},
    }
    async with Client(server()) as c:
        out = await run(c, "fmc_update_access_rule", args)
    assert out["status"] == "blocked" and "Nothing to change." in out["blockers"]


async def test_rule_lookup_shows_the_inline_filter_rule_as_conditional(inline: respx.MockRouter) -> None:
    rule = {**copy.deepcopy(RULE), "enabled": True, "destinationNetworks": {}, "destinationPorts": {}}
    rule["metadata"]["ruleIndex"] = 1
    inline.get(RULES).mock(return_value=items([rule, *fixture("accessrules")["items"]]))
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_rule_lookup",
            {"policy": "mcp-test-acp", "source": "192.0.2.10", "destination": "198.51.100.10", "port": 22},
        )
    first = out["may_match_first"][0]
    assert first["name"] == "mcp-w6-inline-rule"
    assert first["applications"] == ["inline-filter:risk High or Very High"]
    assert "applications" in first["depends_on"]

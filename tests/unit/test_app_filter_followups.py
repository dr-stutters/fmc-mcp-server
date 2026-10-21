"""#273 follow-ups to #268 (application filters FMC 10.0.1 doesn't list), from the Wave 6 final-live run:

- FMC does check a filter id when the rule is saved: a rule naming an unknown id was refused with 400
  "Object for Type ApplicationFilter and UUID ... is not found" (final-live A4). Previews say so instead of
  "confirm with fmc_get_access_rule after saving".
- After a server restart fmc_find_application(kind='filter') found nothing while the rule writers resolved
  the same name from the rules using it: kind='filter' now reads the access policies' rules too."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.rule_conditions import filters_used_by
from fmc_mcp.server import create_server
from fmc_mcp.tools.conditions import FILTER_SCAN_POLICIES

from .conftest import ACP_ID, CFG, fixture, items, make_settings

FX = fixture("app_filters_fmc10")
RULES = f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules"
FILTERS = f"{CFG}/object/applicationfilters"
RULE = FX["rule_with_filter"]  # mcp-w6-appfilter-rule, applicationFilters [mcp-w6-appfilter]
FILTER_ID = RULE["applications"]["applicationFilters"][0]["id"]
UNKNOWN = "6a286913-8fb9-443b-8c58-aee2def5f209"  # final-live A4's random uuid4
REFUSED = {
    "error": {
        "category": "FRAMEWORK",
        "messages": [{"description": f"Object for Type ApplicationFilter and UUID {UNKNOWN} is not found"}],
        "severity": "ERROR",
    }
}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def rules_plus(*extra: dict[str, Any]) -> httpx.Response:
    data = fixture("accessrules")
    data["items"] += [copy.deepcopy(r) for r in extra]
    return httpx.Response(200, json=data)


@pytest.fixture
def fmc10(lab: respx.MockRouter) -> respx.MockRouter:
    lab.get(FILTERS).mock(return_value=httpx.Response(200, json=FX["list_after_create"]))  # FMC lists none
    lab.get(url__regex=rf"{FILTERS}/[0-9a-f-]{{36}}$").mock(return_value=httpx.Response(404, json={}))
    return lab


async def test_preview_says_fmc_checks_the_id_on_save(fmc10: respx.MockRouter) -> None:
    fmc10.post(RULES).mock(return_value=httpx.Response(400, json=REFUSED))
    args = {
        "policy": "mcp-test-acp",
        "name": "mcp-w6-randfilter",
        "action": "ALLOW",
        "enabled": False,
        "application_filters": [UNKNOWN],
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_access_rule", args)
        note = next(e for e in preview["side_effects"] if UNKNOWN in e)
        assert "FMC checks the id when the rule is saved" in note
        assert "is not found" in note and "nothing is saved" in note
        assert "after saving" not in note and "can't be checked beforehand" not in note
        with pytest.raises(
            ToolError, match=f"Object for Type ApplicationFilter and UUID {UNKNOWN} is not found"
        ):
            await run(c, "fmc_create_access_rule", {**args, "confirm": preview["confirm"]})


async def test_an_unknown_name_points_at_the_rules_and_inline_filters(fmc10: respx.MockRouter) -> None:
    async with Client(server()) as c:
        with pytest.raises(ToolError) as e:
            await run(
                c,
                "fmc_create_access_rule",
                {"policy": "mcp-test-acp", "name": "x", "action": "ALLOW", "application_filters": ["nope"]},
            )
    text = str(e.value)
    assert "fmc_find_application kind=filter" in text and "inline_app_filter" in text
    assert "check the rule afterwards" not in text


async def test_find_filter_after_a_restart_reads_the_rules(fmc10: respx.MockRouter) -> None:
    """Nothing remembered, FMC lists none: the filter is found where the rules use it."""
    rules = fmc10.get(RULES).mock(return_value=rules_plus(RULE))
    async with Client(server()) as c:
        out = await run(c, "fmc_find_application", {"text": "w6-appfilter", "kind": "filter"})
        by_id = await run(c, "fmc_find_application", {"text": FILTER_ID, "kind": "filter"})
        none = await run(c, "fmc_find_application", {"text": "nope", "kind": "filter"})
    assert out["application_filters"] == [
        {
            "id": FILTER_ID,
            "name": "mcp-w6-appfilter",
            "listed_by_fmc": False,
            "used_by": ["mcp-test-acp / mcp-w6-appfilter-rule"],
        }
    ]
    assert out["summary"] == "1 match(es) for 'w6-appfilter'."
    assert out["rules_scan"] == (
        "FMC lists no application filters, so the rules of 1 of 1 access policies were read."
    )
    assert "kind='filter' also lists the ones the access policies' rules use" in out["filter_note"]
    assert by_id["application_filters"][0]["name"] == "mcp-w6-appfilter"
    assert none["application_filters"] == [] and none["summary"] == "Nothing matches 'nope'."
    assert rules.call_count == 3


async def test_kind_any_does_not_read_the_rules(fmc10: respx.MockRouter) -> None:
    fmc10.get(f"{CFG}/object/applications").mock(return_value=items([]))
    fmc10.get(f"{CFG}/object/applicationcategories").mock(return_value=items([]))
    fmc10.get(f"{CFG}/object/applicationtags").mock(return_value=items([]))
    rules = fmc10.get(RULES).mock(return_value=rules_plus(RULE))
    async with Client(server()) as c:
        out = await run(c, "fmc_find_application", {"text": "w6-appfilter"})
    assert not rules.called and "rules_scan" not in out
    assert "kind='filter'" in out["filter_note"]


async def test_a_filter_the_server_created_is_not_listed_twice(fmc10: respx.MockRouter) -> None:
    fmc10.post(FILTERS).mock(return_value=httpx.Response(201, json=FX["create_answer"]))
    fmc10.get(RULES).mock(return_value=rules_plus(RULE))
    async with Client(server()) as c:
        preview = await run(
            c, "fmc_create_application_filter", {"name": "mcp-w6-appfilter", "risks": ["High"]}
        )
        await run(
            c,
            "fmc_create_application_filter",
            {"name": "mcp-w6-appfilter", "risks": ["High"], "confirm": preview["confirm"]},
        )
        out = await run(c, "fmc_find_application", {"text": "appfilter", "kind": "filter"})
    assert [r["name"] for r in out["application_filters"]] == ["mcp-w6-appfilter"]
    assert "conditions" in out["application_filters"][0]  # the remembered row, with its conditions


async def test_the_scan_is_capped_and_says_so(fmc10: respx.MockRouter) -> None:
    acp = fixture("accesspolicies")["items"][0]
    extra = [
        {**acp, "id": f"00000000-0000-0ed3-0000-0000000{i:05d}", "name": f"acp-{i}"}
        for i in range(FILTER_SCAN_POLICIES + 5)
    ]
    fmc10.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([acp, *extra]))
    fmc10.get(RULES).mock(return_value=rules_plus(RULE))
    others = fmc10.get(
        url__regex=rf"{CFG}/policy/accesspolicies/00000000-0000-0ed3-0000-0000000\d{{5}}/accessrules"
    ).mock(return_value=items([]))
    async with Client(server()) as c:
        out = await run(c, "fmc_find_application", {"text": "appfilter", "kind": "filter"})
    assert others.call_count == FILTER_SCAN_POLICIES - 1
    assert (
        f"the rules of {FILTER_SCAN_POLICIES} of {FILTER_SCAN_POLICIES + 6} access policies"
        in out["rules_scan"]
    )
    assert f"(the first {FILTER_SCAN_POLICIES};" in out["rules_scan"]


def test_filters_used_by_names_each_rule() -> None:
    other = {**copy.deepcopy(RULE), "name": "second"}
    used = filters_used_by([RULE, other, {"applications": {"applications": [{"id": "846"}]}}, {}], "pol")
    assert list(used) == [FILTER_ID.lower()]
    assert used[FILTER_ID.lower()]["used_by"] == ["pol / mcp-w6-appfilter-rule", "pol / second"]

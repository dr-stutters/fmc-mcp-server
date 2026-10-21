"""F66 fix: application filters FMC 10.0.1 doesn't list.

Recorded live (tests/fixtures/app_filters_fmc10.json): fmc_create_application_filter gets a 201 with the new
filter, but FMC's list stays empty and GET / DELETE by id answer 404; an access rule POST still takes the
filter by id ({id, type, name}) and rule GETs carry it. So the rule writers resolve a name from the filters
this server created and the filters the policy's rules use, and send a UUID FMC answers 404 for as given."""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.rule_conditions import filter_refs_in_rules
from fmc_mcp.server import create_server

from .conftest import ACP_ID, CFG, fixture, items, make_settings

FX = fixture("app_filters_fmc10")
LIVE = fixture("rule_conditions")
RULES = f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules"
FILTERS = f"{CFG}/object/applicationfilters"
CREATED = FX["create_answer"]
REF = {"id": CREATED["id"], "type": "ApplicationFilter", "name": "mcp-w6-appfilter"}
NOT_FOUND = httpx.Response(404, json={"error": {"messages": [{"description": "Not found"}]}})


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def confirm(c: Client[Any], name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    preview = await run(c, name, args)
    assert preview["status"] == "preview", preview
    return preview, await run(c, name, {**args, "confirm": preview["confirm"]})


def rules_plus(*extra: dict[str, Any]) -> httpx.Response:
    data = fixture("accessrules")
    data["items"] += [copy.deepcopy(r) for r in extra]
    return httpx.Response(200, json=data)


@pytest.fixture
def fmc10(lab: respx.MockRouter) -> respx.MockRouter:
    """FMC 10.0.1 as recorded: the filter list is empty and a filter's id answers 404."""
    lab.get(FILTERS, name="list").mock(return_value=httpx.Response(200, json=FX["list_after_create"]))
    lab.get(url__regex=rf"{FILTERS}/[0-9a-f-]{{36}}$", name="by_id").mock(return_value=NOT_FOUND)
    lab.get(f"{CFG}/object/applicationcategories").mock(
        return_value=httpx.Response(
            200, json={k: v for k, v in LIVE["applicationcategories"].items() if k != "_source"}
        )
    )
    return lab


async def test_a_created_filter_is_found_by_name_for_rules(fmc10: respx.MockRouter) -> None:
    fmc10.post(FILTERS).mock(return_value=httpx.Response(201, json=CREATED))
    post = fmc10.post(RULES).mock(return_value=httpx.Response(201, json={"id": "r-new", "name": "x"}))
    async with Client(server()) as c:
        preview, done = await confirm(
            c, "fmc_create_application_filter", {"name": "mcp-w6-appfilter", "risks": ["High", "Very High"]}
        )
        assert any("can only be removed in the FMC UI" in e for e in preview["side_effects"])
        result = done["result"]
        assert result["id"] == CREATED["id"] and CREATED["id"] in result["use"]
        assert "doesn't return application filters created over its API" in result["note"]
        # FMC lists none, so the rule writer finds the name among the filters this server created
        preview, _ = await confirm(
            c,
            "fmc_create_access_rule",
            {
                "policy": "mcp-test-acp",
                "name": "mcp-w6-appfilter-rule",
                "action": "ALLOW",
                "application_filters": ["MCP-W6-APPFILTER"],
            },
        )
        assert preview["preview"]["rule"]["applications"] == ["filter:mcp-w6-appfilter"]
        assert any("isn't listed by FMC; it is sent by id" in e for e in preview["side_effects"])
        sent = json.loads(post.calls.last.request.content)
        assert sent["applications"] == {"applicationFilters": [REF]}
        # it is listed by fmc_find_application, marked as not listed by FMC, with the note why
        out = await run(c, "fmc_find_application", {"text": "appfilter", "kind": "filter"})
        assert out["application_filters"] == [
            {
                "name": "mcp-w6-appfilter",
                "id": CREATED["id"],
                "conditions": ["risk High or Very High"],
                "listed_by_fmc": False,
            }
        ]
        assert "FMC lists no application filters" in out["filter_note"]
        # and a second filter of the same name is refused before anything is sent
        out = await run(c, "fmc_create_application_filter", {"name": "mcp-w6-appfilter", "risks": ["High"]})
        assert out["status"] == "blocked" and "already exists" in out["blockers"][0]


async def test_explicit_application_filter_answer_is_remembered(fmc10: respx.MockRouter) -> None:
    answer = FX["create_answer_explicit_app"]
    fmc10.get(f"{CFG}/object/applications").mock(
        return_value=httpx.Response(
            200, json={"items": [{"id": "846", "type": "Application", "name": "SSH"}]}
        )
    )
    fmc10.post(FILTERS).mock(return_value=httpx.Response(201, json=answer))
    async with Client(server()) as c:
        _, done = await confirm(
            c, "fmc_create_application_filter", {"name": "mcp-w6-appfilter2", "applications": ["SSH"]}
        )
        assert done["result"]["id"] == answer["id"]
        out = await run(c, "fmc_find_application", {"text": answer["id"], "kind": "filter"})
    (row,) = out["application_filters"]
    assert row["name"] == "mcp-w6-appfilter2" and row["applications"] == ["SSH"]


async def test_a_name_resolves_from_the_rules_that_use_it(fmc10: respx.MockRouter) -> None:
    """After a restart the server has forgotten its filters; a rule of the policy still names it."""
    fmc10.get(RULES).mock(return_value=rules_plus(FX["rule_with_filter"]))
    post = fmc10.post(RULES).mock(return_value=httpx.Response(201, json={"id": "r-new", "name": "x"}))
    async with Client(server()) as c:
        preview, _ = await confirm(
            c,
            "fmc_create_access_rule",
            {
                "policy": "mcp-test-acp",
                "name": "x",
                "action": "ALLOW",
                "application_filters": ["mcp-w6-appfilter"],
            },
        )
    assert json.loads(post.calls.last.request.content)["applications"] == {"applicationFilters": [REF]}
    assert any(CREATED["id"] in e and "sent by id" in e for e in preview["side_effects"])


async def test_an_unlisted_name_says_to_pass_the_uuid(fmc10: respx.MockRouter) -> None:
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="No application filter named 'nope': FMC lists none") as e:
            await run(
                c,
                "fmc_create_access_rule",
                {"policy": "mcp-test-acp", "name": "x", "action": "ALLOW", "application_filters": ["nope"]},
            )
    assert "pass the filter's UUID" in str(e.value)
    assert "doesn't return application filters created over its API" in str(e.value)


async def test_a_uuid_fmc_answers_404_for_is_sent_as_given(fmc10: respx.MockRouter) -> None:
    post = fmc10.post(RULES).mock(return_value=httpx.Response(201, json={"id": "r-new", "name": "x"}))
    unknown = "881148ec-cd11-11f1-9947-00000000a002"
    async with Client(server()) as c:
        preview, _ = await confirm(
            c,
            "fmc_create_access_rule",
            {"policy": "mcp-test-acp", "name": "x", "action": "ALLOW", "application_filters": [unknown]},
        )
    assert json.loads(post.calls.last.request.content)["applications"] == {
        "applicationFilters": [{"id": unknown, "type": "ApplicationFilter"}]
    }
    assert any(f"FMC answers 404 for application filter {unknown}" in e for e in preview["side_effects"])
    assert fmc10.routes["by_id"].call_count >= 1  # FMC was asked first


async def test_update_keeps_and_reuses_the_rules_own_filter(fmc10: respx.MockRouter) -> None:
    """The rule's current filter is known by name from the rule itself (FMC lists none)."""
    rule = copy.deepcopy(FX["rule_with_filter"])
    fmc10.get(RULES).mock(return_value=rules_plus(rule))
    fmc10.get(f"{RULES}/{rule['id']}").mock(return_value=httpx.Response(200, json=rule))
    fmc10.get(f"{CFG}/object/applications").mock(
        return_value=httpx.Response(
            200, json={"items": [{"id": "846", "type": "Application", "name": "SSH"}]}
        )
    )
    put = fmc10.put(f"{RULES}/{rule['id']}").mock(return_value=httpx.Response(200, json=rule))
    async with Client(server()) as c:
        preview, _ = await confirm(
            c,
            "fmc_update_access_rule",
            {
                "policy": "mcp-test-acp",
                "rule": "mcp-w6-appfilter-rule",
                "applications": ["SSH"],
                "application_filters": ["mcp-w6-appfilter"],
            },
        )
    sent = json.loads(put.calls.last.request.content)["applications"]
    assert sent["applicationFilters"] == [REF]
    assert sent["applications"] == [{"id": "846", "type": "Application", "name": "SSH"}]
    assert preview["preview"]["changes"]["applications"] == {
        "from": ["filter:mcp-w6-appfilter"],
        "to": ["SSH", "filter:mcp-w6-appfilter"],
    }


async def test_update_resolves_a_name_another_rule_of_the_policy_uses(fmc10: respx.MockRouter) -> None:
    """After a restart (nothing remembered) fmc_update_access_rule(rule=A, application_filters=['x']) where
    only rule B uses x: the policy's rules are read once and x resolves from B, as AppFiltersParam says."""
    target = copy.deepcopy(fixture("accessrules")["items"][0])  # mcp-test-allow-web: no filter
    rules = fmc10.get(RULES).mock(return_value=rules_plus(FX["rule_with_filter"]))
    fmc10.get(f"{RULES}/{target['id']}").mock(return_value=httpx.Response(200, json=target))
    put = fmc10.put(f"{RULES}/{target['id']}").mock(return_value=httpx.Response(200, json=target))
    async with Client(server()) as c:
        preview, _ = await confirm(
            c,
            "fmc_update_access_rule",
            {"policy": "mcp-test-acp", "rule": target["id"], "application_filters": ["mcp-w6-appfilter"]},
        )
    assert json.loads(put.calls.last.request.content)["applications"] == {"applicationFilters": [REF]}
    assert preview["preview"]["changes"]["applications"]["to"] == ["filter:mcp-w6-appfilter"]
    assert any("isn't listed by FMC; it is sent by id" in e for e in preview["side_effects"])
    # no extra request: the update reads the policy's rules once anyway (rule positions for move_to)
    assert rules.call_count == 2  # once for the preview, once for the confirm


def test_filter_refs_in_rules_reads_the_live_rule_shape() -> None:
    rules = [
        FX["rule_with_filter"],
        FX["rule_with_filter"],
        {"applications": {"applications": [{"id": "846"}]}},
    ]
    assert filter_refs_in_rules(rules) == [REF]
    assert filter_refs_in_rules([{}, {"applications": None}]) == []


async def test_a_listed_filter_still_comes_from_fmc(fmc10: respx.MockRouter) -> None:
    """Where FMC does list filters (other versions, UI-made ones), its list answers first."""
    listed = {**CREATED, "id": "00000000-0000-0ed3-0000-021474960002", "name": "mcp-w6-listed"}
    fmc10.routes["list"].mock(return_value=items([listed]))
    post = fmc10.post(RULES).mock(return_value=httpx.Response(201, json={"id": "r-new", "name": "x"}))
    async with Client(server()) as c:
        preview, _ = await confirm(
            c,
            "fmc_create_access_rule",
            {
                "policy": "mcp-test-acp",
                "name": "x",
                "action": "ALLOW",
                "application_filters": ["mcp-w6-listed"],
            },
        )
        with pytest.raises(ToolError, match=r"No application filter named 'nope'\. .*pass the filter's UUID"):
            await run(
                c,
                "fmc_create_access_rule",
                {"policy": "mcp-test-acp", "name": "x", "action": "ALLOW", "application_filters": ["nope"]},
            )
    assert json.loads(post.calls.last.request.content)["applications"]["applicationFilters"][0]["name"] == (
        "mcp-w6-listed"
    )
    assert not any("sent by id" in e for e in preview["side_effects"])

"""fmc_update_access_rule(category=...) on FMC 10.0.1 (F76 #171, W6N live-A finding 1).

FMC re-creates a rule it moves into a category: the old id answers 404 after the move and the bulk PUT
answers with an id that isn't the stored one either. Recorded live:
tests/fixtures/rule_category_move_fmc10.json.
The tool used to re-read the old id and report an error although the move was applied.
"""

import copy
import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, DOMAIN, fixture, make_settings

FX = fixture("rule_category_move_fmc10")


def live(key: str) -> dict[str, Any]:
    out = copy.deepcopy(FX[key])
    out.pop("_source", None)
    return dict(out)


CHILD = live("child_acp")
CHILD["metadata"]["domain"]["id"] = DOMAIN  # the test login's domain owns it
RULES = f"{CFG}/policy/accesspolicies/{CHILD['id']}/accessrules"
OLD_ID = FX["rule_before_move"]["id"]
NEW_ID = FX["rule_after_move"]["id"]


def page(rows: list[dict[str, Any]]) -> httpx.Response:
    return httpx.Response(200, json={"items": rows, "paging": {"count": len(rows)}})


def child_policy(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=page([CHILD]))
    fmc.get(f"{CFG}/policy/accesspolicies/{CHILD['id']}").mock(return_value=httpx.Response(200, json=CHILD))
    fmc.get(f"{CFG}/policy/accesspolicies/{CHILD['id']}/categories").mock(
        return_value=httpx.Response(200, json=live("categories"))
    )


def rules_before_and_after(fmc: respx.MockRouter, after: list[dict[str, Any]]) -> respx.Route:
    """The child's rule list: the rule (and an inherited one) until the bulk PUT, then `after`."""
    inherited = live("inherited_rule_row")
    before = [live("rule_before_move"), inherited]
    put = fmc.put(RULES).mock(return_value=httpx.Response(200, json=FX["bulk_put_into_category"]["response"]))
    fmc.get(RULES).mock(side_effect=lambda _req: page(after if put.called else before))
    return put


async def preview_apply(args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = (await c.call_tool("fmc_update_access_rule", args)).structured_content
        assert preview is not None and preview["status"] == "preview", preview.get("blockers")
        done = (
            await c.call_tool("fmc_update_access_rule", {**args, "confirm": preview["confirm"]})
        ).structured_content
        assert done is not None
        return preview, done


ARGS = {"policy": "mcp-w6-child-acp", "rule": "mcp-w6-child-icmp", "category": "mcp-w6-cat-b"}


def test_recorded_shapes() -> None:
    """What the fix relies on, as FMC 10.0.1 answered it."""
    answer_id = FX["bulk_put_into_category"]["response"]["items"][0]["id"]
    stored_id = FX["list_after_bulk_put"]["items"][0]["id"]
    sent_id = FX["bulk_put_into_category"]["request"][0]["id"]
    assert len({answer_id, stored_id, sent_id}) == 3  # three ids for one rule
    assert FX["rule_after_move"]["name"] == FX["rule_before_move"]["name"] and NEW_ID != OLD_ID
    assert FX["rule_after_move"]["commentHistoryList"] == FX["rule_before_move"]["commentHistoryList"]
    assert FX["inherited_rule_row"]["metadata"]["accessPolicy"]["name"] == "mcp-w6-acp"  # the base's rule


async def test_move_into_category_finds_the_re_created_rule(fmc: respx.MockRouter) -> None:
    child_policy(fmc)
    put = rules_before_and_after(fmc, [live("rule_after_move"), live("inherited_rule_row")])
    old = fmc.get(f"{RULES}/{OLD_ID}").mock(return_value=httpx.Response(404, json={}))
    preview, done = await preview_apply(ARGS)
    assert preview["preview"]["move"]["from"]["category"] == "mcp-w6-cat-a"
    assert preview["preview"]["move"]["into_category"]["name"] == "mcp-w6-cat-b"
    assert any("re-creates the rule in the category: it gets a new id" in s for s in preview["side_effects"])
    req = put.calls.last.request
    assert dict(req.url.params) == {"bulk": "true", "category": "mcp-w6-cat-b"}
    assert json.loads(req.content)[0]["id"] == OLD_ID
    result = done["result"]
    assert done["status"] == "applied", done
    assert result["rule"]["id"] == NEW_ID and result["rule"]["name"] == "mcp-w6-child-icmp"
    assert result["now_at"] == {
        "index": 1,
        "name": "mcp-w6-child-icmp",
        "section": "default",
        "category": "mcp-w6-cat-b",
        "id": NEW_ID,
    }
    assert result["id_changed"] == {"from": OLD_ID, "to": NEW_ID} and "new id" in result["note"]
    assert old.call_count == 0  # the old id is never read again (FMC answers 404)


async def test_a_base_policy_rule_of_the_same_name_is_not_taken(fmc: respx.MockRouter) -> None:
    """A child's rule list holds its base policy's rules too; the moved rule is the child's own."""
    child_policy(fmc)
    namesake = {**live("inherited_rule_row"), "name": "mcp-w6-child-icmp"}
    rules_before_and_after(fmc, [namesake, live("rule_after_move")])
    _, done = await preview_apply(ARGS)
    assert done["result"]["rule"]["id"] == NEW_ID


async def test_rule_not_listed_after_the_move_is_a_warning_not_an_error(fmc: respx.MockRouter) -> None:
    child_policy(fmc)
    rules_before_and_after(fmc, [live("inherited_rule_row")])
    _, done = await preview_apply(ARGS)
    result = done["result"]
    assert done["status"] == "applied", done
    assert (
        result["rule"] == "mcp-w6-child-icmp"
        and "lists no rule named 'mcp-w6-child-icmp'" in result["warning"]
    )
    assert "id" not in result  # the PUT answer's id is not the stored one: not shown

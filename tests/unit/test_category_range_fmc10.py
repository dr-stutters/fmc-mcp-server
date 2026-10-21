"""Category rule ranges as FMC 10.0.1 answers them (F76 #171, W6N live-A): an empty category reads
startIndex/endIndex 0, not -1 as in the spec example, and showed as rules "0" in fmc_get_access_policy.
Recorded live: tests/fixtures/categories_fmc10.json."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.acp_structure import category_row
from fmc_mcp.server import create_server

from .conftest import ACP_ID, CFG, fixture, make_settings

FX = fixture("categories_fmc10")


def test_empty_categories_read_zero_and_show_none() -> None:
    rows = [category_row(c) for c in FX["list_after_creates"]["items"]]
    assert [(r["name"], r["section"], r["rules"]) for r in rows] == [
        ("mcp-w6-cat-m", "mandatory", "none"),
        ("mcp-w6-cat-b", "default", "none"),
        ("mcp-w6-cat-a", "default", "none"),
    ]
    for key in ("post_default", "post_mandatory", "post_above"):
        assert FX[key]["metadata"]["startIndex"] == 0 == FX[key]["metadata"]["endIndex"]
        assert category_row(FX[key])["rules"] == "none"


def test_a_category_with_one_rule() -> None:
    assert category_row(FX["put_with_one_rule"]) == {
        "name": "mcp-w6-cat-b2",
        "section": "default",
        "rules": "1",
        "id": "00000000-0000-0ed3-0000-000268434570",
    }
    spec_empty = {"metadata": {"section": "Default", "startIndex": -1, "endIndex": -1}}
    assert category_row(spec_empty)["rules"] == "none"  # the spec example's empty category


async def test_create_category_result_with_the_live_answer(lab: respx.MockRouter) -> None:
    created = {k: v for k, v in FX["post_mandatory"].items() if k != "_source"}
    before = {"items": [], "paging": {"count": 0}}
    after = {"items": [created], "paging": {"count": 1}}
    lab.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/categories").mock(
        side_effect=[httpx.Response(200, json=before)] * 2 + [httpx.Response(200, json=after)]
    )
    post = lab.post(f"{CFG}/policy/accesspolicies/{ACP_ID}/categories").mock(
        return_value=httpx.Response(201, json=created)
    )
    args: dict[str, Any] = {"policy": "mcp-test-acp", "name": "mcp-w6-cat-m", "section": "mandatory"}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        preview = (await c.call_tool("fmc_create_category", args)).structured_content
        assert preview is not None and preview["status"] == "preview", preview
        done = (
            await c.call_tool("fmc_create_category", {**args, "confirm": preview["confirm"]})
        ).structured_content
    assert done is not None
    assert json.loads(post.calls.last.request.content) == {"name": "mcp-w6-cat-m", "type": "Category"}
    assert done["result"]["category"] == {
        "name": "mcp-w6-cat-m",
        "section": "mandatory",
        "rules": "none",
        "id": created["id"],
    }

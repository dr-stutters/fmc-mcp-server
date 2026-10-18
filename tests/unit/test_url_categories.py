"""F63: URL category + reputation conditions in access rules, and in fmc_rule_lookup.

The 126 URL categories are recorded from FMC 10.0.1 (tests/fixtures/urlcategories.json); the reputation
levels are FMC 10.0.1's spec enum (IUrlCategoryAndReputation.reputation)."""

import json
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server
from fmc_mcp.url_categories import (
    FALLBACK_REPUTATIONS,
    enum_of,
    merge_url_block,
    normalise_reputation,
    reputation_levels,
    reputation_meaning,
    url_category_match,
)

from .conftest import ACP_ID, CFG, fixture, items, make_settings

RULES = f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules"
GAMBLING = {"id": "abba9b63-bb10-4729-b901-2e2aa0f02049", "type": "URLCategory", "name": "Gambling"}
MALWARE = {"id": "abba9b63-bb10-4729-b901-2e2aa0f01001", "type": "URLCategory", "name": "Malware Sites"}
URL_OBJ = {"type": "Url", "name": "mcp-test-url", "id": "00000000-0000-0ed3-0000-021474837401"}


def cat(c: dict[str, Any], rep: str = "ANY_AND_UNKNOWN") -> dict[str, Any]:
    return {"type": "UrlCategoryAndReputation", "category": c, "reputation": rep}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def preview_apply(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    async with Client(server()) as c:
        preview = await run(c, name, args)
        assert preview["status"] == "preview", preview
        done = await run(c, name, {**args, "confirm": preview["confirm"]})
        return preview, done


@pytest.fixture
def urlcats(lab: respx.MockRouter) -> respx.MockRouter:
    lab.get(f"{CFG}/object/urlcategories").mock(
        return_value=httpx.Response(200, json=fixture("urlcategories"))
    )
    return lab


def rules_with(url_rule_urls: dict[str, Any] | None) -> dict[str, Any]:
    """The recorded mcp-test-acp rules with rule 6 (mcp-test-url-rule) given another urls block."""
    data = fixture("accessrules")
    for r in data["items"]:
        if r["name"] == "mcp-test-url-rule":
            if url_rule_urls is None:
                r.pop("urls", None)
            else:
                r["urls"] = url_rule_urls
    return data


# --- helpers ---------------------------------------------------------------------------------------


def test_reputation_levels_and_meaning() -> None:
    assert enum_of("enum: ANY_EXCEPT_UNKNOWN|TRUSTED|UNTRUSTED") == [
        "ANY_EXCEPT_UNKNOWN",
        "TRUSTED",
        "UNTRUSTED",
    ]
    assert enum_of("string") == []
    levels = list(FALLBACK_REPUTATIONS)
    assert normalise_reputation(None, levels, "built-in") == "ANY_AND_UNKNOWN"
    assert normalise_reputation("questionable and unknown", levels, "built-in") == "QUESTIONABLE_AND_UNKNOWN"
    with pytest.raises(Exception, match="BENIGN_SITES"):
        normalise_reputation("BENIGN_SITES", levels, "spec")  # FMC's own example value, not in the enum
    assert reputation_meaning("QUESTIONABLE", "BLOCK_RESET") == "sites rated questionable or untrusted"
    assert reputation_meaning("FAVORABLE", "ALLOW") == "sites rated trusted or favorable"
    assert reputation_meaning("UNTRUSTED_AND_UNKNOWN", "BLOCK") == (
        "sites rated untrusted, and sites with no reputation"
    )
    assert reputation_meaning("ANY_AND_UNKNOWN", "BLOCK") == "every site in the category"


async def test_reputation_levels_come_from_the_spec_index() -> None:
    index = SimpleNamespace(
        schemas={
            "IUrlCategoryAndReputation": {"fields": {"reputation": "enum: ANY_AND_UNKNOWN|TRUSTED, desc"}}
        }
    )

    class Store:
        async def get(self) -> Any:
            return index

    ctx = SimpleNamespace(lifespan_context={"specs": Store()})
    assert await reputation_levels(ctx) == (["ANY_AND_UNKNOWN", "TRUSTED"], "spec")
    assert await reputation_levels(SimpleNamespace(lifespan_context={})) == (
        list(FALLBACK_REPUTATIONS),
        "built-in",
    )


def test_merge_url_block_replaces_only_the_given_part() -> None:
    cur = {"objects": [URL_OBJ], "urlCategoriesWithReputation": [cat(GAMBLING)]}
    assert merge_url_block(cur, None, [cat(MALWARE)]) == {
        "objects": [URL_OBJ],
        "urlCategoriesWithReputation": [cat(MALWARE)],
    }
    assert merge_url_block(cur, {}, None) == {"urlCategoriesWithReputation": [cat(GAMBLING)]}
    assert merge_url_block(cur, None, []) == {"objects": [URL_OBJ]}
    assert merge_url_block(None, {}, []) == {}


def test_url_category_match() -> None:
    only_cats = {"urlCategoriesWithReputation": [cat(GAMBLING), cat(MALWARE, "QUESTIONABLE")]}
    assert url_category_match(None, "Gambling") == (True, False)
    assert url_category_match(only_cats, None) == (None, False)
    assert url_category_match(only_cats, "gambling") == (True, False)
    assert url_category_match(only_cats, "Malware Sites") == (True, True)
    assert url_category_match(only_cats, "News") == (False, False)
    assert url_category_match({"objects": [URL_OBJ]}, "News") == (None, False)


# --- access rule writes ----------------------------------------------------------------------------


async def test_create_block_rule_with_categories(urlcats: respx.MockRouter) -> None:
    post = urlcats.post(RULES).mock(
        return_value=httpx.Response(201, json={"id": "new", "name": "no-gambling"})
    )
    preview, _ = await preview_apply(
        "fmc_create_access_rule",
        {
            "policy": "mcp-test-acp",
            "name": "no-gambling",
            "action": "BLOCK_RESET",
            "url_categories": [
                {"category": "gambling"},
                {"category": "Malware Sites", "reputation": "questionable"},
            ],
        },
    )
    assert any("URL licence" in e for e in preview["side_effects"])
    shown = preview["preview"]
    assert shown["rule"]["urls"] == [
        "category:Gambling (ANY_AND_UNKNOWN)",
        "category:Malware Sites (QUESTIONABLE)",
    ]
    assert shown["url_categories"][1] == {
        "category": "Malware Sites",
        "reputation": "QUESTIONABLE",
        "matches": "sites rated questionable or untrusted",
    }
    body = json.loads(post.calls.last.request.content)
    assert body["urls"] == {"urlCategoriesWithReputation": [cat(GAMBLING), cat(MALWARE, "QUESTIONABLE")]}


async def test_create_rule_with_url_objects_and_categories(urlcats: respx.MockRouter) -> None:
    urlcats.get(f"{CFG}/object/urls").mock(return_value=items([URL_OBJ]))
    post = urlcats.post(RULES).mock(return_value=httpx.Response(201, json={"id": "new", "name": "web"}))
    await preview_apply(
        "fmc_create_access_rule",
        {
            "policy": "mcp-test-acp",
            "name": "web",
            "action": "ALLOW",
            "urls": ["mcp-test-url"],
            "url_categories": [{"category": GAMBLING["id"], "reputation": "TRUSTED"}],
        },
    )
    body = json.loads(post.calls.last.request.content)
    assert body["urls"]["objects"][0]["id"] == URL_OBJ["id"]
    assert body["urls"]["urlCategoriesWithReputation"] == [cat(GAMBLING, "TRUSTED")]


async def test_unknown_category_or_reputation_is_refused(urlcats: respx.MockRouter) -> None:
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="Did you mean: Gambling"):
            await run(
                c,
                "fmc_create_access_rule",
                {
                    "policy": "mcp-test-acp",
                    "name": "x",
                    "action": "BLOCK",
                    "url_categories": [{"category": "Gamblin"}],
                },
            )
        with pytest.raises(ToolError, match="allows: ANY_EXCEPT_UNKNOWN"):
            await run(
                c,
                "fmc_create_access_rule",
                {
                    "policy": "mcp-test-acp",
                    "name": "x",
                    "action": "BLOCK",
                    "url_categories": [{"category": "Gambling", "reputation": "risky"}],
                },
            )


async def test_update_categories_keeps_url_objects(urlcats: respx.MockRouter) -> None:
    rule = next(r for r in fixture("accessrules")["items"] if r["name"] == "mcp-test-url-rule")
    put = urlcats.put(f"{RULES}/{rule['id']}").mock(return_value=httpx.Response(200, json=rule))
    preview, _ = await preview_apply(
        "fmc_update_access_rule",
        {"policy": "mcp-test-acp", "rule": "mcp-test-url-rule", "url_categories": [{"category": "Gambling"}]},
    )
    assert preview["preview"]["changes"]["urls"] == {
        "from": ["mcp-test-url"],
        "to": ["mcp-test-url", "category:Gambling (ANY_AND_UNKNOWN)"],
    }
    assert preview["preview"]["url_categories"][0]["matches"] == "every site in the category"
    body = json.loads(put.calls.last.request.content)
    assert body["urls"]["objects"][0]["name"] == "mcp-test-url"
    assert body["urls"]["urlCategoriesWithReputation"] == [cat(GAMBLING)]


async def test_update_urls_keeps_categories_and_empty_list_removes_them(urlcats: respx.MockRouter) -> None:
    both = {"objects": [URL_OBJ], "urlCategoriesWithReputation": [cat(GAMBLING)]}
    data = rules_with(both)
    urlcats.get(RULES).mock(return_value=httpx.Response(200, json=data))
    rule = next(r for r in data["items"] if r["name"] == "mcp-test-url-rule")
    put = urlcats.put(f"{RULES}/{rule['id']}").mock(return_value=httpx.Response(200, json=rule))
    await preview_apply(
        "fmc_update_access_rule",
        {"policy": "mcp-test-acp", "rule": "mcp-test-url-rule", "urls": ["https://example.com/x"]},
    )
    body = json.loads(put.calls.last.request.content)
    assert body["urls"] == {
        "literals": [{"type": "Url", "url": "https://example.com/x"}],
        "urlCategoriesWithReputation": [cat(GAMBLING)],
    }
    data = rules_with({"urlCategoriesWithReputation": [cat(GAMBLING)]})
    urlcats.get(RULES).mock(return_value=httpx.Response(200, json=data))
    preview, _ = await preview_apply(
        "fmc_update_access_rule",
        {"policy": "mcp-test-acp", "rule": "mcp-test-url-rule", "url_categories": []},
    )
    assert preview["preview"]["changes"]["urls"] == {
        "from": ["category:Gambling (ANY_AND_UNKNOWN)"],
        "to": "any",
    }
    assert "urls" not in json.loads(put.calls.last.request.content)


# --- rule lookup -----------------------------------------------------------------------------------

FLOW = {
    "policy": "mcp-test-acp",
    "source": "1.1.1.1",
    "destination": "8.8.8.8",
    "port": 53,
    "protocol": "udp",
}


async def lookup(lab: respx.MockRouter, urls: dict[str, Any] | None, **kw: Any) -> dict[str, Any]:
    lab.get(RULES).mock(return_value=httpx.Response(200, json=rules_with(urls)))
    async with Client(server()) as c:
        out: dict[str, Any] = await run(c, "fmc_rule_lookup", {**FLOW, **kw})
    return out


async def test_rule_lookup_evaluates_url_categories(lab: respx.MockRouter) -> None:
    cats = {"urlCategoriesWithReputation": [cat(GAMBLING), cat(MALWARE, "QUESTIONABLE")]}
    out = await lookup(lab, cats)
    assert out["may_match_first"][0]["depends_on"] == ["urls"]
    assert out["may_match_first"][0]["urls"] == [
        "category:Gambling (ANY_AND_UNKNOWN)",
        "category:Malware Sites (QUESTIONABLE)",
    ]
    out = await lookup(lab, cats, url_category="Gambling")
    assert out["matched_rule"]["name"] == "mcp-test-url-rule" and out["flow"]["url_category"] == "Gambling"
    out = await lookup(lab, cats, url_category="Malware Sites")
    assert out["may_match_first"][0]["depends_on"] == ["url_reputation"] and "matched_rule" not in out
    out = await lookup(lab, cats, url_category="News")
    assert "may_match_first" not in out and out["default_action"] == "BLOCK"
    out = await lookup(lab, {"objects": [URL_OBJ]}, url_category="News")
    assert out["may_match_first"][0]["depends_on"] == ["url_category"]

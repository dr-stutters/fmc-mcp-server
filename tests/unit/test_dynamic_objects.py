"""Dynamic objects and IP mappings (F4), with payload shapes recorded from FMC 10.0.1."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from stutters_mcp_core import InvalidRequest

from fmc_mcp.server import create_server
from fmc_mcp.tools.dynamic_objects import normalize_ips
from fmc_mcp.tools.troubleshoot import name_snort_rules

from .conftest import CFG, items, make_settings

DYN = {
    "id": "00000000-0000-0ed3-0000-021474863056",
    "name": "mcp-test-quarantine",
    "description": "mcp test",
    "type": "DynamicObject",
    "objectType": "IP",
}
ACP = {"id": "00000000-0000-0ed3-0000-021474847655", "name": "mcp-test-ftd-acp", "type": "AccessPolicy"}
RULE = {
    "id": "00000000-0000-0ed3-0000-000268434491",
    "name": "mcp-test-quarantine-block",
    "action": "BLOCK",
    "enabled": True,
    "metadata": {"ruleIndex": 1},
    "sourceDynamicObjects": {"objects": [{"id": DYN["id"], "name": DYN["name"], "type": "DynamicObject"}]},
}
ALLOW = {"id": "00000000-0000-0ed3-0000-000268434474", "name": "mcp-test-allow-out", "action": "ALLOW"}
MAPPINGS = f"{CFG}/object/dynamicobjects/{DYN['id']}/mappings"


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


@pytest.fixture
def dyn(fmc: respx.MockRouter) -> respx.MockRouter:
    fmc.get(f"{CFG}/object/dynamicobjects").mock(return_value=items([DYN]))
    fmc.get(MAPPINGS).mock(return_value=items([{"mapping": "10.99.1.250"}]))
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules").mock(return_value=items([RULE, ALLOW]))
    return fmc


def test_normalize_ips() -> None:
    assert normalize_ips(["10.1.1.1", "10.1.1.1/32", " 10.2.0.0/16", "2001:db8::1"]) == [
        "10.1.1.1",
        "10.2.0.0/16",
        "2001:db8::1",
    ]
    for bad in (["nope"], ["10.1.1.1/24"]):
        with pytest.raises(InvalidRequest):
            normalize_ips(bad)


async def test_list_with_mappings(dyn: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_list_dynamic_objects", {"response_format": "json"})
    assert out["results"][0]["mappings"] == ["10.99.1.250"] and out["results"][0]["mapping_count"] == 1


async def test_map_preview_shows_rules_and_no_deploy(dyn: respx.MockRouter) -> None:
    post = dyn.post(f"{CFG}/object/dynamicobjectmappings").mock(return_value=httpx.Response(201, json={}))
    args = {"object": "mcp-test-quarantine", "add": ["10.99.1.10", "10.99.1.250"], "remove": ["10.99.9.9"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_map_dynamic_object", args)
        assert preview["status"] == "preview"
        assert preview["preview"]["add"] == ["10.99.1.10"]  # .250 is already mapped
        assert preview["preview"]["remove"] == []  # .9.9 isn't mapped
        assert preview["preview"]["rules"][0]["rule"] == "mcp-test-quarantine-block"
        assert any("without a deployment" in s for s in preview["side_effects"])
        await run(c, "fmc_map_dynamic_object", {**args, "confirm": preview["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body == {"add": [{"mappings": ["10.99.1.10"], "dynamicObject": {"id": DYN["id"]}}]}


async def test_map_nothing_to_change_is_blocked(dyn: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_map_dynamic_object", {"object": DYN["name"], "add": ["10.99.1.250"]})
    assert out["status"] == "blocked"


async def test_map_rejects_overlap_and_garbage(dyn: respx.MockRouter) -> None:
    async with Client(server()) as c:
        for args in ({"add": ["10.1.1.1"], "remove": ["10.1.1.1"]}, {"add": ["x"]}, {}):
            r = await c.call_tool(
                "fmc_map_dynamic_object", {"object": DYN["name"], **args}, raise_on_error=False
            )
            assert r.is_error


async def test_delete_blocked_while_rule_uses_it(dyn: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_delete_dynamic_object", {"object": DYN["name"]})
    assert out["status"] == "blocked" and "mcp-test-quarantine-block" in out["blockers"][0]


async def test_create_with_mappings(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/dynamicobjects").mock(return_value=items([]))
    create = fmc.post(f"{CFG}/object/dynamicobjects").mock(return_value=httpx.Response(201, json=DYN))
    maps = fmc.post(f"{CFG}/object/dynamicobjectmappings").mock(return_value=httpx.Response(201, json={}))
    args = {"name": DYN["name"], "mappings": ["10.99.1.10"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_dynamic_object", args)
        done = await run(c, "fmc_create_dynamic_object", {**args, "confirm": preview["confirm"]})
    assert json.loads(create.calls.last.request.content)["objectType"] == "IP"
    assert json.loads(maps.calls.last.request.content)["add"][0]["mappings"] == ["10.99.1.10"]
    assert done["result"]["mappings"] == ["10.99.1.10"]


async def test_access_rule_with_dynamic_source(dyn: respx.MockRouter) -> None:
    dyn.get(f"{CFG}/policy/accesspolicies/{ACP['id']}").mock(return_value=httpx.Response(200, json=ACP))
    post = dyn.post(f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules").mock(
        return_value=httpx.Response(201, json={"id": "r"})
    )
    args = {"policy": ACP["name"], "name": "q2", "action": "BLOCK", "source_dynamic_objects": [DYN["name"]]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_access_rule", args)
        await run(c, "fmc_create_access_rule", {**args, "confirm": preview["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["sourceDynamicObjects"]["objects"][0]["id"] == DYN["id"]


async def test_name_snort_rules(dyn: respx.MockRouter) -> None:
    traces = [
        {
            "matched_rules": [
                {
                    "type": "ACCESS-LIST",
                    "rule_id": "268434491",
                    "rule": RULE["name"],
                    "policy": "mcp-test-ftd-acp - Default",
                },
                {"type": "SNORT", "rule_id": "268434474"},
            ],
            "phases": [{"type": "SNORT", "rule_id": "268434474"}],
        }
    ]
    from fmc_mcp.client import FmcApp

    app = FmcApp(make_settings())
    try:
        await name_snort_rules(app, traces, None)
    finally:
        await app.aclose()
    assert traces[0]["verdict_rule"] == "mcp-test-allow-out"
    assert traces[0]["phases"][0]["rule"] == "mcp-test-allow-out"


async def test_create_reports_partial_failure(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/dynamicobjects").mock(return_value=items([]))
    fmc.post(f"{CFG}/object/dynamicobjects").mock(return_value=httpx.Response(201, json=DYN))
    fmc.post(f"{CFG}/object/dynamicobjectmappings").mock(
        return_value=httpx.Response(400, json={"error": {"messages": [{"description": "bad"}]}})
    )
    args = {"name": DYN["name"], "mappings": ["10.99.1.10"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_dynamic_object", args)
        r = await c.call_tool(
            "fmc_create_dynamic_object", {**args, "confirm": preview["confirm"]}, raise_on_error=False
        )
    assert r.is_error and DYN["id"] in r.content[0].text  # type: ignore[union-attr]


async def test_rule_scan_cached_between_preview_and_confirm(dyn: respx.MockRouter) -> None:
    dyn.post(f"{CFG}/object/dynamicobjectmappings").mock(return_value=httpx.Response(201, json={}))
    args = {"object": DYN["name"], "add": ["10.99.1.10"]}
    async with Client(server()) as c:
        preview = await run(c, "fmc_map_dynamic_object", args)
        calls_after_preview = sum(1 for call in dyn.calls if "/accessrules" in str(call.request.url))
        await run(c, "fmc_map_dynamic_object", {**args, "confirm": preview["confirm"]})
    calls = sum(1 for call in dyn.calls if "/accessrules" in str(call.request.url))
    assert calls == calls_after_preview == 1

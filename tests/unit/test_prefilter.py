"""F20 prefilter writes."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, items, make_settings

PF = {"id": "4897c8f4-e211-4661-b0a4-25b0826cded9", "name": "mcp-test-pf", "type": "PrefilterPolicy"}
ACP = {"id": "00000000-0000-0ed3-0000-021474847655", "name": "acp", "type": "AccessPolicy"}
RULES = f"{CFG}/policy/prefilterpolicies/{PF['id']}/prefilterrules"


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def test_create_fastpath_rule(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/prefilterpolicies").mock(return_value=items([PF]))
    fmc.get(RULES).mock(return_value=items([]))
    post = fmc.post(RULES).mock(side_effect=lambda req: httpx.Response(201, json=json.loads(req.content)))
    args = {
        "policy": "mcp-test-pf",
        "name": "fp",
        "action": "FASTPATH",
        "source_networks": ["10.0.0.5"],
        "destination_networks": ["10.0.1.0/24"],
        "bidirectional": True,
        "log": True,
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_prefilter_rule", args)
        assert preview["status"] == "preview", preview
        assert any("skips Snort" in s for s in preview["side_effects"])
        await run(c, "fmc_create_prefilter_rule", {**args, "confirm": preview["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["action"] == "FASTPATH" and body["ruleType"] == "PREFILTER" and body["bidirectional"] is True
    assert body["sourceNetworks"]["literals"][0]["value"] == "10.0.0.5"
    assert body["logEnd"] is True and body["sendEventsToFMC"] is True


async def test_bidirectional_needs_fastpath_without_ports(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/prefilterpolicies").mock(return_value=items([PF]))
    async with Client(server()) as c:
        r = await c.call_tool(
            "fmc_create_prefilter_rule",
            {"policy": "mcp-test-pf", "name": "b", "action": "BLOCK", "bidirectional": True},
            raise_on_error=False,
        )
    assert r.is_error and "FASTPATH" in r.content[0].text  # type: ignore[union-attr]


async def test_link_prefilter_policy_sends_policy_fields_only(fmc: respx.MockRouter) -> None:
    full = {
        **ACP,
        "defaultAction": {"action": "BLOCK"},
        "rules": {"refType": "list"},
        "prefilterPolicySetting": {"id": "def", "name": "Default Prefilter Policy"},
    }
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    fmc.get(f"{CFG}/policy/prefilterpolicies").mock(return_value=items([PF]))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}").mock(return_value=httpx.Response(200, json=full))
    put = fmc.put(f"{CFG}/policy/accesspolicies/{ACP['id']}").mock(
        return_value=httpx.Response(200, json=full)
    )
    args = {"access_policy": "acp", "prefilter_policy": "mcp-test-pf"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_set_prefilter_policy", args)
        assert preview["preview"]["from"] == "Default Prefilter Policy"
        await run(c, "fmc_set_prefilter_policy", {**args, "confirm": preview["confirm"]})
    body = json.loads(put.calls.last.request.content)
    assert "rules" not in body and body["prefilterPolicySetting"]["id"] == PF["id"]

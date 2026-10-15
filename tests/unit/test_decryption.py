"""F13 slice 2: decryption policy tools."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, items, make_settings

DEC = {
    "id": "d1",
    "name": "mcp-test-dec",
    "type": "DecryptionPolicy",
    "defaultAction": {"policyAction": "DO_NOT_DECRYPT"},
}
ACP = {"id": "00000000-0000-0ed3-0000-021474847655", "name": "acp", "type": "AccessPolicy"}
RULES = f"{CFG}/policy/decryptionpolicies/d1/decryptionpolicyrules"


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def test_create_do_not_decrypt_rule(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/decryptionpolicies").mock(return_value=items([DEC]))
    fmc.get(RULES).mock(return_value=items([]))
    post = fmc.post(RULES).mock(return_value=httpx.Response(201, json={"id": "r1"}))
    args = {
        "policy": "mcp-test-dec",
        "name": "dnd",
        "destination_networks": ["203.0.113.10"],
        "destination_ports": ["tcp/443"],
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_create_decryption_rule", args)
        assert p["preview"]["rule"]["action"] == "DO_NOT_DECRYPT"
        await run(c, "fmc_create_decryption_rule", {**args, "confirm": p["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["ruleAction"] == "DO_NOT_DECRYPT" and body["destinationPorts"]["literals"][0]["port"] == "443"


async def test_unlink_is_refused_with_explanation(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}").mock(
        return_value=httpx.Response(
            200, json={**ACP, "decryptionPolicySetting": {"id": "d1", "name": "mcp-test-dec"}}
        )
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_set_decryption_policy", {"access_policy": "acp", "decryption_policy": ""})
    assert out["status"] == "blocked" and "can't remove" in out["blockers"][0]

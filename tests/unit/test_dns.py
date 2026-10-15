"""F13 slice 3: DNS block via custom SI DNS lists."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server
from fmc_mcp.tools.dns import list_name

from .conftest import CFG, items, make_settings

POL = {"id": "dp1", "name": "mcp-test-dns", "type": "DNSPolicy"}
RULES = f"{CFG}/policy/dnspolicies/dp1/dnsrules"
LISTS = f"{CFG}/object/customsidnslists"


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def test_list_names() -> None:
    assert list_name("bad.example.com") == "mcp-dns-bad.example.com"
    assert list_name("*.evil.test") != list_name("_.evil.test")


async def test_block_uploads_list_and_creates_rule(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/dnspolicies").mock(return_value=items([POL]))
    fmc.get(RULES).mock(return_value=items([]))
    fmc.get(LISTS).mock(return_value=items([]))
    upload = fmc.post(LISTS).mock(
        return_value=httpx.Response(
            201, json={"id": "l1", "name": "mcp-dns-bad.example.com", "type": "CustomSIDNSListObject"}
        )
    )
    rule = fmc.post(RULES).mock(
        side_effect=lambda req: httpx.Response(201, json={**json.loads(req.content), "id": "r1"})
    )
    args = {"policy": "mcp-test-dns", "domains": ["Bad.Example.com."]}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        p = await run(c, "fmc_dns_block", args)
        assert p["preview"]["domains"] == ["bad.example.com"] and not upload.called
        await run(c, "fmc_dns_block", {**args, "confirm": p["confirm"]})
        with pytest.raises(ToolError, match="not a domain"):
            await run(c, "fmc_dns_block", {"policy": "mcp-test-dns", "domains": ["not a domain"]})
    assert (
        b"payloadFile" in upload.calls.last.request.content
        and b"bad.example.com" in upload.calls.last.request.content
    )
    body = json.loads(rule.calls.last.request.content)
    assert body["action"] == "NXDOMAIN" and body["dnsLists"]["objects"][0]["id"] == "l1"

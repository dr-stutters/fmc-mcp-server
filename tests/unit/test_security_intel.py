"""F21 Security Intelligence block/unblock."""

import json

import httpx
import pytest
import respx
from fastmcp import Client
from stutters_mcp_core import InvalidRequest

from fmc_mcp.server import create_server
from fmc_mcp.tools.security_intel import classify

from .conftest import CFG, items, make_settings

ACP = {"id": "00000000-0000-0ed3-0000-021474847655", "name": "acp", "type": "AccessPolicy"}
SI_PATH = f"{CFG}/policy/accesspolicies/{ACP['id']}/securityintelligencepolicies"
SI = {
    "id": "si1",
    "type": "SecurityIntelligencePolicy",
    "networks": {
        "blocklist": [{"network": {"id": "g", "name": "Global Block List", "type": "SINetworkList"}}]
    },
    "urls": {"blocklist": []},
}


def test_classify() -> None:
    assert classify("10.1.1.1") == ("host", "10.1.1.1")
    assert classify("10.1.1.7/24") == ("network", "10.1.1.0/24")
    assert classify("10.1.1.7/32") == ("host", "10.1.1.7")
    assert classify("bad.example.com") == ("url", "bad.example.com")
    with pytest.raises(InvalidRequest):
        classify("not a thing")


async def test_block_adds_object_to_si_list(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    fmc.get(SI_PATH).mock(return_value=items([SI]))
    fmc.get(f"{SI_PATH}/si1").mock(return_value=httpx.Response(200, json=SI))
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([]))
    fmc.post(f"{CFG}/object/hosts").mock(
        return_value=httpx.Response(201, json={"id": "h1", "type": "Host", "name": "mcp-si-203.0.113.7"})
    )
    put = fmc.put(f"{SI_PATH}/si1").mock(
        side_effect=lambda req: httpx.Response(200, json=json.loads(req.content))
    )
    args = {"policy": "acp", "entries": ["203.0.113.7"]}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        r = await c.call_tool("fmc_si_block", args)
        preview = r.structured_content
        assert preview and preview["preview"]["deploy_needed"] is True
        await c.call_tool("fmc_si_block", {**args, "confirm": preview["confirm"]})
    names = [
        x["network"]["name"] for x in json.loads(put.calls.last.request.content)["networks"]["blocklist"]
    ]
    assert names == ["Global Block List", "mcp-si-203.0.113.7"]

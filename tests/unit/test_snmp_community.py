"""fmc_configure_snmp checks the community before sending it (F80 #175, W6N live-A finding).

FMC 10.0.1 answered a community with '-' with a 400 that echoed the value ("Invalid Community String: ...
alphanumeric string of up to 32 characters; spaces and special characters are not permitted."), after the
preview had passed. Recorded live: tests/fixtures/snmp_settings_fmc10.json.
"""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, fixture, items, make_settings

FX = fixture("snmp_settings_fmc10")
CUR = {k: v for k, v in FX["snmpsettings_v2c"].items() if k != "_source"}
PSID = CUR["id"]
PS = {"id": PSID, "name": "mcp-w6-ps", "type": "FTDPlatformSettingsPolicy"}
BASE = f"{CFG}/policy/ftdplatformsettingspolicies/{PSID}"


def mocks(fmc: respx.MockRouter) -> respx.Route:
    fmc.get(f"{CFG}/policy/ftdplatformsettingspolicies").mock(return_value=items([PS]))
    fmc.get(f"{BASE}/snmpsettings").mock(return_value=items([CUR]))
    fmc.get(f"{BASE}/snmpsettings/{PSID}").mock(return_value=httpx.Response(200, json=CUR))
    return fmc.put(f"{BASE}/snmpsettings/{PSID}").mock(return_value=httpx.Response(200, json=CUR))


async def call(args: dict[str, Any]) -> Any:
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        r = await c.call_tool("fmc_configure_snmp", args)
        return r.structured_content


def test_recorded_shape() -> None:
    assert CUR["communityString"] == "********" == CUR["snmpMgmtHosts"][0]["communityString"]
    assert "alphanumeric string of up to 32 characters" in FX["put_refused"]["description"]


@pytest.mark.parametrize(
    "community",
    ["mcp-w6-test-comm", "has space", "under_score", "a" * 33, "café"],
)
async def test_a_community_fmc_refuses_is_blocked_in_the_preview(
    fmc: respx.MockRouter, community: str
) -> None:
    put = mocks(fmc)
    out = await call({"policy": "mcp-w6-ps", "location": "dc1", "community": community})
    assert out["status"] == "blocked"
    assert any("1 to 32 letters and digits" in b for b in out["blockers"])
    assert community not in json.dumps(out)  # the value is never echoed
    assert put.call_count == 0


async def test_an_alphanumeric_community_passes(fmc: respx.MockRouter) -> None:
    put = mocks(fmc)
    args = {"policy": "mcp-w6-ps", "location": "dc1", "community": "mcpw6Test42"}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        p = (await c.call_tool("fmc_configure_snmp", args)).structured_content
        assert p["status"] == "preview", p
        await c.call_tool("fmc_configure_snmp", {**args, "confirm": p["confirm"]})
    body = json.loads(put.calls.last.request.content)
    assert body["communityString"] == "mcpw6Test42" == body["snmpMgmtHosts"][0]["communityString"]
    out = await call({"policy": "mcp-w6-ps", "location": "dc2", "community": "a" * 32})  # the longest
    assert out["status"] == "preview"

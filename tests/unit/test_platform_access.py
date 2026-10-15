"""F24 NTP / SNMP / SSH access writes."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, items, make_settings

PSID = "00000000-0000-0ed3-0000-021474873072"
PS = {"id": PSID, "name": "ps", "type": "FTDPlatformSettingsPolicy"}
BASE = f"{CFG}/policy/ftdplatformsettingspolicies/{PSID}"
ZONE = {"id": "z1", "name": "inside", "type": "SecurityZone"}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def base_mocks(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/ftdplatformsettingspolicies").mock(return_value=items([PS]))


async def test_ntp_servers(fmc: respx.MockRouter) -> None:
    base_mocks(fmc)
    cur = {"id": PSID, "type": "NTPSetting", "ntpMode": "SYNC_VIA_MGMT_CENTER_NTP"}
    fmc.get(f"{BASE}/ntpsettings").mock(return_value=items([cur]))
    fmc.get(f"{BASE}/ntpsettings/{PSID}").mock(return_value=httpx.Response(200, json=cur))
    put = fmc.put(f"{BASE}/ntpsettings/{PSID}").mock(return_value=httpx.Response(200, json=cur))
    args = {"policy": "ps", "servers": ["10.0.0.123"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_ntp", args)
        await run(c, "fmc_configure_ntp", {**args, "confirm": p["confirm"]})
    body = json.loads(put.calls.last.request.content)
    assert body["ntpMode"] == "SYNC_VIA_NTP_SERVER" and body["ntpServerInfos"] == ["10.0.0.123"]


async def test_snmp_masked_community_must_be_given(fmc: respx.MockRouter) -> None:
    base_mocks(fmc)
    cur = {
        "id": PSID,
        "type": "FTDSNMPPlatformSettings",
        "enableSNMPServers": True,
        "communityString": "**********",
        "snmpMgmtHosts": [
            {
                "ipAddress": {"id": "h", "name": "nms", "type": "Host"},
                "snmpVersion": "SNMPv2c",
                "communityString": "*****",
            }
        ],
    }
    fmc.get(f"{BASE}/snmpsettings").mock(return_value=items([cur]))
    fmc.get(f"{BASE}/snmpsettings/{PSID}").mock(return_value=httpx.Response(200, json=cur))
    put = fmc.put(f"{BASE}/snmpsettings/{PSID}").mock(return_value=httpx.Response(200, json=cur))
    async with Client(server()) as c:
        blocked = await run(c, "fmc_configure_snmp", {"policy": "ps", "location": "dc1"})
        assert blocked["status"] == "blocked" and "masks" in blocked["blockers"][0]
        args = {"policy": "ps", "location": "dc1", "community": "s3cret"}
        p = await run(c, "fmc_configure_snmp", args)
        assert "s3cret" not in json.dumps(p)
        await run(c, "fmc_configure_snmp", {**args, "confirm": p["confirm"]})
    body = json.loads(put.calls.last.request.content)
    assert body["communityString"] == "s3cret" and body["snmpMgmtHosts"][0]["communityString"] == "s3cret"
    assert body["location"] == "dc1"


async def test_ssh_allow(fmc: respx.MockRouter) -> None:
    base_mocks(fmc)
    fmc.get(f"{BASE}/sshaccesssettings").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/securityzones").mock(return_value=items([ZONE]))
    fmc.get(f"{CFG}/object/interfacegroups").mock(return_value=items([]))
    post = fmc.post(f"{BASE}/sshaccesssettings").mock(return_value=httpx.Response(201, json={"id": "s1"}))
    args = {"policy": "ps", "action": "allow", "network": "10.9.0.0/16", "interfaces": ["inside"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_configure_ssh_access", args)
        assert p["status"] == "preview", p
        await run(c, "fmc_configure_ssh_access", {**args, "confirm": p["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["ipAddress"] == {"literal": "10.9.0.0/16"} and body["interfaces"]["objects"][0]["id"] == "z1"

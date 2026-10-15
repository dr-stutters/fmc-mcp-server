"""Platform settings (F3), with payload shapes recorded from FMC 10.0.1."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, empty, items, make_settings

PID = "00000000-0000-0ed3-0000-021474873072"
PS = f"{CFG}/policy/ftdplatformsettingspolicies"
BASE = f"{PS}/{PID}"
ZONE = {"id": "4fcc07ce-c7e9-11f1-88b7-6dea5174bd84", "name": "mcp-test-ftd-in", "type": "SecurityZone"}
SERVERS = {
    "type": "Server",
    "id": PID,
    "allowUserTrafficWhenDown": True,
    "messageSizeQueue": "512",
    "servers": [
        {
            "ipAddress": {"literal": "10.99.1.10"},
            "protocol": "UDP",
            "port": "514",
            "isMgmtReachable": False,
            "logMessagesInEMBLEM": False,
            "secureSyslog": False,
            "interfaces": {"objects": [ZONE]},
        }
    ],
}
BASIC = {
    "type": "BasicLoggingSetup",
    "id": PID,
    "enableLogging": False,
    "internalBuffMemSizeInBytes": 4096,
    "loggingToFMCType": "VPN",
    "maxFlashForLoggingInKB": 3076,
    "minFreePreservedSpaceInKB": 1024,
}
SETTINGS = {"type": "SyslogSetting", "id": PID, "facility": "LOCAL4"}
DEST = {
    "type": "LoggingDestination",
    "id": "00000000-0000-0ed3-0000-021474873153",
    "loggingDestination": "SYSLOG_SERVERS",
    "allEventConfig": {"filterCriteria": "SEVERITY", "value": "INFO"},
}


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


@pytest.fixture
def ps(fmc: respx.MockRouter) -> respx.MockRouter:
    fmc.get(PS).mock(
        return_value=items([{"id": PID, "name": "mcp-test-ps", "type": "FTDPlatformSettingsPolicy"}])
    )
    fmc.get(f"{BASE}/syslog/servers").mock(return_value=items([SERVERS]))
    fmc.get(f"{BASE}/syslog/basicloggingsetups").mock(return_value=items([BASIC]))
    fmc.get(f"{BASE}/syslog/syslogsettings").mock(return_value=items([SETTINGS]))
    fmc.get(f"{BASE}/syslog/loggingdestinations").mock(return_value=items([DEST]))
    fmc.get(f"{BASE}/syslog/eventlists").mock(return_value=empty())
    fmc.get(f"{BASE}/sshaccesssettings").mock(return_value=empty())
    fmc.get(f"{BASE}/ntpsettings").mock(
        return_value=items([{"type": "NTPSetting", "ntpMode": "SYNC_VIA_MGMT_CENTER_NTP"}])
    )
    fmc.get(f"{BASE}/snmpsettings").mock(
        return_value=items(
            [{"type": "FTDSNMPPlatformSettings", "enableSNMPServers": True, "readCommunity": "s3cret"}]
        )
    )
    for sub in ("httpaccesssettings", "bannersettings", "dnssettings"):
        fmc.get(f"{BASE}/{sub}").mock(return_value=items([{"type": "X", "id": PID}]))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items([{"policy": {"id": PID}, "targets": [{"id": "d", "name": "mcp-ftd1"}]}])
    )
    fmc.get(f"{CFG}/object/securityzones").mock(return_value=items([ZONE]))
    return fmc


async def test_summary(ps: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_get_platform_settings", {"policy": "mcp-test-ps"})
    sl = out["syslog"]
    assert out["assigned_to"] == ["mcp-ftd1"]
    assert sl["servers"][0] == {
        "host": "10.99.1.10",
        "protocol": "UDP",
        "port": "514",
        "via": ["mcp-test-ftd-in"],
        "emblem": None,
        "secure": None,
    }
    assert sl["destinations"][0]["all_events"] == "SEVERITY INFO" and sl["send_to_fmc"] == "VPN"
    assert "s3cret" not in json.dumps(out)


async def test_configure_syslog_steps(ps: respx.MockRouter) -> None:
    put_servers = ps.put(f"{BASE}/syslog/servers/{PID}").mock(return_value=httpx.Response(200, json={}))
    put_basic = ps.put(f"{BASE}/syslog/basicloggingsetups/{PID}").mock(
        return_value=httpx.Response(200, json={})
    )
    put_dest = ps.put(f"{BASE}/syslog/loggingdestinations/{DEST['id']}").mock(
        return_value=httpx.Response(200, json={})
    )
    args = {
        "policy": "mcp-test-ps",
        "add_servers": ["10.99.1.20"],
        "remove_servers": ["10.99.1.10"],
        "protocol": "TCP",
        "port": 1470,
        "interfaces": ["mcp-test-ftd-in"],
        "logging_enabled": True,
        "server_level": "WARNING",
    }
    async with Client(server()) as c:
        preview = await run(c, "fmc_configure_syslog", args)
        assert set(preview["preview"]["changes"]) == {"servers", "basic_logging", "syslog_destination"}
        done = await run(c, "fmc_configure_syslog", {**args, "confirm": preview["confirm"]})
    assert done["result"]["applied"] == ["servers", "basic_logging", "destination"]
    servers = json.loads(put_servers.calls.last.request.content)["servers"]
    assert [s["ipAddress"] for s in servers] == [{"literal": "10.99.1.20"}]
    assert servers[0]["interfaces"]["objects"][0]["id"] == ZONE["id"] and servers[0]["port"] == "1470"
    basic = json.loads(put_basic.calls.last.request.content)
    assert basic["enableLogging"] is True and basic["loggingToFMCLogLevel"] == "ERR"  # FMC 10.0.1 quirk
    assert json.loads(put_dest.calls.last.request.content)["allEventConfig"]["value"] == "WARNING"


async def test_configure_syslog_blockers(ps: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_configure_syslog",
            {"policy": "mcp-test-ps", "add_servers": ["10.99.1.10"], "via_management": True},
        )
        assert out["status"] == "blocked" and "already configured" in " ".join(out["blockers"])
        r = await c.call_tool(
            "fmc_configure_syslog",
            {"policy": "mcp-test-ps", "add_servers": ["10.99.1.30"]},
            raise_on_error=False,
        )
        assert r.is_error  # needs interfaces or via_management


async def test_access_logging(fmc: respx.MockRouter) -> None:
    acp = {"id": "00000000-0000-0ed3-0000-021474847655", "name": "mcp-test-ftd-acp", "type": "AccessPolicy"}
    cur = {
        "type": "LoggingSetting",
        "id": "ls1",
        "syslogConfigFromPlatformSetting": False,
        "enableipsSyslog": False,
    }
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([acp]))
    fmc.get(f"{CFG}/policy/accesspolicies/{acp['id']}/loggingsettings").mock(return_value=items([cur]))
    put = fmc.put(f"{CFG}/policy/accesspolicies/{acp['id']}/loggingsettings/ls1").mock(
        return_value=httpx.Response(200, json={})
    )
    args = {"policy": acp["name"], "use_platform_syslog": True, "severity": "INFO", "ips_syslog": True}
    async with Client(server()) as c:
        r = await c.call_tool(
            "fmc_set_access_logging", {"policy": acp["name"], "ips_syslog": True}, raise_on_error=False
        )
        assert r.is_error
        preview = await run(c, "fmc_set_access_logging", args)
        await run(c, "fmc_set_access_logging", {**args, "confirm": preview["confirm"]})
    body = json.loads(put.calls.last.request.content)
    assert body["syslogConfigFromPlatformSetting"] and body["ipsSyslogSeverity"] == "INFO"

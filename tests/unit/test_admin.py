"""F14 admin operations (shapes recorded from FMC 10.0.1)."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools.admin import _with_thresholds

from .conftest import CFG, items, make_settings

DEV = {"id": "2c11eaca-c7e3-11f1-a7ce-a8b537b1b4bb", "name": "ftd1", "type": "Device", "sw_version": "10.0.0"}
HP_ID = "1114175a-2eca-11f1-bc1d-b8e359adb5f3"
CPU = {
    "moduleId": "hm_cpu",
    "enabled": True,
    "type": "FMC_FTD",
    "criticalThreshold": 90,
    "warningThreshold": 80,
    "alertConfig": [
        {
            "name": "alert_cpu_lina",
            "enabled": True,
            "thresholds": [{"type": "red", "value": 90}, {"type": "yellow", "value": 80}],
        },
        {
            "name": "alert_cpu",
            "enabled": False,
            "thresholds": [{"type": "red", "value": 95}, {"type": "yellow", "value": 85}],
        },
    ],
}
HP = {
    "id": HP_ID,
    "name": "Initial_Health_Policy",
    "type": "HealthPolicy",
    "policyType": "DevicePolicy",
    "healthModules": [CPU],
}
HOST = {
    "id": "00000000-0000-0ed3-0000-021474837221",
    "name": "h1",
    "type": "Host",
    "value": "10.9.9.9",
    "overridable": False,
}


def server(**kw: Any) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, **kw))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def test_alert_thresholds_follow_module_thresholds() -> None:
    out = _with_thresholds(CPU, {**CPU, "warningThreshold": 70})
    assert out["warningThreshold"] == 70
    lina, other = out["alertConfig"]
    assert {"type": "yellow", "value": 70} in lina["thresholds"]  # equalled the old 80
    assert {"type": "yellow", "value": 85} in other["thresholds"]  # its own value: kept


async def test_no_backup_file_is_an_empty_list(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/backup/files").mock(
        return_value=httpx.Response(400, json={"error": {"messages": [{"description": "File not found."}]}})
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_list_backups", {"response_format": "json"})
    assert out["results"] == []


async def test_update_health_policy(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/healthpolicies").mock(return_value=items([HP]))
    fmc.get(f"{CFG}/policy/healthpolicies/{HP_ID}").mock(return_value=httpx.Response(200, json=HP))
    put = fmc.put(f"{CFG}/policy/healthpolicies/{HP_ID}").mock(return_value=httpx.Response(200, json=HP))
    args = {"policy": "Initial_Health_Policy", "module": "hm_cpu", "warning": 70}
    async with Client(server()) as c:
        preview = await run(c, "fmc_update_health_policy", args)
        assert preview["preview"]["from"]["warning"] == 80 and preview["preview"]["to"]["warning"] == 70
        await run(c, "fmc_update_health_policy", {**args, "confirm": preview["confirm"]})
        bad = await run(c, "fmc_update_health_policy", {**args, "warning": 95})
    sent = json.loads(put.calls.last.request.content)["healthModules"][0]
    assert sent["warningThreshold"] == 70 and sent["criticalThreshold"] == 90
    assert bad["status"] == "blocked" and "above critical" in bad["blockers"][0]


async def test_set_object_override_makes_overridable(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([HOST]))
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get(f"{CFG}/object/hosts/{HOST['id']}/overrides").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/hosts/{HOST['id']}").mock(return_value=httpx.Response(200, json=HOST))
    put = fmc.put(f"{CFG}/object/hosts/{HOST['id']}").mock(return_value=httpx.Response(200, json=HOST))
    args = {"object": "h1", "type": "host", "device": "ftd1", "value": "10.9.9.8"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_set_object_override", args)
        assert preview["preview"]["makes_overridable"] is True
        await run(c, "fmc_set_object_override", {**args, "confirm": preview["confirm"]})
    first, second = (json.loads(call.request.content) for call in put.calls)
    assert first == {"id": HOST["id"], "type": "Host", "name": "h1", "value": "10.9.9.9", "overridable": True}
    assert second["value"] == "10.9.9.8" and second["overrides"]["target"]["id"] == DEV["id"]


async def test_list_users_explains_missing_permission(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/users/users").mock(
        return_value=httpx.Response(
            403, json={"error": {"messages": [{"description": "The user is not authorized"}]}}
        )
    )
    async with Client(server()) as c:
        r = await c.call_tool("fmc_list_users", {}, raise_on_error=False)
    assert r.is_error and "User Management" in r.content[0].text  # type: ignore[union-attr]


async def test_upgrade_status_merges_history(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get("/api/fmc_platform/v1/updates/deviceupgradeinfo").mock(
        return_value=items(
            [
                {
                    "deviceInfo": [
                        {
                            "device": {"id": DEV["id"]},
                            "maintenanceMode": True,
                            "upgradeHistory": [{"version": "10.0.0-140", "upgradeTime": -1}],
                        }
                    ]
                }
            ]
        )
    )
    fmc.get("/api/fmc_platform/v1/updates/upgradepackages").mock(return_value=httpx.Response(500, json={}))
    async with Client(server()) as c:
        out = await run(c, "fmc_upgrade_status", {"response_format": "json"})
    assert out["devices"][0]["upgrade_history"] == ["10.0.0-140"] and out["devices"][0]["maintenance_mode"]
    assert any("upgrade packages unavailable" in n for n in out["notes"])

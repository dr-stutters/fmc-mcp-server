"""On-demand activity lookups (F5): health alerts over a window and the merged timeline."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools.activity import clean_details, collapse_alerts

from .conftest import CFG, items, make_settings

DEV = {"id": "2c11eaca-c7e3-11f1-a7ce-a8b537b1b4bb", "name": "mcp-ftd1", "type": "Device"}
PLATFORM_AUDIT = "/api/fmc_platform/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/audit/auditrecords"


def alert(
    ts: int, status: str, details: str, module: str = "APPLIANCE_HEARTBEAT", dev: str = DEV["id"]
) -> dict[str, Any]:
    return {
        "deviceUUID": dev,
        "moduleID": module,
        "timestamp": ts,
        "status": status,
        "details": details,
        "type": "Alert",
    }


def test_clean_details() -> None:
    assert (
        clean_details("2 failed:<p><ul><li>* DNS &quot;<b>x</b>&quot;</li></ul></p>")
        == '2 failed: * DNS " x "'
    )


def test_collapse_alerts_merges_repeats_and_marks_changes() -> None:
    raw = [
        alert(100, "YELLOW", "no reply 1 min"),
        alert(160, "RED", "no reply 2 min"),
        alert(220, "RED", "no reply 2 min"),
        alert(280, "RECOVERED", "ok"),
        alert(100, "RED", "4 failed: * a * b", module="HM_TALOSAGENT", dev="0"),
        alert(400, "RED", "4 failed: * b * a", module="HM_TALOSAGENT", dev="0"),  # same items, other order
    ]
    rows = collapse_alerts(raw, {DEV["id"]: "mcp-ftd1"})
    by = {(r["module"], r["status"]): r for r in rows}
    red = by[("APPLIANCE_HEARTBEAT", "RED")]
    assert red["count"] == 2 and red["changed_from"] == "YELLOW" and red["device"] == "mcp-ftd1"
    assert by[("APPLIANCE_HEARTBEAT", "RECOVERED")]["changed_from"] == "RED"
    assert by[("HM_TALOSAGENT", "RED")]["count"] == 2 and by[("HM_TALOSAGENT", "RED")]["device"] == "FMC"
    assert rows[0]["module"] == "HM_TALOSAGENT"  # newest last_seen first


def _alerts_route(fmc: respx.MockRouter, rows: list[dict[str, Any]]) -> respx.Route:
    def handler(request: httpx.Request) -> httpx.Response:
        off = int(request.url.params.get("offset", 0))
        lim = int(request.url.params.get("limit", 25))
        return httpx.Response(200, json={"items": rows[off : off + lim], "paging": {"count": len(rows)}})

    return fmc.get(f"{CFG}/health/alerts").mock(side_effect=handler)


async def test_list_health_alerts_filters_and_reads_tail(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    route = _alerts_route(fmc, [alert(100 + i, "RED", "x") for i in range(3)])
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool("fmc_list_health_alerts", {"device": "mcp-ftd1", "response_format": "json"})
    out = r.structured_content or json.loads(r.content[0].text)  # type: ignore[union-attr]
    assert out["results"][0]["count"] == 3 and out["raw_alerts"] == 3
    f = route.calls.last.request.url.params["filter"]
    assert f"deviceUUIDs:{DEV['id']},0" in f and "status:RED,YELLOW" in f and "startTime:" in f


async def test_recent_activity_merges_and_survives_a_failing_source(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    _alerts_route(
        fmc, [alert(1_800_000_000, "RED", "Appliance mcp-ftd1 is not sending heartbeats.", dev="0")]
    )
    fmc.get(PLATFORM_AUDIT).mock(
        return_value=items(
            [
                {
                    "time": 1_800_000_100,
                    "username": "admin",
                    "subSystem": "Access Control",
                    "message": "Rule edited",
                },
                {"time": 1_800_000_050, "username": "admin", "subSystem": "API", "message": "GET https://x"},
                {
                    "time": 1_800_000_040,
                    "username": "admin",
                    "subSystem": "Session Expiration",
                    "message": "New session",
                },
            ]
        )
    )
    fmc.get(f"{CFG}/deployment/jobhistories").mock(
        return_value=httpx.Response(500, json={"error": {"messages": [{"description": "boom"}]}})
    )
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool("fmc_recent_activity", {"response_format": "json"})
    out = r.structured_content or json.loads(r.content[0].text)  # type: ignore[union-attr]
    assert [x["source"] for x in out["results"]] == ["audit", "health"]
    assert out["results"][1]["device"] == "FMC"
    assert "deploy" in out["errors"]

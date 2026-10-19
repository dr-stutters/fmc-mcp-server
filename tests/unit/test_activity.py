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


def _audit_route(fmc: respx.MockRouter, recs: list[dict[str, Any]]) -> respx.Route:
    """FMC 10.0.1 behaviour: the newest 100 records in [starttime, endtime], nothing past offset 100."""

    def handler(request: httpx.Request) -> httpx.Response:
        p = request.url.params
        lo = int(p["starttime"])
        hi = int(p.get("endtime", 10**12))
        sel = sorted((r for r in recs if lo <= r["time"] <= hi), key=lambda r: -r["time"])[:100]
        if int(p.get("offset", 0)) >= 100:
            sel = []
        return httpx.Response(200, json={"items": sel, "paging": {"count": len(sel)}})

    return fmc.get(PLATFORM_AUDIT).mock(side_effect=handler)


def _rec(i: int, t: int, msg: str, sub: str = "API", user: str = "mcp") -> dict[str, Any]:
    return {"auditId": f"a{i}", "time": t, "subSystem": sub, "message": msg, "username": user}


async def test_audit_records_read_the_whole_window_past_fmcs_100_cap(fmc: respx.MockRouter) -> None:
    import time as _t

    now = int(_t.time())
    recs = [
        _rec(0, now - 3000, "Save Policy mcp-test-acp:12", "Policies > Access Control > Policy Editor", "bob")
    ]
    recs += [
        _rec(i, now - 2900 + i, "GET https://f/api/fmc_config/v1/domain/x-1/object/hosts OK (200)")
        for i in range(1, 350)
    ]
    route = _audit_route(fmc, recs)
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool(
            "fmc_list_audit_records", {"text": "mcp-test-acp", "since_minutes": 60, "response_format": "json"}
        )
    out = r.structured_content or json.loads(r.content[0].text)  # type: ignore[union-attr]
    assert [x["user"] for x in out["results"]] == ["bob"]
    assert out["records_read"] == 350 and "note" not in out
    assert any("endtime" in call.request.url.params for call in route.calls)


async def test_audit_records_cap_reports_coverage(fmc: respx.MockRouter) -> None:
    import time as _t

    from fmc_mcp import audit

    now = int(_t.time())
    _audit_route(fmc, [_rec(i, now - 5000 + i, "GET x") for i in range(5000)])
    audit_pages, audit.AUDIT_MAX_PAGES = audit.AUDIT_MAX_PAGES, 3
    try:
        scan = None
        async with Client(create_server(make_settings())) as c:
            r = await c.call_tool("fmc_list_audit_records", {"since_minutes": 120, "response_format": "json"})
            scan = r.structured_content or json.loads(r.content[0].text)  # type: ignore[union-attr]
    finally:
        audit.AUDIT_MAX_PAGES = audit_pages
    assert scan["results"] == []  # all reads, skipped by default
    assert "read back to" in scan["note"] and scan["records_read"] >= 290


async def test_audit_logins_are_listed_when_asked_for(fmc: respx.MockRouter) -> None:
    import time as _t

    now = int(_t.time())
    _audit_route(fmc, [_rec(1, now - 10, "Login Success", "Login", "alice"), _rec(2, now - 5, "GET x")])
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool("fmc_list_audit_records", {"subsystem": "Login", "response_format": "json"})
    out = r.structured_content or json.loads(r.content[0].text)  # type: ignore[union-attr]
    assert [x["user"] for x in out["results"]] == ["alice"]


def test_condense_audit_drops_echo_rows() -> None:
    from fmc_mcp.tools.activity import condense_audit

    recs = [
        _rec(1, 100, "Save Policy acp:3", "Policies > Access Control > Policy Editor"),
        _rec(2, 100, "PUT https://f/api/fmc_config/v1/domain/d-1/policy/accesspolicies/1 OK (200)"),
        _rec(3, 90, "DELETE https://f/api/fmc_config/v1/domain/d-1/policy/dnspolicies/1/dnsrules/2 OK (200)"),
        _rec(
            4, 80, "POST https://f/api/fmc_config/v1/domain/d-1/deployment/deploymentrequests Accepted (202)"
        ),
        _rec(5, 81, "Policy Deployment to ftd1 - SUCCESS", "Task Queue"),
    ]
    kept = [r["auditId"] for r in condense_audit(recs, deploy_ok=True)]
    assert kept == ["a1", "a3"]
    assert [r["auditId"] for r in condense_audit(recs, deploy_ok=False)] == ["a1", "a3", "a4", "a5"]


def test_condense_audit_keeps_unrelated_and_failed_writes() -> None:
    from fmc_mcp.tools.activity import condense_audit

    recs = [
        _rec(1, 100, "Login Success", "Login"),
        _rec(2, 100, "POST https://f/api/fmc_config/v1/domain/d-1/object/hosts Created (201)"),
        _rec(3, 50, "Save Policy acp:3", "Policies > Access Control > Policy Editor"),
        _rec(4, 50, "PUT https://f/api/fmc_config/v1/domain/d-1/policy/accesspolicies/1 Bad Request (400)"),
        _rec(
            5,
            40,
            "POST https://f/api/fmc_config/v1/domain/d-1/deployment/deploymentrequests Bad Request (422)",
        ),
    ]
    assert [r["auditId"] for r in condense_audit(recs, deploy_ok=True)] == ["a1", "a2", "a3", "a4", "a5"]


async def test_packet_tracer_runs_are_not_changes(fmc: respx.MockRouter) -> None:
    """#201: FMC logs each packet-tracer run under Devices > Troubleshoot > Packet Tracer (recorded on FMC
    10.0.1); it changes nothing, so it is a read, and with include_audit_reads it names its device."""
    import time

    from fmc_mcp.audit import device_in, is_read

    from .conftest import fixture

    trace = {**fixture("audit_packet_tracer")["record"], "time": int(time.time()) - 120}
    assert is_read(trace) and device_in(trace) == "mcp-ftd1"
    edit = {"time": int(time.time()) - 60, "username": "admin", "subSystem": "Access Control", "message": "x"}
    fmc.get(PLATFORM_AUDIT).mock(return_value=items([edit, trace]))
    _alerts_route(fmc, [])
    fmc.get(f"{CFG}/deployment/jobhistories").mock(return_value=items([]))
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool("fmc_recent_activity", {"response_format": "json"})
        out = r.structured_content or json.loads(r.content[0].text)  # type: ignore[union-attr]
        assert [x["summary"] for x in out["results"]] == ["Access Control: x"]
        r = await c.call_tool("fmc_recent_activity", {"response_format": "json", "include_audit_reads": True})
        out = r.structured_content or json.loads(r.content[0].text)  # type: ignore[union-attr]
    traced = [x for x in out["results"] if "packet-tracer" in x["summary"]]
    assert len(traced) == 1 and traced[0]["device"] == "mcp-ftd1"

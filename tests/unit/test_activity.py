"""On-demand activity lookups (F5): health alerts over a window and the merged timeline."""

import json
import re
import time
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp import audit
from fmc_mcp.audit import is_read
from fmc_mcp.server import create_server
from fmc_mcp.tools.activity import clean_details, collapse_alerts, status_changes

from .conftest import CFG, fixture, items, make_settings

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


def _like(pattern: str, value: str) -> bool:
    """FMC 10.0.1's `subsystem` filter: SQL LIKE on the whole name, case-insensitive (checked live)."""
    rx = "".join(".*" if ch == "%" else "." if ch == "_" else re.escape(ch) for ch in pattern)
    return re.fullmatch(rx, value, re.I | re.S) is not None


def _audit_route(fmc: respx.MockRouter, recs: list[dict[str, Any]], like: bool = True) -> respx.Route:
    """FMC 10.0.1 behaviour: the newest 100 records in [starttime, endtime], nothing past offset 100;
    `subsystem` filters (SQL LIKE; like=False: an FMC matching whole names only), `username` and
    `source` are ignored."""

    def match(sub: str | None, value: str) -> bool:
        if sub is None:
            return True
        return _like(sub, value) if like else sub.lower() == value.lower()

    def handler(request: httpx.Request) -> httpx.Response:
        p = request.url.params
        lo = int(p["starttime"])
        hi = int(p.get("endtime", 10**12))
        sub = p.get("subsystem")
        sel = sorted(
            (r for r in recs if lo <= r["time"] <= hi and match(sub, str(r.get("subSystem", "")))),
            key=lambda r: -r["time"],
        )[:100]
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


# --- #201: health repeats, #203: the audit window on a busy FMC ------------------------------------------


AUDIT10 = fixture("audit_fmc10")
TALOS = fixture("health_talosagent_flap")["items"]


def _out(r: Any) -> Any:
    return r.structured_content or json.loads(r.content[0].text)  # type: ignore[union-attr]


def test_fmc10_reads_and_changes_are_told_apart() -> None:
    """Recorded FMC 10.0.1 records: page views carry the page's UI path as subsystem ('Policies > Security
    policies > Access Control > Policy Editor', message 'Page View'), so they are reads like API GETs,
    logins, 'View ...' and packet-tracer runs; worded saves, creates, deletes and deployments are not."""
    recs = AUDIT10["changes"] + AUDIT10["unfiltered"]
    reads = {r["message"][:40] for r in recs if is_read(r)}
    kept = {r["message"][:40] for r in recs if not is_read(r)}
    assert "Page View" in reads and "Login Success" in reads and "View url filtering settings" in reads
    assert any(m.startswith("Trace: packet-tracer") for m in reads)
    assert any(m.startswith("GET ") for m in reads)
    assert {
        "Save Policy mcp-fw-threat-acp:587",
        "create mcp-fw-demo-branch-wan:643",
        "Delete Policy mcp-fw-nat",
        "Save mcp-fw-file-av:595",
        "Policy Deployment to mcp-ftd1 - SUCCESS",
    } <= kept
    assert "Page View" not in kept


def test_hit_count_and_cli_subsystems_are_reads() -> None:
    """#201: FMC's operational subsystems (troubleshooting anywhere in the path, hit counts, the CLI)."""
    for sub in (
        "Policies > Security policies > Access Control > Hit Count",
        "Devices > Device Management > Troubleshoot > Threat Defense CLI",
        "Devices > Troubleshoot > Packet Capture",
    ):
        assert is_read({"subSystem": sub, "message": "Refresh"}), sub
    editor = "Policies > Security policies > Access Control > Policy Editor"
    assert not is_read({"subSystem": editor, "message": "Save Policy acp:3"})


def _busy_log(now: int) -> list[dict[str, Any]]:
    """A busy FMC's last 24 hours: 3000 API reads in the newest ~3 hours (agents polling), the recorded
    change records spread over the day (a 'Save Policy mcp-fw-threat-acp' 13 hours ago), page views and
    a deployment."""
    get = AUDIT10["unfiltered"][0]
    recs = [{**get, "time": now - 60 - i * 3, "auditId": f"get{i}"} for i in range(3000)]
    for i, r in enumerate(AUDIT10["changes"]):
        recs.append({**r, "time": now - 3600 * (i + 1) - 13 * 60, "auditId": f"chg{i}"})
    deploy = next(r for r in AUDIT10["unfiltered"] if r["subSystem"] == "Task Queue")
    recs.append({**deploy, "time": now - 20 * 3600, "auditId": "dep"})
    return recs


async def test_who_changed_a_policy_reaches_the_whole_day(fmc: respx.MockRouter) -> None:
    """#203: 3000 API GETs in the newest hours used to stop the read 4 hours back after 25 requests. Now the
    newest 500 records are read in full and the rest of the day through FMC's change subsystems."""
    now = int(time.time())
    route = _audit_route(fmc, _busy_log(now))
    async with Client(create_server(make_settings())) as c:
        out = _out(
            await c.call_tool(
                "fmc_list_audit_records",
                {"text": "mcp-fw-threat-acp", "since_minutes": 1440, "response_format": "json"},
            )
        )
    assert [r["message"] for r in out["results"]] == [
        "Save Policy mcp-fw-threat-acp:627",
        "Save Policy mcp-fw-threat-acp:587",
    ]
    subs = [c.request.url.params.get("subsystem") for c in route.calls]
    assert subs.count(None) == audit.CHANGE_SCAN_PAGES and {"%>%", "Task Queue"} <= set(subs)
    assert len(route.calls) <= audit.CHANGE_SCAN_PAGES + 3
    assert out["reads_skipped"] >= 400  # the 5 slices overlap by a second
    assert "Every audit record was read back to" in out["note"] and "of them reads" in out["note"]


async def test_changes_today_list_deployments_and_object_edits(fmc: respx.MockRouter) -> None:
    now = int(time.time())
    _audit_route(fmc, _busy_log(now))
    async with Client(create_server(make_settings())) as c:
        out = _out(
            await c.call_tool(
                "fmc_list_audit_records", {"since_minutes": 1440, "limit": 100, "response_format": "json"}
            )
        )
    msgs = [r["message"] for r in out["results"]]
    assert "Policy Deployment to mcp-ftd1 - SUCCESS" in msgs and "create mcp-fw-demo-branch-wan:643" in msgs
    assert "Page View" not in msgs and not any(m.startswith("Trace:") for m in msgs)


async def test_subsystem_is_filtered_by_fmc(fmc: respx.MockRouter) -> None:
    """#203: `subsystem` goes to FMC as '%<text>%' (FMC 10.0.1: SQL LIKE, case-insensitive), so the whole
    window is read in one request instead of every record."""
    now = int(time.time())
    route = _audit_route(fmc, _busy_log(now))
    async with Client(create_server(make_settings())) as c:
        out = _out(
            await c.call_tool(
                "fmc_list_audit_records",
                {"subsystem": "nat policy editor", "since_minutes": 1440, "response_format": "json"},
            )
        )
    assert [r["message"] for r in out["results"]] == ["Delete Policy mcp-fw-nat"]
    assert [c.request.url.params["subsystem"] for c in route.calls] == ["%nat policy editor%"]
    assert "note" not in out


async def test_an_fmc_without_like_filters_is_read_as_before(fmc: respx.MockRouter) -> None:
    """An FMC whose `subsystem` filter matches whole names only finds nothing for '%...%': the tools read
    every record and filter here, as before (the coverage note then says how far back they got)."""
    now = int(time.time())
    recs = [{**r, "time": now - 600 - i, "auditId": f"c{i}"} for i, r in enumerate(AUDIT10["changes"])]
    recs += [{**AUDIT10["unfiltered"][0], "time": now - 2000 - i, "auditId": f"g{i}"} for i in range(700)]
    route = _audit_route(fmc, recs, like=False)
    async with Client(create_server(make_settings())) as c:
        out = _out(
            await c.call_tool("fmc_list_audit_records", {"subsystem": "NAT", "response_format": "json"})
        )
        assert [r["message"] for r in out["results"]] == ["Delete Policy mcp-fw-nat"]
        assert route.calls[0].request.url.params["subsystem"] == "%NAT%"
        assert "subsystem" not in route.calls[1].request.url.params
        out = _out(
            await c.call_tool("fmc_list_audit_records", {"text": "threat-acp", "response_format": "json"})
        )
    assert [r["message"] for r in out["results"]] == [
        "Save Policy mcp-fw-threat-acp:627",
        "Save Policy mcp-fw-threat-acp:587",
    ]
    assert out["records_read"] == len(recs) and "note" not in out


async def test_a_user_filter_still_reads_here(fmc: respx.MockRouter) -> None:
    """FMC 10.0.1 ignores `username` on audit/auditrecords (checked live), so the tool doesn't send it."""
    now = int(time.time())
    recs = [_rec(1, now - 30, "Save Policy acp:1", "Policies > x", "bob"), _rec(2, now - 20, "x")]
    route = _audit_route(fmc, recs)
    async with Client(create_server(make_settings())) as c:
        out = _out(await c.call_tool("fmc_list_audit_records", {"user": "bob", "response_format": "json"}))
    assert [r["user"] for r in out["results"]] == ["bob"]
    assert all("username" not in c.request.url.params for c in route.calls)


async def test_recent_activity_reads_changes_past_the_reads(fmc: respx.MockRouter) -> None:
    """fmc_recent_activity shares the change reader: an object edit 50 minutes ago behind 2950 newer GETs."""
    now = int(time.time())
    get = AUDIT10["unfiltered"][0]
    recs = [{**get, "time": now - 30 - i, "auditId": f"g{i}"} for i in range(2950)]
    edit = next(r for r in AUDIT10["changes"] if r["message"].startswith("create"))
    recs.append({**edit, "time": now - 3000, "username": "bob"})
    _audit_route(fmc, recs)
    _alerts_route(fmc, [])
    fmc.get(f"{CFG}/deployment/jobhistories").mock(return_value=items([]))
    async with Client(create_server(make_settings())) as c:
        out = _out(await c.call_tool("fmc_recent_activity", {"response_format": "json"}))
    assert [x["summary"] for x in out["results"]] == [
        "Objects > Object Management > NetworkObject: create mcp-fw-demo-branch-wan:643"
    ]
    assert "Every audit record was read back to" in out["partial"]["audit"]


def test_health_repeats_collapse_on_status_with_newest_details() -> None:
    """#201 (recorded, FMC 10.0.1): HM_TALOSAGENT stays RED while its details alternate between '1 modules
    failed' and '2 modules failed': one row, the newest details, the re-wordings counted, no changed_from."""
    rows = collapse_alerts(TALOS, {})
    assert len(rows) == 1
    row = rows[0]
    assert (row["device"], row["module"], row["status"], row["count"]) == ("FMC", "HM_TALOSAGENT", "RED", 16)
    assert row["changed_from"] is None and row["details_changed"] == 12
    assert row["details"].startswith("2 modules failed")  # the newest alert's


def test_changed_from_only_on_a_status_change() -> None:
    raw = [
        alert(100, "YELLOW", "cpu 85%", module="CPU"),
        alert(400, "RED", "cpu 95%", module="CPU"),
        alert(700, "RED", "cpu 97%", module="CPU"),
        alert(100, "RED", "Talos. Failed. ", module="THREAT_DATA_UPDATES"),
        alert(400, "RED", "Failed. Talos. ", module="THREAT_DATA_UPDATES"),  # same sentences, other order
    ]
    rows = {(r["module"], r["status"]): r for r in collapse_alerts(raw, {})}
    assert rows[("CPU", "YELLOW")]["changed_from"] is None
    red = rows[("CPU", "RED")]
    assert red["changed_from"] == "YELLOW" and red["count"] == 2 and red["details_changed"] == 1
    assert red["details"] == "cpu 97%"
    assert rows[("THREAT_DATA_UPDATES", "RED")]["details_changed"] == 0


def test_status_changes_leave_out_problems_older_than_the_window() -> None:
    start = TALOS[0]["timestamp"] - 100  # the window opens just before a health run
    new_red = [alert(start + 1800 + 300 * i, "RED", "no heartbeat") for i in range(4)]
    flap = [
        alert(start + 600, "RED", "down", module="INTERFACE"),
        alert(start + 900, "RECOVERED", "up", module="INTERFACE"),
    ]
    changed, ongoing = status_changes(TALOS + new_red + flap, {DEV["id"]: "mcp-ftd1"}, start)
    assert [(r["module"], r["status"]) for r in ongoing] == [("HM_TALOSAGENT", "RED")]
    assert {(r["module"], r["status"], r["changed_from"]) for r in changed} == {
        ("APPLIANCE_HEARTBEAT", "RED", None),
        ("INTERFACE", "RED", None),
        ("INTERFACE", "RECOVERED", "RED"),
    }


async def test_recent_activity_lists_health_changes_not_steady_problems(fmc: respx.MockRouter) -> None:
    """#201: the eval's 'what changed in the last hour?' listed HM_TALOSAGENT 'RED -> RED' 7 times."""
    now = int(time.time())
    shift = now - 3500 - TALOS[0]["timestamp"]
    talos = [{**a, "timestamp": a["timestamp"] + shift} for a in TALOS if a["timestamp"] + shift < now]
    beat = "Appliance mcp-ftd1 is not sending heartbeats."
    new_red = [alert(now - 1200 + 300 * i, "RED", beat) for i in range(3)]
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    _alerts_route(fmc, talos + new_red)
    fmc.get(PLATFORM_AUDIT).mock(return_value=items([]))
    fmc.get(f"{CFG}/deployment/jobhistories").mock(return_value=items([]))
    async with Client(create_server(make_settings())) as c:
        out = _out(await c.call_tool("fmc_recent_activity", {"response_format": "json"}))
    assert [(x["source"], x["device"], x["summary"][:23]) for x in out["results"]] == [
        ("health", "mcp-ftd1", "APPLIANCE_HEARTBEAT RED")
    ]
    assert "HM_TALOSAGENT RED on FMC" in out["health_ongoing"]

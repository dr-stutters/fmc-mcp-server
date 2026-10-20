"""F55: fmc_live_connections (syslog buffer, or 'show conn' where FMC allows it) and
fmc_user_identity_sessions (FMC's analysis/activesessions and analysis/useractivity)."""

from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from fmc_mcp._core.testing import call_tool
from fmc_mcp.server import create_server
from fmc_mcp.tools import live, show_commands
from fmc_mcp.tools.live import parse_log_buffer, parse_show_conn_detail

from .conftest import CFG, fixture, items, make_settings

LIVE = fixture("ftd_live")
DEV = fixture("ftd_device")
DEVPATH = f"{CFG}/devices/devicerecords/{DEV['id']}"
CMD = f"{DEVPATH}/operational/commands"
SESSIONS = f"{CFG}/analysis/activesessions"
ACTIVITY = f"{CFG}/analysis/useractivity"


async def call(name: str, args: dict[str, Any]) -> Any:
    return await call_tool(create_server(make_settings()), name, {"response_format": "json", **args})


@pytest.fixture
def ftd(fmc: respx.MockRouter) -> respx.MockRouter:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get(DEVPATH).mock(return_value=httpx.Response(200, json=DEV))
    return fmc


def logging_on(fmc: respx.MockRouter) -> respx.Route:
    return fmc.get(CMD).mock(return_value=httpx.Response(200, json=LIVE["show logging (buffer on)"]))


def denied() -> httpx.Response:
    return httpx.Response(403, json={"error": {"messages": [{"description": "The user is not authorized"}]}})


# --- parsers ---------------------------------------------------------------------------------------


def test_parse_log_buffer_pairs_built_teardown_and_snort_events() -> None:
    text = LIVE["show logging (buffer on)"]["items"][0]["commandOutput"]
    conns, enabled = parse_log_buffer(text)
    assert enabled
    rows = {c.conn_id or f"{c.protocol}:{c.initiator}": c.row() for c in conns}
    web = rows["101"]
    assert web["state"] == "closed"
    assert (web["initiator"], web["responder"]) == ("inside 10.99.1.10:40001", "outside 192.0.2.80:80")
    assert (web["user"], web["rule"], web["action"], web["application"]) == (
        "LAB\\alice",
        "mcp-fw-baseline",
        "Allow",
        "HTTP",
    )
    assert (web["bytes"], web["duration"], web["reason"]) == (1520, "0:00:01", "TCP FINs from inside")
    assert web["started"] == "Oct 18 2026 14:01:02" and web["ended"] == "Oct 18 2026 14:01:03"
    telnet = rows["102"]
    assert telnet["state"] == "open" and "bytes" not in telnet
    dns = rows["103"]  # inbound: the 'for' side opened it
    assert (dns["initiator"], dns["responder"], dns["bytes"]) == (
        "outside 192.0.2.53:5353",
        "inside 10.99.1.11:53",
        96,
    )
    icmp = rows["ICMP:10.99.1.10"]
    assert (icmp["responder"], icmp["state"]) == ("192.0.2.80 type 8", "closed")
    orphan = rows["99"]  # teardown whose 'Built' scrolled out of the buffer
    assert (orphan["state"], orphan["bytes"], orphan["reason"]) == (
        "closed",
        5000,
        "TCP Reset-O from outside",
    )
    assert len(conns) == 5  # the NAT translation line (305011) is not a connection


def test_parse_log_buffer_snort_icmp_event_joins_the_icmp_connection() -> None:
    text = LIVE["show logging (buffer on)"]["items"][0]["commandOutput"]
    text += (
        "Oct 18 2026 14:01:22: %FTD-1-430003: SrcIP: 10.99.1.10, DstIP: 192.0.2.80, SrcPort: 8, DstPort: 0, "
        "Protocol: icmp, AccessControlRuleAction: Allow, AccessControlRuleName: mcp-fw-lab-extra, "
        "InitiatorBytes: 84, ResponderBytes: 84\n"
    )
    conns, _ = parse_log_buffer(text)
    icmp = [c for c in conns if c.protocol.upper().startswith("ICMP")]
    assert len(icmp) == 1 and icmp[0].rule == "mcp-fw-lab-extra" and icmp[0].bytes == 168


def test_parse_log_buffer_off() -> None:
    conns, enabled = parse_log_buffer(LIVE["show logging (buffer off)"]["items"][0]["commandOutput"])
    assert (conns, enabled) == ([], False)


def test_parse_show_conn_detail_real_output() -> None:
    conns = parse_show_conn_detail(LIVE["show conn all detail"])
    assert [c.protocol for c in conns] == ["OSPF", "OSPF", "TCP"]
    bgp = conns[2].row()
    # 'Initiator: 10.99.1.1, Responder: 10.99.1.2' turns the printed order around
    assert (bgp["initiator"], bgp["responder"]) == ("NP Identity Ifc 10.99.1.1:24127", "inside 10.99.1.2:179")
    assert (bgp["flags"], bgp["idle"], bgp["duration"], bgp["bytes"]) == ("UI", "14s", "19m6s", 472)
    assert conns[0].row()["bytes"] == 10040 and "flags" not in conns[0].row()


# --- fmc_live_connections ----------------------------------------------------------------------------


async def test_buffer_off_says_how_to_turn_it_on(ftd: respx.MockRouter) -> None:
    route = ftd.get(CMD).mock(return_value=httpx.Response(200, json=LIVE["show logging (buffer off)"]))
    data = await call("fmc_live_connections", {"device": "mcp-ftd1", "host": "10.99.1.10"})
    assert data["available"] is False and data["results"] == []
    assert "refuses 'show conn'" in data["note"] and "INTERNAL_BUFFER" in data["note"]
    assert route.calls.last.request.url.params["command"] == "show logging"


async def test_host_filter_and_columns(ftd: respx.MockRouter) -> None:
    logging_on(ftd)
    data = await call("fmc_live_connections", {"device": "mcp-ftd1", "host": "10.99.1.10"})
    assert data["source"] == "syslog buffer (show logging)"
    # open connections first ('right now'), then the most recently active
    assert [(r["protocol"], r["state"]) for r in data["results"]] == [
        ("TCP", "open"),
        ("ICMP", "closed"),
        ("TCP", "closed"),
    ]
    assert data["open"] == 1 and data["connections_seen"] == 5
    data = await call("fmc_live_connections", {"device": "mcp-ftd1"})
    assert [r.get("id", r["protocol"]) for r in data["results"]] == ["102", "99", "ICMP", "103", "101"]
    data = await call("fmc_live_connections", {"device": "mcp-ftd1", "host": "10.99.1.0/24", "port": 23})
    assert [r["id"] for r in data["results"]] == ["102"]
    data = await call("fmc_live_connections", {"device": "mcp-ftd1", "protocol": "udp", "state": "closed"})
    assert [r["id"] for r in data["results"]] == ["103"]


async def test_user_filter_uses_sessions_and_log_names(ftd: respx.MockRouter) -> None:
    logging_on(ftd)
    sessions = ftd.get(SESSIONS).mock(return_value=httpx.Response(200, json=LIVE["activesessions"]))
    data = await call("fmc_live_connections", {"device": "mcp-ftd1", "user": "alice"})
    # alice's own connections by name, plus the one from her session IP (10.99.1.12) that names no user
    assert sorted(r.get("id", r["protocol"]) for r in data["results"]) == ["101", "102", "99"]
    assert data["user_ips"] == ["10.99.1.12"]
    assert sessions.calls.last.request.url.params["username"] == "alice"


async def test_user_filter_without_identity_permission(ftd: respx.MockRouter) -> None:
    logging_on(ftd)
    ftd.get(SESSIONS).mock(return_value=denied())
    data = await call("fmc_live_connections", {"device": "mcp-ftd1", "user": "alice"})
    assert sorted(r["id"] for r in data["results"]) == ["101", "102"]
    assert "403" in data["note"] and "Analysis > Users" in data["note"]


async def test_show_conn_used_where_fmc_allows_it(
    ftd: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    newer = show_commands.build("show conn <?-option>, show logging, show version")

    async def allowlist(ctx: Any) -> Any:
        return newer

    monkeypatch.setattr(live, "supported_commands", allowlist)
    route = ftd.get(CMD).mock(return_value=items([{"commandOutput": LIVE["show conn all detail"]}]))
    data = await call("fmc_live_connections", {"device": "mcp-ftd1", "host": "10.99.1.1", "port": 179})
    assert data["source"] == "show conn detail"
    params = route.calls.last.request.url.params
    assert (params["command"], params["parameters"]) == ("show conn", "address 10.99.1.1 port 179 detail")
    assert [r["protocol"] for r in data["results"]] == ["TCP"]


def test_alternatives_point_at_the_new_tools() -> None:
    with pytest.raises(Exception, match="fmc_live_connections"):
        show_commands.check_command("show conn")
    with pytest.raises(Exception, match="fmc_user_identity_sessions"):
        show_commands.check_command("show user-identity user active")


# --- fmc_user_identity_sessions ------------------------------------------------------------------------


async def test_sessions_by_ip_with_history(ftd: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live, "clock", lambda: LIVE["useractivity"]["items"][0]["time"] + 600)
    sessions = ftd.get(SESSIONS).mock(return_value=httpx.Response(200, json=LIVE["activesessions"]))
    activity = ftd.get(ACTIVITY).mock(return_value=httpx.Response(200, json=LIVE["useractivity"]))
    data = await call("fmc_user_identity_sessions", {"ip": "10.99.1.12", "history": True, "hours": 2})
    assert data["results"] == [
        {
            "user": "alice",
            "realm": "LAB",
            "ip": "10.99.1.12",
            "device": "mcp-ftd-identity",
            "authentication": "Passive Authentication",
            "login": "2026-10-18T14:00:00Z",
            "last_seen": "2026-10-18T14:05:00Z",
            "source": "LDAP",
            "email": "alice@lab.example",
            "department": "mcp-staff (lab)",
        }
    ]
    assert sessions.calls.last.request.url.params["currentIP"] == "10.99.1.12"
    p = activity.calls.last.request.url.params
    assert p["ipAddress"] == "10.99.1.12" and p["sort"] == "time:desc" and "time" not in p
    assert data["history"][0]["event"] == "User Login"


INVALID_TIME = {"error": {"category": "VALIDATION", "messages": [{"description": "Invalid time field."}]}}


def activity(at: int | None, event: str = "User Login") -> dict[str, Any]:
    row = {**LIVE["useractivity"]["items"][0], "time": at, "event": event}
    return row if at is not None else {k: v for k, v in row.items() if k != "time"}


async def test_history_window_is_applied_here(ftd: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    """FMC 10.0.1 answers 422 'Invalid time field.' to the spec's time=after:<epoch> filter (live,
    2026-10-19; also after:..,before:.., epoch ms and ISO 8601), so the window is cut from the newest
    events here."""
    now = 1792380000
    monkeypatch.setattr(live, "clock", lambda: now)
    ftd.get(SESSIONS).mock(return_value=items([]))

    def answer(request: httpx.Request) -> httpx.Response:
        if "time" in request.url.params:
            return httpx.Response(422, json=INVALID_TIME)
        rows = [
            activity(now - 7200, "User Logoff"),
            activity(now - 3 * 86400),
            activity(now - 60),
            activity(None),
        ]
        return items(rows)

    route = ftd.get(ACTIVITY).mock(side_effect=answer)
    data = await call("fmc_user_identity_sessions", {"ip": "10.99.1.12", "history": True, "hours": 24})
    assert route.called and "time" not in route.calls.last.request.url.params
    # newest first, the 3-day-old event dropped, the one without a time kept (last)
    assert [(h.get("time"), h["event"]) for h in data["history"]] == [
        ("2026-10-19T03:19:00Z", "User Login"),
        ("2026-10-19T01:20:00Z", "User Logoff"),
        (None, "User Login"),
    ]


@pytest.mark.parametrize(
    ("answer", "expect"),
    [
        (httpx.Response(422, json=INVALID_TIME), "Invalid time field"),
        (httpx.Response(500, json={"error": {"messages": [{"description": "boom"}]}}), "boom"),
        (denied(), "Events & Logs > Analysis > Users"),
    ],
)
async def test_history_failure_keeps_the_sessions(
    ftd: respx.MockRouter, answer: httpx.Response, expect: str
) -> None:
    """#199: FMC refusing the user activity (FMC 10.0.1's 422 'Invalid time field.', a 5xx, a role without
    Analysis > Users) no longer fails the call: the sessions come back with `history_error`."""
    ftd.get(SESSIONS).mock(return_value=httpx.Response(200, json=LIVE["activesessions"]))
    ftd.get(ACTIVITY).mock(return_value=answer)
    data = await call("fmc_user_identity_sessions", {"ip": "10.99.1.12", "history": True})
    assert [r["user"] for r in data["results"]] == ["alice"] and data["sessions"] == 1
    assert expect in data["history_error"] and "history" not in data


async def test_history_reads_fmc10_rows(ftd: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    """Real FMC 10.0.1 user activity (epoch seconds, null ports, the FMC as `device`), newest first."""
    rows = fixture("useractivity_fmc10")
    monkeypatch.setattr(live, "clock", lambda: rows["items"][0]["time"] + 60)
    ftd.get(SESSIONS).mock(return_value=items([]))
    route = ftd.get(ACTIVITY).mock(return_value=httpx.Response(200, json=rows))
    data = await call("fmc_user_identity_sessions", {"user": "mcp-bob", "history": True, "hours": 1})
    assert route.calls.last.request.url.params["username"] == "mcp-bob"
    assert data["history"][1] == {
        "time": "2026-10-20T22:42:24Z",
        "event": "User Logoff",
        "user": "mcp-bob",
        "realm": "lab",
        "ip": "10.10.34.100",
        "device": "fmc.example",
        "authentication": "Passive Authentication",
        "sgt": "Contractors",
    }
    assert "history_error" not in data


async def test_sessions_by_device_name(ftd: respx.MockRouter) -> None:
    sessions = ftd.get(SESSIONS).mock(return_value=items([]))
    data = await call("fmc_user_identity_sessions", {"device": DEV["id"]})
    assert sessions.calls.last.request.url.params["device"] == "mcp-ftd1"
    assert data["sessions"] == 0 and "No active session" in data["note"]


async def test_sessions_403_names_the_permission(ftd: respx.MockRouter) -> None:
    ftd.get(SESSIONS).mock(return_value=denied())
    with pytest.raises(ToolError, match="Analysis > Users"):
        await call("fmc_user_identity_sessions", {"user": "alice"})


async def test_sessions_need_a_filter(ftd: respx.MockRouter) -> None:
    with pytest.raises(ToolError, match="Give an ip"):
        await call("fmc_user_identity_sessions", {})


# --- packet-tracer flows and FTD 10's number tail (#202), recorded on FTD 10.0.0 ------------------------

INJECTION = fixture("ftd_logging_injection")["text"]


def test_parse_log_buffer_marks_packet_tracer_flows_and_drops_the_number_tail() -> None:
    conns, _ = parse_log_buffer(INJECTION)
    rows = {c.conn_id: c for c in conns}
    assert rows["29"].reason == "TCP FINs from outside" and not rows["29"].simulated
    assert rows["44"].reason == "Free the flow created as result of packet injection" and rows["44"].simulated


async def test_packet_tracer_flows_are_left_out_and_counted(ftd: respx.MockRouter) -> None:
    out = {"items": [{"commandInput": "show logging", "commandOutput": INJECTION}]}
    ftd.get(CMD).mock(return_value=httpx.Response(200, json=out))
    data = await call("fmc_live_connections", {"device": "mcp-ftd1", "host": "10.99.1.10"})
    assert [r["id"] for r in data["results"]] == ["29"]
    assert data["results"][0]["started"] == "2026-10-18T23:00:57Z"
    assert data["packet_tracer_flows"] == 1 and "packet-tracer simulation" in data["note"]
    md = await call_tool(
        create_server(make_settings()),
        "fmc_live_connections",
        {"device": "mcp-ftd1", "response_format": "markdown"},
    )
    assert "| started | ended |" in str(md)

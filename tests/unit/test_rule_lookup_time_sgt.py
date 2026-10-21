"""fmc_rule_lookup decides time-range and source-SGT conditions where FMC has the data (W6 live fix, F66).

Live on FMC 10.0.1 / FTD 10.0.0 (tests/fixtures/rule_lookup_fmc10.json): a rule whose time range had ended got
no hits but was listed as conditional; bob's telnet was decided by the SGT rule (Contractors, the SGT of his
ISE login in FMC's user activity) while the lookup gave the verdict to the later user rule."""

import copy
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx

from fmc_mcp import lookup_conditions
from fmc_mcp._core.testing import call_tool
from fmc_mcp.lookup_conditions import FlowSgt, sgt_check, time_range_check, window_state
from fmc_mcp.server import create_server
from fmc_mcp.tools import live

from .conftest import ACP_ID, CFG, fixture, items, make_settings

FX = fixture("rule_lookup_fmc10")
SGTS = fixture("rule_conditions")
RULES = f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules"
ACTIVITY = f"{CFG}/analysis/useractivity"
STARTED, EXPIRED = FX["timerange_started"], FX["timerange_expired"]
NOW = datetime(2026, 10, 21, 6, 0, tzinfo=UTC)
INSIDE_NET = {
    "id": "00000000-0000-0ed3-0000-021474841321",
    "type": "Network",
    "name": "mcp-test-ftd-inside-net",
    "value": "10.99.1.0/24",
}


async def lookup(args: dict[str, Any]) -> Any:
    return await call_tool(
        create_server(make_settings()),
        "fmc_rule_lookup",
        {"policy": "mcp-test-acp", "protocol": "tcp", **args},
    )


def body(fx: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json={k: v for k, v in fx.items() if k != "_source"})


@pytest.fixture
def at_six(lab: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> respx.MockRouter:
    """The lab at 06:00Z on the day of the live run, with the SGTs FMC downloaded from ISE."""
    monkeypatch.setattr(lookup_conditions, "now", lambda: NOW)
    monkeypatch.setattr(live, "clock", lambda: NOW.timestamp())
    nets = fixture("networkaddresses")
    nets["items"].append(INSIDE_NET)
    lab.get(f"{CFG}/object/networkaddresses").mock(return_value=httpx.Response(200, json=nets))
    lab.get(f"{CFG}/object/timeranges", name="timeranges").mock(return_value=items([STARTED, EXPIRED]))
    lab.get(f"{CFG}/object/isesecuritygrouptags").mock(return_value=body(SGTS["isesecuritygrouptags"]))
    lab.get(f"{CFG}/object/securitygrouptags").mock(
        return_value=httpx.Response(422, json={"error": SGTS["securitygrouptags_ise_enabled"]["error"]})
    )
    lab.get(f"{CFG}/object/realmusers").mock(return_value=items([]))
    return lab


# --- time ranges -----------------------------------------------------------------------------------


async def test_an_ended_time_range_rule_is_left_out(at_six: respx.MockRouter) -> None:
    at_six.get(RULES).mock(return_value=items(FX["acp_rules"]))
    out = await lookup({"source": "10.99.1.10", "destination": "192.0.2.80", "port": 80})
    assert out["verdict"] == "Rule 7 'mcp-w6-allow-out' → ALLOW"
    assert "may_match_first" not in out  # mcp-w6-expired is no longer 'conditional'
    assert out["not_in_effect"] == [
        {
            "index": 2,
            "name": "mcp-w6-expired",
            "action": "ALLOW",
            "time_range": "mcp-w6-tr-expired",
            "reason": "ended 2026-10-02T23:59",
            "evaluated_at": "2026-10-21T06:00:00Z",
        }
    ]
    assert out["evaluated_at"] == "2026-10-21T06:00:00Z"  # the verdict holds at this moment
    assert at_six.routes["timeranges"].call_count == 1


async def test_a_recurring_range_stays_conditional(at_six: respx.MockRouter) -> None:
    """mcp-w6-tr-now ('Started', daily 00:00-23:59 until 2026-10-23): it depends on the device's clock."""
    at_six.get(RULES).mock(return_value=items(FX["acp_rules"]))
    out = await lookup({"source": "10.99.1.10", "destination": "192.0.2.76", "port": 443})
    assert out["verdict"] == "Rule 7 'mcp-w6-allow-out' → ALLOW"
    (first,) = out["may_match_first"]
    assert first["name"] == "mcp-w6-time-now" and first["depends_on"] == ["timeRangeObjects"]
    assert "evaluated_at" not in out  # no time range decided anything


async def test_a_range_fmc_wont_list_stays_conditional(at_six: respx.MockRouter) -> None:
    at_six.get(RULES).mock(return_value=items(FX["acp_rules"]))
    at_six.routes["timeranges"].mock(return_value=httpx.Response(500, json={}))
    out = await lookup({"source": "10.99.1.10", "destination": "192.0.2.80", "port": 80})
    assert [r["name"] for r in out["may_match_first"]] == ["mcp-w6-expired"]
    assert "not_in_effect" not in out


def test_window_state_reads_fmcs_started_literal_and_every_time_zone() -> None:
    assert window_state(EXPIRED, NOW) == (False, "ended 2026-10-02T23:59")
    assert window_state(STARTED, NOW) == (None, None)  # 'Started' = no start bound; it recurs daily
    plain = {k: v for k, v in STARTED.items() if k != "recurrenceList"}
    assert window_state(plain, NOW) == (True, None)  # until 2026-10-23T23:59 local, in every zone
    # an end 10 h ago may still be ahead on a device at UTC-12; 13 h ago it has passed everywhere
    assert window_state({"effectiveEndDateTime": "2026-10-20T20:00"}, NOW) == (None, None)
    assert window_state({"effectiveEndDateTime": "2026-10-20T16:59"}, NOW)[0] is False
    # a start 15 h ahead is ahead everywhere; 13 h ahead has already come at UTC+14
    assert window_state({"effectiveStartDateTime": "2026-10-21T21:00"}, NOW) == (
        False,
        "starts 2026-10-21T21:00",
    )
    assert window_state({"effectiveStartDateTime": "2026-10-21T19:00"}, NOW) == (None, None)
    assert window_state({"effectiveStartDateTime": "soon"}, NOW) == (None, None)


def test_time_range_check_with_several_or_unknown_ranges() -> None:
    ranges = {STARTED["id"]: STARTED, EXPIRED["id"]: EXPIRED}
    ref = {"id": EXPIRED["id"], "type": "TimeRange", "name": "mcp-w6-tr-expired"}
    assert time_range_check({}, ranges, NOW) == (True, None)
    assert time_range_check({"timeRangeObjects": [ref]}, None, NOW) == (None, None)
    assert time_range_check({"timeRangeObjects": {"objects": [ref]}}, ranges, NOW)[0] is False
    assert time_range_check({"timeRangeObjects": [{"id": "gone"}]}, ranges, NOW) == (None, None)
    both = [ref, {"id": STARTED["id"], "type": "TimeRange"}]
    assert time_range_check({"timeRangeObjects": both}, ranges, NOW) == (None, None)


# --- source SGTs -----------------------------------------------------------------------------------


async def test_bobs_session_sgt_decides_the_sgt_rule(at_six: respx.MockRouter) -> None:
    at_six.get(RULES).mock(return_value=items(FX["threat_rules"]))
    activity = at_six.get(ACTIVITY).mock(return_value=items(FX["useractivity_bob"]))
    out = await lookup(
        {
            "source": "10.10.34.100",
            "destination": "192.0.2.10",
            "port": 23,
            "identities": ["mcp-bob", "mcp-contractors"],
        }
    )
    assert out["verdict"] == "Rule 1 'mcp-w6-sgt-block' → BLOCK"
    assert "may_match_first" not in out
    caveat = out["source_sgt"].pop("caveat")
    assert out["source_sgt"] == {
        "sgt": "Contractors (SGT 5)",
        "from": "FMC user activity: User Login mcp-bob at 2026-10-21T05:53:11Z",
    }
    # the newest login within 30 days, not checked against an active session: the tool says so
    assert (
        "newest ISE login for 10.10.34.100" in caveat and "not cross-checked with an active session" in caveat
    )
    assert activity.calls.last.request.url.params["ipAddress"] == "10.10.34.100"


async def test_alices_session_sgt_skips_the_sgt_rule(at_six: respx.MockRouter) -> None:
    at_six.get(RULES).mock(return_value=items(FX["threat_rules"]))
    at_six.get(ACTIVITY).mock(return_value=items(FX["useractivity_alice"]))
    out = await lookup(
        {"source": "10.10.34.100", "destination": "192.0.2.10", "port": 23, "identities": ["mcp-alice"]}
    )
    assert out["verdict"] == "Rule 3 'mcp-fw-baseline' → ALLOW"
    assert out["source_sgt"]["sgt"] == "Employees (SGT 4)" and "may_match_first" not in out


async def test_given_sgt_wins_and_needs_no_activity_read(at_six: respx.MockRouter) -> None:
    at_six.get(RULES).mock(return_value=items(FX["threat_rules"]))
    activity = at_six.get(ACTIVITY).mock(return_value=items(FX["useractivity_alice"]))
    out = await lookup(
        {
            "source": "10.10.34.100",
            "destination": "192.0.2.10",
            "port": 23,
            "identities": [],
            "source_sgt": "5",
        }
    )
    assert out["verdict"] == "Rule 1 'mcp-w6-sgt-block' → BLOCK"
    assert out["source_sgt"] == {"sgt": "Contractors (SGT 5)", "from": "source_sgt (given)"}
    assert activity.call_count == 0


@pytest.mark.parametrize(
    ("events", "note"),
    [
        ([], "No ISE login for 10.10.34.100"),
        ("logoff", "is 'User Logoff' by mcp-alice"),
        ("no-sgt", "carries no SGT"),
    ],
)
async def test_unknown_session_sgt_keeps_the_rule_conditional(
    at_six: respx.MockRouter, events: Any, note: str
) -> None:
    rows = copy.deepcopy(FX["useractivity_alice"])
    if events == "logoff":
        rows = rows[1:2]
        rows[0]["username"] = "mcp-alice"
    elif events == "no-sgt":
        rows = rows[:1]
        rows[0]["securityGroupTag"] = ""
    else:
        rows = events
    at_six.get(RULES).mock(return_value=items(FX["threat_rules"]))
    at_six.get(ACTIVITY).mock(return_value=items(rows))
    out = await lookup({"source": "10.10.34.100", "destination": "192.0.2.10", "port": 23, "identities": []})
    (first,) = out["may_match_first"]
    assert first["name"] == "mcp-w6-sgt-block" and first["depends_on"] == ["sourceSecurityGroupTags"]
    assert note in out["source_sgt"]["note"]
    assert out["verdict"] == "Rule 3 'mcp-fw-baseline' → ALLOW"


async def test_activity_refused_keeps_sgt_rules_conditional(at_six: respx.MockRouter) -> None:
    at_six.get(RULES).mock(return_value=items(FX["threat_rules"]))
    at_six.get(ACTIVITY).mock(
        return_value=httpx.Response(403, json={"error": {"messages": [{"description": "not authorized"}]}})
    )
    out = await lookup({"source": "10.10.34.100", "destination": "192.0.2.10", "port": 23, "identities": []})
    assert out["may_match_first"][0]["name"] == "mcp-w6-sgt-block"
    assert "Analysis > Users" in out["source_sgt"]["note"]


async def test_resolve_user_false_reads_no_activity(at_six: respx.MockRouter) -> None:
    at_six.get(RULES).mock(return_value=items(FX["threat_rules"]))
    activity = at_six.get(ACTIVITY).mock(return_value=items(FX["useractivity_bob"]))
    out = await lookup(
        {
            "source": "10.10.34.100",
            "destination": "192.0.2.10",
            "port": 23,
            "identities": [],
            "resolve_user": False,
        }
    )
    assert out["may_match_first"][0]["name"] == "mcp-w6-sgt-block" and "source_sgt" not in out
    assert activity.call_count == 0


def test_sgt_check_by_name_or_tag() -> None:
    rule = FX["threat_rules"][0]["sourceSecurityGroupTags"]
    tags = {"9370d4c0-8c01-11e6-996c-525400b48521": (5, "ISE")}
    assert sgt_check({}, None, None) is True
    assert sgt_check(rule, None, tags) is None
    assert sgt_check(rule, FlowSgt(note="unknown"), tags) is None
    assert sgt_check(rule, FlowSgt(name="contractors"), None) is True
    assert sgt_check(rule, FlowSgt(tag=5), tags) is True
    # can't compare: the rule's SGT has no tag number (no catalogue) and the flow's has no name
    assert sgt_check(rule, FlowSgt(tag=5), None) is None
    assert sgt_check(rule, FlowSgt(tag=4), None) is None
    assert sgt_check(rule, FlowSgt(name="Employees", tag=4), tags) is False  # another tag number
    assert sgt_check(rule, FlowSgt(tag=4), tags) is False
    # a name: ruled out only when it is FMC's (in the catalogue), never by an unchecked one (a typo)
    assert sgt_check(rule, FlowSgt(name="Contractor"), tags) is None
    assert sgt_check(rule, FlowSgt(name="Employees"), None) is None
    assert sgt_check(rule, FlowSgt(name="Employees", verified=True), None) is False
    # several SGTs: one match is enough; ruled out only when every one is certainly another
    two = {"objects": [*rule["objects"], {"id": "x", "type": "ISESecurityGroupTag", "name": "Guests"}]}
    assert sgt_check(two, FlowSgt(name="guests"), None) is True
    assert sgt_check(two, FlowSgt(tag=4), tags) is None  # Guests has no number here
    assert sgt_check(two, FlowSgt(name="Employees", tag=4, verified=True), tags) is False


@pytest.mark.parametrize(
    ("given", "fail_catalogue", "note"),
    [
        ("5", True, "SGT catalogue could not be read"),
        ("Contractor", False, "'Contractor' is not in FMC's SGT catalogue"),
    ],
)
async def test_an_sgt_that_cant_be_compared_keeps_the_sgt_rule_conditional(
    at_six: respx.MockRouter, given: str, fail_catalogue: bool, note: str
) -> None:
    """A failed SGT catalogue read (the rule's SGT has no tag number to compare with '5') or a typo'd SGT
    name: the SGT BLOCK rule stays conditional, with a note, instead of being skipped so that the later
    ALLOW reads as the definite verdict."""
    at_six.get(RULES).mock(return_value=items(FX["threat_rules"]))
    if fail_catalogue:
        at_six.get(f"{CFG}/object/isesecuritygrouptags").mock(return_value=httpx.Response(500, json={}))
    args = {"source": "10.10.34.100", "destination": "192.0.2.10", "port": 23, "identities": []}
    out = await lookup({**args, "source_sgt": given})
    (first,) = out["may_match_first"]
    assert first["name"] == "mcp-w6-sgt-block" and first["depends_on"] == ["sourceSecurityGroupTags"]
    assert note in out["source_sgt"]["note"]

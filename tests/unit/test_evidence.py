"""F80 fmc_export_access_rules(evidence=true): per-rule audit evidence on recorded FMC 10.0.1 shapes (rules,
policy-editor audit records, job history, SI), hit counts, pending devices, and the ticket column only when
change management answers."""

import csv
import io
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools import evidence
from fmc_mcp.tools.evidence import EVIDENCE_COLUMNS, is_save, last_change, match_ticket, revision

from .conftest import CFG, fixture, items, make_settings

REC = fixture("compliance_fmc10")
ACP = {**REC["acp"], "defaultAction": {"id": "da-1", "action": "BLOCK", "type": "AccessPolicyDefaultAction"}}
ACP_ID = ACP["id"]
BASE = f"{CFG}/policy/accesspolicies/{ACP_ID}"
DEV_ID = REC["device"]["id"]
RULES = REC["rules"]["items"]
NOW = 1792584000.0  # 2026-10-21T12:00Z
AUDIT = "/api/fmc_platform/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/audit/auditrecords"


@pytest.fixture(autouse=True)
def frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evidence.time, "time", lambda: NOW)


async def export(args: dict[str, Any]) -> dict[str, Any]:
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool("fmc_export_access_rules", args)
    out: dict[str, Any] = r.structured_content or json.loads(r.content[0].text)  # type: ignore[union-attr]
    return out


def mock_policy(fmc: respx.MockRouter, assigned: bool = True) -> dict[str, respx.Route]:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    fmc.get(BASE).mock(return_value=httpx.Response(200, json=ACP))
    fmc.get(f"{BASE}/accessrules").mock(return_value=httpx.Response(200, json=REC["rules"]))
    targets = [{"id": DEV_ID, "type": "Device", "name": "mcp-ftd1"}] if assigned else []
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items([{"policy": {"id": ACP_ID, "type": "AccessPolicy"}, "targets": targets}])
    )
    hits = [
        {
            "rule": {"id": RULES[1]["id"], "name": RULES[1]["name"], "type": "AccessRule"},
            "hitCount": 2,
            "firstHitTimeStamp": "2026-10-21T06:12:55Z",
            "lastHitTimeStamp": "2026-10-21T06:13:01Z",
            "lastFetchTimeStamp": "2026-10-21T06:13:10Z",
        },
        {"rule": {"id": RULES[0]["id"], "name": RULES[0]["name"]}, "hitCount": 0},
        {"rule": {"id": RULES[2]["id"], "name": RULES[2]["name"]}, "hitCount": 0},
        {
            "rule": {"id": "da-1", "name": "Default Action", "type": "AccessPolicyDefaultAction"},
            "hitCount": 7,
        },
    ]
    return {
        "refresh": fmc.put(f"{BASE}/operational/hitcounts").mock(return_value=httpx.Response(200, json={})),
        "hits": fmc.get(f"{BASE}/operational/hitcounts").mock(return_value=items(hits)),
        "si": fmc.get(f"{BASE}/securityintelligencepolicies").mock(
            return_value=httpx.Response(200, json=REC["si"])
        ),
        "dns": fmc.get(f"{CFG}/policy/dnspolicies/dc906e6e-69ed-11e4-82ce-87dc73eef419").mock(
            return_value=httpx.Response(
                200, json={"id": "dc906e6e-69ed-11e4-82ce-87dc73eef419", "name": "Default DNS Policy"}
            )
        ),
        "audit": fmc.get(AUDIT).mock(return_value=httpx.Response(200, json=REC["audit"])),
        "jobs": fmc.get(f"{CFG}/deployment/jobhistories").mock(
            return_value=httpx.Response(200, json=REC["jobs"])
        ),
        "deployable": fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([])),
        "tickets": fmc.get(f"{CFG}/changemanagement/tickets").mock(
            return_value=httpx.Response(
                403, json={"error": {"messages": [{"description": "The user is not authorized."}]}}
            )
        ),
    }


async def test_evidence_rows_on_recorded_lab_policy(fmc: respx.MockRouter) -> None:
    routes = mock_policy(fmc)
    out = await export({"policy": "mcp-w6-acp", "evidence": True, "since_days": 2})
    rows = {r["name"]: r for r in out["results"]}
    fqdn = rows["mcp-w6-fqdn-allow"]
    assert fqdn["dst_networks"] == ["mcp-w6-fqdn"] and fqdn["dst_ports"] == [
        "tcp/443"
    ]  # the flat definition stays
    ev = fqdn["evidence"]
    assert ev["hits"] == [
        {
            "device": "mcp-ftd1",
            "hits": 2,
            "first_hit": "2026-10-21T06:12:55 (FMC local time)",  # no refresh task ran: offset unknown
            "last_hit": "2026-10-21T06:13:01 (FMC local time)",
        }
    ]
    assert ev["logging"] == {"log": "end", "to_fmc": True, "syslog": False}
    assert ev["last_change"] == {
        "at": "2026-10-21T06:11:04Z",
        "by": "mcp-api-svc",
        "audit": "Save Policy mcp-w6-acp:743",
        "revision": "743",
        "audit_at": "2026-10-21T06:11:06Z",
    }
    assert ev["deployed"] == [
        {
            "device": "mcp-ftd1",
            "job": "Deploy_Job_146",
            "at": "2026-10-21T06:12:00Z",
            "by": "mcp-api-svc",
            "note": "W6 live-B2: F70 replace mcp-w6-a->b + F69 DNS group mcp-w6-dns + FQDN rule",
        }
    ]
    assert ev["comments"][0]["by"] == "mcp-api-svc" and "FQDN rule" in ev["comments"][0]["comment"]
    assert "ticket" not in ev  # change management not readable: no ticket column
    block = rows["mcp-w6-quarantine-block"]["evidence"]
    assert block["logging"] == {"log": "begin", "to_fmc": True, "syslog": True}
    assert block["hits"][0]["hits"] == 0
    pol = out["evidence"]
    assert pol["devices"] == ["mcp-ftd1"] and pol["default_action"]["hits"][0]["hits"] == 7
    assert pol["security_intelligence"]["dns_policy"] == "Default DNS Policy"
    assert pol["security_intelligence"]["logging"] is True
    assert pol["change_management"].startswith("not readable by this account (403)")
    assert not any("Tickets" in n for n in pol.get("notes") or [])  # no own-tickets note when none are read
    assert pol["saves_in_window"] == 5  # the other policy's save and the assignment aren't counted
    created = {"at": "2026-10-20T23:56:12Z", "by": "mcp-api-svc", "audit": "Create Policy mcp-w6-acp"}
    assert pol["policy_events"] == [created]
    audit_q = routes["audit"].calls.last.request.url.params
    assert audit_q["subsystem"] == "%Access Control > Policy Editor%" and audit_q["expanded"] == "true"
    assert routes["refresh"].called  # counters refreshed first, like fmc_get_hit_counts
    flt = routes["hits"].calls.last.request.url.params["filter"]
    assert f"deviceId:{DEV_ID}" in flt and "da-1" in flt


async def test_evidence_csv_has_the_evidence_columns(fmc: respx.MockRouter) -> None:
    mock_policy(fmc)
    out = await export({"policy": "mcp-w6-acp", "evidence": True, "format": "csv"})
    reader = list(csv.DictReader(io.StringIO(out["csv"])))
    assert reader[0].keys() >= set(EVIDENCE_COLUMNS)
    fqdn = next(r for r in reader if r["name"] == "mcp-w6-fqdn-allow")
    assert fqdn["hits"] == "2" and fqdn["changed_by"] == "mcp-api-svc"
    assert fqdn["change_record"] == "Save Policy mcp-w6-acp:743"
    assert fqdn["deployed"].startswith("mcp-ftd1: Deploy_Job_146 2026-10-21T06:12:00Z by mcp-api-svc")
    assert fqdn["ticket"] == ""  # no ticket column values without change management
    assert out["evidence"]["devices"] == ["mcp-ftd1"]


async def test_pending_device_and_out_of_date(fmc: respx.MockRouter) -> None:
    routes = mock_policy(fmc)
    row = {
        **REC["deployable_row_trimmed"],
        "name": "mcp-ftd1",
        "device": {"id": DEV_ID, "name": "mcp-ftd1"},
        "deviceMembers": [],
        "policyStatusList": [{"upToDate": False, "policy": {"name": "mcp-w6-acp", "id": ACP_ID}}],
    }
    routes["deployable"].mock(return_value=items([row]))
    out = await export({"policy": "mcp-w6-acp", "evidence": True})
    assert out["evidence"]["out_of_date_on"] == ["mcp-ftd1"]
    assert all(r["evidence"]["deployed"] == [{"device": "mcp-ftd1", "pending": True}] for r in out["results"])


async def test_unassigned_policy_reads_no_hit_counts(fmc: respx.MockRouter) -> None:
    routes = mock_policy(fmc, assigned=False)
    out = await export({"policy": "mcp-w6-acp", "evidence": True})
    assert not routes["hits"].called and not routes["refresh"].called and not routes["deployable"].called
    assert "assigned to no device" in " ".join(out["evidence"]["notes"])
    ev = out["results"][1]["evidence"]
    assert "hits" not in ev and "deployed" not in ev and ev["last_change"]["by"] == "mcp-api-svc"


async def test_hit_count_error_is_a_note(fmc: respx.MockRouter) -> None:
    """FMC 10.0.1 answers 500 for a device the policy isn't assigned to (recorded)."""
    routes = mock_policy(fmc)
    routes["hits"].mock(return_value=httpx.Response(500, json=REC["hitcounts_unassigned"]["error"]))
    out = await export({"policy": "mcp-w6-acp", "evidence": True})
    assert any("hit counts not read" in n and "not assigned" in n for n in out["evidence"]["notes"])
    assert out["results"][0]["evidence"]["last_change"]["revision"] == "743"


async def test_ticket_column_only_when_change_management_answers(fmc: respx.MockRouter) -> None:
    """FMC's ticket list has no history (spec: GET tickets/{id}?history=true has it), so each ticket
    updated in the window is read by id; tickets closed before the window are not."""
    routes = mock_policy(fmc)
    history = [
        {"time": "2026-10-21T06:05Z", "state": "IN_PROGRESS", "user": "mcp-api-svc"},
        {"time": "2026-10-21T06:20Z", "state": "PENDING_APPROVAL", "user": "mcp-api-svc"},
        {"time": "2026-10-21T06:25Z", "state": "APPROVED", "user": "approver"},
    ]
    ticket = {  # the list's shape (spec example): no ticketHistory
        "id": "t-1",
        "name": "CHG042",
        "status": "APPROVED",
        "assignedTo": "mcp-api-svc",
        "metadata": {"creator": "mcp-api-svc", "lastUpdateTime": "2026-10-21T06:30Z"},
        "type": "Ticket",
    }
    other = {
        **ticket,
        "id": "t-2",
        "name": "CHG001",
        "assignedTo": "someone",
        "metadata": {"creator": "someone"},
    }
    old = {**ticket, "id": "t-3", "name": "CHG000", "metadata": {"lastUpdateTime": "2026-09-01T10:00Z"}}
    routes["tickets"].mock(return_value=items([other, ticket, old]))
    by_id = {
        "t-1": fmc.get(f"{CFG}/changemanagement/tickets/t-1").mock(
            return_value=httpx.Response(200, json={**ticket, "ticketHistory": history})
        ),
        "t-2": fmc.get(f"{CFG}/changemanagement/tickets/t-2").mock(
            return_value=httpx.Response(
                200, json={**other, "ticketHistory": [{**h, "user": "someone"} for h in history]}
            )
        ),
        "t-3": fmc.get(f"{CFG}/changemanagement/tickets/t-3").mock(return_value=httpx.Response(404)),
    }
    out = await export({"policy": "mcp-w6-acp", "evidence": True})
    assert out["evidence"]["change_management"] == "on"
    t = out["results"][1]["evidence"]["ticket"]
    assert t == {
        "ticket": "CHG042",
        "status": "APPROVED",
        "approved_by": "approver",
        "approved_at": "2026-10-21T06:25Z",
        "id": "t-1",
    }
    assert routes["tickets"].calls.last.request.url.params["allUsers"] == "true"  # every user's tickets
    assert by_id["t-1"].calls.last.request.url.params["history"] == "true" and by_id["t-2"].called
    assert not by_id["t-3"].called  # closed before the window: can't span a change in it

    # without the 'review tickets' permission: the account's own tickets
    def own_only(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("allUsers"):
            return httpx.Response(403, json={"error": {"messages": [{"description": "Not authorized"}]}})
        return items([ticket])

    routes["tickets"].mock(side_effect=own_only)
    out = await export({"policy": "mcp-w6-acp", "evidence": True})
    assert out["results"][1]["evidence"]["ticket"]["ticket"] == "CHG042"
    assert any("only this account's own" in n for n in out["evidence"]["notes"])

    routes["tickets"].mock(
        return_value=httpx.Response(
            500, json={"error": {"messages": [{"description": "Change Management mode is not enabled"}]}}
        )
    )
    out = await export({"policy": "mcp-w6-acp", "evidence": True})
    assert out["evidence"]["change_management"] == "off: no ticket column"
    assert all("ticket" not in r["evidence"] for r in out["results"])


async def test_audit_unreadable_keeps_the_change_time_for_the_deployment(fmc: respx.MockRouter) -> None:
    """Without the audit log the rule's own timestamp still picks the deployment after it (Deploy_Job_146
    at 06:11:32Z), not the first job of the window (Deploy_Job_143 at 05:45, before the change)."""
    routes = mock_policy(fmc)
    routes["audit"].mock(
        return_value=httpx.Response(500, json={"error": {"messages": [{"description": "x"}]}})
    )
    out = await export({"policy": "mcp-w6-acp", "evidence": True})
    ev = out["results"][1]["evidence"]
    assert ev["last_change"] == {
        "at": "2026-10-21T06:11:04Z",
        "note": "audit records not read: no change record",
    }
    assert ev["deployed"][0]["job"] == "Deploy_Job_146"
    assert any(n.startswith("Audit records not read") for n in out["evidence"]["notes"])
    assert "saves_in_window" not in out["evidence"]


async def test_change_before_the_window_names_no_job(fmc: respx.MockRouter) -> None:
    """A rule last changed before the window: a job inside it need not be the one that pushed it."""
    routes = mock_policy(fmc)
    rules = json.loads(json.dumps(REC["rules"]))
    for r in rules["items"]:
        r["metadata"]["timestamp"] = 1790000000000  # 2026-09-21, before a 2-day window
    fmc.get(f"{BASE}/accessrules").mock(return_value=httpx.Response(200, json=rules))
    out = await export({"policy": "mcp-w6-acp", "evidence": True, "since_days": 2})
    ev = out["results"][1]["evidence"]
    assert ev["last_change"]["note"] == "before the evidence window"
    assert ev["deployed"] == [
        {
            "device": "mcp-ftd1",
            "deployed": "yes (FMC lists it up to date); the change predates the evidence window "
            "(2026-10-19T12:00:00Z)",
        }
    ]
    routes["deployable"].mock(
        return_value=httpx.Response(500, json={"error": {"messages": [{"description": "x"}]}})
    )
    out = await export({"policy": "mcp-w6-acp", "evidence": True, "since_days": 2})
    assert out["results"][1]["evidence"]["deployed"][0]["deployed"].startswith("unknown; the change predates")


async def test_without_evidence_nothing_extra_is_read(fmc: respx.MockRouter) -> None:
    routes = mock_policy(fmc)
    out = await export({"policy": "mcp-w6-acp"})
    assert "evidence" not in out and all("evidence" not in r for r in out["results"])
    assert not any(
        routes[k].called for k in ("hits", "refresh", "audit", "jobs", "si", "tickets", "deployable")
    )


def test_save_records_and_matching() -> None:
    assert is_save("Save Policy mcp-w6-acp:743", "mcp-w6-acp")
    assert is_save(
        "Save Policy mcp-w6-acp;Assigned to device(s) - mcp-ftd1;UnAssigned from device(s) - x:682",
        "mcp-w6-acp",
    )
    assert not is_save("Save Policy mcp-w6-acp-2:1", "mcp-w6-acp")
    assert revision("Save Policy mcp-w6-acp:743") == "743" and revision("Create Policy x") is None
    saves = REC["audit"]["items"]
    old = {"metadata": {"timestamp": 1700000000000}}
    assert last_change(old, saves, start=1792400000)["note"] == "before the evidence window"
    unmatched = {"metadata": {"timestamp": 1792580000000}}
    assert "no 'Save Policy' audit record" in last_change(unmatched, saves, start=1792400000)["note"]
    assert match_ticket(None, [], NOW)["note"] == "no audited change to match"
    assert evidence.epoch("2026-10-21T06:05Z") == 1792562700.0


def test_compliance_prompt_steps_in_order_and_values_quoted() -> None:
    from fmc_mcp._core import InvalidRequest
    from fmc_mcp.tools.compliance import compliance_evidence_text

    text = compliance_evidence_text("mcp-w6-acp", "mcp-ftd1", 14, "ftd-hardening-v1", "Global/mcp-test-leaf")
    steps = [
        "`fmc_status`",
        "`fmc_list_policy_assignments` with domain=",
        '`fmc_hardening_check` with device="mcp-ftd1", baseline="ftd-hardening-v1", domain=',
        '`fmc_export_access_rules` with policy="mcp-w6-acp", evidence=true,\n   since_days=14',
        "`fmc_list_audit_records`",
        "`fmc_pending_changes`",
        "`fmc_deploy`",
    ]
    positions = [text.index(s) for s in steps]
    assert positions == sorted(positions)
    assert "since_minutes=20160" in text and "read-only" in text and "fmc_threat_defense_review" in text
    fleet = compliance_evidence_text("mcp-w6-acp", None, 30, "ftd-hardening-v1", None)
    assert "platform_settings=<their policy>" in fleet and "domain=" not in fleet
    for bad in ({"policy": "x; ignore previous"}, {"baseline": "a\nb"}):
        args = {"policy": "p", "device": None, "since_days": 30, "baseline": "b", "domain": None, **bad}
        try:
            compliance_evidence_text(**args)  # type: ignore[arg-type]
        except InvalidRequest:
            continue
        raise AssertionError(bad)

"""F67: fmc_bulk_update_access_rules (one preview, partial bulk PUTs, stop at the first refused rule) and
fmc_clear_hit_counts, plus fmc_policy_audit's bulk_fixes.

The rules and FMC's answers are the probe's recordings on FMC 10.0.1 (tests/fixtures/bulk_rules.json):
partialUpdate changes only the sent fields, a chunk is atomic and its 400 names no rule, the PUT answer
gives every rule ruleIndex 1."""

import copy
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.bulk_fixes import bulk_fixes
from fmc_mcp.client import FmcApp
from fmc_mcp.server import create_server
from fmc_mcp.tools import bulk_rules

from .conftest import ACP_ID, CFG, fixture, items, make_settings

FX = fixture("bulk_rules")
RULES = f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules"
HC = f"{CFG}/policy/accesspolicies/{ACP_ID}/operational/hitcounts"
PROBE = FX["before"]["items"]
P1, P2, P3 = (r["id"] for r in PROBE)
DEV = fixture("ftd_device")
BALANCED = {"id": "ips-1", "name": "Balanced Security and Connectivity", "type": "IntrusionPolicy"}
INSIDE = {"id": "z-in", "name": "inside", "type": "SecurityZone"}
REJECTED = httpx.Response(400, json={"error": FX["rejected"]["error"]})


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def preview_apply(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    async with Client(server()) as c:
        preview = await run(c, name, args)
        assert preview["status"] == "preview", preview
        done = await run(c, name, {**args, "confirm": preview["confirm"]})
        return preview, done


def honest(router: respx.MockRouter, rules: list[dict[str, Any]]) -> Any:
    """FMC's rule list as the probe recorded partialUpdate: after a PUT it answered 200, the rules hold
    exactly the fields that PUT sent (comments aside)."""

    def get(request: httpx.Request) -> httpx.Response:
        now = copy.deepcopy(rules)
        by_id = {r["id"]: r for r in now}
        for call in router.calls:
            req, resp = call.request, call.optional_response
            if req.method == "PUT" and req.url.path == RULES and resp is not None and resp.status_code == 200:
                for b in json.loads(req.content):
                    if b["id"] in by_id:
                        by_id[b["id"]].update({k: v for k, v in b.items() if k != "newComments"})
        return items(now)

    return get


@pytest.fixture
def probe(lab: respx.MockRouter) -> respx.MockRouter:
    """mcp-test-acp holding the probe's three rules as recorded."""
    lab.get(RULES).mock(side_effect=honest(lab, PROBE))
    lab.get(f"{CFG}/policy/intrusionpolicies").mock(return_value=items([BALANCED]))
    lab.get(f"{CFG}/object/securityzones").mock(return_value=items([INSIDE]))
    lab.get(f"{CFG}/object/interfacegroups").mock(return_value=items([]))
    lab.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    lab.get(f"{CFG}/devices/devicerecords/{DEV['id']}").mock(return_value=httpx.Response(200, json=DEV))
    return lab


def sent(route: respx.Route, i: int = -1) -> list[dict[str, Any]]:
    call = route.calls[i]
    assert call.request.url.params["bulk"] == "true" and call.request.url.params["partialUpdate"] == "true"
    body: list[dict[str, Any]] = json.loads(call.request.content)
    return body


# --- bulk update -----------------------------------------------------------------------------------


async def test_bulk_enable_log_and_comment(probe: respx.MockRouter) -> None:
    put = probe.put(RULES).mock(return_value=httpx.Response(200, json=FX["applied"]))
    preview, done = await preview_apply(
        "fmc_bulk_update_access_rules",
        {
            "policy": "mcp-test-acp",
            "select": {"names": ["MCP-W6-PROBE-1", "mcp-w6-probe-3"]},
            "set": {"enabled": True, "log": "end", "comment": "w6 bulk"},
        },
    )
    assert sent(put) == [
        {"id": P1, "type": "AccessRule", "logBegin": False, "newComments": ["w6 bulk"]},
        {
            "id": P3,
            "type": "AccessRule",
            "enabled": True,
            "logEnd": True,
            "sendEventsToFMC": True,  # FMC refuses logEnd without a destination (probe, 400)
            "newComments": ["w6 bulk"],
        },
    ]
    shown = preview["preview"]
    assert shown["selected"] == 2 and shown["to_change"] == 2
    rows = {r["rule"]: r for r in shown["rules"]}
    assert rows["mcp-w6-probe-1"]["changes"] == {
        "logBegin": {"from": True, "to": False},
        "comment": {"add": "w6 bulk"},
    }
    assert rows["mcp-w6-probe-3"]["changes"]["enabled"] == {"from": False, "to": True}
    assert rows["mcp-w6-probe-3"]["index"] == 3  # from the GET, not the PUT answer (ruleIndex 1 for all)
    assert "1 bulk PUT(s)" in shown["requests"]
    assert any("don't move rules" in e for e in preview["side_effects"])
    assert done["result"]["applied"] == 2 and done["result"]["rules"] == ["mcp-w6-probe-1", "mcp-w6-probe-3"]
    assert "kept_by_fmc" not in done["result"] and done["result"]["verified"].startswith("one GET")


async def test_rules_already_as_asked_and_skipped(probe: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_bulk_update_access_rules",
            {"policy": "mcp-test-acp", "select": {"enabled": True}, "set": {"enabled": True}},
        )
        assert out["status"] == "blocked"
        assert out["preview"]["already_as_asked"] == ["mcp-w6-probe-1", "mcp-w6-probe-2"]
        assert "Nothing to change" in out["blockers"][0]
        out = await run(
            c,
            "fmc_bulk_update_access_rules",
            {
                "policy": "mcp-test-acp",
                "select": {"text": "mcp-w6-probe"},
                "set": {"intrusion_policy": "Balanced Security and Connectivity"},
            },
        )
    assert out["status"] == "preview"
    assert [r["rule"] for r in out["preview"]["rules"]] == ["mcp-w6-probe-1", "mcp-w6-probe-3"]
    assert out["preview"]["rules"][0]["changes"] == {"ipsPolicy": {"from": None, "to": BALANCED["name"]}}
    assert out["preview"]["skipped"] == [
        {
            "index": 2,
            "rule": "mcp-w6-probe-2",
            "reason": "is a BLOCK rule; intrusion policies go on ALLOW rules only",
        }
    ]


async def test_action_change_fixes_block_logging_and_skips_rules_with_ips(probe: respx.MockRouter) -> None:
    rules = [dict(r) for r in PROBE]
    rules[2] = {**rules[2], "ipsPolicy": BALANCED}
    probe.get(RULES).mock(return_value=items(rules))
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_bulk_update_access_rules",
            {"policy": "mcp-test-acp", "select": {"action": "ALLOW"}, "set": {"action": "BLOCK_RESET"}},
        )
    (row,) = out["preview"]["rules"]
    assert row["rule"] == "mcp-w6-probe-1"
    assert row["changes"]["action"] == {"from": "ALLOW", "to": "BLOCK_RESET"}
    assert row["changes"]["logEnd"] == {"from": True, "to": False}  # block rules log at the start
    assert out["preview"]["skipped"][0]["rule"] == "mcp-w6-probe-3"
    assert "fmc_update_access_rule" in out["preview"]["skipped"][0]["reason"]


async def test_add_source_zones(probe: respx.MockRouter) -> None:
    put = probe.put(RULES).mock(return_value=httpx.Response(200, json=FX["applied"]))
    preview, _ = await preview_apply(
        "fmc_bulk_update_access_rules",
        {"policy": "mcp-test-acp", "select": {"ids": [P1]}, "set": {"add_source_zones": ["inside"]}},
    )
    assert preview["preview"]["rules"][0]["changes"] == {"sourceZones": {"from": "any", "to": ["inside"]}}
    assert sent(put) == [{"id": P1, "type": "AccessRule", "sourceZones": {"objects": [INSIDE]}}]


async def test_selection_and_set_are_checked(probe: respx.MockRouter) -> None:
    base = {"policy": "mcp-test-acp"}
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="select needs at least one criterion"):
            await run(c, "fmc_bulk_update_access_rules", {**base, "select": {}, "set": {"enabled": False}})
        with pytest.raises(ToolError, match="set needs at least one change"):
            await run(c, "fmc_bulk_update_access_rules", {**base, "select": {"ids": [P1]}, "set": {}})
        with pytest.raises(ToolError, match="can't remove an intrusion policy"):
            await run(
                c,
                "fmc_bulk_update_access_rules",
                {**base, "select": {"ids": [P1]}, "set": {"intrusion_policy": ""}},
            )
        with pytest.raises(ToolError, match="section"):  # no moves: unknown fields are refused
            await run(
                c,
                "fmc_bulk_update_access_rules",
                {**base, "select": {"ids": [P1]}, "set": {"section": "mandatory"}},
            )
        out = await run(
            c,
            "fmc_bulk_update_access_rules",
            {**base, "select": {"names": ["mcp-w6-probe-1", "nope"]}, "set": {"enabled": False}},
        )
        assert out["status"] == "blocked" and "No rule named 'nope'" in out["blockers"][0]
        out = await run(
            c,
            "fmc_bulk_update_access_rules",
            {**base, "select": {"section": "mandatory"}, "set": {"enabled": False}},
        )
        assert out["blockers"] == ["No rule matches the selection."]


def many_rules(n: int) -> list[dict[str, Any]]:
    base = PROBE[0]
    return [
        {
            **base,
            "id": f"r{i}",
            "name": f"mcp-w6-r{i}",
            "enabled": True,
            "metadata": {**base["metadata"], "ruleIndex": i},
        }
        for i in range(1, n + 1)
    ]


async def test_a_refused_chunk_is_halved_to_name_the_rule(
    probe: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bulk_rules, "CHUNK", 4)
    probe.get(RULES).mock(return_value=items(many_rules(6)))

    def answer(request: httpx.Request) -> httpx.Response:
        ids = [b["id"] for b in json.loads(request.content)]
        return REJECTED if "r3" in ids else httpx.Response(200, json={"items": []})

    put = probe.put(RULES).mock(side_effect=answer)
    args = {"policy": "mcp-test-acp", "select": {"text": "mcp-w6-r"}, "set": {"enabled": False}}
    async with Client(server()) as c:
        preview = await run(c, "fmc_bulk_update_access_rules", args)
        assert "2 bulk PUT(s)" in preview["preview"]["requests"]
        with pytest.raises(ToolError) as err:
            await run(c, "fmc_bulk_update_access_rules", {**args, "confirm": preview["confirm"]})
    text = str(err.value)
    assert "FMC refused rule 'mcp-w6-r3'" in text and "Provide at least one destination" in text
    assert "Applied before it: 2 rule(s) (mcp-w6-r1, mcp-w6-r2); not applied: 4" in text
    # [r1..r4] refused -> [r1,r2] applied -> [r3,r4] refused -> [r3] refused: stop (r4..r6 never sent)
    assert [[b["id"] for b in json.loads(c.request.content)] for c in put.calls] == [
        ["r1", "r2", "r3", "r4"],
        ["r1", "r2"],
        ["r3", "r4"],
        ["r3"],
    ]


async def test_a_server_error_stops_at_once(probe: respx.MockRouter) -> None:
    put = probe.put(RULES).mock(
        return_value=httpx.Response(500, json={"error": {"messages": [{"description": "boom"}]}})
    )
    args = {"policy": "mcp-test-acp", "select": {"text": "mcp-w6-probe"}, "set": {"comment": "x"}}
    async with Client(server()) as c:
        preview = await run(c, "fmc_bulk_update_access_rules", args)
        assert preview["preview"]["to_change"] == 3  # a comment-only edit touches every rule
        with pytest.raises(ToolError, match="may or may not have been applied"):
            await run(c, "fmc_bulk_update_access_rules", {**args, "confirm": preview["confirm"]})
    assert put.call_count == 1  # never resent: the comments could be appended twice


def assigned(lab: respx.MockRouter) -> None:
    lab.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items(
            [
                {
                    "policy": {"id": ACP_ID, "type": "AccessPolicy"},
                    "targets": [{"id": DEV["id"], "name": "mcp-ftd1", "type": "Device"}],
                }
            ]
        )
    )
    lab.get(f"{CFG}/deployment/deployabledevices/{DEV['id']}/pendingchanges").mock(return_value=items([]))


async def test_select_rules_without_hits(probe: respx.MockRouter) -> None:
    assigned(probe)
    refresh = probe.put(HC).mock(return_value=httpx.Response(200, json={}))
    recent = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    probe.get(HC).mock(
        return_value=items(
            [
                {"rule": {"id": P1, "name": "mcp-w6-probe-1"}, "hitCount": 0},
                {"rule": {"id": P2, "name": "mcp-w6-probe-2"}, "hitCount": 5, "lastHitTimeStamp": recent},
            ]
        )
    )
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_bulk_update_access_rules",
            {"policy": "mcp-test-acp", "select": {"zero_hits_days": 30}, "set": {"enabled": False}},
        )
    assert refresh.called  # fresh counters before judging
    assert [r["rule"] for r in out["preview"]["rules"]] == ["mcp-w6-probe-1"]  # probe-3 is disabled already
    assert "Hit counts from: mcp-ftd1." in out["preview"]["notes"]


async def test_zero_hits_needs_a_deployed_policy(probe: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_bulk_update_access_rules",
            {"policy": "mcp-test-acp", "select": {"zero_hits_days": 30}, "set": {"enabled": False}},
        )
    assert out["status"] == "blocked" and "runs on no device yet" in " ".join(out["blockers"])


# --- audit bulk_fixes ------------------------------------------------------------------------------


def test_bulk_fixes_group_identical_findings() -> None:
    findings = [
        {"check": "no_logging", "rule": {"name": "a"}},
        {"check": "no_logging", "rule": {"name": "b"}},
        {"check": "no_intrusion", "rule": {"name": "a"}},
        {"check": "unused", "rule": {"name": "c"}},
        {"check": "unused", "rule": {"name": "d"}},
        {"check": "shadowed", "rule": {"name": "e"}},
        {"check": "shadowed", "rule": {"name": "f"}},
    ]
    fixes = bulk_fixes("p", findings, 90)
    assert fixes == [
        {
            "check": "no_logging",
            "rules": 2,
            "fix": "fmc_bulk_update_access_rules(policy='p', select={'names': ['a', 'b']}, "
            "set={'log': 'end'})",
        },
        {
            "check": "unused",
            "rules": 2,
            "fix": "fmc_bulk_update_access_rules(policy='p', select={'zero_hits_days': 90}, set={'enabled': "
            "False, 'comment': 'no hits in 90 days (fmc_policy_audit)'})",
        },
    ]
    many = [{"check": "no_logging", "rule": {"name": f"r{i}"}} for i in range(60)]
    (row,) = bulk_fixes("p", many, 90)
    assert row["rules"] == 60 and "the other 10" in row["note"]


async def test_audit_offers_bulk_fixes(lab: respx.MockRouter) -> None:
    async with Client(create_server(make_settings())) as c:
        out = await run(
            c, "fmc_policy_audit", {"policy": "mcp-test-acp", "checks": ["no_intrusion", "no_logging"]}
        )
    checks = {f["check"]: f for f in out["bulk_fixes"]}
    assert "fmc_bulk_update_access_rules(policy='mcp-test-acp'" in checks["no_intrusion"]["fix"]
    assert checks["no_intrusion"]["rules"] == sum(1 for f in out["findings"] if f["check"] == "no_intrusion")


# --- clear hit counts ------------------------------------------------------------------------------


async def test_clear_hit_counts_previews_what_is_lost(probe: respx.MockRouter) -> None:
    probe.put(HC).mock(return_value=httpx.Response(200, json={}))
    probe.get(HC).mock(
        return_value=items(
            [
                {
                    "rule": {"id": P1, "name": "mcp-w6-probe-1"},
                    "hitCount": 12,
                    "lastHitTimeStamp": "2026-10-20T10:00:00Z",
                },
                {"rule": {"id": P2, "name": "mcp-w6-probe-2"}, "hitCount": 3},
            ]
        )
    )
    delete = probe.delete(HC).mock(return_value=httpx.Response(200, json={}))
    preview, done = await preview_apply(
        "fmc_clear_hit_counts",
        {"policy": "mcp-test-acp", "device": DEV["name"], "rules": ["mcp-w6-probe-1", "2"]},
    )
    shown = preview["preview"]
    assert shown["hits_lost"] == 15 and shown["rules_with_hits"] == 2
    assert [(r["rule"], r["hits"]) for r in shown["counters"]] == [
        ("mcp-w6-probe-1", 12),
        ("mcp-w6-probe-2", 3),
    ]
    assert delete.calls.last.request.url.params["filter"] == f"deviceId:{DEV['id']};ids:{P1},{P2}"
    assert done["result"]["cleared"] == 2
    preview, _ = await preview_apply(
        "fmc_clear_hit_counts", {"policy": "mcp-test-acp", "device": DEV["name"]}
    )
    assert preview["preview"]["rules"] == 3 and preview["preview"]["hits_lost"] == 15
    assert delete.calls.last.request.url.params["filter"] == f"deviceId:{DEV['id']}"  # every rule


async def test_clear_hit_counts_ignores_policy_locks(probe: respx.MockRouter) -> None:
    """F76: hit counts are the device's counters, not the policy's configuration, so another user's lock on
    the policy doesn't block clearing them (it does block rule edits)."""
    acp = copy.deepcopy(fixture("accesspolicies")["items"][0])
    acp["metadata"]["lockingStatus"] = {"status": "LOCKED", "userName": "alice"}
    probe.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([acp]))
    probe.put(HC).mock(return_value=httpx.Response(200, json={}))
    probe.get(HC).mock(return_value=items([{"rule": {"id": P1, "name": "mcp-w6-probe-1"}, "hitCount": 1}]))
    async with Client(server()) as c:
        out = await run(c, "fmc_clear_hit_counts", {"policy": "mcp-test-acp", "device": DEV["name"]})
        assert out["status"] == "preview" and "policy_lock" not in out["preview"]
        out = await run(
            c,
            "fmc_bulk_update_access_rules",
            {"policy": "mcp-test-acp", "select": {"names": ["mcp-w6-probe-1"]}, "set": {"enabled": False}},
        )
    assert out["status"] == "blocked" and "locked by alice" in out["blockers"][-1]


async def test_clear_every_rule_shows_the_default_action_counter(probe: respx.MockRouter) -> None:
    """Without rule ids FMC clears every rule on the device and, as recorded live on 10.0.1, the default
    action's counter too, so the preview shows it (apart from hits_lost)."""
    probe.put(HC).mock(return_value=httpx.Response(200, json={}))
    rows = [
        {"rule": {"id": P1, "name": "mcp-w6-probe-1"}, "hitCount": 4},
        {
            "rule": {"id": "da-1", "name": "Default Action", "type": "AccessPolicyDefaultAction"},
            "hitCount": 30,
            "lastHitTimeStamp": "2026-10-20T11:00:00Z",
        },
    ]
    probe.get(HC).mock(return_value=items(rows))
    async with Client(server()) as c:
        every = await run(c, "fmc_clear_hit_counts", {"policy": "mcp-test-acp", "device": DEV["name"]})
        some = await run(
            c, "fmc_clear_hit_counts", {"policy": "mcp-test-acp", "device": DEV["name"], "rules": ["1"]}
        )
    shown = every["preview"]
    assert shown["hits_lost"] == 4 and shown["default_action"]["hits"] == 30
    assert "resets the default action's counter too" in shown["default_action"]["note"]
    assert "default_action" not in some["preview"]  # ids given: only those rules are cleared


async def test_clear_prefilter_hit_counts(probe: respx.MockRouter) -> None:
    pf = {"id": "00000000-0000-0ed3-0000-021474960101", "type": "PrefilterPolicy", "name": "mcp-w6-pf"}
    probe.get(f"{CFG}/policy/prefilterpolicies").mock(return_value=items([pf]))
    pf_hc = f"{CFG}/policy/prefilterpolicies/{pf['id']}/operational/hitcounts"
    pf_rules = f"{CFG}/policy/prefilterpolicies/{pf['id']}/prefilterrules"
    rule = {"id": "pf-r1", "name": "mcp-w6-fastpath", "type": "PrefilterRule", "metadata": {"ruleIndex": 1}}
    probe.get(pf_rules).mock(return_value=items([rule]))
    probe.put(pf_hc).mock(return_value=httpx.Response(200, json={}))
    probe.get(pf_hc).mock(return_value=items([{"rule": {"id": "pf-r1"}, "hitCount": 7}]))
    delete = probe.delete(pf_hc).mock(return_value=httpx.Response(200, json={}))
    preview, done = await preview_apply(
        "fmc_clear_hit_counts",
        {"policy": pf["name"], "device": DEV["name"], "kind": "prefilter", "rules": ["mcp-w6-fastpath"]},
    )
    assert preview["preview"]["hits_lost"] == 7 and "default_action" not in preview["preview"]
    assert delete.calls.last.request.url.params["filter"] == f"deviceId:{DEV['id']};ids:pf-r1"
    assert done["result"]["cleared"] == 1


async def test_clear_hit_counts_unknown_rule(probe: respx.MockRouter) -> None:
    probe.put(HC).mock(return_value=httpx.Response(200, json={}))
    probe.get(HC).mock(return_value=items([]))
    async with Client(server()) as c:
        out = await run(
            c, "fmc_clear_hit_counts", {"policy": "mcp-test-acp", "device": DEV["name"], "rules": ["nope"]}
        )
    assert out["status"] == "blocked" and out["blockers"] == ["No rule 'nope' in 'mcp-test-acp'."]


# --- what FMC kept (W6 live, 2026-10-21) -------------------------------------------------------------

MONITOR = FX["monitor"]


async def test_monitor_rule_is_skipped_for_log_none(lab: respx.MockRouter) -> None:
    """The live call: log='none' on [ALLOW, MONITOR, ALLOW]. FMC keeps a MONITOR rule's end-of-connection
    logging, so the preview skips it with the reason instead of reporting it as changed."""
    rules = [*PROBE, MONITOR["rule"]]
    lab.get(RULES).mock(side_effect=honest(lab, rules))
    put = lab.put(RULES).mock(return_value=httpx.Response(200, json={"items": []}))
    preview, done = await preview_apply(
        "fmc_bulk_update_access_rules",
        {
            "policy": "mcp-test-acp",
            "select": {"names": ["mcp-w6-probe-1", "mcp-w6-monitor", "mcp-w6-probe-2"]},
            "set": {"log": "none"},
        },
    )
    shown = preview["preview"]
    assert [r["rule"] for r in shown["rules"]] == ["mcp-w6-probe-1", "mcp-w6-probe-2"]
    assert shown["skipped"] == [{"index": 4, "rule": "mcp-w6-monitor", "reason": bulk_rules.MONITOR_LOG_SKIP}]
    assert [b["id"] for b in sent(put)] == [P1, P2]
    assert done["result"]["applied"] == 2


async def test_monitor_rule_only_loses_begin_logging(lab: respx.MockRouter) -> None:
    rules = [*PROBE, {**MONITOR["rule"], "logBegin": True}]
    lab.get(RULES).mock(side_effect=honest(lab, rules))
    put = lab.put(RULES).mock(return_value=httpx.Response(200, json={"items": []}))
    preview, _ = await preview_apply(
        "fmc_bulk_update_access_rules",
        {"policy": "mcp-test-acp", "select": {"names": ["mcp-w6-monitor"]}, "set": {"log": "none"}},
    )
    (row,) = preview["preview"]["rules"]
    assert row["changes"] == {"logBegin": {"from": True, "to": False}}
    assert row["note"] == bulk_rules.MONITOR_LOG_NOTE
    assert sent(put) == [{"id": MONITOR["rule"]["id"], "type": "AccessRule", "logBegin": False}]


async def test_fields_fmc_kept_are_reported_not_applied(lab: respx.MockRouter) -> None:
    """FMC answered 200 but the GET afterwards shows the rule unchanged (as it did for the MONITOR rule):
    the result names the rule and the fields under kept_by_fmc and doesn't count it as applied."""
    keeps = MONITOR["rule"]["id"]

    def get(request: httpx.Request) -> httpx.Response:
        rows = honest(lab, [*PROBE, MONITOR["rule"]])(request).json()["items"]
        return items([MONITOR["after"] if r["id"] == keeps else r for r in rows])

    lab.get(RULES).mock(side_effect=get)
    lab.put(RULES).mock(return_value=httpx.Response(200, json={"items": []}))
    _, done = await preview_apply(
        "fmc_bulk_update_access_rules",
        {
            "policy": "mcp-test-acp",
            "select": {"names": ["mcp-w6-probe-3", "mcp-w6-monitor"]},
            "set": {"enabled": False},
        },
    )
    result = done["result"]
    assert result["applied"] == 0 and result["rules"] == []  # probe-3 is disabled already: not sent
    assert result["kept_by_fmc"] == [
        {"rule": "mcp-w6-monitor", "fields": {"enabled": {"sent": False, "fmc_has": True}}}
    ]
    assert "left 1 rule(s) without the change" in result["warning"]


async def test_kept_by_fmc_reads_the_live_monitor_answer(lab: respx.MockRouter) -> None:
    """What the tool sent before this fix (logEnd/sendEventsToFMC false) against the rule FMC kept."""
    lab.get(RULES).mock(return_value=items([MONITOR["after"]]))
    app = FmcApp(make_settings())
    try:
        kept, why = await bulk_rules.kept_by_fmc(
            app, RULES, [MONITOR["sent"]], {MONITOR["rule"]["id"]: "mcp-w6-monitor"}
        )
    finally:
        await app.aclose()
    assert why is None
    assert kept == [
        {
            "rule": "mcp-w6-monitor",
            "fields": {
                "logEnd": {"sent": False, "fmc_has": True},
                "sendEventsToFMC": {"sent": False, "fmc_has": True},
            },
        }
    ]


async def test_a_failed_read_back_says_unverified(probe: respx.MockRouter) -> None:
    calls = {"n": 0}

    def get(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] > 2:  # preview + confirm read the rules; the read-back fails
            return httpx.Response(500, json={"error": {"messages": [{"description": "boom"}]}})
        return items(PROBE)

    probe.get(RULES).mock(side_effect=get)
    probe.put(RULES).mock(return_value=httpx.Response(200, json={"items": []}))
    _, done = await preview_apply(
        "fmc_bulk_update_access_rules",
        {"policy": "mcp-test-acp", "select": {"ids": [P1]}, "set": {"enabled": False}},
    )
    assert done["result"]["applied"] == 1 and done["result"]["verified"].startswith("Not verified")

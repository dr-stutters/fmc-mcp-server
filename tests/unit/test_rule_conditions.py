"""F66: application, application-filter, VLAN-tag, time-range and SGT conditions of access rules, plus
fmc_find_application, fmc_create_application_filter and fmc_create_time_range.

Shapes recorded from FMC 10.0.1 (tests/fixtures/rule_conditions.json): the application catalogue ignores
`filter=`, the custom SGT list answers 422 while ISE is enabled, time ranges carry minute-precision local
times."""

import json
from datetime import datetime
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.refs import vlan_literal
from fmc_mcp.rule_conditions import (
    app_labels,
    condition_text,
    filter_row,
    merge_app_block,
    relabel_changes,
    sgt_label,
    time_range_row,
)
from fmc_mcp.rules import flatten_access_rule
from fmc_mcp.server import create_server
from fmc_mcp.tools.common import ref_label
from fmc_mcp.tools.conditions import in_effect

from .conftest import ACP_ID, CFG, empty, fixture, items, make_settings

FX = fixture("rule_conditions")
RULES = f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules"
HTTP = {"id": "676", "type": "Application", "name": "HTTP"}
SSH = {"id": "846", "type": "Application", "name": "SSH"}
EMPLOYEES = {"id": "93ad6890-8c01-11e6-996c-525400b48521", "type": "ISESecurityGroupTag", "name": "Employees"}
PCI = {"id": "93f91790-8c01-11e6-996c-525400b48521", "type": "ISESecurityGroupTag", "name": "PCI_Servers"}
EXPIRED = FX["timeranges"]["items"][0]
WORKDAY = {
    "id": "00000000-0000-0ed3-0000-021474960001",
    "type": "TimeRange",
    "name": "mcp-w6-workday",
    "recurrenceList": [
        {
            "recurrenceType": "DAILY_INTERVAL",
            "days": ["MON", "TUE", "WED", "THU", "FRI"],
            "dailyStartTime": "08:00",
            "dailyEndTime": "18:00",
        }
    ],
}
# The spec's list shape (metadata.count): FMC 10.0.1 lists no filter created over its API (the live list
# stays empty, fixture applicationfilters_empty); its POST answer is applicationfilter_created.
FILTER = {
    "id": "00000000-0000-0ed3-0000-021474960002",
    "type": "ApplicationFilter",
    "name": "mcp-w6-high-risk",
    "appConditions": [{"risks": [{"id": "HIGH", "type": "ApplicationRisk", "name": "High"}]}],
    "metadata": {"count": 1946},
}
VLAN_OBJ = {"id": "00000000-0000-0ed3-0000-021474960003", "type": "VlanTag", "name": "mcp-w6-vlan20"}


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


def body(fx: dict[str, Any]) -> httpx.Response:
    return httpx.Response(200, json={k: v for k, v in fx.items() if k != "_source"})


@pytest.fixture
def conds(lab: respx.MockRouter) -> respx.MockRouter:
    lab.get(f"{CFG}/object/applications", name="apps").mock(return_value=body(FX["applications_page"]))
    lab.get(f"{CFG}/object/applications/676", name="http").mock(return_value=body(FX["application_http"]))
    lab.get(f"{CFG}/object/applications/846").mock(return_value=body(FX["application_ssh"]))
    lab.get(f"{CFG}/object/applications/424242").mock(return_value=httpx.Response(404, json={}))
    lab.get(f"{CFG}/object/applicationfilters").mock(return_value=items([FILTER]))
    lab.get(f"{CFG}/object/applicationcategories").mock(return_value=body(FX["applicationcategories"]))
    lab.get(f"{CFG}/object/applicationtags").mock(return_value=body(FX["applicationtags"]))
    lab.get(f"{CFG}/object/isesecuritygrouptags", name="isesgts").mock(
        return_value=body(FX["isesecuritygrouptags"])
    )
    lab.get(f"{CFG}/object/securitygrouptags", name="customsgts").mock(
        return_value=httpx.Response(422, json={"error": FX["securitygrouptags_ise_enabled"]["error"]})
    )
    lab.get(f"{CFG}/object/timeranges").mock(return_value=items([EXPIRED, WORKDAY]))
    lab.get(f"{CFG}/object/vlantags").mock(return_value=items([VLAN_OBJ]))
    lab.get(f"{CFG}/object/vlangrouptags").mock(return_value=empty())
    return lab


# --- helpers ---------------------------------------------------------------------------------------


def test_vlan_literals_and_labels() -> None:
    assert vlan_literal("10") == {"type": "VlanTagLiteral", "startTag": 10, "endTag": 10}
    assert vlan_literal(" 100 - 110 ") == {"type": "VlanTagLiteral", "startTag": 100, "endTag": 110}
    assert vlan_literal("mcp-w6-vlan20") is None
    with pytest.raises(Exception, match="1-4094"):
        vlan_literal("4095")
    with pytest.raises(Exception, match="1-4094"):
        vlan_literal("20-10")
    assert ref_label({"type": "VlanTagLiteral", "startTag": 10, "endTag": 10}) == "VLAN 10"
    assert ref_label({"type": "VlanTagLiteral", "startTag": 100, "endTag": 110}) == "VLAN 100-110"


def test_app_block_merge_and_labels() -> None:
    cur = {"applications": [HTTP], "applicationFilters": [{"id": "f", "name": "mcp-w6-high-risk"}]}
    assert merge_app_block(cur, [SSH], None) == {
        "applications": [SSH],
        "applicationFilters": cur["applicationFilters"],
    }
    assert merge_app_block(cur, None, []) == {"applications": [HTTP]}
    assert merge_app_block(cur, [], []) == {}
    inline = {"inlineApplicationFilters": [{"risks": [{"id": "HIGH", "name": "High"}]}]}
    assert merge_app_block(inline, [], None) == inline  # inline filters are kept
    assert app_labels({**cur, **inline}) == ["HTTP", "filter:mcp-w6-high-risk", "inline-filter:risk High"]
    cond = {
        "risks": [{"name": "High"}, {"name": "Very High"}],
        "categories": [{"name": "file sharing"}],
    }
    assert condition_text(cond) == "risk High or Very High and category file sharing"


def test_sgt_labels_and_flatten() -> None:
    tags = {EMPLOYEES["id"]: (4, "ISE")}
    assert sgt_label(EMPLOYEES) == "Employees"
    assert sgt_label(EMPLOYEES, tags) == "Employees (SGT 4)"
    assert sgt_label({"type": "SecurityGroupTag", "name": "mcp-w6-sgt", "tag": 23}) == "mcp-w6-sgt (SGT 23)"
    rule = {
        "name": "r",
        "action": "ALLOW",
        "sourceSecurityGroupTags": {"objects": [EMPLOYEES]},
        "vlanTags": {
            "objects": [VLAN_OBJ],
            "literals": [{"type": "VlanTagLiteral", "startTag": 10, "endTag": 10}],
        },
        "timeRangeObjects": [WORKDAY],
        "applications": {"applications": [HTTP]},
    }
    row = flatten_access_rule(rule, tags)
    assert row["src_sgts"] == ["Employees (SGT 4)"]
    assert row["vlan_tags"] == ["mcp-w6-vlan20", "VLAN 10"]
    assert row["time_ranges"] == ["mcp-w6-workday"]
    assert row["applications"] == ["HTTP"]


def test_relabel_changes() -> None:
    cur = {"applications": {"applications": [HTTP]}, "timeRangeObjects": [WORKDAY]}
    new = {"applications": {"applications": [HTTP, SSH]}, "sourceSecurityGroupTags": {"objects": [EMPLOYEES]}}
    changes = {"applications.applications": {"from": "...", "to": "..."}, "timeRangeObjects": {}}
    out = relabel_changes(changes, cur, new, {EMPLOYEES["id"]: (4, "ISE")})
    assert out == {
        "applications": {"from": ["HTTP"], "to": ["HTTP", "SSH"]},
        "timeRangeObjects": {"from": ["mcp-w6-workday"], "to": "any"},
        "sourceSecurityGroupTags": {"from": "any", "to": ["Employees (SGT 4)"]},
    }


def test_time_range_rows_and_in_effect() -> None:
    now = datetime(2026, 10, 20, 9, 30)  # a Tuesday
    assert time_range_row(EXPIRED, now)["ended"] is True
    assert time_range_row(WORKDAY, now) == {
        "name": "mcp-w6-workday",
        "start": "now",
        "end": "never",
        "recurring": ["MON,TUE,WED,THU,FRI 08:00-18:00"],
    }
    assert in_effect(WORKDAY, now) is True
    assert in_effect(WORKDAY, datetime(2026, 10, 20, 19, 0)) is False
    assert in_effect(WORKDAY, datetime(2026, 10, 25, 9, 30)) is False  # Sunday
    assert in_effect(EXPIRED, now) is False
    weekend = {
        "recurrenceList": [
            {
                "recurrenceType": "RANGE",
                "rangeStartDay": "FRI",
                "rangeStartTime": "18:00",
                "rangeEndDay": "MON",
                "rangeEndTime": "06:00",
            }
        ]
    }
    assert in_effect(weekend, datetime(2026, 10, 25, 12, 0)) is True  # Sunday noon
    assert in_effect(weekend, datetime(2026, 10, 26, 5, 59)) is True  # Monday early
    assert in_effect(weekend, now) is False
    overnight = {
        "recurrenceList": [
            {
                "recurrenceType": "DAILY_INTERVAL",
                "days": ["TUE"],
                "dailyStartTime": "22:00",
                "dailyEndTime": "06:00",
            }
        ]
    }
    assert in_effect(overnight, datetime(2026, 10, 20, 23, 0)) is True
    assert in_effect(overnight, now) is False


# --- access rule writes ----------------------------------------------------------------------------


async def test_create_rule_with_every_new_condition(conds: respx.MockRouter) -> None:
    post = conds.post(RULES).mock(return_value=httpx.Response(201, json={"id": "new", "name": "mcp-w6-app"}))
    preview, _ = await preview_apply(
        "fmc_create_access_rule",
        {
            "policy": "mcp-test-acp",
            "name": "mcp-w6-app",
            "action": "ALLOW",
            "applications": ["http", "846", "HTTP"],
            "application_filters": ["mcp-w6-high-risk"],
            "vlan_tags": ["mcp-w6-vlan20", "10", "100-110"],
            "time_range": "mcp-w6-workday",
            "source_sgts": ["Employees"],
            "destination_sgts": ["14"],
        },
    )
    sent = json.loads(post.calls.last.request.content)
    assert sent["applications"] == {
        "applications": [HTTP, SSH],
        "applicationFilters": [{"id": FILTER["id"], "type": "ApplicationFilter", "name": "mcp-w6-high-risk"}],
    }
    assert sent["vlanTags"] == {
        "objects": [VLAN_OBJ],
        "literals": [
            {"type": "VlanTagLiteral", "startTag": 10, "endTag": 10},
            {"type": "VlanTagLiteral", "startTag": 100, "endTag": 110},
        ],
    }
    assert sent["timeRangeObjects"] == [{"id": WORKDAY["id"], "type": "TimeRange", "name": "mcp-w6-workday"}]
    assert sent["sourceSecurityGroupTags"] == {"objects": [EMPLOYEES]}
    assert sent["destinationSecurityGroupTags"] == {"objects": [PCI]}
    shown = preview["preview"]
    assert shown["rule"]["src_sgts"] == ["Employees (SGT 4)"]
    assert shown["rule"]["dst_sgts"] == ["PCI_Servers (SGT 14)"]
    assert shown["rule"]["vlan_tags"] == ["mcp-w6-vlan20", "VLAN 10", "VLAN 100-110"]
    assert shown["rule"]["applications"] == ["HTTP", "SSH", "filter:mcp-w6-high-risk"]
    assert shown["sgts"] == {
        "source": [{"name": "Employees", "tag": 4, "source": "ISE"}],
        "destination": [{"name": "PCI_Servers", "tag": 14, "source": "ISE"}],
    }
    assert shown["time_range"]["recurring"] == ["MON,TUE,WED,THU,FRI 08:00-18:00"]
    effects = " | ".join(preview["side_effects"])
    assert "Snort has identified the application" in effects
    assert "own time zone" in effects
    assert "pxGrid" in effects
    assert "only to traffic on inline sets" in effects  # VLAN rules never match on routed interfaces
    # the catalogue index was read once for two names; the numeric id with one GET
    assert conds.routes["apps"].call_count == 1
    assert conds.routes["customsgts"].call_count >= 1  # 422 while ISE is on: treated as "no custom SGTs"


async def test_create_rule_with_expired_time_range_warns(conds: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_create_access_rule",
            {"policy": "mcp-test-acp", "name": "x", "action": "ALLOW", "time_range": "mcp-test-hyg-expired"},
        )
    assert out["status"] == "preview" and not out.get("blockers")
    assert "ended 2024-12-26T23:59: the rule will never match" in out["side_effects"][0]
    assert not any("inline sets" in e for e in out["side_effects"])  # no VLAN tags, no VLAN note
    assert out["preview"]["time_range"]["ended"] is True


async def test_unknown_application_sgt_and_filter_are_refused(conds: respx.MockRouter) -> None:
    base = {"policy": "mcp-test-acp", "name": "x", "action": "BLOCK"}
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="No application named 'HTTPX'.*Close: HTTP"):
            await run(c, "fmc_create_access_rule", {**base, "applications": ["HTTPX"]})
        with pytest.raises(ToolError, match="No application with id 424242"):
            await run(c, "fmc_create_access_rule", {**base, "applications": ["424242"]})
        with pytest.raises(ToolError, match="No security group tag 'Employes'.*Did you mean: Employees"):
            await run(c, "fmc_create_access_rule", {**base, "source_sgts": ["Employes"]})
        with pytest.raises(ToolError, match="No application filter named 'nope'"):
            await run(c, "fmc_create_access_rule", {**base, "application_filters": ["nope"]})


async def test_custom_sgts_when_ise_is_off(conds: respx.MockRouter) -> None:
    conds.routes["isesgts"].mock(
        return_value=httpx.Response(
            422,
            json={
                "error": {
                    "messages": [
                        {
                            "description": "Request cannot be processed because Identity "
                            "Service Engine is disabled"
                        }
                    ]
                }
            },
        )
    )
    custom = {"id": "c-23", "type": "SecurityGroupTag", "name": "mcp-w6-sgt", "tag": 23}
    conds.routes["customsgts"].mock(return_value=items([custom]))
    post = conds.post(RULES).mock(return_value=httpx.Response(201, json={"id": "n", "name": "x"}))
    preview, _ = await preview_apply(
        "fmc_create_access_rule",
        {"policy": "mcp-test-acp", "name": "x", "action": "ALLOW", "source_sgts": ["23"]},
    )
    assert preview["preview"]["rule"]["src_sgts"] == ["mcp-w6-sgt (SGT 23)"]
    sent = json.loads(post.calls.last.request.content)
    assert sent["sourceSecurityGroupTags"] == {
        "objects": [{"id": "c-23", "type": "SecurityGroupTag", "name": "mcp-w6-sgt"}]
    }


def rules_with(**fields: Any) -> dict[str, Any]:
    data = fixture("accessrules")
    for r in data["items"]:
        if r["name"] == "mcp-test-allow-web":
            r.update(fields)
    return data


async def test_update_replaces_only_the_given_parts(conds: respx.MockRouter) -> None:
    filt = {"id": FILTER["id"], "type": "ApplicationFilter", "name": "mcp-w6-high-risk"}
    data = rules_with(
        applications={"applications": [HTTP], "applicationFilters": [filt]},
        timeRangeObjects=[{"id": WORKDAY["id"], "type": "TimeRange", "name": "mcp-w6-workday"}],
        sourceSecurityGroupTags={"objects": [EMPLOYEES]},
        vlanTags={"literals": [{"type": "VlanTagLiteral", "startTag": 10, "endTag": 10}]},
    )
    conds.get(RULES).mock(return_value=httpx.Response(200, json=data))
    rule = next(r for r in data["items"] if r["name"] == "mcp-test-allow-web")
    put = conds.put(f"{RULES}/{rule['id']}").mock(return_value=httpx.Response(200, json=rule))
    preview, _ = await preview_apply(
        "fmc_update_access_rule",
        {
            "policy": "mcp-test-acp",
            "rule": "mcp-test-allow-web",
            "applications": ["SSH"],
            "time_range": "",
            "source_sgts": [],
            "destination_sgts": ["PCI_Servers"],
            "vlan_tags": ["100-110"],
        },
    )
    changes = preview["preview"]["changes"]
    assert changes["applications"] == {
        "from": ["HTTP", "filter:mcp-w6-high-risk"],
        "to": ["SSH", "filter:mcp-w6-high-risk"],
    }
    assert changes["timeRangeObjects"] == {"from": ["mcp-w6-workday"], "to": "any"}
    assert changes["sourceSecurityGroupTags"] == {"from": ["Employees (SGT 4)"], "to": "any"}
    assert changes["destinationSecurityGroupTags"] == {"from": "any", "to": ["PCI_Servers (SGT 14)"]}
    assert changes["vlanTags"] == {"from": ["VLAN 10"], "to": ["VLAN 100-110"]}
    assert any("only to traffic on inline sets" in e for e in preview["side_effects"])
    assert not any(k.startswith("applications.") for k in changes)
    sent = json.loads(put.calls.last.request.content)
    assert sent["applications"] == {"applications": [SSH], "applicationFilters": [filt]}
    assert "timeRangeObjects" not in sent and "sourceSecurityGroupTags" not in sent
    assert sent["destinationSecurityGroupTags"] == {"objects": [PCI]}
    # conditions not given are kept as they are
    assert sent["destinationNetworks"] == rule["destinationNetworks"]


async def test_update_empty_lists_clear_the_application_block(conds: respx.MockRouter) -> None:
    data = rules_with(applications={"applications": [HTTP]})
    conds.get(RULES).mock(return_value=httpx.Response(200, json=data))
    rule = next(r for r in data["items"] if r["name"] == "mcp-test-allow-web")
    put = conds.put(f"{RULES}/{rule['id']}").mock(return_value=httpx.Response(200, json=rule))
    preview, _ = await preview_apply(
        "fmc_update_access_rule", {"policy": "mcp-test-acp", "rule": "mcp-test-allow-web", "applications": []}
    )
    assert preview["preview"]["changes"]["applications"] == {"from": ["HTTP"], "to": "any"}
    assert "applications" not in json.loads(put.calls.last.request.content)
    assert conds.routes["apps"].call_count == 0  # nothing to resolve


# --- rule lookup -----------------------------------------------------------------------------------


async def test_rule_lookup_labels_sgts_with_tags(conds: respx.MockRouter) -> None:
    conds.get(RULES).mock(
        return_value=httpx.Response(
            200,
            json=rules_with(sourceSecurityGroupTags={"objects": [EMPLOYEES]}, destinationNetworks={}),
        )
    )
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_rule_lookup",
            {"policy": "mcp-test-acp", "source": "192.0.2.10", "destination": "198.51.100.10", "port": 443},
        )
    first = out["may_match_first"][0]
    assert first["name"] == "mcp-test-allow-web"
    assert first["src_sgts"] == ["Employees (SGT 4)"]
    assert "sourceSecurityGroupTags" in first["depends_on"]


# --- fmc_find_application ---------------------------------------------------------------------------


async def test_find_application_exact_partial_and_id(conds: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_find_application", {"text": "http", "kind": "application"})
        assert out["applications"] == [
            {
                "name": "HTTP",
                "id": "676",
                "risk": "Very Low",
                "business_relevance": "Medium",
                "categories": ["network protocols/services"],
                "tags": ["file sharing/transfer", "allows remote connect", "opens port"],
                "types": ["Server"],
            }
        ]
        assert out["similar_applications"] == ["HTTP/2 (90002)", "HTTPS (90001)"]
        assert out["catalogue_size"] == 11 and "can't filter" in out["index_note"]
        out = await run(c, "fmc_find_application", {"text": "face", "kind": "application", "limit": 1})
        assert out["applications"] == [] and out["similar_applications"] == ["Facebook (90003)"]
        assert out["similar_total"] == 2
        out = await run(c, "fmc_find_application", {"text": "676", "kind": "application"})
        assert out["applications"][0]["name"] == "HTTP" and "similar_applications" not in out
        out = await run(c, "fmc_find_application", {"text": "nothing-like-it"})
        assert out["summary"] == "Nothing matches 'nothing-like-it'."
    assert conds.routes["apps"].call_count == 1  # one index read per server


async def test_find_application_filters_and_attributes(conds: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_find_application", {"text": "high"})
    assert out["application_filters"] == [
        {"name": "mcp-w6-high-risk", "id": FILTER["id"], "conditions": ["risk High"], "matches_apps": 1946}
    ]
    assert out["attributes"]["risks"] == ["High", "Very High"]
    async with Client(server()) as c:
        out = await run(c, "fmc_find_application", {"text": "sharing", "kind": "attribute"})
    assert out["attributes"] == {"categories": ["file sharing"]}


def test_filter_row_caps_the_matched_applications() -> None:
    """The spec's GET example lists the applications a filter's conditions match: show a few."""
    apps = [{"id": str(i), "type": "Application", "name": f"app{i}"} for i in range(25)]
    row = filter_row({**FILTER, "applications": apps})
    assert row["applications"] == [f"app{i}" for i in range(10)]
    assert row["applications_total"] == 25 and row["matches_apps"] == 1946
    assert "applications_total" not in filter_row({**FILTER, "applications": apps[:3]})


# --- fmc_create_application_filter -----------------------------------------------------------------


async def test_create_application_filter(conds: respx.MockRouter) -> None:
    conds.get(f"{CFG}/object/applicationfilters").mock(return_value=empty())
    post = conds.post(f"{CFG}/object/applicationfilters").mock(
        return_value=httpx.Response(201, json={"id": "f-new", "name": "mcp-w6-risky-sharing"})
    )
    preview, done = await preview_apply(
        "fmc_create_application_filter",
        {
            "name": "mcp-w6-risky-sharing",
            "risks": ["high", "Very High", "HIGH"],
            "categories": ["File Sharing"],
            "tags": ["opens port"],
            "types": ["webapp"],
            "applications": ["SSH"],
        },
    )
    sent = json.loads(post.calls.last.request.content)
    assert sent == {
        "name": "mcp-w6-risky-sharing",
        "type": "ApplicationFilter",
        "applications": [SSH],
        "appConditions": [
            {
                "risks": [
                    {"id": "HIGH", "type": "ApplicationRisk", "name": "High"},
                    {"id": "VERY_HIGH", "type": "ApplicationRisk", "name": "Very High"},
                ],
                "applicationTypes": [{"id": "WEBAPP", "type": "ApplicationType", "name": "Webapp"}],
                "categories": [{"id": "90101", "type": "ApplicationCategory", "name": "file sharing"}],
                "tags": [{"id": "98", "type": "ApplicationTag", "name": "opens port"}],
            }
        ],
    }
    assert preview["preview"]["matches"] == (
        "applications SSH or every application with risk High or Very High and category file sharing and "
        "tag opens port and type Webapp"
    )
    assert done["status"] == "applied"


async def test_create_application_filter_checks(conds: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_create_application_filter", {"name": "mcp-w6-high-risk", "risks": ["High"]})
        assert out["status"] == "blocked"
        assert "already exists" in " ".join(out.get("blockers") or [])
        with pytest.raises(ToolError, match="Give applications or at least one attribute"):
            await run(c, "fmc_create_application_filter", {"name": "x"})
        with pytest.raises(ToolError, match="Unknown risk 'severe'"):
            await run(c, "fmc_create_application_filter", {"name": "x", "risks": ["severe"]})
        with pytest.raises(ToolError, match="No application category 'sharing'.*file sharing"):
            await run(c, "fmc_create_application_filter", {"name": "x", "categories": ["sharing"]})


# --- fmc_create_time_range -------------------------------------------------------------------------


async def test_create_time_range(conds: respx.MockRouter) -> None:
    post = conds.post(f"{CFG}/object/timeranges").mock(
        return_value=httpx.Response(201, json={"id": "t-new", "name": "mcp-w6-business-hours"})
    )
    args = {
        "name": "mcp-w6-business-hours",
        "start": "2026-10-20",
        "end": "2027-01-01 00:00:00",
        "recurrences": [
            {
                "days": ["mon", "Tuesday", "WED", "THU", "FRI", "MON"],
                "start_time": "8:00",
                "end_time": "18:00",
            },
            {"start_day": "sat", "start_time": "09:00", "end_day": "SUN", "end_time": "12:00"},
        ],
    }
    preview, done = await preview_apply("fmc_create_time_range", args)
    sent = json.loads(post.calls.last.request.content)
    assert sent == {
        "name": "mcp-w6-business-hours",
        "type": "TimeRange",
        "effectiveStartDateTime": "2026-10-20T00:00",
        "effectiveEndDateTime": "2027-01-01T00:00",
        "recurrenceList": [
            {
                "recurrenceType": "DAILY_INTERVAL",
                "days": ["MON", "TUE", "WED", "THU", "FRI"],
                "dailyStartTime": "08:00",
                "dailyEndTime": "18:00",
            },
            {
                "recurrenceType": "RANGE",
                "rangeStartDay": "SAT",
                "rangeStartTime": "09:00",
                "rangeEndDay": "SUN",
                "rangeEndTime": "12:00",
            },
        ],
    }
    shown = preview["preview"]
    assert shown["time_range"]["recurring"] == [
        "MON,TUE,WED,THU,FRI 08:00-18:00",
        "weekly SAT 09:00 to SUN 12:00",
    ]
    assert isinstance(shown["in_effect_now"], bool)
    assert any("own time zone" in e for e in preview["side_effects"])
    assert done["status"] == "applied"


async def test_create_time_range_checks(conds: respx.MockRouter) -> None:
    async with Client(server()) as c:
        out = await run(c, "fmc_create_time_range", {"name": "mcp-test-hyg-expired", "end": "2020-01-01"})
        assert "already exists" in " ".join(out.get("blockers") or [])
        assert "ends in the past" in out["side_effects"][0]
        for bad, msg in (
            ({"start": "2026-10-21", "end": "2026-10-20"}, "end must be after start"),
            ({"start": "tomorrow"}, "must be a date"),
            ({"start": "2026-10-20T08:00+02:00"}, "leave out the time zone"),
            ({"recurrences": [{"start_time": "08:00", "end_time": "09:00"}]}, "Give days"),
            ({"recurrences": [{"days": ["XYZ"], "start_time": "08:00", "end_time": "09:00"}]}, "Unknown day"),
            ({"recurrences": [{"days": ["MON"], "start_time": "25:00", "end_time": "09:00"}]}, "HH:MM"),
            (
                {"recurrences": [{"start_day": "FRI", "start_time": "08:00", "end_time": "09:00"}]},
                "start_day and end_day",
            ),
        ):
            with pytest.raises(ToolError, match=msg):
                await run(c, "fmc_create_time_range", {"name": "x", **bad})


# --- live FMC 10.0.1 shapes (W6 live-B1, 2026-10-21) ------------------------------------------------

LIVE = FX["live_rules"]


def test_live_rule_gets_read_back_as_authored() -> None:
    """The rules fmc_create_access_rule made, as FMC 10.0.1 returns them: every condition shows by name."""
    rows = {k: flatten_access_rule(v) for k, v in LIVE.items() if k != "_source"}
    assert rows["app_ssh"]["applications"] == ["SSH"]
    assert rows["time_now"]["time_ranges"] == ["mcp-w6-tr-now"] and rows["time_now"]["dst_ports"] == [
        "TCP/443"
    ]
    assert rows["vlan"]["vlan_tags"] == ["VLAN 100"]
    assert rows["app_filter"]["applications"] == ["filter:mcp-w6-appfilter"]
    assert "vlan_tags" not in rows["app_ssh"]  # FMC's empty vlanTags {} is no condition


async def test_update_keeps_fmcs_application_default_port_flag(conds: respx.MockRouter) -> None:
    """FMC adds applicationDefaultPort: false to every applications block: a new list keeps it, [] drops the
    whole block (the live GET then had no applications key) and the other conditions stay."""
    rule = LIVE["app_ssh"]
    conds.get(RULES).mock(return_value=items([rule]))
    put = conds.put(f"{RULES}/{rule['id']}").mock(return_value=httpx.Response(200, json=rule))
    base = {"policy": "mcp-test-acp", "rule": "mcp-w6-app-ssh"}
    preview, _ = await preview_apply("fmc_update_access_rule", {**base, "applications": ["SSH", "HTTP"]})
    assert preview["preview"]["changes"]["applications"] == {"from": ["SSH"], "to": ["SSH", "HTTP"]}
    sent = json.loads(put.calls.last.request.content)
    assert sent["applications"] == {"applicationDefaultPort": False, "applications": [SSH, HTTP]}
    assert sent["destinationNetworks"] == rule["destinationNetworks"]
    preview, _ = await preview_apply("fmc_update_access_rule", {**base, "applications": []})
    assert preview["preview"]["changes"]["applications"] == {"from": ["SSH"], "to": "any"}
    sent = json.loads(put.calls.last.request.content)
    assert "applications" not in sent and sent["sourceNetworks"] == rule["sourceNetworks"]


def test_time_range_fmc_stored_without_a_start() -> None:
    """FMC answers effectiveStartDateTime 'Started' for a range created without a start."""
    tr = {k: v for k, v in FX["timerange_started"].items() if k != "_source"}
    row = time_range_row(tr, datetime(2026, 10, 21, 6, 0))
    assert row == {
        "name": "mcp-w6-tr-now",
        "start": "Started",
        "end": "2026-10-23T23:59",
        "recurring": ["MON,TUE,WED,THU,FRI,SAT,SUN 00:00-23:59"],
    }
    assert time_range_row(tr, datetime(2026, 10, 24, 6, 0))["ended"] is True


async def test_create_application_filter_live_body_and_answer(conds: respx.MockRouter) -> None:
    """The live call: risks=['High', 'Very High'] sends no condition 'type' and FMC answers 201 with the
    condition's 'search' text and an empty metadata."""
    answer = {k: v for k, v in FX["applicationfilter_created"].items() if k != "_source"}
    conds.get(f"{CFG}/object/applicationfilters").mock(return_value=body(FX["applicationfilters_empty"]))
    post = conds.post(f"{CFG}/object/applicationfilters").mock(return_value=httpx.Response(201, json=answer))
    _, done = await preview_apply(
        "fmc_create_application_filter", {"name": "mcp-w6-appfilter", "risks": ["High", "Very High"]}
    )
    assert json.loads(post.calls.last.request.content) == {
        "name": "mcp-w6-appfilter",
        "type": "ApplicationFilter",
        "appConditions": [{"risks": answer["appConditions"][0]["risks"]}],
    }
    assert done["status"] == "applied" and done["result"]["id"] == answer["id"]
    assert filter_row(answer) == {
        "name": "mcp-w6-appfilter",
        "id": answer["id"],
        "conditions": ["risk High or Very High"],
    }

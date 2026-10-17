from datetime import UTC, datetime
from typing import Any

import httpx
import respx

from fmc_mcp._core.testing import call_tool
from fmc_mcp.catalog import Catalog
from fmc_mcp.server import create_server
from fmc_mcp.tools.hygiene import consolidation, duplicate_objects, expired_time_ranges, permissive

from .conftest import ACP_ID, CFG, fixture, items, make_settings

STATIC = ["shadowed", "permissive", "no_intrusion", "no_logging", "disabled", "consolidation"]


async def call(name: str, args: dict[str, Any] | None = None) -> Any:
    return await call_tool(create_server(make_settings()), name, args or {})


def rule(name: str, index: int, action: str = "ALLOW", **fields: Any) -> dict[str, Any]:
    return {
        "id": f"id-{name}",
        "name": name,
        "action": action,
        "enabled": True,
        "metadata": {"ruleIndex": index, "section": "Default", "category": "--Undefined--"},
        **fields,
    }


def nets(*names: str) -> dict[str, Any]:
    return {"objects": [{"name": n, "id": f"obj-{n}", "type": "Host"} for n in names]}


async def test_audit_ranks_seeded_findings(lab: respx.MockRouter) -> None:
    data = await call("fmc_policy_audit", {"policy": "mcp-test-acp", "checks": STATIC})
    findings = data["findings"]
    by = {(f["check"], f.get("rule", {}).get("name")): f for f in findings}
    assert by[("shadowed", "mcp-test-shadowed")]["severity"] == "high"
    assert by[("shadowed", "mcp-test-shadowed")]["covered_by"] == "mcp-test-block-app"
    assert "move_to=4" in by[("shadowed", "mcp-test-shadowed")]["fix"]
    assert by[("shadowed", "mcp-test-redundant")]["severity"] == "medium"
    assert by[("disabled", "mcp-test-disabled")]["severity"] == "info"
    assert ("no_intrusion", "mcp-test-allow-web") in by
    assert ("no_logging", "mcp-test-block-app") in by
    assert not any(f["check"] == "permissive" for f in findings)  # the URL rule has a condition
    assert [f["severity"] for f in findings] == sorted(
        (f["severity"] for f in findings), key=["high", "medium", "low", "info"].index
    )
    assert data["summary"]["checks_run"] == STATIC
    assert data["summary"]["by_severity"]["high"] == 1


async def test_audit_reads_hit_counts_from_assigned_devices_and_ha_members(lab: respx.MockRouter) -> None:
    lab.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items(
            [
                {
                    "policy": {"id": ACP_ID, "type": "AccessPolicy"},
                    "targets": [
                        {"id": "dev-1", "name": "ftd1", "type": "Device"},
                        {"id": "ha-1", "name": "ha", "type": "DeviceHAPair"},
                    ],
                }
            ]
        )
    )
    lab.get(f"{CFG}/devicehapairs/ftddevicehapairs/ha-1").mock(
        return_value=httpx.Response(
            200,
            json={"primary": {"id": "dev-2", "name": "ftd2"}, "secondary": {"id": "dev-3", "name": "ftd3"}},
        )
    )
    rules = fixture("accessrules")["items"]
    web = next(r for r in rules if r["name"] == "mcp-test-allow-web")
    ssh = next(r for r in rules if r["name"] == "mcp-test-ssh-admin")
    hc = f"{CFG}/policy/accesspolicies/{ACP_ID}/operational/hitcounts"

    def hitcounts(request: httpx.Request) -> httpx.Response:
        dev = request.url.params["filter"].split(";")[0].split(":")[1]
        rows = []
        for r in rules:
            if not r.get("enabled", True):
                continue
            count, last = 0, ""
            if r is web and dev == "dev-3":  # only the standby member saw traffic
                count, last = 5, datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            if r is ssh:
                count, last = 2, "2020-01-01T00:00:00Z"
            rows.append(
                {"rule": {"id": r["id"], "name": r["name"]}, "hitCount": count, "lastHitTimeStamp": last}
            )
        return items(rows)

    get = lab.get(hc).mock(side_effect=hitcounts)
    data = await call(
        "fmc_policy_audit", {"policy": "mcp-test-acp", "checks": ["unused"], "refresh_hits": False}
    )
    devices = {c.request.url.params["filter"].split(";")[0] for c in get.calls}
    assert devices == {"deviceId:dev-1", "deviceId:dev-2", "deviceId:dev-3"}
    assert data["hit_counts_from"] == ["ftd1", "ha/ftd2", "ha/ftd3"]
    unused = {f["rule"]["name"]: f for f in data["findings"]}
    assert "mcp-test-allow-web" not in unused
    assert unused["mcp-test-ssh-admin"]["detail"].startswith("No hits in 90 days")
    assert unused["mcp-test-block-app"]["detail"] == "Never hit on 3 device(s)."
    assert "mcp-test-disabled" not in unused
    assert "enabled=False" in unused["mcp-test-block-app"]["fix"]


async def test_audit_unassigned_policy_notes_unused_skipped(lab: respx.MockRouter) -> None:
    data = await call("fmc_policy_audit", {"policy": "mcp-test-acp", "checks": ["unused"]})
    assert data["findings"] == []
    assert any("not assigned" in n for n in data["notes"])


def test_permissive_flags_only_unconditional_allows() -> None:
    rules = [
        rule("any-any", 1),
        rule("any-trust", 2, "TRUST"),
        rule("any-block", 3, "BLOCK"),
        rule("narrow", 4, destinationNetworks=nets("web")),
        {**rule("off", 5), "enabled": False},
    ]
    assert [f["rule"]["name"] for f in permissive("p", rules)] == ["any-any", "any-trust"]


def test_consolidation_needs_exactly_one_differing_condition() -> None:
    rules = [
        rule("a", 1, destinationNetworks=nets("web1"), destinationPorts=nets("https")),
        rule("b", 2, destinationNetworks=nets("web2"), destinationPorts=nets("https")),
        rule("c", 3, destinationNetworks=nets("web3"), destinationPorts=nets("ssh")),  # two fields differ
        rule("d", 4, "BLOCK", destinationNetworks=nets("web3"), destinationPorts=nets("ssh")),
    ]
    found = consolidation("p", rules)
    assert [(f["rule"]["name"], f["merge_with"]) for f in found] == [("a", "b")]
    assert "destination_networks=['web1', 'web2']" in found[0]["fix"]


def test_duplicate_objects_by_value_used_first() -> None:
    cat = Catalog(app=None, domain=None)  # type: ignore[arg-type]
    cat.objects = {
        "1": {"id": "1", "name": "web-a", "type": "Host", "value": "10.0.0.1"},
        "2": {"id": "2", "name": "web-b", "type": "Host", "value": "10.0.0.1/32"},
        "3": {"id": "3", "name": "other", "type": "Host", "value": "10.0.0.2"},
        "4": {
            "id": "4",
            "name": "any-ipv4",
            "type": "Network",
            "value": "10.0.0.1",
            "metadata": {"readOnly": {"state": True, "reason": "SYSTEM"}},
        },
        "5": {"id": "5", "name": "https-a", "type": "ProtocolPortObject", "protocol": "TCP", "port": "443"},
        "6": {"id": "6", "name": "https-b", "type": "ProtocolPortObject", "protocol": "TCP", "port": "443"},
    }
    rules = [rule("r", 1, destinationNetworks={"objects": [{"id": "2", "name": "web-b"}]})]
    found = duplicate_objects(cat, rules)
    assert [f["objects"] for f in found] == [["web-b", "web-a"], ["https-a", "https-b"]]
    assert found[0]["used_in_policy"] == ["web-b"]
    assert "fmc_delete_object(object='web-a')" in found[0]["fix"]


def test_expired_time_ranges() -> None:
    trs = [
        {"id": "t1", "name": "xmas-2024", "effectiveEndDateTime": "2024-12-31T23:59"},
        {"id": "t2", "name": "forever", "effectiveEndDateTime": ""},
        {"id": "t3", "name": "old-unused", "effectiveEndDateTime": "2023-01-01T00:00"},
    ]
    rules = [
        rule(
            "holiday", 1, timeRangeObjects=[{"id": "t1", "name": "xmas-2024", "type": "TimeRange"}]
        ),  # FMC's shape
        rule("always", 2, timeRangeObjects={"objects": [{"id": "t2", "name": "forever"}]}),
    ]
    found = expired_time_ranges("p", trs, rules, datetime(2026, 1, 1, tzinfo=UTC))
    assert [(f["severity"], f.get("rule", {}).get("name"), f["time_range"]) for f in found] == [
        ("medium", "holiday", "xmas-2024"),
        ("low", None, "old-unused"),
    ]

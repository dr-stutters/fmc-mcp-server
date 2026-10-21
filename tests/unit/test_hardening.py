"""F80 fmc_hardening_check: the YAML baseline, the checks on recorded FMC 10.0.1 shapes, findings appearing
and clearing, device checks (FTDv, HA, content, licences, pending)."""

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp._core import InvalidRequest
from fmc_mcp.baseline import DEFAULT_BASELINE, bundled, bundled_text, load_baseline, parse_baseline
from fmc_mcp.server import create_server
from fmc_mcp.tools import hardening
from fmc_mcp.tools.hardening import EVALUATORS, Exposure

from .conftest import CFG, TOP_CFG, as_leaf, fixture, items, make_settings

REC = fixture("compliance_fmc10")
PS_ID = REC["ps"]["id"]
PSP = f"{CFG}/policy/ftdplatformsettingspolicies"
DEV = REC["device"]
DEV_ID = DEV["id"]
ACP_ID = DEV["accessPolicy"]["id"]
# 2026-10-21T12:00Z: two days after the recorded FMC backup and rule update, 211 days after the VDB
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC).timestamp()
ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(autouse=True)
def frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hardening.time, "time", lambda: NOW)


async def run(args: dict[str, Any], **settings: Any) -> dict[str, Any]:
    async with Client(create_server(make_settings(**settings))) as c:
        r = await c.call_tool("fmc_hardening_check", args)
    out: dict[str, Any] = r.structured_content or json.loads(r.content[0].text)  # type: ignore[union-attr]
    return out


def mock_ps(
    fmc: respx.MockRouter, sections: dict[str, Any], cfg: str = CFG, ps: dict[str, Any] | None = None
) -> dict[str, respx.Route]:
    pol = ps or REC["ps"]
    fmc.get(f"{cfg}/policy/ftdplatformsettingspolicies").mock(return_value=items([pol]))
    return {
        sub: fmc.get(f"{cfg}/policy/ftdplatformsettingspolicies/{pol['id']}/{sub}").mock(
            return_value=httpx.Response(200, json=body)
        )
        for sub, body in sections.items()
    }


def mock_fmc(fmc: respx.MockRouter, cfg: str = CFG) -> None:
    fmc.get("/api/fmc_platform/v1/info/serverversion").mock(
        return_value=httpx.Response(200, json=REC["serverversion"])
    )
    fmc.get("/api/fmc_platform/v1/license/smartlicenses").mock(
        return_value=httpx.Response(200, json=REC["smart"])
    )
    fmc.get(f"{cfg}/backup/files/manager").mock(return_value=httpx.Response(200, json=REC["backup_manager"]))


def by_check(rows: list[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    return {r["check"]: r for r in rows or []}


# --- the baseline ------------------------------------------------------------------------------------


def test_docs_copy_is_the_packaged_baseline() -> None:
    assert (ROOT / "docs" / "baselines" / "ftd-hardening.yaml").read_text() == bundled_text(
        "ftd-hardening.yaml"
    )


def test_bundled_baseline_every_check_has_evaluator_source_and_known_fix_tool() -> None:
    base = bundled()[DEFAULT_BASELINE]
    assert base.version == "1" and len(base.checks) >= 20
    ids = [c.id for c in base.checks]
    assert set(ids) == EVALUATORS  # every evaluator has a check and every check an evaluator
    for c in base.checks:
        assert c.source, c.id
        assert c.scope in ("fmc", "platform_settings", "device")
    tools = {c.id: c.fix_tool for c in base.checks}
    assert tools["snmp-v3-only"] == "fmc_configure_snmp" and tools["external-authentication"] is None
    assert [c.id for c in base.checks if not c.enabled] == ["syslog-tls"]


def test_edited_baseline_from_bundle_dir(tmp_path: Path) -> None:
    text = bundled_text("ftd-hardening.yaml").replace("name: ftd-hardening-v1", "name: acme-ftd")
    text = text.replace(
        "    title: Syslog servers are reached over TCP with TLS\n    severity: low\n    enabled: false",
        "    title: Syslog servers are reached over TCP with TLS\n    severity: high\n    enabled: true",
    )
    (tmp_path / "acme.yaml").write_text(text)
    for ref in ("acme.yaml", "acme"):
        b = load_baseline(ref, tmp_path)
        assert b.name == "acme-ftd" and b.origin == "FMC_BUNDLE_DIR/acme.yaml"
        tls = next(c for c in b.checks if c.id == "syslog-tls")
        assert tls.enabled and tls.severity == "high"
    assert load_baseline(DEFAULT_BASELINE, tmp_path).origin == "bundled"  # bundled names are reserved
    (tmp_path / "copy.yaml").write_text(bundled_text("ftd-hardening.yaml"))  # edited, name unchanged
    with pytest.raises(InvalidRequest, match="its own `name`"):
        load_baseline("copy.yaml", tmp_path)
    with pytest.raises(InvalidRequest, match="FMC_BUNDLE_DIR is not set"):
        load_baseline("acme", None)
    with pytest.raises(InvalidRequest, match="give a bundled name"):
        load_baseline("../etc/passwd", tmp_path)
    with pytest.raises(InvalidRequest, match="No baseline"):
        load_baseline("nope.yaml", tmp_path)


def test_baseline_typos_are_refused() -> None:
    good = "name: x\nchecks:\n  - {id: a, scope: device, severity: low, source: [s]}\n"
    assert parse_baseline(good, "t").checks[0].enabled
    for bad, why in (
        (good.replace("severity: low", "severty: low"), "unknown keys"),
        (good.replace("scope: device", "scope: firewall"), "scope must be"),
        (good.replace("severity: low", "severity: urgent"), "severity must be"),
        (good.replace(", source: [s]", ""), "must name where"),
        ("name: x\nchecks: []\n", "non-empty list"),
        ("- just a list", "expected a mapping"),
    ):
        with pytest.raises(InvalidRequest, match=why):
            parse_baseline(bad, "t")


async def test_unknown_check_id_is_not_evaluated_never_passed(fmc: respx.MockRouter, tmp_path: Path) -> None:
    text = bundled_text("ftd-hardening.yaml").replace("name: ftd-hardening-v1", "name: mine")
    text += "  - id: telnet-off\n    scope: device\n    title: no telnet\n    severity: high\n"
    text += "    source: [ours]\n"
    (tmp_path / "mine.yaml").write_text(text)
    mock_ps(fmc, REC["ps_sections"])
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([]))
    out = await run(
        {"platform_settings": "mcp-w6-ps", "baseline": "mine.yaml", "checks": ["telnet-off"]},
        bundle_dir=tmp_path,
    )
    assert out["not_evaluated"] == [
        {"check": "telnet-off", "why": "this server has no evaluator for this check id"}
    ]
    assert out["summary"]["findings"] == 0 and "passed" not in out


# --- platform settings on recorded shapes --------------------------------------------------------------


async def test_recorded_lab_policy_findings_ranked_with_fix_and_source(fmc: respx.MockRouter) -> None:
    mock_ps(fmc, REC["ps_sections"])
    mock_fmc(fmc)
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([]))
    out = await run({"platform_settings": "mcp-w6-ps"})
    assert out["baseline"]["name"] == "ftd-hardening-v1" and out["baseline"]["disabled"] == ["syslog-tls"]
    assert out["target"] == {"platform_settings": "mcp-w6-ps"}
    found = by_check(out["findings"])
    assert list(found) == [
        "fmc-content-current",  # medium (VDB 211 days old)
        "external-authentication",  # medium
        "syslog-rfc5424",  # low, in baseline order
        "login-banner",
        "icmp-restricted",
    ]
    assert [f["severity"] for f in out["findings"]] == ["medium", "medium", "low", "low", "low"]
    assert "VDB build 426" in found["fmc-content-current"]["detail"] and found["fmc-content-current"]["ui"]
    assert found["syslog-rfc5424"]["fix"] == (
        "fmc_configure_syslog(policy='mcp-w6-ps', timestamp_format='RFC_5424')"
    )
    assert found["login-banner"]["fix_tool"] == "fmc_set_banner"
    assert found["icmp-restricted"]["fix"].startswith(
        "fmc_configure_mgmt_access(policy='mcp-w6-ps', kind='icmp'"
    )
    assert (
        found["external-authentication"]["fix_tool"] is None
        and "External Authentication" in found["external-authentication"]["ui"]
    )
    assert all(f["source"] for f in out["findings"])
    documented = {c.id: c.fix_tool for c in bundled()[DEFAULT_BASELINE].checks}
    assert all(f["fix_tool"] in (documented[f["check"]], None) for f in out["findings"])  # YAML = evaluator
    ok = by_check(out["passed"])
    assert {
        "ssh-access-restricted",
        "https-access-restricted",
        "snmp-v3-only",
        "syslog-servers",
        "ntp-servers",
        "dns-configured",
        "smart-licensing",
        "fmc-backup-recent",
    } <= set(ok)
    assert ok["ssh-access-restricted"]["detail"].startswith("No SSH access entries")
    assert ok["syslog-servers"]["evidence"] == {"servers": ["mcp-w6-syslog-host UDP/514"], "level": "INFO"}
    assert ok["fmc-backup-recent"]["detail"] == "Newest FMC backup 2026-10-19T02:02:50Z."
    assert by_check(out["not_applicable"])["snmp-hosts-restricted"]["detail"] == "The SNMP server is off."
    assert any("assigned to no device" in n for n in out["notes"])
    assert any("show banner" in n for n in out["notes"])


async def test_snmp_v2c_and_open_ssh_appear_then_clear(fmc: respx.MockRouter) -> None:
    """The Stage 2 plan on mcp-w6-ps: SNMP v2c on and SSH open -> two high findings; fixed -> gone."""
    sections = copy.deepcopy(REC["ps_sections"])
    sections["snmpsettings"]["items"][0].update(
        enableSNMPServers=True,
        communityString="*******",
        snmpMgmtHosts=[
            {
                "ipAddress": {"name": "mcp-w6-nms", "id": "h1", "type": "Host"},
                "snmpVersion": "SNMPv2c",
                "poll": True,
                "trap": True,
                "interfaces": {"objects": [{"name": "mcp-test-ftd-in", "id": "z1", "type": "SecurityZone"}]},
            }
        ],
    )
    zone = {"objects": [{"name": "mcp-test-ftd-in", "id": "z1", "type": "SecurityZone"}]}
    sections["sshaccesssettings"] = items(
        [
            {
                "type": "SSHAccessSetting",
                "id": "s1",
                "ipAddress": {"object": {"name": "any-ipv4", "id": "a4", "type": "Network"}},
                "interfaces": zone,
            }
        ]
    ).json()
    routes = mock_ps(fmc, sections)
    nms = {"id": "h1", "name": "mcp-w6-nms", "type": "Host", "value": "198.51.100.25"}
    fmc.get(f"{CFG}/object/networkaddresses").mock(return_value=items([nms]))
    fmc.get(f"{CFG}/object/ranges").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/networkgroups").mock(return_value=items([]))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([]))
    args = {
        "platform_settings": "mcp-w6-ps",
        "checks": ["ssh-access-restricted", "snmp-v3-only", "snmp-hosts-restricted"],
    }
    out = await run(args)
    found = by_check(out["findings"])
    assert list(found) == ["ssh-access-restricted", "snmp-v3-only"] and out["summary"]["by_severity"] == {
        "high": 2
    }
    assert found["ssh-access-restricted"]["detail"] == "SSH is allowed from any-ipv4 via ['mcp-test-ftd-in']."
    assert found["ssh-access-restricted"]["fix"].startswith(
        "fmc_configure_ssh_access(policy='mcp-w6-ps', action='remove', network='any-ipv4', "
        "interfaces=['mcp-test-ftd-in'])"
    )
    # live-A read "SNMP is on with a community string is set ..." (W6N, F80 #175): the problems follow "but"
    assert found["snmp-v3-only"]["detail"] == (
        "SNMP is on, but a community string is set (SNMPv1/v2c polling); manager mcp-w6-nms uses SNMPv2c."
    )
    # FMC masks the community and fmc_configure_snmp blocks a change without it: the fix says to give it
    assert found["snmp-v3-only"]["fix"].startswith(
        "fmc_configure_snmp(policy='mcp-w6-ps', enabled=False, community='<the current community>')"
    )
    assert "*******" not in json.dumps(out)  # the masked community isn't echoed
    assert by_check(out["passed"])["snmp-hosts-restricted"]["detail"] == "SNMP managers: mcp-w6-nms."

    # fixed: SNMP off again and SSH only from a management /24
    routes["snmpsettings"].mock(return_value=httpx.Response(200, json=REC["ps_sections"]["snmpsettings"]))
    ssh = [
        {
            "type": "SSHAccessSetting",
            "id": "s1",
            "ipAddress": {"literal": "198.51.100.0/24"},
            "interfaces": zone,
        }
    ]
    routes["sshaccesssettings"].mock(return_value=items(ssh))
    out = await run(args)
    assert out["findings"] == [] and out["summary"]["verdict"] == "No findings."
    assert (
        by_check(out["passed"])["ssh-access-restricted"]["detail"] == "SSH allowed only from 198.51.100.0/24."
    )


async def test_section_read_error_is_unknown_and_the_rest_runs(fmc: respx.MockRouter) -> None:
    sections = dict(REC["ps_sections"])
    del sections["externalauthsettings"]
    mock_ps(fmc, sections)
    fmc.get(f"{PSP}/{PS_ID}/externalauthsettings").mock(
        return_value=httpx.Response(
            403, json={"error": {"messages": [{"description": "The user is not authorized."}]}}
        )
    )
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([]))
    out = await run(
        {"platform_settings": "mcp-w6-ps", "checks": ["external-authentication", "dns-configured"]}
    )
    unknown = by_check(out["unknown"])["external-authentication"]
    assert unknown["detail"].startswith("Could not read external_auth")
    assert "dns-configured" in by_check(out["passed"])


async def test_targets_and_check_ids_are_validated(fmc: respx.MockRouter) -> None:
    async with Client(create_server(make_settings())) as c:
        both = await c.call_tool(
            "fmc_hardening_check", {"device": "a", "platform_settings": "b"}, raise_on_error=False
        )
        neither = await c.call_tool("fmc_hardening_check", {}, raise_on_error=False)
    assert both.is_error and neither.is_error
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([]))
    mock_ps(fmc, {})
    async with Client(create_server(make_settings())) as c:
        bad = await c.call_tool(
            "fmc_hardening_check",
            {"platform_settings": "mcp-w6-ps", "checks": ["telnet-off"]},
            raise_on_error=False,
        )
    assert bad.is_error and "Unknown check ids" in bad.content[0].text  # type: ignore[union-attr]


# --- devices -------------------------------------------------------------------------------------------


def mock_device_lab(fmc: respx.MockRouter, record: dict[str, Any], pending: list[dict[str, Any]]) -> None:
    """mcp-ftd1 as recorded: a leaf device on Global's platform settings policy (assigned from Global)."""
    as_leaf(fmc)
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([record]))
    fmc.get(f"{CFG}/devices/devicerecords/{record['id']}").mock(return_value=httpx.Response(200, json=record))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([]))
    gps = {"type": "FTDPlatformSettingsPolicy", "name": "mcp-test-ps", "id": "ps-global"}
    fmc.get(f"{TOP_CFG}/assignment/policyassignments").mock(
        return_value=items(
            [{"policy": gps, "targets": [{"id": record["id"], "type": "Device", "name": record["name"]}]}]
        )
    )
    mock_ps(fmc, REC["ps_sections"], cfg=TOP_CFG, ps=gps)
    mock_fmc(fmc)
    fmc.get(f"{CFG}/backup/files/{record['id']}").mock(
        return_value=httpx.Response(400, json=REC["backup_device_error"]["error"])
    )
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items(pending))
    acp = {
        "id": ACP_ID,
        "name": "mcp-test-ftd-acp",
        "type": "AccessPolicy",
        "defaultAction": {"action": "BLOCK"},
    }
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}").mock(return_value=httpx.Response(200, json=acp))
    ips = {"name": "Balanced Security and Connectivity", "id": "ips1", "type": "IntrusionPolicy"}
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=items(
            [{"id": "r1", "name": "allow-out", "action": "ALLOW", "enabled": True, "ipsPolicy": ips}]
        )
    )


DEVICE_CHECKS = [
    "platform-settings-assigned",
    "ha-interface-monitoring",
    "device-content-current",
    "device-licences",
    "device-backup-recent",
    "no-pending-deployment",
    "dns-configured",
]


async def test_device_checks_on_recorded_ftdv(fmc: respx.MockRouter) -> None:
    pending = copy.deepcopy(REC["deployable_row_trimmed"])
    pending.update(id=DEV_ID, name="mcp-ftd1", device={"id": DEV_ID, "name": "mcp-ftd1"}, deviceMembers=[])
    mock_device_lab(fmc, DEV, [pending])
    out = await run({"device": DEV_ID, "checks": DEVICE_CHECKS})
    assert out["target"] == {"platform_settings": "mcp-test-ps", "devices": ["mcp-ftd1"]}
    ok, na, found = (
        by_check(out.get("passed")),
        by_check(out.get("not_applicable")),
        by_check(out["findings"]),
    )
    assert ok["platform-settings-assigned"]["detail"] == "Platform settings policy mcp-test-ps."
    assert ok["dns-configured"]["target"] == "platform settings mcp-test-ps"  # read in Global, the owner
    assert ok["device-licences"]["evidence"]["needs"] == {"IPS": "intrusion policy on rule 'allow-out'"}
    assert na["ha-interface-monitoring"]["detail"] == "Not an HA unit."
    assert na["device-backup-recent"]["detail"].startswith("Threat Defense Virtual has no device backup")
    content = found["device-content-current"]
    assert content["detail"] == "Out of date: VDB Build 426 - 2026-03-24 09:29:08.0 is 211 days old."
    assert content["fix_tool"] is None and "System > Updates" in content["ui"]
    stale = found["no-pending-deployment"]
    assert stale["evidence"] == {"out_of_date": ["mcp-sdwan-acp", "lsp-rel-20261019-1844"]}
    assert stale["fix"] == "fmc_pending_changes(device='mcp-ftd1'), then fmc_deploy(devices=['mcp-ftd1'])"
    # the platform settings policy belongs to Global: its fixes are written there, not in the leaf
    out = await run({"device": DEV_ID, "checks": ["login-banner"], "domain": "Global/mcp-test-leaf"})
    banner = by_check(out["findings"])["login-banner"]
    assert banner["fix"].startswith("fmc_set_banner(policy='mcp-test-ps', text=") and banner["fix"].endswith(
        "domain='Global')"
    )


async def test_device_behind_fmc_and_missing_licence(fmc: respx.MockRouter) -> None:
    rec = copy.deepcopy(DEV)
    rec["license_caps"] = ["ESSENTIALS"]
    rec["model"] = "Cisco Secure Firewall 3110 Threat Defense"
    rec["metadata"]["lspVersion"] = "lsp-rel-20261001-0900"
    mock_device_lab(fmc, rec, [])
    fmc.get(f"{CFG}/backup/files/{DEV_ID}").mock(
        return_value=httpx.Response(
            200, json=items([{"creationDate": "2026-10-01 01:00:00", "fileName": "b.tar"}]).json()
        )
    )
    out = await run({"device": "mcp-ftd1", "checks": DEVICE_CHECKS})
    found = by_check(out["findings"])
    assert found["device-licences"]["fix"] == "fmc_set_device_licenses(device='mcp-ftd1', add=['IPS'])"
    assert found["device-licences"]["severity"] == "high" and out["findings"][0]["check"] == "device-licences"
    content = found["device-content-current"]
    assert "intrusion rules lsp-rel-20261001-0900 (FMC has lsp-rel-20261019-1844)" in content["detail"]
    assert content["fix"] == "fmc_deploy(devices=['mcp-ftd1'])"
    backup = found["device-backup-recent"]
    assert backup["detail"] == "Newest device backup 2026-10-01T01:00:00Z is 20 days old (limit 7)."
    assert backup["fix"] == "fmc_backup_devices(devices=['mcp-ftd1'])"
    assert by_check(out["passed"])["no-pending-deployment"]["detail"].startswith("Nothing pending")


async def test_ha_pair_monitoring_recorded_then_a_gap(fmc: respx.MockRouter) -> None:
    pair_id = "03e0cc6c-cb56-11f1-85ee-4ce46f180443"
    rec = copy.deepcopy(DEV)
    rec["metadata"]["containerDetails"] = {
        "id": pair_id,
        "type": "DeviceHAPair",
        "name": "mcp-fw-ha",
        "role": "PRIMARY",
        "status": "Active",
    }
    mock_device_lab(fmc, rec, [])
    leaf = {"id": "a1c73df0-8353-8db7-1097-000000000000", "name": "mcp-test-leaf", "type": "Domain"}
    fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs/{pair_id}").mock(
        return_value=httpx.Response(
            200, json={"id": pair_id, "name": "mcp-fw-ha", "metadata": {"domain": leaf}}
        )
    )
    mon = fmc.get(f"{CFG}/devicehapairs/ftddevicehapairs/{pair_id}/monitoredinterfaces").mock(
        return_value=httpx.Response(200, json=REC["ha_monitored"])
    )
    out = await run({"device": DEV_ID, "checks": ["ha-interface-monitoring"]})
    assert by_check(out["passed"])["ha-interface-monitoring"]["detail"].startswith(
        "Every addressed interface of mcp-fw-ha"
    )
    gap = copy.deepcopy(REC["ha_monitored"])
    gap["items"][2]["monitorForFailures"] = False
    del gap["items"][2]["ipv4Configuration"]["standbyIPv4Address"]
    mon.mock(return_value=httpx.Response(200, json=gap))
    out = await run({"device": DEV_ID, "checks": ["ha-interface-monitoring"]})
    f = out["findings"][0]
    assert f["detail"] == "mcp-fw-ha: inside not monitored for failures; inside no standby IP address."
    assert f["fix"] == (
        "fmc_configure_ha_monitoring(ha_pair='mcp-fw-ha', interface='inside', monitored=True, "
        "standby_ip='<standby address>')"
    )


async def test_device_without_platform_settings(fmc: respx.MockRouter) -> None:
    as_leaf(fmc)
    fmc.get(f"{CFG}/devices/devicerecords/{DEV_ID}").mock(return_value=httpx.Response(200, json=DEV))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([]))
    fmc.get(f"{TOP_CFG}/assignment/policyassignments").mock(return_value=items([]))
    out = await run({"device": DEV_ID, "checks": ["platform-settings-assigned", "ssh-access-restricted"]})
    f = by_check(out["findings"])["platform-settings-assigned"]
    assert f["fix"].startswith(
        "fmc_assign_policy(kind='platform_settings', policy='<hardened platform settings policy>'"
    )
    assert (
        by_check(out["not_applicable"])["ssh-access-restricted"]["detail"]
        == "No platform settings policy to check."
    )


# --- pure checks -----------------------------------------------------------------------------------------


async def test_exposure_names_literals_prefixes_and_objects() -> None:
    class Cat:
        def networks(self, ref: Any) -> Any:
            return {"wide": [(4, 0, 2**31 - 1)], "narrow": [(4, 0, 255)]}.get(ref.get("id"))

    async def resolve() -> Any:
        return Cat()

    e = Exposure({}, resolve)
    assert await e.is_open({"literal": "0.0.0.0/0"}) is True
    assert await e.is_open({"literal": "10.0.0.0/7"}) is True  # wider than /8
    assert await e.is_open({"literal": "10.0.0.0/8"}) is False
    assert await e.is_open({"object": {"name": "any-ipv4", "id": "x", "type": "Network"}}) is True
    assert await e.is_open({"object": {"name": "mgmt", "id": "wide", "type": "Network"}}) is True
    assert await e.is_open({"name": "mgmt", "id": "narrow", "type": "Host"}) is False
    assert await e.is_open({"name": "2001:db8::11", "type": "Network"}) is False  # FMC's unnamed literal ref
    assert await e.is_open({"object": {"name": "fqdn", "id": "nope", "type": "FQDN"}}) is None
    strict = Exposure({"min_prefix_v4": 24}, resolve)
    assert await strict.is_open({"literal": "10.0.0.0/16"}) is True


async def test_smart_licensing_states() -> None:
    check = next(c for c in bundled()[DEFAULT_BASELINE].checks if c.id == "smart-licensing")
    run_ = hardening.Run(app=None, domain=None, now=NOW)  # type: ignore[arg-type]
    for smart, status in (
        ({"regStatus": "REGISTERED", "metadata": {"authStatus": "AUTHORIZED"}}, "pass"),
        ({"regStatus": "REGISTERED", "metadata": {"authStatus": "OUT_OF_COMPLIANCE"}}, "fail"),
        ({"regStatus": "UNREGISTERED", "metadata": {}}, "fail"),
        ({"regStatus": "EVALUATION", "metadata": {"evalExpiresInDays": 40}}, "fail"),
    ):
        run_.fmc = hardening.FmcRead(smart=smart)
        assert (await hardening.smart_licensing(check, run_)).status == status, smart


def test_content_parsers() -> None:
    assert hardening.lsp_key("lsp-rel-20261019-1844") == "20261019-1844"
    assert hardening.vdb_build("build 426 ( 2026-03-24 09:29:08 )") == 426
    assert hardening.vdb_build("Build 426 - 2026-03-24 09:29:08.0") == 426
    assert hardening.day("2026-10-19-001-vrt") == datetime(2026, 10, 19, tzinfo=UTC)
    assert hardening.day("lsp-rel-20261019-1844", hardening._LSP_DATE) == datetime(2026, 10, 19, tzinfo=UTC)
    assert hardening.backup_rows(REC["backup_manager"])[0]["targetId"] == "manager"  # one object, not a list
    assert hardening.backup_rows({"items": []}) == []

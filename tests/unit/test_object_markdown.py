"""#200: the markdown answer of the show-one tools keeps nested rows (tools/render.py).

Contract: for every tool that renders one object with `response_format`, each list of records in its
JSON answer appears in its markdown answer as a table under `### <key path> (<n>)` with all the records'
fields as columns, and every value of the JSON answer appears somewhere in the markdown. Shapes: FMC
10.0.1 recordings (tests/fixtures/object_markdown_fmc10.json and the fixtures the other modules use)."""

import ast
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools.render import is_ref, is_rows, object_markdown

from . import test_admin, test_file_policy, test_identity, test_si_feeds, test_tickets
from .conftest import CFG, fixture, items, make_settings
from .test_decryption import mock_tls
from .test_pki import mock_catalog

REC = fixture("object_markdown_fmc10")
TOOLS = Path(__file__).resolve().parents[2] / "src" / "fmc_mcp" / "tools"


# --- the renderer ----------------------------------------------------------------------------------------


def test_rows_become_a_table_with_every_field() -> None:
    md = object_markdown(
        {
            "name": "p",
            "rules": [
                {"index": 1, "action": "block", "file_types": ["MSEXE", "PDF"]},
                {"index": 2, "action": "detect", "store_files": ["MALWARE"], "note": "a | b"},
            ],
            "id": "x",
        }
    )
    assert md.startswith("- **name**: p\n- **id**: x\n\n### rules (2)\n\n")
    assert "| index | action | file_types | store_files | note |" in md
    assert "| 1 | block | MSEXE, PDF |  |  |" in md and "| 2 | detect |  | MALWARE | a \\| b |" in md


def test_references_stay_names_and_objects_stay_readable() -> None:
    md = object_markdown(
        {
            "base": {"id": "1", "name": "Balanced", "type": "intrusionpolicy"},
            "zones": [
                {"id": "z1", "name": "inside", "type": "SecurityZone"},
                {"id": "z2", "name": "outside"},
            ],
            "settings": {"inspect_archives": False, "archive_depth": 2},
            "advanced": {"tls13": {"enabled": True}, "rows": [{"a": 1, "b": {"c": 2}}]},
        }
    )
    assert "- **base**: Balanced" in md and "- **zones**: inside, outside" in md
    assert "- **settings**: inspect_archives: False, archive_depth: 2" in md
    assert "- **advanced**:\n  - **tls13**: enabled: True" in md
    assert "### advanced.rows (1)\n\n| a | b |\n|---|---|\n| 1 | c: 2 |" in md


def test_notes_one_per_line_and_multiline_text_fenced() -> None:
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    md = object_markdown({"notes": ["Install it first, then deploy.", "Two"], "certificate_pem": pem + "\n"})
    assert "- **notes**:\n  - Install it first, then deploy.\n  - Two" in md
    assert f"### certificate_pem\n\n```\n{pem}\n```" in md
    assert object_markdown({}) == "_Empty._"


def test_no_tool_renders_markdown_through_core_object_result() -> None:
    """New show-one tools must use object_reply: core's object_result(fmt=...) hides nested rows."""
    offenders = []
    for path in sorted(p for p in TOOLS.glob("*.py") if p.name != "render.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "object_result"
                and any(k.arg == "fmt" for k in node.keywords)
            ):
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


# --- the contract over the tools -------------------------------------------------------------------------


def records(data: Any, path: str = "") -> Iterator[tuple[str, list[Any]]]:
    """(key path, rows) for every list of records outside a table."""
    if isinstance(data, dict):
        for k, v in data.items():
            if is_rows(v):
                yield f"{path}{k}", v
            elif isinstance(v, dict):
                yield from records(v, f"{path}{k}.")


def leaves(v: Any) -> Iterator[str]:
    if isinstance(v, dict):
        if is_ref(v):
            yield str(v.get("name") or v.get("label") or v.get("display") or v.get("id"))
            return
        for x in v.values():
            yield from leaves(x)
    elif isinstance(v, list):
        for x in v:
            yield from leaves(x)
    elif v is not None:
        yield str(v)


def shown(md: str, value: str) -> bool:
    return value.strip() in md or value.replace("\n", " ").replace("|", "\\|") in md


def setup_file_policy(fmc: respx.MockRouter) -> None:
    fp = test_file_policy
    fmc.get(f"{CFG}/policy/filepolicies").mock(return_value=items([fp.FP]))
    fmc.get(fp.FILE_RULES).mock(return_value=items([fp.EXE_BLOCK, fp.MALWARE]))


def setup_intrusion(fmc: respx.MockRouter) -> None:
    ips = REC["intrusion_policies"]["items"][1]
    fmc.get(f"{CFG}/policy/intrusionpolicies").mock(
        return_value=httpx.Response(200, json=REC["intrusion_policies"])
    )
    fmc.get(f"{CFG}/policy/intrusionpolicies/{ips['id']}/intrusionrules").mock(
        return_value=httpx.Response(200, json=REC["intrusion_overrides"])
    )


def setup_upgrades(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([fixture("ftd_device")]))
    fmc.get("/api/fmc_platform/v1/updates/deviceupgradeinfo").mock(
        return_value=httpx.Response(200, json=REC["device_upgrade_info"])
    )
    fmc.get("/api/fmc_platform/v1/updates/upgradepackages").mock(
        return_value=httpx.Response(200, json=REC["upgrade_packages"])
    )


def setup_health(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/healthpolicies").mock(return_value=items([test_admin.HP]))
    dev = {**fixture("ftd_device"), "healthPolicy": {"id": test_admin.HP_ID, "name": "Initial_Health_Policy"}}
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([dev]))


def setup_nap(fmc: respx.MockRouter) -> None:
    fp = test_file_policy
    data = fixture("networkanalysispolicies")
    fmc.get(fp.NAPS).mock(return_value=items([*data["items"], fp.CUSTOM_NAP]))
    fmc.get(f"{fp.NAPS}/{fp.CUSTOM_NAP['id']}/inspectoroverrideconfigs").mock(
        return_value=items(
            [{"type": "InspectorOverrideConfig", "inspectorOverrideConfig": {"http_inspect": {}}}]
        )
    )


def setup_si_policy(fmc: respx.MockRouter) -> None:
    si = test_si_feeds
    feed = {"id": si.FEED_ID, "type": "SINetworkFeed", "name": "mcp-fw-feed-ip"}
    lst = {"id": si.LIST_ID, "type": "SIURLList", "name": "mcp-fw-list-url"}
    si.mock_policy(
        fmc, si.si_policy(add=[("networks", "network", "blocklist", feed), ("urls", "url", "allowlist", lst)])
    )
    setup_si_domain(fmc)
    fmc.get(f"{CFG}/policy/dnspolicies/{si.DEFAULT_DNS['id']}/dnsrules").mock(
        return_value=httpx.Response(200, json=si.REC["dns_rules"])
    )


def setup_si_domain(fmc: respx.MockRouter) -> None:
    si = test_si_feeds
    si.mock_catalogs(
        fmc, {"ip": [si.ip_feed(1_760_000_000)], "dns": [si.dns_feed()]}, {"url": [si.url_list()]}
    )


def setup_dns(fmc: respx.MockRouter) -> None:
    si = test_si_feeds
    fmc.get(f"{CFG}/policy/dnspolicies").mock(return_value=items([si.DEFAULT_DNS]))
    fmc.get(f"{CFG}/policy/dnspolicies/{si.DEFAULT_DNS['id']}/dnsrules").mock(
        return_value=httpx.Response(200, json=si.REC["dns_rules"])
    )


def setup_tickets(fmc: respx.MockRouter) -> None:
    t = {**test_tickets.T, "status": "IN_PROGRESS", "metadata": {"creator": "apiuser"}}
    fmc.get(test_tickets.TICKETS).mock(return_value=items([t]))
    fmc.get(f"{test_tickets.TICKETS}/t-1/previewchanges").mock(
        return_value=items(
            [
                {
                    "entityName": "mcp-host",
                    "entityType": "Host",
                    "action": "CREATE",
                    "lastUpdatedByUsers": [{"name": "apiuser"}],
                    "valueAdded": [{"fieldName": "Value", "newValue": "192.0.2.10"}],
                }
            ]
        )
    )
    fmc.get(f"{test_tickets.TICKETS}/t-1/validationresults").mock(
        return_value=items([{"level": "WARNING", "message": "Rule 3 is shadowed by rule 1"}])
    )


def setup_identity_policy(fmc: respx.MockRouter) -> None:
    idp, acp = test_identity.IDP, test_identity.ACP
    fmc.get(f"{CFG}/policy/identitypolicies").mock(return_value=items([idp]))
    rule = {
        "id": "ir1",
        "name": "passive-ise",
        "enabled": True,
        "authenticationType": "PASSIVE",
        "realm": {"id": test_identity.REALM_ID, "name": "corp", "type": "Realm"},
        "metadata": {"ruleIndex": 1},
    }
    fmc.get(f"{CFG}/policy/identitypolicies/{idp['id']}/identityrules").mock(return_value=items([rule]))
    fmc.get(f"{CFG}/policy/accesspolicies").mock(
        return_value=items([{**acp, "identityPolicySetting": {"id": idp["id"], "name": "idp"}}])
    )


Setup = Callable[[respx.MockRouter], None]
CASES: list[tuple[str, dict[str, Any], Setup, set[str]]] = [
    ("fmc_get_file_policy", {"policy": "mcp-fw-file"}, setup_file_policy, {"rules"}),
    ("fmc_get_intrusion_policy", {"policy": "mcp-fw-ips"}, setup_intrusion, {"overridden_rules"}),
    ("fmc_upgrade_status", {}, setup_upgrades, {"devices", "upgrade_packages"}),
    ("fmc_get_health_policy", {"policy": "Initial_Health_Policy"}, setup_health, {"modules"}),
    ("fmc_get_network_analysis_policy", {"policy": "mcp-fw-nap"}, setup_nap, set()),
    ("fmc_get_decryption_policy", {"policy": "mcp-test-tls"}, mock_tls, {"rules"}),
    ("fmc_get_certificate", {"certificate": "mcp-test-resign-ca"}, mock_catalog, set()),
    (
        "fmc_get_security_intelligence",
        {"policy": test_si_feeds.ACP["name"]},
        setup_si_policy,
        {"dns_rules", "feeds_and_lists"},
    ),
    ("fmc_get_security_intelligence", {}, setup_si_domain, {"feeds", "lists"}),
    ("fmc_get_dns_policy", {"policy": test_si_feeds.DEFAULT_DNS["name"]}, setup_dns, {"rules"}),
    ("fmc_change_tickets", {"ticket": "CHG001"}, setup_tickets, {"tickets", "changes", "validation"}),
    ("fmc_get_realm", {"realm": "corp", "members": "both"}, test_identity.mock_realm, {"directories"}),
    ("fmc_get_identity_policy", {"policy": "idp"}, setup_identity_policy, {"rules"}),
]


async def answer(c: Client[Any], tool: str, args: dict[str, Any], fmt: str) -> str:
    r = await c.call_tool(tool, {**args, "response_format": fmt})
    return r.content[0].text  # type: ignore[union-attr]


@pytest.mark.parametrize(("tool", "args", "setup", "tables"), CASES, ids=[f"{c[0]}{c[1]}" for c in CASES])
async def test_markdown_keeps_every_nested_row(
    fmc: respx.MockRouter, tool: str, args: dict[str, Any], setup: Setup, tables: set[str]
) -> None:
    setup(fmc)
    async with Client(create_server(make_settings())) as c:
        data = json.loads(await answer(c, tool, args, "json"))
        md = await answer(c, tool, args, "markdown")
    found = dict(records(data))
    assert tables <= set(found), f"{tool}: the fixture should have rows under {tables - set(found)}"
    lines = md.split("\n")
    for path, rows in found.items():
        heading = f"### {path} ({len(rows)})"
        assert heading in lines, f"{tool}: no table for {path}:\n{md}"
        header = lines[lines.index(heading) + 2]
        cols = {c.strip() for c in header.strip("|").split("|")}
        fields = {k for r in rows if isinstance(r, dict) for k in r}
        assert fields <= cols, f"{tool}: {path} lacks columns {fields - cols}"
    missing = [v for v in leaves(data) if not shown(md, v)]
    assert not missing, f"{tool}: values missing from the markdown: {missing[:10]}\n{md}"


async def test_intrusion_used_by_is_clean(fmc: respx.MockRouter) -> None:
    setup_intrusion(fmc)
    async with Client(create_server(make_settings())) as c:
        out = json.loads(await answer(c, "fmc_get_intrusion_policy", {"policy": "mcp-fw-ips"}, "json"))
        md = await answer(c, "fmc_get_intrusion_policy", {"policy": "mcp-fw-ips"}, "markdown")
    assert out["used_by"] == {
        "access_policies": 1,
        "devices": 1,
        "access_policy_names": ["mcp-fw-threat-acp"],
    }
    assert "asscoiated" not in md and "PG.FIREWALL" not in md
    assert "| 1:498 | INDICATOR-COMPROMISE id check returned root | DISABLE | BLOCK |" in md


async def test_upgrade_status_markdown_lists_each_device(fmc: respx.MockRouter) -> None:
    setup_upgrades(fmc)
    async with Client(create_server(make_settings())) as c:
        out = json.loads(await answer(c, "fmc_upgrade_status", {}, "json"))
        md = await answer(c, "fmc_upgrade_status", {}, "markdown")
    assert out["upgrade_packages"][0]["version"] == "10.0.1 Hotfix P (10.0.1.1-2)"
    assert (
        "| mcp-ftd1 | 10.0.0 | Cisco Secure Firewall Threat Defense for KVM | SNORT3 | False | 10.0.0-140 |"
        in md
    )

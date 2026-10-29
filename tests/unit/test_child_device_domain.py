"""#382 (F19): a child-domain device seen from Global.

FMC 10.0.1, live round l16: Global's device list holds every FTD of the child domain, each record naming its
owner in `metadata.domain`; the access policy assigned to it lives in that child domain, so a GET of it in
Global is a 404. Device-scoped tools read the device's policies in the device's domain and say so; an
explicit `domain` that disagrees is a clear error; fmc_list_devices gets a `domain` column and
fmc_list_policies in Global names the child domains whose devices use policies listed there."""

import json
import re
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server

from .conftest import CFG, CHILD, items, make_settings

CHILD_CFG = f"/api/fmc_config/v1/domain/{CHILD}"
ACP_ID = "00505686-0000-0ed3-0000-004294967999"
DEV_ID = "2c11eaca-c7e3-11f1-a7ce-a8b537b1b4bb"
HQ_ID = "3d22fbdb-c7e3-11f1-a7ce-a8b537b1b4cc"
ACP_REF = {"id": ACP_ID, "name": "branch-acp", "type": "AccessPolicy"}
# The Global device record as FMC 10.0.1 returns it for a child-domain FTD (metadata.domain = the child).
BRANCH_FTD = {
    "id": DEV_ID,
    "name": "ftd-branch",
    "type": "Device",
    "hostName": "192.0.2.10",
    "model": "Cisco Secure Firewall Threat Defense for VMware",
    "sw_version": "10.0.0",
    "isConnected": True,
    "accessPolicy": ACP_REF,
    "deploymentStatus": "DEPLOYED",
    "metadata": {"domain": {"name": "Branch", "id": CHILD, "type": "Domain"}},
}
HQ_FTD = {
    "id": HQ_ID,
    "name": "ftd-hq",
    "type": "Device",
    "hostName": "192.0.2.20",
    "accessPolicy": {"id": "00505686-0000-0ed3-0000-004294967000", "name": "hq-acp", "type": "AccessPolicy"},
    "metadata": {"domain": {"name": "Global", "id": CFG.rsplit("/", 1)[-1], "type": "Domain"}},
}
ACP = {"id": ACP_ID, "name": "branch-acp", "type": "AccessPolicy", "defaultAction": {"action": "BLOCK"}}
RULE = {
    "id": "00505686-0000-0ed3-0000-000268434474",
    "name": "branch-allow-web",
    "type": "AccessRule",
    "action": "ALLOW",
    "enabled": True,
    "metadata": {"ruleIndex": 1, "section": "Mandatory"},
}
# The ACCESS-LIST phase names the first Snort-bound rule; Snort's phase only gives the deciding rule's id.
ACL_CONFIG = (
    "\naccess-group CSM_FW_ACL_ global\n"
    "access-list CSM_FW_ACL_ advanced permit ip any any rule-id 268434473\n"
    "access-list CSM_FW_ACL_ remark rule-id 268434473: ACCESS POLICY: branch-acp - Mandatory\n"
    "access-list CSM_FW_ACL_ remark rule-id 268434473: L7 RULE: branch-app-rule\n"
)
NOT_FOUND = httpx.Response(
    404,
    json={
        "error": {"category": "FRAMEWORK", "messages": [{"description": "Not found"}], "severity": "ERROR"}
    },
)


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def server() -> Any:
    return create_server(make_settings())


@pytest.fixture
def md(fmc: respx.MockRouter) -> respx.MockRouter:
    """Global lists the child's FTD; the policy exists only in the child (Global's path is a 404)."""
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([BRANCH_FTD]))
    fmc.get(f"{CFG}/devices/devicerecords/{DEV_ID}").mock(return_value=httpx.Response(200, json=BRANCH_FTD))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}", name="global_acp").mock(return_value=NOT_FOUND)
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules", name="global_rules").mock(
        return_value=NOT_FOUND
    )
    fmc.get(f"{CFG}/policy/accesspolicies", name="global_acps").mock(return_value=items([]))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([]))
    fmc.get(f"{CHILD_CFG}/policy/accesspolicies/{ACP_ID}", name="child_acp").mock(
        return_value=httpx.Response(200, json=ACP)
    )
    fmc.get(f"{CHILD_CFG}/policy/accesspolicies/{ACP_ID}/accessrules", name="child_rules").mock(
        return_value=items([RULE])
    )
    fmc.get(f"{CHILD_CFG}/assignment/policyassignments").mock(
        return_value=items(
            [
                {
                    "id": ACP_ID,
                    "policy": ACP_REF,
                    "targets": [{"id": DEV_ID, "name": "ftd-branch", "type": "Device"}],
                }
            ]
        )
    )
    return fmc


def rest_empty(router: respx.MockRouter) -> None:
    """Everything else in the child domain (object catalogs, interfaces, categories) answers empty. Added
    last: respx matches routes in order, so a test's own child-domain routes go first."""
    router.get(url__regex=re.escape(CHILD_CFG) + r"/.*").mock(return_value=items([]))


async def test_rule_lookup_reads_the_policy_in_the_devices_domain(md: respx.MockRouter) -> None:
    rest_empty(md)
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_rule_lookup",
            {
                "device": "ftd-branch",
                "source": "198.51.100.10",
                "destination": "203.0.113.80",
                "protocol": "tcp",
                "port": 443,
                "source_zone": "inside",
                "destination_zone": "outside",
            },
        )
    assert out["verdict"] == "Rule 1 'branch-allow-web' → ALLOW", out
    assert out["policy"] == "branch-acp"
    assert out["domain"] == "Global/Branch (the device's)"
    assert not md.routes["global_acp"].called and not md.routes["global_rules"].called
    assert md.routes["child_acp"].called and md.routes["child_rules"].called


async def test_an_explicit_domain_that_disagrees_is_a_clear_error(md: respx.MockRouter) -> None:
    rest_empty(md)
    async with Client(server()) as c:
        with pytest.raises(
            ToolError, match=r"ftd-branch is in domain Global/Branch; pass domain='Global/Branch'"
        ):
            await run(
                c,
                "fmc_rule_lookup",
                {
                    "device": "ftd-branch",
                    "source": "198.51.100.10",
                    "destination": "203.0.113.80",
                    "protocol": "tcp",
                    "port": 443,
                    "domain": "Global",
                },
            )
        with pytest.raises(ToolError, match="is in domain Global/Branch"):
            await run(c, "fmc_get_access_policy", {"device": "ftd-branch", "domain": "Global"})
    assert not md.routes["global_acp"].called


async def test_the_devices_own_domain_given_explicitly_works(md: respx.MockRouter) -> None:
    md.get(f"{CHILD_CFG}/devices/devicerecords").mock(return_value=items([BRANCH_FTD]))
    rest_empty(md)
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_rule_lookup",
            {
                "device": "ftd-branch",
                "source": "198.51.100.10",
                "destination": "203.0.113.80",
                "protocol": "tcp",
                "port": 443,
                "source_zone": "inside",
                "destination_zone": "outside",
                "domain": "Global/Branch",
            },
        )
    assert out["verdict"].startswith("Rule 1 'branch-allow-web'")
    assert "domain" not in out  # read where the caller asked: nothing to point out


async def test_get_access_policy_by_device_follows_the_devices_domain(md: respx.MockRouter) -> None:
    rest_empty(md)
    async with Client(server()) as c:
        out = await run(c, "fmc_get_access_policy", {"device": "ftd-branch"})
        with pytest.raises(ToolError, match="Give the access policy"):
            await run(c, "fmc_get_access_policy", {})
    assert out["name"] == "branch-acp" and out["default_action"] == "BLOCK"
    assert out["domain"] == "Global/Branch (the device's)"
    assert out["assigned_to"] == ["ftd-branch"]
    assert out["rules"]["total"] == 1
    assert not md.routes["global_acp"].called


def tracer_routes(md: respx.MockRouter) -> respx.Route:
    """The child FTD's inside interface and a trace FMC answers in the child domain."""
    inside = {
        "id": "if-inside",
        "type": "PhysicalInterface",
        "name": "GigabitEthernet0/0",
        "ifname": "inside",
    }
    md.get(f"{CHILD_CFG}/devices/devicerecords/{DEV_ID}/physicalinterfaces").mock(
        return_value=items([inside])
    )
    # Snort decided on a rule the ACCESS-LIST phase names only by id: the name comes from the policy.
    trace = {
        "deviceResponse": [
            {
                "deviceDetails": {"name": "ftd-branch", "id": DEV_ID, "type": "Device"},
                "phases": [
                    {
                        "id": 1,
                        "type": "ACCESS-LIST",
                        "result": "ALLOW",
                        "config": ACL_CONFIG,
                        "additionalInformation": "\nThis packet will be sent to snort\n",
                    },
                    {
                        "id": 2,
                        "type": "SNORT",
                        "subType": "firewall",
                        "result": "ALLOW",
                        "config": "\nNetwork 0, Inspection 0, Detection 0, Rule ID 268434474\n",
                        "additionalInformation": "\nStarting rule matching, zone -1 -> -1\nallow action\n",
                    },
                ],
                "result": {
                    "inputInterface": "inside(vrfid:0)",
                    "outputInterface": "outside(vrfid:0)",
                    "action": "allow",
                },
            }
        ]
    }
    md.get(f"{CHILD_CFG}/policy/accesspolicies", name="child_acps").mock(return_value=items([ACP]))
    post = md.post(f"/api/fmc_troubleshoot/v1/domain/{CHILD}/packettracer/traces").mock(
        return_value=httpx.Response(200, json=trace)
    )
    md.get(url__regex=re.escape(CFG) + r"/(devicehapairs|deviceclusters)/.*").mock(return_value=items([]))
    rest_empty(md)
    return post


async def test_packet_tracer_names_rules_in_the_devices_domain(md: respx.MockRouter) -> None:
    post = tracer_routes(md)
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_packet_tracer",
            {
                "device": "ftd-branch",
                "input_interface": "inside",
                "protocol": "tcp",
                "source_ip": "198.51.100.10",
                "destination_ip": "203.0.113.80",
                "destination_port": 443,
            },
        )
    assert post.called
    assert out["domain"] == "Global/Branch (the device's)"
    assert not md.routes["global_acps"].called and not md.routes["global_rules"].called
    named = [r.get("rule") for t in out["results"] for r in t.get("matched_rules") or []]
    assert "branch-allow-web" in named, out


async def test_prove_policy_traces_and_names_in_the_devices_domain(md: respx.MockRouter) -> None:
    post = tracer_routes(md)
    flow = {"source": "198.51.100.10", "destination": "203.0.113.80", "port": 443, "expect": "allow"}
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_prove_policy",
            {
                "flows": [{**flow, "input_interface": "inside"}],
                "device": "ftd-branch",
                "response_format": "json",
            },
        )
        text = (
            (
                await c.call_tool(
                    "fmc_prove_policy",
                    {"flows": [{**flow, "input_interface": "inside"}], "device": "ftd-branch"},
                )
            )
            .content[0]
            .text
        )  # type: ignore[union-attr]
    row = out["results"][0]
    assert post.called and row["result"] == "pass", row
    assert row["rule"] == "branch-allow-web" and row["domain"] == "Global/Branch (the device's)"
    assert "Global/Branch (the device's)" in text  # the markdown table gets the column
    assert not md.routes["global_acps"].called


async def test_list_devices_shows_the_domain_of_descendant_devices(md: respx.MockRouter) -> None:
    md.get(f"{CFG}/devices/devicerecords").mock(return_value=items([HQ_FTD, BRANCH_FTD]))
    rest_empty(md)
    async with Client(server()) as c:
        out = await run(c, "fmc_list_devices", {"response_format": "json"})
        text = (await c.call_tool("fmc_list_devices", {})).content[0].text  # type: ignore[union-attr]
    rows = {r["name"]: r for r in out["results"]}
    assert rows["ftd-branch"]["domain"] == "Global/Branch"
    assert rows["ftd-hq"]["domain"] == "Global"
    assert "domain" in text and "Global/Branch" in text


async def test_list_devices_without_descendant_devices_has_no_domain_column(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([HQ_FTD]))
    async with Client(server()) as c:
        out = await run(c, "fmc_list_devices", {"response_format": "json"})
    assert "domain" not in out["results"][0]


async def test_list_policies_in_global_points_at_the_child_domain(md: respx.MockRouter) -> None:
    rest_empty(md)
    async with Client(server()) as c:
        out = await run(c, "fmc_list_policies", {"kind": "access", "response_format": "json"})
    assert out["results"] == []
    assert "Global/Branch (ftd-branch)" in out["note"] and "domain='Global/Branch'" in out["note"]


async def test_list_policies_in_the_leaf_has_no_note(md: respx.MockRouter) -> None:
    md.get(f"{CHILD_CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    rest_empty(md)
    async with Client(server()) as c:
        out = await run(
            c, "fmc_list_policies", {"kind": "access", "domain": "Branch", "response_format": "json"}
        )
    assert [r["name"] for r in out["results"]] == ["branch-acp"]
    assert "note" not in out


async def test_device_home_cases(fmc: respx.MockRouter) -> None:
    from fmc_mcp.client import FmcApp

    from .conftest import DOMAIN

    app = FmcApp(make_settings())
    try:
        await app.ensure_login()
        assert await app.device_home(BRANCH_FTD, None) == (CHILD, "Global/Branch")
        assert await app.device_home(HQ_FTD, None) == (DOMAIN, None)
        assert await app.device_home(BRANCH_FTD, "Global", strict=False) == (CHILD, "Global/Branch")
        assert await app.device_home(BRANCH_FTD, "Branch") == (CHILD, None)
        # a record without metadata: one GET in the requested domain says where it lives (cached)
        lookup = fmc.get(f"{CFG}/devices/devicerecords/{DEV_ID}").mock(
            return_value=httpx.Response(200, json=BRANCH_FTD)
        )
        bare = {"id": DEV_ID, "name": "ftd-branch"}
        assert await app.device_home(bare, None) == (CHILD, "Global/Branch")
        assert await app.device_home(bare, None) == (CHILD, "Global/Branch")
        assert lookup.call_count == 1
        # an owner this login doesn't list: left to FMC
        elsewhere = {**BRANCH_FTD, "metadata": {"domain": {"id": "77777777-0000-4000-8000-000000000007"}}}
        assert await app.device_home(elsewhere, None) == (DOMAIN, None)
    finally:
        await app.aclose()

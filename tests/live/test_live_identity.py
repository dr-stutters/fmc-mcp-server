"""F13 identity slice against the lab AD (DC01.mitchcloud.lab, scripts/seed_identity.py): realm test and
download from FMC, an access rule on group mcp-contractors deployed to the FTD, and fmc_rule_lookup with
identities. There is no passive identity source in the lab (no ISE/pxGrid session for the inside host), so
the FTD never learns a user for 10.99.1.10 and the rule can't be proven on traffic; the test checks what
FMC and the FTD's policy show."""

from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .test_live_ftd import ACP, DEVICE, apply, call, deploy, needs_ftd

pytestmark = pytest.mark.live

REALM = "mcp-test-mitchcloud"
IDP = "mcp-test-idp"
RULE = "mcp-test-w-contractors-telnet"
GROUPS = {"mcp-employees", "mcp-contractors", "mcp-netadmins", "mcp-netreadonly"}


async def realm_or_skip(client: Client[Any]) -> dict[str, Any]:
    listed = await call(client, "fmc_get_realm", {"response_format": "json"})
    if not any(r["name"] == REALM for r in listed["results"]):
        pytest.skip(f"realm {REALM} missing: run scripts/seed_identity.py")
    out: dict[str, Any] = await call(
        client, "fmc_get_realm", {"realm": REALM, "members": "groups", "response_format": "json"}
    )
    return out


async def test_realm_test_and_download(client: Client[Any]) -> None:
    await realm_or_skip(client)
    try:
        tested = await call(client, "fmc_test_realm", {"realm": REALM})
    except ToolError as e:
        if "FMC_UI_USERNAME" in str(e):
            pytest.skip("FMC_UI_USERNAME not set")
        raise
    assert all(s["result"] == "ok" for s in tested["servers"]), tested
    done = await apply(client, "fmc_download_realm", {"realm": REALM})
    assert done["status"] == "success", done
    realm = await realm_or_skip(client)
    assert set(realm["groups"]) >= GROUPS, realm


@needs_ftd
async def test_group_rule_deploys(client: Client[Any]) -> None:
    realm = await realm_or_skip(client)
    assert "mcp-contractors" in realm.get("groups", []), realm
    idp = await call(client, "fmc_get_identity_policy", {"policy": IDP, "response_format": "json"})
    if ACP not in idp["used_by"]:
        pytest.skip(f"{IDP} is not selected in {ACP} (UI only: scripts/seed_identity.py)")
    await apply(
        client,
        "fmc_create_access_rule",
        {
            "policy": ACP,
            "name": RULE,
            "action": "BLOCK",
            "users": ["mcp-contractors"],
            "destination_ports": ["tcp/23"],
            "insert_before": 1,
        },
    )
    try:
        rules = await call(client, "fmc_list_access_rules", {"policy": ACP, "response_format": "json"})
        row = next(r for r in rules["results"] if r["name"] == RULE)
        assert row["users"] == ["mcp-contractors"], row
        flow = {"source": "10.99.1.10", "destination": "198.18.128.1", "port": 23, "device": DEVICE}
        unknown = await call(client, "fmc_rule_lookup", flow)
        assert any(r["name"] == RULE and r["depends_on"] == ["users"] for r in unknown["may_match_first"])
        bob = await call(client, "fmc_rule_lookup", {**flow, "identities": ["mcp-bob", "mcp-contractors"]})
        assert bob["matched_rule"]["name"] == RULE, bob
        alice = await call(client, "fmc_rule_lookup", {**flow, "identities": ["mcp-alice", "mcp-employees"]})
        assert alice["matched_rule"]["name"] != RULE, alice
        await deploy(client, "mcp live test: user group rule", ignore_warning=True)
        acp = await call(client, "fmc_get_access_policy", {"policy": ACP})
        assert acp.get("identity_policy") == IDP, acp
    finally:
        await apply(client, "fmc_delete_access_rule", {"policy": ACP, "rule": RULE})
        await deploy(client, "mcp live test: user group rule removed", ignore_warning=True)

"""F13 identity slice against an AD/LDAP realm already set up in FMC (FMC_LIVE_REALM; docs/live-tests.md):
realm test and download from FMC, an access rule on the group FMC_LIVE_REALM_GROUP deployed to the FTD, and
fmc_rule_lookup with identities. The rule test also needs an identity policy (FMC_LIVE_IDENTITY_POLICY)
selected in mcp-test-ftd-acp (FMC's REST API can't select it). Without a passive identity source (ISE/pxGrid
or an agent) the FTD never learns a user for the inside host, so the rule can't be proven on traffic; the
test checks what FMC and the FTD's policy show."""

from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .live_env import live_env, need
from .test_live_ftd import ACP, DEVICE, TRACE_TARGET, apply, call, deploy, needs_ftd

pytestmark = pytest.mark.live

REALM = live_env("FMC_LIVE_REALM")
GROUP = live_env("FMC_LIVE_REALM_GROUP")
IDP = live_env("FMC_LIVE_IDENTITY_POLICY")
RULE = "mcp-test-w-group-telnet"


async def realm_or_skip(client: Client[Any]) -> dict[str, Any]:
    need("FMC_LIVE_REALM")
    need("FMC_LIVE_REALM_GROUP")
    listed = await call(client, "fmc_get_realm", {"response_format": "json"})
    if not any(r["name"] == REALM for r in listed["results"]):
        pytest.skip(f"FMC has no realm {REALM} (FMC_LIVE_REALM)")
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
    assert GROUP in realm["groups"], realm


@needs_ftd
async def test_group_rule_deploys(client: Client[Any]) -> None:
    need("FMC_LIVE_IDENTITY_POLICY")
    realm = await realm_or_skip(client)
    assert GROUP in realm.get("groups", []), realm
    idp = await call(client, "fmc_get_identity_policy", {"policy": IDP, "response_format": "json"})
    if ACP not in idp["used_by"]:
        pytest.skip(f"{IDP} is not selected in {ACP} (FMC web UI only)")
    await apply(
        client,
        "fmc_create_access_rule",
        {
            "policy": ACP,
            "name": RULE,
            "action": "BLOCK",
            "users": [GROUP],
            "destination_ports": ["tcp/23"],
            "insert_before": 1,
        },
    )
    try:
        rules = await call(client, "fmc_list_access_rules", {"policy": ACP, "response_format": "json"})
        row = next(r for r in rules["results"] if r["name"] == RULE)
        assert row["users"] == [GROUP], row
        flow = {"source": "10.99.1.10", "destination": TRACE_TARGET, "port": 23, "device": DEVICE}
        unknown = await call(client, "fmc_rule_lookup", flow)
        assert any(r["name"] == RULE and r["depends_on"] == ["users"] for r in unknown["may_match_first"])
        # identities are compared by name, so made-up users do: one in the group, one outside it
        member = await call(client, "fmc_rule_lookup", {**flow, "identities": ["mcp-test-member", GROUP]})
        assert member["matched_rule"]["name"] == RULE, member
        outsider = ["mcp-test-other", "mcp-test-group"]
        other = await call(client, "fmc_rule_lookup", {**flow, "identities": outsider})
        assert other["matched_rule"]["name"] != RULE, other
        await deploy(client, "mcp live test: user group rule", ignore_warning=True)
        acp = await call(client, "fmc_get_access_policy", {"policy": ACP})
        assert acp.get("identity_policy") == IDP, acp
    finally:
        await apply(client, "fmc_delete_access_rule", {"policy": ACP, "rule": RULE})
        await deploy(client, "mcp live test: user group rule removed", ignore_warning=True)

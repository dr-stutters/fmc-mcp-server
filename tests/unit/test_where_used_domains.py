"""fmc_where_used on a multi-domain FMC (#210): a Global object used by a child domain's policy. FMC answers
usage only in the object's owner domain (400 in the child), and a child's policy is invisible from Global
(404), so usage runs in the owner domain and each policy's rules are read where the policy is visible.
Recorded in the lab: tests/fixtures/where_used_inherited.json."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, CHILD, FIXTURES, empty, items, make_settings

LAB_LEAF = "a1c73df0-8353-8db7-1097-000000000000"
# The lab's leaf id becomes the test FMC's Global/Branch.
REC: dict[str, Any] = json.loads(
    (FIXTURES / "where_used_inherited.json").read_text().replace(LAB_LEAF, CHILD)
)
CHILD_CFG = f"/api/fmc_config/v1/domain/{CHILD}"
ACP = "policy/accesspolicies/00000000-0000-0ed3-0000-021474836766/accessrules"  # mcp-test-acp (Global)
IMP = "policy/accesspolicies/00000000-0000-0ed3-0000-021474849158/accessrules"  # mcp-test-acp-import (leaf)
NAT = "policy/ftdnatpolicies/00000000-0000-0ed3-0000-021474836981/natrules"  # mcp-test-nat (Global)
WANT = {
    ("mcp-test-acp", "mcp-test-ssh-admin", "Global"),
    ("mcp-test-acp-import", "mcp-test-ssh-admin", "Global/Branch"),
    ("mcp-test-acp-import", "mcp-test-shadowed", "Global/Branch"),
}


async def where_used(domain: str | None = None) -> Any:
    args: dict[str, Any] = {"object": "mcp-test-db", "type": "host"}
    if domain:
        args["domain"] = domain
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool("fmc_where_used", args)
    return r.structured_content


def rules_of(out: dict[str, Any]) -> set[tuple[str, str, str]]:
    return {(r["policy"], r["name"], r["domain"]) for r in out["rules"]}


async def test_child_domain_asks_the_owner_domain_and_reads_each_policy_where_it_lives(
    fmc: respx.MockRouter,
) -> None:
    fmc.get(f"{CHILD_CFG}/object/hosts").mock(return_value=items([REC["leaf_host"]]))
    leaf_usage = fmc.get(f"{CHILD_CFG}/object/operational/usage").mock(
        return_value=httpx.Response(400, json=REC["leaf_usage_400"])
    )
    fmc.get(f"{CFG}/object/operational/usage").mock(
        return_value=httpx.Response(200, json=REC["global_usage"])
    )
    fmc.get(f"{CHILD_CFG}/{ACP}").mock(
        return_value=httpx.Response(200, json=REC["global_policy_rules_from_leaf"])
    )
    fmc.get(f"{CHILD_CFG}/{IMP}").mock(return_value=httpx.Response(200, json=REC["leaf_policy_rules"]))
    fmc.get(f"{CHILD_CFG}/{NAT}").mock(return_value=empty())
    out = await where_used("Branch")
    assert leaf_usage.called
    assert out["in_use"] is True and out["object"]["domain"] == "Global"
    assert "inherited from 'Global'" in out["note"]
    assert {u["name"]: u.get("domain") for u in out["used_by"]} == {
        "mcp-test-acp": "Global",
        "mcp-test-acp-import": "Global/Branch",
        "mcp-test-nat": None,  # no rules to tell
    }
    assert rules_of(out) == WANT
    assert "warnings" not in out


async def test_global_reads_a_child_policy_in_the_child(fmc: respx.MockRouter) -> None:
    host = {**REC["leaf_host"], "metadata": {"domain": REC["leaf_host"]["metadata"]["domain"]}}
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([host]))
    fmc.get(f"{CFG}/object/operational/usage").mock(
        return_value=httpx.Response(200, json=REC["global_usage"])
    )
    fmc.get(f"{CFG}/{ACP}").mock(return_value=httpx.Response(200, json=REC["global_policy_rules_from_leaf"]))
    hidden = fmc.get(f"{CFG}/{IMP}").mock(return_value=httpx.Response(404, json={}))
    fmc.get(f"{CHILD_CFG}/{IMP}").mock(return_value=httpx.Response(200, json=REC["leaf_policy_rules"]))
    fmc.get(f"{CFG}/{NAT}").mock(return_value=empty())
    out = await where_used()
    assert hidden.call_count == 1  # tried in Global first, then in the domain below
    assert rules_of(out) == WANT
    assert "note" not in out and out["object"]["domain"] == "Global"


async def test_policy_no_domain_can_read_is_a_warning(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([REC["leaf_host"]]))
    fmc.get(f"{CFG}/object/operational/usage").mock(
        return_value=httpx.Response(200, json=REC["global_usage"])
    )
    fmc.get(f"{CFG}/{ACP}").mock(return_value=httpx.Response(200, json=REC["global_policy_rules_from_leaf"]))
    for path in (f"{CFG}/{IMP}", f"{CHILD_CFG}/{IMP}"):
        fmc.get(path).mock(return_value=httpx.Response(404, json={}))
    fmc.get(f"{CFG}/{NAT}").mock(return_value=empty())
    out = await where_used()
    assert rules_of(out) == {("mcp-test-acp", "mcp-test-ssh-admin", "Global")}
    assert out["warnings"] == [
        "Couldn't read the rules of mcp-test-acp-import in any domain this login sees."
    ]


async def test_usage_refused_in_the_owner_domain_still_explains(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([REC["leaf_host"]]))
    fmc.get(f"{CFG}/object/operational/usage").mock(
        return_value=httpx.Response(400, json=REC["leaf_usage_400"])
    )
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool(
            "fmc_where_used", {"object": "mcp-test-db", "type": "host"}, raise_on_error=False
        )
    assert r.is_error and "fmc_list_access_rules" in r.content[0].text  # type: ignore[union-attr]

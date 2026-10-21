"""fmc_assign_policy writes an ancestor-owned policy's assignment in the policy's own domain (#273).

FMC 10.0.1 (final-live 2026-10-21): assigning Global's mcp-test-ftd-acp to mcp-ftd1 from Global/mcp-test-leaf
POSTed the new PolicyAssignment in the leaf and FMC answered 406 "You do not have the required authorization
to do this operation."; the same call with domain='Global' worked. Called from Global for a leaf device, the
preview's `from` was empty: Global's list doesn't show the leaf-owned policy the device runs."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, CHILD, fixture, items, make_settings

CHILD_CFG = f"/api/fmc_config/v1/domain/{CHILD}"
FX = fixture("assign_owner_domain_fmc10")
GLOBAL_ACP = FX["leaf_accesspolicy_global_owned"]  # mcp-test-ftd-acp, metadata.domain Global
PS_ROWS = FX["leaf_platformsettings_expanded"]["items"]  # mcp-test-ps (Global), mcp-fw-ps, mcp-w6-ps (leaf)
GLOBAL_PS, LEAF_PS = PS_ROWS[0], PS_ROWS[2]
GLOBAL_ASSIGNMENTS = FX["global_assignments"]["items"]  # mcp-test-ps and mcp-test-ftd-acp on mcp-ftd1
FTD1 = GLOBAL_ASSIGNMENTS[0]["targets"][0]
LEAF = {"id": CHILD, "name": "Global \\ Branch", "type": "Domain"}
FTD1_RECORD = {"id": FTD1["id"], "name": FTD1["name"], "type": "Device", "metadata": {"domain": LEAF}}
OTHER = {"id": "2c0f0000-0000-4000-8000-000000000009", "name": "ftd-other", "type": "Device"}
LEAF_ACP = {
    "id": "00000000-0000-0ed3-0000-021474964001",
    "name": "mcp-w6-acp",
    "type": "AccessPolicy",
    "metadata": {"domain": LEAF},
}


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


def assignment(policy: dict[str, Any], *targets: dict[str, Any]) -> dict[str, Any]:
    pol = {k: policy[k] for k in ("id", "name", "type")}
    tgts = [{k: t[k] for k in ("id", "type", "name")} for t in targets]
    return {
        "id": policy["id"],
        "type": "PolicyAssignment",
        "name": policy["name"],
        "policy": pol,
        "targets": tgts,
    }


def leaf_mocks(
    fmc: respx.MockRouter, *, leaf_rows: list[dict[str, Any]], global_rows: list[dict[str, Any]]
) -> None:
    fmc.get(f"{CHILD_CFG}/devices/devicerecords").mock(return_value=items([FTD1_RECORD]))
    fmc.get(f"{CHILD_CFG}/policy/accesspolicies").mock(return_value=items([GLOBAL_ACP, LEAF_ACP]))
    fmc.get(f"{CHILD_CFG}/policy/ftdplatformsettingspolicies").mock(return_value=items(PS_ROWS))
    fmc.get(f"{CHILD_CFG}/assignment/policyassignments").mock(return_value=items(leaf_rows))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items(global_rows))


async def test_first_assignment_of_a_global_policy_is_posted_in_global(fmc: respx.MockRouter) -> None:
    """The final-live case: mcp-ftd1 runs the leaf's mcp-w6-acp; Global's mcp-test-ftd-acp has no
    assignment yet."""
    leaf_mocks(fmc, leaf_rows=[assignment(LEAF_ACP, FTD1)], global_rows=[GLOBAL_ASSIGNMENTS[0]])
    leaf_post = fmc.post(f"{CHILD_CFG}/assignment/policyassignments").mock(
        return_value=httpx.Response(406, json=FX["fmc_406"])
    )
    post = fmc.post(f"{CFG}/assignment/policyassignments").mock(return_value=httpx.Response(201, json={}))
    args = {"kind": "access", "policy": "mcp-test-ftd-acp", "devices": ["mcp-ftd1"], "domain": "Branch"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_assign_policy", args)
        assert preview["status"] == "preview", preview
        assert preview["preview"]["changes"] == [
            {"device": "mcp-ftd1", "from": "mcp-w6-acp", "to": "mcp-test-ftd-acp"}
        ]
        assert preview["preview"]["domain"] == "Global/Branch"
        assert preview["preview"]["assigned_in"] == "Global"
        assert any("assignment is made there" in s and "406" in s for s in preview["side_effects"]), preview
        await run(c, "fmc_assign_policy", {**args, "confirm": preview["confirm"]})
    assert not leaf_post.called
    body = json.loads(post.calls.last.request.content)
    assert body == {
        "type": "PolicyAssignment",
        "policy": {"id": GLOBAL_ACP["id"], "type": "AccessPolicy"},
        "targets": [{"id": FTD1["id"], "type": "Device"}],
    }


async def test_global_policy_with_an_assignment_is_updated_in_global(fmc: respx.MockRouter) -> None:
    """mcp-test-ps already targets another device: PUT its assignment where it lives, keeping that target."""
    leaf_mocks(
        fmc,
        leaf_rows=[assignment(LEAF_PS, FTD1)],
        global_rows=[{**GLOBAL_ASSIGNMENTS[0], "targets": [OTHER]}, GLOBAL_ASSIGNMENTS[1]],
    )
    leaf_put = fmc.put(f"{CHILD_CFG}/assignment/policyassignments/{GLOBAL_PS['id']}")
    put = fmc.put(f"{CFG}/assignment/policyassignments/{GLOBAL_PS['id']}").mock(
        return_value=httpx.Response(200, json={})
    )
    args = {"kind": "platform_settings", "policy": "mcp-test-ps", "devices": ["mcp-ftd1"], "domain": "Branch"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_assign_policy", args)
        assert preview["preview"]["changes"] == [
            {"device": "mcp-ftd1", "from": "mcp-w6-ps", "to": "mcp-test-ps"}
        ]
        assert (
            preview["preview"]["policy_domain"] == "Global" and preview["preview"]["assigned_in"] == "Global"
        )
        await run(c, "fmc_assign_policy", {**args, "confirm": preview["confirm"]})
    assert not leaf_put.called
    body = json.loads(put.calls.last.request.content)
    assert body["id"] == GLOBAL_PS["id"]
    assert [t["id"] for t in body["targets"]] == [OTHER["id"], FTD1["id"]]


async def test_leaf_policy_from_the_leaf_stays_in_the_leaf(fmc: respx.MockRouter) -> None:
    leaf_mocks(fmc, leaf_rows=[], global_rows=GLOBAL_ASSIGNMENTS)
    post = fmc.post(f"{CHILD_CFG}/assignment/policyassignments").mock(
        return_value=httpx.Response(201, json={})
    )
    args = {"kind": "platform_settings", "policy": "mcp-w6-ps", "devices": ["mcp-ftd1"], "domain": "Branch"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_assign_policy", args)
        assert preview["preview"]["changes"] == [
            {"device": "mcp-ftd1", "from": "mcp-test-ps", "to": "mcp-w6-ps"}
        ]
        assert "assigned_in" not in preview["preview"]
        assert not any("406" in s for s in preview["side_effects"])
        await run(c, "fmc_assign_policy", {**args, "confirm": preview["confirm"]})
    assert post.called


async def test_from_global_a_leaf_device_shows_its_leaf_policy(fmc: respx.MockRouter) -> None:
    """Called from Global for a leaf device: `from` comes from the device's own domain's list (one read)."""
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([FTD1_RECORD]))
    fmc.get(f"{CFG}/policy/ftdplatformsettingspolicies").mock(return_value=items([GLOBAL_PS]))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([GLOBAL_ASSIGNMENTS[1]]))
    leaf_list = fmc.get(f"{CHILD_CFG}/assignment/policyassignments").mock(
        return_value=items([assignment(LEAF_PS, FTD1)])
    )
    post = fmc.post(f"{CFG}/assignment/policyassignments").mock(return_value=httpx.Response(201, json={}))
    args = {"kind": "platform_settings", "policy": "mcp-test-ps", "devices": ["mcp-ftd1"], "domain": "Global"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_assign_policy", args)
        assert preview["preview"]["changes"] == [
            {"device": "mcp-ftd1", "from": "mcp-w6-ps", "to": "mcp-test-ps"}
        ]
        assert "assigned_in" not in preview["preview"]
        await run(c, "fmc_assign_policy", {**args, "confirm": preview["confirm"]})
    assert leaf_list.call_count == 2  # once per call (preview, confirm), not per device
    assert post.called


async def test_owner_domain_refusal_says_where_and_why(fmc: respx.MockRouter) -> None:
    leaf_mocks(fmc, leaf_rows=[assignment(LEAF_ACP, FTD1)], global_rows=[GLOBAL_ASSIGNMENTS[0]])
    fmc.post(f"{CFG}/assignment/policyassignments").mock(return_value=httpx.Response(406, json=FX["fmc_406"]))
    args = {"kind": "access", "policy": "mcp-test-ftd-acp", "devices": ["mcp-ftd1"], "domain": "Branch"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_assign_policy", args)
        r = await c.call_tool(
            "fmc_assign_policy", {**args, "confirm": preview["confirm"]}, raise_on_error=False
        )
    text = r.content[0].text  # type: ignore[union-attr]
    assert r.is_error and "in domain 'Global', which owns 'mcp-test-ftd-acp'" in text, text
    assert "write access to 'Global'" in text

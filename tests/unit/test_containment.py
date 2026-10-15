"""fmc_contain_host / fmc_release_host (F9): quarantine via a dynamic object, no deployment."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, items, make_settings
from .test_dynamic_objects import ACP, ALLOW, DYN, MAPPINGS, RULE

DEV = {"id": "dev-1", "name": "mcp-ftd1", "type": "Device"}
ASSIGN = {"id": ACP["id"], "policy": ACP, "targets": [DEV]}
QDYN = {**DYN, "name": "mcp-quarantine"}
QREF = {"objects": [{"id": DYN["id"], "name": "mcp-quarantine", "type": "DynamicObject"}]}
QOUT = {**RULE, "name": "mcp-quarantine-out", "sourceDynamicObjects": QREF}
QIN = {
    "id": "in-1",
    "name": "mcp-quarantine-in",
    "action": "BLOCK",
    "enabled": True,
    "metadata": {"ruleIndex": 2},
    "destinationDynamicObjects": QREF,
}
QRULES = [QOUT, QIN]
MAP_POST = f"{CFG}/object/dynamicobjectmappings"
RULES = f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules"


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def base(
    fmc: respx.MockRouter, *, objects: list[Any], rules: list[Any], mapped: list[str]
) -> respx.MockRouter:
    fmc.get(f"{CFG}/object/dynamicobjects").mock(return_value=items(objects))
    fmc.get(MAPPINGS).mock(return_value=items([{"mapping": m} for m in mapped]))
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}").mock(return_value=httpx.Response(200, json=ACP))
    fmc.get(RULES).mock(return_value=items(rules))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([ASSIGN]))
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([]))
    return fmc


async def test_contain_with_rule_in_place_needs_no_deploy(fmc: respx.MockRouter) -> None:
    base(fmc, objects=[QDYN], rules=[*QRULES, ALLOW], mapped=["10.99.1.250"])
    post = fmc.post(MAP_POST).mock(return_value=httpx.Response(201, json={}))
    args = {"ip": "10.99.1.10", "reason": "ISE ANC quarantine"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_contain_host", args)
        p = preview["preview"]
        assert preview["status"] == "preview" and not p["deploy_needed"]
        assert p["devices"] == ["mcp-ftd1"] and p["block_rules"][0]["rule"] == "mcp-quarantine-out"
        assert p["steps"] == ["Map 10.99.1.10 into 'mcp-quarantine'"]
        assert any("without a deployment" in s for s in preview["side_effects"])
        done = await run(c, "fmc_contain_host", {**args, "confirm": preview["confirm"]})
    assert json.loads(post.calls.last.request.content)["add"][0]["mappings"] == ["10.99.1.10"]
    assert done["result"]["contained"] and not done["result"]["deploy_needed"]


async def test_contain_is_idempotent(fmc: respx.MockRouter) -> None:
    base(fmc, objects=[QDYN], rules=QRULES, mapped=["10.99.1.10"])
    post = fmc.post(MAP_POST).mock(return_value=httpx.Response(201, json={}))
    args = {"ip": "10.99.1.10/32", "reason": "again"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_contain_host", args)
        assert preview["preview"]["already_contained"] and "nothing to change" in preview["action"]
        done = await run(c, "fmc_contain_host", {**args, "confirm": preview["confirm"]})
    assert not post.called and done["result"]["already_contained"]


async def test_contain_sets_up_object_and_rules(fmc: respx.MockRouter) -> None:
    base(fmc, objects=[], rules=[ALLOW], mapped=[])
    mk = fmc.post(f"{CFG}/object/dynamicobjects").mock(return_value=httpx.Response(201, json=QDYN))
    rule = fmc.post(RULES).mock(
        side_effect=lambda req: httpx.Response(201, json=json.loads(req.content) | {"id": "r"})
    )
    post = fmc.post(MAP_POST).mock(return_value=httpx.Response(201, json={}))
    args = {"ip": "10.99.1.10", "reason": "INC-42"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_contain_host", args)
        p = preview["preview"]
        assert p["deploy_needed"] and len(p["steps"]) == 4 and not p["object_exists"]
        assert any("ONE deployment" in s and "mcp-ftd1" in s for s in preview["side_effects"])
        done = await run(c, "fmc_contain_host", {**args, "confirm": preview["confirm"]})
    assert json.loads(mk.calls.last.request.content)["objectType"] == "IP"
    bodies = [json.loads(call.request.content) for call in rule.calls]
    assert [b["name"] for b in bodies] == ["mcp-quarantine-in", "mcp-quarantine-out"]  # -out inserted last
    params = [dict(call.request.url.params) for call in rule.calls]
    assert params == [{"section": "mandatory"}, {"insertBefore": "1"}]
    assert bodies[1]["sourceDynamicObjects"]["objects"][0]["id"] == DYN["id"]
    assert bodies[0]["destinationDynamicObjects"]["objects"][0]["id"] == DYN["id"]
    assert bodies[1]["action"] == "BLOCK" and bodies[1]["logBegin"] and not bodies[1]["logEnd"]
    assert post.called
    assert done["result"]["created_rules"] == ["mcp-quarantine-out", "mcp-quarantine-in"]
    assert done["result"]["deploy_needed"]


async def test_contain_needs_policy_when_ambiguous(fmc: respx.MockRouter) -> None:
    base(fmc, objects=[QDYN], rules=[ALLOW], mapped=[])
    other = {"id": "p2", "name": "other-acp", "type": "AccessPolicy"}
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items([ASSIGN, {"id": "p2", "policy": other, "targets": [{"id": "d2", "name": "ftd2"}]}])
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_contain_host", {"ip": "10.99.1.10", "reason": "x"})
    assert out["status"] == "blocked" and "pass `policy`" in out["blockers"][0]


async def test_release_and_release_again(fmc: respx.MockRouter) -> None:
    base(fmc, objects=[QDYN], rules=QRULES, mapped=["10.99.1.10", "10.99.1.11"])
    post = fmc.post(MAP_POST).mock(return_value=httpx.Response(201, json={}))
    async with Client(server()) as c:
        preview = await run(c, "fmc_release_host", {"ip": "10.99.1.10"})
        assert preview["preview"]["other_contained"] == ["10.99.1.11"]
        done = await run(c, "fmc_release_host", {"ip": "10.99.1.10", "confirm": preview["confirm"]})
    assert json.loads(post.calls.last.request.content)["remove"][0]["mappings"] == ["10.99.1.10"]
    assert done["result"]["released"]
    fmc.get(MAPPINGS).mock(return_value=items([{"mapping": "10.99.1.11"}]))
    post.reset()
    async with Client(server()) as c:
        preview = await run(c, "fmc_release_host", {"ip": "10.99.1.10"})
        assert "nothing to change" in preview["action"]
        done = await run(c, "fmc_release_host", {"ip": "10.99.1.10", "confirm": preview["confirm"]})
    assert not post.called and not done["result"]["released"]


async def test_object_from_settings(fmc: respx.MockRouter) -> None:
    base(fmc, objects=[DYN], rules=[RULE], mapped=[])
    srv = create_server(make_settings(mcp_enable_writes=True, quarantine_object=DYN["name"]))
    async with Client(srv) as c:
        out = await run(c, "fmc_release_host", {"ip": "10.99.1.10"})
    assert out["preview"]["object"] == DYN["name"]


async def test_ineffective_rule_is_flagged_and_replaced(fmc: respx.MockRouter) -> None:
    # The only quarantine rule sits below an ALLOW rule and has a port condition: not containment.
    weak = {
        **QOUT,
        "name": "old-q",
        "metadata": {"ruleIndex": 2},
        "destinationPorts": {"objects": [{"name": "HTTPS"}]},
    }
    base(fmc, objects=[QDYN], rules=[ALLOW, weak], mapped=[])
    async with Client(server()) as c:
        out = await run(c, "fmc_contain_host", {"ip": "10.99.1.10", "reason": "x"})
    assert out["preview"]["deploy_needed"] and out["preview"]["block_rules"] == []
    flagged = next(s for s in out["side_effects"] if "old-q" in s)
    assert "destinationPorts" in flagged and "below an enabled non-block rule" in flagged


async def test_rule_name_collision_blocks(fmc: respx.MockRouter) -> None:
    disabled = {**QOUT, "enabled": False}
    base(fmc, objects=[QDYN], rules=[disabled, QIN, ALLOW], mapped=[])
    async with Client(server()) as c:
        out = await run(c, "fmc_contain_host", {"ip": "10.99.1.10", "reason": "x"})
    assert out["status"] == "blocked" and "mcp-quarantine-out" in out["blockers"][0]


async def test_bad_object_name(fmc: respx.MockRouter) -> None:
    async with Client(server()) as c:
        r = await c.call_tool(
            "fmc_release_host", {"ip": "10.99.1.10", "object": "x" * 46}, raise_on_error=False
        )
    assert r.is_error

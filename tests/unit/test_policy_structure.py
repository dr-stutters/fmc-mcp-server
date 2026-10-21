"""F76 (#171): access policy categories, inheritance (base policy) and policy locks.

Shapes: tests/fixtures/policy_structure_fmc10.json. Recorded live on FMC 10.0.1 by the W6N probe: the
inheritance setting of a policy without a base (its id is the policy's own id, no basePolicy key), the lock
list with nothing locked (one empty item), the access policy's metadata.lockingStatus. From the 10.0.1 spec
examples (Stage 2 proves them live): a setting with a base, a locked policy, categories, the lock POST answer.
"""

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp._core.testing import call_tool
from fmc_mcp.acp_structure import category_row, lock_state, read_locks
from fmc_mcp.server import create_server

from .conftest import ACP_ID, CFG, empty, fixture, items, make_settings

FX = fixture("policy_structure_fmc10")
CHILD = "00000000-0000-0ed3-0000-021474963108"
ACP = fixture("accesspolicies")["items"][0]  # mcp-test-acp, ACP_ID, UNLOCKED
CHILD_ACP = {
    **copy.deepcopy(ACP),
    "id": CHILD,
    "name": "mcp-w6-child-acp",
    "metadata": FX["acp_metadata_unlocked_live"],
}
DEVICE = "43d57cc8-0000-4000-8000-00000000f001"


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else r.content[0].text  # type: ignore[union-attr]


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def preview_apply(name: str, args: dict[str, Any]) -> tuple[Any, Any]:
    async with Client(server()) as c:
        preview = await run(c, name, args)
        assert preview["status"] == "preview", preview
        done = await run(c, name, {**args, "confirm": preview["confirm"]})
        return preview, done


async def preview_only(name: str, args: dict[str, Any]) -> Any:
    async with Client(server()) as c:
        return await run(c, name, args)


def acp_list(fmc: respx.MockRouter, *policies: dict[str, Any]) -> None:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items(list(policies)))
    for p in policies:
        fmc.get(f"{CFG}/policy/accesspolicies/{p['id']}").mock(return_value=httpx.Response(200, json=p))


def no_base(fmc: respx.MockRouter, policy_id: str) -> respx.Route:
    return fmc.get(f"{CFG}/policy/accesspolicies/{policy_id}/inheritancesettings").mock(
        return_value=items([{"id": policy_id, "type": "AccessPolicyInheritanceSetting"}])
    )


def with_base(fmc: respx.MockRouter, policy_id: str, base_id: str) -> respx.Route:
    setting = {
        **FX["inheritance_with_base_spec"],
        "id": policy_id,
        "basePolicy": {"id": base_id, "type": "AccessPolicy"},
    }
    return fmc.get(f"{CFG}/policy/accesspolicies/{policy_id}/inheritancesettings").mock(
        return_value=items([setting])
    )


def categories(fmc: respx.MockRouter, policy_id: str = ACP_ID, data: Any = None) -> respx.Route:
    return fmc.get(f"{CFG}/policy/accesspolicies/{policy_id}/categories").mock(
        return_value=httpx.Response(200, json=data if data is not None else FX["categories_spec"])
    )


def locked_acp(user: str | None = "alice") -> dict[str, Any]:
    p = copy.deepcopy(ACP)
    p["metadata"] = copy.deepcopy(FX["acp_metadata_locked_spec"])
    if user is None:
        p["metadata"]["lockingStatus"].pop("userName")
    else:
        p["metadata"]["lockingStatus"]["userName"] = user
    return p


# --- shapes -------------------------------------------------------------------------------------------


def test_recorded_shapes() -> None:
    assert lock_state({"metadata": FX["acp_metadata_unlocked_live"]}) == {"status": "UNLOCKED"}
    assert lock_state({"metadata": FX["acp_metadata_locked_spec"]}) == {
        "status": "LOCKED",
        "locked_by": "alice",
    }
    assert lock_state({"id": "x", "type": "AccessPolicy"}) is None  # a reference, not the policy
    rows = {r["name"]: r for r in map(category_row, FX["categories_spec"]["items"])}
    assert rows["mcp-w6-cat-web"] == {
        "name": "mcp-w6-cat-web",
        "section": "default",
        "rules": "1-2",
        "id": "00000000-0000-0ed3-0000-000000000c02",
    }
    assert rows["mcp-w6-cat-corp"]["rules"] == "none"  # FMC's -1 = an empty category


async def test_empty_lock_list_is_no_lock(fmc: respx.MockRouter) -> None:
    """FMC 10.0.1 answers {items: [{}], count 1} when nothing is locked: no phantom row."""
    from fmc_mcp.client import FmcApp

    app = FmcApp(make_settings())
    try:
        assert await read_locks(app, None) == []
        fmc.get(f"{CFG}/policy/operational/policylocks").mock(
            return_value=httpx.Response(200, json=FX["policylocks_locked_spec"])
        )
        assert await read_locks(app, None) == [
            {"policy": "mcp-test-acp", "policy_id": ACP_ID, "status": "LOCKED", "locked_by": "alice"}
        ]
        fmc.get(f"{CFG}/policy/operational/policylocks").mock(return_value=httpx.Response(403, json={}))
        assert await read_locks(app, None) is None
    finally:
        await app.aclose()


# --- categories ---------------------------------------------------------------------------------------


async def test_create_category_in_a_section(lab: respx.MockRouter) -> None:
    created = {
        "id": "00000000-0000-0ed3-0000-000000000c03",
        "type": "Category",
        "name": "mcp-w6-cat-new",
        "metadata": {"section": "Mandatory", "startIndex": -1, "endIndex": -1},
    }
    cats = categories(lab)
    after = {"items": FX["categories_spec"]["items"] + [created], "paging": {"count": 3}}
    cats.side_effect = [
        httpx.Response(200, json=FX["categories_spec"]),
        httpx.Response(200, json=FX["categories_spec"]),
        httpx.Response(200, json=after),
    ]
    post = lab.post(f"{CFG}/policy/accesspolicies/{ACP_ID}/categories").mock(
        return_value=httpx.Response(201, json={**created, "links": {}})
    )
    preview, done = await preview_apply(
        "fmc_create_category", {"policy": "mcp-test-acp", "name": "mcp-w6-cat-new", "section": "mandatory"}
    )
    assert preview["action"] == "Create category 'mcp-w6-cat-new' in 'mcp-test-acp' in the mandatory section"
    assert [c["name"] for c in preview["preview"]["categories_now"]] == ["mcp-w6-cat-corp", "mcp-w6-cat-web"]
    req = post.calls.last.request
    assert json.loads(req.content) == {"name": "mcp-w6-cat-new", "type": "Category"}
    assert req.url.params["section"] == "mandatory"
    assert done["result"]["category"] == {
        "name": "mcp-w6-cat-new",
        "section": "mandatory",
        "rules": "none",
        "id": created["id"],
    }


async def test_create_category_above_another_and_refusals(lab: respx.MockRouter) -> None:
    categories(lab)
    post = lab.post(f"{CFG}/policy/accesspolicies/{ACP_ID}/categories").mock(
        return_value=httpx.Response(201, json={"id": "c", "name": "mcp-w6-cat-x", "type": "Category"})
    )
    _, done = await preview_apply(
        "fmc_create_category",
        {"policy": "mcp-test-acp", "name": "mcp-w6-cat-x", "above_category": "MCP-W6-CAT-WEB"},
    )
    assert post.calls.last.request.url.params["aboveCategory"] == "mcp-w6-cat-web"  # FMC's spelling
    out = await preview_only(
        "fmc_create_category", {"policy": "mcp-test-acp", "name": "mcp-w6-cat-web", "above_category": "nope"}
    )
    assert out["status"] == "blocked"
    assert any("already has a category named" in b for b in out["blockers"])
    assert any("No category in 'mcp-test-acp' named 'nope'" in b for b in out["blockers"])
    out = await preview_only(
        "fmc_create_category", {"policy": "mcp-test-acp", "name": "x", "insert_before": 99}
    )
    assert out["blockers"] == ["Position 99 is beyond the last rule (7 rules)."]
    with pytest.raises(ToolError, match="Give one position"):
        await preview_only(
            "fmc_create_category",
            {"policy": "mcp-test-acp", "name": "x", "section": "default", "insert_after": 2},
        )
    assert post.call_count == 1


async def test_rename_category(lab: respx.MockRouter) -> None:
    categories(lab)
    cid = "00000000-0000-0ed3-0000-000000000c02"
    put = lab.put(f"{CFG}/policy/accesspolicies/{ACP_ID}/categories/{cid}").mock(
        side_effect=lambda r: httpx.Response(200, json=json.loads(r.content))
    )
    preview, done = await preview_apply(
        "fmc_rename_category",
        {"policy": "mcp-test-acp", "category": "mcp-w6-cat-web", "new_name": "mcp-w6-cat-www"},
    )
    assert preview["preview"]["changes"] == {"name": {"from": "mcp-w6-cat-web", "to": "mcp-w6-cat-www"}}
    body = json.loads(put.calls.last.request.content)
    assert body["id"] == cid and body["name"] == "mcp-w6-cat-www" and body["type"] == "Category"
    assert "metadata" not in body and "links" not in body
    assert done["result"]["category"]["name"] == "mcp-w6-cat-www"
    out = await preview_only(
        "fmc_rename_category", {"policy": "mcp-test-acp", "category": cid, "new_name": "mcp-w6-cat-corp"}
    )
    assert out["blockers"] == ["Policy 'mcp-test-acp' already has a category named 'mcp-w6-cat-corp'."]


def rules_in(category: str | None, *names: str) -> dict[str, Any]:
    data = copy.deepcopy(fixture("accessrules"))
    for r in data["items"]:
        if r["name"] in names:
            r["metadata"]["category"] = category
    return data


async def test_delete_category_shows_where_its_rules_went(lab: respx.MockRouter) -> None:
    categories(lab)
    before = rules_in("mcp-w6-cat-web", "mcp-test-allow-web", "mcp-test-ssh-admin")
    after = rules_in("--Undefined--", "mcp-test-allow-web")
    after["items"] = [r for r in after["items"] if r["name"] != "mcp-test-ssh-admin"]  # FMC dropped one
    rules = lab.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules")
    rules.side_effect = [httpx.Response(200, json=before)] * 2 + [httpx.Response(200, json=after)]
    cid = "00000000-0000-0ed3-0000-000000000c02"
    delete = lab.delete(f"{CFG}/policy/accesspolicies/{ACP_ID}/categories/{cid}").mock(
        return_value=httpx.Response(200, json={"id": cid})
    )
    preview, done = await preview_apply(
        "fmc_delete_category", {"policy": "mcp-test-acp", "category": "mcp-w6-cat-web"}
    )
    assert [r["name"] for r in preview["preview"]["rules_in_category"]] == [
        "mcp-test-allow-web",
        "mcp-test-ssh-admin",
    ]
    assert "stay in the policy" in preview["side_effects"][0]
    assert delete.call_count == 1
    assert done["result"]["rules_now"] == [
        {
            "index": 1,
            "name": "mcp-test-allow-web",
            "section": "default",
            "id": "00000000-0000-0ed3-0000-000268434437",
        }
    ]
    assert (
        done["result"]["rules_missing"] == ["mcp-test-ssh-admin"] and "re-create" in done["result"]["warning"]
    )


async def test_rule_into_category(lab: respx.MockRouter) -> None:
    categories(lab)
    rid = "00000000-0000-0ed3-0000-000268434440"
    moved = copy.deepcopy(next(r for r in fixture("accessrules")["items"] if r["id"] == rid))
    moved["metadata"].update(category="mcp-w6-cat-web", ruleIndex=3)
    lab.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules/{rid}").mock(
        return_value=httpx.Response(200, json=moved)
    )
    put = lab.put(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=httpx.Response(200, json={"items": [moved]})
    )
    preview, done = await preview_apply(
        "fmc_update_access_rule",
        {"policy": "mcp-test-acp", "rule": "mcp-test-block-app", "category": "mcp-w6-cat-web"},
    )
    assert preview["preview"]["move"]["into_category"]["rules"] == "1-2"
    assert preview["action"].endswith("(into category 'mcp-w6-cat-web')")
    req = put.calls.last.request
    assert dict(req.url.params) == {"bulk": "true", "category": "mcp-w6-cat-web"}
    assert json.loads(req.content)[0]["id"] == rid
    assert done["result"]["now_at"]["category"] == "mcp-w6-cat-web" and done["result"]["now_at"]["index"] == 3
    # a Mandatory category: the preview says the rule changes section
    out = await preview_only(
        "fmc_update_access_rule", {"policy": "mcp-test-acp", "rule": rid, "category": "mcp-w6-cat-corp"}
    )
    assert any("from the default section into the mandatory section" in s for s in out["side_effects"])
    out = await preview_only(
        "fmc_update_access_rule", {"policy": "mcp-test-acp", "rule": rid, "category": "nope"}
    )
    assert out["blockers"] == [
        "Policy 'mcp-test-acp' has no category 'nope'; create it first (fmc_create_category)."
    ]
    with pytest.raises(ToolError, match="either move_to or category"):
        await preview_only(
            "fmc_update_access_rule", {"policy": "mcp-test-acp", "rule": rid, "category": "x", "move_to": 1}
        )


async def test_create_rule_needs_an_existing_category(lab: respx.MockRouter) -> None:
    out = await preview_only(
        "fmc_create_access_rule",
        {"policy": "mcp-test-acp", "name": "mcp-w6-r", "action": "ALLOW", "category": "mcp-w6-nope"},
    )
    assert out["status"] == "blocked"
    assert out["blockers"] == [
        "Policy 'mcp-test-acp' has no category 'mcp-w6-nope'; create it first (fmc_create_category)."
    ]


# --- inheritance --------------------------------------------------------------------------------------


def child_and_parent(fmc: respx.MockRouter) -> None:
    acp_list(fmc, ACP, CHILD_ACP)
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=httpx.Response(200, json=fixture("accessrules"))
    )
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items(
            [
                {
                    "id": CHILD,
                    "policy": {"id": CHILD, "name": "mcp-w6-child-acp", "type": "AccessPolicy"},
                    "targets": [{"id": DEVICE, "name": "mcp-ftd1", "type": "Device"}],
                }
            ]
        )
    )


async def test_set_base_policy(fmc: respx.MockRouter) -> None:
    child_and_parent(fmc)
    no_base(fmc, ACP_ID)
    setting = fmc.get(f"{CFG}/policy/accesspolicies/{CHILD}/inheritancesettings").mock(
        return_value=httpx.Response(200, json=FX["inheritance_none_live"])
    )
    path = f"{CFG}/policy/accesspolicies/{CHILD}/inheritancesettings/{CHILD}"
    put = fmc.put(path).mock(return_value=httpx.Response(200, json=FX["inheritance_with_base_spec"]))
    fmc.get(path).mock(return_value=httpx.Response(200, json=FX["inheritance_with_base_spec"]))
    preview, done = await preview_apply(
        "fmc_set_base_policy", {"policy": "mcp-w6-child-acp", "base": "mcp-test-acp"}
    )
    p = preview["preview"]
    assert preview["action"] == "Set the base policy of 'mcp-w6-child-acp' to 'mcp-test-acp'"
    assert p["chain"] == {"from": ["mcp-w6-child-acp"], "to": ["mcp-w6-child-acp", "mcp-test-acp"]}
    assert (
        p["inherited_from_base"]["default"]["rules"] == 7
        and p["inherited_from_base"]["default_action"] == "BLOCK"
    )
    assert p["assigned_to"] == ["mcp-ftd1"] and preview["blast_radius"] == 1
    assert "Mandatory rules first" in preview["side_effects"][0]
    assert json.loads(put.calls.last.request.content) == {
        "type": "AccessPolicyInheritanceSetting",
        "id": CHILD,
        "basePolicy": {"id": ACP_ID, "type": "AccessPolicy"},
    }
    assert done["result"]["base_policy"] == "mcp-test-acp" and "warning" not in done["result"]
    assert setting.call_count >= 2  # preview + confirm re-read the chain


async def test_remove_base_policy_and_say_when_fmc_keeps_it(fmc: respx.MockRouter) -> None:
    child_and_parent(fmc)
    no_base(fmc, ACP_ID)
    with_base(fmc, CHILD, ACP_ID)
    path = f"{CFG}/policy/accesspolicies/{CHILD}/inheritancesettings/{CHILD}"
    put = fmc.put(path).mock(return_value=httpx.Response(200, json=FX["inheritance_with_base_spec"]))
    fmc.get(path).mock(return_value=httpx.Response(200, json=FX["inheritance_with_base_spec"]))
    preview, done = await preview_apply("fmc_set_base_policy", {"policy": CHILD, "base": "none"})
    assert preview["action"] == "Remove the base policy of 'mcp-w6-child-acp'"
    assert preview["preview"]["base"] == {"from": "mcp-test-acp", "to": None}
    assert "stops getting 'mcp-test-acp'" in preview["side_effects"][0]
    assert json.loads(put.calls.last.request.content) == {
        "type": "AccessPolicyInheritanceSetting",
        "id": CHILD,
    }
    assert done["result"]["base_policy"] == "mcp-test-acp" and "not none" in done["result"]["warning"]


async def test_base_policy_refusals(fmc: respx.MockRouter) -> None:
    child_and_parent(fmc)
    with_base(fmc, ACP_ID, CHILD)  # the parent already inherits from the child
    no_base(fmc, CHILD)
    out = await preview_only("fmc_set_base_policy", {"policy": "mcp-w6-child-acp", "base": "mcp-test-acp"})
    assert out["status"] == "blocked"
    assert out["blockers"] == [
        "'mcp-test-acp' already inherits from 'mcp-w6-child-acp' (mcp-test-acp -> mcp-w6-child-acp): "
        "that would be a loop."
    ]
    out = await preview_only(
        "fmc_set_base_policy", {"policy": "mcp-w6-child-acp", "base": "mcp-w6-child-acp"}
    )
    assert "A policy can't be its own base." in out["blockers"]
    out = await preview_only("fmc_set_base_policy", {"policy": "mcp-w6-child-acp", "base": "none"})
    assert out["blockers"] == ["Nothing to change: the policy has no base."]


async def test_create_access_policy_with_a_base(fmc: respx.MockRouter) -> None:
    acp_list(fmc, ACP)
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=httpx.Response(200, json=fixture("accessrules"))
    )
    post = fmc.post(f"{CFG}/policy/accesspolicies").mock(
        return_value=httpx.Response(201, json={**CHILD_ACP, "links": {}})
    )
    path = f"{CFG}/policy/accesspolicies/{CHILD}/inheritancesettings/{CHILD}"
    put = fmc.put(path).mock(return_value=httpx.Response(200, json=FX["inheritance_with_base_spec"]))
    fmc.get(path).mock(return_value=httpx.Response(200, json=FX["inheritance_with_base_spec"]))
    args = {"name": "mcp-w6-child-acp", "base_policy": "mcp-test-acp"}
    preview, done = await preview_apply("fmc_create_access_policy", args)
    assert preview["action"] == "Create access policy 'mcp-w6-child-acp' with base 'mcp-test-acp'"
    assert preview["preview"]["inherited_from_base"]["default"]["rules"] == 7
    assert json.loads(post.calls.last.request.content) == {
        "name": "mcp-w6-child-acp",
        "type": "AccessPolicy",
        "defaultAction": {"action": "BLOCK"},
    }
    assert json.loads(put.calls.last.request.content)["basePolicy"] == {"id": ACP_ID, "type": "AccessPolicy"}
    assert done["result"]["policy"]["id"] == CHILD and done["result"]["base_policy"] == "mcp-test-acp"
    # FMC refuses the base after the create: the policy exists, the result says how to finish
    put.mock(
        return_value=httpx.Response(422, json={"error": {"messages": [{"description": "Invalid base"}]}})
    )
    _, done = await preview_apply("fmc_create_access_policy", {**args, "name": "mcp-w6-child2-acp"})
    assert done["result"]["policy"]["id"] == CHILD
    assert "fmc_set_base_policy(policy='mcp-w6-child2-acp', base='mcp-test-acp')" in done["result"]["warning"]
    out = await preview_only("fmc_create_access_policy", {"name": "mcp-w6-x", "base_policy": "mcp-nope"})
    assert out["status"] == "blocked" and "No access policy named 'mcp-nope'" in out["blockers"][0]


async def test_create_access_policy_without_a_base_is_unchanged(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=empty())
    fmc.post(f"{CFG}/policy/accesspolicies").mock(
        return_value=httpx.Response(201, json={**CHILD_ACP, "links": {}})
    )
    put = fmc.put(f"{CFG}/policy/accesspolicies/{CHILD}/inheritancesettings/{CHILD}")
    preview, done = await preview_apply("fmc_create_access_policy", {"name": "mcp-w6-child-acp"})
    assert preview["action"] == "Create access policy 'mcp-w6-child-acp'" and "side_effects" not in preview
    assert done["result"]["id"] == CHILD and put.call_count == 0


# --- locks --------------------------------------------------------------------------------------------


async def test_lock_and_unlock(lab: respx.MockRouter) -> None:
    post = lab.post(f"{CFG}/policy/operational/policylocks").mock(
        return_value=httpx.Response(200, json=FX["policylock_post_response_spec"])
    )
    preview, done = await preview_apply("fmc_policy_lock", {"policy": "mcp-test-acp", "action": "lock"})
    assert (
        preview["preview"]["lock_now"] == {"status": "UNLOCKED"}
        and preview["preview"]["api_user"] == "apiuser"
    )
    assert json.loads(post.calls.last.request.content) == {
        "policies": [{"lock": True, "policy": {"id": ACP_ID, "type": "AccessPolicy"}}]
    }
    assert done["result"]["locks"] == [
        {"policy": "mcp-test-acp", "policy_id": ACP_ID, "status": "LOCKED", "locked_by": "apiuser"}
    ]
    out = await preview_only("fmc_policy_lock", {"policy": "mcp-test-acp", "action": "unlock"})
    assert out["blockers"] == ["Nothing to change: 'mcp-test-acp' isn't locked."]


async def test_unlock_someone_elses_lock_needs_break_lock(lab: respx.MockRouter) -> None:
    lab.get(f"{CFG}/policy/operational/policylocks").mock(
        return_value=httpx.Response(200, json=FX["policylocks_locked_spec"])
    )
    post = lab.post(f"{CFG}/policy/operational/policylocks").mock(return_value=httpx.Response(200, json={}))
    out = await preview_only("fmc_policy_lock", {"policy": "mcp-test-acp", "action": "unlock"})
    assert out["status"] == "blocked" and "locked by alice, not by apiuser" in out["blockers"][0]
    out = await preview_only("fmc_policy_lock", {"policy": "mcp-test-acp", "action": "lock"})
    assert "they must unlock it first" in out["blockers"][0]
    preview, _ = await preview_apply(
        "fmc_policy_lock", {"policy": "mcp-test-acp", "action": "unlock", "break_lock": True}
    )
    assert preview["preview"]["lock_now"] == {"status": "LOCKED", "locked_by": "alice"}
    assert "Takes the lock away from alice" in preview["side_effects"][0]
    assert json.loads(post.calls.last.request.content)["policies"][0]["lock"] is False


async def test_lock_with_parents(fmc: respx.MockRouter) -> None:
    child_and_parent(fmc)
    with_base(fmc, CHILD, ACP_ID)
    no_base(fmc, ACP_ID)
    post = fmc.post(f"{CFG}/policy/operational/policylocks").mock(return_value=httpx.Response(200, json={}))
    preview, _ = await preview_apply(
        "fmc_policy_lock", {"policy": "mcp-w6-child-acp", "action": "lock", "include_parents": True}
    )
    assert preview["action"] == "Lock access policy 'mcp-w6-child-acp' and its base policies (mcp-test-acp)"
    entry = json.loads(post.calls.last.request.content)["policies"][0]
    assert entry == {
        "lock": True,
        "policy": {"id": CHILD, "type": "AccessPolicy"},
        "lockParentsInHierarchy": True,
    }


async def test_acp_write_previews_name_the_lock_holder(lab: respx.MockRouter) -> None:
    """Another user's lock blocks every access policy write preview with their name (FMC would refuse the
    write with a bare error); the API user's own lock is a note."""
    acp_list(lab, locked_acp("alice"))
    args = {"policy": "mcp-test-acp", "name": "mcp-w6-r", "action": "ALLOW"}
    out = await preview_only("fmc_create_access_rule", args)
    assert out["status"] == "blocked"
    assert "Access policy 'mcp-test-acp' is locked by alice." in out["blockers"][-1]
    out = await preview_only("fmc_delete_access_rule", {"policy": "mcp-test-acp", "rule": "1"})
    assert out["status"] == "blocked" and "locked by alice" in out["blockers"][0]
    acp_list(lab, locked_acp("APIUSER"))
    out = await preview_only("fmc_create_access_rule", args)
    assert out["status"] == "preview" and "locked by you" in out["preview"]["policy_lock"]


async def test_lock_holder_from_the_lock_list_when_the_policy_names_nobody(lab: respx.MockRouter) -> None:
    acp_list(lab, locked_acp(None))
    lab.get(f"{CFG}/policy/operational/policylocks").mock(
        return_value=httpx.Response(200, json=FX["policylocks_locked_spec"])
    )
    out = await preview_only("fmc_delete_access_rule", {"policy": "mcp-test-acp", "rule": "1"})
    assert "locked by alice" in out["blockers"][0]


async def test_unlocked_policy_costs_no_lock_read(lab: respx.MockRouter) -> None:
    locks = lab.get(f"{CFG}/policy/operational/policylocks").mock(return_value=items([{}]))
    out = await preview_only("fmc_delete_access_rule", {"policy": "mcp-test-acp", "rule": "1"})
    assert out["status"] == "preview" and "policy_lock" not in out["preview"]
    assert locks.call_count == 0


# --- reads --------------------------------------------------------------------------------------------


async def test_get_access_policy_shows_base_lock_and_categories(fmc: respx.MockRouter) -> None:
    child_and_parent(fmc)
    fmc.get(f"{CFG}/policy/accesspolicies/{CHILD}/accessrules").mock(return_value=empty())
    with_base(fmc, CHILD, ACP_ID)
    with_base(fmc, ACP_ID, "00000000-0000-0ed3-0000-0000000000aa")  # a grandparent the list doesn't name
    no_base(fmc, "00000000-0000-0ed3-0000-0000000000aa")
    categories(fmc, CHILD)
    data = await call_tool(
        create_server(make_settings()), "fmc_get_access_policy", {"policy": "mcp-w6-child-acp"}
    )
    assert data["parent_policy"] == "mcp-test-acp"
    assert data["base_chain"] == ["mcp-test-acp", "00000000-0000-0ed3-0000-0000000000aa"]
    assert data["lock"] == {"status": "UNLOCKED"}
    assert [c["name"] for c in data["categories"]] == ["mcp-w6-cat-corp", "mcp-w6-cat-web"]


async def test_get_access_policy_without_structure(lab: respx.MockRouter) -> None:
    data = await call_tool(
        create_server(make_settings()), "fmc_get_access_policy", {"policy": "mcp-test-acp"}
    )
    assert data["lock"] == {"status": "UNLOCKED"}
    assert "parent_policy" not in data and "base_chain" not in data and "categories" not in data


def pending(fmc: respx.MockRouter, rows: list[dict[str, Any]], acp: dict[str, Any] | None = None) -> None:
    device = {
        "id": DEVICE,
        "name": "mcp-ftd1",
        "type": "Device",
        "accessPolicy": acp or {"id": CHILD, "name": "mcp-w6-child-acp", "type": "AccessPolicy"},
    }
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([device]))
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([{"device": {"id": DEVICE}}]))
    fmc.get(f"{CFG}/deployment/deployabledevices/{DEVICE}/pendingchanges").mock(return_value=items(rows))


async def test_pending_changes_name_a_locked_base_policy(fmc: respx.MockRouter) -> None:
    """The live proof's shape: mcp-ftd1 runs a child policy whose base is locked by someone else."""
    pending(
        fmc,
        [
            {"entityName": "mcp-test-acp", "entityType": "NGFWAccessControlPolicy", "action": "UPDATE"},
            {"entityName": "mcp-w6-tr-now", "entityType": "TimeRange", "action": "ADD"},
        ],
    )
    fmc.get(f"{CFG}/policy/operational/policylocks").mock(
        return_value=httpx.Response(200, json=FX["policylocks_locked_spec"])
    )
    with_base(fmc, CHILD, ACP_ID)
    no_base(fmc, ACP_ID)
    data = await call_tool(
        create_server(make_settings()),
        "fmc_pending_changes",
        {"device": "mcp-ftd1", "response_format": "json"},
    )
    rows = {r["entity"]: r for r in data["results"]}
    assert rows["mcp-test-acp"]["locked_by"] == "alice" and "locked_by" not in rows["mcp-w6-tr-now"]
    assert data["policy_locks"] == [
        {
            "policy": "mcp-test-acp",
            "status": "LOCKED",
            "locked_by": "alice",
            "why": "a base policy of the device's access policy 'mcp-w6-child-acp'",
        }
    ]
    assert "locked" in data["note"]


async def test_pending_changes_quiet_when_nothing_is_locked(fmc: respx.MockRouter) -> None:
    pending(
        fmc, [{"entityName": "mcp-test-acp", "entityType": "NGFWAccessControlPolicy", "action": "UPDATE"}]
    )
    chain = with_base(fmc, CHILD, ACP_ID)
    data = await call_tool(
        create_server(make_settings()),
        "fmc_pending_changes",
        {"device": "mcp-ftd1", "response_format": "json"},
    )
    assert "policy_locks" not in data and "locked_by" not in data["results"][0]
    assert chain.call_count == 0  # nothing locked: no base chain read

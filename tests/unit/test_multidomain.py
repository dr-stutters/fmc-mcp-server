"""F19 multi-domain: domain tree, the domain in previews, inherited objects/policies blocked below their
owner domain."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, CHILD, DOMAIN, items, make_settings

CHILD_CFG = f"/api/fmc_config/v1/domain/{CHILD}"
GLOBAL_REF = {"id": DOMAIN, "name": "Global", "type": "Domain"}
CHILD_REF = {"id": CHILD, "name": "Branch", "type": "Domain"}
HOST = {
    "id": "00505686-0000-0ed3-0000-000000000001",
    "name": "h1",
    "type": "Host",
    "value": "10.0.0.1",
    "metadata": {"domain": GLOBAL_REF},
}


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


async def test_domain_tree_with_devices(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(
        return_value=items([{"id": "d1", "name": "ftd1", "metadata": {"domain": CHILD_REF}}])
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_list_domains", {"response_format": "json"})
    rows = {r["name"]: r for r in out["results"]}
    assert rows["Global"]["leaf"] is False and rows["Global"]["default"] is True
    assert rows["Global"].get("devices") is None
    assert rows["Global/Branch"]["leaf"] is True and rows["Global/Branch"]["devices"] == ["ftd1"]
    assert rows["Global/Branch"]["parent_uuid"] == DOMAIN


async def test_inherited_object_is_blocked_in_child_domain(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CHILD_CFG}/object/hosts").mock(return_value=items([HOST]))
    fmc.get(f"{CHILD_CFG}/object/operational/usage").mock(return_value=items([]))
    put = fmc.put(f"{CHILD_CFG}/object/hosts/{HOST['id']}")
    async with Client(server()) as c:
        out = await run(
            c, "fmc_update_object", {"object": "h1", "type": "host", "value": "10.0.0.9", "domain": "Branch"}
        )
    assert out["status"] == "blocked", out
    assert out["preview"]["domain"] == "Global/Branch"
    assert "defined in domain 'Global'" in out["blockers"][0] and "domain='Global'" in out["blockers"][0]
    assert not put.called


async def test_owner_domain_edit_shows_domain(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([HOST]))
    fmc.get(f"{CFG}/object/operational/usage").mock(return_value=items([]))
    fmc.put(f"{CFG}/object/hosts/{HOST['id']}").mock(return_value=httpx.Response(200, json=HOST))
    async with Client(server()) as c:
        out = await run(c, "fmc_update_object", {"object": "h1", "type": "host", "value": "10.0.0.9"})
    assert out["status"] == "preview" and out["preview"]["domain"] == "Global"


async def test_device_paths_go_to_the_owning_leaf_domain(fmc: respx.MockRouter) -> None:
    from fmc_mcp.client import FmcApp

    dev_id = "2c11eaca-c7e3-11f1-a7ce-a8b537b1b4bb"
    lookup = fmc.get(f"{CFG}/devices/devicerecords/{dev_id}").mock(
        return_value=httpx.Response(200, json={"id": dev_id, "metadata": {"domain": CHILD_REF}})
    )
    app = FmcApp(make_settings())
    try:
        await app.ensure_login()
        sub = f"devices/devicerecords/{dev_id}/routing/ipv4staticroutes"
        assert await app.config_path(sub) == f"{CHILD_CFG}/{sub}"
        assert await app.config_path(sub) == f"{CHILD_CFG}/{sub}"  # cached
        assert lookup.call_count == 1
        # explicitly in the leaf: unchanged; collections and other paths: unchanged
        assert await app.config_path(sub, "Branch") == f"{CHILD_CFG}/{sub}"
        assert await app.config_path("devices/devicerecords") == f"{CFG}/devices/devicerecords"
        assert await app.config_path("object/hosts") == f"{CFG}/object/hosts"
    finally:
        await app.aclose()


def test_is_below_uses_whole_path_segments() -> None:
    from fmc_mcp.client import FmcApp

    app = FmcApp(make_settings())
    app.domains = [
        {"name": "Global", "uuid": DOMAIN},
        {"name": "Global/A", "uuid": "a" * 8 + "-0000-0000-0000-000000000000"},
        {"name": "Global/AB", "uuid": "b" * 8 + "-0000-0000-0000-000000000000"},
    ]
    a, ab = app.domains[1]["uuid"], app.domains[2]["uuid"]
    assert app._is_below(ab, DOMAIN) and app._is_below(a, DOMAIN)
    assert not app._is_below(ab, a) and not app._is_below(DOMAIN, a)


async def test_listing_teaches_device_domains_without_lookups(fmc: respx.MockRouter) -> None:
    from fmc_mcp.client import FmcApp

    dev_id = "2c11eaca-c7e3-11f1-a7ce-a8b537b1b4bb"
    fmc.get(f"{CFG}/devices/devicerecords").mock(
        return_value=items([{"id": dev_id, "name": "ftd1", "metadata": {"domain": CHILD_REF}}])
    )
    lookup = fmc.get(f"{CFG}/devices/devicerecords/{dev_id}")
    app = FmcApp(make_settings())
    try:
        await app.ensure_login()
        await app.all(await app.config_path("devices/devicerecords"))
        sub = f"devices/devicerecords/{dev_id}/physicalinterfaces"
        assert await app.config_path(sub) == f"{CHILD_CFG}/{sub}"
        assert not lookup.called
        app.forget_devices()
        assert dev_id not in app.device_domains
    finally:
        await app.aclose()


# --- policy assignments inherited from an ancestor domain -------------------------------------------
# FMC lists in a domain only the assignments of policies that domain owns (FMC 10.0.1, read in the lab:
# Global/mcp-test-leaf's list lacked mcp-ftd1's Global access policy and mcp-ftd-identity's Global NAT
# policy, which only Global's list shows). fmc_assign_policy's preview then said from=None.

LEAF_DEV = {
    "id": "2c0f0000-0000-4000-8000-000000000001",
    "name": "ftd-leaf",
    "type": "Device",
    "metadata": {"domain": CHILD_REF},
}
SIBLING = {"id": "2c0f0000-0000-4000-8000-000000000002", "name": "ftd-other-leaf", "type": "Device"}
GLOBAL_ACP = {"id": "00000000-0000-0ed3-0000-000000000001", "name": "global-acp", "type": "AccessPolicy"}
LEAF_ACP = {"id": "00000000-0000-0ed3-0000-000000000002", "name": "leaf-acp", "type": "AccessPolicy"}
GLOBAL_NAT = {"id": "00000000-0000-0ed3-0000-000000000003", "name": "global-nat", "type": "FTDNatPolicy"}
LEAF_NAT = {"id": "00000000-0000-0ed3-0000-000000000004", "name": "leaf-nat", "type": "FTDNatPolicy"}


def assignment(policy: dict[str, Any], *targets: dict[str, Any]) -> dict[str, Any]:
    return {"id": policy["id"], "type": "PolicyAssignment", "name": policy["name"], "policy": policy,
            "targets": [{k: t[k] for k in ("id", "type", "name")} for t in targets]}  # fmt: skip


def leaf_mocks(fmc: respx.MockRouter, device: dict[str, Any] = LEAF_DEV) -> None:
    fmc.get(f"{CHILD_CFG}/devices/devicerecords").mock(return_value=items([device]))
    fmc.get(f"{CHILD_CFG}/policy/accesspolicies").mock(return_value=items([GLOBAL_ACP, LEAF_ACP]))
    fmc.get(f"{CHILD_CFG}/policy/ftdnatpolicies").mock(return_value=items([GLOBAL_NAT, LEAF_NAT]))
    fmc.get(f"{CHILD_CFG}/assignment/policyassignments").mock(return_value=items([]))


async def test_assign_policy_preview_names_a_policy_inherited_from_global(fmc: respx.MockRouter) -> None:
    leaf_mocks(fmc)  # no accessPolicy on the device record: only the lists can say what it runs
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items([assignment(GLOBAL_ACP, LEAF_DEV, SIBLING)])
    )
    post = fmc.post(f"{CHILD_CFG}/assignment/policyassignments").mock(
        return_value=httpx.Response(201, json={})
    )
    args = {"kind": "access", "policy": "leaf-acp", "devices": ["ftd-leaf"], "domain": "Branch"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_assign_policy", args)
        assert preview["status"] == "preview", preview
        assert preview["preview"]["changes"] == [
            {"device": "ftd-leaf", "from": "global-acp", "to": "leaf-acp"}
        ]
        await run(c, "fmc_assign_policy", {**args, "confirm": preview["confirm"]})
        listed = await run(
            c,
            "fmc_list_policy_assignments",
            {"domain": "Branch", "device": "ftd-leaf", "response_format": "json"},
        )
    body = json.loads(post.calls.last.request.content)
    assert body["policy"]["id"] == LEAF_ACP["id"] and body["targets"] == [
        {"id": LEAF_DEV["id"], "type": "Device"}
    ]
    assert [(r["policy"], r.get("domain")) for r in listed["results"]] == [("global-acp", "Global")]


async def test_assign_inherited_policy_keeps_its_other_targets(fmc: respx.MockRouter) -> None:
    leaf_mocks(fmc)
    fmc.get(f"{CHILD_CFG}/assignment/policyassignments").mock(
        return_value=items([assignment(LEAF_NAT, LEAF_DEV)])
    )
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=items([assignment(GLOBAL_NAT, SIBLING)]))
    put = fmc.put(f"{CHILD_CFG}/assignment/policyassignments/{GLOBAL_NAT['id']}").mock(
        return_value=httpx.Response(200, json={})
    )
    args = {"kind": "nat", "policy": "global-nat", "devices": ["ftd-leaf"], "domain": "Branch"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_assign_policy", args)
        assert preview["preview"]["changes"] == [
            {"device": "ftd-leaf", "from": "leaf-nat", "to": "global-nat"}
        ]
        assert preview["preview"]["policy_domain"] == "Global"
        assert any("keeps its 1 other target" in s for s in preview["side_effects"]), preview
        await run(c, "fmc_assign_policy", {**args, "confirm": preview["confirm"]})
    body = json.loads(put.calls.last.request.content)
    assert body["id"] == GLOBAL_NAT["id"]
    assert [t["id"] for t in body["targets"]] == [SIBLING["id"], LEAF_DEV["id"]]


async def test_unreadable_ancestor_falls_back_to_the_device_record(fmc: respx.MockRouter) -> None:
    leaf_mocks(fmc, {**LEAF_DEV, "accessPolicy": GLOBAL_ACP})
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=httpx.Response(403, json={}))
    async with Client(server()) as c:
        preview = await run(
            c,
            "fmc_assign_policy",
            {"kind": "access", "policy": "leaf-acp", "devices": ["ftd-leaf"], "domain": "Branch"},
        )
    assert preview["preview"]["changes"] == [{"device": "ftd-leaf", "from": "global-acp", "to": "leaf-acp"}]
    assert "policy_domain" not in preview["preview"]


async def test_domain_ancestors_nearest_first(fmc: respx.MockRouter) -> None:
    from fmc_mcp.client import FmcApp

    app = FmcApp(make_settings())
    mid, leaf = "a" * 8 + "-0000-0000-0000-000000000000", "b" * 8 + "-0000-0000-0000-000000000000"
    try:
        await app.ensure_login()
        app.domains = [
            {"name": "Global", "uuid": DOMAIN},
            {"name": "Global/A", "uuid": mid},
            {"name": "Global/A/B", "uuid": leaf},
        ]
        assert await app.domain_ancestors(leaf) == [mid, DOMAIN]
        assert await app.domain_ancestors("Global/A") == [DOMAIN]
        assert await app.domain_ancestors("Global") == []
    finally:
        await app.aclose()


async def test_nat_policy_of_a_leaf_device_inherited_from_global(fmc: respx.MockRouter) -> None:
    """live-1b R1: fmc_find_address(device=...) found no NAT policy on a leaf device running a Global one."""
    from fmc_mcp.client import FmcApp
    from fmc_mcp.tools.policies import nat_policy_of

    fmc.get(f"{CHILD_CFG}/assignment/policyassignments").mock(
        return_value=items([assignment(LEAF_ACP, LEAF_DEV)])
    )
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items([assignment(GLOBAL_NAT, LEAF_DEV)])
    )
    app = FmcApp(make_settings())
    try:
        assert await nat_policy_of(app, LEAF_DEV["id"], "Branch") == GLOBAL_NAT["id"]
        assert await nat_policy_of(app, SIBLING["id"], "Branch") is None
    finally:
        await app.aclose()


# --- unused objects in a child domain (#197) ---------------------------------------------------------
# A child domain sees Global's objects as readOnly with reason DOMAIN, FMC's built-ins included; only
# Global's own listing says SYSTEM (recorded in the lab, fixture unused_inherited_builtins.json).

UNUSED_TYPES = (
    "hosts",
    "networks",
    "ranges",
    "fqdns",
    "networkgroups",
    "portobjectgroups",
    "urls",
    "urlgroups",
)


def unused_mocks(fmc: respx.MockRouter) -> Any:
    from .conftest import empty, fixture

    rec = fixture("unused_inherited_builtins")
    leaf_own = {
        "id": "00000000-0000-0ed3-0000-000000000099",
        "name": "leaf-unused",
        "type": "ProtocolPortObject",
        "protocol": "TCP",
        "port": "8081",
        "metadata": {"domain": CHILD_REF},
    }
    fmc.get(f"{CHILD_CFG}/object/protocolportobjects", params={"filter": "unusedOnly:true"}).mock(
        return_value=items([*rec["leaf_unused"], leaf_own])
    )
    for path in UNUSED_TYPES:
        fmc.get(f"{CHILD_CFG}/object/{path}", params={"filter": "unusedOnly:true"}).mock(return_value=empty())
    return rec


async def test_unused_objects_in_child_domain_skip_inherited_builtins(fmc: respx.MockRouter) -> None:
    rec = unused_mocks(fmc)
    owner = fmc.get(f"{CFG}/object/protocolportobjects").mock(return_value=items(rec["global_list"]))
    async with Client(server()) as c:
        out = await run(c, "fmc_unused_objects", {"domain": "Branch", "response_format": "json"})
    names = [r["name"] for r in out["results"]]
    assert names == ["mcp-test-udp-5000s", "leaf-unused"], names  # AOL and Bittorrent are FMC built-ins
    assert owner.call_count == 1  # one read of the owner's list per type, only for types with inherited rows
    assert "note" not in out


async def test_unused_objects_owner_unreadable_keeps_rows_with_a_note(fmc: respx.MockRouter) -> None:
    unused_mocks(fmc)
    fmc.get(f"{CFG}/object/protocolportobjects").mock(return_value=httpx.Response(403, json={"error": "no"}))
    async with Client(server()) as c:
        out = await run(c, "fmc_unused_objects", {"domain": "Branch", "response_format": "json"})
    assert len(out["results"]) == 4
    assert "Couldn't read Global" in out["note"], out

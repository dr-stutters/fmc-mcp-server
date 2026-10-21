"""F19 multi-domain: domain tree, the domain in previews, inherited objects/policies blocked below their
owner domain."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, CHILD, DOMAIN, fixture, items, make_settings

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


# --- FMC built-ins seen from a child domain (#197) ---------------------------------------------------
# A child domain sees Global's objects as readOnly with reason DOMAIN, FMC's built-ins included; only
# Global's own listing says SYSTEM. The built-ins keep FMC's fixed ids; objects FMC creates get ...-0ed3-...
# (recorded in the lab: unused_inherited_builtins.json, leaf_inherited_objects.json).

LEAF_VIEW: dict[str, Any] = fixture("leaf_inherited_objects")
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


def leaf_rows() -> dict[str, dict[str, Any]]:
    rows = LEAF_VIEW["networkaddresses"]["items"] + LEAF_VIEW["networkgroups"]["items"]
    return {str(o["name"]): o for o in rows}


def test_is_system_tells_inherited_builtins_from_globals_own_objects() -> None:
    from fmc_mcp.tools.common import is_system

    rows = leaf_rows()
    rec = fixture("unused_inherited_builtins")
    for o in [*rec["leaf_unused"], *rows.values()]:
        assert (o["metadata"].get("readOnly") or {}).get("reason") in (None, "DOMAIN"), o["name"]
    builtins = {"any-ipv4", "any-ipv6", "IPv4-Private-10.0.0.0-8", "any", "IPv4-Private-All-RFC1918"}
    assert all(is_system(rows[n]) for n in builtins)
    assert [is_system(o) for o in rec["leaf_unused"]] == [True, True, False]  # AOL, Bittorrent, a Global port
    for name in ("mcp-test-db", "mcp-test-servers", "mcp-test-range", "mcp-fw-ha-inside-net"):
        assert not is_system(rows[name]), name  # Global's own objects and the leaf's
    assert all(is_system(o) for o in rec["global_list"][:2])  # Global itself says SYSTEM
    # Only network and port objects are built-ins: an inherited zone (FMC gives zones v1 UUIDs) is not.
    zone = {
        "id": "20d5bbce-c9d6-11f1-8e93-9a786f180443",
        "name": "mcp-test-identity-inside",
        "type": "SecurityZone",
        "metadata": {"readOnly": {"state": True, "reason": "DOMAIN"}, "domain": GLOBAL_REF},
    }
    assert not is_system(zone)


def unused_mocks(fmc: respx.MockRouter) -> Any:
    from .conftest import empty

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
    for path in ("networkgroups",):  # the filter lists no network group: also the full list
        fmc.get(f"{CHILD_CFG}/object/{path}").mock(return_value=empty())
    return rec


async def test_unused_objects_in_child_domain_skip_inherited_builtins(fmc: respx.MockRouter) -> None:
    unused_mocks(fmc)
    owner = fmc.get(f"{CFG}/object/protocolportobjects").mock(return_value=httpx.Response(403, json={}))
    async with Client(server()) as c:
        out = await run(c, "fmc_unused_objects", {"domain": "Branch", "response_format": "json"})
    rows = {r["name"]: r for r in out["results"]}
    assert list(rows) == ["mcp-test-udp-5000s", "leaf-unused"], rows  # AOL and Bittorrent are FMC built-ins
    assert rows["mcp-test-udp-5000s"]["inherited_from"] == "Global"
    assert "inherited_from" not in rows["leaf-unused"]
    assert not owner.called  # decided from the objects themselves: no read of Global's lists
    assert "note" not in out


async def test_list_objects_in_child_domain_marks_builtins_system(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CHILD_CFG}/object/networkgroups").mock(
        return_value=httpx.Response(200, json=LEAF_VIEW["networkgroups"])
    )
    async with Client(server()) as c:
        every = await run(
            c, "fmc_list_objects", {"type": "network_group", "domain": "Branch", "response_format": "json"}
        )
        user = await run(
            c,
            "fmc_list_objects",
            {"type": "network_group", "include_system": False, "domain": "Branch", "response_format": "json"},
        )
    rows = {r["name"]: r for r in every["results"]}
    assert rows["any"]["system"] is True and "inherited_from" not in rows["any"]
    assert rows["IPv4-Private-All-RFC1918"]["system"] is True
    assert rows["mcp-test-servers"]["inherited_from"] == "Global" and "system" not in rows["mcp-test-servers"]
    assert [r["name"] for r in user["results"]] == ["mcp-test-servers"]


async def test_find_address_in_child_domain_leaves_out_builtins(lab: respx.MockRouter) -> None:
    from fmc_mcp._core.testing import call_tool

    from .conftest import as_leaf

    as_leaf(lab)
    for name in ("networkaddresses", "networkgroups"):
        lab.get(f"{CFG}/object/{name}").mock(return_value=httpx.Response(200, json=LEAF_VIEW[name]))
    args = {"address": "10.10.20.5", "areas": ["objects"], "response_format": "json"}
    srv = create_server(make_settings())
    out = await call_tool(srv, "fmc_find_address", args)
    where = [r["where"] for r in out["results"] if r["area"] == "objects"]
    assert where[0] == "Host mcp-test-db" and "Network mcp-test-app-net" in where
    assert not [w for w in where if "IPv4-Private" in w], where  # FMC built-ins, as in Global
    broad = await call_tool(srv, "fmc_find_address", {**args, "include_broad": True})
    assert "Network IPv4-Private-10.0.0.0-8" in [r["where"] for r in broad["results"]]


def test_hygiene_duplicates_in_child_domain_skip_builtins() -> None:
    from typing import cast

    from fmc_mcp.catalog import Catalog
    from fmc_mcp.client import FmcApp
    from fmc_mcp.tools.hygiene import duplicate_objects

    objs = {str(o["id"]): o for o in leaf_rows().values()}
    ten = {"id": "00000000-0000-0ed3-0000-000000000098", "name": "lab-10", "type": "Network"}
    objs[ten["id"]] = {**ten, "value": "10.0.0.0/8", "metadata": {"domain": CHILD_REF}}
    cat = Catalog(cast(FmcApp, None), "Branch", objects=objs)
    found = duplicate_objects(cat, [])
    assert not found, found  # IPv4-Private-10.0.0.0-8 is FMC's: not a duplicate to delete


def test_bundle_in_child_domain_names_globals_objects_only() -> None:
    from fmc_mcp.tools.bundle import object_entry

    rows, here = leaf_rows(), "Global/mcp-test-leaf"  # what app.domain_name says for the leaf
    assert object_entry(rows["mcp-test-db"], here)["domain"] == "Global"
    assert "domain" not in object_entry(rows["IPv4-Private-10.0.0.0-8"], here)  # as in Global's export
    # The leaf's own object: FMC's metadata calls the leaf 'Global \\ mcp-test-leaf'.
    assert rows["mcp-fw-ha-inside-net"]["metadata"]["domain"]["name"] == "Global \\ mcp-test-leaf"
    assert "domain" not in object_entry(rows["mcp-fw-ha-inside-net"], here)


def test_bundle_entry_does_not_depend_on_the_exporting_users_role() -> None:
    # A read-only API user sees every object as readOnly reason RBAC (bundle_acp.json, recorded with such a
    # user): the bundle must still name Global's own objects and leave out FMC's built-ins, as for a writer.
    import copy

    from fmc_mcp.tools.bundle import object_entry

    rec = fixture("bundle_acp")
    ro_rows = {
        str(o["name"]): o
        for path, page in rec.items()
        if path.endswith(("/object/hosts", "/object/protocolportobjects"))
        for o in page["items"]
    }
    here = "Global/mcp-test-leaf"
    assert ro_rows["mcp-test-db"]["metadata"]["readOnly"]["reason"] == "RBAC"
    assert object_entry(ro_rows["mcp-test-db"], here)["domain"] == "Global"
    assert "domain" not in object_entry(ro_rows["AOL"], here)
    for name in ("mcp-test-db", "IPv4-Private-10.0.0.0-8", "mcp-test-servers"):
        writer = leaf_rows()[name]  # reason DOMAIN
        reader = copy.deepcopy(writer)
        reader["metadata"]["readOnly"] = {"state": True, "reason": "RBAC"}
        assert object_entry(reader, here) == object_entry(writer, here), name


async def test_delete_inherited_builtin_says_system_only(fmc: respx.MockRouter) -> None:
    aol = fixture("unused_inherited_builtins")["leaf_unused"][0]
    fmc.get(f"{CHILD_CFG}/object/protocolportobjects").mock(return_value=items([aol]))
    fmc.get(f"{CHILD_CFG}/object/operational/usage").mock(
        return_value=httpx.Response(400, json={"error": {"messages": [{"description": "not supported"}]}})
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_delete_object", {"object": "AOL", "type": "port", "domain": "Branch"})
    assert out["status"] == "blocked"
    assert out["blockers"] == [
        "Read-only system object."
    ]  # not "repeat with domain='Global'": it is read-only there too


# --- a read-only API user: every object says readOnly reason RBAC (#249) -------------------------------
# bundle_acp.json was recorded in Global with a read-only API user: built-ins and the lab's own objects
# alike carry readOnly {state: true, reason: RBAC}. Before #249 is_system() took every one of them for a
# built-in, so fmc_list_objects(include_system=false), fmc_unused_objects, fmc_find_address and the hygiene
# duplicate check hid every user object from such a login.

READER: dict[str, Any] = fixture("bundle_acp")


def reader_rows(*kinds: str) -> dict[str, dict[str, Any]]:
    """The recorded read-only user's objects of these collections (object/<kind>), by name."""
    return {
        str(o["name"]): o
        for path, page in READER.items()
        for kind in kinds
        if path.endswith(f"/object/{kind}")
        for o in page["items"]
    }


def as_reader(page: dict[str, Any]) -> dict[str, Any]:
    """A recorded page as the read-only user sees it: every item readOnly reason RBAC."""
    import copy

    out = copy.deepcopy(page)
    for o in out.get("items") or []:
        o.setdefault("metadata", {})["readOnly"] = {"state": True, "reason": "RBAC"}
    return out


def test_is_system_for_a_read_only_user_decides_by_type_and_id() -> None:
    from fmc_mcp.tools.common import is_system, role_read_only

    rows = reader_rows("hosts", "networks", "networkgroups", "protocolportobjects", "ranges", "urls")
    assert {o["metadata"]["readOnly"]["reason"] for o in rows.values()} == {"RBAC"}
    builtins = {
        "any-ipv4",
        "any-ipv6",
        "any",
        "IPv4-Private-All-RFC1918",
        "IPv4-Private-10.0.0.0-8",
        "AOL",
        "HTTP",
    }
    assert all(is_system(rows[n]) for n in builtins)
    own = [n for n in rows if n.startswith("mcp-test-")]
    assert len(own) == 12 and not [n for n in own if is_system(rows[n])]
    assert all(role_read_only(o) for o in rows.values())
    # outside the object catalog (policies) there is no type/id rule: RBAC keeps them read-only, as before
    (acp,) = [p for p in READER[f"{CFG}/policy/accesspolicies"]["items"] if p["name"] == "mcp-test-acp"]
    assert is_system(acp)
    # a writer's view of the same objects is not role-bound
    writer = {**rows["mcp-test-db"], "metadata": {"readOnly": {"state": False}}}
    assert not role_read_only(writer) and not is_system(writer)


async def test_list_objects_for_a_read_only_user_keeps_user_objects(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/networkgroups").mock(
        return_value=httpx.Response(200, json=READER[f"{CFG}/object/networkgroups"])
    )
    async with Client(server()) as c:
        user = await run(
            c,
            "fmc_list_objects",
            {"type": "network_group", "include_system": False, "response_format": "json"},
        )
        every = await run(c, "fmc_list_objects", {"type": "network_group", "response_format": "json"})
    assert [r["name"] for r in user["results"]] == ["mcp-test-servers"]
    rows = {r["name"]: r for r in every["results"]}
    assert rows["any"]["system"] is True and "system" not in rows["mcp-test-servers"]


async def test_unused_objects_for_a_read_only_user(fmc: respx.MockRouter) -> None:
    hosts = reader_rows("hosts")
    ports = reader_rows("protocolportobjects")
    fmc.get(f"{CFG}/object/hosts", params={"filter": "unusedOnly:true"}).mock(
        return_value=items([hosts["any-ipv6"], hosts["mcp-test-unused"]])
    )
    fmc.get(f"{CFG}/object/protocolportobjects", params={"filter": "unusedOnly:true"}).mock(
        return_value=items([ports["AOL"], ports["Bittorrent"], ports["mcp-test-udp-5000s"]])
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_unused_objects", {"types": ["host", "port"], "response_format": "json"})
    assert [r["name"] for r in out["results"]] == ["mcp-test-unused", "mcp-test-udp-5000s"], out


async def test_find_address_for_a_read_only_user_leaves_out_builtins_only(lab: respx.MockRouter) -> None:
    from fmc_mcp._core.testing import call_tool

    from .conftest import as_leaf

    as_leaf(lab)
    for name in ("networkaddresses", "networkgroups"):
        lab.get(f"{CFG}/object/{name}").mock(
            return_value=httpx.Response(200, json=as_reader(LEAF_VIEW[name]))
        )
    args = {"address": "10.10.20.5", "areas": ["objects"], "response_format": "json"}
    srv = create_server(make_settings())
    out = await call_tool(srv, "fmc_find_address", args)
    where = [r["where"] for r in out["results"] if r["area"] == "objects"]
    assert where[0] == "Host mcp-test-db" and "Network mcp-test-app-net" in where, where
    assert not [w for w in where if "IPv4-Private" in w], where
    broad = await call_tool(srv, "fmc_find_address", {**args, "include_broad": True})
    assert "Network IPv4-Private-10.0.0.0-8" in [r["where"] for r in broad["results"]]


def test_hygiene_duplicates_for_a_read_only_user() -> None:
    import copy
    from typing import cast

    from fmc_mcp.catalog import Catalog
    from fmc_mcp.client import FmcApp
    from fmc_mcp.tools.hygiene import duplicate_objects

    rbac = {"state": True, "reason": "RBAC"}
    objs = {str(o["id"]): o for o in as_reader({"items": list(leaf_rows().values())})["items"]}
    ten = {
        "id": "00000000-0000-0ed3-0000-000000000098",
        "name": "lab-10",
        "type": "Network",
        "value": "10.0.0.0/8",
    }
    objs[ten["id"]] = {**ten, "metadata": {"readOnly": rbac}}
    cat = Catalog(cast(FmcApp, None), None, objects=objs)
    assert not duplicate_objects(cat, [])  # IPv4-Private-10.0.0.0-8 is FMC's: lab-10 has no duplicate
    db = copy.deepcopy(leaf_rows()["mcp-test-db"])
    twin = {
        **db,
        "id": "00000000-0000-0ed3-0000-000000000097",
        "name": "lab-db",
        "metadata": {"readOnly": rbac},
    }
    objs[twin["id"]] = twin
    objs[str(db["id"])]["metadata"]["readOnly"] = rbac
    (found,) = duplicate_objects(Catalog(cast(FmcApp, None), None, objects=objs), [])
    assert sorted(found["objects"]) == ["lab-db", "mcp-test-db"], found


async def test_writes_name_the_role_not_a_system_object(fmc: respx.MockRouter) -> None:
    """Before #249 a read-only user's object was refused as 'a read-only system object'; it is still
    refused (FMC would answer 403), now for what it is."""
    db = reader_rows("hosts")["mcp-test-db"]
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([db]))
    fmc.get(f"{CFG}/object/operational/usage").mock(return_value=items([]))
    put = fmc.put(f"{CFG}/object/hosts/{db['id']}")
    async with Client(server()) as c:
        upd = await c.call_tool(
            "fmc_update_object",
            {"object": "mcp-test-db", "type": "host", "value": "192.0.2.9"},
            raise_on_error=False,
        )
        out = await run(c, "fmc_delete_object", {"object": "mcp-test-db", "type": "host"})
    assert upd.is_error and "read-only for this API user's role" in upd.content[0].text  # type: ignore[union-attr]
    assert "system object" not in upd.content[0].text  # type: ignore[union-attr]
    assert out["status"] == "blocked"
    assert out["blockers"] == [
        "'mcp-test-db' is read-only for this API user's role (FMC: readOnly reason RBAC): use an account "
        "whose role may modify it."
    ]
    assert not put.called

"""F70 object lifecycle at scale: fmc_delete_objects, fmc_replace_object, fmc_import_objects(mode='sync').

Shapes are FMC 10.0.1's (tests/fixtures/object_lifecycle.json, recorded 2026-10-20 in the lab's leaf
domain and redacted): the usage API names a static route as a `Device` row ("Static Route Setting under
virtual router Global", the device's id) and a network group as `NetworkAddress`; expanded security zones
carry their device `interfaces`."""

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server

from .conftest import CFG, CHILD, fixture, items, make_settings

REC = fixture("object_lifecycle")
OTHER = {"name": "Global", "id": "99999999-0000-4000-8000-000000000001", "type": "Domain"}
HERE = {"name": "Global", "id": "e276abec-e0f2-11e3-8169-6d9ed49b625f", "type": "Domain"}
ACP = "00000000-0000-0ed3-0000-000000000a01"
NATP = "00000000-0000-0ed3-0000-000000000b01"
PFP = "00000000-0000-0ed3-0000-000000000c01"
DEV = "4fc3908a-0000-4000-8000-000000000d01"


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def server(dangerous: bool = True) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=dangerous))


def obj(oid: str, name: str, type_: str, **kw: Any) -> dict[str, Any]:
    return {"id": oid, "name": name, "type": type_, "metadata": {"domain": HERE}, **kw}


def system(o: dict[str, Any]) -> dict[str, Any]:
    return {**o, "metadata": {"readOnly": {"state": True, "reason": "SYSTEM"}, "domain": HERE}}


def inherited(o: dict[str, Any]) -> dict[str, Any]:
    return {**o, "metadata": {"readOnly": {"state": True, "reason": "DOMAIN"}, "domain": OTHER}}


def collection(rows: list[dict[str, Any]], unused: set[str] | None = None) -> Callable[..., httpx.Response]:
    """A GET handler for an object collection that honours FMC's nameOrValue and unusedOnly filters."""

    def handler(request: httpx.Request) -> httpx.Response:
        out = rows
        for part in request.url.params.get("filter", "").split(";"):
            key, _, val = part.partition(":")
            if key == "nameOrValue":
                out = [o for o in out if val.lower() in (str(o.get("name")) + str(o.get("value"))).lower()]
            elif key == "unusedOnly" and unused is not None:
                out = [o for o in out if o["id"] in unused]
        return items(out)

    return handler


def empty_collections(fmc: respx.MockRouter, *paths: str) -> None:
    for p in paths:
        fmc.get(f"{CFG}/object/{p}").mock(return_value=items([]))


# --- fmc_delete_objects ---------------------------------------------------------------------------


async def test_delete_by_prefix_in_dependency_order(fmc: respx.MockRouter) -> None:
    """A group and the host it holds go together (group first); a host a policy still uses is refused
    with that policy named; FMC's built-ins and Global's objects are refused; bulk DELETE per type."""
    g1 = obj("g1", "mcp-w6-grp", "NetworkGroup", objects=[{"id": "h2", "type": "Host", "name": "mcp-w6-h2"}])
    hosts = [
        obj("h1", "mcp-w6-h1", "Host", value="192.0.2.1"),
        obj("h2", "mcp-w6-h2", "Host", value="192.0.2.2"),
        obj("h3", "mcp-w6-h3", "Host", value="192.0.2.3"),
        system(obj("h4", "mcp-w6-builtin", "Host", value="192.0.2.4")),
        inherited(
            obj("00000000-0000-0ed3-0000-021474990005", "mcp-w6-global", "Host", value="192.0.2.5")
        ),  # FMC-made id (0ed3)
        obj("h6", "mcp-w6-seed-keep", "Host", value="192.0.2.6"),
        obj("h7", "other", "Host", value="192.0.2.7"),
        # FMC 10.0.1 in a leaf: an ancestor's object can be read-only with no reason at all
        {
            **obj("00000000-0000-0ed3-0000-021474990008", "mcp-w6-noreason", "Host", value="192.0.2.8"),
            "metadata": {"readOnly": {"state": True}, "domain": OTHER},
        },
    ]
    fmc.get(f"{CFG}/object/hosts").mock(
        side_effect=collection(
            hosts,
            unused={
                "h1",
                "h4",
                "00000000-0000-0ed3-0000-021474990005",
                "h6",
                "h7",
                "00000000-0000-0ed3-0000-021474990008",
            },
        )
    )
    fmc.get(f"{CFG}/object/networkgroups").mock(side_effect=collection([g1], unused={"g1"}))
    usage = {
        "h2": [{"type": "NetworkAddress", "name": "mcp-w6-grp", "id": "g1"}],
        "h3": [{"type": "AccessPolicy", "name": "mcp-w6-acp", "id": ACP}],
    }
    fmc.get(f"{CFG}/object/operational/usage").mock(
        side_effect=lambda req: items(usage[req.url.params["filter"].split(";")[0].split(":")[1]])
    )
    calls: list[tuple[str, str]] = []

    def deleted(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path.rsplit("/", 1)[1], request.url.params.get("filter", "")))
        assert request.url.params["bulk"] == "true"
        return httpx.Response(200, json={"items": []})

    fmc.delete(f"{CFG}/object/hosts").mock(side_effect=deleted)
    fmc.delete(f"{CFG}/object/networkgroups").mock(side_effect=deleted)
    args = {"prefix": "mcp-w6-", "types": ["host", "network_group"], "exclude": ["mcp-w6-seed-*"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_delete_objects", args)
        assert p["status"] == "preview", p
        got = p["preview"]
        assert [r["name"] for r in got["delete"]["objects"]] == ["mcp-w6-h1", "mcp-w6-grp", "mcp-w6-h2"]
        assert got["delete"]["objects"][2]["after"] == ["mcp-w6-grp"]
        refused = {r["name"]: r["reason"] for r in got["refused"]}
        assert refused["mcp-w6-h3"] == "in use by AccessPolicy mcp-w6-acp"
        assert "built-in" in refused["mcp-w6-builtin"]
        assert "'Global'" in refused["mcp-w6-global"] and "'Global'" in refused["mcp-w6-noreason"]
        assert got["excluded"] == ["mcp-w6-seed-keep"] and p["blast_radius"] == 3
        assert got["requests"] == 3 and got["order"] == [
            "1 host (bulk)",
            "1 network_group (bulk)",
            "1 host (bulk)",
        ]
        out = (await run(c, "fmc_delete_objects", {**args, "confirm": p["confirm"]}))["result"]
    assert out["deleted"] == 3
    assert calls == [("hosts", "ids:h1"), ("networkgroups", "ids:g1"), ("hosts", "ids:h2")]


async def test_delete_refusal_cascades_to_members(fmc: respx.MockRouter) -> None:
    """A group that stays (a policy uses it) keeps its member in use, so the member is refused too."""
    g1 = obj("g1", "mcp-w6-grp", "NetworkGroup")
    fmc.get(f"{CFG}/object/hosts").mock(
        side_effect=collection([obj("h2", "mcp-w6-h2", "Host", value="192.0.2.2")], unused=set())
    )
    fmc.get(f"{CFG}/object/networkgroups").mock(side_effect=collection([g1], unused=set()))
    usage = {
        "h2": [{"type": "NetworkAddress", "name": "mcp-w6-grp", "id": "g1"}],
        "g1": [{"type": "AccessPolicy", "name": "mcp-w6-acp", "id": ACP}],
    }
    fmc.get(f"{CFG}/object/operational/usage").mock(
        side_effect=lambda req: items(usage[req.url.params["filter"].split(";")[0].split(":")[1]])
    )
    async with Client(server()) as c:
        p = await run(
            c,
            "fmc_delete_objects",
            {"names": ["mcp-w6-grp", "MCP-W6-H2", "nope"], "types": ["host", "network_group"]},
        )
    assert p["status"] == "blocked" and "Nothing to delete" in p["blockers"][0]
    reasons = {r["name"]: r["reason"] for r in p["preview"]["refused"]}
    assert reasons == {
        "mcp-w6-grp": "in use by AccessPolicy mcp-w6-acp",
        "mcp-w6-h2": "in use by NetworkAddress mcp-w6-grp",
    }
    assert p["preview"]["not_found"] == ["nope"]


async def test_delete_unused_only_zones_and_dynamic_objects(fmc: respx.MockRouter) -> None:
    """Zones on interfaces and dynamic objects a rule uses are skipped (counted) with unused_only; zones go
    one by one, dynamic objects in bulk."""
    zones = REC["securityzones"]["items"]
    fmc.get(f"{CFG}/object/securityzones").mock(return_value=items(zones))
    fmc.get(f"{CFG}/object/interfacegroups").mock(return_value=items([]))
    dyn = [obj("d1", "mcp-w6-dyn-used", "DynamicObject"), obj("d2", "mcp-w6-dyn-free", "DynamicObject")]
    fmc.get(f"{CFG}/object/dynamicobjects").mock(return_value=items(dyn))
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([{"id": ACP, "name": "mcp-w6-acp"}]))
    rule = {
        "id": "r1",
        "name": "mcp-w6-r1",
        "type": "AccessRule",
        "sourceDynamicObjects": {
            "objects": [{"id": "d1", "type": "DynamicObject", "name": "mcp-w6-dyn-used"}]
        },
    }
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP}/accessrules").mock(return_value=items([rule]))
    fmc.get(f"{CFG}/policy/prefilterpolicies").mock(return_value=items([]))
    fmc.get(f"{CFG}/policy/ftdnatpolicies").mock(return_value=items([]))
    free_zone = next(z for z in zones if not z.get("interfaces"))
    zdel = fmc.delete(f"{CFG}/object/securityzones/{free_zone['id']}").mock(
        return_value=httpx.Response(200, json={})
    )
    ddel = fmc.delete(f"{CFG}/object/dynamicobjects").mock(return_value=httpx.Response(200, json={}))
    args = {"prefix": "mcp-w6-", "unused_only": True, "kinds": ["zones", "dynamic_objects"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_delete_objects", args)
        got = p["preview"]
        assert [r["name"] for r in got["delete"]["zones"]] == [free_zone["name"]]
        assert [r["name"] for r in got["delete"]["dynamic_objects"]] == ["mcp-w6-dyn-free"]
        assert got["in_use_skipped"] == 2 and "refused" not in got
        assert any("IP mappings" in s for s in p["side_effects"])
        await run(c, "fmc_delete_objects", {**args, "confirm": p["confirm"]})
    assert zdel.called and ddel.calls.last.request.url.params["filter"] == "ids:d2"


async def test_delete_policies(fmc: respx.MockRouter) -> None:
    """An assigned policy is refused; a prefilter policy linked only by an access policy that is deleted
    too goes after it; the system default prefilter policy is refused."""
    acps = [
        {
            **obj(ACP, "mcp-w6-acp", "AccessPolicy"),
            "prefilterPolicySetting": {"id": "pf1", "type": "PrefilterPolicy"},
        },
        obj("a2", "mcp-w6-acp-live", "AccessPolicy"),
    ]
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items(acps))
    fmc.get(f"{CFG}/policy/prefilterpolicies").mock(
        return_value=items(
            [
                obj("pf1", "mcp-w6-pf", "PrefilterPolicy"),
                {**obj("pf0", "mcp-w6-default", "PrefilterPolicy"), "isSystemDefined": True},
            ]
        )
    )
    fmc.get(f"{CFG}/policy/ftdnatpolicies").mock(return_value=items([]))
    fmc.get(f"{CFG}/policy/ftdplatformsettingspolicies").mock(return_value=items([]))
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items(
            [
                {
                    "id": "as1",
                    "policy": {"id": "a2", "type": "AccessPolicy"},
                    "targets": [{"id": DEV, "name": "mcp-ftd1", "type": "Device"}],
                }
            ]
        )
    )
    order: list[str] = []
    for pid, coll in ((ACP, "accesspolicies"), ("pf1", "prefilterpolicies")):
        fmc.delete(f"{CFG}/policy/{coll}/{pid}").mock(
            side_effect=lambda req: (
                order.append(req.url.path.rsplit("/", 1)[1]),
                httpx.Response(200, json={}),
            )[1]
        )
    args = {"prefix": "mcp-w6-", "kinds": ["policies"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_delete_objects", args)
        got = p["preview"]
        assert [r["name"] for r in got["delete"]["policies"]] == ["mcp-w6-acp", "mcp-w6-pf"]
        reasons = {r["name"]: r["reason"] for r in got["refused"]}
        assert reasons["mcp-w6-acp-live"].startswith("assigned to mcp-ftd1")
        assert reasons["mcp-w6-default"] == "system-defined policy"
        await run(c, "fmc_delete_objects", {**args, "confirm": p["confirm"]})
    assert order == [ACP, "pf1"]


async def test_delete_stops_at_first_failure(fmc: respx.MockRouter) -> None:
    hosts = [obj(f"h{i:02}", f"mcp-w6-h{i:02}", "Host", value=f"192.0.2.{i}") for i in range(60)]
    fmc.get(f"{CFG}/object/hosts").mock(side_effect=collection(hosts, unused={h["id"] for h in hosts}))
    fmc.delete(f"{CFG}/object/hosts").mock(
        side_effect=[
            httpx.Response(200, json={}),
            httpx.Response(
                400, json={"error": {"messages": [{"description": "Object deletion restricted"}]}}
            ),
        ]
    )
    args = {"prefix": "mcp-w6-", "types": ["host"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_delete_objects", args)
        assert p["preview"]["requests"] == 2
        with pytest.raises(ToolError, match="stopped after 50 of 60"):
            await run(c, "fmc_delete_objects", {**args, "confirm": p["confirm"]})


async def test_delete_dry_run_and_arguments(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(
        side_effect=collection([obj("h1", "mcp-w6-h1", "Host", value="192.0.2.1")], unused={"h1"})
    )
    async with Client(server()) as c:
        d = await run(c, "fmc_delete_objects", {"prefix": "mcp-w6-", "types": ["host"], "dry_run": True})
        assert d["status"] == "dry_run" and "confirm" not in d and d["preview"]["counts"] == {"objects": 1}
        for bad, msg in (
            ({}, "Select what to delete"),
            ({"prefix": "mc"}, "at least 3"),
            ({"names": ["a"], "prefix": "mcp-w6-"}, "not both"),
            ({"prefix": "mcp-w6-", "types": ["security_zone"]}, "Not deletable here"),
        ):
            with pytest.raises(ToolError, match=msg):
                await run(c, "fmc_delete_objects", bad)
    async with Client(server(dangerous=False)) as c:
        assert "fmc_delete_objects" not in {t.name for t in await c.list_tools()}


LIVE_GROUPS = REC["networkgroups_live"]  # FMC 10.0.1: the unused filter answers no network group


def live_groups(rows: list[dict[str, Any]]) -> Callable[..., httpx.Response]:
    """networkgroups as FMC 10.0.1 answers them: nameOrValue works, unusedOnly answers nothing (the
    recorded empty answer, no `items`)."""
    by_name = collection(rows)

    def handler(request: httpx.Request) -> httpx.Response:
        if "unusedOnly" in request.url.params.get("filter", ""):
            return httpx.Response(200, json=LIVE_GROUPS["unused_filter"])
        return by_name(request)

    return handler


def usage_by_id(usage: dict[str, list[dict[str, Any]]]) -> Callable[..., httpx.Response]:
    """The usage API: the given rows per object id, FMC's empty answer (no `items`) for the rest."""

    def handler(request: httpx.Request) -> httpx.Response:
        oid = request.url.params["filter"].split(";")[0].split(":")[1]
        if usage.get(oid):
            return items(usage[oid])
        return httpx.Response(200, json=LIVE_GROUPS["usage_none"])

    return handler


async def test_prefix_cleanup_deletes_a_group_fmc_10_0_1_doesnt_call_unused(fmc: respx.MockRouter) -> None:
    """The live-B2 prefix cleanup: FMC 10.0.1's unused filter answers no network group, the usage API names
    nothing for the group, so the group goes first and its members after it; nothing is refused."""
    grp = LIVE_GROUPS["by_name"]["items"][0]
    member_ids = [m["id"] for m in grp["objects"]]
    hosts = [
        obj("00000000-0000-0ed3-0000-021474996337", "mcp-w6-sync-1", "Host", value="192.0.2.101"),
        obj(member_ids[0], "mcp-w6-sync-2", "Host", value="192.0.2.112"),
        obj(member_ids[1], "mcp-w6-sync-3", "Host", value="192.0.2.103"),
        obj("00000000-0000-0ed3-0000-021474996339", "mcp-w6-sync-orphan", "Host", value="192.0.2.109"),
    ]
    unused_hosts = {hosts[0]["id"], hosts[3]["id"]}
    fmc.get(f"{CFG}/object/hosts").mock(side_effect=collection(hosts, unused=unused_hosts))
    fmc.get(f"{CFG}/object/networkgroups").mock(side_effect=live_groups([grp]))
    in_grp = [{"type": "NetworkAddress", "name": grp["name"], "id": grp["id"]}]  # usage names a group so
    usage = fmc.get(f"{CFG}/object/operational/usage").mock(
        side_effect=usage_by_id({member_ids[0]: in_grp, member_ids[1]: in_grp})
    )
    calls: list[tuple[str, str]] = []

    def deleted(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path.rsplit("/", 1)[1], request.url.params.get("filter", "")))
        if request.url.path.endswith("networkgroups"):
            return httpx.Response(200, json=LIVE_GROUPS["delete_answer"])
        return httpx.Response(200, json={})

    fmc.delete(f"{CFG}/object/hosts").mock(side_effect=deleted)
    fmc.delete(f"{CFG}/object/networkgroups").mock(side_effect=deleted)
    args = {"prefix": "mcp-w6-sync-", "types": ["host", "network_group"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_delete_objects", args)
        assert p["status"] == "preview", p
        got = p["preview"]
        assert "refused" not in got, got["refused"]
        assert [r["name"] for r in got["delete"]["objects"]] == [
            "mcp-w6-sync-1",
            "mcp-w6-sync-orphan",
            "mcp-w6-sync-grp",
            "mcp-w6-sync-2",
            "mcp-w6-sync-3",
        ]
        assert got["delete"]["objects"][3]["after"] == ["mcp-w6-sync-grp"]
        assert got["order"] == ["2 host (bulk)", "1 network_group (bulk)", "2 host (bulk)"]
        assert usage.call_count == 3  # the two members and the group
        out = (await run(c, "fmc_delete_objects", {**args, "confirm": p["confirm"]}))["result"]
    assert out["deleted"] == 5
    assert calls == [
        ("hosts", f"ids:{hosts[0]['id']},{hosts[3]['id']}"),
        ("networkgroups", f"ids:{grp['id']}"),
        ("hosts", f"ids:{member_ids[0]},{member_ids[1]}"),
    ]


async def test_unused_only_checks_groups_with_the_usage_api(
    fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """unused_only: FMC's filter answers no network group (10.0.1), in the prefix and without it (the
    blind-filter signature), so the groups are listed without it: a group the usage API names nothing for
    is deleted, a used one skipped; a group past the usage budget is refused as not checked (not counted as
    in use)."""
    groups = [
        obj("g1", "mcp-w6-grp-free", "NetworkGroup", objects=[{"id": "h1", "type": "Host"}]),
        obj("g2", "mcp-w6-grp-used", "NetworkGroup"),
        obj("g3", "mcp-w6-grp-late", "NetworkGroup"),
    ]
    route = fmc.get(f"{CFG}/object/networkgroups").mock(side_effect=live_groups(groups))
    fmc.get(f"{CFG}/object/operational/usage").mock(
        side_effect=usage_by_id({"g2": [{"type": "AccessPolicy", "name": "mcp-w6-acp", "id": ACP}]})
    )
    monkeypatch.setattr("fmc_mcp.tools.object_lifecycle.USAGE_CAP", 2)
    args = {"prefix": "mcp-w6-", "unused_only": True, "types": ["network_group"], "dry_run": True}
    async with Client(server()) as c:
        d = await run(c, "fmc_delete_objects", args)
    got = d["preview"]
    assert [r["name"] for r in got["delete"]["objects"]] == ["mcp-w6-grp-free"]
    assert got["in_use_skipped"] == 1
    assert [(r["name"], r["reason"].split(" (")[0]) for r in got["refused"]] == [
        ("mcp-w6-grp-late", "not checked")
    ]
    assert [r.request.url.params["filter"] for r in route.calls] == [
        "nameOrValue:mcp-w6-;unusedOnly:true",
        "unusedOnly:true",  # the signature: none at all in the domain
        "nameOrValue:mcp-w6-",  # then the groups, decided by the usage API
    ]


async def test_unused_objects_lists_groups_the_filter_leaves_out(
    fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """live-B2: mcp-w6-grp (members, no referrer) was missing from fmc_unused_objects because FMC 10.0.1's
    filter answers no network group. Groups it leaves out are asked of the usage API, except built-ins,
    Global's groups and groups another group holds (no request for those), up to GROUP_USAGE_CAP."""
    free = obj("g1", "mcp-w6-grp", "NetworkGroup", objects=[{"id": "h1", "type": "Host", "name": "mcp-w6-b"}])
    outer = obj("g2", "mcp-w6-outer", "NetworkGroup", objects=[{"id": "g3", "type": "NetworkGroup"}])
    inner = obj("g3", "mcp-w6-inner", "NetworkGroup")
    groups = [free, outer, inner, system(obj("g4", "IPv4-Private-All-RFC1918", "NetworkGroup"))]
    groups.append(inherited(obj("g5", "mcp-test-servers", "NetworkGroup")))
    fmc.get(f"{CFG}/object/networkgroups").mock(side_effect=live_groups(groups))
    for path in ("hosts", "networks", "ranges", "fqdns", "protocolportobjects", "urls"):
        fmc.get(f"{CFG}/object/{path}").mock(return_value=items([]))
    for path in ("portobjectgroups", "urlgroups"):
        fmc.get(f"{CFG}/object/{path}").mock(
            return_value=httpx.Response(200, json=LIVE_GROUPS["unused_filter"])
        )
    usage = fmc.get(f"{CFG}/object/operational/usage").mock(
        side_effect=usage_by_id({"g2": [{"type": "AccessPolicy", "name": "mcp-w6-acp", "id": ACP}]})
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_unused_objects", {"response_format": "json"})
        assert [(r["name"], r["object_type"], r.get("checked_by")) for r in out["results"]] == [
            ("mcp-w6-grp", "network_group", "usage API")
        ]
        assert out["results"][0]["members"] == ["mcp-w6-b"]
        assert "2 were checked with FMC's usage API" in out["note"]
        asked = sorted(r.request.url.params["filter"].split(";")[0] for r in usage.calls)
        assert asked == ["uuid:g1", "uuid:g2"]  # not the inner, built-in or Global's group
        monkeypatch.setattr("fmc_mcp.tools.objects.GROUP_USAGE_CAP", 1)
        capped = await run(c, "fmc_unused_objects", {"types": ["network_group"], "response_format": "json"})
    assert [r["name"] for r in capped["results"]] == ["mcp-w6-grp"]
    assert "1 more groups were not checked (at most 1 per call): mcp-w6-outer" in capped["note"]


async def test_blind_filter_group_the_usage_api_refuses_is_neither_freed_nor_listed(
    fmc: respx.MockRouter,
) -> None:
    """FMC's filter lists no network group (10.0.1) and its usage API answers 400 for the group: nothing
    says it is free, so fmc_delete_objects refuses it (unknown, not "in use") and fmc_unused_objects leaves
    it out."""
    grp = obj("g1", "mcp-w6-grp", "NetworkGroup")
    fmc.get(f"{CFG}/object/networkgroups").mock(side_effect=live_groups([grp]))
    usage = fmc.get(f"{CFG}/object/operational/usage").mock(
        return_value=httpx.Response(400, json={"error": {"messages": [{"description": "Invalid type"}]}})
    )
    async with Client(server()) as c:
        for unused_only in (False, True):
            args = {"prefix": "mcp-w6-", "types": ["network_group"], "unused_only": unused_only}
            d = await run(c, "fmc_delete_objects", {**args, "dry_run": True})
            got = d["preview"]
            assert "delete" not in got or not got["delete"].get("objects"), got
            ((name, reason),) = [(r["name"], r["reason"]) for r in got["refused"]]
            assert name == "mcp-w6-grp" and reason.startswith("not checked (FMC's unused filter lists no ")
            assert "usage API can't answer" in reason and not got.get("in_use_skipped")
        listed = await run(c, "fmc_unused_objects", {"types": ["network_group"], "response_format": "json"})
    assert listed["results"] == [] and usage.call_count == 3


async def test_port_group_filter_disagreement_is_refused(fmc: respx.MockRouter) -> None:
    """Only network groups have live evidence of a blind filter. A port group FMC's filter doesn't call
    unused, with no referrer named by the usage API, stays refused as in use, even when the filter lists no
    port group at all; unused_only skips it and fmc_unused_objects doesn't ask the usage API."""
    pg = obj("p1", "mcp-w6-ports", "PortObjectGroup")
    fmc.get(f"{CFG}/object/portobjectgroups").mock(side_effect=collection([pg], unused=set()))
    usage = fmc.get(f"{CFG}/object/operational/usage").mock(
        return_value=httpx.Response(200, json=LIVE_GROUPS["usage_none"])
    )
    async with Client(server()) as c:
        args = {"prefix": "mcp-w6-", "types": ["port_group"], "dry_run": True}
        d = await run(c, "fmc_delete_objects", args)
        assert [(r["name"], r["reason"]) for r in d["preview"]["refused"]] == [
            ("mcp-w6-ports", "in use (FMC's unused filter says so, its usage API names nothing)")
        ]
        assert usage.call_count == 1
        only = await run(c, "fmc_delete_objects", {**args, "unused_only": True})
        assert only["preview"]["delete"] == {} and only["blockers"] == ["Nothing to delete."]
        listed = await run(c, "fmc_unused_objects", {"types": ["port_group"], "response_format": "json"})
    assert listed["results"] == [] and "note" not in listed
    assert usage.call_count == 1  # neither unused_only nor the listing asked about the port group


async def test_network_group_filter_that_answers_stays_authoritative(fmc: respx.MockRouter) -> None:
    """The relaxation needs the blind-filter signature: here FMC's filter lists another network group as
    unused (outside the prefix, so asked without it), so it works, and a group it doesn't list whose
    usage answer is empty is refused as in use, not freed."""
    other = obj("g9", "mcp-test-spare", "NetworkGroup")
    target = obj("g1", "mcp-w6-grp", "NetworkGroup")
    route = fmc.get(f"{CFG}/object/networkgroups").mock(
        side_effect=collection([other, target], unused={"g9"})
    )
    usage = fmc.get(f"{CFG}/object/operational/usage").mock(
        return_value=httpx.Response(200, json=LIVE_GROUPS["usage_none"])
    )
    async with Client(server()) as c:
        d = await run(
            c, "fmc_delete_objects", {"prefix": "mcp-w6-", "types": ["network_group"], "dry_run": True}
        )
        assert [(r["name"], r["reason"]) for r in d["preview"]["refused"]] == [
            ("mcp-w6-grp", "in use (FMC's unused filter says so, its usage API names nothing)")
        ]
        assert [r.request.url.params["filter"] for r in route.calls] == [
            "nameOrValue:mcp-w6-",
            "nameOrValue:mcp-w6-;unusedOnly:true",
            "unusedOnly:true",  # the signature check: FMC lists mcp-test-spare, so not blind
        ]
        listed = await run(c, "fmc_unused_objects", {"types": ["network_group"], "response_format": "json"})
    assert [(r["name"], r.get("checked_by")) for r in listed["results"]] == [("mcp-test-spare", None)]
    assert usage.call_count == 1 and "note" not in listed


# --- fmc_replace_object ---------------------------------------------------------------------------

OLD = obj("00000000-0000-0ed3-0000-0000000000a1", "mcp-w6-a", "Host", value="192.0.2.10")
NEW = obj("00000000-0000-0ed3-0000-0000000000b1", "mcp-w6-b", "Host", value="192.0.2.11")


def ref(o: dict[str, Any]) -> dict[str, Any]:
    return {"id": o["id"], "type": o["type"], "name": o["name"]}


def lab_for_replace(fmc: respx.MockRouter, usage: list[dict[str, Any]] | None) -> dict[str, Any]:
    fmc.get(f"{CFG}/object/hosts").mock(side_effect=collection([OLD, NEW]))
    empty_collections(fmc, "networks", "ranges", "fqdns")
    group = obj(
        "g1",
        "mcp-w6-grp",
        "NetworkGroup",
        objects=[ref(OLD), {"id": "x1", "type": "Network", "name": "keep"}],
    )
    fmc.get(f"{CFG}/object/networkgroups").mock(side_effect=collection([group]))
    if usage is None:
        fmc.get(f"{CFG}/object/operational/usage").mock(
            return_value=httpx.Response(
                400, json={"error": {"messages": [{"description": "API not supported"}]}}
            )
        )
    else:
        fmc.get(f"{CFG}/object/operational/usage").mock(return_value=items(usage))
    rules = [
        {
            "id": "r1",
            "name": "mcp-w6-r1",
            "type": "AccessRule",
            "action": "ALLOW",
            "metadata": {"ruleIndex": 1, "domain": HERE},
            "sourceNetworks": {"objects": [ref(OLD)]},
            "commentHistoryList": [{"comment": "old"}],
        },
        {
            "id": "r2",
            "name": "mcp-w6-r2",
            "type": "AccessRule",
            "action": "ALLOW",
            "metadata": {"ruleIndex": 2, "domain": HERE},
            "destinationNetworks": {
                "objects": [ref(NEW), ref(OLD)],
                "literals": [{"type": "Host", "value": "198.51.100.7"}],
            },
        },
        {
            "id": "r3",
            "name": "mcp-w6-r3",
            "type": "AccessRule",
            "action": "BLOCK",
            "metadata": {"ruleIndex": 3, "domain": HERE},
        },
    ]
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([{"id": ACP, "name": "mcp-w6-acp"}]))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP}/accessrules").mock(return_value=items(rules))
    fmc.get(f"{CFG}/policy/prefilterpolicies").mock(return_value=items([]))
    nat = fixture("natrules")["items"][1]  # the recorded auto NAT rule
    nat = {**nat, "originalNetwork": ref(OLD)}
    fmc.get(f"{CFG}/policy/ftdnatpolicies").mock(return_value=items([{"id": NATP, "name": "mcp-w6-nat"}]))
    fmc.get(f"{CFG}/policy/ftdnatpolicies/{NATP}/natrules").mock(return_value=items([nat]))
    fmc.get(f"{CFG}/policy/ftdnatpolicies/{NATP}/autonatrules/{nat['id']}").mock(
        return_value=httpx.Response(200, json=nat)
    )
    fmc.get(f"{CFG}/devices/devicerecords").mock(
        return_value=items([{"id": DEV, "name": "mcp-sdwan-t1-spoke1"}])
    )
    routes = REC["ipv4staticroutes"]["items"]
    routes = [{**routes[0], "selectedNetworks": [ref(OLD)]}, *routes[1:]]
    fmc.get(f"{CFG}/devices/devicerecords/{DEV}/routing/ipv4staticroutes").mock(return_value=items(routes))
    fmc.get(f"{CFG}/devices/devicerecords/{DEV}/routing/ipv6staticroutes").mock(return_value=items([]))
    return {"group": group, "nat": nat, "route": routes[0]}


async def test_replace_everywhere_in_order(fmc: respx.MockRouter) -> None:
    usage = [
        {"type": "NetworkAddress", "name": "mcp-w6-grp", "id": "g1"},
        {"type": "AccessPolicy", "name": "mcp-w6-acp", "id": ACP},
        {"type": "PrefilterPolicy", "name": "mcp-w6-pf", "id": PFP},
        {"type": "FTDNatPolicy", "name": "mcp-w6-nat", "id": NATP},
        {**REC["usage_static_route"]["items"][0], "id": DEV},
    ]
    lab = lab_for_replace(fmc, usage)
    pf_rule = {
        "id": "p1",
        "name": "mcp-w6-p1",
        "type": "PrefilterRule",
        "action": "FASTPATH",
        "ruleType": "PREFILTER",
        "metadata": {"ruleIndex": 1, "domain": HERE},
        "destinationNetworks": {"objects": [ref(OLD)]},
    }
    fmc.get(f"{CFG}/policy/prefilterpolicies/{PFP}/prefilterrules").mock(return_value=items([pf_rule]))
    seen: list[tuple[str, Any]] = []
    params: list[dict[str, str]] = []

    def put(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path.split("/v1/domain/")[1].split("/", 1)[1], json.loads(request.content)))
        params.append(dict(request.url.params))
        return httpx.Response(200, json={})

    fmc.put(f"{CFG}/policy/accesspolicies/{ACP}/accessrules").mock(side_effect=put)
    fmc.put(f"{CFG}/policy/prefilterpolicies/{PFP}/prefilterrules/p1").mock(side_effect=put)
    fmc.put(f"{CFG}/object/networkgroups/g1").mock(side_effect=put)
    fmc.put(f"{CFG}/policy/ftdnatpolicies/{NATP}/autonatrules/{lab['nat']['id']}").mock(side_effect=put)
    fmc.put(f"{CFG}/devices/devicerecords/{DEV}/routing/ipv4staticroutes/{lab['route']['id']}").mock(
        side_effect=put
    )
    gone = fmc.delete(f"{CFG}/object/hosts/{OLD['id']}").mock(return_value=httpx.Response(200, json={}))
    args = {"old": "mcp-w6-a", "new": "mcp-w6-b", "type": "host", "delete_old": True}
    async with Client(server(dangerous=False)) as c:
        p = await run(c, "fmc_replace_object", args)
        assert p["status"] == "preview", p
        got = p["preview"]
        assert got["counts"] == {
            "access_rules": 2,
            "prefilter_rules": 1,
            "groups": 1,
            "nat_rules": 1,
            "static_routes": 1,
        }
        assert got["changes"]["access_rules"] == [
            {"where": "mcp-w6-acp #1 mcp-w6-r1", "fields": ["sourceNetworks"]},
            {"where": "mcp-w6-acp #2 mcp-w6-r2", "fields": ["destinationNetworks"]},
        ]
        assert got["changes"]["static_routes"][0]["where"].startswith("mcp-sdwan-t1-spoke1: mcp-w6-a via")
        # live-B2 showed "mcp-w6-nat AUTO #- (auto)": an auto NAT rule has no index, its object names it
        assert [c["where"] for c in got["changes"]["nat_rules"]] == [
            "mcp-w6-nat auto NAT of mcp-w6-a (STATIC)"
        ]
        assert got["found_by"] == "FMC's usage API" and "not_changed" not in got
        assert got["write_requests"] == 6 and p["blast_radius"] == 7
        out = (await run(c, "fmc_replace_object", {**args, "confirm": p["confirm"]}))["result"]
    assert out["replaced"] == {
        "access_rules": 2,
        "prefilter_rules": 1,
        "groups": 1,
        "nat_rules": 1,
        "static_routes": 1,
    }
    assert out["old_deleted"] is True and gone.called
    assert [s[0].split("/")[-1] if "accessrules" not in s[0] else "accessrules" for s in seen] == [
        "accessrules",
        "p1",
        "g1",
        lab["nat"]["id"],
        lab["route"]["id"],
    ]
    # access rules: one bulk partial update (the F67 probe's recorded shape), only the changed blocks,
    # whole blocks (literals kept); the rules' other fields, comments and positions are not sent
    assert params[0] == {"bulk": "true", "partialUpdate": "true"}
    assert seen[0][1] == [
        {"id": "r1", "type": "AccessRule", "sourceNetworks": {"objects": [ref(NEW)]}},
        {
            "id": "r2",
            "type": "AccessRule",
            # already there: the old one just goes
            "destinationNetworks": {
                "objects": [ref(NEW)],
                "literals": [{"type": "Host", "value": "198.51.100.7"}],
            },
        },
    ]
    assert params[1] == {} and seen[1][1]["destinationNetworks"] == {"objects": [ref(NEW)]}
    assert seen[1][1]["action"] == "FASTPATH" and "metadata" not in seen[1][1]  # full rule PUT
    assert seen[2][1]["objects"] == [ref(NEW), {"id": "x1", "type": "Network", "name": "keep"}]
    assert seen[3][1]["originalNetwork"] == ref(NEW)
    assert seen[4][1]["selectedNetworks"] == [ref(NEW)] and "metadata" not in seen[4][1]


async def test_replace_reports_references_it_cant_change(fmc: respx.MockRouter) -> None:
    """A VPN that uses the old object and a policy referencing it outside its rules are named; delete_old
    is then refused."""
    usage = [
        {"type": "FTDS2SVpn", "name": "mcp-w6-vpn", "id": "v1"},
        {"type": "AccessPolicy", "name": "mcp-w6-acp", "id": ACP},
        {"type": "Device", "name": "Static Route Setting under virtual router blue", "id": DEV},
    ]
    lab_for_replace(fmc, usage)
    async with Client(server()) as c:
        p = await run(
            c,
            "fmc_replace_object",
            {"old": "mcp-w6-a", "new": "mcp-w6-b", "scope": ["groups", "nat_rules"], "delete_old": True},
        )
    assert p["status"] == "blocked"
    assert p["preview"]["not_changed"] == [
        "FTDS2SVpn mcp-w6-vpn",
        "AccessPolicy mcp-w6-acp (access_rules not in scope)",
        f"static routes in virtual router 'blue' of device {DEV}",
    ]
    assert any(b.startswith("delete_old: the old object stays referenced") for b in p["blockers"])
    assert p["preview"]["counts"] == {"groups": 1}


async def test_replace_without_usage_searches_everything(fmc: respx.MockRouter) -> None:
    """Where FMC's usage API can't answer, every policy and device (capped) is searched."""
    lab_for_replace(fmc, None)
    async with Client(server()) as c:
        p = await run(c, "fmc_replace_object", {"old": "mcp-w6-a", "new": "mcp-w6-b"})
    assert p["status"] == "preview"
    assert p["preview"]["counts"] == {"access_rules": 2, "groups": 1, "nat_rules": 1, "static_routes": 1}
    assert p["preview"]["found_by"].startswith("a search of every policy")


def held_by(policy_id: str, name: str, user: str) -> httpx.Response:
    """FMC's lock list with one access policy locked (the 10.0.1 spec example's shape)."""
    lock = {
        "type": "PolicyLock",
        "policy": {"name": name, "id": policy_id, "type": "AccessPolicy"},
        "status": "LOCKED",
        "metadata": {"lockedByUser": {"name": user}},
    }
    return httpx.Response(200, json={"items": [{"policies": [lock]}], "paging": {"count": 1}})


async def test_replace_blocked_by_another_users_policy_lock(fmc: respx.MockRouter) -> None:
    """F76: the rules' access policy locked by someone else blocks the preview (FMC would refuse the bulk PUT
    part way through); the API user's own lock is a note. The rules carry no policy reference here, so the
    policy comes from their collection path."""
    lab_for_replace(fmc, None)
    locks = fmc.get(f"{CFG}/policy/operational/policylocks").mock(
        return_value=held_by(ACP, "mcp-w6-acp", "alice")
    )
    args = {"old": "mcp-w6-a", "new": "mcp-w6-b", "scope": ["access_rules"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_replace_object", args)
        assert p["status"] == "blocked"
        assert p["blockers"] == [
            "Access policy 'mcp-w6-acp' is locked by alice. FMC refuses changes to it until they unlock it "
            "(in the FMC UI, or fmc_policy_lock action='unlock' as that user; break_lock=True takes the "
            "lock away from them)."
        ]
        locks.mock(return_value=held_by(ACP, "mcp-w6-acp", "apiuser"))
        p = await run(c, "fmc_replace_object", args)
        assert p["status"] == "preview" and "locked by you" in p["preview"]["policy_lock"]
        locks.reset()
        p = await run(c, "fmc_replace_object", {**args, "scope": ["groups"]})  # no access rule changes
        assert p["status"] == "preview" and locks.call_count == 0


async def test_replace_blockers(fmc: respx.MockRouter) -> None:
    lab = lab_for_replace(fmc, None)
    net = obj("n1", "mcp-w6-net", "Network", value="192.0.2.0/24")
    fmc.get(f"{CFG}/object/networks").mock(side_effect=collection([net]))
    outer = obj(
        "g2",
        "mcp-w6-outer",
        "NetworkGroup",
        objects=[{"id": "g1", "type": "NetworkGroup", "name": "mcp-w6-grp"}],
    )
    fmc.get(f"{CFG}/object/networkgroups").mock(side_effect=collection([lab["group"], outer]))
    route = {**lab["route"], "gateway": {"object": ref(OLD)}, "selectedNetworks": []}
    fmc.get(f"{CFG}/devices/devicerecords/{DEV}/routing/ipv4staticroutes").mock(return_value=items([route]))
    empty_collections(fmc, "protocolportobjects", "portobjectgroups", "icmpv4objects", "icmpv6objects")
    fmc.get(f"{CFG}/object/hosts/{OLD['id']}").mock(return_value=httpx.Response(200, json=OLD))
    async with Client(server()) as c:
        p = await run(
            c, "fmc_replace_object", {"old": "mcp-w6-a", "new": "mcp-w6-net", "scope": ["static_routes"]}
        )
        assert p["status"] == "blocked" and "gateway must be a host object" in p["blockers"][0]
        p = await run(
            c, "fmc_replace_object", {"old": "mcp-w6-a", "new": "mcp-w6-outer", "scope": ["groups"]}
        )
        assert any("make a group contain itself" in b for b in p["blockers"])
        with pytest.raises(ToolError, match="same family"):
            await run(c, "fmc_replace_object", {"old": "mcp-w6-a", "new": "HTTPS"})
        with pytest.raises(ToolError, match="same object"):
            await run(c, "fmc_replace_object", {"old": "mcp-w6-a", "new": OLD["id"]})


async def test_replace_zone_names_interfaces_it_leaves(fmc: respx.MockRouter) -> None:
    """A zone's interfaces are set on the interface, so they stay in the old zone: the preview says so
    (rules on the new zone no longer match their traffic) and delete_old is refused. FMC's usage API
    refuses zones (400), so the policies are searched."""
    zones = REC["securityzones"]["items"]  # mcp-w6-zone-wan: 2 interfaces; mcp-w6-zone-spare: none
    fmc.get(f"{CFG}/object/securityzones").mock(return_value=items(zones))
    fmc.get(f"{CFG}/object/interfacegroups").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/operational/usage").mock(
        return_value=httpx.Response(400, json={"error": {"messages": [{"description": "not supported"}]}})
    )
    rule = {
        "id": "r1",
        "name": "mcp-w6-r1",
        "type": "AccessRule",
        "action": "ALLOW",
        "metadata": {"ruleIndex": 1, "domain": HERE},
        "sourceZones": {"objects": [ref(zones[0])]},
    }
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([{"id": ACP, "name": "mcp-w6-acp"}]))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP}/accessrules").mock(return_value=items([rule]))
    args = {
        "old": "mcp-w6-zone-wan",
        "new": "mcp-w6-zone-spare",
        "type": "security_zone",
        "scope": ["access_rules"],
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_replace_object", args)
        assert p["status"] == "preview", p
        assert p["preview"]["counts"] == {"access_rules": 1}
        (left,) = p["preview"]["not_changed"]
        assert left.startswith("2 device interface(s) in security_zone 'mcp-w6-zone-wan' (Ethernet0/0)")
        assert "fmc_update_interface" in left
        p = await run(c, "fmc_replace_object", {**args, "delete_old": True})
    assert p["status"] == "blocked"
    assert any(b.startswith("delete_old: the old object stays referenced") for b in p["blockers"])


def test_replace_nat_port_needs_a_port_object() -> None:
    """NAT port fields are IProtocolPortObject: a port group or ICMP object there is refused before any
    write (FMC would reject it after the rules and groups had changed)."""
    from fmc_mcp.tools.object_lifecycle import Walk, make_site, site_blockers

    port = obj("p-old", "mcp-w6-port", "ProtocolPortObject", protocol="TCP", port="8443")
    group = obj("pg-new", "mcp-w6-ports", "PortObjectGroup")
    nat = {
        **obj("n1", "", "FTDManualNatRule"),
        "originalSource": {"id": "h1", "type": "Host"},
        "originalDestinationPort": ref(port),
    }
    # site_blockers makes no FMC call, so the walk needs no client
    walk = Walk(None, None, HERE["id"], port, ref(group), {"nat_rules"})  # type: ignore[arg-type]
    site = make_site("nat_rules", "mcp-w6-nat manual #1", "path", nat, "p-old", ref(group))
    assert site is not None and site.fields == ["originalDestinationPort"]
    walk.sites.append(site)
    (msg,) = site_blockers(walk, group)
    assert "originalDestinationPort take one TCP/UDP port object, not a PortObjectGroup" in msg
    assert site_blockers(walk, obj("p-new", "mcp-w6-port2", "ProtocolPortObject")) == []


def test_swap_dedupes_and_counts() -> None:
    from fmc_mcp.tools.object_lifecycle import swap

    old, new = {"id": "A", "type": "Host"}, {"id": "b", "type": "Host", "name": "b"}
    node = {"objects": [old, new, {"id": "c"}], "literals": [{"value": "192.0.2.1"}], "metadata": {"id": "a"}}
    got, n = swap(node, "a", new)
    assert n == 1 and got["objects"] == [new, {"id": "c"}] and got["metadata"] == {"id": "a"}


# --- fmc_import_objects(mode='sync') --------------------------------------------------------------


async def test_sync_creates_updates_groups_and_orphans(fmc: respx.MockRouter) -> None:
    hosts = [
        obj("ha", "ipam-a", "Host", value="192.0.2.1"),
        obj("hb", "ipam-b", "Host", value="192.0.2.2", description="old"),
        obj("hc", "ipam-c", "Host", value="192.0.2.3"),
        obj("hd", "other-d", "Host", value="192.0.2.4"),
    ]
    fmc.get(f"{CFG}/object/hosts").mock(side_effect=collection(hosts))
    fmc.get(f"{CFG}/object/networks").mock(
        side_effect=collection([obj("n9", "ipam-net-old", "Network", value="198.51.100.0/24")])
    )
    empty_collections(fmc, "ranges", "fqdns")
    group = obj(
        "g1",
        "ipam-web",
        "NetworkGroup",
        objects=[ref(hosts[0]), ref(hosts[1]), {"id": "gx", "type": "NetworkGroup", "name": "nested"}],
        literals=[{"type": "Network", "value": "198.51.100.0/24"}],
    )
    fmc.get(f"{CFG}/object/networkgroups").mock(side_effect=collection([group]))
    post = fmc.post(f"{CFG}/object/hosts").mock(
        return_value=httpx.Response(201, json={"items": [obj("he", "ipam-e", "Host", value="192.0.2.5")]})
    )
    put_b = fmc.put(f"{CFG}/object/hosts/hb").mock(return_value=httpx.Response(200, json={}))
    put_g = fmc.put(f"{CFG}/object/networkgroups/g1").mock(return_value=httpx.Response(200, json={}))
    new_group = fmc.post(f"{CFG}/object/networkgroups").mock(return_value=httpx.Response(201, json={}))
    rows = [
        {"name": "ipam-a", "type": "host", "value": "192.0.2.1", "groups": ["ipam-web"]},
        {"name": "ipam-b", "type": "host", "value": "192.0.2.22"},
        {"name": "ipam-e", "type": "host", "value": "192.0.2.5", "groups": ["ipam-web", "ipam-new"]},
    ]
    args = {"objects": rows, "mode": "sync", "prefix": "ipam-"}
    async with Client(server(dangerous=False)) as c:
        p = await run(c, "fmc_import_objects", args)
        assert p["status"] == "preview", p
        got = p["preview"]
        assert [(r["name"], r["action"]) for r in got["rows"]] == [
            ("ipam-a", "unchanged"),
            ("ipam-b", "update"),
            ("ipam-e", "create"),
        ]
        assert got["rows"][1]["from"] == "192.0.2.2" and "description" not in got["rows"][1]
        assert got["groups"] == [
            {
                "group": "ipam-web",
                "type": "network_group",
                "action": "update",
                "add": ["ipam-e"],
                "remove": ["ipam-b"],
                "kept": ["nested", "198.51.100.0/24"],
            },
            {"group": "ipam-new", "type": "network_group", "action": "create", "members": ["ipam-e"]},
        ]
        # every type of the family is checked, not only the types the rows use
        assert [o["name"] for o in got["orphans"]] == ["ipam-c", "ipam-net-old"]
        assert got["summary"]["orphans"] == 2 and p["blast_radius"] == 4
        out = (await run(c, "fmc_import_objects", {**args, "confirm": p["confirm"]}))["result"]
    assert (
        out["created"] == 1
        and out["updated"] == 1
        and out["groups_updated"] == 1
        and out["groups_created"] == 1
    )
    assert [b["name"] for b in json.loads(post.calls.last.request.content)] == ["ipam-e"]
    body_b = json.loads(put_b.calls.last.request.content)
    assert body_b["value"] == "192.0.2.22" and body_b["description"] == "old"
    gbody = json.loads(put_g.calls.last.request.content)
    assert [o["name"] for o in gbody["objects"]] == ["ipam-a", "nested", "ipam-e"]
    assert gbody["literals"] == [{"type": "Network", "value": "198.51.100.0/24"}]
    assert json.loads(new_group.calls.last.request.content) == {
        "name": "ipam-new",
        "type": "NetworkGroup",
        "objects": [{"id": "he", "type": "Host", "name": "ipam-e"}],
    }


async def test_sync_row_shows_a_description_only_change(fmc: respx.MockRouter) -> None:
    """live-B2's third sync: only mcp-w6-sync-2's description changed, and the row read "value
    192.0.2.112, from 192.0.2.112". The row now says what changes: the description, not the value."""
    hosts = [
        obj("h2", "mcp-w6-sync-2", "Host", value="192.0.2.112", description="W6 F70 sync"),
        obj("h3", "mcp-w6-sync-3", "Host", value="192.0.2.103"),
    ]
    fmc.get(f"{CFG}/object/hosts").mock(side_effect=collection(hosts))
    empty_collections(fmc, "networks", "ranges", "fqdns", "networkgroups")
    put = fmc.put(f"{CFG}/object/hosts/h2").mock(return_value=httpx.Response(200, json={}))
    rows = [
        {"name": "mcp-w6-sync-2", "type": "host", "value": "192.0.2.112", "description": "W6 F70 sync 3"},
        {"name": "mcp-w6-sync-3", "type": "host", "value": "192.0.2.103"},
        {"name": "mcp-w6-sync-4", "type": "host", "value": "192.0.2.104", "description": "new"},
    ]
    fmc.post(f"{CFG}/object/hosts").mock(return_value=httpx.Response(201, json={"items": []}))
    args = {"objects": rows, "mode": "sync", "prefix": "mcp-w6-sync-"}
    async with Client(server(dangerous=False)) as c:
        p = await run(c, "fmc_import_objects", args)
        assert p["preview"]["rows"][:2] == [
            {
                "row": 1,
                "name": "mcp-w6-sync-2",
                "type": "host",
                "action": "update",
                "value": "192.0.2.112",
                "description": {"from": "W6 F70 sync", "to": "W6 F70 sync 3"},
            },
            {"row": 2, "name": "mcp-w6-sync-3", "type": "host", "action": "unchanged"},
        ]
        await run(c, "fmc_import_objects", {**args, "confirm": p["confirm"]})
    body = json.loads(put.calls.last.request.content)
    assert body["value"] == "192.0.2.112" and body["description"] == "W6 F70 sync 3"


async def test_sync_problems_and_modes(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(side_effect=collection([]))
    fmc.get(f"{CFG}/object/networks").mock(
        side_effect=collection([obj("n1", "ipam-n", "Network", value="192.0.2.0/24")])
    )
    empty_collections(fmc, "ranges", "fqdns", "networkgroups")
    async with Client(server(dangerous=False)) as c:
        p = await run(
            c,
            "fmc_import_objects",
            {"objects": [{"name": "ipam-n", "type": "host", "value": "192.0.2.9"}], "mode": "sync"},
        )
        assert p["status"] == "blocked" and "can't change an object's type" in p["blockers"][0]
        assert p["preview"]["orphans"].startswith("not checked")
        rows = [
            {"name": "ipam-x", "type": "host", "value": "192.0.2.9", "groups": ["ipam-y", " "]},
            {"name": "ipam-y", "type": "host", "value": "192.0.2.10"},
        ]
        p = await run(c, "fmc_import_objects", {"objects": rows, "mode": "sync"})
        assert p["status"] == "blocked"
        assert p["preview"]["problems"] == [
            "row 1 ('ipam-x'): an empty group name.",
            "group 'ipam-y': a network object already has that name.",
        ]
        with pytest.raises(ToolError, match="mode='sync' only"):
            await run(
                c,
                "fmc_import_objects",
                {"objects": [{"name": "x", "type": "host", "value": "192.0.2.9", "groups": ["g"]}]},
            )
        with pytest.raises(ToolError, match="mode='sync' only"):
            await run(
                c,
                "fmc_import_objects",
                {"objects": [{"name": "x", "type": "host", "value": "192.0.2.9"}], "prefix": "ipam-"},
            )


def test_nat_where_labels_auto_and_manual_rules() -> None:
    from fmc_mcp.tools.object_lifecycle import nat_where

    auto = {"kind": "auto", "section": "AUTO", "nat_type": "STATIC", "original_source": "web-srv"}
    assert nat_where("nat", auto) == "nat auto NAT of web-srv (STATIC)"
    manual = {"kind": "manual", "section": "BEFORE_AUTO", "index": 3}
    assert nat_where("nat", manual) == "nat manual NAT #3 (before_auto)"
    assert nat_where("nat", {"kind": "manual"}) == "nat manual NAT"


async def test_a_builtin_seen_from_a_leaf_is_refused_as_builtin(fmc: respx.MockRouter) -> None:
    """Wave 6 live-B2: in the leaf, any-ipv4 was refused as "defined in domain 'Global'" (right outcome, wrong
    reason: Global refuses it too). FMC 10.0.1's leaf rows (leaf_inherited_objects.json) say readOnly DOMAIN
    for its built-ins and for Global's own objects alike; the fixed id tells them apart."""
    rows = fixture("leaf_inherited_objects")["networkaddresses"]["items"]
    builtin = next(r for r in rows if r["name"] == "any-ipv4")
    global_own = next(r for r in rows if "-0ed3-" in r["id"] and r["metadata"]["domain"]["name"] == "Global")
    child = f"/api/fmc_config/v1/domain/{CHILD}"
    by_type: dict[str, list[dict[str, Any]]] = {"Host": [], "Network": [], "Range": []}
    for r in (builtin, global_own):
        by_type[r["type"]].append(r)
    for path, t in (("hosts", "Host"), ("networks", "Network"), ("ranges", "Range")):
        rows_t = by_type[t]
        fmc.get(f"{child}/object/{path}").mock(
            side_effect=collection(rows_t, unused={r["id"] for r in rows_t})
        )
    names = ["any-ipv4", global_own["name"]]
    async with Client(server()) as c:
        p = await run(
            c,
            "fmc_delete_objects",
            {"names": names, "types": ["host", "network", "range"], "domain": "Branch"},
        )
    reasons = {r["name"]: r["reason"] for r in p["preview"]["refused"]}
    assert reasons["any-ipv4"] == "FMC built-in (system) object, read-only in every domain"
    assert reasons[global_own["name"]] == "defined in domain 'Global' (only inherited here; delete it there)"


async def test_delete_objects_refuses_a_read_only_users_objects_for_the_role(fmc: respx.MockRouter) -> None:
    """#249: a read-only API user sees its objects readOnly reason RBAC. They are no built-ins any more, so
    the refusal names the role (FMC would answer 403); FMC's built-in stays a built-in."""

    def rbac(o: dict[str, Any]) -> dict[str, Any]:
        return {**o, "metadata": {"readOnly": {"state": True, "reason": "RBAC"}, "domain": HERE}}

    hosts = [
        rbac(obj("00000000-0000-0ed3-0000-0000000000e1", "mcp-w6-ro", "Host", value="192.0.2.1")),
        rbac(obj("dde11d62-288b-4b4c-92e0-1dad0496f14b", "any-ipv6", "Host", value="::/0")),
    ]
    fmc.get(f"{CFG}/object/hosts").mock(side_effect=collection(hosts, unused={o["id"] for o in hosts}))
    delete = fmc.delete(f"{CFG}/object/hosts")
    async with Client(server()) as c:
        p = await run(c, "fmc_delete_objects", {"names": ["mcp-w6-ro", "any-ipv6"], "types": ["host"]})
    refused = {r["name"]: r["reason"] for r in p["preview"]["refused"]}
    assert refused["mcp-w6-ro"].startswith("read-only for this API user's role (FMC: readOnly reason RBAC)")
    assert "built-in" in refused["any-ipv6"]
    assert not p["preview"].get("delete", {}).get("objects")
    assert not delete.called

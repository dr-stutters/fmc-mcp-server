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

from .conftest import CFG, fixture, items, make_settings

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
        inherited(obj("h5", "mcp-w6-global", "Host", value="192.0.2.5")),
        obj("h6", "mcp-w6-seed-keep", "Host", value="192.0.2.6"),
        obj("h7", "other", "Host", value="192.0.2.7"),
        # FMC 10.0.1 in a leaf: an ancestor's object can be read-only with no reason at all
        {
            **obj("h8", "mcp-w6-noreason", "Host", value="192.0.2.8"),
            "metadata": {"readOnly": {"state": True}, "domain": OTHER},
        },
    ]
    fmc.get(f"{CFG}/object/hosts").mock(
        side_effect=collection(hosts, unused={"h1", "h4", "h5", "h6", "h7", "h8"})
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

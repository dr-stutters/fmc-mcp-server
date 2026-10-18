"""fmc_find_address (F59): one address across objects, dynamic objects, rules, NAT, routes and VPN."""

import copy
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from fmc_mcp._core.testing import call_tool
from fmc_mcp.server import create_server
from fmc_mcp.tools import find_address

from .conftest import ACP_ID, CFG, empty, fixture, items, make_settings

EXTRA = fixture("find_address")
DYN = EXTRA["object/dynamicobjects"]["items"][0]
PF = EXTRA["policy/prefilterpolicies"]["items"][0]
TOPO = EXTRA["policy/ftds2svpns"]["items"][0]
DEVICE = fixture("ftd_device")


async def call(args: dict[str, Any]) -> Any:
    return await call_tool(
        create_server(make_settings()), "fmc_find_address", {"response_format": "json", **args}
    )


@pytest.fixture
def world(lab: respx.MockRouter) -> respx.MockRouter:
    """The recorded mcp-test-* policies and objects plus dynamic objects, prefilter and VPN collections."""
    lab.get(f"{CFG}/object/dynamicobjects").mock(
        return_value=httpx.Response(200, json=EXTRA["object/dynamicobjects"])
    )
    lab.get(f"{CFG}/object/dynamicobjects/{DYN['id']}/mappings").mock(return_value=items([]))
    lab.get(f"{CFG}/policy/prefilterpolicies").mock(
        return_value=httpx.Response(200, json=EXTRA["policy/prefilterpolicies"])
    )
    lab.get(f"{CFG}/policy/prefilterpolicies/{PF['id']}").mock(return_value=httpx.Response(200, json=PF))
    lab.get(f"{CFG}/policy/prefilterpolicies/{PF['id']}/prefilterrules").mock(return_value=empty())
    lab.get(f"{CFG}/policy/ftds2svpns").mock(return_value=empty())
    return lab


def rows_by(data: dict[str, Any], area: str) -> list[dict[str, Any]]:
    return [r for r in data["results"] if r["area"] == area]


async def test_host_ranked_across_objects_rules_and_nat(world: respx.MockRouter) -> None:
    data = await call({"address": "10.10.10.80"})
    first = data["results"][0]
    assert (first["rank"], first["match"], first["area"]) == (1, "exact", "objects")
    assert first["where"] == "Host mcp-test-web"
    objs = {r["where"]: r for r in rows_by(data, "objects")}
    assert objs["NetworkGroup mcp-test-servers"]["via"] == "mcp-test-web"
    assert objs["Network mcp-test-dmz-net"]["match"] == "contains"
    assert "NetworkGroup any" not in objs  # built-in object hidden unless include_broad
    rules = {r["where"]: r for r in rows_by(data, "access_rules")}
    web = rules["mcp-test-acp #1 mcp-test-allow-web (ALLOW)"]
    assert (web["side"], web["via"], web["value"]) == (
        "destination",
        "mcp-test-servers > mcp-test-web",
        "10.10.10.80",
    )
    assert rules["mcp-test-acp #3 mcp-test-redundant (ALLOW)"]["via"] == "mcp-test-web"
    ssh = rules["mcp-test-acp #2 mcp-test-ssh-admin (ALLOW)"]
    assert (ssh["side"], ssh["via"], ssh["match"], ssh["value"]) == (
        "source",
        "literal",
        "contains",
        "10.0.0.0/8",
    )
    nat = rows_by(data, "nat_rules")
    assert {(r["side"], r["match"]) for r in nat} == {
        ("original_source", "exact"),
        ("original_source", "contains"),
    }
    auto = next(r for r in nat if r["match"] == "exact")
    assert auto["where"].startswith("mcp-test-nat AUTO") and "(auto STATIC)" in auto["where"]
    # exact matches come before the ones that only contain the host, narrowest first
    matches = [r["match"] for r in data["results"]]
    assert matches == sorted(matches, key=lambda m: m != "exact")
    contains = [r for r in data["results"] if r["match"] == "contains"]
    assert contains[-1]["value"] == "10.0.0.0/8"
    assert data["by_area"]["access_rules"] == 3 and data["searched"]["access_policies"] == 1
    assert data["not_checked"][0].startswith("identity: no user-to-IP source")
    assert "hidden_broad_matches" not in data


async def test_network_query_finds_values_inside_it(world: respx.MockRouter) -> None:
    data = await call({"address": "10.10.20.0/24", "areas": ["objects", "access_rules"]})
    objs = {r["where"]: r["match"] for r in rows_by(data, "objects")}
    assert objs["Network mcp-test-app-net"] == "exact"
    assert objs["Host mcp-test-db"] == "inside"
    rules = {r["where"]: r for r in rows_by(data, "access_rules")}
    assert rules["mcp-test-acp #4 mcp-test-block-app (BLOCK)"]["match"] == "exact"
    assert rules["mcp-test-acp #2 mcp-test-ssh-admin (ALLOW)"]["value"] in ("10.10.20.5", "10.0.0.0/8")
    assert set(data["searched"]) == {"objects", "access_policies", "access_rules"}


async def test_dynamic_object_mapping_and_rule_through_it(world: respx.MockRouter) -> None:
    world.get(f"{CFG}/object/dynamicobjects/{DYN['id']}/mappings").mock(
        return_value=httpx.Response(200, json=EXTRA["mappings"])
    )
    rules = copy.deepcopy(fixture("accessrules"))
    rules["items"].append(
        {
            "id": "rule-quarantine",
            "name": "mcp-test-quarantine-block",
            "action": "BLOCK",
            "enabled": True,
            "metadata": {"ruleIndex": 8, "section": "Mandatory"},
            "sourceDynamicObjects": {
                "objects": [{"id": DYN["id"], "name": DYN["name"], "type": "DynamicObject"}]
            },
        }
    )
    world.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=httpx.Response(200, json=rules)
    )
    data = await call({"address": "10.99.1.10", "areas": ["dynamic_objects", "access_rules"]})
    dyn = rows_by(data, "dynamic_objects")
    assert dyn == [
        {
            "rank": dyn[0]["rank"],
            "match": "contains",
            "area": "dynamic_objects",
            "where": "dynamic object mcp-test-quarantine",
            "via": "mapping",
            "value": "10.99.1.0/24",
        }
    ]
    hit = next(r for r in rows_by(data, "access_rules") if "quarantine" in r["where"])
    assert (hit["side"], hit["via"]) == ("source", "mcp-test-quarantine > 10.99.1.0/24")
    # the mappings are read once per call, shared by both areas
    calls = [c for c in world.calls if c.request.url.path.endswith("/mappings")]
    assert len(calls) == 1


async def test_prefilter_rules_both_directions(world: respx.MockRouter) -> None:
    world.get(f"{CFG}/policy/prefilterpolicies/{PF['id']}/prefilterrules").mock(
        return_value=httpx.Response(200, json=EXTRA["prefilterrules"])
    )
    data = await call({"address": "10.10.10.80", "areas": ["prefilter_rules"]})
    rows = rows_by(data, "prefilter_rules")
    assert len(rows) == 1
    assert rows[0]["where"] == "Default Prefilter Policy #1 mcp-test-fastpath-web (PREFILTER FASTPATH)"
    assert (rows[0]["side"], rows[0]["via"]) == ("source (bidirectional)", "mcp-test-web")
    assert data["hidden_broad_matches"] == 1  # the 0.0.0.0/0 literal of mcp-test-block-any
    data = await call({"address": "192.0.2.7", "areas": ["prefilter_rules"], "include_broad": True})
    sides = {(r["where"].split(" (")[0], r["side"], r["match"]) for r in data["results"]}
    assert sides == {
        ("Default Prefilter Policy #1 mcp-test-fastpath-web", "destination (bidirectional)", "contains"),
        ("Default Prefilter Policy #2 mcp-test-block-any", "source", "contains"),
    }


async def test_static_route_gateway_and_hidden_default_route(world: respx.MockRouter) -> None:
    world.get(f"{CFG}/devices/devicerecords").mock(
        return_value=items([{"id": DEVICE["id"], "name": DEVICE["name"], "type": "Device"}])
    )
    world.get(f"{CFG}/devices/devicerecords/{DEVICE['id']}/routing/ipv4staticroutes").mock(
        return_value=httpx.Response(200, json=fixture("ftd_ipv4staticroutes"))
    )
    data = await call({"address": "192.0.2.10", "areas": ["static_routes"]})
    assert data["results"] == [
        {
            "rank": 1,
            "match": "exact",
            "area": "static_routes",
            "where": "mcp-ftd1: route via 192.0.2.10 on outside",
            "side": "gateway",
            "via": "literal",
            "value": "192.0.2.10",
        }
    ]
    assert data["hidden_broad_matches"] == 1  # any-ipv4 destination
    assert data["searched"] == {"devices": 1, "static_routes": 1}
    data = await call({"address": "192.0.2.10", "areas": ["static_routes"], "include_broad": True})
    assert [r["side"] for r in data["results"]] == ["gateway", "destination"]
    assert data["results"][1]["via"] == "any-ipv4"


async def test_vpn_protected_network_and_extranet_peer(world: respx.MockRouter) -> None:
    world.get(f"{CFG}/policy/ftds2svpns").mock(
        return_value=httpx.Response(200, json=EXTRA["policy/ftds2svpns"])
    )
    world.get(f"{CFG}/policy/ftds2svpns/{TOPO['id']}/endpoints").mock(
        return_value=httpx.Response(200, json=EXTRA["endpoints"])
    )
    data = await call({"address": "10.10.10.80", "areas": ["vpn"]})
    assert [(r["where"], r["side"], r["via"]) for r in data["results"]] == [
        ("VPN mcp-test-s2s: mcp-ftd1 (PEER)", "protected network", "mcp-test-dmz-net")
    ]
    data = await call({"address": "192.0.2.20", "areas": ["vpn"]})
    assert [(r["where"], r["side"], r["match"]) for r in data["results"]] == [
        ("VPN mcp-test-s2s: mcp-test-peer (PEER)", "peer address", "exact")
    ]
    assert data["searched"] == {"vpn_topologies": 1, "vpn_endpoints": 2}


async def test_device_scope_reads_only_its_policies_and_routes(world: respx.MockRouter) -> None:
    dev = {**DEVICE, "accessPolicy": {"id": ACP_ID, "name": "mcp-test-acp", "type": "AccessPolicy"}}
    world.get(f"{CFG}/devices/devicerecords").mock(return_value=items([dev]))
    world.get(f"{CFG}/devices/devicerecords/{DEVICE['id']}/routing/ipv4staticroutes").mock(
        return_value=empty()
    )
    nat_id = "00000000-0000-0ed3-0000-021474837632"
    world.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=items(
            [
                {
                    "policy": {"type": "FTDNatPolicy", "id": nat_id, "name": "mcp-test-nat"},
                    "targets": [{"id": DEVICE["id"], "type": "Device", "name": "mcp-ftd1"}],
                }
            ]
        )
    )
    world.get(f"{CFG}/policy/ftdnatpolicies/{nat_id}").mock(
        return_value=httpx.Response(200, json={"name": "mcp-test-nat", "id": nat_id, "type": "FTDNatPolicy"})
    )
    world.get(f"{CFG}/policy/accesspolicies/{ACP_ID}").mock(
        return_value=httpx.Response(
            200,
            json={
                **fixture("accesspolicies")["items"][0],
                "prefilterPolicySetting": {"id": PF["id"], "type": "PrefilterPolicy"},
            },
        )
    )
    data = await call(
        {
            "address": "10.10.10.80",
            "device": "mcp-ftd1",
            "areas": ["access_rules", "prefilter_rules", "nat_rules", "static_routes"],
        }
    )
    assert data["searched"] == {
        "access_policies": 1,
        "access_rules": 7,
        "prefilter_policies": 1,
        "prefilter_rules": 0,
        "nat_policies": 1,
        "nat_rules": 2,
        "devices": 1,
        "static_routes": 0,
    }
    paths = {c.request.url.path for c in world.calls}
    assert f"{CFG}/policy/ftds2svpns" not in paths


async def test_identity_hook_rows_rank_first(
    world: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def sessions(app: Any, ip: Any, domain: Any) -> list[dict[str, Any]]:
        return [{"where": f"user mcp-alice on {ip} (ISE pxGrid)", "via": "session", "side": "user"}]

    monkeypatch.setattr(find_address, "IDENTITY_LOOKUPS", [sessions])
    data = await call({"address": "10.10.10.80", "areas": ["identity", "objects"]})
    assert data["results"][0]["area"] == "identity"
    assert data["results"][0]["where"] == "user mcp-alice on 10.10.10.80 (ISE pxGrid)"
    assert "not_checked" not in data
    data = await call({"address": "10.10.10.0/24", "areas": ["identity"]})
    assert data["not_checked"] == ["identity: user sessions are looked up for a single address only"]


@pytest.mark.parametrize("bad", ["any", "0.0.0.0/0", "www.example.com", "10.1.1.300"])
async def test_refuses_any_and_names(world: respx.MockRouter, bad: str) -> None:
    with pytest.raises(ToolError, match="any|not one IP address"):
        await call({"address": bad})


async def test_markdown_table(world: respx.MockRouter) -> None:
    out = await call_tool(
        create_server(make_settings()), "fmc_find_address", {"address": "10.10.10.80", "areas": ["objects"]}
    )
    text = out if isinstance(out, str) else str(out)
    assert "| rank | match | area | where | side | via | value |" in text

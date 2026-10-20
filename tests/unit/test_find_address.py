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
    lab.get(f"{CFG}/analysis/activesessions").mock(return_value=empty())  # nobody logged in
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
    assert "not_checked" not in data and not rows_by(data, "identity")
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


async def test_identity_rows_come_from_fmc_sessions(world: respx.MockRouter) -> None:
    """The wired-in lookup (identity_sources.users_on_ip): FMC's identity sessions for the one IP."""
    session = {
        "currentIP": "10.10.10.80",
        "username": "alice",
        "realmName": "corp",
        "authenticationType": "Passive Authentication",
        "lastSeen": 1792334300,
    }
    route = world.get(f"{CFG}/analysis/activesessions").mock(return_value=items([session]))
    data = await call({"address": "10.10.10.80", "areas": ["identity", "objects"]})
    first = data["results"][0]
    assert (first["area"], first["where"], first["value"]) == ("identity", "user corp\\alice", "10.10.10.80")
    assert first["via"] == "identity session (Passive Authentication)"
    assert route.calls.last.request.url.params["currentIP"] == "10.10.10.80"
    # the lab's API role today: 403 becomes a warning that names the permission, the rest still answers
    world.get(f"{CFG}/analysis/activesessions").mock(
        return_value=httpx.Response(403, json={"error": {"messages": [{"description": "not authorized"}]}})
    )
    data = await call({"address": "10.10.10.80", "areas": ["identity", "objects"]})
    assert data["results"][0]["area"] == "objects"
    assert "Identity lookup failed (FMC refused" in data["warning"] and "Analysis > Users" in data["warning"]


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


# --- interfaces area (#205, F59 Wave 6 amendment) -------------------------------------------------------
# Eval on FMC 10.0.1: 'where is <inside subnet>/24 used on mcp-ftd1?' listed the object, the access rule and
# the NAT rule but not the device's own inside interface (the subnet's gateway).

ALLIF = fixture("ftd_allinterfaces")["ftdallinterfaces"]
HA = fixture("ha_failover")
DEVPATH = f"{CFG}/devices/devicerecords"


def with_devices(world: respx.MockRouter, devices: list[dict[str, Any]], pairs: list[Any] = ()) -> None:  # type: ignore[assignment]
    world.get(DEVPATH).mock(return_value=items(devices))
    world.get(f"{CFG}/devicehapairs/ftddevicehapairs").mock(return_value=items(list(pairs)))
    world.get(f"{CFG}/deviceclusters/ftddevicecluster").mock(return_value=items([]))


async def test_interface_address_and_connected_subnet(world: respx.MockRouter) -> None:
    with_devices(world, [DEVICE])
    reads = world.get(f"{DEVPATH}/{DEVICE['id']}/ftdallinterfaces").mock(
        return_value=httpx.Response(200, json=ALLIF)
    )
    data = await call({"address": "10.99.1.0/24", "areas": ["interfaces"]})
    assert data["results"] == [
        {
            "rank": 1,
            "match": "exact",
            "area": "interfaces",
            "where": "mcp-ftd1: interface inside",
            "side": "connected subnet",
            "via": "Ethernet0/1 (physical)",
            "value": "10.99.1.1/24",
        }
    ]
    assert data["searched"] == {"interface_devices": 1, "interfaces": 4}
    (row,) = (await call({"address": "10.99.1.1", "areas": ["interfaces"]}))["results"]
    assert (row["match"], row["side"]) == ("exact", "address")
    (row,) = (await call({"address": "10.99.100.50", "areas": ["interfaces"]}))["results"]
    assert (row["match"], row["side"], row["where"], row["via"]) == (
        "contains",
        "connected subnet",
        "mcp-ftd1: interface mcp-dmz",
        "Ethernet0/1 (subinterface)",
    )
    assert reads.call_count == 3  # one request per device and call
    # the eval's ask: with the device, the interface ranks with the object, rule and NAT rows
    data = await call({"address": "10.99.1.0/24", "device": "mcp-ftd1", "areas": ["interfaces", "objects"]})
    assert data["results"][0]["area"] == "interfaces" and data["results"][0]["match"] == "exact"


async def test_ha_pair_read_once_with_standby_addresses_and_failover_link(world: respx.MockRouter) -> None:
    pair = HA["pair"]
    units = [
        {**DEVICE, "id": pair["primary"]["id"], "name": "mcp-fw-ha-a"},
        {**DEVICE, "id": pair["secondary"]["id"], "name": "mcp-fw-ha-b"},
    ]
    with_devices(world, units, [pair])
    inside = {**ALLIF["items"][1], "ipv4": {"static": {"address": "192.0.2.1", "netmask": "24"}}}
    world.get(f"{DEVPATH}/{pair['primary']['id']}/ftdallinterfaces").mock(return_value=items([inside]))
    world.get(f"{CFG}/devicehapairs/ftddevicehapairs/{pair['id']}/monitoredinterfaces").mock(
        return_value=items(HA["monitoredinterfaces"])
    )
    (row,) = (await call({"address": "192.0.2.1", "areas": ["interfaces"]}))["results"]
    assert (row["where"], row["side"]) == ("mcp-fw-ha: interface inside", "address")
    row, subnet = (await call({"address": "192.0.2.2", "areas": ["interfaces"]}))["results"]
    assert (row["match"], row["where"], row["side"], row["via"], row["value"]) == (
        "exact",
        "mcp-fw-ha: interface inside",
        "standby address",
        "Ethernet0/1 (HA monitored interface)",
        "192.0.2.2/24",
    )
    assert (subnet["match"], subnet["side"]) == ("contains", "connected subnet")
    # one link for failover and state: listed once (the standby address, and the active one's subnet)
    rows = (await call({"address": "203.0.113.2", "areas": ["interfaces"]}))["results"]
    assert [(r["match"], r["where"], r["side"], r["via"]) for r in rows] == [
        ("exact", "mcp-fw-ha: failover link FAILOVER-LINK", "standby address", "Ethernet0/2 (failover link)"),
        (
            "contains",
            "mcp-fw-ha: failover link FAILOVER-LINK",
            "active connected subnet",
            "Ethernet0/2 (failover link)",
        ),
    ]
    data = await call({"address": "192.0.2.0/24", "areas": ["interfaces"]})
    assert data["searched"] == {"interface_devices": 1, "interfaces": 1}  # the pair, read on its primary
    assert [(r["match"], r["side"], r["value"]) for r in data["results"]] == [
        ("exact", "connected subnet", "192.0.2.1/24"),
        ("inside", "standby address", "192.0.2.2/24"),
    ]
    paths = {c.request.url.path for c in world.calls}
    assert f"{DEVPATH}/{pair['secondary']['id']}/ftdallinterfaces" not in paths


async def test_static_route_names_the_ftd_that_owns_the_next_hop(world: respx.MockRouter) -> None:
    branch = {**DEVICE, "id": "0f000000-0000-4000-8000-00000000000f", "name": "mcp-fw-branch1"}
    with_devices(world, [DEVICE, branch])
    world.get(f"{DEVPATH}/{DEVICE['id']}/ftdallinterfaces").mock(return_value=httpx.Response(200, json=ALLIF))
    outside = {**ALLIF["items"][0], "ipv4": {"static": {"address": "198.51.100.7", "netmask": "24"}}}
    world.get(f"{DEVPATH}/{branch['id']}/ftdallinterfaces").mock(return_value=items([outside]))
    route = copy.deepcopy(fixture("ftd_ipv4staticroutes"))
    route["items"][0]["gateway"] = {"literal": {"type": "Host", "value": "198.51.100.7"}}
    world.get(f"{DEVPATH}/{DEVICE['id']}/routing/ipv4staticroutes").mock(
        return_value=httpx.Response(200, json=route)
    )
    world.get(f"{DEVPATH}/{branch['id']}/routing/ipv4staticroutes").mock(return_value=empty())
    data = await call({"address": "198.51.100.7", "areas": ["interfaces", "static_routes"]})
    assert [(r["area"], r["where"], r["side"]) for r in data["results"]] == [
        ("interfaces", "mcp-fw-branch1: interface outside", "address"),
        (
            "static_routes",
            "mcp-ftd1: route via 198.51.100.7 on outside (next hop: mcp-fw-branch1 outside)",
            "gateway",
        ),
    ]

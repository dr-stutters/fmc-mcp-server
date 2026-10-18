"""Read-only live tests. They expect the seeded mcp-test-* objects and policies (docs/live-tests.md)."""

import json
from typing import Any

import pytest
from fastmcp import Client

from .live_env import need

pytestmark = pytest.mark.live


async def call(client: Client[Any], name: str, args: dict[str, Any] | None = None) -> Any:
    result = await client.call_tool(name, args or {})
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)  # type: ignore[union-attr]


@pytest.fixture
async def seeded(client: Client[Any]) -> None:
    data = await call(
        client, "fmc_list_policies", {"kind": "access", "name": "mcp-test-acp", "response_format": "json"}
    )
    if not data["results"]:
        pytest.skip("mcp-test-* objects not seeded (docs/live-tests.md)")


async def test_domains_and_devices(client: Client[Any]) -> None:
    domains = await call(client, "fmc_list_domains", {"response_format": "json"})
    assert any(d["default"] for d in domains["results"])
    for tool in ("fmc_list_devices", "fmc_list_ha_pairs", "fmc_list_clusters", "fmc_list_deployable_devices"):
        data = await call(client, tool, {"response_format": "json"})
        assert isinstance(data["results"], list)


async def test_access_policy(client: Client[Any], seeded: None) -> None:
    data = await call(client, "fmc_get_access_policy", {"policy": "mcp-test-acp"})
    assert data["rules"]["total"] >= 7
    rules = await call(client, "fmc_list_access_rules", {"policy": "mcp-test-acp", "response_format": "json"})
    names = [r["name"] for r in rules["results"]]
    assert names.index("mcp-test-allow-web") < names.index("mcp-test-block-app")


async def test_rule_lookup_and_shadowing(client: Client[Any], seeded: None) -> None:
    data = await call(
        client,
        "fmc_rule_lookup",
        {"policy": "mcp-test-acp", "source": "192.0.2.1", "destination": "10.10.10.80", "port": 443},
    )
    assert data["matched_rule"]["name"] == "mcp-test-allow-web"
    shadow = await call(client, "fmc_shadowed_rules", {"policy": "mcp-test-acp"})
    assert {f["rule"]["name"] for f in shadow["findings"]} >= {"mcp-test-redundant", "mcp-test-shadowed"}


async def test_objects(client: Client[Any], seeded: None) -> None:
    found = await call(client, "fmc_find_object", {"value": "10.10.20.5", "response_format": "json"})
    assert "mcp-test-db" in {r["name"] for r in found["results"]}
    ports = await call(client, "fmc_find_object", {"value": "tcp/8443", "response_format": "json"})
    assert "mcp-test-web-ports" in {r["name"] for r in ports["results"]}
    used = await call(client, "fmc_where_used", {"object": "mcp-test-db", "type": "host"})
    assert used["in_use"] and any(r.get("name") == "mcp-test-ssh-admin" for r in used["rules"])
    unused = await call(client, "fmc_unused_objects", {"types": ["host"], "response_format": "json"})
    assert "mcp-test-unused" in {r["name"] for r in unused["results"]}
    obj = await call(client, "fmc_get_object", {"object": "mcp-test-servers"})
    assert obj["members"] == ["mcp-test-web", "mcp-test-app-net", "10.10.40.0/24"]


async def test_nat_and_others(client: Client[Any], seeded: None) -> None:
    nat = await call(client, "fmc_list_nat_rules", {"policy": "mcp-test-nat", "response_format": "json"})
    assert {r["kind"] for r in nat["results"]} == {"auto", "manual"}
    pre = await call(client, "fmc_list_prefilter_rules", {"response_format": "json"})
    assert pre["default_action"]
    ips = await call(client, "fmc_list_policies", {"kind": "intrusion", "response_format": "json"})
    assert ips["results"]
    audit = await call(client, "fmc_list_audit_records", {"limit": 5, "response_format": "json"})
    assert audit["results"]


async def test_spec_tools(client: Client[Any]) -> None:
    hits = await call(client, "fmc_search_spec", {"query": "accessrules"})
    assert any("accessrules" in h["name"] for h in hits["results"])
    ver = await call(
        client, "fmc_api_call", {"method": "GET", "path": "/api/fmc_platform/v1/info/serverversion"}
    )
    assert ver["items"][0]["serverVersion"]


async def test_api_call_fills_domain(client: Client[Any]) -> None:
    hosts = await call(
        client,
        "fmc_api_call",
        {"method": "GET", "path": "/api/fmc_config/v1/domain/{domainUUID}/object/hosts"},
    )
    assert "items" in hosts


async def test_audit_window_reaches_past_fmcs_100_record_cap(client: Client[Any]) -> None:
    """F26: FMC returns only the newest 100 audit records per query; the tool slices the window."""
    for _ in range(3):  # make sure the window holds more than 100 records (each call logs GETs)
        await call(
            client, "fmc_list_audit_records", {"since_minutes": 5, "limit": 1, "response_format": "json"}
        )
    data = await call(
        client,
        "fmc_list_audit_records",
        {"since_minutes": 60, "changes_only": False, "limit": 1000, "response_format": "json"},
    )
    assert data["records_read"] > 100
    times = [r["time"] for r in data["results"]]
    assert times == sorted(times, reverse=True)


async def test_interface_kinds_and_create_preview(client: Client[Any]) -> None:
    """F58 (read-only): every interface kind lists on FMC_LIVE_DEVICE, and fmc_create_interface previews a
    loopback (never confirmed: nothing changes)."""
    device = need("FMC_LIVE_DEVICE")
    kinds = ["physical", "subinterface", "etherchannel", "vti", "loopback", "bridge_group"]
    data = await call(
        client, "fmc_list_device_interfaces", {"device": device, "kinds": kinds, "response_format": "json"}
    )
    assert any(r["kind"] == "physical" for r in data["results"])
    preview = await call(
        client,
        "fmc_create_interface",
        {"device": device, "kind": "loopback", "logical_name": "mcp-f58-lo", "ipv4": "198.51.100.58/32"},
    )
    assert (
        preview["status"] in ("preview", "blocked")
        and preview["preview"]["body"]["type"] == "LoopbackInterface"
    )

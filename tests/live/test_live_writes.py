"""Live write tests: preview, confirm, verify and clean up `mcp-test-w-*` objects."""

import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio
from fastmcp import Client

pytestmark = pytest.mark.live

P = "mcp-test-w"


async def call(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    result = await client.call_tool(name, args)
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)  # type: ignore[union-attr]


async def apply(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    preview = await call(client, name, args)
    assert preview["status"] == "preview", preview
    done = await call(client, name, {**args, "confirm": preview["confirm"]})
    assert done["status"] == "applied", done
    return done


async def try_apply(client: Client[Any], name: str, args: dict[str, Any]) -> None:
    try:
        preview = await call(client, name, args)
        if preview.get("status") == "preview":
            await call(client, name, {**args, "confirm": preview["confirm"]})
    except Exception:  # cleanup is best-effort
        pass


async def cleanup(client: Client[Any]) -> None:
    status = await call(client, "fmc_status", {})
    domain = status["fmc"]["default_domain"]["uuid"]
    for kind, coll in (("access", "accesspolicies"), ("nat", "ftdnatpolicies")):
        found = await call(client, "fmc_list_policies", {"kind": kind, "name": P, "response_format": "json"})
        for pol in found["results"]:
            path = f"/api/fmc_config/v1/domain/{domain}/policy/{coll}/{pol['id']}"
            await try_apply(client, "fmc_api_call", {"method": "DELETE", "path": path})
    for obj, typ in (
        (f"{P}-group", "network_group"),
        (f"{P}-host", "host"),
        (f"{P}-host2", "host"),
        (f"{P}-net", "network"),
        (f"{P}-tcp", "port"),
        (f"{P}-zone", "security_zone"),
    ):
        await try_apply(client, "fmc_delete_object", {"object": obj, "type": typ})


@pytest_asyncio.fixture(loop_scope="session")
async def clean(client: Client[Any]) -> AsyncIterator[None]:
    await cleanup(client)
    yield
    await cleanup(client)


async def test_object_lifecycle(client: Client[Any], clean: None) -> None:
    await apply(client, "fmc_create_object", {"type": "host", "name": f"{P}-host", "value": "10.77.0.5"})
    await apply(client, "fmc_create_object", {"type": "host", "name": f"{P}-host2", "value": "10.77.0.6"})
    await apply(client, "fmc_create_object", {"type": "network", "name": f"{P}-net", "value": "10.77.1.0/24"})
    await apply(client, "fmc_create_object", {"type": "port", "name": f"{P}-tcp", "value": "tcp/9443"})
    dup = await call(client, "fmc_create_object", {"type": "host", "name": f"{P}-host", "value": "10.77.0.5"})
    assert dup["status"] == "blocked"

    await apply(client, "fmc_update_object", {"object": f"{P}-host", "type": "host", "value": "10.77.0.7"})
    got = await call(client, "fmc_get_object", {"object": f"{P}-host", "type": "host"})
    assert got["value"] == "10.77.0.7"

    await apply(
        client,
        "fmc_create_group",
        {"kind": "network", "name": f"{P}-group", "members": [f"{P}-host", "10.77.9.0/24"]},
    )
    await apply(
        client, "fmc_update_group", {"group": f"{P}-group", "add": [f"{P}-net"], "remove": ["10.77.9.0/24"]}
    )
    group = await call(client, "fmc_get_object", {"object": f"{P}-group", "type": "network_group"})
    assert sorted(group["members"]) == sorted([f"{P}-host", f"{P}-net"])

    # in use -> delete blocked
    blocked = await call(client, "fmc_delete_object", {"object": f"{P}-host", "type": "host"})
    assert blocked["status"] == "blocked" and "in use" in blocked["blockers"][0]

    await apply(client, "fmc_create_security_zone", {"name": f"{P}-zone"})
    await apply(client, "fmc_delete_object", {"object": f"{P}-host2", "type": "host"})


async def test_access_rules(client: Client[Any], clean: None) -> None:
    await apply(client, "fmc_create_object", {"type": "host", "name": f"{P}-host", "value": "10.77.0.5"})
    await apply(client, "fmc_create_security_zone", {"name": f"{P}-zone"})
    await apply(client, "fmc_create_access_policy", {"name": f"{P}-acp", "default_action": "BLOCK"})
    acp = f"{P}-acp"
    await apply(
        client,
        "fmc_create_access_rule",
        {
            "policy": acp,
            "name": "allow-web",
            "action": "ALLOW",
            "source_zones": [f"{P}-zone"],
            "destination_networks": [f"{P}-host", "10.77.5.0/24"],
            "destination_ports": ["HTTPS", "tcp/8080"],
            "comment": "created by live test",
        },
    )
    await apply(
        client,
        "fmc_create_access_rule",
        {"policy": acp, "name": "block-all", "action": "BLOCK", "log": "none"},
    )
    await apply(
        client,
        "fmc_create_access_rule",
        {"policy": acp, "name": "trust-first", "action": "TRUST", "insert_before": 1, "log": "none"},
    )
    rules = await call(client, "fmc_list_access_rules", {"policy": acp, "response_format": "json"})
    assert [r["name"] for r in rules["results"]] == ["trust-first", "allow-web", "block-all"]
    assert rules["results"][1]["dst_ports"] == ["HTTPS", "TCP/8080"]

    lookup = await call(
        client,
        "fmc_rule_lookup",
        {
            "policy": acp,
            "source": "1.2.3.4",
            "destination": "10.77.0.5",
            "port": 8080,
            "source_zone": f"{P}-zone",
        },
    )
    assert lookup["matched_rule"]["name"] == "trust-first"

    await apply(client, "fmc_update_access_rule", {"policy": acp, "rule": "trust-first", "move_to": 3})
    await apply(client, "fmc_update_access_rule", {"policy": acp, "rule": "block-all", "enabled": False})
    rules = await call(client, "fmc_list_access_rules", {"policy": acp, "response_format": "json"})
    assert [(r["name"], r["enabled"]) for r in rules["results"]] == [
        ("allow-web", True),
        ("block-all", False),
        ("trust-first", True),
    ]
    await apply(client, "fmc_delete_access_rule", {"policy": acp, "rule": "block-all"})
    rules = await call(client, "fmc_list_access_rules", {"policy": acp, "response_format": "json"})
    assert len(rules["results"]) == 2


async def test_nat_rules(client: Client[Any], clean: None) -> None:
    await apply(client, "fmc_create_object", {"type": "host", "name": f"{P}-host", "value": "10.77.0.5"})
    await apply(client, "fmc_create_object", {"type": "host", "name": f"{P}-host2", "value": "10.77.0.6"})
    await apply(client, "fmc_create_nat_policy", {"name": f"{P}-nat"})
    nat = f"{P}-nat"
    await apply(
        client,
        "fmc_create_nat_rule",
        {"policy": nat, "kind": "auto", "original_source": f"{P}-host", "translated_source": f"{P}-host2"},
    )
    await apply(
        client,
        "fmc_create_nat_rule",
        {
            "policy": nat,
            "kind": "manual",
            "original_source": f"{P}-host2",
            "translated_source": f"{P}-host",
            "description": "live test",
        },
    )
    rules = await call(client, "fmc_list_nat_rules", {"policy": nat, "response_format": "json"})
    manual = next(r for r in rules["results"] if r["kind"] == "manual")
    await apply(client, "fmc_update_nat_rule", {"policy": nat, "rule_id": manual["id"], "enabled": False})
    rules = await call(client, "fmc_list_nat_rules", {"policy": nat, "response_format": "json"})
    assert next(r for r in rules["results"] if r["kind"] == "manual")["enabled"] is False
    await apply(client, "fmc_delete_nat_rule", {"policy": nat, "rule_id": manual["id"]})
    rules = await call(client, "fmc_list_nat_rules", {"policy": nat, "response_format": "json"})
    assert [r["kind"] for r in rules["results"]] == ["auto"]

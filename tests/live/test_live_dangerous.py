"""Dangerous tools against the lab. The lab FMC manages no devices, so deploy can only be checked for
its 'nothing to deploy' path; registration and HA are covered by unit tests with mocked FMC replies."""

import json
from typing import Any

import pytest
from fastmcp import Client

pytestmark = pytest.mark.live


async def call(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    result = await client.call_tool(name, args)
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)  # type: ignore[union-attr]


async def test_deploy_with_nothing_pending(client: Client[Any]) -> None:
    pending = await call(client, "fmc_list_deployable_devices", {"response_format": "json"})
    if pending["results"]:
        pytest.skip("devices have pending changes; not deploying from a test")
    out = await call(client, "fmc_deploy", {})
    assert out["status"] == "blocked"


async def test_delete_policy(client: Client[Any]) -> None:
    name = "mcp-test-d-acp"
    found = await call(
        client, "fmc_list_policies", {"kind": "access", "name": name, "response_format": "json"}
    )
    if not found["results"]:
        preview = await call(client, "fmc_create_access_policy", {"name": name})
        await call(client, "fmc_create_access_policy", {"name": name, "confirm": preview["confirm"]})
    preview = await call(client, "fmc_delete_policy", {"kind": "access", "policy": name})
    assert preview["status"] == "preview" and preview["preview"]["assigned_to"] == []
    done = await call(
        client, "fmc_delete_policy", {"kind": "access", "policy": name, "confirm": preview["confirm"]}
    )
    assert done["status"] == "applied"
    found = await call(
        client, "fmc_list_policies", {"kind": "access", "name": name, "response_format": "json"}
    )
    assert found["results"] == []

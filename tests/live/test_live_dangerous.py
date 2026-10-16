"""Dangerous tools against the lab that don't need a device: deploy's 'nothing to deploy' path and
policy deletion. Registration, deploy and rollback against a real FTD are in test_live_ftd.py; HA
needs two FTDs and is covered by unit tests with mocked FMC replies."""

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


async def test_deploy_refused_outside_deploy_window() -> None:
    """F18: with FMC_DEPLOY_WINDOW closed, a deploy preview is blocked and says when it next opens.
    A second server as the same user: its login ends the shared client's session, which recovers."""
    from datetime import UTC, datetime, timedelta

    from fmc_mcp._core.testing import live_settings
    from fmc_mcp.config import Settings
    from fmc_mcp.server import create_server

    start = datetime.now(UTC) + timedelta(hours=12)  # a one-minute window 12 hours away: closed now
    window = f"daily {start:%H:%M}-{start + timedelta(minutes=1):%H:%M} UTC"
    settings = live_settings(
        Settings, "FMC_", deploy_window=window, mcp_enable_writes=True, mcp_enable_dangerous=True
    )
    async with Client(create_server(settings)) as c:
        out = await call(c, "fmc_deploy", {})
    assert out["status"] == "blocked", out
    assert "FMC_DEPLOY_WINDOW" in json.dumps(out) and "next opens" in json.dumps(out), out

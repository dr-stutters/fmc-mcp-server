"""F19 multi-domain against a leaf domain (FMC_LIVE_LEAF_DOMAIN, e.g. Global/mcp-test-leaf) that holds the FTD
FMC_LIVE_DEVICE. Skipped without them (docs/live-tests.md) or when FMC has no such domain."""

import json
from typing import Any

import pytest
from fastmcp import Client

from .live_env import live_env, need

pytestmark = pytest.mark.live

LEAF = live_env("FMC_LIVE_LEAF_DOMAIN")


async def call(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    result = await client.call_tool(name, args)
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)  # type: ignore[union-attr]


async def leaf(client: Client[Any]) -> dict[str, Any]:
    need("FMC_LIVE_LEAF_DOMAIN")
    out = await call(client, "fmc_list_domains", {"response_format": "json"})
    rows = {r["name"]: r for r in out["results"]}
    if LEAF not in rows:
        pytest.skip(f"FMC has no domain {LEAF} (FMC_LIVE_LEAF_DOMAIN)")
    return rows


async def test_domain_tree(client: Client[Any]) -> None:
    device = need("FMC_LIVE_DEVICE")
    rows = await leaf(client)
    assert rows["Global"]["leaf"] is False
    assert rows[LEAF]["leaf"] is True and device in (rows[LEAF].get("devices") or [])


async def test_object_lifecycle_in_leaf_and_inherited_block(client: Client[Any]) -> None:
    await leaf(client)
    name, args = "mcp-test-md-host", {"type": "host", "value": "10.255.7.7", "domain": LEAF}
    preview = await call(client, "fmc_create_object", {"name": name, **args})
    assert preview["status"] == "preview" and preview["preview"]["domain"] == LEAF, preview
    await call(client, "fmc_create_object", {"name": name, **args, "confirm": preview["confirm"]})
    try:
        # the leaf object is not visible in Global (objects inherit downwards only)
        found = await call(client, "fmc_list_objects", {"name_or_value": name, "response_format": "json"})
        assert not [r for r in found["results"] if r.get("name") == name]
        # a Global object is visible in the leaf but can only be changed in Global
        blocked = await call(
            client,
            "fmc_update_object",
            {"object": "mcp-test-web", "type": "host", "description": "x", "domain": LEAF},
        )
        assert blocked["status"] == "blocked" and "defined in domain 'Global'" in blocked["blockers"][0]
    finally:
        d = await call(client, "fmc_delete_object", {"object": name, "type": "host", "domain": LEAF})
        await call(
            client,
            "fmc_delete_object",
            {"object": name, "type": "host", "domain": LEAF, "confirm": d["confirm"]},
        )


async def test_device_tools_from_global_reach_the_leaf_device(client: Client[Any]) -> None:
    """Device changes from Global go to the device's leaf domain (FMC refuses them in Global)."""
    device = need("FMC_LIVE_DEVICE")
    await leaf(client)
    out = await call(client, "fmc_list_device_interfaces", {"device": device, "response_format": "json"})
    assert out["results"], out
    routes = await call(client, "fmc_list_routes", {"device": device, "response_format": "json"})
    assert "results" in routes

"""F14 admin operations against the lab FMC: versions, backups list, a health threshold changed and
reverted, and a per-device object override set, listed and removed (mcp-test-unused on mcp-ftd1)."""

import json
from typing import Any

import pytest
from fastmcp import Client

from .test_live_ftd import DEVICE, apply, call, needs_ftd

pytestmark = pytest.mark.live


async def test_versions_and_backups(client: Client[Any]) -> None:
    status = await call(client, "fmc_upgrade_status", {"response_format": "json"})
    assert status["fmc"]["version"] and status["fmc"]["vdb"]
    backups = await call(client, "fmc_list_backups", {"response_format": "json"})
    assert "results" in backups


async def test_health_threshold_change_and_revert(client: Client[Any]) -> None:
    pols = await call(client, "fmc_get_health_policy", {"response_format": "json"})
    device_pol = next(p for p in pols["results"] if p["type"] == "DevicePolicy")
    one = await call(client, "fmc_get_health_policy", {"policy": device_pol["id"], "response_format": "json"})
    cpu = next(m for m in one["modules"] if m["module"] == "hm_cpu")
    old = cpu["warning"]
    args = {"policy": device_pol["id"], "module": "hm_cpu"}
    await apply(client, "fmc_update_health_policy", {**args, "warning": old - 5})
    try:
        again = await call(
            client, "fmc_get_health_policy", {"policy": device_pol["id"], "response_format": "json"}
        )
        assert next(m for m in again["modules"] if m["module"] == "hm_cpu")["warning"] == old - 5
    finally:
        await apply(client, "fmc_update_health_policy", {**args, "warning": old})


@needs_ftd
async def test_object_override_on_device(client: Client[Any]) -> None:
    args = {"object": "mcp-test-unused", "type": "host", "device": DEVICE}
    await apply(client, "fmc_set_object_override", {**args, "value": "10.99.99.97"})
    try:
        out = await call(
            client,
            "fmc_list_object_overrides",
            {"object": "mcp-test-unused", "type": "host", "response_format": "json"},
        )
        assert [r["value"] for r in out["results"]] == ["10.99.99.97"], out
        assert out["default_value"] == "10.99.99.99"
    finally:
        await apply(client, "fmc_set_object_override", {**args, "remove": True})
    out = await call(
        client,
        "fmc_list_object_overrides",
        {"object": "mcp-test-unused", "type": "host", "response_format": "json"},
    )
    assert not out["results"], json.dumps(out)

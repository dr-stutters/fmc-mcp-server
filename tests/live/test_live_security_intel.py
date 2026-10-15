"""F21 Security Intelligence on the real FTD: block the outside gateway for mcp-test-ftd-acp through the SI
network block list, deploy, packet tracer shows the SI drop; unblock and deploy again."""

import json
from typing import Any

import pytest
from fastmcp import Client

from .test_live_ftd import ACP, DEVICE, apply, call, deploy, fresh_port, needs_ftd

pytestmark = pytest.mark.live

TARGET = "198.18.128.1"


async def trace(client: Client[Any]) -> dict[str, Any]:
    out = await call(
        client,
        "fmc_packet_tracer",
        {
            "device": DEVICE,
            "input_interface": "inside",
            "protocol": "tcp",
            "source_ip": "10.99.1.10",
            "source_port": fresh_port(),
            "destination_ip": TARGET,
            "destination_port": 443,
            "verbose": True,
        },
    )
    return dict(out["results"][0])


@needs_ftd
async def test_si_block_and_unblock(client: Client[Any]) -> None:
    await apply(client, "fmc_si_block", {"policy": ACP, "entries": [TARGET]})
    try:
        si = await call(client, "fmc_get_security_intelligence", {"policy": ACP, "response_format": "json"})
        assert f"mcp-si-{TARGET}" in si["network_block"], si
        await deploy(client, "mcp live test: SI block", ignore_warning=True)
        res = await trace(client)
        assert res["action"] == "drop", res
        assert (
            "security" in json.dumps(res).lower()
            or "blacklist" in json.dumps(res).lower()
            or "block" in json.dumps(res).lower()
        ), res
    finally:
        await apply(client, "fmc_si_block", {"policy": ACP, "entries": [TARGET], "action": "unblock"})
        await deploy(client, "mcp live test: SI unblock", ignore_warning=True)
    si = await call(client, "fmc_get_security_intelligence", {"policy": ACP, "response_format": "json"})
    assert f"mcp-si-{TARGET}" not in si["network_block"]

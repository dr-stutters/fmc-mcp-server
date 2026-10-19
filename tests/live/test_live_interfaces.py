"""F58 read-only live check (needs FMC_LIVE_DEVICE): every interface kind lists on the device, and
fmc_create_interface previews a loopback. The preview is never confirmed, so nothing changes."""

import json
from typing import Any

import pytest
from fastmcp import Client

from .live_env import need

pytestmark = pytest.mark.live


async def call(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    result = await client.call_tool(name, args)
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)  # type: ignore[union-attr]


async def test_interface_kinds_and_create_preview(client: Client[Any]) -> None:
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
    assert preview["status"] in ("preview", "blocked")
    assert preview["preview"]["body"]["type"] == "LoopbackInterface"

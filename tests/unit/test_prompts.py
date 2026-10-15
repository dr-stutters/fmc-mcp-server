from typing import Any

import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools.prompts import why_blocked_text

from .conftest import make_settings


def test_why_blocked_text_with_everything_known() -> None:
    text = why_blocked_text("10.99.1.10", "198.18.134.76", "TCP", 23, "mcp-ftd1", "inside", "acp")
    assert "tcp 10.99.1.10 -> 198.18.134.76 port 23" in text
    assert "destination_port=23" in text and 'input_interface="inside"' in text
    assert "`fmc_list_policy_assignments`" not in text  # policy given
    steps = [
        "fmc_rule_lookup",
        "fmc_packet_tracer",
        "fmc_get_hit_counts",
        "fmc_pending_changes",
        "fmc_list_deployments",
        "fmc_list_audit_records",
    ]
    positions = [text.index(f"`{s}`") for s in steps]
    assert positions == sorted(positions)
    assert "no-v4-adjacency" in text and "preview" in text


def test_why_blocked_text_icmp_finds_context() -> None:
    text = why_blocked_text("10.99.1.10", "8.8.8.8", "icmp", None, None, None, None)
    assert "destination_port" not in text and "port=" not in text
    assert "`fmc_list_devices`" in text and "`fmc_list_policy_assignments`" in text


async def test_prompt_listed_and_rendered(fmc: respx.MockRouter) -> None:
    async with Client(create_server(make_settings())) as c:
        prompts = {p.name: p for p in await c.list_prompts()}
        assert "fmc_why_blocked" in prompts
        r = await c.get_prompt(
            "fmc_why_blocked", {"source": "10.0.0.1", "destination": "10.0.0.2", "port": "443"}
        )
        body: Any = r.messages[0].content
        assert "port 443" in body.text

"""F16: the read tier as the read-only FMC user (role mcp-ro), the write user's role, and the 403 matrix.

Needs the users from scripts/seed_access.py: FMC_RO_USERNAME / FMC_RO_PASSWORD (role mcp-ro) in .env, and
FMC_USERNAME (role mcp-rw) for the rest of the live suite. The read tier must work completely as mcp-ro;
`test_ro_user_cannot_write` proves FMC itself refuses a write from that account (not just the MCP tiers).
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from fastmcp import Client

from fmc_mcp._core.testing.least_privilege import read_tier_report, readonly_live_settings
from fmc_mcp.config import Settings
from fmc_mcp.server import create_server

pytestmark = pytest.mark.live

DEVICE = os.environ.get("FMC_LIVE_DEVICE", "mcp-ftd1")
POLICY = "mcp-test-acp"
FTD_POLICY = "mcp-test-ftd-acp"

# Objects from scripts/seed_lab.py and the ftd-fmc lab (mcp-ftd1). Device tools need the FTD online.
SAMPLES: dict[str, dict[str, Any]] = {
    "fmc_get_device": {"device": DEVICE},
    "fmc_list_device_interfaces": {"device": DEVICE},
    "fmc_get_access_policy": {"policy": POLICY},
    "fmc_list_access_rules": {"policy": POLICY},
    "fmc_get_access_rule": {"policy": POLICY, "rule": "mcp-test-allow-web"},
    "fmc_list_nat_rules": {"policy": "mcp-test-nat"},
    "fmc_get_object": {"object": "mcp-test-web"},
    "fmc_find_object": {"value": "10.10.10.80"},
    "fmc_where_used": {"object": "mcp-test-web"},
    "fmc_rule_lookup": {"policy": POLICY, "source": "10.10.20.5", "destination": "10.10.10.80"},
    "fmc_shadowed_rules": {"policy": POLICY},
    "fmc_pending_changes": {"device": DEVICE},
    "fmc_list_routes": {"device": DEVICE},
    "fmc_run_show_command": {"device": DEVICE, "command": "show version"},
    "fmc_packet_tracer": {
        "device": DEVICE,
        "input_interface": "inside",
        "protocol": "icmp",
        "source_ip": "10.99.1.10",
        "destination_ip": "198.18.128.1",
    },
    "fmc_get_hit_counts": {"policy": FTD_POLICY, "device": DEVICE},
    "fmc_device_health": {"device": DEVICE},
    "fmc_get_platform_settings": {"policy": "mcp-test-ps"},
    "fmc_get_routing": {"device": DEVICE},
    "fmc_search_spec": {"query": "access rules"},
    "fmc_get_definition": {"name": "AccessRule"},
    "fmc_get_intrusion_policy": {"policy": "mcp-test-ips"},
    "fmc_find_intrusion_rules": {"query": "2000:1000001", "policy": "mcp-test-ips"},
    "fmc_list_object_overrides": {"object": "mcp-test-unused", "type": "host"},
}

# Need objects the lab doesn't always have (an HA pair, a VPN topology, a task id).
SKIP = {"fmc_api_call", "fmc_get_ha_status", "fmc_get_vpn_topology", "fmc_get_task"}


# FMC ties reading deployments and pending changes to the "Deploy Configuration to Devices" permission,
# which mcp-ro deliberately lacks (it would also allow deploying). docs/least-privilege.md.
# fmc_list_backups needs Backup Management (mcp-rw only); fmc_list_users needs User Management (neither role).
EXPECTED_DENIED = {
    "fmc_list_deployable_devices",
    "fmc_list_deployments",
    "fmc_pending_changes",
    "fmc_list_backups",
    "fmc_list_users",
}


async def test_read_tier_as_readonly_user() -> None:
    settings = readonly_live_settings(Settings, "FMC_")
    report = await read_tier_report(create_server(settings), SAMPLES, skip=SKIP)
    print(report.summary())
    assert set(report.denied) == EXPECTED_DENIED, report.summary()
    assert all("403" in v for v in report.denied.values()), report.summary()
    assert len(report.ok) >= 43, report.summary()


async def test_ro_user_cannot_write() -> None:
    """FMC refuses a write from the mcp-ro account itself (the appliance role, not only the MCP tiers)."""
    # the in-memory caller is `local` (MCP role admin), so the write tool is visible; FMC must refuse it
    settings = readonly_live_settings(Settings, "FMC_")
    args = {"name": "mcp-test-ro-denied", "type": "host", "value": "10.255.255.1"}
    async with Client(create_server(settings)) as c:
        preview = (await c.call_tool("fmc_create_object", args)).structured_content
        assert preview and preview["status"] == "preview", preview
        res = await c.call_tool(
            "fmc_create_object", {**args, "confirm": preview["confirm"]}, raise_on_error=False
        )
        text = " ".join(getattr(x, "text", "") for x in res.content)
        assert res.is_error, text
        assert "403" in text or "denied" in text.lower(), text

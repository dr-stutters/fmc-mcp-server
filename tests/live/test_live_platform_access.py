"""F24 on the real FTD (platform settings mcp-test-ps, assigned to mcp-ftd1): NTP server, SNMP v2c manager and
SSH access from the inside network; deploy; check the running config; revert and deploy again."""

from typing import Any

import pytest
from fastmcp import Client

from .test_live_ftd import DEVICE, apply, call, deploy, needs_ftd, show

pytestmark = pytest.mark.live

PS = "mcp-test-ps"
ZONE = "mcp-test-ftd-in"
COMMUNITY = "mcpLiveComm24"


async def ensure(client: Client[Any], name: str, args: dict[str, Any]) -> None:
    preview = await call(client, name, args)
    if preview["status"] == "preview":
        done = await call(client, name, {**args, "confirm": preview["confirm"]})
        assert done["status"] == "applied", done


@needs_ftd
async def test_ntp_snmp_ssh(client: Client[Any]) -> None:
    assigned = await call(client, "fmc_get_platform_settings", {"policy": PS})
    assert DEVICE in str(assigned), "mcp-test-ps must be assigned to the FTD"
    try:
        await apply(client, "fmc_configure_ntp", {"policy": PS, "servers": ["198.18.128.1"]})
        await apply(
            client,
            "fmc_configure_snmp",
            {
                "policy": PS,
                "enabled": True,
                "community": COMMUNITY,
                "location": "mcp-lab",
                "add_hosts": ["10.99.1.10"],
                "interfaces": [ZONE],
            },
        )
        await ensure(
            client,
            "fmc_configure_ssh_access",
            {"policy": PS, "action": "allow", "network": "10.99.1.0/24", "interfaces": [ZONE]},
        )
        await deploy(client, "mcp live test: ntp snmp ssh", ignore_warning=True)
        ntp = await call(client, "fmc_get_platform_settings", {"policy": PS})
        assert "198.18.128.1" in str(ntp["ntp"]), ntp  # FTD NTP runs on the management side, not in LINA
        snmp = await show(client, "show running-config snmp-server")
        assert "10.99.1.10" in snmp and "mcp-lab" in snmp and COMMUNITY not in snmp, snmp
        assert "10.99.1.0" in await show(client, "show running-config ssh")
    finally:
        await ensure(client, "fmc_configure_ntp", {"policy": PS, "servers": []})
        await ensure(
            client,
            "fmc_configure_snmp",
            {
                "policy": PS,
                "enabled": False,
                "community": COMMUNITY,
                "remove_hosts": ["mcp-host-10.99.1.10", "mcp-test-db"],
            },
        )
        await ensure(
            client,
            "fmc_configure_ssh_access",
            {"policy": PS, "action": "remove", "network": "10.99.1.0/24", "interfaces": [ZONE]},
        )
        await deploy(client, "mcp live test: ntp snmp ssh reverted", ignore_warning=True)

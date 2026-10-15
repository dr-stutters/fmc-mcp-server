"""Live reads for F10/F11 (HA status, VPN topologies, RA VPN). The full build/switch/break/delete
runs need the two-FTDv lab (CML `mcp-fmc-ha`) and are recorded in the notes."""

from typing import Any

import pytest
from fastmcp import Client

from .test_live_writes import call

pytestmark = pytest.mark.live


async def test_vpn_and_ravpn_reads(client: Client[Any]) -> None:
    topos = await call(client, "fmc_list_vpn_topologies", {"response_format": "json"})
    for t in topos["results"][:2]:
        out = await call(client, "fmc_get_vpn_topology", {"topology": t["id"]})
        assert "endpoints" in out and "manualPreSharedKey" not in str(out)
    ra = await call(client, "fmc_get_ravpn", {})
    assert isinstance(ra["policies"], list)


async def test_ha_status_when_paired(client: Client[Any]) -> None:
    pairs = await call(client, "fmc_list_ha_pairs", {"response_format": "json"})
    if not pairs["results"]:
        pytest.skip("No HA pair on this FMC.")
    out = await call(client, "fmc_get_ha_status", {"ha_pair": pairs["results"][0]["id"]})
    assert {"primary", "secondary"} <= set(out["units"]) and out["monitored_interfaces"]

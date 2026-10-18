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


async def test_ha_failover_state_from_the_units(client: Client[Any]) -> None:
    """F65: the units' own failover state through FMC (read-only: show failover / state / history)."""
    pairs = await call(client, "fmc_list_ha_pairs", {"response_format": "json"})
    for pair in pairs["results"]:
        out = await call(client, "fmc_get_ha_status", {"ha_pair": pair["id"], "history": 3})
        states = [u.get("device_state") for u in out["units"].values()]
        if all(states):  # both units answered through FMC (a stopped lab pair only gives notes)
            break
    else:
        pytest.skip("No HA pair whose units answer show commands.")
    assert sorted(s.split()[0] for s in states) == ["Active", "Standby"]
    assert out["failover"] == "On" and out["failover_link"]["status"] == "up"
    assert {c["check"] for c in out["checks"]} >= {"standby_ready", "failover_link_up", "config_in_sync"}
    assert isinstance(out["ready_for_switch"], bool) and out["summary"]
    assert out["last_failover"]["at"] and "stateful_replication" in out

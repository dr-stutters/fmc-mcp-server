"""Live F9: contain and release a host with the quarantine dynamic object (no deployment).

Uses 10.99.1.250 (no real host) so it can run against a lab where the quarantine rules are already
deployed; the real-traffic check (ping from inside-host blocked, then restored) is in the notes."""

from typing import Any

import pytest
from fastmcp import Client

from .test_live_writes import apply, call

pytestmark = pytest.mark.live
IP = "10.99.1.250"


async def test_contain_release_idempotent(client: Client[Any]) -> None:
    preview = await call(client, "fmc_contain_host", {"ip": IP, "reason": "mcp live test"})
    if preview["status"] == "blocked":
        pytest.skip(f"Containment not possible here: {preview['blockers']}")
    if preview["preview"]["deploy_needed"]:
        pytest.skip("The quarantine block rules aren't set up; run fmc_contain_host once and deploy.")
    try:
        done = await apply(client, "fmc_contain_host", {"ip": IP, "reason": "mcp live test"})
        assert done["result"]["contained"] and not done["result"]["deploy_needed"]
        again = await apply(client, "fmc_contain_host", {"ip": IP, "reason": "mcp live test"})
        assert again["result"]["already_contained"]
        listed = await call(
            client, "fmc_list_dynamic_objects", {"name": "quarantine", "response_format": "json"}
        )
        assert any(IP in (o.get("mappings") or []) for o in listed["results"])
        devices = await call(client, "fmc_list_devices", {"response_format": "json"})
        if devices["results"]:  # F28: the offline lookup sees the mapping
            look = await call(
                client,
                "fmc_rule_lookup",
                {
                    "device": devices["results"][0]["name"],
                    "source": IP,
                    "destination": "8.8.8.8",
                    "port": 443,
                },
            )
            assert look["verdict"].endswith("BLOCK") and "quarantine" in look["matched_rule"]["name"]
    finally:
        out = await apply(client, "fmc_release_host", {"ip": IP})
    assert out["result"]["released"]
    out = await apply(client, "fmc_release_host", {"ip": IP})
    assert not out["result"]["released"]

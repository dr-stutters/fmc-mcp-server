"""F13 slice 3: DNS block on the real FTD. A DNS policy mcp-test-dns is linked to mcp-test-ftd-acp's Security
Intelligence, a domain is blocked (custom SI DNS list in rule mcp-dns-block), deployed, then unblocked and the
previous DNS policy linked again and deployed."""

from typing import Any

import pytest
from fastmcp import Client

from .test_live_ftd import ACP, apply, call, deploy, needs_ftd

pytestmark = pytest.mark.live

DNS = "mcp-test-dns"
BLOCKED = "mcp-blocked.example.com"
DEFAULT = "Default DNS Policy"


@needs_ftd
async def test_dns_block(client: Client[Any]) -> None:
    pols = await call(client, "fmc_get_dns_policy", {"response_format": "json"})
    if not any(p["name"] == DNS for p in pols["results"]):
        await apply(client, "fmc_create_dns_policy", {"name": DNS})
    si = await call(client, "fmc_get_security_intelligence", {"policy": ACP, "response_format": "json"})
    before = DEFAULT if si.get("dns_policy") != DNS else None  # the SI view may show an older name
    if before:
        await apply(client, "fmc_set_dns_policy", {"access_policy": ACP, "dns_policy": DNS})
    try:
        await apply(client, "fmc_dns_block", {"policy": DNS, "domains": [BLOCKED]})
        one = await call(client, "fmc_get_dns_policy", {"policy": DNS, "response_format": "json"})
        rule = next(r for r in one["rules"] if r["name"] == "mcp-dns-block")
        assert rule["action"] == "NXDOMAIN"
        assert "mcp-dns-mcp-blocked.example.com" in rule["dns_lists"]
        await deploy(client, "mcp live test: DNS block", ignore_warning=True)
    finally:
        await apply(client, "fmc_dns_block", {"policy": DNS, "domains": [BLOCKED], "action": "unblock"})
        if before:
            await apply(client, "fmc_set_dns_policy", {"access_policy": ACP, "dns_policy": before})
        await deploy(client, "mcp live test: DNS unblocked", ignore_warning=True)
    one = await call(client, "fmc_get_dns_policy", {"policy": DNS, "response_format": "json"})
    assert not any(r["name"] == "mcp-dns-block" for r in one["rules"])

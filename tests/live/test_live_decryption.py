"""F13 slice 2: a do-not-decrypt rule in decryption policy mcp-test-dec, linked to mcp-test-ftd-acp and
deployed to the FTD; then the rule is removed and deployed again. FMC's API can't unlink a decryption policy,
so mcp-test-dec (default DO_NOT_DECRYPT, no rules: decrypts nothing) stays linked."""

from typing import Any

import pytest
from fastmcp import Client

from .test_live_ftd import ACP, apply, call, deploy, needs_ftd

pytestmark = pytest.mark.live

DEC = "mcp-test-dec"
RULE = "mcp-test-dnd-bank"


@needs_ftd
async def test_do_not_decrypt_rule(client: Client[Any]) -> None:
    pols = await call(client, "fmc_get_decryption_policy", {"response_format": "json"})
    if not any(p["name"] == DEC for p in pols["results"]):
        await apply(client, "fmc_create_decryption_policy", {"name": DEC})
    await apply(
        client,
        "fmc_create_decryption_rule",
        {
            "policy": DEC,
            "name": RULE,
            "destination_networks": ["203.0.113.10"],
            "destination_ports": ["tcp/443"],
        },
    )
    try:
        one = await call(client, "fmc_get_decryption_policy", {"policy": DEC, "response_format": "json"})
        assert any(r["name"] == RULE and r["action"] == "DO_NOT_DECRYPT" for r in one["rules"]), one
        linked = await call(
            client, "fmc_set_decryption_policy", {"access_policy": ACP, "decryption_policy": DEC}
        )
        if linked["status"] == "preview":
            await call(
                client,
                "fmc_set_decryption_policy",
                {"access_policy": ACP, "decryption_policy": DEC, "confirm": linked["confirm"]},
            )
        await deploy(client, "mcp live test: decryption policy", ignore_warning=True)
        acp = await call(client, "fmc_get_access_policy", {"policy": ACP})
        assert acp["decryption_policy"] == DEC, acp
        unlink = await call(
            client, "fmc_set_decryption_policy", {"access_policy": ACP, "decryption_policy": ""}
        )
        assert unlink["status"] == "blocked" and "can't remove" in unlink["blockers"][0]
    finally:
        await apply(client, "fmc_delete_decryption_rule", {"policy": DEC, "rule": RULE})
        await deploy(client, "mcp live test: decryption removed", ignore_warning=True)

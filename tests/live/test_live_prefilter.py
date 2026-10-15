"""F20 prefilter on the real FTD: a FASTPATH rule for the inside host in a custom prefilter policy linked to
mcp-test-ftd-acp; packet tracer shows the prefilter fastpath; then the rule is removed and the default
prefilter policy linked again. The policy mcp-test-pf is kept for later runs."""

import json
from typing import Any

import pytest
from fastmcp import Client

from .test_live_ftd import ACP, DEVICE, apply, call, deploy, needs_ftd

pytestmark = pytest.mark.live

PF = "mcp-test-pf"
RULE = "mcp-test-fastpath-host"
DEFAULT_PF = "Default Prefilter Policy"


async def trace(client: Client[Any]) -> dict[str, Any]:
    out = await call(
        client,
        "fmc_packet_tracer",
        {
            "device": DEVICE,
            "input_interface": "inside",
            "protocol": "icmp",
            "source_ip": "10.99.1.10",
            "destination_ip": "198.18.128.1",
            "verbose": True,
        },
    )
    return dict(out["results"][0])


@needs_ftd
async def test_fastpath_rule(client: Client[Any]) -> None:
    pols = await call(
        client, "fmc_list_policies", {"kind": "prefilter", "name": PF, "response_format": "json"}
    )
    if not any(p["name"] == PF for p in pols["results"]):
        await apply(client, "fmc_create_prefilter_policy", {"name": PF})
    await apply(client, "fmc_set_prefilter_policy", {"access_policy": ACP, "prefilter_policy": PF})
    try:
        await apply(
            client,
            "fmc_create_prefilter_rule",
            {
                "policy": PF,
                "name": RULE,
                "action": "FASTPATH",
                "source_networks": ["10.99.1.10"],
                "destination_networks": ["198.18.128.1"],
                "bidirectional": True,
            },
        )
        await deploy(client, "mcp live test: prefilter fastpath", ignore_warning=True)
        res = await trace(client)
        text = json.dumps(res).lower()
        assert "prefilter" in text or "fastpath" in text or "fast-forward" in text, res
        upd = await call(client, "fmc_update_prefilter_rule", {"policy": PF, "rule": RULE, "enabled": False})
        assert upd["status"] == "preview" and upd["preview"]["changes"]["enabled"]["to"] is False, upd
    finally:
        rules = await call(client, "fmc_list_prefilter_rules", {"policy": PF, "response_format": "json"})
        if any(r.get("name") == RULE for r in rules.get("results", [])):
            await apply(client, "fmc_delete_prefilter_rule", {"policy": PF, "rule": RULE})
        await apply(
            client, "fmc_set_prefilter_policy", {"access_policy": ACP, "prefilter_policy": DEFAULT_PF}
        )
        await deploy(client, "mcp live test: prefilter restored", ignore_warning=True)

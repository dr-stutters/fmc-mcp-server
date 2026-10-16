"""F13 intrusion tuning on the real FTD: a custom Snort 3 rule (ICMP echo) in a custom intrusion policy on the
allow rule mcp-test-allow-out of mcp-test-ftd-acp. DROP -> packet tracer shows the Snort drop; DEFAULT
(disabled) -> allowed again. The policy, rule group and rule are kept for later runs; the rule state and the
access rule are restored."""

import json
from typing import Any

import pytest
from fastmcp import Client

from .live_env import live_env
from .test_live_ftd import ACP, DEVICE, GATEWAY, apply, call, deploy, needs_ftd

pytestmark = pytest.mark.live

IPS = "mcp-test-ips"
GROUP = "mcp-test-rules"
RULE = "2000:1000001"
RULE_TEXT = 'alert icmp any any -> any any ( msg:"mcp-test icmp echo"; itype:8; sid:1000001; rev:1; )'
ALLOW_RULE = "mcp-test-allow-out"
TARGET = live_env("FMC_LIVE_PING_TARGET", GATEWAY)


async def trace(client: Client[Any]) -> dict[str, Any]:
    out = await call(
        client,
        "fmc_packet_tracer",
        {
            "device": DEVICE,
            "input_interface": "inside",
            "protocol": "icmp",
            "source_ip": "10.99.1.10",
            "destination_ip": TARGET,
        },
    )
    return dict(out["results"][0])


@needs_ftd
async def test_custom_rule_drop_and_restore(client: Client[Any]) -> None:
    pols = await call(
        client, "fmc_list_policies", {"kind": "intrusion", "name": IPS, "response_format": "json"}
    )
    if not any(p["name"] == IPS for p in pols["results"]):
        await apply(client, "fmc_create_intrusion_policy", {"name": IPS})
    found = await call(client, "fmc_find_intrusion_rules", {"query": RULE, "response_format": "json"})
    if not found["results"]:
        await apply(client, "fmc_create_intrusion_rule", {"rule_text": RULE_TEXT, "group": GROUP})
    dev = await call(client, "fmc_get_device", {"device": DEVICE})
    if "IPS" not in json.dumps(dev.get("license_caps") or dev):
        await apply(client, "fmc_set_device_licenses", {"device": DEVICE, "add": ["IPS"]})

    await apply(client, "fmc_set_intrusion_rule_state", {"policy": IPS, "rules": [RULE], "state": "DROP"})
    summary = await call(client, "fmc_get_intrusion_policy", {"policy": IPS, "response_format": "json"})
    assert any(r["rule"] == RULE and r["override_state"] == "DROP" for r in summary["overridden_rules"])
    try:
        await apply(
            client, "fmc_update_access_rule", {"policy": ACP, "rule": ALLOW_RULE, "intrusion_policy": IPS}
        )
        await deploy(client, "mcp live test: IPS drop icmp", ignore_warning=True)
        res = await trace(client)
        assert res["action"] == "drop", res
        assert "snort" in json.dumps(res).lower(), res
    finally:
        await apply(
            client, "fmc_set_intrusion_rule_state", {"policy": IPS, "rules": [RULE], "state": "DEFAULT"}
        )
        await apply(
            client, "fmc_update_access_rule", {"policy": ACP, "rule": ALLOW_RULE, "intrusion_policy": ""}
        )
        await deploy(client, "mcp live test: IPS restored", ignore_warning=True)
    res = await trace(client)
    assert res["action"] == "allow" or "adjacency" in res.get("drop_reason", ""), res

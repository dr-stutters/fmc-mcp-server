"""F64: fmc_tls_decryption_check (what the decryption policy does to one TLS flow)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server
from fmc_mcp.tools.decryption_check import host_matches

from .conftest import CFG, fixture, items, make_settings

FX = fixture("decryption_pki")
POL = FX["decryption_policy"]
RULES = FX["decryption_rules"]
PRULES = f"{CFG}/policy/decryptionpolicies/{POL['id']}/decryptionpolicyrules"
ACP = {"id": "00000000-0000-0ed3-0000-000000000a01", "name": "mcp-test-tls-acp", "type": "AccessPolicy"}
DEV = {
    "id": "00000000-0000-0ed3-0000-000000000e01",
    "name": "ftd-a",
    "type": "Device",
    "accessPolicy": {"id": ACP["id"], "name": ACP["name"], "type": "AccessPolicy"},
}


def mock(fmc: respx.MockRouter, rules: list[dict[str, Any]] | None = None, linked: bool = True) -> None:
    for p in (
        "networkaddresses",
        "ranges",
        "networkgroups",
        "protocolportobjects",
        "icmpv4objects",
        "icmpv6objects",
        "portobjectgroups",
    ):
        fmc.get(f"{CFG}/object/{p}").mock(return_value=items([]))
    fmc.get(f"{CFG}/policy/decryptionpolicies").mock(return_value=items([POL]))
    fmc.get(f"{CFG}/policy/decryptionpolicies/{POL['id']}").mock(return_value=httpx.Response(200, json=POL))
    fmc.get(PRULES).mock(return_value=items(RULES if rules is None else rules))
    ca = FX["internal_ca"]
    fmc.get(f"{CFG}/object/internalcas/{ca['id']}").mock(return_value=httpx.Response(200, json=ca))
    acp = {
        **ACP,
        "decryptionPolicySetting": {"id": POL["id"], "name": POL["name"], "type": "DecryptionPolicy"},
    }
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([acp if linked else ACP]))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}").mock(
        return_value=httpx.Response(200, json=acp if linked else ACP)
    )


async def run(args: dict[str, Any]) -> Any:
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool("fmc_tls_decryption_check", args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def test_host_matches() -> None:
    assert host_matches("www.bank.example.com", "https://bank.example.com/login")
    assert host_matches("bank.example.com.", "bank.example.com")
    assert not host_matches("notbank.example.com", "bank.example.com")
    assert not host_matches("bank.example.com", "")


async def test_resign_flow_with_readiness(fmc: respx.MockRouter) -> None:
    mock(fmc)
    out = await run(
        {"source": "192.0.2.10", "destination": "203.0.113.10", "access_policy": "mcp-test-tls-acp"}
    )
    assert out["decryption_policy"] == "mcp-test-tls" and out["action"] == "DECRYPT_RESIGN"
    assert out["matched_rule"]["name"] == "resign-outbound" and "HTTP inside" in out["inspection"]
    checks = {c["check"]: c for c in out["readiness"]}
    assert checks["access policy link"]["ok"] is True
    assert checks["internal CA"]["ok"] is True and "FF:68:66" in checks["internal CA"]["detail"]
    assert checks["clients trust the CA"]["ok"] is None
    assert "Cisco-Trusted-Authorities" in checks["trusted issuers"]["detail"]
    assert "fmc_create_trusted_ca" in checks["trusted issuers"]["detail"]
    assert checks["TLS 1.3 decryption"]["ok"] is False


async def test_exemption_and_default(fmc: respx.MockRouter) -> None:
    mock(fmc)
    dnd = await run(
        {"source": "192.0.2.10", "destination": "203.0.113.66", "decryption_policy": "mcp-test-tls"}
    )
    assert dnd["action"] == "DO_NOT_DECRYPT" and dnd["matched_rule"]["name"] == "dnd-bank"
    assert "can't see the payload" in dnd["inspection"]
    other = await run(
        {"source": "198.51.100.5", "destination": "203.0.113.10", "decryption_policy": "mcp-test-tls"}
    )
    assert other["action"] == "DO_NOT_DECRYPT" and "default action" in other["verdict"]
    assert "readiness" not in other  # nothing to check without an access policy, device or decrypt rule
    port = await run(
        {
            "source": "192.0.2.10",
            "destination": "203.0.113.10",
            "port": 8443,
            "decryption_policy": "mcp-test-tls",
        }
    )
    assert "matched_rule" not in port


async def test_no_decryption_policy_and_wrong_link(fmc: respx.MockRouter) -> None:
    mock(fmc, linked=False)
    out = await run(
        {"source": "192.0.2.10", "destination": "203.0.113.10", "access_policy": "mcp-test-tls-acp"}
    )
    assert out["action"] is None and "no decryption policy" in out["verdict"]
    assert "fmc_set_decryption_policy" in out["next"]
    named = await run(
        {
            "source": "192.0.2.10",
            "destination": "203.0.113.10",
            "access_policy": "mcp-test-tls-acp",
            "decryption_policy": "mcp-test-tls",
        }
    )
    link = next(c for c in named["readiness"] if c["check"] == "access policy link")
    assert link["ok"] is False and "fmc_set_decryption_policy" in link["detail"]
    with pytest.raises(ToolError, match="device the flow crosses"):
        await run({"source": "192.0.2.10", "destination": "203.0.113.10"})
    with pytest.raises(ToolError, match="tcp or udp"):
        await run(
            {
                "source": "192.0.2.10",
                "destination": "203.0.113.10",
                "protocol": "icmp",
                "decryption_policy": "x",
            }
        )


async def test_url_rules_need_the_server_name(fmc: respx.MockRouter) -> None:
    url_rule = {
        "ruleIndex": 1,
        "name": "dnd-bank-sites",
        "ruleAction": "DO_NOT_DECRYPT",
        "enabled": True,
        "urls": {
            "literals": [{"type": "Url", "url": "https://bank.example.com"}],
            "objects": [{"type": "Url", "id": "00000000-0000-0ed3-0000-000000000f01", "name": "health"}],
        },
    }
    cat_rule = {
        "ruleIndex": 2,
        "name": "dnd-finance",
        "ruleAction": "DO_NOT_DECRYPT",
        "enabled": True,
        "urls": {"urlCategoriesWithReputation": [{"category": {"name": "Financial Services"}}]},
    }
    resign = {**RULES[1], "ruleIndex": 3}
    mock(fmc, rules=[url_rule, cat_rule, resign])
    fmc.get(f"{CFG}/object/urls/00000000-0000-0ed3-0000-000000000f01").mock(
        return_value=httpx.Response(200, json={"id": "f01", "type": "Url", "url": "health.example.net"})
    )
    flow = {"source": "192.0.2.10", "destination": "203.0.113.10", "decryption_policy": "mcp-test-tls"}
    bank = await run({**flow, "server_name": "www.bank.example.com"})
    assert bank["matched_rule"]["name"] == "dnd-bank-sites"
    health = await run({**flow, "server_name": "portal.health.example.net"})
    assert health["matched_rule"]["name"] == "dnd-bank-sites"
    other = await run({**flow, "server_name": "www.example.org"})
    assert other["action"] == "DECRYPT_RESIGN"
    assert [r["name"] for r in other["may_match_first"]] == ["dnd-finance"]
    assert other["may_match_first"][0]["depends_on"] == ["url_category"]
    unknown = await run(flow)
    assert [r["depends_on"] for r in unknown["may_match_first"]] == [["url"], ["url_category"]]


async def test_device_with_pending_changes(fmc: respx.MockRouter) -> None:
    mock(fmc)
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(
        return_value=items(
            [
                {
                    "name": "ftd-a",
                    "device": {"id": DEV["id"], "name": "ftd-a"},
                    "policyStatusList": [
                        {"policy": {"type": "DecryptionPolicy", "name": "mcp-test-tls"}, "upToDate": False}
                    ],
                }
            ]
        )
    )
    out = await run(
        {
            "source": "192.0.2.10",
            "destination": "203.0.113.10",
            "device": "ftd-a",
            "source_zone": "inside",
            "destination_zone": "outside",
        }
    )
    assert out["access_policy"] == "mcp-test-tls-acp" and out["action"] == "DECRYPT_RESIGN"
    deployed = next(c for c in out["readiness"] if c["check"] == "deployed")
    assert deployed["ok"] is False and "DecryptionPolicy:mcp-test-tls" in deployed["detail"]

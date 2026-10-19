"""F64 live proof: decryption rules and their TLS versions. FMC 10.0.1 stores a rule created without
`tlsVersions` with all five versions false, then refuses to deploy DO_NOT_DECRYPT and DECRYPT_RESIGN rules
like that ('Support for SSL Versions selection for Decrypt - Resign rule is deprecated'). Recorded answers:
tests/fixtures/decryption_rule_versions_fmc10.json."""

import json

import httpx
import respx
from fastmcp import Client

from fmc_mcp.tools.decryption import version_problem

from . import test_decryption as dec
from . import test_decryption_check as check
from .conftest import fixture

REC = fixture("decryption_rule_versions_fmc10")
CREATED, FIXED = REC["resign_as_created"], REC["dnd_fixed"]


async def test_rule_sends_every_tls_version_and_flags_rules_fmc_refuses(fmc: respx.MockRouter) -> None:
    dec.mock_tls(fmc, rules=[FIXED, CREATED])
    post = fmc.post(dec.PRULES).mock(return_value=httpx.Response(201, json={"id": "r9"}))
    args = {"policy": "mcp-test-tls", "name": "dnd-bank", "destination_networks": ["203.0.113.77"]}
    async with Client(dec.server()) as c:
        p = await dec.run(c, "fmc_create_decryption_rule", args)
        assert p["status"] == "preview" and p["preview"]["tls_versions"] == "all"
        assert "cert_conditions" not in p["preview"]["rule"]
        refused = [s for s in p["side_effects"] if "refuses the deploy" in s]
        assert len(refused) == 1 and "'mcp-fw-resign'" in refused[0] and "all off" in refused[0]
        assert "Decrypt - Resign rule is deprecated" in refused[0]
        await dec.run(c, "fmc_create_decryption_rule", {**args, "confirm": p["confirm"]})
        got = await dec.run(
            c, "fmc_get_decryption_policy", {"policy": "mcp-test-tls", "response_format": "json"}
        )
    body = json.loads(post.calls.last.request.content)
    assert body["tlsVersions"] == {"sslv3": True, "tls10": True, "tls11": True, "tls12": True, "tls13": True}
    versions = [n for n in got["readiness"] if "SSL Versions selection" in n]
    assert len(versions) == 1 and "'mcp-fw-resign'" in versions[0]  # the fixed DND rule is fine


def test_version_problem() -> None:
    partial = {**FIXED, "tlsVersions": {**FIXED["tlsVersions"], "sslv3": False, "tls10": False}}
    assert "sslv3, tls10 off" in str(version_problem(partial))
    assert "all off" in str(version_problem(CREATED))
    assert version_problem(FIXED) is None
    assert version_problem({**CREATED, "ruleAction": "BLOCK"}) is None
    assert version_problem({k: v for k, v in CREATED.items() if k != "tlsVersions"}) is None


async def test_tls_check_names_rules_fmc_refuses_to_deploy(fmc: respx.MockRouter) -> None:
    """Any such rule blocks the deploy of the whole policy, matched or not."""
    flow = {"source": "192.0.2.10", "destination": "203.0.113.66", "decryption_policy": "mcp-test-tls"}
    check.mock(fmc, rules=[FIXED, CREATED])
    out = await check.run(flow)
    versions = next(c for c in out["readiness"] if c["check"] == "TLS versions")
    assert versions["ok"] is False and "'mcp-fw-resign'" in versions["detail"]
    assert "refuses the deploy" in versions["detail"] and "'mcp-fw-dnd'" not in versions["detail"]
    check.mock(fmc, rules=[FIXED])
    assert "readiness" not in await check.run(flow)

"""F13 slice 2 and F64: decryption policy tools."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server
from fmc_mcp.tools.decryption import cert_conditions, rule_row

from .conftest import CFG, fixture, items, make_settings

DEC = {
    "id": "d1",
    "name": "mcp-test-dec",
    "type": "DecryptionPolicy",
    "defaultAction": {"policyAction": "DO_NOT_DECRYPT"},
}
ACP = {"id": "00000000-0000-0ed3-0000-021474847655", "name": "acp", "type": "AccessPolicy"}
RULES = f"{CFG}/policy/decryptionpolicies/d1/decryptionpolicyrules"


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def test_create_do_not_decrypt_rule(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/decryptionpolicies").mock(return_value=items([DEC]))
    fmc.get(RULES).mock(return_value=items([]))
    post = fmc.post(RULES).mock(return_value=httpx.Response(201, json={"id": "r1"}))
    args = {
        "policy": "mcp-test-dec",
        "name": "dnd",
        "destination_networks": ["203.0.113.10"],
        "destination_ports": ["tcp/443"],
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_create_decryption_rule", args)
        assert p["preview"]["rule"]["action"] == "DO_NOT_DECRYPT"
        await run(c, "fmc_create_decryption_rule", {**args, "confirm": p["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["ruleAction"] == "DO_NOT_DECRYPT" and body["destinationPorts"]["literals"][0]["port"] == "443"


async def test_unlink_is_refused_with_explanation(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}").mock(
        return_value=httpx.Response(
            200, json={**ACP, "decryptionPolicySetting": {"id": "d1", "name": "mcp-test-dec"}}
        )
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_set_decryption_policy", {"access_policy": "acp", "decryption_policy": ""})
    assert out["status"] == "blocked" and "can't remove" in out["blockers"][0]


def test_acp_settings_body_keeps_settings_but_not_collections() -> None:
    from fmc_mcp.tools.policies import acp_settings_body

    acp = {
        "id": "a",
        "type": "AccessPolicy",
        "name": "acp",
        "metadata": {"x": 1},
        "links": {"self": "u"},
        "rules": {"refType": "list", "links": {"self": "u"}},
        "advancedLoggingSetting": {"links": {"self": "u"}},
        "securityIntelligence": {"id": "si", "type": "SecurityIntelligencePolicy", "links": {"self": "u"}},
        "identityPolicySetting": {"id": "i", "type": "IdentityPolicy"},
        "defaultAction": {"action": "BLOCK"},
    }
    body = acp_settings_body(acp, prefilterPolicySetting={"id": "p"})
    assert set(body) == {
        "id",
        "type",
        "name",
        "securityIntelligence",
        "identityPolicySetting",
        "defaultAction",
        "prefilterPolicySetting",
    }
    assert "links" not in body["securityIntelligence"]


# --- F64: decrypt-resign, known-key, policy settings ----------------------------------------------------

FX = fixture("decryption_pki")
POL = FX["decryption_policy"]
PRULES = f"{CFG}/policy/decryptionpolicies/{POL['id']}/decryptionpolicyrules"
CAS = f"{CFG}/object/internalcas"
CERTS = f"{CFG}/object/internalcertificates"
EXT = f"{CFG}/object/externalcacertificates"
GROUPS = f"{CFG}/object/externalcacertificategroups"


def mock_tls(fmc: respx.MockRouter, rules: list[dict[str, Any]] | None = None, policy: Any = None) -> None:
    pol = policy or POL
    fmc.get(f"{CFG}/policy/decryptionpolicies").mock(return_value=items([pol]))
    fmc.get(f"{CFG}/policy/decryptionpolicies/{pol['id']}").mock(return_value=httpx.Response(200, json=pol))
    fmc.get(PRULES).mock(return_value=items(FX["decryption_rules"] if rules is None else rules))
    ca, csr = FX["internal_ca"], FX["internal_ca_csr"]
    fmc.get(CAS).mock(return_value=items([ca, csr]))
    fmc.get(f"{CAS}/{ca['id']}").mock(return_value=httpx.Response(200, json=ca))
    fmc.get(f"{CAS}/{csr['id']}").mock(return_value=httpx.Response(200, json=csr))
    web = FX["internal_cert"]
    fmc.get(CERTS).mock(return_value=items([web]))
    fmc.get(f"{CERTS}/{web['id']}").mock(return_value=httpx.Response(200, json=web))
    fmc.get(EXT).mock(return_value=items(FX["trusted_cas"]))
    for t in FX["trusted_cas"]:
        fmc.get(f"{EXT}/{t['id']}").mock(return_value=httpx.Response(200, json=t))
    fmc.get(GROUPS).mock(return_value=items(FX["trusted_ca_groups"]))
    fmc.get(f"{CFG}/policy/accesspolicies").mock(
        return_value=items([{**ACP, "decryptionPolicySetting": {"id": pol["id"], "name": pol["name"]}}])
    )


async def test_resign_rule_with_ca_and_position(fmc: respx.MockRouter) -> None:
    mock_tls(fmc)
    post = fmc.post(PRULES).mock(return_value=httpx.Response(201, json={"id": "r9"}))
    args = {
        "policy": "mcp-test-tls",
        "name": "resign-lab",
        "action": "DECRYPT_RESIGN",
        "internal_ca": "mcp-test-resign-ca",
        "source_networks": ["198.51.100.0/24"],
        "destination_ports": ["tcp/443"],
        "insert_before": 2,
        "log": True,
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_create_decryption_rule", args)
        assert p["status"] == "preview" and p["preview"]["position"] == 2
        assert p["preview"]["rule"]["resign_ca"] == ["mcp-test-resign-ca"] and p["preview"]["rule"]["log"]
        effects = " ".join(p["side_effects"])
        assert "Clients must trust 'mcp-test-resign-ca'" in effects and "TLS 1.3 decryption is off" in effects
        await run(c, "fmc_create_decryption_rule", {**args, "confirm": p["confirm"]})
    req = post.calls.last.request
    body = json.loads(req.content)
    assert req.url.params["insertBefore"] == "2"
    assert body["ruleAction"] == "DECRYPT_RESIGN" and body["replacePublicKey"] is False
    assert body["decryptionCerts"]["objects"][0] == {
        "id": FX["internal_ca"]["id"],
        "type": "InternalCA",
        "name": "mcp-test-resign-ca",
    }
    assert body["logging"] == {"logEnd": True, "sendEvents": True}


async def test_resign_rule_blockers(fmc: respx.MockRouter) -> None:
    mock_tls(fmc)
    base = {
        "policy": "mcp-test-tls",
        "name": "r",
        "action": "DECRYPT_RESIGN",
        "destination_ports": ["tcp/443"],
    }
    async with Client(server()) as c:
        no_ca = await run(c, "fmc_create_decryption_rule", base)
        assert no_ca["status"] == "blocked" and "needs internal_ca" in no_ca["blockers"][0]
        csr = await run(c, "fmc_create_decryption_rule", {**base, "internal_ca": "mcp-test-csr-ca"})
        assert csr["status"] == "blocked" and "still a CSR" in csr["blockers"][0]
        everything = await run(
            c,
            "fmc_create_decryption_rule",
            {**base, "internal_ca": "mcp-test-resign-ca", "destination_ports": None},
        )
        assert any("match all TLS traffic" in b for b in everything["blockers"])
        too_far = await run(
            c, "fmc_create_decryption_rule", {**base, "internal_ca": "mcp-test-resign-ca", "insert_before": 9}
        )
        assert any("insert_before=9" in b for b in too_far["blockers"])
        for bad in (
            {"action": "DO_NOT_DECRYPT", "internal_ca": "x"},
            {"replace_key_only": True, "action": "BLOCK"},
        ):
            with pytest.raises(ToolError):
                await run(c, "fmc_create_decryption_rule", {**base, **bad})
        with pytest.raises(ToolError, match="internal_certificates"):
            await run(c, "fmc_create_decryption_rule", {**base, "action": "DECRYPT_KNOWN_KEY"})


async def test_exemption_below_a_resign_rule_warns(fmc: respx.MockRouter) -> None:
    mock_tls(fmc)
    fmc.post(PRULES).mock(return_value=httpx.Response(201, json={"id": "r9"}))
    args = {"policy": "mcp-test-tls", "name": "dnd-health", "destination_networks": ["203.0.113.77"]}
    async with Client(server()) as c:
        late = await run(c, "fmc_create_decryption_rule", args)
        assert any("insert_before=2" in s for s in late["side_effects"])
        early = await run(c, "fmc_create_decryption_rule", {**args, "insert_before": 1})
        assert not any("top-down" in s for s in early["side_effects"])


async def test_known_key_rule(fmc: respx.MockRouter) -> None:
    mock_tls(fmc)
    post = fmc.post(PRULES).mock(return_value=httpx.Response(201, json={"id": "r9"}))
    args = {
        "policy": "mcp-test-tls",
        "name": "inbound-web",
        "action": "DECRYPT_KNOWN_KEY",
        "internal_certificates": ["mcp-test-web-cert"],
        "destination_networks": ["203.0.113.80"],
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_create_decryption_rule", args)
        assert p["preview"]["rule"]["known_key_certs"] == ["mcp-test-web-cert"]
        await run(c, "fmc_create_decryption_rule", {**args, "confirm": p["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["internalCerts"]["objects"][0]["type"] == "InternalCertificate"
    assert "decryptionCerts" not in body


async def test_create_policy_with_trusted_cas_and_tls13(fmc: respx.MockRouter) -> None:
    mock_tls(fmc)
    fmc.get(f"{CFG}/policy/decryptionpolicies").mock(return_value=items([]))
    created = {**POL, "id": "00000000-0000-0ed3-0000-000000000d02", "name": "mcp-fw-tls"}
    post = fmc.post(f"{CFG}/policy/decryptionpolicies").mock(return_value=httpx.Response(201, json=created))
    item = f"{CFG}/policy/decryptionpolicies/{created['id']}"
    fmc.get(item).mock(return_value=httpx.Response(200, json=created))
    put = fmc.put(item).mock(return_value=httpx.Response(200, json=created))
    args = {"name": "mcp-fw-tls", "trusted_cas": ["mcp-test-server-ca"], "tls13_decryption": True}
    async with Client(server()) as c:
        p = await run(c, "fmc_create_decryption_policy", args)
        assert p["preview"]["advanced"] == {"tls13Decryption": True}
        await run(c, "fmc_create_decryption_policy", {**args, "confirm": p["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert [r["name"] for r in body["trustedCAs"]["objects"]] == [
        "Cisco-Trusted-Authorities",
        "mcp-test-server-ca",
    ]
    sent = json.loads(put.calls.last.request.content)
    assert sent["advancedOptions"]["tls13Decryption"] is True
    assert sent["advancedOptions"]["adaptiveProbe"] is True  # FMC's other defaults are kept
    assert "metadata" not in sent and "links" not in sent


async def test_update_policy_settings(fmc: respx.MockRouter) -> None:
    mock_tls(fmc)
    item = f"{CFG}/policy/decryptionpolicies/{POL['id']}"
    put = fmc.put(item).mock(return_value=httpx.Response(200, json=POL))
    args = {
        "policy": "mcp-test-tls",
        "add_trusted_cas": ["mcp-test-server-ca"],
        "tls13_decryption": True,
        "propagate_untrusted_certs": True,
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_update_decryption_policy", args)
        changes = p["preview"]["changes"]
        assert changes["tls13_decryption"] == {"from": False, "to": True}
        assert "propagate_untrusted_certs" not in changes  # already true
        assert changes["trusted_cas"]["to"] == ["Cisco-Trusted-Authorities", "mcp-test-server-ca"]
        await run(c, "fmc_update_decryption_policy", {**args, "confirm": p["confirm"]})
        same = await run(
            c, "fmc_update_decryption_policy", {"policy": "mcp-test-tls", "tls13_decryption": False}
        )
        assert same["status"] == "blocked" and same["blockers"] == ["Nothing to change."]
        empty = await run(
            c,
            "fmc_update_decryption_policy",
            {"policy": "mcp-test-tls", "remove_trusted_cas": ["Cisco-Trusted-Authorities"]},
        )
        assert "no trusted CAs" in empty["blockers"][0]
    sent = json.loads(put.calls.last.request.content)
    assert sent["advancedOptions"]["tls13Decryption"] is True
    # FMC's request schema has only `objects` (CA groups included), though its answers split out `groups`
    assert set(sent["trustedCAs"]) == {"objects"}
    assert [(r["name"], r["type"]) for r in sent["trustedCAs"]["objects"]] == [
        ("Cisco-Trusted-Authorities", "ExternalCACertificateGroup"),
        ("mcp-test-server-ca", "ExternalCACertificate"),
    ]


async def test_get_policy_shows_settings_and_readiness(fmc: respx.MockRouter) -> None:
    mock_tls(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_get_decryption_policy", {"policy": "mcp-test-tls", "response_format": "json"})
        listing = await run(c, "fmc_get_decryption_policy", {"response_format": "json"})
    assert out["trusted_cas"] == ["Cisco-Trusted-Authorities"]
    assert out["advanced"]["tls13_decryption"] is False and out["used_by"] == ["acp"]
    assert out["rules"][1]["resign_ca"] == ["mcp-test-resign-ca"]
    assert any("TLS 1.3 decryption is off" in n for n in out["readiness"])
    assert listing["results"][0]["used_by"] == "acp"


def test_rule_rows_ignore_fmc10_default_cert_blocks() -> None:
    """fmc_get_decryption_policy's rows: FMC 10.0.1's all-ANY statuses and all-on (or, as created, all-off)
    TLS versions are not conditions; a YES/NO status or a partial version list is."""
    live = fixture("decryption_fmc10")
    dnd, resign = live["decryption_rules"]
    assert "cert_conditions" not in rule_row(dnd) and "cert_conditions" not in rule_row(resign)
    assert cert_conditions(live["resign_rule_post_response"]) == []
    expired = {**resign, "certificateStatuses": {**resign["certificateStatuses"], "expired": "NO"}}
    assert rule_row(expired)["cert_conditions"] == ["certificateStatuses"]
    tls12_only = {**resign, "tlsVersions": {k: k == "tls12" for k in resign["tlsVersions"]}}
    assert cert_conditions(tls12_only) == ["tlsVersions"]
    assert cert_conditions({**resign, "issuerDNs": {"objects": [{"name": "dn", "id": "x"}]}}) == ["issuerDNs"]


# FMC 10.0.1 (live, 2026-10-19): a decryption rule POST with insertBefore answers 500 "JsonNull"
# but stores the rule at the requested index.
OLD = {
    "id": "r0",
    "name": "old",
    "type": "DecryptionPolicyRule",
    "ruleAction": "DO_NOT_DECRYPT",
    "enabled": True,
}
JSON_NULL = httpx.Response(
    500, json={"error": {"category": "OTHER", "messages": [{"description": "JsonNull"}]}}
)


def dnd_args(**kw: Any) -> dict[str, Any]:
    return {
        "policy": "mcp-test-dec",
        "name": "dnd-first",
        "destination_networks": ["192.0.2.10"],
        "destination_ports": ["tcp/443"],
        "insert_before": 1,
        **kw,
    }


async def test_create_rule_500_but_created_is_reported_applied(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/decryptionpolicies").mock(return_value=items([DEC]))
    made = {"id": "r1", "name": "dnd-first", "type": "DecryptionPolicyRule", "metadata": {"ruleIndex": 1}}
    before = items([{**OLD, "metadata": {"ruleIndex": 1}}])
    after = items([{**OLD, "metadata": {"ruleIndex": 2}}, made])
    fmc.get(RULES).mock(side_effect=[before, before, after])
    post = fmc.post(RULES).mock(return_value=JSON_NULL)
    async with Client(server()) as c:
        p = await run(c, "fmc_create_decryption_rule", dnd_args())
        assert p["status"] == "preview" and p["preview"]["position"] == 1
        done = await run(c, "fmc_create_decryption_rule", {**dnd_args(), "confirm": p["confirm"]})
    assert post.calls.last.request.url.params["insertBefore"] == "1"
    assert done["status"] == "applied" and done["result"]["id"] == "r1"
    assert "created the rule" in done["result"]["warning"] and "rule 1" in done["result"]["warning"]


async def test_create_rule_500_and_not_created_is_an_error(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/decryptionpolicies").mock(return_value=items([DEC]))
    fmc.get(RULES).mock(return_value=items([{**OLD, "metadata": {"ruleIndex": 1}}]))
    fmc.post(RULES).mock(return_value=JSON_NULL)
    async with Client(server()) as c:
        p = await run(c, "fmc_create_decryption_rule", dnd_args())
        with pytest.raises(ToolError, match="500"):
            await c.call_tool("fmc_create_decryption_rule", {**dnd_args(), "confirm": p["confirm"]})

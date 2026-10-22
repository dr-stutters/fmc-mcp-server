"""F85 (#319): Decrypt - Resign strips the suites FTD can't decrypt from the ClientHello it forwards, which
steps up only weak undecryptable suites and downgrades TLS 1.2 ChaCha20, AES-CCM and ARIA. The recorded
results are the ftd-tls-cipher-policy lab's step-up experiments (FTDv 10.0.0, FMC 10.0.1, 2026-10-22)."""

from typing import Any

import respx
from fastmcp import Client

from fmc_mcp.cipher_suites import (
    BY_CODE,
    PRESETS,
    RESIGN_DOWNGRADE,
    RESIGN_DOWNGRADED,
    RESIGN_STEPPED_UP,
    SUITES,
    find_suite,
)

from . import test_decryption_check as check
from .test_decryption import run, server
from .test_decryption_rule_update import OLD_TLS, REC, RESIGN, Fmc, apply, args
from .test_decryption_tls_conditions import block_args, mock


def codes(suites: Any) -> set[int]:
    return {s.code for s in suites}


def test_recorded_resign_results() -> None:
    # stripped and strong: the downgrade (each fell back to ECDHE-RSA-AES128-CBC-SHA, or TLS 1.3 AES-128-GCM)
    assert codes(RESIGN_DOWNGRADED) == {52392, 49310, 49248, 4868}
    assert find_suite("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256") in RESIGN_DOWNGRADED
    assert find_suite("0xC0,0x9E").name == "TLS_DHE_RSA_WITH_AES_128_CCM"  # type: ignore[union-attr]
    assert find_suite("0x1304").name == "TLS_AES_128_CCM_SHA256"  # type: ignore[union-attr]
    # stripped and weak: the only "step-up" (NULL-SHA, RC4-MD5, RC4-SHA, ECDHE-RC4, Camellia-CBC)
    assert codes(RESIGN_STEPPED_UP) == {2, 4, 5, 49169, 65, 132}
    # forwarded and decrypted unchanged: 3DES, CBC, RSA key exchange, DHE/ECDHE AES-GCM, TLS 1.3 GCM/ChaCha20
    decrypted = {s.code for s in SUITES if s.resign == "decrypted"}
    assert decrypted == {10, 49170, 47, 60, 156, 51, 49171, 49191, 158, 49199, 4865, 4867}
    # what the downgraded TLS 1.2 sessions ended on is decrypted, weak, and in the weak preset
    fallback = BY_CODE[49171]
    assert fallback.name == "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" and fallback.weak
    assert fallback.resign == "decrypted" and fallback in PRESETS["weak"]
    # TLS 1.3 ChaCha20 is decrypted, TLS 1.2 ChaCha20 isn't
    assert BY_CODE[4867].resign == "decrypted" and BY_CODE[52392].resign == "stripped"
    # the new suites weren't tried on FMC, so they stay out of the weak preset
    assert not codes(PRESETS["weak"]) & {65, 132, 49310, 49248, 4868}
    assert len(codes(SUITES)) == len(SUITES)


def test_warning_text() -> None:
    for words in ("ChaCha20", "AES-CCM", "ARIA", "ECDHE-RSA-AES128-CBC-SHA", "never steps a session up"):
        assert words in RESIGN_DOWNGRADE
    assert "DO_NOT_DECRYPT" in RESIGN_DOWNGRADE and "Known Key" in RESIGN_DOWNGRADE


async def test_create_resign_rule_warns(fmc: respx.MockRouter) -> None:
    mock(fmc)
    resign = {
        "policy": "tls-cipher-dec",
        "name": "resign2",
        "action": "DECRYPT_RESIGN",
        "internal_ca": "tls-cipher-resign-ca",
        "source_zones": ["tls-inside"],
        "destination_ports": ["tcp/10443"],
    }
    async with Client(server()) as c:
        dec = await run(c, "fmc_create_decryption_rule", resign)
        dnd = await run(c, "fmc_create_decryption_rule", block_args(name="dnd", action="DO_NOT_DECRYPT"))
        blk = await run(c, "fmc_create_decryption_rule", block_args(tls_versions=["tls10"]))
    assert dec["status"] == "preview" and RESIGN_DOWNGRADE in dec["side_effects"]
    assert RESIGN_DOWNGRADE not in dnd["side_effects"] and RESIGN_DOWNGRADE not in blk["side_effects"]


async def test_update_resign_rule_warns(fmc: respx.MockRouter) -> None:
    Fmc(fmc, REC["rules_before"]["items"])
    async with Client(server()) as c:
        moved = await run(c, "fmc_update_decryption_rule", args("resign-stepup", insert_before=1))
        off = await run(c, "fmc_update_decryption_rule", args("resign-stepup", enabled=False))
        blk = await run(c, "fmc_update_decryption_rule", args("block-old-tls", log=False))
    assert RESIGN_DOWNGRADE in moved["side_effects"]
    assert moved["side_effects"][0].startswith("After this change:")  # the order warning stays first
    assert RESIGN_DOWNGRADE not in off["side_effects"]  # disabling it removes the risk
    assert RESIGN_DOWNGRADE not in blk["side_effects"]
    assert RESIGN["ruleAction"] == "DECRYPT_RESIGN" and OLD_TLS["ruleAction"] != "DECRYPT_RESIGN"


async def test_update_resign_rule_confirm_still_applies(fmc: respx.MockRouter) -> None:
    lab = Fmc(fmc, REC["rules_before"]["items"])
    lab.put(fmc, RESIGN, "rules_before")
    async with Client(server()) as c:
        p, done = await apply(c, args("resign-stepup", log=False))
    assert RESIGN_DOWNGRADE in p["side_effects"] and done["status"] != "preview"


async def test_check_reports_the_downgrade(fmc: respx.MockRouter) -> None:
    check.mock(fmc)
    out = await check.run(
        {"source": "192.0.2.10", "destination": "203.0.113.10", "access_policy": "mcp-test-tls-acp"}
    )
    assert out["action"] == "DECRYPT_RESIGN"
    checks = {c["check"]: c for c in out["readiness"]}
    assert checks["cipher downgrade"] == {"check": "cipher downgrade", "ok": None, "detail": RESIGN_DOWNGRADE}


async def test_check_exemption_has_no_downgrade(fmc: respx.MockRouter) -> None:
    check.mock(fmc)
    out = await check.run(
        {"source": "192.0.2.10", "destination": "203.0.113.66", "access_policy": "mcp-test-tls-acp"}
    )
    assert out["action"] == "DO_NOT_DECRYPT"
    assert "cipher downgrade" not in {c["check"] for c in out.get("readiness", [])}

"""F82 and F83: TLS version and cipher suite conditions on decryption rules, cipher suite list objects, the
policy's Undecryptable Actions and default-action logging. Recorded answers from the ftd-tls-cipher-policy
lab (FMC 10.0.1): tests/fixtures/decryption_tls_conditions_fmc10.json."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.cipher_suites import PRESETS, find_suite
from fmc_mcp.tools.decryption import (
    default_logged,
    order_problems,
    rule_row,
    undecryptable_row,
    versions_on,
)

from . import test_decryption_check as check
from .conftest import CFG, fixture, items
from .test_decryption import FX, run, server

REC = fixture("decryption_tls_conditions_fmc10")
POL = REC["policy"]
RULES = REC["rules"]["items"]  # resign-stepup (index 3), block-old-tls (1), block-weak-ciphers (2)
RESIGN, OLD_TLS, WEAK = RULES
LIST = REC["lists"]["items"][0]
DEC = f"{CFG}/policy/decryptionpolicies"
PRULES = f"{DEC}/{POL['id']}/decryptionpolicyrules"
LISTS = f"{CFG}/object/ciphersuitelists"
INSIDE, OUTSIDE = RESIGN["sourceZones"]["objects"][0], RESIGN["destinationZones"]["objects"][0]
# after the live proof with the new tools: block-weak-ciphers on tls-weak-no-rc4, unsupported cipher suite
# BLOCK_WITH_RESET, default-action logging on
FINAL_POL, FINAL_RULES = REC["policy_final"], REC["rules_final"]["items"]
NO_RC4, PRESET_LIST = REC["lists_final"]["items"]
IGNORED_LOG = REC["policy_after_event_log_put"]  # PUT with only eventLogAction: FMC kept LOG_NONE
CA = {**FX["internal_ca"], **RESIGN["decryptionCerts"]["objects"][0]}  # a ready CA, under the lab's name


def mock(fmc: respx.MockRouter, rules: list[dict[str, Any]] | None = None, policy: Any = None) -> None:
    pol = policy or POL
    fmc.get(DEC).mock(return_value=items([pol]))
    fmc.get(f"{DEC}/{pol['id']}").mock(return_value=httpx.Response(200, json=pol))
    fmc.get(PRULES).mock(return_value=items(RULES if rules is None else rules))
    fmc.get(LISTS).mock(return_value=items([LIST]))
    fmc.get(f"{LISTS}/{LIST['id']}").mock(return_value=httpx.Response(200, json=LIST))
    fmc.get(f"{CFG}/object/securityzones").mock(return_value=items([INSIDE, OUTSIDE]))
    fmc.get(f"{CFG}/object/interfacegroups").mock(return_value=items([]))
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/internalcas").mock(return_value=items([CA]))
    fmc.get(f"{CFG}/object/internalcas/{CA['id']}").mock(return_value=httpx.Response(200, json=CA))


def block_args(**kw: Any) -> dict[str, Any]:
    return {
        "policy": "tls-cipher-dec",
        "name": "block-old",
        "action": "BLOCK_WITH_RESET",
        "source_zones": ["tls-inside"],
        "destination_zones": ["tls-outside"],
        "log": True,
        **kw,
    }


# --- F82: rules ----------------------------------------------------------------------------------------


def test_rule_rows_show_versions_and_lists() -> None:
    """FMC 10.0.1's rows: block-old-tls has three versions on, block-weak-ciphers a list, resign none."""
    assert rule_row(OLD_TLS)["tls_versions"] == ["sslv3", "tls10", "tls11"]
    assert "cert_conditions" not in rule_row(OLD_TLS)
    assert rule_row(WEAK)["cipher_suite_lists"] == ["tls-weak-ciphers"] and "tls_versions" not in rule_row(
        WEAK
    )
    assert "tls_versions" not in rule_row(RESIGN) and "cipher_suite_lists" not in rule_row(RESIGN)
    # all five off is what FMC stores for a rule created without versions: every version
    assert versions_on({"tlsVersions": dict.fromkeys(OLD_TLS["tlsVersions"], False)}) is None


async def test_block_rule_with_versions(fmc: respx.MockRouter) -> None:
    mock(fmc, rules=[])
    post = fmc.post(PRULES).mock(return_value=httpx.Response(201, json={**OLD_TLS, "id": "r9"}))
    args = block_args(tls_versions=["tls11", "sslv3", "tls10"])
    async with Client(server()) as c:
        p = await run(c, "fmc_create_decryption_rule", args)
        assert p["status"] == "preview", p
        assert p["preview"]["tls_versions"] == ["sslv3", "tls10", "tls11"]
        assert p["preview"]["rule"]["tls_versions"] == ["sslv3", "tls10", "tls11"]
        await run(c, "fmc_create_decryption_rule", {**args, "confirm": p["confirm"]})
    body = json.loads(post.calls.last.request.content)
    # what the lab's block-old-tls holds (FMC 10.0.1 deploys it on a Block rule)
    assert body["tlsVersions"] == OLD_TLS["tlsVersions"]
    assert body["ruleAction"] == "BLOCK_WITH_RESET" and "cipherSuiteLists" not in body
    assert body["sourceZones"]["objects"][0]["name"] == "tls-inside"


async def test_block_rule_with_cipher_list(fmc: respx.MockRouter) -> None:
    mock(fmc, rules=[OLD_TLS])
    post = fmc.post(PRULES).mock(return_value=httpx.Response(201, json={**WEAK, "id": "r9"}))
    args = block_args(name="block-weak", cipher_suite_lists=["tls-weak-ciphers"])
    async with Client(server()) as c:
        p = await run(c, "fmc_create_decryption_rule", args)
        assert p["preview"]["rule"]["cipher_suite_lists"] == ["tls-weak-ciphers"]
        assert p["preview"]["tls_versions"] == "all"
        await run(c, "fmc_create_decryption_rule", {**args, "confirm": p["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["cipherSuiteLists"] == {
        "objects": [{"id": LIST["id"], "name": "tls-weak-ciphers", "type": "CipherSuiteList"}]
    }
    assert all(body["tlsVersions"].values())  # as the lab's block-weak-ciphers


async def test_conditions_refused_on_decrypt_rules(fmc: respx.MockRouter) -> None:
    mock(fmc)
    async with Client(server()) as c:
        for action, extra in (
            ("DO_NOT_DECRYPT", {"tls_versions": ["tls10"]}),
            ("DECRYPT_RESIGN", {"cipher_suite_lists": ["tls-weak-ciphers"], "internal_ca": "x"}),
            ("DECRYPT_KNOWN_KEY", {"tls_versions": ["tls10"], "internal_certificates": ["x"]}),
        ):
            with pytest.raises(ToolError, match=f"not {action}: FMC 10 refuses"):
                await run(c, "fmc_create_decryption_rule", block_args(action=action, **extra))
        # all five versions is no condition: a Block rule needs another one
        every = await run(
            c,
            "fmc_create_decryption_rule",
            {
                "policy": "tls-cipher-dec",
                "name": "b",
                "action": "BLOCK",
                "tls_versions": ["sslv3", "tls10", "tls11", "tls12", "tls13"],
            },
        )
        assert any("match all TLS traffic" in b for b in every["blockers"])
        assert any("every version" in s for s in every["side_effects"])
        # all five versions on a decrypt rule is no condition either, so it isn't refused
        every5 = ["sslv3", "tls10", "tls11", "tls12", "tls13"]
        dnd = await run(
            c, "fmc_create_decryption_rule", {**block_args(action="DO_NOT_DECRYPT"), "tls_versions": every5}
        )
        assert dnd["status"] == "preview" and dnd["preview"]["tls_versions"] == "all"
        # MONITOR takes them
        mon = await run(c, "fmc_create_decryption_rule", block_args(action="MONITOR", tls_versions=["tls10"]))
        assert mon["status"] == "preview"


async def test_resign_above_cipher_block_warns(fmc: respx.MockRouter) -> None:
    """The live finding: a Decrypt-Resign rule above a cipher Block rule lets decryptable weak suites
    through, decrypted and allowed."""
    mock(fmc, rules=[OLD_TLS, WEAK])
    args = {
        "policy": "tls-cipher-dec",
        "name": "resign2",
        "action": "DECRYPT_RESIGN",
        "internal_ca": "tls-cipher-resign-ca",
        "source_zones": ["tls-inside"],
        "destination_ports": ["tcp/10443"],
    }
    async with Client(server()) as c:
        top = await run(c, "fmc_create_decryption_rule", {**args, "insert_before": 2})
        bottom = await run(c, "fmc_create_decryption_rule", args)
        apart = await run(
            c, "fmc_create_decryption_rule", {**args, "insert_before": 1, "source_zones": ["tls-outside"]}
        )
    warn = [s for s in top["side_effects"] if "pass decrypted" in s]
    assert len(warn) == 1 and "above Block rule(s) 2 'block-weak-ciphers'" in warn[0]
    assert "'block-old-tls'" not in warn[0] and "omit insert_before" in warn[0]
    assert not any("pass decrypted" in s for s in bottom["side_effects"])
    # source zone tls-outside: no session matches both rules
    assert not any("pass decrypted" in s for s in apart["side_effects"])


async def test_cipher_block_below_resign_warns(fmc: respx.MockRouter) -> None:
    mock(fmc, rules=[{**RESIGN, "metadata": {"ruleIndex": 1}}])
    args = block_args(name="block-weak", cipher_suite_lists=["tls-weak-ciphers"])
    async with Client(server()) as c:
        late = await run(c, "fmc_create_decryption_rule", args)
        early = await run(c, "fmc_create_decryption_rule", {**args, "insert_before": 1})
    warn = [s for s in late["side_effects"] if "pass decrypted" in s]
    assert len(warn) == 1 and "below decrypt rule(s) 1 'resign-stepup'" in warn[0]
    assert "insert_before=1" in warn[0]
    assert not any("pass decrypted" in s for s in early["side_effects"])


async def test_get_policy_rules_in_order_with_conditions(fmc: respx.MockRouter) -> None:
    mock(fmc)
    async with Client(server()) as c:
        out = await run(
            c, "fmc_get_decryption_policy", {"policy": "tls-cipher-dec", "response_format": "json"}
        )
    # FMC 10.0.1 lists them in creation order (resign-stepup first); shown by index
    assert [r["name"] for r in out["rules"]] == ["block-old-tls", "block-weak-ciphers", "resign-stepup"]
    assert out["rules"][0]["tls_versions"] == ["sslv3", "tls10", "tls11"]
    assert out["rules"][1]["cipher_suite_lists"] == ["tls-weak-ciphers"]
    assert not any("pass decrypted" in n for n in out.get("readiness", []))
    # F83
    assert out["undecryptable"]["unsupported_cipher_suite"] == "BLOCK_WITH_RESET"
    assert out["undecryptable"]["decryption_errors"] == "BLOCK" and len(out["undecryptable"]) == 7
    assert out["default_log"] is False


def test_final_live_state_reads_back() -> None:
    """What the new tools left on FMC 10.0.1, read back the way fmc_get_decryption_policy shows it."""
    rows = {r["name"]: r for r in map(rule_row, FINAL_RULES)}
    assert rows["block-old-tls"]["tls_versions"] == ["sslv3", "tls10", "tls11"]
    assert rows["block-weak-ciphers"]["cipher_suite_lists"] == ["tls-weak-no-rc4"]
    assert order_problems(FINAL_RULES) == []
    assert default_logged(FINAL_POL) and not default_logged(IGNORED_LOG)
    assert undecryptable_row(FINAL_POL)["unsupported_cipher_suite"] == "BLOCK_WITH_RESET"
    assert [find_suite(lit["value"]).fmc for lit in PRESET_LIST["literals"]] == ["accepted"] * 23  # type: ignore[union-attr]


def test_order_problems() -> None:
    """The lab's order, then the resign rule moved to the top (the 'things to try' in the recipe)."""
    assert order_problems(RULES) == []
    moved = [
        {**RESIGN, "metadata": {"ruleIndex": 1}},
        {**OLD_TLS, "metadata": {"ruleIndex": 2}},
        {**WEAK, "metadata": {"ruleIndex": 3}},
    ]
    (problem,) = order_problems(moved)
    assert "rule 1 'resign-stepup'" in problem and "2 'block-old-tls', 3 'block-weak-ciphers'" in problem
    assert order_problems([*moved[:2], {**moved[2], "enabled": False}])[0].endswith(
        "Put the Block rules first."
    )
    # literal destination ports that can't overlap: no session matches both
    port = {"type": "PortLiteral", "protocol": "6"}
    on_443 = {**moved[1], "destinationPorts": {"literals": [{**port, "port": "443"}]}}
    assert "'block-old-tls'" not in order_problems([moved[0], on_443, moved[2]])[0]
    on_range = {**moved[1], "destinationPorts": {"literals": [{**port, "port": "11000-11500"}]}}
    assert "'block-old-tls'" in order_problems([moved[0], on_range, moved[2]])[0]  # 11443 is in it


# --- F82: cipher suite lists ---------------------------------------------------------------------------


def test_weak_preset_is_the_lab_list_and_the_probe() -> None:
    """The preset is the 17 suites FMC 10.0.1 accepted in tls-weak-ciphers, then the NULL, EXPORT, DES and
    RC4-MD5 suites the probe saw accepted; the anonymous ones it refused are left out."""
    lab = [(lit["name"], lit["value"]) for lit in LIST["literals"]]
    preset = [(s.name, str(s.code)) for s in PRESETS["weak"]]
    assert preset[:17] == lab and len(preset) == 23
    probe = REC["probe"]
    assert sorted(int(v) for _, v in preset[17:]) == sorted(probe["accepted"])
    assert all(find_suite(str(c)).fmc == "refused" for c in probe["refused"])  # type: ignore[union-attr]
    assert all(find_suite(str(c)).fmc == "accepted" for c in probe["accepted"])  # type: ignore[union-attr]


def test_find_suite() -> None:
    assert find_suite("tls_rsa_with_aes_128_cbc_sha") == find_suite("47") == find_suite("0x002F")
    assert find_suite("0x00,0x2F") == find_suite("SSL_RSA_WITH_AES_128_CBC_SHA")
    assert find_suite("TLS_RSA_WITH_AES_128_CBC_SHA").code == 47  # type: ignore[union-attr]
    assert find_suite("AES128-SHA") is None and find_suite("") is None and find_suite("99999") is None
    assert find_suite("0xC0,0x9") == find_suite("0xc0, 0x09") == find_suite("49161")
    assert find_suite("4_7") is None and find_suite("+47") is None and find_suite("0x12345") is None


async def test_create_list_from_preset_and_names(fmc: respx.MockRouter) -> None:
    fmc.get(LISTS).mock(return_value=items([LIST]))
    post = fmc.post(LISTS).mock(return_value=httpx.Response(201, json={**LIST, "id": "l2", "name": "weak2"}))
    args = {"name": "weak2", "preset": "weak", "suites": ["0xC013", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_create_cipher_suite_list", args)
        assert p["status"] == "preview" and len(p["preview"]["suites"]) == 24  # 0xC013 is in the preset
        (untried,) = [s for s in p["side_effects"] if "Not yet seen accepted" in s]
        assert "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" in untried and "NULL" not in untried
        await run(c, "fmc_create_cipher_suite_list", {**args, "confirm": p["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["type"] == "CipherSuiteList" and body["literals"][:17] == LIST["literals"]
    assert body["literals"][17] == {"name": "TLS_RSA_WITH_NULL_SHA", "value": "2"}
    assert body["literals"][23] == {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "value": "49191"}


async def test_create_list_blockers(fmc: respx.MockRouter) -> None:
    fmc.get(LISTS).mock(return_value=items([LIST]))
    async with Client(server()) as c:
        dup = await run(c, "fmc_create_cipher_suite_list", {"name": "tls-weak-ciphers", "preset": "weak"})
        bad = await run(c, "fmc_create_cipher_suite_list", {"name": "x", "suites": ["AES128-SHA", "47"]})
        none = await run(c, "fmc_create_cipher_suite_list", {"name": "x"})
        strong = await run(c, "fmc_create_cipher_suite_list", {"name": "x", "suites": ["49199"]})
        anon = await run(c, "fmc_create_cipher_suite_list", {"name": "x", "suites": ["5", "0x0034"]})
    assert dup["status"] == "blocked" and "already exists" in dup["blockers"][0]
    assert (
        bad["status"] == "blocked"
        and "Not a cipher suite this server knows: AES128-SHA" in bad["blockers"][0]
    )
    assert "Give suites" in none["blockers"][0]
    assert anon["blockers"] == [
        "FMC 10.0.1 refuses TLS_DH_anon_WITH_AES_128_CBC_SHA (not in its predefined suites): leave them out."
    ]
    assert any(
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in s and "blocks sessions" in s
        for s in strong["side_effects"]
    )


async def test_create_list_sha_error_names_untried_suites(fmc: respx.MockRouter) -> None:
    fmc.get(LISTS).mock(return_value=items([]))
    sha = {
        "error": {"category": "FRAMEWORK", "messages": [{"description": "Not saved. The SHA is incorrect."}]}
    }
    fmc.post(LISTS).mock(return_value=httpx.Response(400, json=sha))
    args = {"name": "x", "suites": ["47", "TLS_RSA_WITH_NULL_MD5"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_create_cipher_suite_list", args)
        with pytest.raises(ToolError, match="not yet seen accepted: TLS_RSA_WITH_NULL_MD5"):
            await c.call_tool("fmc_create_cipher_suite_list", {**args, "confirm": p["confirm"]})


async def test_list_cipher_suite_lists(fmc: respx.MockRouter) -> None:
    mixed = {
        **LIST,
        "id": "l2",
        "name": "mixed",
        "literals": [
            *LIST["literals"][:2],
            {"name": "X", "value": "1"},
            {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "value": "49199"},
            {"name": "Y", "value": "777"},
        ],
    }
    fmc.get(LISTS).mock(return_value=items([LIST, mixed]))
    async with Client(server()) as c:
        rows = (await run(c, "fmc_list_cipher_suite_lists", {"response_format": "json"}))["results"]
        one = await run(
            c, "fmc_list_cipher_suite_lists", {"name": "tls-weak-ciphers", "response_format": "json"}
        )
        known = await run(c, "fmc_list_cipher_suite_lists", {"known_suites": True, "response_format": "json"})
    assert rows[0] == {"name": "tls-weak-ciphers", "suites": 17, "weak": 17, "id": LIST["id"]}
    assert rows[1]["strong"] == ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] and rows[1]["unknown"] == ["Y"]
    assert rows[1]["weak"] == 3  # code 1 is TLS_RSA_WITH_NULL_MD5 whatever FMC calls it
    assert one["suites"][0] == {"name": "TLS_RSA_WITH_RC4_128_SHA", "code": "5", "weak": "RC4"}
    rc4 = next(r for r in known["results"] if r["code"] == 5)
    assert rc4["hex"] == "0x0005" and rc4["fmc_10_0_1"] == "accepted" and rc4["weak_preset"] is True


# --- F83: undecryptable actions and default-action logging --------------------------------------------


async def test_update_undecryptable_and_default_log(fmc: respx.MockRouter) -> None:
    inherit = {
        **POL,
        "undecryptableActions": {
            **POL["undecryptableActions"],
            "unsupportedCipherSuite": "INHERIT_DEFAULT_ACTION",
        },
    }
    mock(fmc, policy=inherit)
    put = fmc.put(f"{DEC}/{POL['id']}").mock(return_value=httpx.Response(200, json=FINAL_POL))
    args = {
        "policy": "tls-cipher-dec",
        "undecryptable": {"unsupported_cipher_suite": "BLOCK_WITH_RESET", "decryption_errors": "BLOCK"},
        "default_log": True,
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_update_decryption_policy", args)
        assert p["preview"]["changes"] == {
            "undecryptable": {
                "unsupported_cipher_suite": {"from": "INHERIT_DEFAULT_ACTION", "to": "BLOCK_WITH_RESET"}
            },
            "default_log": {"from": False, "to": True},
        }
        done = await run(c, "fmc_update_decryption_policy", {**args, "confirm": p["confirm"]})
        assert done["status"] == "applied" and "warning" not in done["result"]
        same = await run(
            c,
            "fmc_update_decryption_policy",
            {"policy": "tls-cipher-dec", "undecryptable": {"decryption_errors": "BLOCK"}},
        )
        assert same["blockers"] == ["Nothing to change."]
        with pytest.raises(ToolError):  # decryption errors can only be blocked
            await run(
                c,
                "fmc_update_decryption_policy",
                {"policy": "tls-cipher-dec", "undecryptable": {"decryption_errors": "DO_NOT_DECRYPT"}},
            )
        with pytest.raises(ToolError):  # FMC's own key names aren't ours
            await run(
                c,
                "fmc_update_decryption_policy",
                {"policy": "tls-cipher-dec", "undecryptable": {"unsupportedCipherSuite": "BLOCK"}},
            )
    sent = json.loads(put.calls.last.request.content)
    # the full-body PUT FMC 10.0.1 accepted live: the other actions unchanged
    assert sent["undecryptableActions"] == POL["undecryptableActions"]
    assert sent["defaultAction"] == {"policyAction": "DO_NOT_DECRYPT", "eventLogAction": "LOG_FLOW_END"}
    # FMC 10.0.1 keys default-action logging off the policy's `logging` (eventLogAction alone is dropped)
    assert sent["logging"] == {"logEnd": True, "sendEvents": True} == FINAL_POL["logging"]
    assert FINAL_POL["defaultAction"]["eventLogAction"] == "LOG_FLOW_END"
    assert "metadata" not in sent and sent["trustedCAs"] == POL["trustedCAs"]


async def test_default_log_says_when_fmc_drops_it(fmc: respx.MockRouter) -> None:
    """Live: a PUT with defaultAction.eventLogAction LOG_FLOW_END alone came back (and stayed) LOG_NONE."""
    mock(fmc, policy=IGNORED_LOG)
    fmc.put(f"{DEC}/{POL['id']}").mock(return_value=httpx.Response(200, json=IGNORED_LOG))
    args = {"policy": "tls-cipher-dec", "default_log": True}
    async with Client(server()) as c:
        p = await run(c, "fmc_update_decryption_policy", args)
        done = await run(c, "fmc_update_decryption_policy", {**args, "confirm": p["confirm"]})
    assert "without default-action logging on" in done["result"]["warning"]


# --- F82/F83: fmc_tls_decryption_check -----------------------------------------------------------------

FLOW = {
    "source": "10.1.2.2",
    "destination": "10.1.3.3",
    "port": 12443,
    "decryption_policy": "tls-cipher-dec",
    "source_zone": "tls-inside",
    "destination_zone": "tls-outside",
}


def check_mock(fmc: respx.MockRouter, rules: list[dict[str, Any]], policy: dict[str, Any]) -> None:
    check.mock(fmc, rules=rules, policy=policy)
    fmc.get(f"{CFG}/object/internalcas/{CA['id']}").mock(return_value=httpx.Response(200, json=CA))
    for lst in (LIST, NO_RC4, PRESET_LIST):
        fmc.get(f"{LISTS}/{lst['id']}").mock(return_value=httpx.Response(200, json=lst))


def undecryptable(out: dict[str, Any]) -> str:
    return str(next(c for c in out["readiness"] if c["check"] == "undecryptable sessions")["detail"])


async def test_check_names_the_unsupported_cipher_action(fmc: respx.MockRouter) -> None:
    """The lab's only-rc4 case (the resign rule takes the flow; RC4 can't be decrypted), in the three
    states of the live proof."""
    inherit = {
        **FINAL_POL,
        "undecryptableActions": {
            **FINAL_POL["undecryptableActions"],
            "unsupportedCipherSuite": "INHERIT_DEFAULT_ACTION",
        },
    }
    # deploy 1: block-weak-ciphers on a list with RC4 -> FTD reset only-rc4 there (SSLRuleName
    # block-weak-ciphers), before the Unsupported Cipher Suite action
    check_mock(fmc, RULES, inherit)
    out = await check.run(FLOW)
    assert out["verdict"] == "Rule 3 'resign-stepup' -> DECRYPT_RESIGN"
    first = out["may_match_first"]
    assert [r["name"] for r in first] == ["block-old-tls", "block-weak-ciphers"]
    assert first[0]["matches_if"] == ["the session negotiates sslv3, tls10, tls11"]
    assert first[1]["matches_if"][0].startswith("the server picks a suite in tls-weak-ciphers")
    assert "stopped first by rule 2 'block-weak-ciphers' (tls-weak-ciphers)" in undecryptable(out)
    assert "Unsupported cipher suite -> DO_NOT_DECRYPT applies to the other suites" in undecryptable(out)
    assert not any(c["check"] == "rule order" for c in out["readiness"])
    # the list without RC4 and 'inherit': RC4 passes undecrypted (the F83 issue's live 'before')
    check_mock(fmc, FINAL_RULES, inherit)
    detail = undecryptable(await check.run(FLOW))
    assert "-> DO_NOT_DECRYPT (inherited from the default action): a session whose server picks RC4" in detail
    assert "decryption errors -> BLOCK" in detail
    # deploy 2: BLOCK_WITH_RESET -> only-rc4 reset by resign-stepup, flow status Unsupported Cipher Suite
    check_mock(fmc, FINAL_RULES, FINAL_POL)
    assert "-> BLOCK_WITH_RESET." in undecryptable(await check.run(FLOW))


async def test_check_flags_resign_above_block(fmc: respx.MockRouter) -> None:
    moved = [{**RESIGN, "metadata": {"ruleIndex": 1}}, {**OLD_TLS, "metadata": {"ruleIndex": 2}}]
    check.mock(fmc, rules=moved, policy=POL)
    out = await check.run({**FLOW, "port": 443})  # not the resign rule's ports: still a policy-wide check
    order = next(c for c in out["readiness"] if c["check"] == "rule order")
    assert (
        order["ok"] is False and "'resign-stepup' is above Block rule(s) 2 'block-old-tls'" in order["detail"]
    )

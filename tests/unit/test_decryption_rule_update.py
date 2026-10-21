"""F82 (#276), last scope item: fmc_update_decryption_rule (an existing rule's TLS versions, cipher suite
lists, enabled, logging and position) and fmc_delete_object on cipher suite lists. Recorded answers from the
ftd-tls-cipher-policy lab (FMC 10.0.1): tests/fixtures/decryption_rule_update_fmc10.json."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.tools.decryption import ALL_TLS_VERSIONS, rule_body

from .conftest import CFG, CHILD, fixture, items
from .test_decryption import run, server

REC = fixture("decryption_rule_update_fmc10")
POL = fixture("decryption_tls_conditions_fmc10")["policy"]  # the same policy, read in the F82 run
DEC = f"{CFG}/policy/decryptionpolicies"
PRULES = f"{DEC}/{POL['id']}/decryptionpolicyrules"
LISTS = f"{CFG}/object/ciphersuitelists"
CHILD_DEC = f"/api/fmc_config/v1/domain/{CHILD}/policy/decryptionpolicies"


def by_name(state: str) -> dict[str, dict[str, Any]]:
    return {r["name"]: r for r in REC[state]["items"]}


BEFORE = by_name("rules_before")  # block-old-tls 1, block-weak-ciphers 2 (tls-weak-no-rc4), resign-stepup 3
WEAK, OLD_TLS, RESIGN = BEFORE["block-weak-ciphers"], BEFORE["block-old-tls"], BEFORE["resign-stepup"]
CIPHERS, NO_RC4, PRESET = REC["lists_before"]["items"]  # tls-weak-ciphers, tls-weak-no-rc4, tls-weak-preset


class Fmc:
    """The policy's rules as FMC holds them: a PUT moves to `after` (the recorded state) and answers
    `answer` (FMC 10.0.1: 200 with the rule, or 500 "JsonNull" when the PUT moves it)."""

    def __init__(self, fmc: respx.MockRouter, rules: list[dict[str, Any]]) -> None:
        self.rules = rules
        fmc.get(DEC).mock(return_value=items([POL]))
        fmc.get(PRULES).mock(side_effect=lambda _: items(self.rules))
        fmc.get(LISTS).mock(return_value=items(REC["lists_before"]["items"]))
        fmc.get(CHILD_DEC).mock(return_value=items([]))

    def put(self, fmc: respx.MockRouter, rule: dict[str, Any], after: str, status: int = 200) -> respx.Route:
        stored = by_name(after)[rule["name"]]

        def answer(_: httpx.Request) -> httpx.Response:
            self.rules = REC[after]["items"]
            body = stored if status == 200 else REC["put_500"]
            return httpx.Response(status, json=body)

        fmc.get(f"{PRULES}/{rule['id']}").mock(side_effect=lambda _: httpx.Response(200, json=stored))
        return fmc.put(f"{PRULES}/{rule['id']}").mock(side_effect=answer)


def args(rule: str, **kw: Any) -> dict[str, Any]:
    return {"policy": "tls-cipher-dec", "rule": rule, **kw}


async def apply(c: Client[Any], a: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    p = await run(c, "fmc_update_decryption_rule", a)
    assert p["status"] == "preview", p
    return p, await run(c, "fmc_update_decryption_rule", {**a, "confirm": p["confirm"]})


async def test_switch_cipher_suite_list(fmc: respx.MockRouter) -> None:
    """The live proof's first write: block-weak-ciphers from tls-weak-no-rc4 to tls-weak-preset."""
    lab = Fmc(fmc, REC["rules_before"]["items"])
    put = lab.put(fmc, WEAK, "rules_preset")
    async with Client(server()) as c:
        p, done = await apply(c, args("block-weak-ciphers", cipher_suite_lists=["tls-weak-preset"]))
    assert p["preview"]["changes"] == {
        "cipher_suite_lists": {"from": ["tls-weak-no-rc4"], "to": ["tls-weak-preset"]}
    }
    assert p["preview"]["index"] == 2 and p["side_effects"] == [
        "Takes effect on devices after the next deployment."
    ]
    assert done["status"] == "applied" and "warning" not in done["result"]
    sent = json.loads(put.calls.last.request.content)
    assert put.calls.last.request.url.params.get("insertBefore") is None
    # the whole rule back, as FMC 10.0.1 stored it: only the list changed
    assert sent == rule_body(by_name("rules_preset")["block-weak-ciphers"])
    assert {k: v for k, v in sent.items() if k != "cipherSuiteLists"} == {
        k: v for k, v in rule_body(WEAK).items() if k != "cipherSuiteLists"
    }


async def test_move_up_and_down(fmc: respx.MockRouter) -> None:
    """FMC 10.0.1 answers 500 "JsonNull" to a rule PUT with insertBefore or insertAfter but moves the rule;
    indexes count as they are before the move (insertAfter=2 from index 1 lands at 2)."""
    lab = Fmc(fmc, REC["rules_before"]["items"])
    up = lab.put(fmc, WEAK, "rules_moved_up", status=500)
    async with Client(server()) as c:
        p, done = await apply(c, args("block-weak-ciphers", insert_before=1))
        assert p["preview"]["changes"] == {"index": {"from": 2, "to": 1}}
        assert up.calls.last.request.url.params["insertBefore"] == "1"
        assert done["result"]["index"] == 1
        assert "answered 500" in done["result"]["warning"] and "saved the change" in done["result"]["warning"]
        assert json.loads(up.calls.last.request.content) == rule_body(WEAK)  # nothing else changes
        down = lab.put(fmc, WEAK, "rules_moved_down", status=500)
        p, done = await apply(c, args("block-weak-ciphers", insert_before=3))
    assert p["preview"]["changes"] == {"index": {"from": 1, "to": 2}}
    assert down.calls.last.request.url.params["insertAfter"] == "2"
    assert "insertBefore" not in down.calls.last.request.url.params
    assert done["result"]["index"] == 2 and "not 2" not in done["result"]["warning"]
    assert sorted((r["metadata"]["ruleIndex"], r["name"]) for r in REC["rules_moved_down"]["items"]) == [
        (1, "block-old-tls"),
        (2, "block-weak-ciphers"),
        (3, "resign-stepup"),
    ]


async def test_move_that_did_not_happen(fmc: respx.MockRouter) -> None:
    """A 500 counts as applied only when the rule really moved; a 200 that left it in place says so."""
    lab = Fmc(fmc, REC["rules_before"]["items"])
    lab.put(fmc, WEAK, "rules_before", status=500)  # 500 and nothing moved
    a = args("block-weak-ciphers", insert_before=1)
    async with Client(server()) as c:
        p = await run(c, "fmc_update_decryption_rule", a)
        with pytest.raises(ToolError, match="500"):
            await run(c, "fmc_update_decryption_rule", {**a, "confirm": p["confirm"]})
        lab.put(fmc, WEAK, "rules_before")  # 200, nothing moved
        _, done = await apply(c, a)
    assert "FMC put the rule at index 2, not 1" in done["result"]["warning"]


async def test_move_to_the_end(fmc: respx.MockRouter) -> None:
    """insert_before = rule count + 1: after the last rule (FMC's insertAfter, indexes before the move)."""
    lab = Fmc(fmc, REC["rules_before"]["items"])
    put = lab.put(fmc, OLD_TLS, "rules_before", status=500)
    at_end = [
        {**WEAK, "metadata": {**WEAK["metadata"], "ruleIndex": 1}},
        {**RESIGN, "metadata": {**RESIGN["metadata"], "ruleIndex": 2}},
        {**OLD_TLS, "metadata": {**OLD_TLS["metadata"], "ruleIndex": 3}},
    ]
    put.side_effect = lambda _: (setattr(lab, "rules", at_end), httpx.Response(500, json=REC["put_500"]))[1]
    async with Client(server()) as c:
        p, done = await apply(c, args("block-old-tls", insert_before=4))
    assert p["preview"]["changes"] == {"index": {"from": 1, "to": 3}}
    assert put.calls.last.request.url.params["insertAfter"] == "3"
    assert done["result"]["index"] == 3
    # a Block rule below the resign rule: the preview said so
    assert any("above Block rule(s) 3 'block-old-tls'" in s for s in p["side_effects"])


async def test_moves_stay_within_a_category(fmc: respx.MockRouter) -> None:
    mine = {**OLD_TLS, "metadata": {"ruleIndex": 1, "category": {"name": "mandatory_block"}}}
    Fmc(fmc, [mine, WEAK, RESIGN])
    async with Client(server()) as c:
        out = await run(c, "fmc_update_decryption_rule", args("block-old-tls", insert_before=4))
    assert out["blockers"] == [
        "Rule 3 is in category 'standard_category' and 'block-old-tls' in 'mandatory_block'; moves stay "
        "within a category (delete and re-create the rule to change it)."
    ]


async def test_500_without_the_change_fails(fmc: respx.MockRouter) -> None:
    lab = Fmc(fmc, REC["rules_before"]["items"])
    lab.put(fmc, WEAK, "rules_before", status=500)  # the rule still on tls-weak-no-rc4
    a = args("block-weak-ciphers", cipher_suite_lists=["tls-weak-preset"])
    async with Client(server()) as c:
        p = await run(c, "fmc_update_decryption_rule", a)
        with pytest.raises(ToolError, match="500"):
            await run(c, "fmc_update_decryption_rule", {**a, "confirm": p["confirm"]})


async def test_disable_and_unlog_round_trip(fmc: respx.MockRouter) -> None:
    lab = Fmc(fmc, REC["rules_before"]["items"])
    put = lab.put(fmc, OLD_TLS, "rules_disabled")
    async with Client(server()) as c:
        p, done = await apply(c, args("block-old-tls", enabled=False, log=False))
        assert p["preview"]["changes"] == {
            "enabled": {"from": True, "to": False},
            "log": {"from": True, "to": False},
        }
        off = json.loads(put.calls.last.request.content)
        assert off == rule_body(by_name("rules_disabled")["block-old-tls"])
        assert off["logging"] == {"logEnd": False, "sendEvents": False}
        put = lab.put(fmc, OLD_TLS, "rules_final")
        p, done = await apply(c, args("block-old-tls", enabled=True, log=True))
    assert json.loads(put.calls.last.request.content) == rule_body(OLD_TLS)  # back as it was
    assert done["result"]["enabled"] is True


async def test_tls_versions(fmc: respx.MockRouter) -> None:
    lab = Fmc(fmc, REC["rules_before"]["items"])
    put = lab.put(fmc, OLD_TLS, "rules_before")
    async with Client(server()) as c:
        p, _ = await apply(c, args("block-old-tls", tls_versions=["tls11", "tls10"]))
        every = await run(c, "fmc_update_decryption_rule", args("block-old-tls", tls_versions=[]))
        five = await run(
            c, "fmc_update_decryption_rule", args("block-old-tls", tls_versions=list(ALL_TLS_VERSIONS))
        )
        same = await run(
            c, "fmc_update_decryption_rule", args("block-old-tls", tls_versions=["sslv3", "tls10", "tls11"])
        )
    assert p["preview"]["changes"] == {
        "tls_versions": {"from": ["sslv3", "tls10", "tls11"], "to": ["tls10", "tls11"]}
    }
    assert json.loads(put.calls.last.request.content)["tlsVersions"] == {
        "sslv3": False,
        "tls10": True,
        "tls11": True,
        "tls12": False,
        "tls13": False,
    }
    assert every["preview"]["changes"]["tls_versions"]["to"] == "all"
    assert five["preview"]["changes"]["tls_versions"]["to"] == "all"
    assert any("every version, no condition" in s for s in five["side_effects"])
    assert same["blockers"] == ["Nothing to change."]


async def test_conditions_refused_on_decrypt_rules(fmc: respx.MockRouter) -> None:
    Fmc(fmc, REC["rules_before"]["items"])
    async with Client(server()) as c:
        for extra in ({"tls_versions": ["tls12"]}, {"cipher_suite_lists": ["tls-weak-preset"]}):
            with pytest.raises(ToolError, match="'resign-stepup' is DECRYPT_RESIGN: FMC 10 refuses"):
                await run(c, "fmc_update_decryption_rule", args("resign-stepup", **extra))
        # every version is no condition: allowed, and already so
        none = await run(c, "fmc_update_decryption_rule", args("resign-stepup", tls_versions=[]))
        assert none["blockers"] == ["Nothing to change."]
        # by index, and a rule that isn't there
        by_index = await run(c, "fmc_update_decryption_rule", args("3", tls_versions=[]))
        assert by_index["action"].startswith("Update decryption rule 'resign-stepup'")
        with pytest.raises(ToolError, match="No single rule 'nope'"):
            await run(c, "fmc_update_decryption_rule", args("nope", enabled=False))


async def test_resign_rule_without_versions_gets_every_version(fmc: respx.MockRouter) -> None:
    """FMC 10.0.1 stores all five versions off for a rule created without tlsVersions and then refuses to
    deploy a Do-not-decrypt or Decrypt-Resign rule with that; any update sends every version instead."""
    off = {**RESIGN, "tlsVersions": dict.fromkeys(ALL_TLS_VERSIONS, False)}
    lab = Fmc(fmc, [OLD_TLS, WEAK, off])
    put = lab.put(fmc, RESIGN, "rules_before")
    async with Client(server()) as c:
        p, _ = await apply(c, args("resign-stepup", log=False))
    assert p["preview"]["changes"]["tls_versions"] == {"from": "none selected", "to": "all"}
    assert any("has no TLS version selected" in s for s in p["side_effects"])
    assert json.loads(put.calls.last.request.content)["tlsVersions"] == ALL_TLS_VERSIONS


async def test_order_warnings_and_position_blockers(fmc: respx.MockRouter) -> None:
    Fmc(fmc, REC["rules_before"]["items"])
    async with Client(server()) as c:
        last = await run(c, "fmc_update_decryption_rule", args("block-weak-ciphers", insert_before=4))
        first = await run(c, "fmc_update_decryption_rule", args("resign-stepup", insert_before=1))
        beyond = await run(c, "fmc_update_decryption_rule", args("block-weak-ciphers", insert_before=9))
        here = await run(c, "fmc_update_decryption_rule", args("block-weak-ciphers", insert_before=3))
        swap = await run(c, "fmc_update_decryption_rule", args("block-old-tls", insert_before=3))
    # the previews of the live run (not confirmed)
    assert last["preview"]["changes"] == {"index": {"from": 2, "to": 3}}
    assert last["side_effects"][0].startswith(
        "After this change: DECRYPT_RESIGN rule 2 'resign-stepup' is above Block rule(s) "
        "3 'block-weak-ciphers'"
    )
    assert "above Block rule(s) 2 'block-old-tls', 3 'block-weak-ciphers'" in first["side_effects"][0]
    assert beyond["blockers"] == [
        "insert_before=9, but 'tls-cipher-dec' has 3 rule(s); insert_before=4 moves the rule to the end."
    ]
    assert here["blockers"] == ["Nothing to change."]  # just above rule 3 is where it is
    # Block rules swapping among themselves above the resign rule: no warning
    assert swap["preview"]["changes"] == {"index": {"from": 1, "to": 2}}
    assert not any("After this change" in s for s in swap["side_effects"])


async def test_remove_cipher_lists(fmc: respx.MockRouter) -> None:
    """[] sends the empty block FMC 10.0.1 returns for a rule without lists; an answer that still shows the
    list is flagged."""
    lab = Fmc(fmc, REC["rules_before"]["items"])
    put = lab.put(fmc, WEAK, "rules_before")  # FMC answers with the rule unchanged
    async with Client(server()) as c:
        p, done = await apply(c, args("block-weak-ciphers", cipher_suite_lists=[]))
    assert p["preview"]["changes"] == {"cipher_suite_lists": {"from": ["tls-weak-no-rc4"], "to": []}}
    sent = json.loads(put.calls.last.request.content)
    assert sent["cipherSuiteLists"] == {} == RESIGN["cipherSuiteLists"]
    assert "doesn't show the change" in done["result"]["warning"]


async def test_catch_all_rule_can_be_disabled_and_moved(fmc: respx.MockRouter) -> None:
    """A catch-all Decrypt-Resign rule (no conditions, the usual last rule) isn't blocked for matching
    everything: the update doesn't make it so."""
    conditions = ("sourceZones", "destinationZones", "destinationPorts")
    bare = {k: v for k, v in RESIGN.items() if k not in conditions}
    Fmc(fmc, [OLD_TLS, WEAK, bare])
    async with Client(server()) as c:
        off = await run(c, "fmc_update_decryption_rule", args("resign-stepup", enabled=False))
        up = await run(c, "fmc_update_decryption_rule", args("resign-stepup", insert_before=2))
    assert off["status"] == "preview"
    assert off["preview"]["changes"] == {"enabled": {"from": True, "to": False}}
    assert up["status"] == "preview" and "blockers" not in up


async def test_rule_left_without_conditions_is_blocked(fmc: respx.MockRouter) -> None:
    bare = {k: v for k, v in WEAK.items() if k not in ("sourceZones", "destinationZones")}
    Fmc(fmc, [OLD_TLS, bare, RESIGN])
    async with Client(server()) as c:
        out = await run(c, "fmc_update_decryption_rule", args("block-weak-ciphers", cipher_suite_lists=[]))
    assert out["preview"]["changes"]["cipher_suite_lists"] == {"from": ["tls-weak-no-rc4"], "to": []}
    assert out["blockers"] == [
        "'block-weak-ciphers' (BLOCK_WITH_RESET) would have no condition left and match all TLS traffic."
    ]


async def test_token_covers_the_lists_suites(fmc: respx.MockRouter) -> None:
    lab = Fmc(fmc, REC["rules_before"]["items"])
    lab.put(fmc, WEAK, "rules_preset")
    a = args("block-weak-ciphers", cipher_suite_lists=["tls-weak-preset"])
    async with Client(server()) as c:
        p = await run(c, "fmc_update_decryption_rule", a)
        fewer = {**PRESET, "literals": PRESET["literals"][:3]}
        fmc.get(LISTS).mock(return_value=items([CIPHERS, NO_RC4, fewer]))
        with pytest.raises(ToolError, match="changed since the preview"):
            await run(c, "fmc_update_decryption_rule", {**a, "confirm": p["confirm"]})


# --- fmc_delete_object on cipher suite lists ---------------------------------------------------------


def delete_mocks(fmc: respx.MockRouter, rules: str, child: list[dict[str, Any]] | None = None) -> respx.Route:
    """The lab's lists and rules; FMC's usage API refuses cipher suite lists (it must not be needed)."""
    Fmc(fmc, REC[rules]["items"])
    fmc.get(f"{CFG}/object/operational/usage", name="usage").mock(
        return_value=httpx.Response(400, json=REC["usage_400"])
    )
    if child is not None:
        kid = {"id": "c1", "name": "branch-dec", "type": "DecryptionPolicy"}
        fmc.get(CHILD_DEC).mock(return_value=items([kid]))
        fmc.get(f"{CHILD_DEC}/c1/decryptionpolicyrules").mock(return_value=items(child))
    return fmc.delete(f"{LISTS}/{PRESET['id']}").mock(
        return_value=httpx.Response(200, json=REC["preset_list"])
    )


async def test_delete_unused_cipher_list(fmc: respx.MockRouter) -> None:
    """The live run's last write: tls-weak-preset, once block-weak-ciphers was back on tls-weak-no-rc4."""
    delete = delete_mocks(fmc, "rules_final")
    usage = fmc.routes["usage"]
    a = {"object": "tls-weak-preset", "type": "cipher_suite_list"}
    async with Client(server()) as c:
        p = await run(c, "fmc_delete_object", a)
        assert p["status"] == "preview" and p["action"] == "Delete cipher_suite_list 'tls-weak-preset'"
        done = await run(c, "fmc_delete_object", {**a, "confirm": p["confirm"]})
    assert done["status"] == "applied" and delete.called and not usage.called
    assert [x["name"] for x in REC["lists_final"]["items"]] == ["tls-weak-ciphers", "tls-weak-no-rc4"]


async def test_delete_cipher_list_in_use_is_blocked(fmc: respx.MockRouter) -> None:
    delete = delete_mocks(fmc, "rules_preset")
    async with Client(server()) as c:
        out = await run(c, "fmc_delete_object", {"object": "tls-weak-preset", "type": "cipher_suite_list"})
    assert out["blockers"] == [
        "Still in use by: DecryptionPolicyRule tls-cipher-dec / block-weak-ciphers. Point those rules at "
        "another list (fmc_update_decryption_rule cipher_suite_lists=[...]) or delete them first."
    ]
    assert not delete.called


async def test_delete_cipher_list_used_in_a_child_domain(fmc: respx.MockRouter) -> None:
    """A Global list is visible below Global; a child domain's policies are invisible from Global."""
    in_child = {**WEAK, "id": "c1r", "name": "branch-block", "cipherSuiteLists": {"objects": [PRESET]}}
    delete_mocks(fmc, "rules_final", child=[in_child])
    async with Client(server()) as c:
        out = await run(c, "fmc_delete_object", {"object": PRESET["name"], "type": "cipher_suite_list"})
    assert out["blockers"][0].startswith("Still in use by: DecryptionPolicyRule branch-dec / branch-block.")


async def test_cipher_list_lookups(fmc: respx.MockRouter) -> None:
    delete_mocks(fmc, "rules_final")
    for kind in ("hosts", "networks", "ranges", "fqdns", "networkgroups", "protocolportobjects"):
        fmc.get(f"{CFG}/object/{kind}").mock(return_value=items([]))
    for kind in ("portobjectgroups", "urls", "urlgroups", "securityzones", "interfacegroups"):
        fmc.get(f"{CFG}/object/{kind}").mock(return_value=items([]))
    for kind in ("icmpv4objects", "vlantags", "vlangrouptags"):
        fmc.get(f"{CFG}/object/{kind}").mock(return_value=items([]))
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="pass type='cipher_suite_list'"):
            await run(c, "fmc_delete_object", {"object": "tls-weak-preset"})
        with pytest.raises(ToolError, match="documents no PUT for cipher suite lists"):
            await run(
                c,
                "fmc_update_object",
                {"object": "tls-weak-preset", "type": "cipher_suite_list", "description": "x"},
            )

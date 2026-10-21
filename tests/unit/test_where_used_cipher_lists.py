"""fmc_where_used on cipher suite lists: FMC 10.0.1's usage API answers 400 "API not supported for specified
type" for CipherSuiteList, so the decryption rules are read, as fmc_delete_object does (F82, #276). Recorded
answers from the ftd-tls-cipher-policy lab: tests/fixtures/decryption_rule_update_fmc10.json."""

from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .conftest import CFG, CHILD, as_leaf, items
from .test_decryption import run, server
from .test_decryption_rule_update import CHILD_DEC, LISTS, NO_RC4, POL, PRESET, REC, WEAK, Fmc

NOTE = (
    "FMC's usage API doesn't cover cipher suite lists, so the rules of every decryption policy in this "
    "domain and the domains below the list's own were read."
)


def lab(fmc: respx.MockRouter, rules: str, child: list[dict[str, Any]] | None = None) -> respx.Route:
    """The lab's lists and the policy's rules in state `rules`; the usage API refuses the type."""
    Fmc(fmc, REC[rules]["items"])
    if child is not None:
        kid = {
            "id": "c1",
            "name": "branch-dec",
            "type": "DecryptionPolicy",
            "metadata": {"domain": {"name": "Global/Branch", "id": CHILD, "type": "Domain"}},
        }
        fmc.get(CHILD_DEC).mock(return_value=items([kid]))
        fmc.get(f"{CHILD_DEC}/c1/decryptionpolicyrules").mock(return_value=items(child))
    return fmc.get(f"{CFG}/object/operational/usage").mock(
        return_value=httpx.Response(400, json=REC["usage_400"])
    )


async def where_used(**kw: Any) -> Any:
    async with Client(server()) as c:
        return await run(c, "fmc_where_used", {"type": "cipher_suite_list", **kw})


def brief(rows: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    return [(r["policy"], r["index"], r["name"], r["action"], r["cipher_suite_lists"]) for r in rows]


async def test_lists_the_rules_that_use_a_list_on_the_lab(fmc: respx.MockRouter) -> None:
    """The live check: tls-weak-no-rc4 on the lab's leaf login, used by block-weak-ciphers."""
    as_leaf(fmc)
    usage = lab(fmc, "rules_final")
    out = await where_used(object="tls-weak-no-rc4")
    assert not usage.called
    assert out["object"] == {
        "name": "tls-weak-no-rc4",
        "type": "CipherSuiteList",
        "id": NO_RC4["id"],
        "domain": "Global/mcp-test-leaf",
    }
    assert out["in_use"] is True and out["note"] == NOTE
    assert out["used_by"] == [
        {
            "type": "DecryptionPolicyRule",
            "name": "tls-cipher-dec / block-weak-ciphers",
            "id": WEAK["id"],
            "domain": "Global/mcp-test-leaf",
        }
    ]
    assert brief(out["rules"]) == [
        ("tls-cipher-dec", 2, "block-weak-ciphers", "BLOCK_WITH_RESET", ["tls-weak-no-rc4"])
    ]


async def test_follows_the_rule_to_another_list(fmc: respx.MockRouter) -> None:
    """block-weak-ciphers switched to tls-weak-preset (the run's first update): tls-weak-no-rc4 is free."""
    lab(fmc, "rules_preset")
    fmc.get(f"{LISTS}/{NO_RC4['id']}").mock(return_value=httpx.Response(200, json=NO_RC4))
    preset = await where_used(object=PRESET["name"])
    no_rc4 = await where_used(object=NO_RC4["id"])
    assert [u["name"] for u in preset["used_by"]] == ["tls-cipher-dec / block-weak-ciphers"]
    assert no_rc4["object"]["name"] == "tls-weak-no-rc4"
    assert no_rc4["in_use"] is False and no_rc4["used_by"] == [] and no_rc4["rules"] == []
    assert no_rc4["note"] == NOTE


async def test_unused_list(fmc: respx.MockRouter) -> None:
    lab(fmc, "rules_final")
    out = await where_used(object="tls-weak-ciphers", drill_down=False)
    assert out["in_use"] is False and out["used_by"] == [] and "rules" not in out


async def test_rules_in_a_child_domain_and_rule_order(fmc: respx.MockRouter) -> None:
    """A Global list used by a child domain's policy (invisible from Global) and by two rules of the lab's
    policy, which FMC lists in creation order: rows come by policy, then rule index."""
    above = {**WEAK, "id": "r0", "name": "block-weak-first", "metadata": {**WEAK["metadata"], "ruleIndex": 1}}
    in_child = {
        **WEAK,
        "id": "c1r",
        "name": "branch-block",
        "metadata": {**WEAK["metadata"], "ruleIndex": 4},
    }
    lab(fmc, "rules_final", child=[in_child])
    fmc.get(f"{CFG}/policy/decryptionpolicies/{POL['id']}/decryptionpolicyrules").mock(
        return_value=items(REC["rules_final"]["items"] + [above])
    )
    out = await where_used(object="tls-weak-no-rc4")
    assert out["object"]["domain"] == "Global"
    assert [(u["name"], u["domain"]) for u in out["used_by"]] == [
        ("tls-cipher-dec / block-weak-first", "Global"),
        ("tls-cipher-dec / block-weak-ciphers", "Global"),
        ("branch-dec / branch-block", "Global/Branch"),
    ]
    assert [(r["policy"], r["index"], r["name"], r["domain"]) for r in out["rules"]] == [
        ("tls-cipher-dec", 1, "block-weak-first", "Global"),
        ("tls-cipher-dec", 2, "block-weak-ciphers", "Global"),
        ("branch-dec", 4, "branch-block", "Global/Branch"),
    ]


async def test_cipher_list_needs_its_type(fmc: respx.MockRouter) -> None:
    lab(fmc, "rules_final")
    for kind in ("hosts", "networks", "ranges", "fqdns", "networkgroups", "protocolportobjects"):
        fmc.get(f"{CFG}/object/{kind}").mock(return_value=items([]))
    for kind in ("portobjectgroups", "urls", "urlgroups", "securityzones", "interfacegroups"):
        fmc.get(f"{CFG}/object/{kind}").mock(return_value=items([]))
    for kind in ("icmpv4objects", "vlantags", "vlangrouptags"):
        fmc.get(f"{CFG}/object/{kind}").mock(return_value=items([]))
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="pass type='cipher_suite_list'"):
            await run(c, "fmc_where_used", {"object": "tls-weak-no-rc4"})


async def test_list_and_get_cipher_suite_lists_as_objects(fmc: respx.MockRouter) -> None:
    """cipher_suite_list is an object type for fmc_list_objects and fmc_get_object too: the suites are the
    members."""
    lab(fmc, "rules_final")
    async with Client(server()) as c:
        listed = await run(c, "fmc_list_objects", {"type": "cipher_suite_list", "response_format": "json"})
        got = await run(c, "fmc_get_object", {"object": "tls-weak-no-rc4", "type": "cipher_suite_list"})
    assert [r["name"] for r in listed["results"]] == [
        "tls-weak-ciphers",
        "tls-weak-no-rc4",
        "tls-weak-preset",
    ]
    assert got["object_type"] == "cipher_suite_list" and got["id"] == NO_RC4["id"]
    assert got["members"] == [lit["name"] for lit in NO_RC4["literals"]]
    assert "TLS_RSA_WITH_RC4_128_SHA" not in got["members"]

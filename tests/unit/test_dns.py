"""F13 slice 3: DNS block via custom SI DNS lists."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server
from fmc_mcp.tools.dns import list_name

from .conftest import CFG, items, make_settings

POL = {"id": "dp1", "name": "mcp-test-dns", "type": "DNSPolicy"}
RULES = f"{CFG}/policy/dnspolicies/dp1/dnsrules"
LISTS = f"{CFG}/object/customsidnslists"


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def test_list_names() -> None:
    assert list_name("bad.example.com") == "mcp-dns-bad.example.com"
    assert list_name("*.evil.test") != list_name("_.evil.test")


async def test_block_uploads_list_and_creates_rule(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/dnspolicies").mock(return_value=items([POL]))
    fmc.get(RULES).mock(return_value=items([]))
    fmc.get(LISTS).mock(return_value=items([]))
    upload = fmc.post(LISTS).mock(
        return_value=httpx.Response(
            201, json={"id": "l1", "name": "mcp-dns-bad.example.com", "type": "CustomSIDNSListObject"}
        )
    )
    rule = fmc.post(RULES).mock(
        side_effect=lambda req: httpx.Response(201, json={**json.loads(req.content), "id": "r1"})
    )
    args = {"policy": "mcp-test-dns", "domains": ["Bad.Example.com."]}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        p = await run(c, "fmc_dns_block", args)
        assert p["preview"]["domains"] == ["bad.example.com"] and not upload.called
        await run(c, "fmc_dns_block", {**args, "confirm": p["confirm"]})
        with pytest.raises(ToolError, match="not a domain"):
            await run(c, "fmc_dns_block", {"policy": "mcp-test-dns", "domains": ["not a domain"]})
    assert (
        b"payloadFile" in upload.calls.last.request.content
        and b"bad.example.com" in upload.calls.last.request.content
    )
    body = json.loads(rule.calls.last.request.content)
    assert body["action"] == "NXDOMAIN" and body["dnsLists"]["objects"][0]["id"] == "l1"


async def test_foreign_list_with_our_name_is_refused(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/dnspolicies").mock(return_value=items([POL]))
    fmc.get(RULES).mock(return_value=items([]))
    fmc.get(LISTS).mock(
        return_value=items([{"id": "x", "name": "mcp-dns-bad.example.com", "fileName": "theirs.txt"}])
    )
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        out = await run(c, "fmc_dns_block", {"policy": "mcp-test-dns", "domains": ["bad.example.com"]})
    assert out["status"] == "blocked" and "not made by this tool" in out["blockers"][0]


def test_domain_validation() -> None:
    from fmc_mcp.tools.dns import DOMAIN_RE

    for ok in ("bad.example.com", "*.evil.test", "x.xn--p1ai", "_dmarc.example.org"):
        assert DOMAIN_RE.fullmatch(ok), ok
    for bad in ("-bad.example.com", "localhost", "a..b.com", "bad.example.com."):
        assert not DOMAIN_RE.fullmatch(bad), bad


# --- a DNS policy the domain inherits (#204) ---------------------------------------------------------
# Recorded in Global/mcp-test-leaf (security_intelligence.json, threat_posture.json): the leaf's access
# policy mcp-fw-threat-acp uses Global's 'Default DNS Policy', which its SI reference calls
# "DNS Block List Policy". Here the login's domain (CFG) is that leaf and TOP is Global.


def leaf_recordings() -> tuple[dict[str, Any], dict[str, Any]]:
    from .conftest import DOMAIN, TOP, fixture

    lab_global, lab_leaf = "e276abec-e0f2-11e3-8169-6d9ed49b625f", "a1c73df0-8353-8db7-1097-000000000000"

    def moved(name: str) -> dict[str, Any]:
        text = json.dumps(fixture(name)).replace(lab_global, TOP).replace(lab_leaf, DOMAIN)
        return dict(json.loads(text))

    return moved("security_intelligence"), moved("threat_posture")


def inherited_setup(
    fmc: respx.MockRouter,
    extra_rules: tuple[dict[str, Any], ...] = (),
    domains: list[dict[str, str]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The leaf's view of Global's Default DNS Policy and the access policies using it."""
    from .conftest import LEAF_DOMAINS, TOP, TOP_CFG, as_leaf, empty

    as_leaf(fmc, domains or LEAF_DOMAINS)
    si, rec = leaf_recordings()
    acp, dns = rec["access_policy"], si["dns_policy"]
    global_acp = {
        "id": "00000000-0000-0ed3-0000-021474836766",
        "name": "mcp-test-acp",
        "type": "AccessPolicy",
        "metadata": {"domain": {"id": TOP, "name": "Global", "type": "Domain"}},
    }
    fmc.get(f"{CFG}/policy/dnspolicies").mock(return_value=items([dns]))
    fmc.get(f"{CFG}/policy/dnspolicies/{dns['id']}/dnsrules").mock(
        return_value=items([*si["dns_rules"]["items"], *extra_rules])
    )
    fmc.get(LISTS).mock(return_value=items([]))
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([acp, global_acp]))
    for a in (acp, global_acp):
        fmc.get(f"{CFG}/policy/accesspolicies/{a['id']}/securityintelligencepolicies").mock(
            return_value=httpx.Response(200, json=si["si_policy"])
        )
    fmc.get(f"{CFG}/assignment/policyassignments").mock(
        return_value=httpx.Response(200, json=rec["assignments"])
    )
    fmc.get(f"{TOP_CFG}/assignment/policyassignments").mock(return_value=empty())
    return si, rec


async def dns_block(**args: Any) -> Any:
    base = {"policy": "Default DNS Policy", "domains": ["malware-c2.example.com"]}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        return await run(c, "fmc_dns_block", {**base, **args})


async def test_block_in_inherited_policy_offers_the_leaf_way_first(fmc: respx.MockRouter) -> None:
    inherited_setup(fmc)
    out = await dns_block()
    assert out["status"] == "blocked"
    local, reach = out["blockers"][:2]
    assert local.startswith("'Default DNS Policy' is defined in domain 'Global' and only inherited by")
    assert (
        "fmc_create_dns_policy(name='<new DNS policy>', domain='Global/mcp-test-leaf') -> "
        "fmc_set_dns_policy(access_policy='mcp-fw-threat-acp', dns_policy='<new DNS policy>', "
        "domain='Global/mcp-test-leaf') -> fmc_dns_block(policy='<new DNS policy>', "
        "domains=['malware-c2.example.com'], mode='NXDOMAIN', domain='Global/mcp-test-leaf')"
    ) in local
    # Relinking leaves the inherited policy; the recorded one has only FMC's own rules, so none are named.
    assert "stop using 'Default DNS Policy'" in local and "other rules" not in local
    assert "mcp-test-acp belongs to an ancestor domain" in local
    assert reach.startswith("Or: repeat with domain='Global' to change 'Default DNS Policy' itself")
    assert "domains below it (Global/mcp-test-leaf)" in reach
    assert "used by mcp-fw-threat-acp, mcp-test-acp (devices: mcp-ftd-identity)" in reach
    assert not any("it then applies to every domain below" in b for b in out["blockers"])  # said once


async def test_leaf_way_keeps_the_mode_and_names_the_rules_left_behind(fmc: respx.MockRouter) -> None:
    custom = {"name": "corp-sinkhole", "type": "DNSRule", "action": "SINKHOLE", "enabled": True}
    inherited_setup(fmc, extra_rules=(custom,))
    local = (await dns_block(mode="DROP"))["blockers"][0]
    assert "fmc_dns_block(policy='<new DNS policy>', domains=['malware-c2.example.com'], mode='DROP'" in local
    assert "'Default DNS Policy''s other rules (corp-sinkhole) no longer apply to them" in local


async def test_unblock_in_inherited_policy_points_to_the_owner_only(fmc: respx.MockRouter) -> None:
    inherited_setup(fmc)
    out = await dns_block(action="unblock")
    assert out["status"] == "blocked"
    first = out["blockers"][0]
    assert first.startswith("'Default DNS Policy' is defined in domain 'Global'")
    assert "Repeat with domain='Global' to change 'Default DNS Policy' itself" in first
    assert not any(
        "fmc_create_dns_policy" in b for b in out["blockers"]
    )  # a new policy has nothing to unblock


async def test_inherited_blocker_caps_the_domains_it_names(fmc: respx.MockRouter) -> None:
    from .conftest import DOMAIN, TOP

    many = [{"name": "Global", "uuid": TOP}, {"name": "Global/mcp-test-leaf", "uuid": DOMAIN}]
    many += [{"name": f"Global/t{i:02d}", "uuid": f"77777777-0000-4000-8000-{i:012d}"} for i in range(1, 15)]
    inherited_setup(fmc, domains=many)
    reach = (await dns_block())["blockers"][1]
    assert "Global/mcp-test-leaf, Global/t01" in reach and "and 5 more)" in reach and "t14" not in reach


async def test_set_dns_policy_preview_names_the_current_policy_itself(fmc: respx.MockRouter) -> None:
    from .conftest import fixture

    si = fixture("security_intelligence")
    acp = {"id": "00000000-0000-0ed3-0000-021474901848", "name": "mcp-fw-threat-acp", "type": "AccessPolicy"}
    sip = si["si_policy"]["items"][0]
    base = f"{CFG}/policy/accesspolicies/{acp['id']}/securityintelligencepolicies"
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([acp]))
    fmc.get(f"{CFG}/policy/dnspolicies").mock(return_value=items([si["dns_policy"], POL]))
    fmc.get(f"{CFG}/policy/dnspolicies/{si['dns_policy']['id']}").mock(
        return_value=httpx.Response(200, json=si["dns_policy"])
    )
    fmc.get(base).mock(return_value=items([sip]))
    fmc.get(f"{base}/{sip['id']}").mock(return_value=httpx.Response(200, json=sip))
    args = {"access_policy": "mcp-fw-threat-acp", "dns_policy": "mcp-test-dns"}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        out = await run(c, "fmc_set_dns_policy", args)
    assert sip["dnsPolicy"]["name"] == "DNS Block List Policy"
    assert out["preview"]["from"] == "Default DNS Policy" and out["preview"]["to"] == "mcp-test-dns"


async def test_threat_posture_names_the_dns_policy_itself(fmc: respx.MockRouter) -> None:
    from .test_threat_posture import mock_lab, posture

    mock_lab(fmc)
    out = await posture(fmc)
    assert out["security_intelligence"]["dns_policy"] == "Default DNS Policy"  # not the SI reference's name
    dns = next(f for f in out["findings"] if f["check"] == "dns_no_talos")
    assert dns["detail"].startswith("DNS policy 'Default DNS Policy' blocks no Talos DNS category")


# --- fmc_set_si_lists on a DNS policy the domain inherits (#250) --------------------------------------
# It called any inherited DNS policy "FMC's read-only default", although it can be a custom Global one.
# Now it says what #235 says for fmc_dns_block: the leaf way first, then the owner domain.

LEAF = "Global/mcp-test-leaf"


def si_lists_setup(fmc: respx.MockRouter, custom: bool) -> dict[str, Any]:
    """inherited_setup, plus what fmc_set_si_lists reads; with `custom` the inherited policy is a Global
    DNS policy of the owner's (not FMC's Default DNS Policy), used by both access policies."""
    import copy

    from .test_si_feeds import CATALOG, CUSTOM, FEEDS

    si, rec = inherited_setup(fmc)
    dns = copy.deepcopy(si["dns_policy"])
    if custom:
        dns.update(id="00000000-0000-0ed3-0000-0000000d0c01", name="corp-dns")
        sip = copy.deepcopy(si["si_policy"])
        sip["items"][0]["dnsPolicy"] = {"id": dns["id"], "name": "corp-dns", "type": "DNSPolicy"}
        for path in (
            f"{CFG}/policy/accesspolicies/{rec['access_policy']['id']}/securityintelligencepolicies",
            f"{CFG}/policy/accesspolicies/00000000-0000-0ed3-0000-021474836766/securityintelligencepolicies",
        ):
            fmc.get(path).mock(return_value=httpx.Response(200, json=sip))
        fmc.get(f"{CFG}/policy/dnspolicies/{dns['id']}/dnsrules").mock(
            return_value=items(si["dns_rules"]["items"])
        )
    fmc.get(f"{CFG}/policy/dnspolicies/{dns['id']}").mock(return_value=httpx.Response(200, json=dns))
    for kind in ("ip", "url", "dns"):
        fmc.get(f"{CFG}/object/{CATALOG[kind]}").mock(return_value=items(si["catalog"][kind]))
        fmc.get(f"{CFG}/object/{FEEDS[kind]}").mock(return_value=items([]))
        fmc.get(f"{CFG}/object/{CUSTOM[kind]}").mock(return_value=items([]))
    return dns


async def si_lists(**args: Any) -> Any:
    base = {"policy": "mcp-fw-threat-acp", "names": ["DNS Malware"]}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        return await run(c, "fmc_set_si_lists", {**base, **args})


@pytest.mark.parametrize("custom", [False, True], ids=["default-dns-policy", "custom-global-policy"])
async def test_si_lists_in_an_inherited_dns_policy_offer_the_leaf_way(
    fmc: respx.MockRouter, custom: bool
) -> None:
    dns = si_lists_setup(fmc, custom)
    put = fmc.put(path__regex=r".*/dnsrules.*")
    post = fmc.post(path__regex=r".*/dnsrules.*")
    out = await si_lists()
    assert out["status"] == "blocked", out
    local, reach = out["blockers"][:2]
    assert local.startswith(f"{dns['name']!r} is defined in domain 'Global' and only inherited by {LEAF!r}")
    assert (
        f"To add these DNS feeds/lists to 'mcp-fw-threat-acp' in {LEAF!r} only, give it a DNS policy of its "
        f"own: fmc_create_dns_policy(name='<new DNS policy>', domain={LEAF!r}) -> fmc_set_dns_policy("
        f"access_policy='mcp-fw-threat-acp', dns_policy='<new DNS policy>', domain={LEAF!r}) -> "
        "fmc_set_si_lists(policy='mcp-fw-threat-acp', names=['DNS Malware'], list_type='block', "
        f"action='add', dns_answer='NXDOMAIN', domain={LEAF!r}), then fmc_deploy."
    ) in local
    # only the access policy named is relinked: Global's mcp-test-acp is not offered (nor called Global's)
    assert "belongs to an ancestor domain" not in local
    assert reach.startswith(f"Or: repeat with domain='Global' to change {dns['name']!r} itself")
    assert "used by mcp-fw-threat-acp, mcp-test-acp (devices: mcp-ftd-identity)" in reach
    assert not [b for b in out["blockers"] if "default" in b.lower() and "read-only" in b], out["blockers"]
    assert not any("it then applies to every domain below" in b for b in out["blockers"])  # said once
    assert not put.called and not post.called


async def test_si_lists_remove_from_an_inherited_dns_policy_points_to_the_owner(
    fmc: respx.MockRouter,
) -> None:
    si_lists_setup(fmc, custom=True)
    out = await si_lists(action="remove")
    assert out["status"] == "blocked"
    first = out["blockers"][0]
    assert first.startswith("'corp-dns' is defined in domain 'Global'")
    assert "Repeat with domain='Global' to change 'corp-dns' itself" in first
    assert not any(
        "fmc_create_dns_policy" in b for b in out["blockers"]
    )  # a new policy has nothing to remove


async def test_si_lists_for_an_inherited_access_policy_point_to_the_owner(fmc: respx.MockRouter) -> None:
    si_lists_setup(fmc, custom=True)
    out = await si_lists(policy="mcp-test-acp")
    assert out["status"] == "blocked"
    first = out["blockers"][0]
    assert "Repeat with domain='Global' to change 'corp-dns' itself" in first
    assert first.endswith("(mcp-test-acp belongs to an ancestor domain too and can only be relinked there.)")
    assert not any("fmc_create_dns_policy" in b for b in out["blockers"])

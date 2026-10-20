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


async def test_block_in_inherited_policy_offers_the_leaf_way_first(fmc: respx.MockRouter) -> None:
    from .conftest import TOP, TOP_CFG, as_leaf, empty

    as_leaf(fmc)
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
        return_value=httpx.Response(200, json=si["dns_rules"])
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
    args = {"policy": "Default DNS Policy", "domains": ["malware-c2.example.com"]}
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        out = await run(c, "fmc_dns_block", args)
    assert out["status"] == "blocked"
    local, reach = out["blockers"][:2]
    assert local.startswith("'Default DNS Policy' is defined in domain 'Global' and only inherited by")
    assert (
        "fmc_create_dns_policy(name='<new DNS policy>', domain='Global/mcp-test-leaf') -> "
        "fmc_set_dns_policy(access_policy='mcp-fw-threat-acp', dns_policy='<new DNS policy>', "
        "domain='Global/mcp-test-leaf') -> fmc_dns_block(policy='<new DNS policy>', "
        "domains=['malware-c2.example.com'], domain='Global/mcp-test-leaf')"
    ) in local
    assert "mcp-test-acp belongs to an ancestor domain" in local
    assert reach.startswith("Or repeat with domain='Global'")
    assert "domains below it (Global/mcp-test-leaf)" in reach
    assert "used by mcp-fw-threat-acp, mcp-test-acp (devices: mcp-ftd-identity)" in reach
    assert not any("it then applies to every domain below" in b for b in out["blockers"])  # said once


async def test_threat_posture_names_the_dns_policy_itself(fmc: respx.MockRouter) -> None:
    from .test_threat_posture import mock_lab, posture

    mock_lab(fmc)
    out = await posture(fmc)
    assert out["security_intelligence"]["dns_policy"] == "Default DNS Policy"  # not the SI reference's name
    dns = next(f for f in out["findings"] if f["check"] == "dns_no_talos")
    assert dns["detail"].startswith("DNS policy 'Default DNS Policy' blocks no Talos DNS category")

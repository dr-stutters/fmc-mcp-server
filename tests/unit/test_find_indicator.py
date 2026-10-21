"""fmc_find_indicator (F79): one domain, URL or hash across objects, rules, SI and DNS policy."""

import copy
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from fmc_mcp._core import InvalidRequest
from fmc_mcp._core.testing import call_tool
from fmc_mcp.server import create_server
from fmc_mcp.tools.find_indicator import (
    HASH_NOTE,
    host_relation,
    parse_indicator,
    relation,
    split_url,
)

from .conftest import CFG, as_leaf, empty, fixture, items, make_settings

FX = fixture("find_indicator")
ACP = FX["acp"]
DNS_POL = FX["dnspolicy"]
DEFAULT_DNS = FX["default_dnspolicy"]
DEC = FX["decryptionpolicy"]
LISTS = {
    o["id"]: o
    for o in (FX["siurllist_domain_block"], FX["siurllist_global_block"], FX["sidnslist_global_block"])
}


async def call(args: dict[str, Any]) -> Any:
    return await call_tool(
        create_server(make_settings()), "fmc_find_indicator", {"response_format": "json", **args}
    )


def own_list(request: httpx.Request) -> httpx.Response:
    """FMC's own SI lists by id: the recorded ones, the rest empty (entryCount 0, no validEntries)."""
    oid = request.url.path.rsplit("/", 1)[-1]
    kind = "SIDNSList" if "/sidnslists/" in request.url.path else "SIURLList"
    body = LISTS.get(oid) or {"metadata": {"entryCount": 0}, "type": kind, "id": oid, "name": "empty"}
    return httpx.Response(200, json=body)


@pytest.fixture
def world(fmc: respx.MockRouter) -> respx.MockRouter:
    """mcp-w6-acp with its SI, the DNS policies, a decryption policy, the objects and SI feeds/lists."""
    for name in ("object/fqdns", "object/urls", "object/urlgroups"):
        fmc.get(f"{CFG}/{name}", name=name).mock(return_value=httpx.Response(200, json=FX[name]))
    groups = fixture("networkgroups")
    groups["items"].append(FX["networkgroup_fqdn"])
    fmc.get(f"{CFG}/object/networkgroups").mock(return_value=httpx.Response(200, json=groups))
    for name in ("object/siurlfeeds", "object/sidnsfeeds", "object/customsidnslists"):
        fmc.get(f"{CFG}/{name}", name=name).mock(return_value=httpx.Response(200, json=FX[name]))
    fmc.get(f"{CFG}/object/customsiurllists").mock(return_value=empty())
    fmc.get(path__regex=rf"{CFG}/object/(siurllists|sidnslists)/[^/]+$", name="own_lists").mock(
        side_effect=own_list
    )
    fmc.get(f"{CFG}/policy/accesspolicies", name="acps").mock(return_value=items([ACP]))
    linked = {**ACP, "decryptionPolicySetting": {"id": DEC["id"], "name": DEC["name"], "type": DEC["type"]}}
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}").mock(return_value=httpx.Response(200, json=linked))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/securityintelligencepolicies").mock(
        return_value=httpx.Response(200, json=FX["securityintelligencepolicies"])
    )
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules", name="rules").mock(
        return_value=httpx.Response(200, json=FX["accessrules"])
    )
    fmc.get(f"{CFG}/policy/dnspolicies", name="dnspolicies").mock(return_value=items([DEFAULT_DNS, DNS_POL]))
    fmc.get(f"{CFG}/policy/dnspolicies/{DNS_POL['id']}", name="dnspolicy").mock(
        return_value=httpx.Response(200, json=DNS_POL)
    )
    default_rules = {"items": FX["dnsrules"]["items"][:4]}
    fmc.get(f"{CFG}/policy/dnspolicies/{DEFAULT_DNS['id']}/dnsrules").mock(
        return_value=httpx.Response(200, json=default_rules)
    )
    fmc.get(f"{CFG}/policy/dnspolicies/{DNS_POL['id']}/dnsrules").mock(
        return_value=httpx.Response(200, json=FX["dnsrules"])
    )
    fmc.get(f"{CFG}/policy/decryptionpolicies", name="decpolicies").mock(return_value=items([DEC]))
    fmc.get(f"{CFG}/policy/decryptionpolicies/{DEC['id']}/decryptionpolicyrules").mock(
        return_value=httpx.Response(200, json=FX["decryptionpolicyrules"])
    )
    return fmc


def rows_by(data: dict[str, Any], area: str) -> dict[str, dict[str, Any]]:
    return {f"{r['where']}|{r.get('side')}": r for r in data["results"] if r["area"] == area}


def config_calls(router: respx.MockRouter) -> list[str]:
    """The tool's own FMC reads (the device list is the server's login-time device-domain map)."""
    paths = [c.request.url.path for c in router.calls]
    return [p for p in paths if "/fmc_config/" in p and not p.endswith("/devices/devicerecords")]


async def test_domain_sweep_ranks_every_area(world: respx.MockRouter) -> None:
    data = await call({"value": "Bad.Example.com."})
    assert (data["indicator"], data["kind"]) == ("bad.example.com", "domain")
    first = data["results"][0]
    assert (first["rank"], first["match"]) == (1, "exact")
    objs = {r["where"]: r for r in data["results"] if r["area"] == "objects"}
    assert objs["Url mcp-si-bad.example.com"]["match"] == "exact"
    assert objs["FQDN mcp-w6-fqdn-apex"]["match"] == "exact"
    assert objs["FQDN mcp-w6-fqdn-dl"]["match"] == "inside"
    assert objs["Url mcp-w6-url-payload"]["match"] == "inside"
    assert objs["UrlGroup mcp-w6-urlgrp"]["via"] == "mcp-w6-url-payload"
    assert objs["NetworkGroup mcp-w6-fqdn-grp"]["via"] == "mcp-w6-fqdn-dl"
    assert "FQDN mcp-w6-fqdn" not in objs  # cisco.com
    assert objs["Url mcp-test-url"]["match"] == "contains"  # https://example.com: a parent domain
    assert "Url mcp-w6-url-other" not in objs

    si = rows_by(data, "security_intelligence")
    assert si["mcp-w6-acp: Security Intelligence URL list|block"]["match"] == "exact"
    vias = {r["via"] for r in data["results"] if r["area"] == "security_intelligence"}
    assert vias == {"mcp-si-bad.example.com", "URL feed mcp-w6-feed-url"}

    dns = rows_by(data, "dns_rules")
    where = "DNS policy mcp-w6-dns #5 mcp-dns-block (NXDOMAIN) [access policies: mcp-w6-acp]"
    assert dns[f"{where}|dns list"]["via"] == "DNS custom list mcp-dns-bad.example.com"
    assert dns[f"{where}|dns list"]["value"] == "bad.example.com"

    lists = {r["where"]: r for r in data["results"] if r["area"] == "si_lists"}
    assert lists["SI URL feed mcp-w6-feed-url"]["via"] == "fetched entry"
    assert lists["SI DNS custom list mcp-dns-bad.example.com"]["via"] == "list name (fmc_dns_block list)"

    rules = rows_by(data, "access_rules")
    block = rules["mcp-w6-acp #2 mcp-w6-url-block (BLOCK)|url"]
    assert (block["match"], block["via"], block["value"]) == (
        "exact",
        "literal (+1 more)",
        "https://bad.example.com/",
    )
    dl = rules["mcp-w6-acp #3 mcp-w6-dl-allow (ALLOW) [disabled]|destination"]
    assert (dl["match"], dl["via"]) == ("inside", "mcp-w6-fqdn-grp > mcp-w6-fqdn-dl")
    assert not any("mcp-w6-fqdn-allow" in w or "ip-only" in w for w in rules)
    dec = rows_by(data, "decryption_rules")
    assert dec["mcp-fw-dec #1 mcp-w6-dnd-bad (DO_NOT_DECRYPT)|url"]["match"] == "exact"

    # ranked like fmc_find_address: exact, then the values inside the domain, then those containing it
    matches = [r["match"] for r in data["results"]]
    assert matches == sorted(matches, key=lambda m: {"exact": 0, "inside": 1, "contains": 2}[m])
    assert data["by_area"] == {
        "objects": 7,
        "si_lists": 2,
        "security_intelligence": 2,
        "dns_rules": 1,
        "access_rules": 2,
        "decryption_rules": 1,
    }
    searched = data["searched"]
    assert (searched["access_policies"], searched["si_policies"], searched["dns_policies"]) == (1, 1, 2)
    assert (searched["si_feeds"], searched["si_custom_lists"], searched["si_lists_read"]) == (2, 2, 8)
    assert searched["requests"] == len(config_calls(world)) == 24
    nc = " ".join(data["not_checked"])
    assert "DNS custom list soc-iocs (12 entries; FMC returns the count, not the entries)" in nc
    assert "DNS feed mcp-w6-feed-dns (FMC lists no fetched entries" in nc
    assert "URL Talos category URL Malware" in nc
    assert "URL categories and reputation in 1 rule(s)" in nc
    assert "TID" in data["limits"] and "warning" not in data


async def test_subdomain_finds_parent_values_but_not_parent_fqdns(world: respx.MockRouter) -> None:
    data = await call({"value": "www.bad.example.com", "areas": ["objects", "si_lists", "access_rules"]})
    objs = {r["where"]: r for r in data["results"] if r["area"] == "objects"}
    assert objs["Url mcp-si-bad.example.com"]["match"] == "contains"
    assert "FQDN mcp-w6-fqdn-apex" not in objs  # an FQDN object resolves its own name only
    assert "FQDN mcp-w6-fqdn-dl" not in objs
    lists = {r["where"]: r["match"] for r in data["results"] if r["area"] == "si_lists"}
    assert lists == {
        "SI URL feed mcp-w6-feed-url": "contains",
        "SI DNS custom list mcp-dns-bad.example.com": "contains",
    }
    assert set(data["searched"]) == {
        "objects",
        "si_feeds",
        "si_custom_lists",
        "access_policies",
        "access_rules",
        "requests",
    }
    assert not world.routes["dnspolicies"].called and not world.routes["decpolicies"].called


async def test_url_with_path(world: respx.MockRouter) -> None:
    data = await call({"value": "HTTP://bad.example.com/payload.exe/", "areas": ["objects"]})
    assert (data["indicator"], data["kind"]) == ("bad.example.com/payload.exe", "url")
    objs = {r["where"]: r["match"] for r in data["results"]}
    assert objs["Url mcp-w6-url-payload"] == "exact"
    assert objs["UrlGroup mcp-w6-urlgrp"] == "exact"
    assert objs["Url mcp-si-bad.example.com"] == "contains"
    assert objs["FQDN mcp-w6-fqdn-apex"] == "contains"  # same host: the FQDN rule covers the URL
    assert "FQDN mcp-w6-fqdn-dl" not in objs  # another host
    assert data["searched"] == {"objects": 12, "requests": 4}
    assert len(config_calls(world)) == 4


async def test_hash_answers_without_reading_fmc(world: respx.MockRouter) -> None:
    sha = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    data = await call({"value": sha})
    assert (data["indicator"], data["kind"]) == (sha.lower(), "SHA-256 file hash")
    assert data["results"] == [] and data["not_checked"] == [HASH_NOTE]
    assert HASH_NOTE.startswith("FMC's file lists and TID observables aren't searched")
    assert config_calls(world) == []
    md5 = await call({"value": "d41d8cd98f00b204e9800998ecf8427e"})
    assert md5["kind"] == "MD5 file hash"


@pytest.mark.parametrize(
    ("value", "text"),
    [
        ("192.0.2.10", "fmc_find_address"),
        ("198.51.100.0/24", "fmc_find_address"),
        ("any", "fmc_find_address"),
        ("not a domain", "not a domain, URL or file hash"),
        ("http://192.0.2.5", "fmc_find_address"),
        ("abc123", "not a domain, URL or file hash"),
    ],
)
async def test_bad_values_are_refused(fmc: respx.MockRouter, value: str, text: str) -> None:
    with pytest.raises(ToolError, match=text):
        await call({"value": value})


async def test_budget_names_what_was_not_read(world: respx.MockRouter) -> None:
    data = await call({"value": "bad.example.com", "max_requests": 15})
    assert data["searched"]["requests"] <= 15
    assert len(config_calls(world)) <= 15
    warning = data["warning"]
    assert warning.startswith("Stopped at max_requests=15; not read:")
    assert (
        "not read: rules of DNS policy Default DNS Policy, rules of DNS policy mcp-w6-dns, rules of "
        in warning
    )
    assert "mcp-w6-acp, decryption policies." in warning and "raise max_requests" in warning
    # objects, SI feeds/lists and the access policy's SI came first
    assert data["by_area"] == {"objects": 7, "si_lists": 2, "security_intelligence": 2}


async def test_access_policy_narrows_to_its_dns_and_decryption_policies(world: respx.MockRouter) -> None:
    data = await call({"value": "bad.example.com", "access_policy": ACP["id"]})
    assert not world.routes["acps"].called  # resolved by id
    assert not world.routes["dnspolicies"].called and not world.routes["decpolicies"].called
    assert world.routes["dnspolicy"].called  # the DNS policy's own name, not the SI reference's alias
    dns = [r["where"] for r in data["results"] if r["area"] == "dns_rules"]
    assert dns == ["DNS policy mcp-w6-dns #5 mcp-dns-block (NXDOMAIN) [access policies: mcp-w6-acp]"]
    assert data["searched"]["dns_policies"] == 1 and data["searched"]["decryption_policies"] == 1
    assert data["by_area"]["decryption_rules"] == 1


async def test_device_narrows_to_its_access_policy(world: respx.MockRouter) -> None:
    """device=: the FTD's access policy (by id), its SI, its DNS policy and its decryption policy only;
    searched.requests counts every read, the device lookup included."""
    dev = {
        **fixture("ftd_device"),
        "accessPolicy": {"id": ACP["id"], "name": ACP["name"], "type": ACP["type"]},
    }
    devices = world.get(f"{CFG}/devices/devicerecords").mock(return_value=items([dev]))
    other = "00000000-0000-0ed3-0000-021479000999"
    world.routes["acps"].mock(
        return_value=items([ACP, {"id": other, "name": "mcp-w6-other", "type": "AccessPolicy"}])
    )
    data = await call({"value": "bad.example.com", "device": dev["name"]})
    assert devices.called and not world.routes["acps"].called  # the device names its policy's id
    assert not world.routes["dnspolicies"].called and not world.routes["decpolicies"].called
    assert world.routes["dnspolicy"].called
    paths = [c.request.url.path for c in world.calls]
    assert not any(other in p for p in paths)
    assert {r["where"].split(" #")[0] for r in data["results"] if r["area"] == "access_rules"} == {
        "mcp-w6-acp"
    }
    dns = [r["where"] for r in data["results"] if r["area"] == "dns_rules"]
    assert dns == ["DNS policy mcp-w6-dns #5 mcp-dns-block (NXDOMAIN) [access policies: mcp-w6-acp]"]
    assert data["by_area"]["decryption_rules"] == 1
    searched = data["searched"]
    assert (searched["access_policies"], searched["dns_policies"], searched["decryption_policies"]) == (
        1,
        1,
        1,
    )
    # the device list is the tool's own read here (by name), on top of the reads config_calls counts
    assert searched["requests"] == len(config_calls(world)) + 1


async def test_markdown_reply(world: respx.MockRouter) -> None:
    out = await call_tool(
        create_server(make_settings()),
        "fmc_find_indicator",
        {"value": "evil.test", "areas": ["objects", "security_intelligence"]},
    )
    text = out if isinstance(out, str) else str(out)
    assert "UrlGroup mcp-w6-urlgrp" in text and "Domain-Block-List-for-URL-mcp-test-leaf" in text


async def test_own_block_list_entries_and_unreadable_ones(world: respx.MockRouter) -> None:
    lists = copy.deepcopy(LISTS)
    lists[FX["siurllist_global_block"]["id"]]["metadata"]["entryCount"] = 3  # entries, but none listed

    def answer(request: httpx.Request) -> httpx.Response:
        oid = request.url.path.rsplit("/", 1)[-1]
        if oid in lists:
            return httpx.Response(200, json=lists[oid])
        return own_list(request)

    world.routes["own_lists"].mock(side_effect=answer)
    data = await call({"value": "evil.test", "areas": ["security_intelligence"]})
    si = [r for r in data["results"]]
    assert {(r["via"], r["match"]) for r in si} == {
        ("URL list Domain-Block-List-for-URL-mcp-test-leaf", "exact")
    }
    assert (
        "URL list Global Block List for URL (3 entries; FMC returns the count, not the entries)"
        in " ".join(data["not_checked"])
    )


async def test_leaf_skips_descendant_lists_and_names_invisible_ones(world: respx.MockRouter) -> None:
    """In a domain without child domains the Descendant lists hold nothing it can see (FMC 10.0.1 answers
    404 for them from the lab's leaf): they are not read. Another list FMC answers 404 for is named."""
    as_leaf(world)
    gone = FX["sidnslist_global_block"]["id"]

    def answer(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(gone):
            return httpx.Response(404, json={"error": {"messages": [{"description": "not found"}]}})
        return own_list(request)

    world.routes["own_lists"].mock(side_effect=answer)
    data = await call({"value": "bad.example.com", "areas": ["dns_rules"]})
    read = [c.request.url.path for c in world.routes["own_lists"].calls]
    assert not any("17a11eb0" in p or "1fca9c10" in p for p in read)  # the two Descendant lists
    assert len(read) == 2 and data["searched"]["si_lists_read"] == 2
    assert "DNS list Global-Block-List-for-DNS (not visible from this domain)" in " ".join(
        data["not_checked"]
    )
    assert data["by_area"] == {"dns_rules": 1}


def test_relations() -> None:
    assert host_relation("bad.example.com", "bad.example.com") == "exact"
    assert host_relation("example.com", "bad.example.com") == "contains"
    assert host_relation("dl.bad.example.com", "bad.example.com") == "inside"
    assert host_relation("*.example.com", "bad.example.com") == "contains"
    assert host_relation("*.bad.example.com", "bad.example.com") == "inside"
    assert host_relation("notexample.com", "example.com") is None
    assert host_relation("192.0.2.1", "2.1") is None
    want = parse_indicator("http://bad.example.com/a/b.exe")
    assert relation(("bad.example.com", "/a"), want) == "contains"
    assert relation(("bad.example.com", "/a/b.exe"), want) == "exact"
    assert relation(("bad.example.com", "/ab"), want) is None
    assert relation(("example.com", "/a/b.exe"), want) is None  # a path on another host
    assert relation(("dl.bad.example.com", ""), want) is None
    dom = parse_indicator("bad.example.com")
    assert relation(("bad.example.com", "/x"), dom) == "inside"
    assert relation(("dl.bad.example.com", "/x"), dom) == "inside"
    assert split_url("https://User:pw@Bad.Example.com:8443/a/?q=1") == ("bad.example.com", "/a?q=1")
    assert split_url("") is None and split_url("http://") is None
    assert parse_indicator("*.evil.test").text == "evil.test"
    with pytest.raises(InvalidRequest):
        parse_indicator("10.0.0.0-10.0.0.9")

"""F61: Security Intelligence feeds and custom lists, their status, and using them in a policy.

Policy, SI and catalog shapes are recorded from FMC 10.0.1 (tests/fixtures/security_intelligence.json);
feed and custom-list objects follow the 10.0.1 spec examples (the lab had none when this was written)."""

import copy
import json
import time
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp._core import InvalidRequest
from fmc_mcp.server import create_server
from fmc_mcp.tools.security_intel import (
    MONITOR_GAP,
    SI_MARKER,
    check_feed_url,
    clean_entries,
    feed_status,
    source_row,
)

from .conftest import CFG, fixture, items, make_settings

REC = fixture("security_intelligence")
ACP = {"id": "00000000-0000-0ed3-0000-021474901848", "name": "mcp-fw-threat-acp", "type": "AccessPolicy"}
SI_BASE = f"{CFG}/policy/accesspolicies/{ACP['id']}/securityintelligencepolicies"
SI_ID = REC["si_policy"]["items"][0]["id"]
DEFAULT_DNS = REC["dns_policy"]
FEED_ID = "fc79ce12-069a-11ed-87bb-780a89d43a90"
LIST_ID = "7ebc2fc6-97e3-11ed-8e55-39813451a4e3"
DNS_FEED_ID = "12db08a0-cf6c-11ef-a8f3-9fe11ed203f6"
OWN_DNS = {"id": "0050568a-0000-0000-0000-00000000d0d0", "name": "mcp-fw-dns", "type": "DNSPolicy"}
CATALOG = {"ip": "sinetworklists", "url": "siurllists", "dns": "sidnslists"}
FEEDS = {"ip": "sinetworkfeeds", "url": "siurlfeeds", "dns": "sidnsfeeds"}
CUSTOM = {"ip": "customsiiplists", "url": "customsiurllists", "dns": "customsidnslists"}


def ip_feed(updated: float | None = None, entries: int = 3) -> dict[str, Any]:
    meta: dict[str, Any] = {"readOnly": {"state": False}, "entryCount": entries, "timestamp": 1792320617}
    if updated is not None:
        meta["feedUpdateTime"] = int(updated)
    return {
        "metadata": meta,
        "type": "SINetworkFeed",
        "id": FEED_ID,
        "name": "mcp-fw-feed-ip",
        "feedURL": "http://feed.example.test/ip.txt",
        "updateFrequency": 60,
    }


def url_list(file_name: str = f"mcp-fw-list-url{SI_MARKER}") -> dict[str, Any]:
    return {
        "fileName": file_name,
        "name": "mcp-fw-list-url",
        "id": LIST_ID,
        "type": "CustomSIURLListObject",
        "metadata": {
            "readOnly": {"state": False},
            "entryCount": 2,
            "invalidEntryCount": 0,
            "timestamp": 1792320617,
        },
    }


def dns_feed() -> dict[str, Any]:
    return {
        "metadata": {"readOnly": {"state": False}, "entryCount": 0, "timestamp": 1792320617},
        "type": "SIDNSFeed",
        "id": DNS_FEED_ID,
        "name": "mcp-fw-feed-dns",
        "feedURL": "http://feed.example.test/dns.txt",
        "updateFrequency": 120,
    }


def si_policy(**extra: Any) -> dict[str, Any]:
    si = copy.deepcopy(REC["si_policy"]["items"][0])
    for section, key, which, ref in extra.get("add", []):
        si[section][which].append({key: ref})
    if "dns" in extra:
        si["dnsPolicy"] = extra["dns"]
    return si


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def mock_catalogs(
    fmc: respx.MockRouter, feeds: dict[str, list[dict[str, Any]]], lists: dict[str, list[dict[str, Any]]]
) -> None:
    for kind in ("ip", "url", "dns"):
        fmc.get(f"{CFG}/object/{CATALOG[kind]}").mock(return_value=items(REC["catalog"][kind]))
        fmc.get(f"{CFG}/object/{FEEDS[kind]}").mock(return_value=items(feeds.get(kind, [])))
        fmc.get(f"{CFG}/object/{CUSTOM[kind]}").mock(return_value=items(lists.get(kind, [])))


def mock_policy(fmc: respx.MockRouter, si: dict[str, Any]) -> respx.Route:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    fmc.get(SI_BASE).mock(return_value=items([si]))
    fmc.get(f"{SI_BASE}/{SI_ID}").mock(return_value=httpx.Response(200, json=si))
    return fmc.put(f"{SI_BASE}/{SI_ID}").mock(
        side_effect=lambda req: httpx.Response(200, json=json.loads(req.content))
    )


def server() -> Any:
    return create_server(make_settings(mcp_enable_writes=True))


# --- pure helpers -----------------------------------------------------------------------------


def test_feed_status() -> None:
    now = time.time()
    assert feed_status(ip_feed(now - 600), now) == "ok"
    assert feed_status(ip_feed(None), now).startswith("not downloaded yet")
    assert feed_status(ip_feed(now - 5 * 3600), now).startswith("stale: last update 5 h ago")
    assert feed_status(ip_feed(now - 600, entries=0), now).startswith("downloaded but empty")
    off = {**ip_feed(now - 30 * 86400), "updateFrequency": 0}
    assert feed_status(off, now) == "ok (automatic refresh off)"
    row = source_row("ip", "feed", ip_feed(1792320000), now)
    assert row["last_update"].endswith("Z") and row["url"] == "http://feed.example.test/ip.txt"
    assert source_row("url", "custom", url_list())["uploaded_by_this_server"] is True


def test_clean_entries() -> None:
    assert clean_entries("ip", ["203.0.113.7", "198.51.100.0/24 # scanner", "203.0.113.7/32", ""]) == [
        "203.0.113.7",
        "198.51.100.0/24",
    ]
    assert clean_entries("ip", ["192.0.2.1\n192.0.2.2\n# comment"]) == ["192.0.2.1", "192.0.2.2"]
    assert clean_entries("url", ["bad.example.com", "http://bad.example.org/x"]) == [
        "bad.example.com",
        "http://bad.example.org/x",
    ]
    assert clean_entries("dns", ["Bad.Example.com.", "*.evil.test"]) == ["bad.example.com", "*.evil.test"]
    for kind, bad in (
        ("ip", "198.51.100.7/24"),
        ("ip", "0.0.0.0/0"),
        ("ip", "bad.example.com"),
        ("url", "203.0.113.7"),
        ("dns", "not a domain"),
    ):
        with pytest.raises(InvalidRequest):
            clean_entries(kind, [bad])
    with pytest.raises(InvalidRequest, match="No entries"):
        clean_entries("ip", ["# only a comment"])


def test_feed_url_checks() -> None:
    assert check_feed_url(" https://feed.example.test/ip.txt ") == "https://feed.example.test/ip.txt"
    for bad in ("ftp://feed.example.test/x", "feed.example.test/x", "http://user:pw@feed.example.test/x"):
        with pytest.raises(InvalidRequest):
            check_feed_url(bad)


# --- fmc_get_security_intelligence ------------------------------------------------------------


async def test_policy_view_shows_feed_status_and_dns_rules(fmc: respx.MockRouter) -> None:
    now = time.time()
    feed_ref = {"id": FEED_ID, "type": "SINetworkFeed", "name": "mcp-fw-feed-ip"}
    list_ref = {"id": LIST_ID, "type": "SIURLList", "name": "mcp-fw-list-url"}
    si = si_policy(
        add=[("networks", "network", "blocklist", feed_ref), ("urls", "url", "allowlist", list_ref)]
    )
    mock_policy(fmc, si)
    mock_catalogs(fmc, {"ip": [ip_feed(now - 900)], "dns": [dns_feed()]}, {"url": [url_list()]})
    fmc.get(f"{CFG}/policy/dnspolicies/{DEFAULT_DNS['id']}/dnsrules").mock(
        return_value=httpx.Response(200, json=REC["dns_rules"])
    )
    async with Client(server()) as c:
        out = await run(
            c, "fmc_get_security_intelligence", {"policy": ACP["name"], "response_format": "json"}
        )
    assert out["network_block"][-1] == "mcp-fw-feed-ip" and out["dns_policy"] == "DNS Block List Policy"
    assert [r["name"] for r in out["dns_rules"]][2] == "Global Block List for DNS"
    rows = {r["name"]: r for r in out["feeds_and_lists"]}
    assert rows["mcp-fw-feed-ip"]["status"] == "ok" and rows["mcp-fw-feed-ip"]["used_as"] == [
        "network block list"
    ]
    assert (
        rows["mcp-fw-list-url"]["used_as"] == ["URL allow list"] and rows["mcp-fw-list-url"]["entries"] == 2
    )
    assert "1 not used here" in out["other_feeds_and_lists"]  # the DNS feed


async def test_domain_view_lists_feeds_and_lists(fmc: respx.MockRouter) -> None:
    mock_catalogs(fmc, {"ip": [ip_feed(None)], "dns": [dns_feed()]}, {"url": [url_list()]})
    async with Client(server()) as c:
        out = await run(c, "fmc_get_security_intelligence", {"response_format": "json"})
    feeds = {r["name"]: r for r in out["feeds"]}
    assert feeds["mcp-fw-feed-ip"]["status"].startswith("not downloaded yet")
    assert out["lists"][0]["name"] == "mcp-fw-list-url" and out["lists"][0]["kind"] == "url"


# --- fmc_create_si_feed -----------------------------------------------------------------------


async def test_create_feed(fmc: respx.MockRouter) -> None:
    mock_catalogs(fmc, {}, {})
    post = fmc.post(f"{CFG}/object/sinetworkfeeds").mock(
        side_effect=lambda req: httpx.Response(
            201, json={**json.loads(req.content), "id": FEED_ID, "metadata": {"entryCount": 0}}
        )
    )
    args = {"kind": "ip", "name": "mcp-fw-feed-ip", "url": "http://feed.example.test/ip.txt", "refresh": 30}
    async with Client(server()) as c:
        p = await run(c, "fmc_create_si_feed", args)
        assert p["preview"]["body"] == {
            "name": "mcp-fw-feed-ip",
            "type": "SINetworkFeed",
            "feedURL": "http://feed.example.test/ip.txt",
            "updateFrequency": 30,
        }
        assert not post.called
        done = await run(c, "fmc_create_si_feed", {**args, "confirm": p["confirm"]})
        with pytest.raises(ToolError, match="credentials"):
            await run(c, "fmc_create_si_feed", {**args, "url": "http://u:p@feed.example.test/ip.txt"})
    assert json.loads(post.calls.last.request.content)["type"] == "SINetworkFeed"
    assert done["result"]["feed"]["status"].startswith("not downloaded yet")


async def test_create_feed_name_taken(fmc: respx.MockRouter) -> None:
    mock_catalogs(fmc, {}, {})
    async with Client(server()) as c:
        out = await run(
            c, "fmc_create_si_feed", {"kind": "ip", "name": "Malware", "url": "http://x.example.test/a"}
        )
    assert out["status"] == "blocked" and "already exists" in out["blockers"][0]


# --- fmc_upload_si_list -----------------------------------------------------------------------


async def test_upload_list_is_multipart(fmc: respx.MockRouter) -> None:
    mock_catalogs(fmc, {}, {})
    up = fmc.post(f"{CFG}/object/customsiiplists").mock(
        return_value=httpx.Response(
            201,
            json={
                "id": LIST_ID,
                "name": "mcp-fw-list-ip",
                "type": "CustomSIIPListObject",
                "metadata": {"entryCount": 2, "invalidEntryCount": 0},
            },
        )
    )
    args = {
        "kind": "ip",
        "name": "mcp-fw-list-ip",
        "entries": ["203.0.113.7", "198.51.100.0/24", "203.0.113.7"],
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_upload_si_list", args)
        assert p["preview"]["entries"] == 2 and p["preview"]["file"] == f"mcp-fw-list-ip{SI_MARKER}"
        done = await run(c, "fmc_upload_si_list", {**args, "confirm": p["confirm"]})
    req = up.calls.last.request
    assert req.headers["content-type"].startswith("multipart/form-data")
    assert b'name="payloadFile"' in req.content and b"203.0.113.7\n198.51.100.0/24\n" in req.content
    assert done["result"]["entries"] == 2


async def test_upload_replaces_own_list_and_refuses_foreign(fmc: respx.MockRouter) -> None:
    mock_catalogs(fmc, {}, {"url": [url_list()]})
    put = fmc.put(f"{CFG}/object/customsiurllists/{LIST_ID}").mock(
        return_value=httpx.Response(200, json={**url_list(), "metadata": {"entryCount": 1}})
    )
    args = {"kind": "url", "name": "mcp-fw-list-url", "entries": ["bad.example.com"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_upload_si_list", args)
        assert p["preview"]["replaces"]["entries"] == 2
        await run(c, "fmc_upload_si_list", {**args, "confirm": p["confirm"]})
    assert put.called and b"bad.example.com" in put.calls.last.request.content

    mock_catalogs(fmc, {}, {"url": [url_list("theirs.txt")]})
    async with Client(server()) as c:
        out = await run(c, "fmc_upload_si_list", args)
    assert out["status"] == "blocked" and "not uploaded by fmc_upload_si_list" in out["blockers"][0]


# --- fmc_set_si_lists -------------------------------------------------------------------------


async def test_add_talos_category_and_feed_to_block_list(fmc: respx.MockRouter) -> None:
    put = mock_policy(fmc, si_policy())
    mock_catalogs(fmc, {"ip": [ip_feed(time.time())]}, {})
    args = {"policy": ACP["name"], "names": ["Malware", "mcp-fw-feed-ip"], "kind": "ip"}
    async with Client(server()) as c:
        p = await run(c, "fmc_set_si_lists", args)
        assert [e["name"] for e in p["preview"]["entries"]] == ["Malware", "mcp-fw-feed-ip"]
        await run(c, "fmc_set_si_lists", {**args, "confirm": p["confirm"]})
        again = await run(c, "fmc_set_si_lists", {**args, "names": ["Global Block List"]})
    block = json.loads(put.calls.last.request.content)["networks"]["blocklist"]
    assert [e["network"]["name"] for e in block][-2:] == ["Malware", "mcp-fw-feed-ip"]
    assert block[-1]["network"]["type"] == "SINetworkFeed" and block[-2]["network"]["type"] == "SINetworkList"
    assert len(block) == 4  # the Domain and Global block lists stay
    assert again["status"] == "blocked" and "already in the list" in again["blockers"][0]


async def test_remove_from_allow_list(fmc: respx.MockRouter) -> None:
    list_ref = {"id": LIST_ID, "type": "SIURLList", "name": "mcp-fw-list-url"}
    put = mock_policy(fmc, si_policy(add=[("urls", "url", "allowlist", list_ref)]))
    mock_catalogs(fmc, {}, {"url": [url_list()]})
    args = {"policy": ACP["name"], "names": ["mcp-fw-list-url"], "list_type": "allow", "action": "remove"}
    async with Client(server()) as c:
        p = await run(c, "fmc_set_si_lists", args)
        await run(c, "fmc_set_si_lists", {**args, "confirm": p["confirm"]})
    allow = json.loads(put.calls.last.request.content)["urls"]["allowlist"]
    assert LIST_ID not in {e["url"]["id"] for e in allow} and len(allow) == 2


async def test_monitor_only_is_dns_only(fmc: respx.MockRouter) -> None:
    mock_policy(fmc, si_policy())
    mock_catalogs(fmc, {}, {})
    async with Client(server()) as c:
        out = await run(
            c, "fmc_set_si_lists", {"policy": ACP["name"], "names": ["CnC"], "list_type": "monitor"}
        )
        with pytest.raises(ToolError, match="make one call for each"):
            await run(c, "fmc_set_si_lists", {"policy": ACP["name"], "names": ["CnC", "DNS CnC"]})
    assert out["status"] == "blocked" and out["blockers"] == [MONITOR_GAP]


async def test_dns_lists_need_an_own_dns_policy(fmc: respx.MockRouter) -> None:
    mock_policy(fmc, si_policy())
    mock_catalogs(fmc, {"dns": [dns_feed()]}, {})
    fmc.get(f"{CFG}/policy/dnspolicies/{DEFAULT_DNS['id']}").mock(
        return_value=httpx.Response(200, json=DEFAULT_DNS)
    )
    fmc.get(f"{CFG}/policy/dnspolicies/{DEFAULT_DNS['id']}/dnsrules").mock(
        return_value=httpx.Response(200, json=REC["dns_rules"])
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_set_si_lists", {"policy": ACP["name"], "names": ["DNS Malware"]})
    assert out["status"] == "blocked" and "read-only default DNS policy" in out["blockers"][0]


async def test_dns_monitor_rule_with_feed_and_category(fmc: respx.MockRouter) -> None:
    mock_policy(fmc, si_policy(dns=OWN_DNS))
    mock_catalogs(fmc, {"dns": [dns_feed()]}, {})
    fmc.get(f"{CFG}/policy/dnspolicies/{OWN_DNS['id']}").mock(return_value=httpx.Response(200, json=OWN_DNS))
    fmc.get(f"{CFG}/policy/dnspolicies/{OWN_DNS['id']}/dnsrules").mock(
        return_value=items(REC["dns_rules"]["items"])
    )
    post = fmc.post(f"{CFG}/policy/dnspolicies/{OWN_DNS['id']}/dnsrules").mock(
        side_effect=lambda req: httpx.Response(201, json={**json.loads(req.content), "id": "r1"})
    )
    args = {"policy": ACP["name"], "names": ["mcp-fw-feed-dns", "DNS Phishing"], "list_type": "monitor"}
    async with Client(server()) as c:
        p = await run(c, "fmc_set_si_lists", args)
        assert p["preview"]["answer"] == "MONITOR" and p["preview"]["rule"].startswith(
            "mcp-si-dns-monitor (new"
        )
        done = await run(c, "fmc_set_si_lists", {**args, "confirm": p["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["action"] == "MONITOR" and body["name"] == "mcp-si-dns-monitor"
    assert body["dnsFeeds"]["objects"][0]["id"] == DNS_FEED_ID
    assert body["dnsLists"]["objects"][0]["name"] == "DNS Phishing"
    assert done["result"]["rule"]["dns_feeds"] == ["mcp-fw-feed-dns"]


async def test_dns_remove_last_entry_deletes_rule(fmc: respx.MockRouter) -> None:
    rule = {
        "id": "r1",
        "name": "mcp-si-dns-block",
        "type": "DNSRule",
        "action": "NXDOMAIN",
        "enabled": True,
        "dnsFeeds": {"objects": [{"id": DNS_FEED_ID, "type": "SIDNSFeed", "name": "mcp-fw-feed-dns"}]},
    }
    mock_policy(fmc, si_policy(dns=OWN_DNS))
    mock_catalogs(fmc, {"dns": [dns_feed()]}, {})
    fmc.get(f"{CFG}/policy/dnspolicies/{OWN_DNS['id']}").mock(return_value=httpx.Response(200, json=OWN_DNS))
    rules = f"{CFG}/policy/dnspolicies/{OWN_DNS['id']}/dnsrules"
    fmc.get(rules).mock(return_value=items([rule]))
    fmc.get(f"{rules}/r1").mock(return_value=httpx.Response(200, json=rule))
    delete = fmc.delete(f"{rules}/r1").mock(return_value=httpx.Response(200, json={}))
    args = {"policy": ACP["name"], "names": ["mcp-fw-feed-dns"], "action": "remove"}
    async with Client(server()) as c:
        p = await run(c, "fmc_set_si_lists", args)
        await run(c, "fmc_set_si_lists", {**args, "confirm": p["confirm"]})
    assert delete.called


# --- fmc_delete_si_object ---------------------------------------------------------------------


async def test_delete_blocked_while_used_then_deletes(fmc: respx.MockRouter) -> None:
    feed_ref = {"id": FEED_ID, "type": "SINetworkFeed", "name": "mcp-fw-feed-ip"}
    mock_policy(fmc, si_policy(add=[("networks", "network", "blocklist", feed_ref)]))
    mock_catalogs(fmc, {"ip": [ip_feed(time.time())]}, {})
    gone = fmc.delete(f"{CFG}/object/sinetworkfeeds/{FEED_ID}").mock(
        return_value=httpx.Response(200, json={})
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_delete_si_object", {"name": "mcp-fw-feed-ip"})
        assert (
            out["status"] == "blocked"
            and "access policy 'mcp-fw-threat-acp' (SI block list)" in out["blockers"][0]
        )
        with pytest.raises(ToolError, match="No custom feed or list"):
            await run(c, "fmc_delete_si_object", {"name": "Malware"})
        mock_policy(fmc, si_policy())
        p = await run(c, "fmc_delete_si_object", {"name": "mcp-fw-feed-ip"})
        await run(c, "fmc_delete_si_object", {"name": "mcp-fw-feed-ip", "confirm": p["confirm"]})
    assert gone.called

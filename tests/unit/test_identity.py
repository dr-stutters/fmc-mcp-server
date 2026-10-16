"""F13 identity slice: realms, trusted CAs, identity policies, user/group access rules, rule lookup."""

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp._core import InvalidRequest
from fmc_mcp.server import create_server
from fmc_mcp.tools.analysis import _user_match
from fmc_mcp.tools.identity import fmc_fingerprint, parse_directory, pem_body
from fmc_mcp.ui import ui_credentials

from .conftest import CFG, items, make_settings

REALM_ID = "e86435e4-c8fa-11f1-acd3-69ea5174bd84"
REALM = {
    "id": REALM_ID,
    "name": "corp",
    "type": "Realm",
    "realmType": "AD",
    "enabled": True,
    "adPrimaryDomain": "example.com",
    "baseDn": "DC=example,DC=com",
    "groupDn": "OU=Groups,DC=example,DC=com",
    "dirUsername": "svc@example.com",
    "dirPassword": "*********",
    "directoryConfigurations": [
        {"id": 0, "hostname": "10.0.0.11", "port": 389, "encryptionProtocol": "NONE"},
        {"id": 1, "hostname": "10.0.0.12", "port": 389, "encryptionProtocol": "NONE"},
    ],
    "updateHour": 0,
    "updateInterval": 24,
    "metadata": {"isDownloading": False, "domain": {"id": "e276abec-e0f2-11e3-8169-6d9ed49b625f"}},
}
GROUP = {
    "id": "1",
    "type": "RealmUserGroup",
    "name": "contractors",
    "realm": {"id": REALM_ID, "type": "Realm", "name": "corp"},
    "metadata": {"lastSynced": 1792112394},
}
USER = {
    "id": "7",
    "type": "RealmUser",
    "name": "bob",
    "realm": {"id": REALM_ID, "type": "Realm", "name": "corp"},
}
IDP = {"id": "871a2430-c8fd-11f1-acd3-69ea5174bd84", "name": "idp", "type": "IdentityPolicy"}
ACP = {"id": "00000000-0000-0ed3-0000-021474847655", "name": "acp", "type": "AccessPolicy"}
CA_PEM = (Path(__file__).resolve().parent.parent / "fixtures" / "test-ca-cert.txt").read_text()


def server(**kw: Any) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, **kw))


def ui_server() -> Any:
    return server(ui_username="uiuser", ui_password="uipw")


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def mock_realm(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/realms").mock(return_value=items([REALM]))
    fmc.get(f"{CFG}/object/realms/{REALM_ID}").mock(return_value=httpx.Response(200, json=REALM))
    fmc.get(f"{CFG}/object/realmusergroups").mock(return_value=items([GROUP]))
    fmc.get(f"{CFG}/object/realmusers").mock(return_value=items([USER]))


def pjb_calls(route: respx.Route) -> list[tuple[str, Any]]:
    out = []
    for call in route.calls:
        form = parse_qs(call.request.content.decode())
        out.append((form["function"][0], json.loads(form["parameters"][0])))
    return out


# --- helpers ---------------------------------------------------------------------------------------------


def test_parse_directory() -> None:
    assert parse_directory("10.0.0.1") == ("10.0.0.1", 389, "NONE")
    assert parse_directory("ldaps://dc01.example.com") == ("dc01.example.com", 636, "LDAPS")
    assert parse_directory("starttls://dc01:3268") == ("dc01", 3268, "STARTTLS")
    with pytest.raises(InvalidRequest):
        parse_directory("dc01:99999")


def test_pem_fingerprint_matches_fmc_format() -> None:
    text, der = pem_body("junk before\n" + CA_PEM)
    assert text.startswith("-----BEGIN CERTIFICATE-----\n") and len(der) > 100
    fp = fmc_fingerprint(der)
    assert len(fp.split(":")) == 20 and fp == fp.upper()
    with pytest.raises(InvalidRequest):
        pem_body(CA_PEM + CA_PEM)


def test_ui_credentials_rules() -> None:
    with pytest.raises(InvalidRequest, match="FMC_UI_USERNAME"):
        ui_credentials(make_settings())
    with pytest.raises(InvalidRequest, match="must differ"):
        ui_credentials(make_settings(ui_username="APIUSER", ui_password="x"))
    assert ui_credentials(make_settings(ui_username="ui", ui_password="x")) == ("ui", "x")


def test_user_match() -> None:
    block = {"objects": [GROUP]}
    assert _user_match(None, None) is True
    assert _user_match(block, None) is None
    assert _user_match(block, ["bob", "Contractors"]) is True
    assert _user_match(block, ["corp\\contractors"]) is True
    assert _user_match(block, ["alice", "employees"]) is False
    assert _user_match(block, []) is False
    assert _user_match(block, ["other\\contractors"]) is False


async def test_download_without_ui_user_is_blocked_in_preview(fmc: respx.MockRouter) -> None:
    mock_realm(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_download_realm", {"realm": "corp"})
    assert out["status"] == "blocked" and "FMC_UI_USERNAME" in out["blockers"][0]


def test_ldaps_dns_name_is_not_an_ip() -> None:
    from fmc_mcp.tools.identity import _is_ip

    assert _is_ip("10.0.0.1") and _is_ip("fe80::1") and not _is_ip("cafe") and not _is_ip("dc01.example.com")


# --- realms ----------------------------------------------------------------------------------------------


async def test_get_realm_shows_downloaded_members(fmc: respx.MockRouter) -> None:
    mock_realm(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_get_realm", {"realm": "corp", "members": "both", "response_format": "json"})
    assert out["downloaded"] == {"groups": 1, "users": 1}
    assert out["groups"] == ["contractors"] and out["users"] == ["bob"]
    assert out["last_download"].startswith("2026-")
    assert "dirPassword" not in json.dumps(out) and "*****" not in json.dumps(out)


async def test_create_realm_hides_password_and_sends_it(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/realms").mock(return_value=items([]))
    post = fmc.post(f"{CFG}/object/realms").mock(return_value=httpx.Response(201, json=REALM))
    args = {
        "name": "corp",
        "directory_servers": ["10.0.0.11", "10.0.0.12:3268"],
        "base_dn": "DC=example,DC=com",
        "group_dn": "OU=Groups,DC=example,DC=com",
        "bind_user": "svc@example.com",
        "bind_password": "S3cret-bind!",
        "ad_domain": "example.com",
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_create_realm", args)
        assert "S3cret-bind!" not in json.dumps(p)
        assert p["preview"]["bind_password"] == "set (hidden)"
        done = await run(c, "fmc_create_realm", {**args, "confirm": p["confirm"]})
        assert "S3cret-bind!" not in json.dumps(done)
        # a different password than previewed invalidates the confirm
        p2 = await run(c, "fmc_create_realm", args)
        r = await c.call_tool(
            "fmc_create_realm",
            {**args, "bind_password": "other", "confirm": p2["confirm"]},
            raise_on_error=False,
        )
        assert r.is_error or "applied" not in json.dumps(r.structured_content)
        assert post.call_count == 1
    body = json.loads(post.calls.last.request.content)
    assert body["dirPassword"] == "S3cret-bind!" and body["realmType"] == "AD"
    assert [d["port"] for d in body["directoryConfigurations"]] == [389, 3268]


async def test_ldaps_realm_needs_ca_and_a_name(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/realms").mock(return_value=items([]))
    async with Client(server()) as c:
        out = await run(
            c,
            "fmc_create_realm",
            {
                "name": "corp",
                "directory_servers": ["ldaps://10.0.0.11"],
                "base_dn": "DC=example,DC=com",
                "bind_user": "svc",
                "bind_password": "x",
                "ad_domain": "example.com",
            },
        )
    assert out["status"] == "blocked"
    assert any("ca_certificate" in b for b in out["blockers"])
    assert any("IP address" in b for b in out["blockers"])


async def test_trusted_ca_duplicate_is_blocked(fmc: respx.MockRouter) -> None:
    _, der = pem_body(CA_PEM)
    fmc.get(f"{CFG}/object/externalcacertificates").mock(
        return_value=items([{"id": "c1", "name": "corp-root", "certFingerprint": fmc_fingerprint(der)}])
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_create_trusted_ca", {"name": "new-root", "pem": CA_PEM})
    assert out["status"] == "blocked" and "corp-root" in out["blockers"][0]


async def test_test_realm_uses_ui_session_per_server(fmc: respx.MockRouter) -> None:
    mock_realm(fmc)
    login = fmc.post("/auth/login").mock(
        return_value=httpx.Response(200, json={"session": {"csrfToken": "tok"}})
    )
    fmc.get("/auth/logout").mock(return_value=httpx.Response(200))
    replies = iter([{"data": {"status": "0"}}, {"data": {"status": "1"}}])
    pjb = fmc.post("/pjb.cgi").mock(side_effect=lambda req: httpx.Response(200, json=next(replies)))
    async with Client(ui_server()) as c:
        out = await run(c, "fmc_test_realm", {"realm": "corp"})
    assert [s["result"] for s in out["servers"]] == ["ok", "failed"]
    assert "1 of 2" in out["verdict"] and out["check"]
    calls = pjb_calls(pjb)
    assert [c[0] for c in calls] == ["SF::IdentityRealm::RealmTest::testDirectoryConnection"] * 2
    assert [c[1][1] for c in calls] == [0, 1]
    assert b"uipw" in login.calls.last.request.content


async def test_test_realm_without_ui_user_explains(fmc: respx.MockRouter) -> None:
    mock_realm(fmc)
    async with Client(server()) as c:
        r = await c.call_tool("fmc_test_realm", {"realm": "corp"}, raise_on_error=False)
    assert r.is_error and "FMC_UI_USERNAME" in r.content[0].text


async def test_download_waits_for_fmc_task(fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    mock_realm(fmc)
    fmc.post("/auth/login").mock(return_value=httpx.Response(200, json={"session": {"csrfToken": "t"}}))
    fmc.get("/auth/logout").mock(return_value=httpx.Response(200))
    old = {"uuid": "old", "seq": 1, "category": "LDAP Download", "status": "success", "body": "corp old"}
    new = {
        "uuid": "new",
        "seq": 2,
        "category": "LDAP Download",
        "status": "success",
        "body": "<strong>Download users/groups from corp</strong><br> LDAP download successful: 1 groups",
    }
    state = {"refreshed": False}

    def reply(req: httpx.Request) -> httpx.Response:
        fn = parse_qs(req.content.decode())["function"][0]
        if fn.endswith("refreshRealm"):
            state["refreshed"] = True
            return httpx.Response(200, json={"data": {}})
        msgs = [old, new] if state["refreshed"] else [old]
        return httpx.Response(200, json={"data": {"messages": {"task": msgs}}})

    fmc.post("/pjb.cgi").mock(side_effect=reply)
    async with Client(ui_server()) as c:
        p = await run(c, "fmc_download_realm", {"realm": "corp"})
        out = await run(c, "fmc_download_realm", {"realm": "corp", "confirm": p["confirm"]})
    res = out["result"]
    assert res["status"] == "success" and "successful" in res["fmc_message"] and "<" not in res["fmc_message"]
    assert res["downloaded"]["groups"] == {"before": 1, "after": 1}


# --- identity policies -----------------------------------------------------------------------------------


async def test_identity_rule_goes_into_standard_category(fmc: respx.MockRouter) -> None:
    mock_realm(fmc)
    fmc.get(f"{CFG}/policy/identitypolicies").mock(return_value=items([IDP]))
    base = f"{CFG}/policy/identitypolicies/{IDP['id']}"
    fmc.get(f"{base}/identityrules").mock(return_value=items([]))
    fmc.get(f"{base}/identitycategories").mock(
        return_value=items(
            [{"id": "cat-a", "name": "admin_category"}, {"id": "cat-s", "name": "standard_category"}]
        )
    )
    post = fmc.post(f"{base}/identityrules").mock(return_value=httpx.Response(201, json={"id": "r1"}))
    args = {"policy": "idp", "name": "passive", "realm": "corp", "source_networks": ["10.99.1.0/24"]}
    async with Client(server()) as c:
        p = await run(c, "fmc_create_identity_rule", args)
        assert p["preview"]["rule"]["auth"] == "PASSIVE"
        await run(c, "fmc_create_identity_rule", {**args, "confirm": p["confirm"]})
    req = post.calls.last.request
    assert req.url.params["intoCategory"] == "cat-s"
    body = json.loads(req.content)
    assert body["type"] == "IdentityPolicyRule" and body["realm"]["type"] == "IdentityRealm"


async def test_identity_policy_shows_access_policies_using_it(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/policy/identitypolicies").mock(return_value=items([IDP]))
    fmc.get(f"{CFG}/policy/identitypolicies/{IDP['id']}/identityrules").mock(return_value=items([]))
    fmc.get(f"{CFG}/policy/accesspolicies").mock(
        return_value=items([{**ACP, "identityPolicySetting": {"id": IDP["id"], "name": "idp"}}])
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_get_identity_policy", {"policy": "idp", "response_format": "json"})
    assert out["used_by"] == ["acp"]


# --- access rules on users and groups --------------------------------------------------------------------


def mock_acp(fmc: respx.MockRouter, linked: bool, realm_rule: bool) -> respx.Route:
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    full = {**ACP, **({"identityPolicySetting": {"id": IDP["id"], "name": "idp"}} if linked else {})}
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}").mock(return_value=httpx.Response(200, json=full))
    rules = [{"id": "ir", "name": "p", "realm": {"id": REALM_ID, "name": "corp"}}] if realm_rule else []
    fmc.get(f"{CFG}/policy/identitypolicies/{IDP['id']}/identityrules").mock(return_value=items(rules))
    path = f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules"
    fmc.get(path).mock(return_value=items([]))
    return fmc.post(path).mock(
        return_value=httpx.Response(201, json={"id": "r", "type": "AccessRule", "name": "no-telnet"})
    )


ARGS = {
    "policy": "acp",
    "name": "no-telnet",
    "action": "BLOCK",
    "users": ["contractors"],
    "destination_ports": ["tcp/23"],
}


@pytest.mark.parametrize(
    ("linked", "realm_rule", "needle"),
    [(False, False, "no identity policy"), (True, False, "no rule for realm")],
)
async def test_user_rule_blocked_without_identity_setup(
    fmc: respx.MockRouter, linked: bool, realm_rule: bool, needle: str
) -> None:
    mock_realm(fmc)
    mock_acp(fmc, linked, realm_rule)
    async with Client(server()) as c:
        out = await run(c, "fmc_create_access_rule", ARGS)
    assert out["status"] == "blocked" and needle in out["blockers"][0]


async def test_user_rule_sends_group_with_realm(fmc: respx.MockRouter) -> None:
    mock_realm(fmc)
    post = mock_acp(fmc, True, True)
    async with Client(server()) as c:
        p = await run(c, "fmc_create_access_rule", ARGS)
        assert p["preview"]["rule"]["users"] == ["contractors"]
        await run(c, "fmc_create_access_rule", {**ARGS, "confirm": p["confirm"]})
    ref = json.loads(post.calls.last.request.content)["users"]["objects"][0]
    assert ref == {
        "id": "1",
        "type": "RealmUserGroup",
        "name": "contractors",
        "realm": {"id": REALM_ID, "type": "Realm", "name": "corp"},
    }


async def test_unknown_group_is_not_found(fmc: respx.MockRouter) -> None:
    mock_realm(fmc)
    mock_acp(fmc, True, True)
    async with Client(server()) as c:
        r = await c.call_tool("fmc_create_access_rule", {**ARGS, "users": ["nobody"]}, raise_on_error=False)
    assert r.is_error and "fmc_download_realm" in r.content[0].text

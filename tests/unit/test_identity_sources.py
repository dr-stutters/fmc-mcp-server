"""F34 identity sources: fmc_get_identity_sources, fmc_user_ip_lookup, and fmc_rule_lookup resolving the
user on the source IP. Fixtures: tests/fixtures/identity_sources.json (FMC 10.0.1, recorded + spec shapes)."""

import copy
import ipaddress
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

from fmc_mcp._core import AuthError
from fmc_mcp.client import FmcApp
from fmc_mcp.server import create_server
from fmc_mcp.tools.identity_sources import (
    ROLE_HINT,
    cert_row,
    identity_memory,
    ise_state,
    latest_alerts,
    split_identity,
    user_ips,
    users_on_ip,
)

from .conftest import CFG, empty, fixture, items, make_settings

FX = fixture("identity_sources")
IDENT = FX["devices"][0]["id"]
ACP = {"id": "00000000-0000-0ed3-0000-021474847655", "name": "acp", "type": "AccessPolicy"}
IDP = FX["identitypolicies"]["items"][0]


def server() -> Any:
    return create_server(make_settings())


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def ok(body: Any) -> httpx.Response:
    return httpx.Response(200, json=body)


def by_filter(responses: dict[str, Any], default: Any = None) -> Any:
    """A respx side effect answering by the `filter` query parameter."""

    def answer(request: httpx.Request) -> httpx.Response:
        body = responses.get(request.url.params.get("filter", ""), default)
        return ok(body) if body is not None else empty()

    return answer


def mock_sessions(fmc: respx.MockRouter, rows: list[dict[str, Any]] | None) -> respx.Route:
    """rows=None: 403 like the lab's API role."""
    route = fmc.get(f"{CFG}/analysis/activesessions")
    if rows is None:
        return route.mock(return_value=httpx.Response(403, json=FX["activesessions_403"]))

    def answer(request: httpx.Request) -> httpx.Response:
        ip, user = request.url.params.get("currentIP"), request.url.params.get("username")
        hits = [
            r
            for r in rows
            if (not ip or r["currentIP"] == ip) and (not user or user.lower() in r["username"].lower())
        ]
        return ok({"items": hits, "paging": {"count": len(hits)}})

    return route.mock(side_effect=answer)


def mock_realm_lookups(fmc: respx.MockRouter) -> None:
    users = FX["realmusers"]["items"]

    def realm_users(request: httpx.Request) -> httpx.Response:
        f = request.url.params.get("filter", "")
        if f.startswith("realm:"):
            return ok({"items": users[:1], "paging": {"count": len(users)}})
        name = f.removeprefix("name:").lower()
        hits = [u for u in users if u["name"].lower().startswith(name)]
        return ok({"items": hits, "paging": {"count": len(hits)}})

    fmc.get(f"{CFG}/object/realmusers").mock(side_effect=realm_users)
    groups = {
        "userId:1": FX["groups_user1"],
        "userId:2": FX["groups_user2"],
        f"realm:{FX['realms']['items'][2]['id']}": {
            "items": FX["groups_user1"]["items"],
            "paging": {"count": 4},
        },
    }
    fmc.get(f"{CFG}/object/realmusergroups").mock(side_effect=by_filter(groups))


def mock_status(
    fmc: respx.MockRouter,
    *,
    ise: dict[str, Any] | None = None,
    sgts: bool = False,
    sessions: list[dict[str, Any]] | None = None,
    bindings: str = "0 / 64000",
    linked: bool = True,
    certs: list[dict[str, Any]] | None = None,
) -> None:
    alerts = copy.deepcopy(FX["health_alerts"])
    for a in alerts["items"]:
        if a["moduleID"] == "ISE" and ise:
            a.update(ise)
        if a["moduleID"] == "SNORT_IDENTITY_MEMORY_USAGE" and a["deviceUUID"] == IDENT and "params" in a:
            a["params"] = a["params"].replace("0 / 64000", bindings)
    fmc.get(f"{CFG}/health/alerts").mock(return_value=ok(alerts))
    if sgts:
        fmc.get(f"{CFG}/object/isesecuritygrouptags").mock(return_value=ok(FX["isesgts"]))
    else:
        fmc.get(f"{CFG}/object/isesecuritygrouptags").mock(
            return_value=httpx.Response(422, json=FX["isesgt_disabled"])
        )
    fmc.get(f"{CFG}/object/realms").mock(return_value=ok(FX["realms"]))
    mock_realm_lookups(fmc)
    fmc.get(f"{CFG}/policy/identitypolicies").mock(return_value=ok(FX["identitypolicies"]))
    fmc.get(f"{CFG}/policy/identitypolicies/{IDP['id']}/identityrules").mock(
        return_value=ok(FX["identityrules"])
    )
    link = {"identityPolicySetting": {"id": IDP["id"], "name": IDP["name"]}} if linked else {}
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([{**ACP, **link}]))
    mock_sessions(fmc, sessions)
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items(FX["devices"]))
    fmc.get(f"{CFG}/object/internalcertificates").mock(
        return_value=items(certs if certs is not None else FX["internalcertificates"]["items"])
    )


# --- helpers -------------------------------------------------------------------------------------------


def test_identity_memory_reads_bindings_from_recorded_params() -> None:
    alert = next(a for a in FX["health_alerts"]["items"] if a["deviceUUID"] == IDENT and "params" in a)
    out = identity_memory(alert)
    assert out["user_ip_bindings"] == "0 / 64000" and out["bindings_in_use"] == 0
    assert out["memory"] == "3.7% (740.7K / 20.0M)"


def test_ise_state_from_health_module() -> None:
    ise = next(a for a in FX["health_alerts"]["items"] if a["moduleID"] == "ISE")
    assert ise_state(ise) == "not_configured"
    assert ise_state({**ise, "details": "Connected to primary host"}) == "connected"
    assert ise_state({**ise, "status": "RED", "details": "Lost connection to pxGrid"}) == "failed"
    assert ise_state({**ise, "status": "YELLOW", "details": "Secondary host unreachable"}) == "degraded"
    assert ise_state(None) == "unknown"


def test_latest_alert_per_device_and_module_wins() -> None:
    old = {"deviceUUID": "0", "moduleID": "ISE", "timestamp": 1, "status": "RED"}
    new = {"deviceUUID": "0", "moduleID": "ISE", "timestamp": 2, "status": "GREEN"}
    assert latest_alerts([new, old])[("0", "ISE")]["status"] == "GREEN"


def test_cert_row_expiry_status() -> None:
    now = 1792334000.0  # 2026-10-18
    c = {"name": "fmc-pxgrid", "subjectCommonName": "fmc.example.com", "issuerCommonName": "corp-root-CA"}
    assert cert_row({**c, "validityEndDate": "Oct 15 03:50:00 2028 GMT"}, now)["status"] == "ok"
    assert cert_row({**c, "validityEndDate": "Nov  1 00:00:00 2026 GMT"}, now)["status"] == "expiring"
    row = cert_row({**c, "validityEndDate": "Jan  2 00:00:00 2026 GMT"}, now)
    assert row["status"] == "expired" and row["expires"] == "2026-01-02" and row["days_left"] < 0


def test_split_identity() -> None:
    assert split_identity("corp\\alice") == ("corp", "alice")
    assert split_identity("alice") == (None, "alice")


# --- fmc_get_identity_sources ---------------------------------------------------------------------------


async def test_identity_sources_without_ise(fmc: respx.MockRouter) -> None:
    """The lab today: no ISE source, realm downloaded, identity policy linked, sessions 403."""
    mock_status(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_get_identity_sources", {})
    assert out["verdict"].startswith("No ISE identity source; sessions not readable")
    ise = out["ise"]
    assert ise["state"] == "not_configured" and ise["sgts_downloaded"] == 0
    assert "Integrations > Other Integrations > Identity Sources" in ise["configure"]
    assert out["passive_identity_agent"]["details"] == "Passive identity agent not enabled"
    assert out["realms"] == [
        {"name": "corp", "type": "AD", "enabled": True, "ad_domain": "example.com", "users": 2, "groups": 4}
    ]
    assert out["identity_policies"][0] == {
        "name": "lab-idp",
        "rules": 1,
        "passive_rules": ["passive-inside"],
        "realms": ["corp"],
        "used_by": ["acp"],
    }
    assert out["sessions"]["error"] == ROLE_HINT
    devs = {d["device"]: d for d in out["devices"]}
    assert devs["ftd-identity"]["user_ip_bindings"] == "0 / 64000"
    assert devs["ftd-identity"]["identity_process"] == "Identity Process are disabled"
    assert devs["ftd-down"]["state"] == "Appliance unreachable"
    assert any("configure it in the FMC UI" in n for n in out["next"])
    assert not any("PASSIVE rule" in n for n in out["next"])  # the policy is linked


async def test_identity_sources_connected_with_sessions_and_bindings(fmc: respx.MockRouter) -> None:
    mock_status(
        fmc,
        ise={"details": "Connected to ISE primary host"},
        sgts=True,
        sessions=FX["activesessions"]["items"],
        bindings="1 / 64000",
        certs=[
            {
                "name": "fmc-pxgrid",
                "subjectCommonName": "fmc.example.com",
                "issuerCommonName": "corp-root-CA",
                "validityEndDate": "Jan  2 00:00:00 2026 GMT",
            }
        ],
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_get_identity_sources", {"device": "ftd-identity"})
    assert out["verdict"] == (
        "ISE/pxGrid is connected; 1 user sessions on FMC; 1 of 1 reporting devices hold user-IP bindings"
    )
    assert out["ise"]["state"] == "connected" and out["ise"]["sgts"] == ["Contractors (5)", "Employees (4)"]
    assert out["sessions"] == {"active": 1, "by_source": {"Passive Authentication / LDAP": 1}}
    assert [d["device"] for d in out["devices"]] == ["ftd-identity"]
    assert out["internal_certificates"][0]["status"] == "expired"
    assert out["next"] == ["Internal certificate 'fmc-pxgrid' is expired (2026-01-02)."]


async def test_identity_sources_failed_ise_and_unlinked_policy(fmc: respx.MockRouter) -> None:
    mock_status(
        fmc, ise={"status": "RED", "details": "Unable to connect to pxGrid on primary host"}, linked=False
    )
    async with Client(server()) as c:
        out = await run(c, "fmc_get_identity_sources", {})
    assert out["ise"]["state"] == "failed" and out["verdict"].startswith("ISE/pxGrid connection FAILED")
    assert out["identity_policies"][0]["used_by"] == []
    assert any("unhealthy" in n for n in out["next"])
    assert any("PASSIVE rule" in n for n in out["next"])


# --- fmc_user_ip_lookup ---------------------------------------------------------------------------------


async def test_ip_lookup_returns_user_groups_and_identities(fmc: respx.MockRouter) -> None:
    mock_sessions(fmc, FX["activesessions"]["items"])
    mock_realm_lookups(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_user_ip_lookup", {"ip": "192.0.2.57"})
    assert out["sessions"][0]["user"] == "alice" and out["sessions"][0]["realm"] == "corp"
    assert out["users"] == [{"user": "alice", "realm": "corp", "groups": ["employees"]}]
    assert out["identities"] == ["corp\\alice", "corp\\employees"]


async def test_ip_lookup_without_session_says_unknown_user(fmc: respx.MockRouter) -> None:
    mock_sessions(fmc, FX["activesessions"]["items"])
    mock_realm_lookups(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_user_ip_lookup", {"ip": "192.0.2.99"})
    assert out["sessions"] == [] and "unknown user" in out["note"] and "identities" not in out


async def test_user_lookup_with_history(fmc: respx.MockRouter) -> None:
    mock_sessions(fmc, FX["activesessions"]["items"])
    mock_realm_lookups(fmc)
    hist = fmc.get(f"{CFG}/analysis/useractivity").mock(return_value=ok(FX["useractivity"]))
    async with Client(server()) as c:
        out = await run(c, "fmc_user_ip_lookup", {"user": "corp\\alice", "history": True})
    assert [s["ip"] for s in out["sessions"]] == ["192.0.2.57"]
    assert out["history"][0]["sgt"] == "Employees" and out["history"][0]["event"] == "User Login"
    assert hist.calls.last.request.url.params["username"] == "alice"


async def test_user_lookup_keeps_groups_when_sessions_are_refused(fmc: respx.MockRouter) -> None:
    mock_sessions(fmc, None)
    mock_realm_lookups(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_user_ip_lookup", {"user": "bob"})
    assert out["sessions_error"] == ROLE_HINT
    assert out["users"] == [{"user": "bob", "realm": "corp", "groups": ["contractors"]}]


async def test_ip_lookup_refused_explains_the_role(fmc: respx.MockRouter) -> None:
    mock_sessions(fmc, None)
    async with Client(server()) as c:
        r = await c.call_tool("fmc_user_ip_lookup", {"ip": "192.0.2.57"}, raise_on_error=False)
    assert r.is_error and "Analysis > Users" in r.content[0].text  # type: ignore[union-attr]


async def test_lookup_needs_ip_or_user(fmc: respx.MockRouter) -> None:
    async with Client(server()) as c:
        r = await c.call_tool("fmc_user_ip_lookup", {}, raise_on_error=False)
    assert r.is_error and "ip or a user" in r.content[0].text  # type: ignore[union-attr]


# --- hooks for fmc_find_address / fmc_prove_policy ------------------------------------------------------


async def test_hooks_map_ip_to_users_and_user_to_ips(fmc: respx.MockRouter) -> None:
    mock_sessions(fmc, FX["activesessions"]["items"])
    app = FmcApp(make_settings())
    try:
        rows = await users_on_ip(app, ipaddress.ip_address("192.0.2.57"), None)
        assert rows == [
            {
                "where": "user corp\\alice",
                "via": "identity session (Passive Authentication)",
                "value": "192.0.2.57",
            }
        ]
        assert await user_ips(app, "alice", None) == ["192.0.2.57"]
        assert await user_ips(app, "other\\alice", None) == []
    finally:
        await app.aclose()


async def test_hooks_report_the_missing_role_on_403(fmc: respx.MockRouter) -> None:
    """fmc_find_address turns a hook's UpstreamError into a warning; the text must say what to fix."""
    mock_sessions(fmc, None)
    app = FmcApp(make_settings())
    try:
        with pytest.raises(AuthError) as ip_err:
            await users_on_ip(app, ipaddress.ip_address("192.0.2.57"), None)
        with pytest.raises(AuthError) as user_err:
            await user_ips(app, "alice", None)
    finally:
        await app.aclose()
    for err in (ip_err.value, user_err.value):
        assert err.status_code == 403 and "Events & Logs > Analysis > Users" in str(err)


async def test_user_lookup_says_when_only_a_substring_matched(fmc: respx.MockRouter) -> None:
    mock_sessions(fmc, FX["activesessions"]["items"])
    mock_realm_lookups(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_user_ip_lookup", {"user": "ali"})
    assert [s["user"] for s in out["sessions"]] == ["alice"]
    assert "contain 'ali'" in out["match"]


async def test_identity_sources_survive_a_sessions_error(fmc: respx.MockRouter) -> None:
    mock_status(fmc)
    fmc.get(f"{CFG}/analysis/activesessions").mock(return_value=httpx.Response(404, json={}))
    async with Client(server()) as c:
        out = await run(c, "fmc_get_identity_sources", {})
    assert out["sessions"]["error"].startswith("FMC identity sessions unavailable")
    assert "; sessions not readable;" in out["verdict"]


# --- fmc_rule_lookup resolves the user ------------------------------------------------------------------

GROUP_REF = {
    "id": "1",
    "type": "RealmUserGroup",
    "name": "contractors",
    "realm": {"id": FX["realms"]["items"][2]["id"], "type": "Realm", "name": "corp"},
}


def mock_policy(fmc: respx.MockRouter) -> None:
    rules = [
        {
            "id": "r1",
            "name": "contractors-no-web",
            "action": "BLOCK",
            "enabled": True,
            "metadata": {"ruleIndex": 1, "section": "Default"},
            "users": {"objects": [GROUP_REF]},
        },
        {"id": "r2", "name": "allow-all", "action": "ALLOW", "enabled": True, "metadata": {"ruleIndex": 2}},
    ]
    fmc.get(f"{CFG}/policy/accesspolicies").mock(return_value=items([ACP]))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}").mock(
        return_value=ok({**ACP, "defaultAction": {"action": "BLOCK"}})
    )
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules").mock(return_value=items(rules))
    for p in (
        "networkaddresses",
        "ranges",
        "networkgroups",
        "protocolportobjects",
        "icmpv4objects",
        "icmpv6objects",
        "portobjectgroups",
    ):
        fmc.get(f"{CFG}/object/{p}").mock(return_value=empty())


FLOW = {"policy": "acp", "source": "192.0.2.57", "destination": "198.51.100.10", "port": 80}
BOB = {**FX["activesessions"]["items"][0], "username": "bob", "user": "bob", "userId": 2}


async def test_rule_lookup_resolves_the_user_on_the_source(fmc: respx.MockRouter) -> None:
    mock_policy(fmc)
    mock_sessions(fmc, [BOB])
    mock_realm_lookups(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_rule_lookup", FLOW)
    assert out["matched_rule"]["name"] == "contractors-no-web" and out["verdict"].endswith("BLOCK")
    assert out["identity"]["user"] == "bob" and out["identity"]["groups"] == ["contractors"]
    assert out["flow"]["identities"] == ["corp\\bob", "corp\\contractors"]


async def test_rule_lookup_other_user_falls_through(fmc: respx.MockRouter) -> None:
    mock_policy(fmc)
    mock_sessions(fmc, FX["activesessions"]["items"])  # alice, employees
    mock_realm_lookups(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_rule_lookup", FLOW)
    assert out["matched_rule"]["name"] == "allow-all" and "may_match_first" not in out


async def test_rule_lookup_no_session_means_unknown_user(fmc: respx.MockRouter) -> None:
    mock_policy(fmc)
    mock_sessions(fmc, [])
    async with Client(server()) as c:
        out = await run(c, "fmc_rule_lookup", FLOW)
    assert out["matched_rule"]["name"] == "allow-all" and out["identity"]["user"] is None
    assert "unknown user" in out["identity"]["note"]


async def test_rule_lookup_refused_sessions_keep_user_rules_conditional(fmc: respx.MockRouter) -> None:
    mock_policy(fmc)
    mock_sessions(fmc, None)
    async with Client(server()) as c:
        out = await run(c, "fmc_rule_lookup", FLOW)
    assert out["identity"]["error"] == ROLE_HINT
    assert out["may_match_first"][0]["name"] == "contractors-no-web"
    assert out["may_match_first"][0]["depends_on"] == ["users"]


async def test_rule_lookup_expands_a_named_users_groups(fmc: respx.MockRouter) -> None:
    mock_policy(fmc)
    sessions = mock_sessions(fmc, [])
    mock_realm_lookups(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_rule_lookup", {**FLOW, "identities": ["bob"]})
        assert out["matched_rule"]["name"] == "contractors-no-web"
        assert out["identity"]["groups_added"] == {"bob": ["contractors"]}
        exact = await run(c, "fmc_rule_lookup", {**FLOW, "identities": ["bob"], "resolve_user": False})
    assert exact["matched_rule"]["name"] == "allow-all" and "identity" not in exact
    assert not sessions.called


@pytest.mark.parametrize("resolve_user", [True, False])
async def test_rule_lookup_without_user_rules_reads_no_sessions(
    fmc: respx.MockRouter, resolve_user: bool
) -> None:
    mock_policy(fmc)
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP['id']}/accessrules").mock(
        return_value=items([{"id": "r2", "name": "allow-all", "action": "ALLOW", "enabled": True}])
    )
    sessions = mock_sessions(fmc, [BOB])
    async with Client(server()) as c:
        out = await run(c, "fmc_rule_lookup", {**FLOW, "resolve_user": resolve_user})
    assert out["matched_rule"]["name"] == "allow-all" and not sessions.called and "identity" not in out

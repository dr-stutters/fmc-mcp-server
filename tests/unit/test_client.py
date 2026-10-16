import importlib.resources
import json
import time
from typing import Any

import httpx
import pytest
import respx

from fmc_mcp._core import AuthError, InvalidRequest
from fmc_mcp._core import __version__ as core_version
from fmc_mcp._core.testing import call_tool
from fmc_mcp.client import FmcApp, fmc_error_detail
from fmc_mcp.server import create_server

from .conftest import CFG, CHILD, DOMAIN, items, login_response, make_settings


async def test_status(fmc: respx.MockRouter) -> None:
    data = await call_tool(create_server(make_settings()), "fmc_status")
    info = data["fmc"]
    assert info["version"] == "10.0.1 (build 1)"
    assert info["default_domain"] == {"name": "Global", "uuid": DOMAIN}
    assert info["managed_devices"] == 0
    assert info["api_user"] == "apiuser"
    assert info["session"]["logins"] == 1
    # core is bundled (fmc_mcp._core, F35): status reports the bundled version
    bundle = json.loads((importlib.resources.files("fmc_mcp._core") / "BUNDLE.json").read_text())
    assert data["server"]["core_version"] == core_version == bundle["version"]
    text = str(data)
    for secret in ("'pw'", "access-1", "refresh-1"):
        assert secret not in text


async def test_login_sends_basic_and_token_header(fmc: respx.MockRouter) -> None:
    seen: list[str] = []

    def version(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["X-auth-access-token"])
        return items([{"serverVersion": "10.0.1"}])

    fmc.get("/api/fmc_platform/v1/info/serverversion").mock(side_effect=version)
    app = FmcApp(make_settings())
    try:
        assert await app.server_version() == "10.0.1"
    finally:
        await app.aclose()
    login = fmc.routes["login"].calls.last.request
    assert login.headers["Authorization"].startswith("Basic ")
    assert seen == ["access-1"]


async def test_login_failure_is_auth_error(fmc: respx.MockRouter) -> None:
    fmc.routes["login"].mock(
        return_value=httpx.Response(401, json={"error": {"messages": [{"description": "Bad creds"}]}})
    )
    app = FmcApp(make_settings())
    try:
        with pytest.raises(AuthError, match="Bad creds"):
            await app.server_version()
    finally:
        await app.aclose()


async def test_expired_token_is_refreshed_not_relogged(fmc: respx.MockRouter) -> None:
    refresh = fmc.post("/api/fmc_platform/v1/auth/refreshtoken").mock(
        return_value=httpx.Response(
            204, headers={"X-auth-access-token": "access-r", "X-auth-refresh-token": "r2"}
        )
    )
    app = FmcApp(make_settings())
    try:
        await app.ensure_login()
        tok = app._auth.token
        assert tok is not None
        tok.expires_at = time.monotonic()  # force expiry
        await app.ensure_login()
        assert refresh.call_count == 1
        sent = refresh.calls.last.request.headers
        assert sent["X-auth-access-token"] == "access-1" and sent["X-auth-refresh-token"] == "refresh-1"
        assert app._auth.token is not None and app._auth.token.headers == {"X-auth-access-token": "access-r"}
        assert fmc.routes["login"].call_count == 1
        assert app.refreshes == 1
    finally:
        await app.aclose()


async def test_after_three_refreshes_logs_in_again(fmc: respx.MockRouter) -> None:
    n = {"i": 0}

    def do_refresh(request: httpx.Request) -> httpx.Response:
        n["i"] += 1
        return httpx.Response(204, headers={"X-auth-access-token": f"r{n['i']}", "X-auth-refresh-token": "x"})

    fmc.post("/api/fmc_platform/v1/auth/refreshtoken").mock(side_effect=do_refresh)
    fmc.routes["login"].mock(side_effect=[login_response(1), login_response(2)])
    app = FmcApp(make_settings())
    try:
        for _ in range(4):
            await app.ensure_login()
            assert app._auth.token is not None
            app._auth.token.expires_at = time.monotonic()
        await app.ensure_login()
        assert n["i"] == 3
        assert fmc.routes["login"].call_count == 2
        assert app._auth.token is not None and app._auth.token.headers["X-auth-access-token"] == "access-2"
    finally:
        await app.aclose()


async def test_refused_refresh_falls_back_to_login(fmc: respx.MockRouter) -> None:
    fmc.post("/api/fmc_platform/v1/auth/refreshtoken").mock(return_value=httpx.Response(401))
    fmc.routes["login"].mock(side_effect=[login_response(1), login_response(2)])
    app = FmcApp(make_settings())
    try:
        await app.ensure_login()
        assert app._auth.token is not None
        app._auth.token.expires_at = time.monotonic()
        await app.ensure_login()
        assert app._auth.token.headers["X-auth-access-token"] == "access-2"
    finally:
        await app.aclose()


async def test_401_triggers_single_renewal(fmc: respx.MockRouter) -> None:
    fmc.post("/api/fmc_platform/v1/auth/refreshtoken").mock(
        return_value=httpx.Response(
            204, headers={"X-auth-access-token": "access-r", "X-auth-refresh-token": "r"}
        )
    )
    calls: list[str] = []

    def version(request: httpx.Request) -> httpx.Response:
        calls.append(request.headers["X-auth-access-token"])
        if request.headers["X-auth-access-token"] == "access-1":
            return httpx.Response(
                401, json={"error": {"messages": [{"description": "Access token invalid."}]}}
            )
        return items([{"serverVersion": "10.0.1"}])

    fmc.get("/api/fmc_platform/v1/info/serverversion").mock(side_effect=version)
    app = FmcApp(make_settings())
    try:
        assert await app.server_version() == "10.0.1"
    finally:
        await app.aclose()
    assert calls == ["access-1", "access-r"]


async def test_concurrent_requests_share_one_login(fmc: respx.MockRouter) -> None:
    import asyncio

    app = FmcApp(make_settings())
    try:
        await asyncio.gather(*(app.api.get("/api/fmc_platform/v1/info/serverversion") for _ in range(8)))
    finally:
        await app.aclose()
    assert fmc.routes["login"].call_count == 1


@pytest.mark.parametrize(
    ("ref", "expected"),
    [(None, DOMAIN), ("Global", DOMAIN), ("global/branch", CHILD), ("Branch", CHILD), (CHILD.upper(), CHILD)],
)
async def test_domain_resolution(fmc: respx.MockRouter, ref: str | None, expected: str) -> None:
    app = FmcApp(make_settings())
    try:
        assert await app.domain_uuid(ref) == expected
    finally:
        await app.aclose()


async def test_default_domain_setting(fmc: respx.MockRouter) -> None:
    app = FmcApp(make_settings(domain="Branch"))
    try:
        assert await app.domain_uuid(None) == CHILD
        assert await app.config_path("object/hosts") == f"/api/fmc_config/v1/domain/{CHILD}/object/hosts"
        with pytest.raises(InvalidRequest, match="Unknown FMC domain"):
            await app.domain_uuid("Nope")
    finally:
        await app.aclose()


def test_error_detail() -> None:
    body: dict[str, Any] = {"error": {"messages": [{"description": "A"}, {"description": "B"}]}}
    assert fmc_error_detail(body) == "A | B"
    assert fmc_error_detail({"description": "Forbidden"}) == "Forbidden"
    assert fmc_error_detail("plain") == "plain"


async def test_error_mapping(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts/x").mock(
        return_value=httpx.Response(
            404, json={"error": {"messages": [{"description": "Resource Not Found."}]}}
        )
    )
    app = FmcApp(make_settings())
    try:
        with pytest.raises(Exception, match="Not found"):
            await app.api.get(f"{CFG}/object/hosts/x")
    finally:
        await app.aclose()


async def test_list_domains(fmc: respx.MockRouter) -> None:
    data = await call_tool(create_server(make_settings()), "fmc_list_domains", {"response_format": "json"})
    assert [r["name"] for r in data["results"]] == ["Global", "Global/Branch"]
    assert data["results"][0]["default"] is True


async def test_failed_login_is_not_retried_immediately(fmc: respx.MockRouter) -> None:
    fmc.routes["login"].mock(
        return_value=httpx.Response(401, json={"error": {"messages": [{"description": "no"}]}})
    )
    app = FmcApp(make_settings())
    try:
        for _ in range(3):
            with pytest.raises(AuthError) as exc:
                await app.server_version()
            assert "pw" not in str(exc.value)
    finally:
        await app.aclose()
    assert fmc.routes["login"].call_count == 1


async def test_login_without_token_header_fails(fmc: respx.MockRouter) -> None:
    fmc.routes["login"].mock(return_value=httpx.Response(204))
    app = FmcApp(make_settings())
    try:
        with pytest.raises(Exception, match="FMC returned HTTP 204"):
            await app.server_version()
    finally:
        await app.aclose()


async def test_transient_refresh_error_does_not_relogin(fmc: respx.MockRouter) -> None:
    fmc.post("/api/fmc_platform/v1/auth/refreshtoken").mock(return_value=httpx.Response(503))
    app = FmcApp(make_settings())
    try:
        await app.ensure_login()
        assert app._auth.token is not None
        app._auth.token.expires_at = time.monotonic()
        with pytest.raises(Exception, match="503"):
            await app.ensure_login()
    finally:
        await app.aclose()
    assert fmc.routes["login"].call_count == 1


async def test_401_with_dead_refresh_logs_in_once(fmc: respx.MockRouter) -> None:
    fmc.post("/api/fmc_platform/v1/auth/refreshtoken").mock(return_value=httpx.Response(401))
    fmc.routes["login"].mock(side_effect=[login_response(1), login_response(2)])

    def version(request: httpx.Request) -> httpx.Response:
        if request.headers["X-auth-access-token"] == "access-1":
            return httpx.Response(401)
        return items([{"serverVersion": "10.0.1"}])

    fmc.get("/api/fmc_platform/v1/info/serverversion").mock(side_effect=version)
    app = FmcApp(make_settings())
    try:
        assert await app.server_version() == "10.0.1"
    finally:
        await app.aclose()
    assert fmc.routes["login"].call_count == 2


async def test_rotated_refresh_token_is_used(fmc: respx.MockRouter) -> None:
    sent: list[str] = []

    def do_refresh(request: httpx.Request) -> httpx.Response:
        sent.append(request.headers["X-auth-refresh-token"])
        n = len(sent)
        return httpx.Response(
            204, headers={"X-auth-access-token": f"a{n}", "X-auth-refresh-token": f"rot{n}"}
        )

    fmc.post("/api/fmc_platform/v1/auth/refreshtoken").mock(side_effect=do_refresh)
    app = FmcApp(make_settings())
    try:
        for _ in range(3):
            await app.ensure_login()
            assert app._auth.token is not None
            app._auth.token.expires_at = time.monotonic()
        await app.ensure_login()
    finally:
        await app.aclose()
    assert sent == ["refresh-1", "rot1", "rot2"]
    assert app.domains  # kept from the login even though refreshes carry no DOMAINS header


async def test_api_call_fills_domain_uuid(fmc: respx.MockRouter) -> None:
    route = fmc.get(f"{CFG}/object/hosts").mock(return_value=items([{"id": "h", "name": "h1"}]))
    data = await call_tool(
        create_server(make_settings()),
        "fmc_api_call",
        {"path": "/api/fmc_config/v1/domain/{domainUUID}/object/hosts"},
    )
    assert route.call_count == 1 and "h1" in str(data)


async def test_api_call_uses_configured_domain(fmc: respx.MockRouter) -> None:
    child = f"/api/fmc_config/v1/domain/{CHILD}/object/hosts"
    route = fmc.get(child).mock(return_value=items([]))
    await call_tool(
        create_server(make_settings(domain="Global/Branch")),
        "fmc_api_call",
        {"path": "/api/fmc_config/v1/domain/{domainUUID}/object/hosts"},
    )
    assert route.call_count == 1


async def test_missing_credentials_is_auth_error(fmc: respx.MockRouter) -> None:
    app = FmcApp(make_settings(password=None))
    try:
        with pytest.raises(AuthError, match="FMC_USERNAME"):
            await app.server_version()
    finally:
        await app.aclose()

"""F36: `fmc-mcp-server check` against a mocked FMC, one test per failure mode."""

import json
from typing import Any

import httpx
import pytest
import respx

from fmc_mcp import main
from fmc_mcp._core.preflight import run_preflight
from fmc_mcp.preflight import preflight, role_access
from tests.unit.conftest import BASE, CFG, DOMAIN, DOMAINS, items, login_response, make_settings

LOGIN = "/api/fmc_platform/v1/auth/generatetoken"
VERSION = "/api/fmc_platform/v1/info/serverversion"
DOMAIN_INFO = "/api/fmc_platform/v1/info/domain"
USER = f"{CFG}/users/users/u-1"


def _mock(
    router: respx.MockRouter,
    *,
    version: str = "10.0.1 (build 1)",
    roles: list[str] | None = None,
    login: httpx.Response | Exception | None = None,
    domains: list[dict[str, str]] | None = None,
) -> None:
    route = router.post(LOGIN)
    if isinstance(login, Exception):
        route.mock(side_effect=login)
    elif login is not None:
        route.mock(return_value=login)
    elif domains is not None:  # FMC lists the login's domains in a header; [] = none
        resp = login_response()
        resp.headers["DOMAINS"] = json.dumps(domains)
        route.mock(return_value=resp)
    else:
        route.mock(return_value=login_response())
    router.get(DOMAIN_INFO).mock(return_value=items(domains if domains is not None else DOMAINS))
    router.get(VERSION).mock(return_value=items([{"serverVersion": version}]))
    if roles is None:  # mcp-ro / mcp-rw can't read users (no User Management)
        router.get(USER).respond(403, json={"error": {"messages": [{"description": "not authorized"}]}})
    else:
        router.get(USER).respond(json={"id": "u-1", "name": "apiuser", "roles": [{"name": r} for r in roles]})


async def _run(**kw: Any) -> dict[str, Any]:
    return await run_preflight(
        make_settings(**kw), preflight, server="fmc-mcp-server", product="FMC", env_prefix="FMC_"
    )


def _rows(report: dict[str, Any], check: str, inst: int = 0) -> list[dict[str, Any]]:
    return [c for c in report["instances"][inst]["checks"] if c["check"] == check]


def _one(report: dict[str, Any], check: str) -> dict[str, Any]:
    (row,) = _rows(report, check)
    return row


@pytest.fixture
def router() -> Any:
    with respx.mock(base_url=BASE, assert_all_called=False) as r:
        yield r


async def test_healthy_read_only(router: respx.MockRouter) -> None:
    _mock(router)
    report = await _run()
    assert report["ok"]
    (reach,) = _rows(report, "reachability")
    assert reach["outcome"] == "ok" and reach["surface"] == "api"
    assert _one(report, "tls")["outcome"] == "ok"
    assert _one(report, "auth")["outcome"] == "ok" and "apiuser" in _one(report, "auth")["detail"]
    domains = _one(report, "domains")
    assert (
        domains["outcome"] == "ok"
        and "2 visible" in domains["detail"]
        and "default Global" in domains["detail"]
    )
    assert _one(report, "role")["outcome"] == "ok"  # roles unreadable, but only reads are enabled
    assert _one(report, "version")["outcome"] == "ok"
    assert _one(report, "rate_limit")["outcome"] == "ok"
    assert "pw" not in json.dumps(report) and "access-1" not in json.dumps(report)


async def test_unreachable(router: respx.MockRouter) -> None:
    router.post(LOGIN).mock(side_effect=httpx.ConnectError("[Errno 111] Connection refused"))
    report = await _run()
    (reach,) = _rows(report, "reachability")
    assert reach["outcome"] == "fail" and "FMC_URL" in reach["hint"]
    assert not report["ok"]
    assert _one(report, "auth")["outcome"] == "skip" and _one(report, "version")["outcome"] == "skip"


async def test_tls_not_trusted(router: respx.MockRouter) -> None:
    err = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed")
    _mock(router, login=err)
    report = await _run()
    tls = _one(report, "tls")
    assert tls["outcome"] == "fail" and "FMC_CA_BUNDLE" in tls["hint"]
    assert _one(report, "role")["outcome"] == "skip"


async def test_wrong_password(router: respx.MockRouter) -> None:
    _mock(router, login=httpx.Response(401, json={"error": {"messages": [{"description": "bad creds"}]}}))
    report = await _run()
    auth = _one(report, "auth")
    assert auth["outcome"] == "fail" and "FMC_PASSWORD" in auth["hint"]
    assert _one(report, "version")["outcome"] == "skip" and not _rows(report, "domains")
    assert not report["ok"]


async def test_no_domains(router: respx.MockRouter) -> None:
    _mock(router, domains=[])
    report = await _run()
    domains = _one(report, "domains")
    assert domains["outcome"] == "fail" and "no FMC domain" in domains["detail"]
    assert not report["ok"]


async def test_unknown_default_domain(router: respx.MockRouter) -> None:
    _mock(router)
    report = await _run(domain="Nowhere")
    assert _one(report, "domains")["outcome"] == "fail" and "FMC_DOMAIN" in _one(report, "domains")["hint"]


async def test_writes_enabled_on_read_only_role(router: respx.MockRouter) -> None:
    _mock(router, roles=["mcp-ro"])
    report = await _run(mcp_enable_writes=True)
    role = _one(report, "role")
    assert role["outcome"] == "fail" and "write" in role["detail"] and "mcp-ro" in role["detail"]
    assert "MCP_ENABLE_WRITES=false" in role["hint"]


async def test_rw_role_allows_dangerous(router: respx.MockRouter) -> None:
    _mock(router, roles=["mcp-rw"])
    report = await _run(mcp_enable_writes=True, mcp_enable_dangerous=True)
    assert _one(report, "role")["outcome"] == "ok"


async def test_administrator_on_read_only_server_warns(router: respx.MockRouter) -> None:
    _mock(router, roles=["Administrator"])
    report = await _run(username="admin")
    role = _one(report, "role")
    assert role["outcome"] == "warn" and "read-only account" in role["hint"]
    assert _one(report, "api_user")["outcome"] == "warn"
    assert report["ok"]


async def test_unknown_role(router: respx.MockRouter) -> None:
    _mock(router, roles=["Custom Ops"])
    assert _one(await _run(), "role")["outcome"] == "ok"  # reads work; nothing more is enabled
    role = _one(await _run(mcp_enable_writes=True), "role")
    assert role["outcome"] == "warn" and "could not tell" in role["detail"]


async def test_roles_unreadable_with_writes(router: respx.MockRouter) -> None:
    _mock(router, roles=None)
    role = _one(await _run(mcp_enable_writes=True), "role")
    assert role["outcome"] == "warn" and "User Management" in role["detail"]


def test_role_access() -> None:
    assert role_access(["mcp-rw"]) is True
    assert role_access(["mcp-ro", "Administrator"]) is True
    assert role_access(["mcp-ro"]) is False
    assert role_access(["mcp-ro", "Custom"]) is None
    assert role_access([]) is None


@pytest.mark.parametrize(
    ("version", "outcome"),
    [("10.0.1 (build 1)", "ok"), ("7.6.0 (build 113)", "warn"), ("7.0.4 (build 55)", "fail")],
)
async def test_version_matrix(router: respx.MockRouter, version: str, outcome: str) -> None:
    _mock(router, version=version)
    assert _one(await _run(), "version")["outcome"] == outcome


@pytest.mark.parametrize(("limit", "outcome"), [(None, "ok"), (120, "ok"), (300, "warn")])
async def test_rate_budget(router: respx.MockRouter, limit: float | None, outcome: str) -> None:
    _mock(router)
    row = _one(await _run(rate_limit=limit), "rate_limit")
    assert row["outcome"] == outcome and row["data"]["per_minute"] == (limit or 110)
    if outcome == "warn":
        assert "FMC_RATE_LIMIT" in row["hint"]


async def test_two_instances(router: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FMC_LAB2_URL", "https://fmc-2.test")
    monkeypatch.setenv("FMC_LAB2_USERNAME", "ro")
    monkeypatch.setenv("FMC_LAB2_PASSWORD", "x")
    _mock(router)
    router.route(host="fmc-2.test").mock(side_effect=httpx.ConnectError("no route to host"))
    report = await _run(instances="lab2")
    assert [i["instance"] for i in report["instances"]] == ["default", "lab2"]
    assert report["instances"][0]["ok"] and not report["instances"][1]["ok"]
    assert _rows(report, "reachability", 1)[0]["outcome"] == "fail"


def test_cli_check_json(
    router: respx.MockRouter,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    for k, v in {
        "FMC_URL": BASE,
        "FMC_USERNAME": "apiuser",
        "FMC_PASSWORD": "s3cret",
        "FMC_RETRIES": "0",
    }.items():
        monkeypatch.setenv(k, v)
    _mock(router)
    monkeypatch.setattr("sys.argv", ["fmc-mcp-server", "check", "--json"])
    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 0
    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["ok"] is True and "s3cret" not in out
    assert DOMAIN not in json.dumps(_one(report, "domains")["detail"])

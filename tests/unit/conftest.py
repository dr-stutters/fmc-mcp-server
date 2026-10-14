import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx

from fmc_mcp.config import Settings

BASE = "https://fmc.test"
DOMAIN = "e276abec-e0f2-11e3-8169-6d9ed49b625f"
CHILD = "11111111-2222-3333-4444-555555555555"
CFG = f"/api/fmc_config/v1/domain/{DOMAIN}"
DOMAINS = [{"name": "Global", "uuid": DOMAIN}, {"name": "Global/Branch", "uuid": CHILD}]


def make_settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "url": BASE,
        "username": "apiuser",
        "password": "pw",
        "retries": 0,
        "mcp_cache_dir": None,
    }
    base.update(kw)
    return Settings(_env_file=None, **base)  # type: ignore[call-arg]


def login_response(n: int = 1) -> httpx.Response:
    return httpx.Response(
        204,
        headers={
            "X-auth-access-token": f"access-{n}",
            "X-auth-refresh-token": f"refresh-{n}",
            "DOMAIN_UUID": DOMAIN,
            "USER_UUID": "u-1",
            "DOMAINS": json.dumps(DOMAINS),
        },
    )


def items(rows: list[dict[str, Any]], total: int | None = None) -> httpx.Response:
    return httpx.Response(
        200, json={"items": rows, "paging": {"count": len(rows) if total is None else total}}
    )


@pytest.fixture
def fmc() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=BASE, assert_all_called=False) as mock:
        mock.post("/api/fmc_platform/v1/auth/generatetoken", name="login").mock(return_value=login_response())
        mock.get("/api/fmc_platform/v1/info/serverversion").mock(
            return_value=items([{"serverVersion": "10.0.1 (build 1)", "hostname": "fmc", "model": "FMCv"}])
        )
        mock.get("/api/fmc_platform/v1/info/domain").mock(
            return_value=items([{**d, "parentUUID": DOMAIN} for d in DOMAINS])
        )
        mock.get(f"{CFG}/devices/devicerecords").mock(return_value=items([], 0))
        yield mock

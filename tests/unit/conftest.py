import asyncio
import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx
from fastmcp import FastMCP

from fmc_mcp.config import Settings
from fmc_mcp.server import create_server

BASE = "https://fmc.test"
DOMAIN = "e276abec-e0f2-11e3-8169-6d9ed49b625f"
CHILD = "11111111-2222-3333-4444-555555555555"
CFG = f"/api/fmc_config/v1/domain/{DOMAIN}"
DOMAINS = [{"name": "Global", "uuid": DOMAIN}, {"name": "Global/Branch", "uuid": CHILD}]
# The lab's layout: the login's domain (DOMAIN, so CFG and every mock below) is a leaf under Global (TOP).
TOP = "99999999-0000-4000-8000-000000000001"
TOP_CFG = f"/api/fmc_config/v1/domain/{TOP}"
LEAF_DOMAINS = [{"name": "Global", "uuid": TOP}, {"name": "Global/mcp-test-leaf", "uuid": DOMAIN}]


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


def make_server(**kw: Any) -> FastMCP[Any]:
    return create_server(make_settings(**kw))


def login_response(n: int = 1, domains: list[dict[str, str]] | None = None) -> httpx.Response:
    return httpx.Response(
        204,
        headers={
            "X-auth-access-token": f"access-{n}",
            "X-auth-refresh-token": f"refresh-{n}",
            "DOMAIN_UUID": DOMAIN,
            "USER_UUID": "u-1",
            "DOMAINS": json.dumps(DOMAINS if domains is None else domains),
        },
    )


def as_leaf(fmc: respx.MockRouter, domains: list[dict[str, str]] = LEAF_DOMAINS) -> None:
    """Log in to DOMAIN as a leaf below Global (TOP_CFG), like the lab's Global/mcp-test-leaf: the
    existing CFG mocks stay the leaf's, and Global's own paths are TOP_CFG."""
    fmc.routes["login"].mock(return_value=login_response(domains=domains))


def items(rows: list[dict[str, Any]], total: int | None = None) -> httpx.Response:
    return httpx.Response(
        200, json={"items": rows, "paging": {"count": len(rows) if total is None else total}}
    )


class ConcurrentFmc:
    """FMC 10.0.1's operational/commands as recorded live (fleet_show.json `concurrent_mixup`; used by
    test_fleet.py and test_device_snapshot.py): a request that overlaps another one, for any device, is
    answered with the output of the newest request in flight. Requests that don't overlap get their own
    device's output. `peak`: most requests at once."""

    def __init__(self, outputs: dict[str, str] | dict[str, dict[str, str]]) -> None:
        self.outputs = outputs  # device id -> its output, or {command: output}
        self.inflight: list[str] = []
        self.peak = 0
        self.calls: list[str] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        dev = request.url.path.split("/")[-3]
        self.calls.append(dev)
        self.inflight.append(dev)
        self.peak = max(self.peak, len(self.inflight))
        await asyncio.sleep(0.01)
        source = self.inflight[-1]
        self.inflight.remove(dev)
        q = request.url.params
        cmd = q["command"] + (f" {q['parameters']}" if "parameters" in q else "")
        out = self.outputs[source]
        text = out if isinstance(out, str) else out[cmd]
        return items([{"commandInput": cmd, "commandOutput": text, "type": "command"}])

    def mount(self, router: respx.MockRouter, cfg: str = CFG) -> "ConcurrentFmc":
        """Answer each device's operational/commands in domain path `cfg` (default: the test domain)."""
        for i in self.outputs:
            router.get(f"{cfg}/devices/devicerecords/{i}/operational/commands").mock(side_effect=self)
        return self


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
        for dom in (DOMAIN, CHILD, TOP):  # no device groups (F68: tools taking devices look them up)
            mock.get(f"/api/fmc_config/v1/domain/{dom}/devicegroups/devicegrouprecords").mock(
                return_value=items([], 0)
            )
            # F76: nothing locked, as FMC 10.0.1 answers it (one empty item)
            mock.get(f"/api/fmc_config/v1/domain/{dom}/policy/operational/policylocks").mock(
                return_value=items([{}])
            )
        yield mock


FIXTURES = __import__("pathlib").Path(__file__).resolve().parent.parent / "fixtures"
ACP_ID = "00000000-0000-0ed3-0000-021474837418"
NAT_ID = "00000000-0000-0ed3-0000-021474837632"


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def empty() -> httpx.Response:
    return httpx.Response(
        200, json={"links": {}, "paging": {"offset": 0, "limit": 0, "count": 0, "pages": 0}}
    )


@pytest.fixture
def lab(fmc: respx.MockRouter) -> respx.MockRouter:
    """The seeded mcp-test-* objects (docs/live-tests.md) as recorded in tests/fixtures."""
    fmc.get(f"{CFG}/policy/accesspolicies").mock(
        return_value=httpx.Response(200, json=fixture("accesspolicies"))
    )
    acp = fixture("accesspolicies")["items"][0]
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}").mock(return_value=httpx.Response(200, json=acp))
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules").mock(
        return_value=httpx.Response(200, json=fixture("accessrules"))
    )
    # F76: no base policy (the setting's id is the policy's own id), no categories
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/inheritancesettings").mock(
        return_value=items([{"id": ACP_ID, "type": "AccessPolicyInheritanceSetting"}])
    )
    fmc.get(f"{CFG}/policy/accesspolicies/{ACP_ID}/categories").mock(return_value=empty())
    fmc.get(f"{CFG}/policy/ftdnatpolicies").mock(
        return_value=items([{"name": "mcp-test-nat", "id": NAT_ID, "type": "FTDNatPolicy"}])
    )
    fmc.get(f"{CFG}/policy/ftdnatpolicies/{NAT_ID}/natrules").mock(
        return_value=httpx.Response(200, json=fixture("natrules"))
    )
    for name in ("networkaddresses", "networkgroups", "protocolportobjects", "portobjectgroups"):
        fmc.get(f"{CFG}/object/{name}").mock(return_value=httpx.Response(200, json=fixture(name)))
    for name in ("icmpv4objects", "icmpv6objects", "ranges"):
        fmc.get(f"{CFG}/object/{name}").mock(return_value=empty())
    fmc.get(f"{CFG}/assignment/policyassignments").mock(return_value=empty())
    return fmc

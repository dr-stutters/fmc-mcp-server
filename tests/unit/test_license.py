"""fmc_license_status and the VPN strong-crypto check read FMC 10's smart-licence metadata."""

from typing import Any

import respx

from fmc_mcp._core.testing import call_tool
from fmc_mcp.server import create_server
from fmc_mcp.tools.common import smart_license_row
from fmc_mcp.tools.vpn import strong_crypto_allowed

from .conftest import items, make_settings

SMART = "/api/fmc_platform/v1/license/smartlicenses"
DEVICE_LICENSES = "/api/fmc_platform/v1/license/devicelicenses"

# Shape recorded from FMC 10.0.1 (account name replaced): the status lives in items[].metadata.
OUT_OF_COMPLIANCE = {
    "regStatus": "REGISTERED",
    "force": "false",
    "type": "SmartLicense",
    "metadata": {
        "authStatus": "OUT_OF_COMPLIANCE",
        "virtualAccount": "mcp-test-va",
        "exportControl": False,
        "evalUsed": True,
        "evalExpiresInDays": 0,
        "lastSynchronizedTime": "2026-10-17T12:51:31UTC",
        "lastRenewedTime": "2026-10-17T11:44:05UTC",
    },
}


async def test_license_status_keeps_smart_license_metadata(fmc: respx.MockRouter) -> None:
    fmc.get(SMART).mock(return_value=items([OUT_OF_COMPLIANCE]))
    fmc.get(DEVICE_LICENSES).mock(return_value=items([]))
    data = await call_tool(create_server(make_settings()), "fmc_license_status", {})
    row = data["smart_license"][0]
    assert row["regStatus"] == "REGISTERED"
    assert row["authStatus"] == "OUT_OF_COMPLIANCE"
    assert row["virtualAccount"] == "mcp-test-va"
    assert row["evalUsed"] is True and row["evalExpiresInDays"] == 0
    assert row["exportControl"] is False
    assert row["lastSynchronizedTime"] == "2026-10-17T12:51:31UTC"
    assert "metadata" not in row and data["device_licenses"] == []


def test_smart_license_row_top_level_wins_and_links_dropped() -> None:
    row = smart_license_row(
        {"regStatus": "EVALUATION", "links": {}, "metadata": {"regStatus": "x", "links": {}}}
    )
    assert row == {"regStatus": "EVALUATION"}
    assert smart_license_row({"regStatus": "UNREGISTERED"}) == {"regStatus": "UNREGISTERED"}


class _Api:
    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body

    async def get(self, path: str, params: Any = None) -> dict[str, Any]:
        assert path == SMART
        return self.body


class _App:
    def __init__(self, body: dict[str, Any]) -> None:
        self.api = _Api(body)


async def test_strong_crypto_reads_export_control_from_metadata() -> None:
    assert await strong_crypto_allowed(_App({"items": [OUT_OF_COMPLIANCE]})) is False  # type: ignore[arg-type]
    allowed = {**OUT_OF_COMPLIANCE, "metadata": {**OUT_OF_COMPLIANCE["metadata"], "exportControl": True}}
    assert await strong_crypto_allowed(_App({"items": [allowed]})) is True  # type: ignore[arg-type]

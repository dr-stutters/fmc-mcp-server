"""F38: a shared host is read-only unless the operator opts in (write, then dangerous)."""

import re
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from fmc_mcp._core.manifest import build_manifest
from fmc_mcp.config import Settings
from tests.unit.conftest import make_server

ROOT = Path(__file__).resolve().parents[2]
# <prefix>_api_call is always registered: GET only below the dangerous tier, any method with it.
TIER_SCOPED = {"fmc_api_call"}


async def _tiers() -> dict[str, str]:
    server = make_server(mcp_enable_writes=True, mcp_enable_dangerous=True)
    manifest = await build_manifest(server, server="fmc-mcp-server", prefix="fmc", version=None)
    return {name: meta["tier"] for name, meta in manifest["tools"].items() if name not in TIER_SCOPED}


async def _names(**kw: Any) -> set[str]:
    async with Client(make_server(**kw)) as client:
        return {t.name for t in await client.list_tools()}


def test_settings_default_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_ENABLE_WRITES", raising=False)
    monkeypatch.delenv("MCP_ENABLE_DANGEROUS", raising=False)
    s = Settings(_env_file=None, url="https://appliance.test")  # type: ignore[call-arg]
    assert s.mcp_enable_writes is False and s.mcp_enable_dangerous is False


async def test_default_server_registers_only_read_tools() -> None:
    tiers = await _tiers()
    assert {"write", "dangerous"} <= set(tiers.values())  # the surface has both, so the test means something
    names = await _names()
    assert names and all(tiers.get(n, "read") == "read" for n in names), sorted(
        n for n in names if tiers.get(n) != "read"
    )


async def test_writes_opt_in_keeps_dangerous_off() -> None:
    tiers = await _tiers()
    names = await _names(mcp_enable_writes=True)
    assert any(tiers.get(n) == "write" for n in names)
    assert not [n for n in names if tiers.get(n) == "dangerous"]


async def test_dangerous_needs_writes() -> None:
    with pytest.raises(ValueError):
        make_server(mcp_enable_dangerous=True)


@pytest.mark.parametrize(
    "name",
    [
        ".env.example",
        "docker-compose.yml",
        "examples/shared-host/.env.example",
        "examples/shared-host/docker-compose.yml",
    ],
)
def test_shipped_config_does_not_enable_writes(name: str) -> None:
    path = ROOT / name
    if not path.exists():
        pytest.skip(f"{name} not shipped")
    text = path.read_text()
    enabled = re.findall(r"^\s*(MCP_ENABLE_(?:WRITES|DANGEROUS))\s*[:=]\s*[\"']?true", text, re.M | re.I)
    assert not enabled, (
        f"{name} turns on {enabled}: a shared host must be read-only until the operator opts in"
    )

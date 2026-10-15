import json
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest
import respx
from fastmcp import FastMCP
from stutters_mcp_core.manifest import build_manifest
from stutters_mcp_core.testing import (
    assert_inbound_references,
    assert_prompt_contract,
    assert_prompt_snapshots,
    assert_tool_contract,
    load_tool_manifests,
)

from fmc_mcp.server import create_server

from .conftest import make_settings


@pytest.mark.parametrize(
    "kw", [{}, {"mcp_enable_writes": True}, {"mcp_enable_writes": True, "mcp_enable_dangerous": True}]
)
async def test_contract(fmc: respx.MockRouter, kw: dict[str, Any]) -> None:
    await assert_tool_contract(create_server(make_settings(**kw)), "fmc")


async def test_prompt_contract(fmc: respx.MockRouter) -> None:
    server = create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))
    await assert_prompt_contract(
        server,
        "fmc",
        samples={
            "fmc_why_blocked": {"source": "10.99.1.10", "destination": "198.18.134.76", "port": "23"},
            "fmc_onboard_ftd": {
                "name": "mcp-ftd2",
                "access_policy": "acp",
                "outside_ip": "198.18.128.163/18",
                "gateway": "198.18.128.1",
                "inside_ip": "10.99.2.1/24",
                "host": "198.18.128.161",
                "test_destination": "198.18.128.1",
            },
        },
        known_prefixes={"cml", "ise", "fmc", "catc"},
        external_tools=_external(),
    )


HERE = Path(__file__).resolve().parent.parent


def _external() -> dict[str, list[str]]:
    """Other servers' tool names: their committed manifests, plus hand-kept lists until they publish one."""
    tools = {k: list(v) for k, v in load_tool_manifests(HERE / "manifests").items()}
    cml = json.loads((HERE / "external" / "cml-tools.json").read_text())["cml"]
    tools.setdefault("cml", cml)
    return tools


def _server() -> FastMCP[Any]:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True))


async def test_inbound_references(fmc: respx.MockRouter) -> None:
    await assert_inbound_references(_server(), "fmc", HERE / "manifests")


async def test_prompt_snapshots(fmc: respx.MockRouter) -> None:
    await assert_prompt_snapshots(_server(), HERE / "snapshots" / "prompts")


async def test_manifest_is_current(fmc: respx.MockRouter) -> None:
    """Other servers check their prompts against tests/manifests/fmc.json: it must match the code."""
    committed = json.loads((HERE / "manifests" / "fmc.json").read_text())
    fresh = await build_manifest(
        _server(), server="fmc-mcp-server", prefix="fmc", version=version("fmc-mcp-server")
    )
    for key in ("version", "tools", "prompts"):
        assert committed[key] == fresh[key], (
            f"tests/manifests/fmc.json is stale ({key}); regenerate: "
            "uv run fmc-mcp-server tools --json --out tests/manifests/fmc.json"
        )

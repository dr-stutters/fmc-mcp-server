import json
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest
import respx
from fastmcp import Client, FastMCP

from fmc_mcp._core.manifest import build_manifest
from fmc_mcp._core.testing import (
    assert_inbound_references,
    assert_prompt_contract,
    assert_prompt_snapshots,
    assert_suite_pack,
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


# Peer snapshot tools the suite pack's change check (C53) calls that their servers have not shipped yet; a
# waiver for a tool a committed peer manifest now lists fails, so the list shrinks as peers ship.
PEER_PENDING = [
    "catc_compare_snapshot",
    "catc_snapshot",
    "catsdwan_compare_snapshot",
    "catsdwan_snapshot",
    "ise_compare_snapshot",
    "ise_snapshot",
]


async def test_suite_pack(fmc: respx.MockRouter) -> None:
    """Core's suite prompt pack (C48) is registered and its fmc leg tools (fmc_snapshot, ...) exist."""
    await assert_suite_pack(_server(), "fmc", HERE / "manifests", pending=PEER_PENDING)


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


async def test_every_referenced_tool_exists(fmc: respx.MockRouter) -> None:
    """F32: descriptions, argument help, instructions and prompt texts only name real tools."""
    import re

    from fmc_mcp.server import INSTRUCTIONS

    # API areas, the package name and a CML recipe field are not tools.
    api_areas = {
        "fmc_config",
        "fmc_platform",
        "fmc_tid",
        "fmc_troubleshoot",
        "fmc_netmap",
        "fmc_mcp",
        "fmc_side",
    }
    async with Client(_server()) as c:
        tools = await c.list_tools()
        prompts = await c.list_prompts()
    names = {t.name for t in tools} | {p.name for p in prompts}
    texts = [INSTRUCTIONS] + [json.dumps([t.description, t.inputSchema]) for t in tools]
    texts += [p.read_text() for p in (HERE / "snapshots" / "prompts").glob("*.md")]
    seen = set(re.findall(r"\bfmc_[a-z0-9_]+", "\n".join(texts)))
    assert sorted(seen - names - api_areas) == []

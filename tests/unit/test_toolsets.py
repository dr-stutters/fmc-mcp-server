"""F46 FMC_TOOLSETS: every tool in exactly one area, one contract test per area, prompts by home area,
unknown names refused, tiers still applied on top."""

import json
from pathlib import Path
from typing import Any

import pytest
import respx
from fastmcp import FastMCP
from pydantic import ValidationError

from fmc_mcp import toolsets
from fmc_mcp._core import suite
from fmc_mcp._core.testing import assert_tool_contract, call_tool
from fmc_mcp.server import create_server

from .conftest import make_settings

MANIFEST = json.loads((Path(__file__).resolve().parent.parent / "manifests" / "fmc.json").read_text())
ALL_TIERS = {"mcp_enable_writes": True, "mcp_enable_dangerous": True}
CORE = toolsets.TOOLSETS["core"] - {"fmc_review_change"}  # review_change only with two-person rails
SUITE = set(suite.PACK)  # core's suite_* prompts: always registered (their legs name what is absent)


def server(**kw: Any) -> FastMCP[Any]:
    return create_server(make_settings(**{**ALL_TIERS, **kw}))


async def names(mcp: FastMCP[Any]) -> tuple[set[str], set[str]]:
    tools = {t.name for t in await mcp.list_tools(run_middleware=False)}
    prompts = {p.name for p in await mcp.list_prompts(run_middleware=False)}
    return tools, prompts


def test_every_tool_is_in_exactly_one_area() -> None:
    listed = [t for _, tools in toolsets.CATALOGUE.values() for t in tools]
    assert len(listed) == len(set(listed)), sorted(t for t in listed if listed.count(t) > 1)
    for area, (blurb, tools) in toolsets.CATALOGUE.items():
        assert list(tools) == sorted(tools), f"{area}: keep the list sorted"
        assert blurb and len(blurb) < 110, area


async def test_the_areas_cover_the_registered_tools(fmc: respx.MockRouter) -> None:
    tools, prompts = await names(server())
    table = set(toolsets.AREA_OF) - {"fmc_review_change"}
    assert sorted(tools - table) == [], "new tool: add it to one area in fmc_mcp/toolsets.py"
    assert sorted(table - tools) == [], "toolsets.py names a tool that is not registered"
    assert set(MANIFEST["tools"]) == tools
    assert set(toolsets.PROMPT_TOOLSETS) == prompts - SUITE and prompts >= SUITE
    # with two-person rails the review tool appears, and it is core
    tools, _ = await names(server(mcp_two_person_tools="fmc_deploy"))
    assert "fmc_review_change" in tools and toolsets.AREA_OF["fmc_review_change"] == "core"


@pytest.mark.parametrize("area", sorted(set(toolsets.TOOLSETS) - {"core"}))
async def test_toolset_registers_exactly_its_area(fmc: respx.MockRouter, area: str) -> None:
    mcp = server(toolsets=area)
    tools, prompts = await names(mcp)
    assert tools == toolsets.TOOLSETS[area] | CORE
    assert prompts == {p for p, home in toolsets.PROMPT_TOOLSETS.items() if home <= {area}} | SUITE
    await assert_tool_contract(mcp, "fmc")


async def test_several_areas_exclusions_and_tiers_on_top(fmc: respx.MockRouter) -> None:
    tools, prompts = await names(server(toolsets="troubleshoot, policy"))
    assert tools == toolsets.TOOLSETS["troubleshoot"] | toolsets.TOOLSETS["policy"] | CORE
    assert "fmc_why_blocked" in prompts and "fmc_vpn_troubleshoot" not in prompts
    tools, _ = await names(server(toolsets="all,-sdwan,-tls"))
    assert not tools & (toolsets.TOOLSETS["sdwan"] | toolsets.TOOLSETS["tls"])
    assert toolsets.TOOLSETS["vpn"] <= tools
    # the tiers still apply: objects without writes = the object reads
    tools, _ = await names(create_server(make_settings(toolsets="objects")))
    reads = {t for t in toolsets.TOOLSETS["objects"] if MANIFEST["tools"][t]["tier"] == "read"}
    assert tools - CORE == reads
    assert "fmc_find_address" in tools and "fmc_create_object" not in tools
    # and so do MCP_DENY_TOOLS
    tools, _ = await names(server(toolsets="objects", mcp_deny_tools="fmc_delete_*"))
    assert "fmc_delete_object" not in tools and "fmc_create_object" in tools


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ("troubleshoot,bogus", "unknown toolset 'bogus'. Toolsets: admin, core, deploy"),
        ("objectz", "(or 'all'; '-<name>' leaves one out)"),
        ("all,-core", "'core' (status, spec search, raw API call) is always loaded"),
    ],
)
def test_unknown_toolsets_fail_at_startup(spec: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message.replace("(", r"\(").replace(")", r"\)")):
        make_settings(toolsets=spec)


def test_parse() -> None:
    assert toolsets.parse(None) is None and toolsets.parse(" , ") is None
    assert toolsets.parse("Troubleshoot") == {"troubleshoot", "core"}
    assert toolsets.parse("-sdwan") == set(toolsets.TOOLSETS) - {"sdwan"}
    assert toolsets.parse("all") == set(toolsets.TOOLSETS)


async def test_status_and_instructions_name_the_loaded_areas(fmc: respx.MockRouter) -> None:
    mcp = server(toolsets="vpn,deploy")
    status = await call_tool(mcp, "fmc_status")
    assert status["fmc"]["toolsets"] == {
        "loaded": ["core", "deploy", "vpn"],
        "not_loaded": sorted(set(toolsets.TOOLSETS) - {"core", "deploy", "vpn"}),
        "setting": "FMC_TOOLSETS",
    }
    assert "loads only some toolsets (FMC_TOOLSETS): core, deploy, vpn" in (mcp.instructions or "")
    full = await call_tool(server(), "fmc_status")
    assert "toolsets" not in full["fmc"]


def test_prompt_home_areas_are_areas_the_prompt_uses() -> None:
    """A prompt's home areas must be among the areas of the fmc tools its rendered text names."""
    for name, meta in MANIFEST["prompts"].items():
        if name in SUITE:  # core's, registered in every toolset selection
            continue
        used = {toolsets.AREA_OF[r] for r in meta["references"] if r in toolsets.AREA_OF}
        assert toolsets.PROMPT_TOOLSETS[name] <= used, (name, sorted(used))


def test_readme_lists_every_toolset() -> None:
    readme = (Path(__file__).resolve().parent.parent.parent / "README.md").read_text()
    for area, (blurb, _) in toolsets.CATALOGUE.items():
        assert f"| `{area}` |" in readme and blurb in readme, f"README toolsets table: {area}"


async def test_tools_carry_their_area_as_core_toolset(fmc: respx.MockRouter) -> None:
    """Core C31: every non-core tool is registered with toolset=<its area> (the manifest records it) and
    core's gate knows every area, so FMC_TOOLSETS names are never 'unknown' in server.toolsets."""
    for tool, meta in MANIFEST["tools"].items():
        area = toolsets.AREA_OF[tool]
        assert meta.get("toolsets") == (None if area == "core" else [area]), tool
    status = await call_tool(server(toolsets="vpn,deploy,core"), "fmc_status")
    core_view = status["server"]["toolsets"]
    assert "unknown" not in core_view and core_view["available"] == sorted(toolsets.TOOLSETS)
    assert set(core_view["loaded"]) == {"deploy", "vpn"}
    assert status["fmc"]["toolsets"]["loaded"] == ["core", "deploy", "vpn"]

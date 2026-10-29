"""Renamed tools and prompts, kept for one minor release under their old names (F86).

FTD SD-WAN (FMC's SD-WAN wizard topologies of FTD hubs and branches) was `fmc_sdwan_*`; next to
cat-sdwan-mcp-server's `catsdwan_*` (Catalyst SD-WAN, a different product) that invited the wrong pick, so
the tools are `*_ftdsdwan_*` from 0.20.0. Each old name stays as a deprecated alias that runs the new tool
and adds `renamed_to` to its result; its description starts 'Deprecated: use <new>'. The aliases go in
the next minor release (one minor release of notice, as Cisco announces its API deprecations a release ahead).
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any

from fastmcp.tools import ToolResult

from fmc_mcp._core import object_result

REMOVED_IN = "0.23.0"

# old tool name -> new tool name
RENAMED_TOOLS: dict[str, str] = {
    "fmc_sdwan_status": "fmc_ftdsdwan_status",
    "fmc_create_sdwan_topology": "fmc_create_ftdsdwan_topology",
    "fmc_update_sdwan_topology": "fmc_update_ftdsdwan_topology",
}
# old prompt name -> new prompt name
RENAMED_PROMPTS: dict[str, str] = {"fmc_sdwan_troubleshoot": "fmc_ftdsdwan_troubleshoot"}


def deprecation(old: str, new: str) -> str:
    return f"Deprecated: use {new} ({old} was renamed in 0.20.0 and goes in {REMOVED_IN})."


def with_rename(out: Any, old: str) -> Any:
    """A tool result with `renamed_to` (and the deprecation line) added."""
    new = RENAMED_TOOLS[old]
    extra = {"renamed_to": new, "deprecated": deprecation(old, new)}
    if isinstance(out, dict):
        return {**out, **extra}
    if isinstance(out, ToolResult) and isinstance(out.structured_content, dict):
        return object_result({**out.structured_content, **extra}, shape=False)
    return out


def tool_alias(fn: Callable[..., Awaitable[Any]], old: str) -> Callable[..., Awaitable[Any]]:
    """`fn` (an async tool) under its old name: same signature and result, plus `renamed_to`.
    A preview's confirm token is bound to the new tool's name, so a preview through the alias confirms
    through either name."""
    new = RENAMED_TOOLS[old]

    @functools.wraps(fn)
    async def alias(*args: Any, **kwargs: Any) -> Any:
        return with_rename(await fn(*args, **kwargs), old)

    alias.__name__ = alias.__qualname__ = old
    alias.__doc__ = f"{deprecation(old, new)} Same arguments and result as {new}, plus `renamed_to`."
    return alias


def prompt_alias(fn: Callable[..., str], old: str) -> Callable[..., str]:
    """A prompt under its old name: the same text after a one-line rename note."""
    new = RENAMED_PROMPTS[old]

    @functools.wraps(fn)
    def alias(*args: Any, **kwargs: Any) -> str:
        return f"(renamed_to: {new}. {deprecation(old, new)})\n\n{fn(*args, **kwargs)}"

    alias.__name__ = alias.__qualname__ = old
    alias.__doc__ = f"{deprecation(old, new)} The same workflow as {new}."
    return alias

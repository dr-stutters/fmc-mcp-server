"""Live tests share ONE server (one FMC login) for the whole session: every FMC login for the same
user can end that user's other sessions, so tests must not log in per test."""

from collections.abc import AsyncIterator
from typing import Any

import pytest_asyncio
from fastmcp import Client, FastMCP
from stutters_mcp_core.testing import live_settings

from fmc_mcp.config import Settings
from fmc_mcp.server import create_server


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def client() -> AsyncIterator[Client[Any]]:
    settings = live_settings(
        Settings, "FMC_", mcp_enable_writes=True, mcp_enable_dangerous=True, allow_ignore_warning=True
    )
    server: FastMCP[Any] = create_server(settings)
    async with Client(server) as c:
        yield c

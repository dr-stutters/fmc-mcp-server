from typing import Any

import pytest
import respx
from stutters_mcp_core.testing import assert_tool_contract

from fmc_mcp.server import create_server

from .conftest import make_settings


@pytest.mark.parametrize(
    "kw", [{}, {"mcp_enable_writes": True}, {"mcp_enable_writes": True, "mcp_enable_dangerous": True}]
)
async def test_contract(fmc: respx.MockRouter, kw: dict[str, Any]) -> None:
    await assert_tool_contract(create_server(make_settings(**kw)), "fmc")

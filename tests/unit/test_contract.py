from typing import Any

import pytest
import respx
from stutters_mcp_core.testing import assert_prompt_contract, assert_tool_contract

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
    )

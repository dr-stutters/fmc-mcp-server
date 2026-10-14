from typing import Any

import pytest
from fastmcp import Client

pytestmark = pytest.mark.live


async def test_status(client: Client[Any]) -> None:
    result = await client.call_tool("fmc_status")
    data = result.structured_content
    assert data is not None
    assert data["fmc"]["version"].startswith(("7.", "10."))
    assert data["fmc"]["default_domain"]["name"]

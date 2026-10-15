"""F25: import 30 mcp-test-bulk-* objects (hosts, networks, ports), re-run with skip_existing (nothing to
create), then delete them."""

from typing import Any

import pytest
from fastmcp import Client

pytestmark = pytest.mark.live


async def call(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    return (await client.call_tool(name, args)).structured_content


async def apply(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    preview = await call(client, name, args)
    assert preview["status"] == "preview", preview
    done = await call(client, name, {**args, "confirm": preview["confirm"]})
    assert done["status"] == "applied", done
    return done["result"]


ROWS = (
    [{"name": f"mcp-test-bulk-h{i}", "type": "host", "value": f"10.250.0.{i}"} for i in range(1, 21)]
    + [{"name": f"mcp-test-bulk-n{i}", "type": "network", "value": f"10.251.{i}.0/24"} for i in range(1, 6)]
    + [{"name": f"mcp-test-bulk-p{i}", "type": "port", "value": f"tcp/{9000 + i}"} for i in range(1, 6)]
)


async def test_bulk_import(client: Client[Any]) -> None:
    try:
        out = await apply(client, "fmc_import_objects", {"objects": ROWS, "skip_existing": True})
        assert out["created"] in (0, 30), out
        again = await call(client, "fmc_import_objects", {"objects": ROWS, "skip_existing": True})
        assert again["status"] == "blocked" and "Nothing to create." in again["blockers"], again
        found = await call(client, "fmc_find_object", {"value": "10.250.0.7", "response_format": "json"})
        assert any(r.get("name") == "mcp-test-bulk-h7" for r in found["results"]), found
    finally:
        for row in ROWS:
            p = await call(client, "fmc_delete_object", {"object": row["name"], "type": row["type"]})
            if p and p.get("status") == "preview":
                await call(
                    client,
                    "fmc_delete_object",
                    {"object": row["name"], "type": row["type"], "confirm": p["confirm"]},
                )

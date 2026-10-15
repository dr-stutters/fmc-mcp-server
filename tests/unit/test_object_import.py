"""F25 bulk object import."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, items, make_settings


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def test_bulk_import_per_type(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/hosts").mock(
        return_value=items([{"id": "h0", "name": "old", "type": "Host", "value": "10.0.0.9"}])
    )
    fmc.get(f"{CFG}/object/protocolportobjects").mock(return_value=items([]))
    hosts = fmc.post(f"{CFG}/object/hosts").mock(return_value=httpx.Response(201, json={"items": []}))
    ports = fmc.post(f"{CFG}/object/protocolportobjects").mock(
        return_value=httpx.Response(201, json={"items": []})
    )
    rows = [
        {"name": "h1", "type": "host", "value": "10.0.0.1"},
        {"name": "old", "type": "host", "value": "10.0.0.9"},
        {"name": "p1", "type": "port", "value": "tcp/8443"},
    ]
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        blocked = await run(c, "fmc_import_objects", {"objects": rows})
        assert blocked["status"] == "blocked" and "same value" in blocked["blockers"][0]
        bad = await run(
            c, "fmc_import_objects", {"objects": [{"name": "x", "type": "host", "value": "nope"}]}
        )
        assert bad["status"] == "blocked"
        args = {"objects": rows, "skip_existing": True}
        p = await run(c, "fmc_import_objects", args)
        assert p["preview"]["skipped_existing"] == ["old"] and p["blast_radius"] == 2
        await run(c, "fmc_import_objects", {**args, "confirm": p["confirm"]})
    assert hosts.calls.last.request.url.params["bulk"] == "true"
    assert [b["name"] for b in json.loads(hosts.calls.last.request.content)] == ["h1"]
    assert json.loads(ports.calls.last.request.content)[0]["port"] == "8443"

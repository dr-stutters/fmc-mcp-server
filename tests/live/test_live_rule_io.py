"""F23: export mcp-test-acp (the seeded objects, docs/live-tests.md), import the rows into a scratch policy,
compare, delete it."""

from typing import Any

import pytest
from fastmcp import Client

pytestmark = pytest.mark.live

SCRATCH = "mcp-test-io-acp"
KEYS = (
    "name",
    "action",
    "enabled",
    "src_networks",
    "dst_networks",
    "src_ports",
    "dst_ports",
    "urls",
    "src_zones",
    "dst_zones",
)


async def call(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await client.call_tool(name, args)
    return r.structured_content


async def apply(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    preview = await call(client, name, args)
    assert preview["status"] == "preview", preview
    done = await call(client, name, {**args, "confirm": preview["confirm"]})
    assert done["status"] == "applied", done
    return done


async def test_export_import_round_trip(client: Client[Any]) -> None:
    out = await call(client, "fmc_export_access_rules", {"policy": "mcp-test-acp"})
    rows = out["results"]
    assert rows and all("name" in r for r in rows)
    csv_out = await call(client, "fmc_export_access_rules", {"policy": "mcp-test-acp", "format": "csv"})
    assert csv_out["csv"].startswith("index,section,category,name,action")
    importable = [r for r in rows if not any(r.get(k) for k in ("applications", "users", "vlan_tags"))]
    found = await call(
        client, "fmc_list_policies", {"kind": "access", "name": SCRATCH, "response_format": "json"}
    )
    if not any(p["name"] == SCRATCH for p in found["results"]):
        await apply(client, "fmc_create_access_policy", {"name": SCRATCH})
    try:
        await apply(client, "fmc_import_access_rules", {"policy": SCRATCH, "rules": importable})
        back = (await call(client, "fmc_export_access_rules", {"policy": SCRATCH}))["results"]
        assert [{k: r.get(k) for k in KEYS} for r in back] == [
            {k: r.get(k) for k in KEYS} for r in importable
        ]
        again = await call(client, "fmc_import_access_rules", {"policy": SCRATCH, "rules": importable[:1]})
        assert again["status"] == "blocked" and "already exists" in " ".join(again["blockers"])
    finally:
        await apply(client, "fmc_delete_policy", {"kind": "access", "policy": SCRATCH})

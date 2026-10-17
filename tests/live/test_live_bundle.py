"""F44: export mcp-test-acp (the seeded objects, docs/live-tests.md) twice, compare, and diff an edited copy
against the live policy. Read only: nothing on FMC changes."""

from typing import Any

import pytest
import yaml
from fastmcp import Client

from fmc_mcp.tools.bundle import dump

pytestmark = pytest.mark.live

EXPORT = {"policy": "mcp-test-acp", "nat_policies": ["mcp-test-nat"]}


async def call(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await client.call_tool(name, args)
    return r.structured_content


def without_stamp(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith("exported_at:"))


async def test_export_is_stable_and_diff_shows_one_rule(client: Client[Any]) -> None:
    first = await call(client, "fmc_export_policy_bundle", EXPORT)
    second = await call(client, "fmc_export_policy_bundle", EXPORT)
    assert first["digest"] == second["digest"], (first["digest"], second["digest"])
    assert without_stamp(first["bundle"]) == without_stamp(second["bundle"])
    assert (
        first["sections"]["access_policy.rules"] >= 4
        and "nat_policies.mcp-test-nat.rules" in first["sections"]
    )

    same = await call(client, "fmc_diff_policy_bundle", {"a": first["bundle"]})
    assert same["identical"] is True, same

    edited = yaml.safe_load(first["bundle"])
    rule = next(r for r in edited["access_policy"]["rules"] if r["name"] == "mcp-test-ssh-admin")
    rule["dst_ports"] = ["tcp/2222"]
    out = await call(client, "fmc_diff_policy_bundle", {"a": dump(edited)})
    assert out["total"] == 1, out
    (ch,) = out["changes"]
    assert ch["key"] == "mcp-test-ssh-admin" and ch["fields"]["dst_ports"]["to"] == ["tcp/22"]

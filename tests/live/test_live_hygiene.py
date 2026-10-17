"""F42: fmc_policy_audit against FMC_LIVE_HYGIENE_POLICY, an access policy seeded with one finding of each
static check (a lab seed script: any-any allow, two mergeable rules, a duplicate host, a rule on an expired
time range, a rule that logs nothing). Read only: nothing on FMC changes."""

from typing import Any

import pytest
from fastmcp import Client

from .live_env import need

pytestmark = pytest.mark.live

STATIC = [
    "shadowed",
    "permissive",
    "no_intrusion",
    "no_logging",
    "disabled",
    "duplicate_objects",
    "expired_time_ranges",
    "consolidation",
]


async def test_audit_finds_each_seeded_check(client: Client[Any]) -> None:
    policy = need("FMC_LIVE_HYGIENE_POLICY")
    out = (
        await client.call_tool("fmc_policy_audit", {"policy": policy, "checks": STATIC})
    ).structured_content
    assert out is not None
    by_check = out["summary"]["by_check"]
    for check in (
        "permissive",
        "no_intrusion",
        "no_logging",
        "duplicate_objects",
        "expired_time_ranges",
        "consolidation",
    ):
        assert by_check.get(check), (check, by_check)
    severities = [f["severity"] for f in out["findings"]]
    assert severities[0] == "high" and severities == sorted(
        severities, key=["high", "medium", "low", "info"].index
    )
    assert all(f["fix"] for f in out["findings"])

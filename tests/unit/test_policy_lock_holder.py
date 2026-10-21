"""The lock holder in an access policy's metadata as FMC 10.0.1 sends it (F76 #171, W6N live-A).

FMC 10.0.1 puts the holder at metadata.lockingStatus.metadata.lockedByUser.name, not lockingStatus.userName as
the spec documents. The previews read the lock list to name the holder instead, and when that list can't be
read (a role without the permission) the API user's own lock blocked its own writes as "locked by another
user". Recorded live: tests/fixtures/policy_locks_fmc10.json.
"""

import copy
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.acp_structure import lock_state, read_locks
from fmc_mcp.client import FmcApp
from fmc_mcp.server import create_server

from .conftest import ACP_ID, CFG, fixture, make_settings

FX = fixture("policy_locks_fmc10")
LOCKED_META = FX["acp_while_locked"]["metadata"]


def test_holder_from_the_live_policy_metadata() -> None:
    assert lock_state({"metadata": LOCKED_META}) == {"status": "LOCKED", "locked_by": "mcp-api-svc"}
    spec = {"lockingStatus": {"status": "LOCKED", "userName": "alice"}}
    assert lock_state({"metadata": spec}) == {"status": "LOCKED", "locked_by": "alice"}  # the spec's form


async def test_live_lock_list_answers(fmc: respx.MockRouter) -> None:
    app = FmcApp(make_settings())
    try:
        fmc.get(f"{CFG}/policy/operational/policylocks").mock(
            return_value=httpx.Response(200, json=FX["locks_while_locked"])
        )
        assert await read_locks(app, None) == [
            {
                "policy": "mcp-w6-child-acp",
                "policy_id": "00000000-0000-0ed3-0000-021475055837",
                "status": "LOCKED",
                "locked_by": "mcp-api-svc",
            }
        ]
        fmc.get(f"{CFG}/policy/operational/policylocks").mock(
            return_value=httpx.Response(200, json=FX["locks_after_unlock"])
        )
        assert await read_locks(app, None) == []
    finally:
        await app.aclose()


async def test_own_lock_is_a_note_even_when_the_lock_list_is_unreadable(lab: respx.MockRouter) -> None:
    acp: dict[str, Any] = copy.deepcopy(fixture("accesspolicies")["items"][0])
    acp["metadata"] = {**acp.get("metadata", {}), "lockingStatus": LOCKED_META["lockingStatus"]}
    lab.get(f"{CFG}/policy/accesspolicies").mock(return_value=httpx.Response(200, json={"items": [acp]}))
    lab.get(f"{CFG}/policy/accesspolicies/{ACP_ID}").mock(return_value=httpx.Response(200, json=acp))
    locks = lab.get(f"{CFG}/policy/operational/policylocks").mock(return_value=httpx.Response(403, json={}))
    args = {"policy": "mcp-test-acp", "name": "mcp-w6-cat-x", "section": "default"}
    settings = make_settings(mcp_enable_writes=True, username="mcp-api-svc")
    async with Client(create_server(settings)) as c:
        out = (await c.call_tool("fmc_create_category", args)).structured_content
    assert out is not None and out["status"] == "preview", out
    assert any("locked by you (mcp-api-svc)" in str(v) for v in out.values())
    assert locks.call_count == 0  # the policy names its holder: no lock-list read
    other = make_settings(mcp_enable_writes=True, username="someone-else")
    async with Client(create_server(other)) as c:
        out = (await c.call_tool("fmc_create_category", args)).structured_content
    assert out is not None and out["status"] == "blocked"
    assert any("is locked by mcp-api-svc" in b for b in out["blockers"])

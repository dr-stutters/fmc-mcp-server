"""F22 change management on the lab FMC. Turns change management ON for a few seconds (as the admin from
.env.admin), opens a ticket, makes an object change inside it, lists the ticket's changes, discards the
ticket and turns change management OFF again. While it is on, writes without a ticket fail for every user,
so the window is kept as short as possible and is always closed in `finally`."""

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest
from dotenv import dotenv_values
from fastmcp import Client

pytestmark = pytest.mark.live

ROOT = Path(__file__).resolve().parents[2]
CM = "/api/fmc_platform/v1/systemconfiguration/changemanagementconfigs"
TICKET = "mcp-test-ticket"


def set_change_management(on: bool) -> None:
    """Switch change management, retrying and checking the result (it must never stay on by accident)."""
    for attempt in range(3):
        try:
            _set_change_management(on)
            return
        except httpx.HTTPError:
            if attempt == 2:
                raise


def _set_change_management(on: bool) -> None:
    env = {**dotenv_values(ROOT / ".env"), **dotenv_values(ROOT / ".env.admin")}
    if not env.get("FMC_ADMIN_USERNAME"):
        pytest.skip("FMC_ADMIN_* not configured (.env.admin)")
    with httpx.Client(base_url=str(env["FMC_URL"]), verify=False, timeout=60) as http:
        r = http.post(
            "/api/fmc_platform/v1/auth/generatetoken",
            auth=(str(env["FMC_ADMIN_USERNAME"]), str(env["FMC_ADMIN_PASSWORD"])),
        )
        h = {"X-auth-access-token": r.headers["X-auth-access-token"]}
        cfg = http.get(CM, headers=h).json()["items"][0]
        body = {"id": cfg["id"], "type": "ChangeManagementSystemConfig", "changeMgmtWorkflowEnabled": on}
        if on:
            body["noOfApprover"] = 1
        http.put(f"{CM}/{cfg['id']}", headers=h, json=body).raise_for_status()
        now = http.get(CM, headers=h).json()["items"][0]
        if bool(now.get("changeMgmtWorkflowEnabled")) != on:
            raise httpx.HTTPError(f"change management is still {now.get('changeMgmtWorkflowEnabled')}")


async def call(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    return (await client.call_tool(name, args)).structured_content


async def apply(client: Client[Any], name: str, args: dict[str, Any]) -> Any:
    preview = await call(client, name, args)
    assert preview["status"] == "preview", preview
    done = await call(client, name, {**args, "confirm": preview["confirm"]})
    assert done["status"] == "applied", done
    return done["result"]


async def test_ticket_flow(client: Client[Any]) -> None:
    off = await call(client, "fmc_change_tickets", {"response_format": "json"})
    assert off["change_management"] == "off"
    set_change_management(True)
    try:
        # a leftover ticket from an interrupted run
        old = await call(client, "fmc_change_tickets", {"response_format": "json"})
        if any(t["name"] == TICKET and t["status"] in ("NEW", "IN_PROGRESS") for t in old.get("tickets") or []):
            await apply(client, "fmc_ticket", {"action": "discard", "name": TICKET})
        opened = await apply(client, "fmc_ticket", {"action": "open", "name": TICKET})
        assert opened["current_ticket"]
        await apply(
            client, "fmc_create_object", {"name": "mcp-test-cm-host", "type": "host", "value": "10.255.9.9"}
        )
        view = await call(client, "fmc_change_tickets", {"ticket": TICKET, "response_format": "json"})
        assert view["change_management"] == "on"
        assert any("mcp-test-cm-host" in str(c) for c in view["changes"]), view
        out = await apply(client, "fmc_ticket", {"action": "discard", "name": TICKET})
        assert out["current_ticket"] is None and out["ticket"]["status"] == "DISCARD"
    finally:
        set_change_management(False)
        cur = await call(client, "fmc_change_tickets", {"response_format": "json"})
        if cur.get("current_ticket"):
            await apply(client, "fmc_ticket", {"action": "release"})
    # FMC reverts a discarded ticket's changes in the background
    for _ in range(12):
        gone = await call(client, "fmc_find_object", {"value": "10.255.9.9", "response_format": "json"})
        if not any(r.get("name") == "mcp-test-cm-host" for r in gone.get("results", [])):
            break
        await asyncio.sleep(10)
    else:
        raise AssertionError(f"the discarded ticket's object is still there: {gone}")

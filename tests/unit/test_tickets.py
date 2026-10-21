"""F22 change-management tickets: open/submit and the ticket-id header on later requests."""

import json
from typing import Any

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server

from .conftest import CFG, items, make_settings

TICKETS = f"{CFG}/changemanagement/tickets"
T = {"id": "t-1", "name": "CHG001", "status": "NEW", "type": "Ticket"}


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


async def test_open_ticket_is_sent_with_later_changes(fmc: respx.MockRouter) -> None:
    listing = fmc.get(TICKETS).mock(return_value=items([]))
    fmc.post(TICKETS).mock(return_value=httpx.Response(201, json=T))
    fmc.put(f"{TICKETS}/t-1").mock(
        side_effect=lambda req: httpx.Response(200, json={**T, **json.loads(req.content)})
    )
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/networkaddresses").mock(return_value=items([]))
    fmc.get(f"{CFG}/object/ranges").mock(return_value=items([]))
    post_host = fmc.post(f"{CFG}/object/hosts").mock(
        return_value=httpx.Response(201, json={"id": "h", "name": "h1", "type": "Host", "value": "10.0.0.1"})
    )
    async with Client(create_server(make_settings(mcp_enable_writes=True))) as c:
        args = {"action": "open", "name": "CHG001"}
        preview = await run(c, "fmc_ticket", args)
        done = await run(c, "fmc_ticket", {**args, "confirm": preview["confirm"]})
        assert done["result"]["current_ticket"] == "t-1"
        assert done["result"]["ticket"]["status"] == "IN_PROGRESS"
        obj = {"name": "h1", "type": "host", "value": "10.0.0.1"}
        p = await run(c, "fmc_create_object", obj)
        await run(c, "fmc_create_object", {**obj, "confirm": p["confirm"]})
        assert post_host.calls.last.request.headers["ticket-id"] == "t-1"
        listing.mock(return_value=items([{**T, "status": "IN_PROGRESS"}]))
        sub = {"action": "submit", "name": "CHG001", "description": "please approve"}
        p = await run(c, "fmc_ticket", sub)
        out = await run(c, "fmc_ticket", {**sub, "confirm": p["confirm"]})
    assert out["result"]["ticket"]["status"] == "PENDING_APPROVAL" and out["result"]["current_ticket"] is None


async def test_release_works_without_fmc_and_submit_needs_open_ticket(fmc: respx.MockRouter) -> None:
    fmc.get(TICKETS).mock(return_value=items([{**T, "status": "APPROVED"}]))
    async with Client(create_server(make_settings(mcp_enable_writes=True, ticket="gone-1"))) as c:
        out = await run(c, "fmc_ticket", {"action": "submit", "name": "CHG001"})
        assert out["status"] == "blocked" and "only open tickets" in out["blockers"][0]
        p = await run(c, "fmc_ticket", {"action": "release"})
        done = await run(c, "fmc_ticket", {"action": "release", "confirm": p["confirm"]})
        assert done["result"]["current_ticket"] is None


async def test_ticket_changes_carry_the_cut_note(fmc: respx.MockRouter) -> None:
    """#273: a ticket's changes are pending-change rows (capped the same way): say what was cut."""
    long = "x" * 5000
    fmc.get(TICKETS).mock(return_value=items([{**T, "status": "IN_PROGRESS"}]))
    fmc.get(f"{TICKETS}/t-1/previewchanges").mock(
        return_value=items(
            [
                {
                    "entityName": "mcp-w6-nap",
                    "entityType": "Snort3NapPolicy",
                    "action": "UPDATE",
                    "valueUpdated": [{"fieldName": "inspectorData", "oldValue": long, "newValue": "short"}],
                },
                {"entityName": "h", "entityType": "Host", "action": "ADD"},
            ]
        )
    )
    fmc.get(f"{TICKETS}/t-1/validationresults").mock(return_value=items([]))
    async with Client(create_server(make_settings())) as c:
        out = await run(c, "fmc_change_tickets", {"ticket": "CHG001", "response_format": "json"})
    (line,) = out["changes"][0]["changes"]
    assert line.endswith(" -> short")  # the new value survives a long old one
    assert "each side of 'old -> new' at 200 characters" in out["changes_note"]

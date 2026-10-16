"""Change-management tickets (F22): FMC 7.6+ can require every change to be made in a ticket that is
submitted for approval before deployment. When a ticket is open in this server, every request carries
it in the `ticket-id` header."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    AuthError,
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    object_result,
)
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain
from fmc_mcp.tools.deploy import pending_row

TICKETS = "changemanagement/tickets"


def ticket_row(t: dict[str, Any]) -> dict[str, Any]:
    meta = t.get("metadata") or {}
    row = {
        "name": t.get("name"),
        "status": t.get("status"),
        "assigned_to": t.get("assignedTo"),
        "creator": meta.get("creator"),
        "updated": meta.get("lastUpdateTime"),
        "id": t.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


ACTIVE = ("NEW", "IN_PROGRESS", "ON_HOLD")


async def find_ticket(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    """A ticket by id, or by name preferring the one still being worked on (names can repeat)."""
    page = await app.all(await app.config_path(TICKETS, domain))
    hits = [t for t in page.items if t.get("id") == ref or str(t.get("name", "")).lower() == ref.lower()]
    if not hits:
        raise NotFound(f"No change-management ticket {ref!r} for this user (fmc_change_tickets).", 404)
    active = [t for t in hits if t.get("status") in ACTIVE]
    if len(active) > 1:
        raise InvalidRequest(
            f"Several open tickets are named {ref!r}; use the ticket id (fmc_change_tickets)."
        )
    return dict(active[0] if active else hits[0])


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Change-management tickets")
    async def fmc_change_tickets(
        ctx: Context,
        ticket: Annotated[
            str | None,
            Field(description="Ticket name or id: show its pending changes and validation results"),
        ] = None,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """FMC change management (7.6+): this API user's tickets with their status, and which ticket this
        server currently sends with every change. With `ticket`, the changes in it and FMC's validation
        results. When change management is on, open a ticket with fmc_ticket(action='open') before
        making changes; approval happens in the FMC UI."""
        app: FmcApp = get_client(ctx)
        path = await app.config_path(TICKETS, domain)
        try:
            page = await app.all(path)
        except AuthError as e:
            raise AuthError(
                f"{e} Tickets need the change-management permissions in the API user's role, and change "
                "management must be enabled (Administration > Configuration > Change Management).",
                e.status_code,
            ) from e
        except UpstreamError as e:
            if "not enabled" in str(e).lower():
                return object_result(
                    {"change_management": "off", "current_ticket": app.ticket_id, "tickets": []},
                    fmt=response_format,
                )
            raise
        out: dict[str, Any] = {
            "change_management": "on",
            "current_ticket": app.ticket_id,
            "tickets": [ticket_row(t) for t in page.items],
        }
        if ticket:
            t = await find_ticket(app, ticket, domain)
            changes = await app.all(f"{path}/{t['id']}/previewchanges", cap=2000)
            checks = await app.all(f"{path}/{t['id']}/validationresults", cap=500)
            out["ticket"] = ticket_row(t)
            out["changes"] = [pending_row(c) for c in changes.items]
            out["validation"] = [
                {"level": v.get("level"), "message": v.get("message") or v.get("description")}
                for v in checks.items
            ]
        return object_result(out, fmt=response_format)

    @reg.write(title="Open, submit or discard a ticket")
    async def fmc_ticket(
        ctx: Context,
        action: Annotated[
            Literal["open", "submit", "discard", "release"],
            Field(
                description="open: create (or reopen) a ticket and send it with every change from now on, "
                "for every caller of this server; submit: send it for approval; discard: drop it and revert "
                "its changes; release: stop sending the current ticket (no FMC change)"
            ),
        ],
        name: Annotated[
            str | None,
            Field(min_length=1, max_length=64, description="Ticket name or id (not needed for release)"),
        ] = None,
        description: Annotated[str | None, Field(description="Ticket description / submit comment")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Work with FMC change-management tickets: open a ticket (every later change from this server
        carries it as ticket-id, for all callers), submit it for approval, discard it, or release it from
        this server. Approval happens in the FMC UI."""
        app: FmcApp = get_client(ctx)
        path = await app.config_path(TICKETS, domain)
        if action == "release":
            rel_blockers: list[str] = [] if app.ticket_id else ["No ticket is being sent."]
            if name and app.ticket_id and name != app.ticket_id:
                try:
                    if (await find_ticket(app, name, domain))["id"] != app.ticket_id:
                        rel_blockers.append(
                            f"{name!r} is not the ticket this server sends ({app.ticket_id})."
                        )
                except UpstreamError:
                    pass  # FMC can't tell (ticket gone, change management off): release anyway

            def release() -> Any:
                app.ticket_id = None
                return {"current_ticket": None}

            async def do_release() -> Any:
                return release()

            return await fmc_preview(
                ctx,
                tool="fmc_ticket",
                args={"action": action, "name": name, "description": description, "domain": domain},
                confirm=confirm,
                plan=Plan(
                    f"Stop sending ticket {app.ticket_id}",
                    details={"current_ticket": app.ticket_id},
                    fingerprint=app.ticket_id,
                    blockers=rel_blockers,
                    side_effects=[
                        "Later changes carry no ticket (FMC refuses them while change management is on)."
                    ],
                ),
                apply=do_release,
            )
        if not name:
            raise InvalidRequest(f"name is required to {action} a ticket.")
        try:
            current: dict[str, Any] | None = await find_ticket(app, name, domain)
        except NotFound:
            current = None
        status = (current or {}).get("status")
        blockers: list[str] = []
        if action != "open" and current is None:
            blockers.append(f"No ticket {name!r}.")
        if action == "open" and current is not None and status not in ACTIVE:
            blockers.append(f"Ticket {name!r} is {status}; open a new one with another name.")
        if action == "submit" and current is not None and status not in ACTIVE:
            blockers.append(f"Ticket {name!r} is {status}; only open tickets can be submitted.")
        if action == "discard" and current is not None and status in ("DISCARD", "APPROVED"):
            blockers.append(f"Ticket {name!r} is already {status}.")
        effects = {
            "open": ["Every later change made through this server, by any caller, carries this ticket."],
            "submit": ["The ticket goes to the approvers; its changes can be deployed once approved."],
            "discard": ["The ticket's changes are reverted (FMC does it in the background)."],
        }[action]
        if action == "open" and app.ticket_id and app.ticket_id != (current or {}).get("id"):
            effects.append(f"Switches this server from ticket {app.ticket_id} to {name!r}.")

        async def apply() -> Any:
            nonlocal current
            sending, app.ticket_id = app.ticket_id, None  # ticket calls themselves carry no ticket-id
            try:
                if action == "open":
                    if current is None:
                        current = await app.api.post(
                            path,
                            {
                                "name": name,
                                "description": description or name,
                                "status": "NEW",
                                "type": "Ticket",
                            },
                        )
                    if current is None:
                        raise InvalidRequest("FMC returned no ticket.")
                    if current.get("status") != "IN_PROGRESS":
                        current = await app.api.put(
                            f"{path}/{current['id']}",
                            {
                                "id": current["id"],
                                "name": current["name"],
                                "type": "Ticket",
                                "status": "IN_PROGRESS",
                            },
                        )
                    sending = current["id"]
                    return {"ticket": ticket_row(current), "current_ticket": sending}
                if current is None:
                    raise InvalidRequest(f"No ticket {name!r}.")
                new_status = "PENDING_APPROVAL" if action == "submit" else "DISCARD"
                body = {"id": current["id"], "name": current["name"], "type": "Ticket", "status": new_status}
                if description:
                    body["stateChangeDescription"] = description
                res = await app.api.put(f"{path}/{current['id']}", body)
                if sending == current["id"]:
                    sending = None
                return {
                    "ticket": ticket_row(res if isinstance(res, dict) else body),
                    "current_ticket": sending,
                }
            finally:
                app.ticket_id = sending

        return await fmc_preview(
            ctx,
            tool="fmc_ticket",
            args={"action": action, "name": name, "description": description, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Ticket {name!r}: {action}",
                details={"ticket": ticket_row(current) if current else None, "current_ticket": app.ticket_id},
                fingerprint={"status": status, "sending": app.ticket_id},
                blockers=blockers,
                side_effects=effects,
            ),
            apply=apply,
        )

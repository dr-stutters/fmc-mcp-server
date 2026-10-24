"""F90: a write's `change_ref` goes into the preview, the FMC change ticket (ticket-id header) and the rule's
comment history (newComments)."""

import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp import change_ref
from fmc_mcp.server import create_server

from .conftest import ACP_ID, CFG, items, make_settings

TICKETS = f"{CFG}/changemanagement/tickets"
RULES = f"{CFG}/policy/accesspolicies/{ACP_ID}/accessrules"
OPEN = {"id": "t-7", "name": "CHG777", "status": "IN_PROGRESS", "type": "Ticket"}
OFF = {"error": {"messages": [{"description": "Change Management is not enabled."}], "severity": "ERROR"}}
RULE = {"policy": "mcp-test-acp", "name": "mcp-f90-rule", "action": "ALLOW", "enabled": False}
HOST = {"name": "h1", "type": "host", "value": "192.0.2.10"}


def server(**kw: Any) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, **kw))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def host_mocks(fmc: respx.MockRouter) -> respx.Route:
    for name in ("hosts", "networkaddresses", "ranges"):
        fmc.get(f"{CFG}/object/{name}").mock(return_value=items([]))
    return fmc.post(f"{CFG}/object/hosts").mock(
        return_value=httpx.Response(
            201, json={"id": "h", "name": "h1", "type": "Host", "value": HOST["value"]}
        )
    )


def rule_post(lab: respx.MockRouter) -> respx.Route:
    return lab.post(RULES).mock(
        side_effect=lambda req: httpx.Response(201, json={**json.loads(req.content), "id": "r-new"})
    )


async def test_rule_create_goes_into_the_named_ticket_with_a_comment(lab: respx.MockRouter) -> None:
    lab.get(TICKETS).mock(return_value=items([{**OPEN, "id": "t-old", "status": "APPROVED"}, OPEN]))
    post = rule_post(lab)
    post_host = host_mocks(lab)
    args = {**RULE, "comment": "allow web", "change_ref": "chg777"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_access_rule", args)
        assert preview["preview"]["change_ref"] == "chg777"
        assert preview["preview"]["change_ticket"]["id"] == "t-7"  # the open one, name case-insensitive
        done = await run(c, "fmc_create_access_rule", {**args, "confirm": preview["confirm"]})
        sent = post.calls.last.request
        assert sent.headers["ticket-id"] == "t-7"
        assert json.loads(sent.content)["newComments"] == ["[chg777] allow web"]
        assert done["result"]["change_ref"] == "chg777"
        # the ticket is this call's only: the next write without change_ref carries none
        p = await run(c, "fmc_create_object", HOST)
        await run(c, "fmc_create_object", {**HOST, "confirm": p["confirm"]})
        assert "ticket-id" not in post_host.calls.last.request.headers


async def test_change_ref_alone_becomes_the_comment_and_overrides_the_server_ticket(
    lab: respx.MockRouter,
) -> None:
    lab.get(TICKETS).mock(return_value=items([OPEN]))
    post = rule_post(lab)
    args = {**RULE, "change_ref": "CHG777"}
    async with Client(server(ticket="t-server")) as c:
        preview = await run(c, "fmc_create_access_rule", args)
        assert any("not the server's current ticket (t-server)" in s for s in preview["side_effects"])
        await run(c, "fmc_create_access_rule", {**args, "confirm": preview["confirm"]})
    sent = post.calls.last.request
    assert sent.headers["ticket-id"] == "t-7"
    assert json.loads(sent.content)["newComments"] == ["Change CHG777"]


async def test_no_open_ticket_of_that_name(fmc: respx.MockRouter) -> None:
    fmc.get(TICKETS).mock(return_value=items([{**OPEN, "status": "APPROVED"}]))
    post_host = host_mocks(fmc)
    args = {**HOST, "change_ref": "CHG777"}
    async with Client(server()) as c:
        blocked = await run(c, "fmc_create_object", args)
        assert blocked["status"] == "blocked"
        assert "fmc_ticket(action='open', name='CHG777')" in blocked["blockers"][0]
    async with Client(server(ticket="t-server")) as c:  # the server's own ticket takes it instead
        preview = await run(c, "fmc_create_object", args)
        assert any("server's current ticket (t-server)" in s for s in preview["side_effects"])
        await run(c, "fmc_create_object", {**args, "confirm": preview["confirm"]})
    assert post_host.calls.last.request.headers["ticket-id"] == "t-server"


async def test_change_management_off_still_shows_and_records_it(fmc: respx.MockRouter) -> None:
    fmc.get(TICKETS).mock(return_value=httpx.Response(400, json=OFF))
    post_host = host_mocks(fmc)
    args = {**HOST, "change_ref": "CHG777"}
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_object", args)
        assert preview["preview"]["change_ref"] == "CHG777"
        assert "change management is off" in preview["preview"]["change_ticket"]
        done = await run(c, "fmc_create_object", {**args, "confirm": preview["confirm"]})
    assert done["result"]["change_ref"] == "CHG777"
    assert "ticket-id" not in post_host.calls.last.request.headers


async def test_confirm_with_another_change_ref_is_refused(fmc: respx.MockRouter) -> None:
    fmc.get(TICKETS).mock(return_value=httpx.Response(400, json=OFF))
    post_host = host_mocks(fmc)
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_object", {**HOST, "change_ref": "CHG777"})
        with pytest.raises(ToolError):
            await run(c, "fmc_create_object", {**HOST, "change_ref": "CHG778", "confirm": preview["confirm"]})
        with pytest.raises(ToolError):
            await run(c, "fmc_create_object", {**HOST, "confirm": preview["confirm"]})
    assert not post_host.calls


async def test_without_change_ref_nothing_changes(fmc: respx.MockRouter) -> None:
    tickets = fmc.get(TICKETS).mock(return_value=items([OPEN]))
    host_mocks(fmc)
    async with Client(server()) as c:
        preview = await run(c, "fmc_create_object", HOST)
    assert "change_ref" not in preview["preview"] and not tickets.calls


@pytest.mark.parametrize("toolsets", [None, "policy"])
async def test_every_write_tool_takes_change_ref(fmc: respx.MockRouter, toolsets: str | None) -> None:
    mcp = server(mcp_enable_dangerous=True, **({"toolsets": toolsets} if toolsets else {}))
    async with Client(mcp) as c:
        tools = await c.list_tools()
    tiers: dict[str, Any] = mcp._stutters_tiers  # type: ignore[attr-defined]
    has = {t.name for t in tools if "change_ref" in (t.input_schema.get("properties") or {})}
    writes = {t.name for t in tools if tiers.get(t.name) in ("write", "dangerous")}
    # fmc_api_call is core's own tool: it gets change_ref with core C33
    assert writes and has == writes - change_ref.SKIP - {"fmc_api_call"}
    assert "fmc_create_access_rule" in has and "fmc_ticket" not in has


def test_comment_text() -> None:
    token = change_ref._current.set("CHG1")
    try:
        assert change_ref.comment(None) == "Change CHG1"
        assert change_ref.comment("why") == "[CHG1] why"
        assert change_ref.comment("[CHG1] why") == "[CHG1] why"
    finally:
        change_ref._current.reset(token)
    assert change_ref.comment("why") == "why" and change_ref.comment(None) is None

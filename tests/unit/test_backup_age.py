"""C73 backup-age rail (stutters-mcp-core#149): FMC's hook reads its own newest backup (backup/files/manager,
the recorded FMC 10.0.1 shape) and dangerous previews show the age, blocked when too old or unknown."""

import copy
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client

import fmc_mcp._core.backup_rail
from fmc_mcp.server import create_server
from fmc_mcp.tools.backup_age import newest_backup

from .conftest import CFG, fixture, items, make_settings

REC = fixture("compliance_fmc10")
BACKUP = REC["backup_manager"]  # creationDate 2026-10-19 02:02:50 (UTC)
MANAGER = f"{CFG}/backup/files/manager"
DEV_ID = "11111111-0000-0000-0000-000000000001"
PENDING = {
    "name": "ftd1",
    "version": "7",
    "canBeDeployed": True,
    "device": {"id": DEV_ID, "name": "ftd1", "type": "Device"},
}
FRESH = datetime(2026, 10, 19, 12, 2, 50, tzinfo=UTC)  # 10 h after the backup
OLD = datetime(2026, 10, 22, 2, 2, 50, tzinfo=UTC)  # 3 days after it


def server(**kw: Any) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, **kw))


async def deploy_preview(fmc: respx.MockRouter, **kw: Any) -> dict[str, Any]:
    fmc.get(f"{CFG}/deployment/deployabledevices").mock(return_value=items([PENDING]))
    async with Client(server(**kw)) as c:
        r = await c.call_tool("fmc_deploy", {})
    out: dict[str, Any] = r.structured_content or json.loads(r.content[0].text)  # type: ignore[union-attr]
    return out


def at(monkeypatch: pytest.MonkeyPatch, now: datetime) -> None:
    monkeypatch.setattr(fmc_mcp._core.backup_rail, "_now", lambda: now)


def backup_block(out: dict[str, Any]) -> dict[str, Any] | None:
    block = out.get("backup") or (out.get("preview") or {}).get("backup")
    return block if isinstance(block, dict) else None


async def test_fresh_backup_shows_age_and_allows(
    fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    at(monkeypatch, FRESH)
    route = fmc.get(MANAGER).mock(return_value=httpx.Response(200, json=BACKUP))
    out = await deploy_preview(fmc, mcp_require_backup_hours=24)
    # no paging parameters: FMC 10.0.1 answers them on this path with 400 'Invalid query parameter for
    # the GETBYID operation' (live read 2026-10-29, #380)
    assert route.called and not route.calls.last.request.url.query
    block = backup_block(out)
    assert block is not None, out
    assert block["ok"] is True and block["age"] == "10h 0m" and block["age_hours"] == 10.0
    assert block["source"] == "FMC backups" and block["max_age_hours"] == 24
    assert block["detail"] == BACKUP["fileName"] and block["taken_at"] == "2026-10-19T02:02:50+00:00"
    assert out["status"] != "blocked" and out.get("confirm"), out
    assert "MCP_REQUIRE_BACKUP_HOURS" not in json.dumps(out.get("blockers") or [])


async def test_three_day_old_backup_blocks(fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, OLD)
    fmc.get(MANAGER).mock(return_value=httpx.Response(200, json=BACKUP))
    out = await deploy_preview(fmc, mcp_require_backup_hours=24)
    block = backup_block(out)
    assert block is not None and block["ok"] is False and block["age"] == "3d 0h"
    assert out["status"] == "blocked"
    assert "3d 0h old, more than the 24 h MCP_REQUIRE_BACKUP_HOURS" in json.dumps(out["blockers"])


async def test_newest_of_a_list_wins(fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, OLD)
    newer = {**copy.deepcopy(BACKUP), "fileName": "newer.tar", "creationDate": "2026-10-21 20:02:50"}
    fmc.get(MANAGER).mock(return_value=items([BACKUP, newer]))
    out = await deploy_preview(fmc, mcp_require_backup_hours=24)
    block = backup_block(out)
    assert (
        block is not None
        and block["ok"] is True
        and block["detail"] == "newer.tar"
        and block["age"] == "6h 0m"
    )


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(400, json={"error": {"messages": [{"description": "File not found."}]}}),
        items([]),
    ],
    ids=["file-not-found", "empty-list"],
)
async def test_no_backup_blocks(
    fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch, response: httpx.Response
) -> None:
    at(monkeypatch, FRESH)
    fmc.get(MANAGER).mock(return_value=response)
    out = await deploy_preview(fmc, mcp_require_backup_hours=24)
    block = backup_block(out)
    assert block is not None and block["age"] == "unknown" and block["ok"] is False
    assert out["status"] == "blocked"
    assert "FMC backups: no backup found" in json.dumps(out["blockers"])


async def test_forbidden_backup_read_blocks(fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, FRESH)
    fmc.get(MANAGER).mock(return_value=httpx.Response(403, json={"error": {"messages": []}}))
    out = await deploy_preview(fmc, mcp_require_backup_hours=24)
    block = backup_block(out)
    assert block is not None and block["age"] == "unknown"
    assert out["status"] == "blocked" and "backup-age check failed" in json.dumps(out["blockers"])


async def test_rail_unset_has_no_backup_section(fmc: respx.MockRouter) -> None:
    route = fmc.get(MANAGER).mock(return_value=httpx.Response(200, json=BACKUP))
    out = await deploy_preview(fmc)
    assert backup_block(out) is None and "backup" not in json.dumps(out.get("blockers") or [])
    assert not route.called


async def test_write_tier_is_not_covered_by_default(
    fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    at(monkeypatch, OLD)
    route = fmc.get(MANAGER).mock(return_value=httpx.Response(200, json=BACKUP))
    fmc.get(f"{CFG}/object/hosts").mock(return_value=items([]))
    async with Client(server(mcp_require_backup_hours=24)) as c:
        r = await c.call_tool("fmc_create_object", {"type": "host", "name": "mcp-h1", "value": "192.0.2.10"})
    out: dict[str, Any] = r.structured_content or json.loads(r.content[0].text)  # type: ignore[union-attr]
    assert backup_block(out) is None and not route.called


async def test_status_reports_the_rail(fmc: respx.MockRouter) -> None:
    async with Client(server(mcp_require_backup_hours=24)) as c:
        status = (await c.call_tool("fmc_status", {})).structured_content
    assert status is not None
    rail = status["server"]["rails"]["backup"]
    assert rail["required"] is True and rail["max_age_hours"] == 24 and rail["hook"] is True


def test_newest_backup_skips_undated_rows() -> None:
    rows = [{"fileName": "a"}, {"fileName": "b", "creationDate": "2026-10-01 00:00:00"}]
    newest = newest_backup(rows)
    assert newest is not None and newest[1]["fileName"] == "b"
    assert newest_backup([{"fileName": "a"}]) is None

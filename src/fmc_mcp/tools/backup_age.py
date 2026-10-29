"""FMC's hook for core's backup-age rail (C73, stutters-mcp-core#149).

With MCP_REQUIRE_BACKUP_HOURS set, every dangerous preview (fmc_deploy, fmc_rollback_deployment, ...) shows
how old FMC's newest backup of itself is, and is blocked when it is older than the limit or can't be told.
The age comes from the read fmc_list_backups(device='manager') makes: `backup/files/manager`, newest by
creationDate. FMC 10.0.1 answers that path with one backup object (the newest) rather than a list, and with
400 'File not found.' when FMC has no backup; both shapes are read here. Any other failure (a 403 for an
API user without the backup permission, FMC down) propagates, and core turns it into "age unknown", which
blocks. This module registers no tool.
"""

from typing import Any

from fastmcp import Context

from fmc_mcp._core import ToolRegistrar, ValidationFailed, get_client
from fmc_mcp._core.backup_rail import BackupAge, register_backup_age
from fmc_mcp.client import FmcApp
from fmc_mcp.tools.admin import BACKUP_FILES
from fmc_mcp.tools.hardening import backup_rows, backup_time

SOURCE = "FMC backups"


def newest_backup(rows: list[dict[str, Any]]) -> tuple[float, dict[str, Any]] | None:
    """The newest backup with a readable creationDate, as (epoch seconds, row)."""
    dated = [(t, b) for b in rows if (t := backup_time(b)) is not None]
    return max(dated, key=lambda tb: tb[0], default=None)


async def fmc_backup_age(ctx: Context) -> BackupAge:
    """How old FMC's newest backup of itself is."""
    app: FmcApp = get_client(ctx)
    try:
        data = await app.api.get(await app.config_path(f"{BACKUP_FILES}/manager"))
    except ValidationFailed as e:
        if "file not found" in str(e).lower():
            return BackupAge(None, SOURCE, "no backup found")
        raise
    rows = backup_rows(data)
    newest = newest_backup(rows)
    if newest is None:
        return BackupAge(None, SOURCE, "no backup found" if not rows else "no backup with a readable date")
    when, row = newest
    return BackupAge.from_time(when, SOURCE, str(row.get("fileName") or "") or None)


def register(reg: ToolRegistrar) -> None:
    register_backup_age(reg, fmc_backup_age)

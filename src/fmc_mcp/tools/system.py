"""System tools: domains."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field
from stutters_mcp_core import ResponseFormat, ToolRegistrar, get_client, list_result
from stutters_mcp_core.http import page_of

from fmc_mcp.client import FmcApp


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="List FMC domains")
    async def fmc_list_domains(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="Filter: domain name contains (case-insensitive)")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        offset: Annotated[int, Field(ge=0)] = 0,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the FMC domains this API account can see (name like 'Global/Child' and UUID), marking
        the default one. Pass a name or UUID from here as `domain` to other tools on multi-domain FMCs."""
        app: FmcApp = get_client(ctx)
        default = await app.domain_uuid(None)
        data = await app.api.get("/api/fmc_platform/v1/info/domain", {"limit": 1000, "expanded": "true"})
        rows = [
            {
                "name": d.get("name"),
                "uuid": d.get("uuid"),
                "default": d.get("uuid") == default,
                "parent_uuid": d.get("parentUUID") if d.get("parentUUID") != d.get("uuid") else None,
            }
            for d in (data or {}).get("items", [])
        ]
        if name:
            rows = [r for r in rows if name.lower() in str(r["name"]).lower()]
        return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)

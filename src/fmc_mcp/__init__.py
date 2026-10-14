"""MCP server for Cisco Secure Firewall Management Center (FMC)."""

from stutters_mcp_core import run_cli

from fmc_mcp.config import Settings
from fmc_mcp.server import SPEC, create_server

__all__ = ["SPEC", "Settings", "create_server", "main"]


def main() -> None:
    run_cli(SPEC, Settings, create_server)

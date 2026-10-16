"""MCP server for Cisco Secure Firewall Management Center (FMC)."""

try:
    from fmc_mcp._core import run_cli
except ModuleNotFoundError as e:  # a source tree or git checkout without the bundled core
    if e.name != "fmc_mcp._core":
        raise
    raise ModuleNotFoundError(
        "fmc_mcp._core is missing: this build doesn't bundle stutters-mcp-core (ADR-005). Install a release "
        "wheel, or run `python scripts/bundle_core.py vendor` in a clone first.",
        name=e.name,
    ) from None
from fmc_mcp.config import Settings
from fmc_mcp.preflight import preflight
from fmc_mcp.server import SPEC, create_server

__all__ = ["SPEC", "Settings", "create_server", "main"]


def main() -> None:
    run_cli(SPEC, Settings, create_server, preflight=preflight)

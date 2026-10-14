"""Server definition: SPEC, instructions and create_server()."""

from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from stutters_mcp_core import ServerSpec, build_server
from stutters_mcp_core.spec import SpecSource

from fmc_mcp.client import SPEC_PATH, FmcApp
from fmc_mcp.config import Settings
from fmc_mcp.tools import (
    analysis,
    dangerous,
    deploy,
    devices,
    object_writes,
    objects,
    policies,
    policy_writes,
    system,
)

INSTRUCTIONS = """
Tools for Cisco Secure Firewall Management Center (FMC), which manages Firewall Threat Defense (FTD)
devices. Object model: domains contain devices (optionally in HA pairs or clusters), policies (access
control with ordered rules in Mandatory/Default sections, NAT, prefilter, intrusion, file, platform
settings) and reusable objects (networks, hosts, ranges, ports, URLs, groups, security zones,
interface groups). Policies are assigned to devices and pushed with a deployment.

Start with fmc_status (version, domains, API user). Every tool accepts names or UUIDs, and a
`domain` (name or UUID) where FMC has several; it defaults to FMC_DOMAIN or the login's domain.

Gotchas: FMC allows about 120 API requests per minute, so prefer the aggregate tools over many small
calls. Changes only reach devices after a deployment. For fmc_api_call, substitute {domainUUID} in
spec paths with the domain UUID from fmc_status.
"""

SPEC = ServerSpec(
    name="fmc-mcp-server",
    prefix="fmc",
    product="Cisco Secure Firewall Management Center",
    env_prefix="FMC_",
    instructions=INSTRUCTIONS,
)


async def _load_spec(app: FmcApp) -> dict[str, Any]:
    # The Swagger 2.0 document is ~10 MB; the core indexes it once and caches the index on disk.
    doc: dict[str, Any] = await app.api.get(SPEC_PATH, timeout=180)
    return doc


async def _spec_version(app: FmcApp) -> str:
    return await app.server_version()


def spec_sources(app: FmcApp) -> list[SpecSource]:
    return [
        SpecSource(
            "fmc",
            _load_spec,
            client=lambda a: a.api,
            version=_spec_version,
            description="FMC REST API (fmc_config, fmc_platform, fmc_tid, fmc_troubleshoot)",
        )
    ]


def create_server(
    settings: Settings,
    *,
    auth: AuthProvider | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastMCP[Any]:
    return build_server(
        SPEC,
        settings,
        client_factory=lambda s: FmcApp(s, transport=transport),
        register=[
            system.register,
            devices.register,
            policies.register,
            objects.register,
            analysis.register,
            deploy.register,
            object_writes.register,
            policy_writes.register,
            dangerous.register,
        ],
        status=FmcApp.status,
        spec_sources=spec_sources,
        auth=auth,
    )

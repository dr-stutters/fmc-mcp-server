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
    activity,
    admin,
    analysis,
    containment,
    dangerous,
    decryption,
    deploy,
    device_config,
    devices,
    dynamic_objects,
    ha,
    intrusion,
    object_import,
    object_writes,
    objects,
    platform_access,
    platform_settings,
    policies,
    policy_writes,
    prefilter,
    prompts,
    routing,
    rule_io,
    security_intel,
    system,
    tickets,
    troubleshoot,
    vpn,
)

INSTRUCTIONS = """
Tools for Cisco Secure Firewall Management Center (FMC), which manages Firewall Threat Defense (FTD)
devices. Object model: domains contain devices (optionally in HA pairs or clusters), policies (access
control with ordered rules in Mandatory/Default sections, NAT, prefilter, intrusion, file, platform
settings) and reusable objects (networks, hosts, ranges, ports, URLs, groups, security zones,
interface groups). Policies are assigned to devices and pushed with a deployment.

Start with fmc_status (version, domains, API user). Every tool accepts names or UUIDs, and a
`domain` (name or UUID) where FMC has several; it defaults to FMC_DOMAIN or the login's domain.

Workflows:
- Onboard an FTD: fmc_register_device (waits for the initial deployment) -> fmc_update_interface
  (logical name, zone, IP) -> fmc_create_static_route -> fmc_assign_policy (NAT, platform settings)
  -> fmc_deploy -> verify with fmc_run_show_command ('show route', 'show interface ip brief').
- Change safely: make the change -> fmc_pending_changes (what the next deploy pushes) -> fmc_deploy
  -> fmc_run_show_command / fmc_list_deployments; undo a bad deployment with fmc_rollback_deployment.
- "Why is this traffic blocked?": fmc_packet_tracer (live verdict, drop reason and matching rule on
  the device) + fmc_rule_lookup (offline walk of the policy) + fmc_get_hit_counts (is the rule hit?).
  The fmc_why_blocked prompt walks these steps in order.
- Send FTD logs to the customer's syslog/SIEM: fmc_get_platform_settings -> fmc_configure_syslog
  (servers, level, facility, RFC 5424) -> fmc_assign_policy(kind='platform_settings') -> fmc_deploy;
  fmc_set_access_logging sends connection/intrusion events there too.
- Dynamic routing: fmc_get_routing (BGP, OSPF, ECMP, PBR, VRFs) -> fmc_configure_bgp /
  fmc_configure_ospf / fmc_create_vrf -> fmc_deploy -> fmc_run_show_command('show route').
- Block a host fast: map its IP into a dynamic object that a BLOCK rule references
  (fmc_map_dynamic_object); mapping changes need no deployment, only the rule does (once).
  fmc_contain_host / fmc_release_host do this for one host with the quarantine object (and propose
  the block rules if they are missing). Blocking IPs/URLs policy-wide with logging (needs a deploy):
  fmc_si_block (Security Intelligence); fmc_get_security_intelligence shows the lists.
- Tune intrusion prevention: fmc_find_intrusion_rules (gid:sid or text) -> fmc_get_intrusion_policy ->
  fmc_set_intrusion_rule_state in a custom policy (fmc_create_intrusion_policy on top of a system one;
  fmc_update_access_rule intrusion_policy=... puts it on an ALLOW rule) -> fmc_deploy. Custom Snort 3
  rules: fmc_create_intrusion_rule.
- Health: fmc_list_devices, fmc_device_health, fmc_list_vpn_tunnels; "what changed or broke in the
  last hour?": fmc_recent_activity (health alerts + audit + deployments), fmc_list_health_alerts.
- Day-2 admin: fmc_upgrade_status (versions), fmc_list_backups / fmc_backup_devices,
  fmc_get_health_policy / fmc_update_health_policy, fmc_list_users, fmc_list_object_overrides /
  fmc_set_object_override (per-device values).
Before changing or deleting an object, check fmc_where_used.

Gotchas: FMC allows about 120 API requests per minute, so prefer the aggregate tools over many small
calls. Changes only reach devices after a deployment. fmc_run_show_command only accepts FMC's
approved show commands (mostly configuration views). fmc_api_call fills {domainUUID} in spec paths
with the default domain.
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


def _path_params(app: FmcApp) -> dict[str, str]:
    uuid = app.default_domain_cached()
    return {"domainUUID": uuid} if uuid else {}


def spec_sources(app: FmcApp) -> list[SpecSource]:
    return [
        SpecSource(
            "fmc",
            _load_spec,
            client=lambda a: a.api,
            version=_spec_version,
            description="FMC REST API (fmc_config, fmc_platform, fmc_tid, fmc_troubleshoot)",
            path_params=_path_params,
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
            device_config.register,
            object_writes.register,
            object_import.register,
            policy_writes.register,
            dangerous.register,
            troubleshoot.register,
            dynamic_objects.register,
            containment.register,
            ha.register,
            vpn.register,
            activity.register,
            platform_settings.register,
            platform_access.register,
            routing.register,
            intrusion.register,
            admin.register,
            prefilter.register,
            security_intel.register,
            rule_io.register,
            tickets.register,
            decryption.register,
            prompts.register,
        ],
        status=FmcApp.status,
        spec_sources=spec_sources,
        auth=auth,
    )

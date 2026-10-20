"""Server definition: SPEC, instructions and create_server()."""

from collections.abc import Callable
from dataclasses import replace
from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider

from fmc_mcp import toolsets
from fmc_mcp._core import ServerSpec, ToolRegistrar, build_server
from fmc_mcp._core.spec import SpecSource
from fmc_mcp.client import SPEC_PATH, FmcApp
from fmc_mcp.config import Settings
from fmc_mcp.tools import (
    activity,
    admin,
    analysis,
    app_routing,
    bundle,
    bundle_import,
    containment,
    dangerous,
    decryption,
    decryption_check,
    deploy,
    device_config,
    devices,
    dns,
    dynamic_objects,
    file_policy,
    find_address,
    ha,
    hygiene,
    identity,
    identity_sources,
    intrusion,
    live,
    metrics,
    network_analysis,
    object_import,
    object_lifecycle,
    object_writes,
    objects,
    pki,
    platform_access,
    platform_settings,
    policies,
    policy_writes,
    prefilter,
    prompts,
    prove,
    routing,
    rule_io,
    sdwan,
    sdwan_status,
    security_intel,
    system,
    templates,
    threat_posture,
    tickets,
    troubleshoot,
    vpn,
    vpn_status,
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
  Loopbacks, VTIs, EtherChannels and BVIs: fmc_create_interface (then fmc_update_interface /
  fmc_delete_interface like any interface).
- Roll out a branch from a device template (FMC 7.6+): fmc_create_device_template (from a working
  branch with source_device) -> fmc_get_device_template (variables, interfaces, VPN/SD-WAN settings)
  -> fmc_register_device (the new FTD) -> fmc_apply_device_template(template, device, variables)
  -> fmc_deploy (device and hubs) -> fmc_get_vpn_topology.
- Change safely: make the change -> fmc_pending_changes (what the next deploy pushes) -> fmc_deploy
  -> fmc_run_show_command / fmc_list_deployments; undo a bad deployment with fmc_rollback_deployment.
- HA: fmc_create_ha_pair (failover link; state_interface for a separate state link) ->
  fmc_configure_ha_monitoring (standby IPs) -> fmc_deploy the pair -> fmc_get_ha_status (each unit's own
  state, link status, last failover and why, ready_for_switch) -> fmc_ha_action switch. The
  fmc_ha_failover_check prompt runs pre-checks, traffic, the switch, verification and a report.
- "Why is this traffic blocked?": fmc_packet_tracer (live verdict, drop reason and matching rule on
  the device) + fmc_rule_lookup (offline walk of the policy) + fmc_get_hit_counts (is the rule hit?).
  The fmc_why_blocked prompt walks these steps in order. "Prove the policy": fmc_prove_policy traces a
  table of flows with expected verdicts (pass/fail/mismatch and the deciding rule); user rules:
  the fmc_prove_user_policy prompt.
- Send FTD logs to the customer's syslog/SIEM: fmc_get_platform_settings -> fmc_configure_syslog
  (servers, level, facility, RFC 5424) -> fmc_assign_policy(kind='platform_settings') -> fmc_deploy;
  fmc_set_access_logging sends connection/intrusion events there too.
- Dynamic routing: fmc_get_routing (BGP, OSPF, ECMP, PBR, VRFs) -> fmc_configure_bgp /
  fmc_configure_ospf / fmc_create_vrf -> fmc_deploy -> fmc_run_show_command('show route').
- SD-WAN (hub and spoke over VTIs): zone the WAN and inside interfaces (fmc_update_interface) ->
  fmc_create_sdwan_topology (hub DVTI, spoke pool, spokes, backup hub, iBGP overlay) -> fmc_deploy hubs
  and spokes -> fmc_get_vpn_topology / fmc_list_vpn_tunnels; add or remove branches and the backup hub
  with fmc_update_sdwan_topology; remove with fmc_delete_s2s_vpn. Health per branch (WAN path metrics,
  app route paths, tunnels, degraded links): fmc_sdwan_status; "app X is slow at branch Y":
  fmc_sdwan_troubleshoot. A new branch end to end (register, template or manual config, join,
  deploy, verify, fmc_prove_policy hand-off): the fmc_onboard_branch prompt.
- SD-WAN application-aware routing: fmc_configure_wan_interface (priority, path monitoring) on each
  WAN link -> fmc_create_app_route (applications/networks/users out of the link with the best
  jitter, loss, RTT or MOS, or by priority) -> fmc_deploy -> fmc_sdwan_status (app routes and the
  path each uses); ECMP across WAN links: fmc_configure_ecmp_zone; remove: fmc_delete_app_route.
- Block a host fast: map its IP into a dynamic object that a BLOCK rule references
  (fmc_map_dynamic_object); mapping changes need no deployment, only the rule does (once).
  fmc_contain_host / fmc_release_host do this for one host with the quarantine object (and propose
  the block rules if they are missing). Blocking IPs/URLs policy-wide with logging (needs a deploy):
  fmc_si_block (Security Intelligence); fmc_get_security_intelligence shows the lists.
- Threat intelligence feeds and lists: fmc_create_si_feed (FMC downloads IPs, URLs or domains from a URL
  on a schedule) or fmc_upload_si_list (a fixed list) -> fmc_set_si_lists (an access policy's SI block or
  do-not-block list; Talos categories by name too; DNS ones go into its DNS policy, which can also only
  monitor) -> fmc_deploy -> fmc_get_security_intelligence (entries and last update of each feed).
- Tune intrusion prevention: fmc_find_intrusion_rules (gid:sid or text) -> fmc_get_intrusion_policy ->
  fmc_set_intrusion_rule_state in a custom policy (fmc_create_intrusion_policy on top of a system one;
  fmc_update_access_rule intrusion_policy=... puts it on an ALLOW rule) -> fmc_deploy. Custom Snort 3
  rules: fmc_create_intrusion_rule.
- Block files and malware: fmc_create_file_policy -> fmc_create_file_rule (e.g. BLOCK MSEXE downloads over
  HTTP, BLOCK_MALWARE for a malware cloud lookup that blocks) -> fmc_update_access_rule file_policy=... on
  ALLOW rules -> fmc_deploy; fmc_get_file_policy shows the rules. Network analysis (preprocessing):
  fmc_get_network_analysis_policy, fmc_create_network_analysis_policy (linking it to an access policy is
  UI-only).
- Users and groups in access rules (AD/LDAP): fmc_create_trusted_ca (LDAPS) -> fmc_create_realm ->
  fmc_test_realm -> fmc_download_realm -> fmc_create_identity_policy + fmc_create_identity_rule (PASSIVE
  needs ISE/pxGrid or an agent for user-IP mappings) -> select the identity policy in the access policy
  editor (FMC's REST API can't) -> fmc_create_access_rule users=[group] -> fmc_deploy;
  fmc_rule_lookup evaluates such rules with the user FMC has on the source IP (or identities=[...]).
- ISE as identity source (pxGrid): fmc_get_identity_sources (ISE connection, SGT download, realms, identity
  policies, sessions, per-device user-IP bindings, certificates, what to fix); the ISE connection itself is
  set in the FMC UI (REST can't). "Who is on 192.0.2.57 / where is alice?" with the user's AD groups as
  rules see them: fmc_user_ip_lookup (every session a device reports, paged: fmc_user_identity_sessions).
- TLS decryption (decrypt-resign): fmc_create_internal_ca (FMC generates the key; self-signed, or a CSR
  your CA signs -> fmc_install_internal_ca_cert) -> install its certificate (fmc_get_certificate) as a
  trusted root on the clients -> fmc_create_decryption_policy (tls13_decryption=true; trusted_cas for
  private server PKIs) -> fmc_create_decryption_rule (DO_NOT_DECRYPT exemptions first, then
  DECRYPT_RESIGN with internal_ca) -> fmc_set_decryption_policy -> fmc_deploy; fmc_tls_decryption_check
  says what a flow gets and what is missing. Existing CA or server keys: fmc_import_certificate_files
  (read from FMC_PKI_DIR on the server host; keys never pass through MCP).
- PoC to production / domain to domain: fmc_export_policy_bundle -> fmc_plan_policy_bundle_import (target
  domain) -> fmc_import_policy_bundle -> fmc_diff_policy_bundle against live -> assign + fmc_deploy.
- "Where does 10.1.2.3 appear?": fmc_find_address (objects and groups, dynamic-object mappings, access,
  prefilter and NAT rules, static routes, VPN endpoints in one ranked call) -> fmc_where_used on an object.
- Policy review: fmc_policy_audit ranks shadowed, permissive, unlogged, uninspected, unused and mergeable
  rules, expired time ranges and duplicate objects, each with a fix to preview; then fmc_pending_changes
  -> fmc_deploy. Threat-defense posture (intrusion and file policies, TRUST/fastpath bypasses, SI and DNS
  coverage, decryption, licences): fmc_threat_posture; the fmc_threat_defense_review prompt combines both.
  Prompts: fmc_policy_cleanup (findings -> approved cleanup -> diff + re-audit) and fmc_rule_change_review
  (one rule change with before/after flows, shadowing check and a deploy plan with rollback).
- Site-to-site VPN: fmc_create_s2s_vpn -> fmc_deploy both peers -> fmc_vpn_status (every topology's
  tunnels with what each device says: IKE and IPsec SAs, traffic each way, routes over the VTIs;
  degraded tunnels first). "The VPN to X is down": the fmc_vpn_troubleshoot prompt (IKE, IPsec,
  routing over the tunnel, NAT exemption, access rules, then one previewed fix).
- "What is this host talking to right now, and who is it?": fmc_live_connections (device, host/user/port;
  from the device's syslog buffer because FMC 10.0.1 refuses 'show conn') -> fmc_user_identity_sessions
  (user <-> IP from FMC's identity view) -> fmc_packet_tracer for the verdict.
- Health: fmc_list_devices, fmc_device_health, fmc_list_vpn_tunnels; "what changed or broke in the
  last hour?": fmc_recent_activity (health alerts + audit + deployments), fmc_list_health_alerts.
  A full ranked review of the estate: the fmc_firewall_health_review prompt.
- Load over time ("was the branch firewall busy at 09:40?"): fmc_device_metrics (CPU, memory,
  throughput, connections and drops over a window, with peaks and dips).
- Day-2 admin: fmc_upgrade_status (versions), fmc_list_backups / fmc_backup_devices,
  fmc_get_health_policy / fmc_update_health_policy, fmc_list_users, fmc_list_object_overrides /
  fmc_set_object_override (per-device values).
- Object cleanup and migrations at scale: fmc_delete_objects (by names, a name prefix or every unused
  object; one preview lists each victim and refuses built-ins, inherited and in-use objects),
  fmc_replace_object (A becomes B in every rule, group, NAT rule and static route, then optionally delete A),
  fmc_import_objects(mode='sync') (an IPAM export or CSV as the desired state: create, update, group members).
Before changing or deleting an object, check fmc_where_used.

Gotchas: FMC allows about 120 API requests per minute, so prefer the aggregate tools over many small
calls. Changes only reach devices after a deployment. fmc_run_show_command only accepts the show
commands FMC's API spec lists (no show bgp, show ospf, show path-monitoring or show policy-route; use
'show route bgp' / 'show route ospf'); it refuses the rest before calling FMC. fmc_api_call fills
{domainUUID} in spec paths with the default domain.
"""

SPEC = ServerSpec(
    name="fmc-mcp-server",
    prefix="fmc",
    product="Cisco Secure Firewall Management Center",
    env_prefix="FMC_",
    instructions=INSTRUCTIONS,
    spec_search_example="access rule",
    spec_path_example="/api/fmc_config/v1/domain/{domainUUID}/policy/accesspolicies/{objectId}/accessrules",
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


REGISTER: list[Callable[[ToolRegistrar], None]] = [
    system.register,
    devices.register,
    policies.register,
    objects.register,
    analysis.register,
    find_address.register,
    hygiene.register,
    threat_posture.register,
    deploy.register,
    device_config.register,
    object_writes.register,
    object_import.register,
    object_lifecycle.register,
    policy_writes.register,
    dangerous.register,
    troubleshoot.register,
    metrics.register,
    live.register,
    prove.register,
    dynamic_objects.register,
    containment.register,
    ha.register,
    vpn.register,
    sdwan.register,
    templates.register,
    sdwan_status.register,
    vpn_status.register,
    activity.register,
    platform_settings.register,
    platform_access.register,
    routing.register,
    app_routing.register,
    intrusion.register,
    file_policy.register,
    network_analysis.register,
    admin.register,
    prefilter.register,
    security_intel.register,
    rule_io.register,
    bundle.register,
    bundle_import.register,
    tickets.register,
    pki.register,
    decryption.register,
    decryption_check.register,
    dns.register,
    identity.register,
    identity_sources.register,
    prompts.register,
]


def create_server(
    settings: Settings,
    *,
    auth: AuthProvider | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastMCP[Any]:
    selected = toolsets.parse(settings.toolsets)
    spec = SPEC
    register = REGISTER
    if selected is not None:  # FMC_TOOLSETS: only these areas (core always)
        spec = replace(SPEC, instructions=SPEC.instructions + toolsets.instructions_note(selected))
        register = [toolsets.filtered(fn, selected) for fn in REGISTER]
    return build_server(
        spec,
        settings,
        client_factory=lambda s: FmcApp(s, transport=transport),
        register=register,
        status=FmcApp.status,
        spec_sources=spec_sources,
        auth=auth,
    )

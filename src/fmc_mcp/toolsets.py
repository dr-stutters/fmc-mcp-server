"""FMC_TOOLSETS (F46): load only some areas of the tool surface.

With every tier on the server registers ~180 tools, and a client loads all their descriptions on every
turn; some clients cap the number of tools. `FMC_TOOLSETS=troubleshoot,objects,deploy` registers only
those areas (plus `core`, which is always on). The read/write/dangerous tiers (MCP_ENABLE_WRITES,
MCP_ENABLE_DANGEROUS) and MCP_ALLOW_TOOLS / MCP_DENY_TOOLS still apply on top: `objects` without
MCP_ENABLE_WRITES gives the object reads only.

Syntax: comma-separated area names; `all` for every area; `-<area>` leaves one out (`all,-sdwan,-tls`).
Unknown names fail at startup with the list of areas. Unset or empty: every area (the default).

Every tool is in exactly one area (TOOLSETS); tests/unit/test_toolsets.py checks the table against the
registered tools, so a new tool must be added here. A prompt is registered when its home areas are loaded
(PROMPT_TOOLSETS); optional steps may name tools of areas that are not. Core's suite prompts (`suite_*`,
C48) are always registered: each names the legs it skips, and its fmc leg (fmc_snapshot,
fmc_compare_snapshot) is in `core`.

This is the fmc catalogue; the generic loader is planned in stutters-mcp-core (C31), and the table is
plain data so it can move onto that mechanism unchanged.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import Any, TypeVar

from fmc_mcp._core import ToolRegistrar

F = TypeVar("F", bound=Callable[..., Any])

ALWAYS = "core"

# area -> (one-line description, tools). Keep each list sorted; one area per tool.
CATALOGUE: dict[str, tuple[str, tuple[str, ...]]] = {
    "core": (
        "always loaded: status, the API spec search and raw API call, domains, devices, tasks, change-check "
        "snapshots",
        (
            "fmc_api_call",
            "fmc_compare_snapshot",
            "fmc_get_definition",
            "fmc_get_task",
            "fmc_list_devices",
            "fmc_list_domains",
            "fmc_review_change",
            "fmc_search_spec",
            "fmc_snapshot",
            "fmc_status",
        ),
    ),
    "admin": (
        "FMC itself: backups, upgrades, health policy, users, audit log, Smart Licensing",
        (
            "fmc_backup_devices",
            "fmc_get_health_policy",
            "fmc_license_status",
            "fmc_list_audit_records",
            "fmc_list_backups",
            "fmc_list_users",
            "fmc_update_health_policy",
            "fmc_upgrade_status",
        ),
    ),
    "deploy": (
        "pending changes, deployments, rollback, change-management tickets",
        (
            "fmc_change_tickets",
            "fmc_deploy",
            "fmc_list_deployable_devices",
            "fmc_list_deployments",
            "fmc_pending_changes",
            "fmc_rollback_deployment",
            "fmc_ticket",
        ),
    ),
    "devices": (
        "device records, registration, licences, interfaces, clusters, device groups, device templates",
        (
            "fmc_apply_device_template",
            "fmc_create_device_group",
            "fmc_create_device_template",
            "fmc_create_inline_set",
            "fmc_create_interface",
            "fmc_create_subinterface",
            "fmc_delete_device",
            "fmc_delete_device_group",
            "fmc_delete_device_template",
            "fmc_delete_inline_set",
            "fmc_delete_interface",
            "fmc_device_snapshot",
            "fmc_diff_device_config",
            "fmc_export_device_config",
            "fmc_get_device",
            "fmc_get_device_template",
            "fmc_list_clusters",
            "fmc_list_device_groups",
            "fmc_list_device_interfaces",
            "fmc_list_device_templates",
            "fmc_register_device",
            "fmc_register_devices",
            "fmc_set_device_licenses",
            "fmc_update_device_group",
            "fmc_update_inline_set",
            "fmc_update_interface",
        ),
    ),
    "ha": (
        "FTD high-availability pairs: status, forming, switch/break, monitored interfaces",
        (
            "fmc_configure_ha_monitoring",
            "fmc_create_ha_pair",
            "fmc_get_ha_status",
            "fmc_ha_action",
            "fmc_list_ha_pairs",
        ),
    ),
    "identity": (
        "users in rules: realms (AD/LDAP), identity policies, ISE identity source, user-IP sessions",
        (
            "fmc_create_identity_policy",
            "fmc_create_identity_rule",
            "fmc_create_realm",
            "fmc_create_trusted_ca",
            "fmc_delete_identity_rule",
            "fmc_delete_realm",
            "fmc_download_realm",
            "fmc_get_identity_policy",
            "fmc_get_identity_sources",
            "fmc_get_realm",
            "fmc_test_realm",
            "fmc_user_identity_sessions",
            "fmc_user_ip_lookup",
        ),
    ),
    "intel": (
        "blocking by reputation: Security Intelligence feeds and lists, DNS policy, host containment",
        (
            "fmc_contain_host",
            "fmc_create_dns_policy",
            "fmc_create_si_feed",
            "fmc_delete_si_object",
            "fmc_dns_block",
            "fmc_find_indicator",
            "fmc_get_dns_policy",
            "fmc_get_security_intelligence",
            "fmc_release_host",
            "fmc_set_dns_policy",
            "fmc_set_si_lists",
            "fmc_si_block",
            "fmc_upload_si_list",
        ),
    ),
    "migrate": (
        "move policy between FMCs or files: policy bundles, access-rule CSV import/export",
        (
            "fmc_diff_policy_bundle",
            "fmc_export_access_rules",
            "fmc_export_policy_bundle",
            "fmc_import_access_rules",
            "fmc_import_policy_bundle",
            "fmc_plan_policy_bundle_import",
        ),
    ),
    "objects": (
        "network/port/URL objects and groups, zones, dynamic objects, overrides, where an address is used",
        (
            "fmc_create_application_filter",
            "fmc_create_dynamic_object",
            "fmc_create_group",
            "fmc_create_object",
            "fmc_create_security_zone",
            "fmc_create_time_range",
            "fmc_delete_dynamic_object",
            "fmc_delete_object",
            "fmc_delete_objects",
            "fmc_find_address",
            "fmc_find_application",
            "fmc_find_object",
            "fmc_get_object",
            "fmc_import_objects",
            "fmc_list_dynamic_objects",
            "fmc_list_object_overrides",
            "fmc_list_objects",
            "fmc_map_dynamic_object",
            "fmc_replace_object",
            "fmc_set_object_override",
            "fmc_unused_objects",
            "fmc_update_group",
            "fmc_update_object",
            "fmc_where_used",
        ),
    ),
    "platform": (
        "platform settings: syslog, connection logging, NTP, SNMP, DNS, NetFlow, SSH/HTTPS/ICMP, banner, "
        "hardening",
        (
            "fmc_configure_dns",
            "fmc_configure_mgmt_access",
            "fmc_configure_netflow",
            "fmc_configure_ntp",
            "fmc_configure_snmp",
            "fmc_configure_ssh_access",
            "fmc_configure_syslog",
            "fmc_create_platform_settings_policy",
            "fmc_get_platform_settings",
            "fmc_hardening_check",
            "fmc_set_access_logging",
            "fmc_set_banner",
        ),
    ),
    "policy": (
        "access control, NAT and prefilter: policies, rules, categories, inheritance, locks, assignments, "
        "hygiene",
        (
            "fmc_assign_policy",
            "fmc_bulk_update_access_rules",
            "fmc_clear_hit_counts",
            "fmc_create_access_policy",
            "fmc_create_access_rule",
            "fmc_create_category",
            "fmc_create_nat_policy",
            "fmc_create_nat_rule",
            "fmc_create_prefilter_policy",
            "fmc_create_prefilter_rule",
            "fmc_delete_access_rule",
            "fmc_delete_category",
            "fmc_delete_nat_rule",
            "fmc_delete_policy",
            "fmc_delete_prefilter_rule",
            "fmc_get_access_policy",
            "fmc_get_access_rule",
            "fmc_list_access_rules",
            "fmc_list_nat_rules",
            "fmc_list_policies",
            "fmc_list_policy_assignments",
            "fmc_list_prefilter_rules",
            "fmc_policy_audit",
            "fmc_policy_lock",
            "fmc_rename_category",
            "fmc_set_base_policy",
            "fmc_set_prefilter_policy",
            "fmc_shadowed_rules",
            "fmc_update_access_rule",
            "fmc_update_nat_rule",
            "fmc_update_prefilter_rule",
        ),
    ),
    "routing": (
        "static routes, BGP, OSPF, VRFs, prefix lists and route maps",
        (
            "fmc_configure_bgp",
            "fmc_configure_ospf",
            "fmc_create_prefix_list",
            "fmc_create_route_map",
            "fmc_create_static_route",
            "fmc_create_vrf",
            "fmc_delete_static_route",
            "fmc_delete_vrf",
            "fmc_get_routing",
            "fmc_list_routes",
        ),
    ),
    "sdwan": (
        "SD-WAN hub and spoke topologies, WAN interfaces, application-aware routing, branch health",
        (
            "fmc_configure_ecmp_zone",
            "fmc_configure_wan_interface",
            "fmc_create_app_route",
            "fmc_create_sdwan_topology",
            "fmc_delete_app_route",
            "fmc_sdwan_status",
            "fmc_update_sdwan_topology",
        ),
    ),
    "threat": (
        "intrusion (IPS), file/malware and network analysis policies, an ACP's threat posture",
        (
            "fmc_create_file_policy",
            "fmc_create_file_rule",
            "fmc_create_intrusion_policy",
            "fmc_create_intrusion_rule",
            "fmc_create_network_analysis_policy",
            "fmc_delete_file_rule",
            "fmc_delete_intrusion_rule",
            "fmc_find_intrusion_rules",
            "fmc_get_file_policy",
            "fmc_get_intrusion_policy",
            "fmc_get_network_analysis_policy",
            "fmc_set_intrusion_recommendations",
            "fmc_set_intrusion_rule_state",
            "fmc_threat_posture",
        ),
    ),
    "tls": (
        "TLS decryption policies and rules, cipher suite lists, certificates (days left, enrolment), "
        "readiness check",
        (
            "fmc_create_cert_enrollment",
            "fmc_create_cipher_suite_list",
            "fmc_create_decryption_policy",
            "fmc_create_decryption_rule",
            "fmc_create_internal_ca",
            "fmc_delete_certificate",
            "fmc_delete_decryption_rule",
            "fmc_enroll_certificate",
            "fmc_get_certificate",
            "fmc_get_decryption_policy",
            "fmc_import_certificate_files",
            "fmc_install_internal_ca_cert",
            "fmc_list_certificates",
            "fmc_list_cipher_suite_lists",
            "fmc_set_decryption_policy",
            "fmc_tls_decryption_check",
            "fmc_update_decryption_policy",
            "fmc_update_decryption_rule",
        ),
    ),
    "troubleshoot": (
        "why is traffic blocked or slow: packet tracer, rule lookup, hit counts, show commands, live state, "
        "profiling",
        (
            "fmc_cpu_profile",
            "fmc_device_health",
            "fmc_device_metrics",
            "fmc_get_hit_counts",
            "fmc_get_profiler_results",
            "fmc_list_health_alerts",
            "fmc_live_connections",
            "fmc_packet_tracer",
            "fmc_prove_policy",
            "fmc_recent_activity",
            "fmc_rule_lookup",
            "fmc_run_show_command",
            "fmc_service_chain_check",
            "fmc_snort_profile",
        ),
    ),
    "vpn": (
        "site-to-site VPN topologies, tunnel status and troubleshooting, remote access VPN build and read",
        (
            "fmc_create_address_pool",
            "fmc_create_group_policy",
            "fmc_create_ravpn",
            "fmc_create_s2s_vpn",
            "fmc_delete_s2s_vpn",
            "fmc_get_ravpn",
            "fmc_get_vpn_topology",
            "fmc_list_vpn_topologies",
            "fmc_list_vpn_tunnels",
            "fmc_set_connection_profile",
            "fmc_vpn_status",
        ),
    ),
}

TOOLSETS: dict[str, frozenset[str]] = {area: frozenset(tools) for area, (_, tools) in CATALOGUE.items()}
AREA_OF: dict[str, str] = {tool: area for area, tools in TOOLSETS.items() for tool in tools}

# prompt -> its home areas: registered only when these are loaded. A prompt may also name tools of other
# areas for optional steps (the instructions say those are missing); tests check these areas are among
# the ones its rendered text uses.
PROMPT_TOOLSETS: dict[str, frozenset[str]] = {
    "fmc_compliance_evidence": frozenset({"migrate", "platform"}),
    "fmc_firewall_health_review": frozenset({"troubleshoot"}),
    "fmc_ha_failover_check": frozenset({"ha"}),
    "fmc_onboard_branch": frozenset({"deploy", "devices", "sdwan"}),
    "fmc_onboard_ftd": frozenset({"deploy", "devices"}),
    "fmc_policy_cleanup": frozenset({"policy"}),
    "fmc_prove_user_policy": frozenset({"identity", "troubleshoot"}),
    "fmc_rule_change_review": frozenset({"deploy", "policy"}),
    "fmc_sdwan_troubleshoot": frozenset({"sdwan"}),
    "fmc_threat_defense_review": frozenset({"threat"}),
    "fmc_vpn_troubleshoot": frozenset({"vpn"}),
    "fmc_why_blocked": frozenset({"policy", "troubleshoot"}),
}

SETTING = "FMC_TOOLSETS"


def parse(spec: str | None) -> frozenset[str] | None:
    """The areas FMC_TOOLSETS selects (core included); None = every area. ValueError on unknown names."""
    entries = [e.strip().lower() for e in re.split(r"[,\s]+", spec or "") if e.strip()]
    if not entries:
        return None
    chosen: set[str] = set()
    dropped: set[str] = set()
    unknown: list[str] = []
    for entry in entries:
        name = entry[1:] if entry.startswith("-") else entry
        if name == "all":
            target = set(TOOLSETS)
        elif name in TOOLSETS:
            target = {name}
        else:
            unknown.append(entry)
            continue
        (dropped if entry.startswith("-") else chosen).update(target)
    if unknown:
        raise ValueError(
            f"{SETTING}: unknown toolset {', '.join(repr(u) for u in unknown)}. Toolsets: "
            f"{', '.join(sorted(TOOLSETS))} (or 'all'; '-<name>' leaves one out)."
        )
    if ALWAYS in dropped:
        raise ValueError(f"{SETTING}: '{ALWAYS}' (status, spec search, raw API call) is always loaded.")
    if not chosen:  # only exclusions: start from every area
        chosen = set(TOOLSETS)
    return frozenset((chosen - dropped) | {ALWAYS})


def tools_in(areas: Iterable[str]) -> frozenset[str]:
    return frozenset(t for a in areas for t in TOOLSETS[a])


def describe(selected: frozenset[str] | None) -> dict[str, Any] | None:
    """For fmc_status: which areas are loaded and which are not (None when FMC_TOOLSETS is unset)."""
    if selected is None:
        return None
    return {
        "loaded": sorted(selected),
        "not_loaded": sorted(set(TOOLSETS) - selected),
        "setting": SETTING,
    }


def instructions_note(selected: frozenset[str] | None) -> str:
    """A line for the server instructions when only some areas are loaded."""
    if selected is None:
        return ""
    missing = sorted(set(TOOLSETS) - selected)
    return (
        f"\nThis server loads only some toolsets ({SETTING}): {', '.join(sorted(selected))}. Tools of the "
        f"other areas ({', '.join(missing)}) named above are not available here; fmc_search_spec + "
        "fmc_api_call reach any endpoint.\n"
    )


class ToolsetRegistrar(ToolRegistrar):
    """The server's registrar with tools and prompts outside the selected areas skipped (and counted).
    Shares the base registrar's state, so tiers, safety rails and status see one registry."""

    def __init__(self, base: ToolRegistrar, selected: frozenset[str]) -> None:
        self.__dict__.update(base.__dict__)
        self.selected = selected
        self.allowed = tools_in(selected)
        skipped: dict[str, str] = getattr(base.mcp, "_fmc_toolset_skipped", {})
        base.mcp._fmc_toolset_skipped = skipped  # type: ignore[attr-defined]
        self.skipped = skipped

    def _gate(self, name: str | None, deco: Callable[[F], F]) -> Callable[[F], F]:
        def gate(fn: F) -> F:
            tool = name or fn.__name__
            if tool not in self.allowed:
                self.skipped[tool] = AREA_OF.get(tool, "?")
                return fn
            return deco(fn)

        return gate

    def read(self, **kw: Any) -> Callable[[F], F]:
        return self._gate(kw.get("name"), super().read(**kw))

    def write(self, **kw: Any) -> Callable[[F], F]:
        return self._gate(kw.get("name"), super().write(**kw))

    def dangerous(self, **kw: Any) -> Callable[[F], F]:
        return self._gate(kw.get("name"), super().dangerous(**kw))

    def prompt(self, **kw: Any) -> Callable[[F], F]:
        deco = super().prompt(**kw)

        def gate(fn: F) -> F:
            name = kw.get("name") or fn.__name__
            if not PROMPT_TOOLSETS.get(name, frozenset()) <= self.selected:
                self.skipped[name] = "prompt"
                return fn
            return deco(fn)

        return gate


def filtered(
    register: Callable[[ToolRegistrar], None], selected: frozenset[str]
) -> Callable[[ToolRegistrar], None]:
    """A module's register function that only registers the selected areas."""

    def run(reg: ToolRegistrar) -> None:
        register(ToolsetRegistrar(reg, selected))

    return run

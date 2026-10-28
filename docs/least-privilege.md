# Least-privilege accounts for `fmc-mcp-server` (F16)

The server needs one FMC account. Give it the smallest role that covers the tiers you enable, and never
the built-in `admin`:

| Server tiers enabled | Account (lab name) | FMC role |
|---|---|---|
| read only (default) | `mcp-api-ro` | custom **`mcp-ro`** |
| read + write (`MCP_ENABLE_WRITES=true`) | `mcp-api-rw` / `mcp-api-svc` | custom **`mcp-rw`** |
| + dangerous (`MCP_ENABLE_DANGEROUS=true`) | same | custom **`mcp-rw`**: deploys, registration, HA, rollback and policy deletes are all covered by the *Devices*, *Deploy* and policy *Modify* permissions below; no Administration permission is needed |

**One user per running copy.** FMC allows one session per user: every new login (REST *or* web UI) for a
user ends that user's other sessions. The hosted container, the live tests and people in the FMC UI must
therefore use different users. The lab has three: `mcp-api-svc` (cortex container), `mcp-api-rw` (live
tests, CLI) and `mcp-api-ro` (read-only live tests). The FMC `admin` user is only used by the seed script.

MCP-side roles (`MCP_ROLES`, core docs/PRODUCTION.md) restrict *callers*; this guide restricts *the server
itself*. Use both.

## 1. Read-only role `mcp-ro`

FMC 10.0 user roles are menu-based. Permission names as the FMC role editor shows them
(Administration > Users > User Roles > Create User Role), with the internal key the seed script uses:

| Menu (FMC term) | Permission | Key | Needed by |
|---|---|---|---|
| Insights & Reports | Dashboard | `overview`, `dashboards` | (UI only; harmless) |
| Events & Logs > Analysis | Audit | `analysis`, `container_analysis`, `audit_log` | `fmc_list_audit_records`, `fmc_recent_activity` |
| Events & Logs > Analysis | Users: Active Sessions, User Activity, Users (view) | not yet checked with a custom role | `fmc_user_identity_sessions`, `fmc_live_connections(user=...)` (FMC answers 403 on `analysis/activesessions` and `analysis/useractivity` without them; the lab roles lacked them on 2026-10-18) |
| Policies > Security policies | Access Control, Intrusion, Rule Editor, Identity, Decryption, Prefilter, Malware & File, DNS, Umbrella DNS Policy (view) | `policy_response`, `firewall_policy`, `firewall`, `intrusion_policy`, `rules`, `identity`, `ssl`, `prefilter_policy`, `file_policy`, `dns_policy`, `umbrella_dns_policy` | `fmc_list_policies`, `fmc_get_access_policy`, `fmc_list_access_rules`, `fmc_get_access_rule`, `fmc_list_prefilter_rules`, `fmc_rule_lookup`, `fmc_shadowed_rules`, `fmc_policy_audit`, `fmc_get_hit_counts`, `fmc_get_intrusion_policy`, `fmc_find_intrusion_rules`, `fmc_license_status` (with `check_policies`, the default: each assigned access policy and its rules) |
| Policies > Network policies | NAT, QoS (view) | `network_policies`, `nat_policy`, `nat`, `qos` | `fmc_list_nat_rules` |
| Objects | Objects (view) | `object_manager` | `fmc_list_objects`, `fmc_get_object`, `fmc_find_object`, `fmc_where_used`, `fmc_unused_objects`, `fmc_list_dynamic_objects`, `fmc_list_object_overrides` |
| Devices | Device Management, Platform Settings, Flexconfig, Certificates (view) | `devices_container`, `devices`, `platform_settings`, `flexconfig_policy`, `certificates` | `fmc_list_devices`, `fmc_get_device`, `fmc_flexconfig_review`, `fmc_license_status` (device names, HA/cluster roles, assigned policies), `fmc_list_device_interfaces`, `fmc_list_ha_pairs`, `fmc_get_ha_status`, `fmc_list_clusters`, `fmc_list_routes`, `fmc_get_routing`, `fmc_list_policy_assignments`, `fmc_get_platform_settings`, `fmc_list_device_templates`, `fmc_get_device_template`, `fmc_list_device_groups` (device templates and groups: assumed to be under Device Management, not yet checked with a custom role) |
| Secure Connections + VPN dashboards | Secure Connections, SD-WAN Summary, Site-to-Site VPN, Remote Access VPN (view) | `vpn`, `vpn_dashboards`, `sd_wan_dashboard`, `s2s_vpn_dashboard`, `ravpn_dashboard` | `fmc_list_vpn_topologies`, `fmc_get_vpn_topology`, `fmc_get_ravpn`, `fmc_list_vpn_tunnels` |
| Integrations | Realms (view) | `registration`, `identity_realms` | identity policy realm lookups |
| Troubleshooting | Health, Health Policy, Health Events | `advanced_troubleshooting`, `health`, `health_policy`, `health_alarm_syslog` | `fmc_device_health`, `fmc_list_health_alerts`, `fmc_recent_activity`, `fmc_get_health_policy` |
| Troubleshooting > Tools | Packet Tracer **+ Modify Packet Tracer**, Threat Defense CLI | `troubleshooting_tools`, `packet_tracer`, `packet_tracer.modify`, `threat_defense_cli` | `fmc_packet_tracer` (running a trace needs *Modify Packet Tracer*; it simulates a packet and changes no configuration), `fmc_run_show_command`, `fmc_device_snapshot` (its show commands; it also reads hit counts, health alerts, tunnels and deployments, the rows above and below) |
| Administration | Product Upgrades, Content Updates, Smart Licenses (view) | `system`, `upgrade_updates`, `device_upgrade`, `update`, `license`, `smart_license` | `fmc_license_status` (Smart Licensing and `/license/devicelicenses`; without the Devices or Access Control permissions above it still answers: rows by device id only, or `not_checked`), `fmc_upgrade_status` |
| Change management | View tickets | `view_tickets` | `fmc_change_tickets` |

`fmc_status`, `fmc_list_domains`, `fmc_get_task`, `fmc_search_spec`, `fmc_get_definition` and GET
`fmc_api_call` need no specific permission beyond a valid login.

**What `mcp-ro` deliberately does not allow** (the tools answer `FMC denied access (403)`):

| Tool | Why |
|---|---|
| `fmc_list_deployable_devices`, `fmc_pending_changes`, `fmc_list_deployments` | FMC ties *reading* deployments and pending changes to **Deploy Configuration to Devices**, which would also let the account deploy. Use the `mcp-rw` account if a read-only operator needs these. |
| every write | no *Modify* permission (verified: a confirmed `fmc_create_object` as `mcp-api-ro` gets 403 from FMC) |
| `fmc_list_backups` | needs **Backup Management** (in `mcp-rw`, which can also run backups) |
| `fmc_list_users` | needs **User Management**, which neither role has: use an administrator account for user audits |
| user roles, external auth, domains, system configuration | no Administration permissions |

## 2. Write role `mcp-rw`

Everything in `mcp-ro`, plus:

| Menu | Permission | Key | Enables |
|---|---|---|---|
| Policies | Modify Access Control (+ Modify Threat Configuration, Modify Other Policy Configuration), Modify Intrusion, Modify Rule Editor, Modify Identity, Modify Decryption, Modify Prefilter, Modify Malware & File, Modify DNS, Modify Umbrella DNS Policy, Modify NAT Policy, Modify QoS Policy | `firewall.modify`, `ac_rule_inspection.modify`, `ac_rule.modify`, `intrusion_policy.modify`, `rules.modify`, `identity.modify`, `ssl.modify`, `prefilter_policy.modify`, `file_policy.modify`, `dns_policy.modify`, `umbrella_dns_policy.modify`, `nat.modify`, `qos.modify` | policy and rule writes, `fmc_contain_host` rule setup, `fmc_assign_policy`, policy deletes |
| Objects | Modify Objects | `object_manager.modify` | object writes (incl. `fmc_create_address_pool`, `fmc_create_group_policy`), `fmc_map_dynamic_object`, `fmc_contain_host` / `fmc_release_host` |
| Devices | Modify Devices, Modify Platform Settings, Modify Certificates | `devices.modify`, `platform_settings.modify`, `certificates.modify` | interfaces, routes, BGP/OSPF/VRF, WAN interface settings, ECMP zones and policy-based routes (`fmc_create_app_route` also needs Modify Objects for its extended access list), HA, register/delete device, syslog, device templates (create/delete/apply) and device groups (create/change/delete; both assumed, not yet checked with a custom role) |
| Devices | Modify Flexconfig (role editor's name not yet checked) | `flexconfig_policy.modify` (assumed) | `fmc_migrate_flexconfig` (F101; the migration also rewrites routing and interfaces: Modify Devices) |
| Integrations | Modify Realms | `identity_realms.modify` | the UI user's `fmc_test_realm` / `fmc_download_realm` (`pjb.cgi` refuses without it; REST realm create/delete worked without it on 10.0.1) |
| Secure Connections | Modify Secure Connections | `vpn.modify` | `fmc_create_s2s_vpn`, `fmc_create_ravpn`, `fmc_set_connection_profile`, VPN deletes |
| (top level) | Deploy Configuration to Devices | `deploy` (FMC adds `task_status`, `task_status.all_users`) | `fmc_deploy`, `fmc_rollback_deployment`, deployment reads |
| Troubleshooting | Modify Health, Modify Health Policy, Apply Health Policy, Modify Threat Defense CLI | `health.modify`, `health_policy.modify`, `health_policy.apply`, `threat_defense_cli.modify` | `fmc_update_health_policy` (F14), `fmc_create_health_policy`, `fmc_assign_health_policy`, `fmc_delete_health_policy` (F100; assigning also edits the device record: Devices > Device Management > Modify Devices) |
| Change management | Modify tickets | `modify_tickets` | `fmc_ticket` |
| Troubleshooting | Snort 3 Profiling (the role editor's name not yet checked) | not yet known | `fmc_snort_profile`, `fmc_cpu_profile`, `fmc_get_profiler_results` (F78). The lab's `mcp-rw` lacks it: FMC 10.0.1 answers 403 "The user is not authorized." on every `snortprofiler` / `cpuprofiler` call while packet tracer works for the same user (2026-10-21); the tools say so instead of blaming the credentials |
| Administration > Advanced | Backup Management | `tools`, `backup_management` | `fmc_list_backups`, `fmc_backup_devices` (F14); not *Restore Backup* |

Still denied: users and roles, external authentication, domains, FMC system configuration, restore, smart
licence registration, FMC upgrades.

## 3. Create the roles and users

**Scripted (lab and rebuild):** the maintainers' seed script `seed_access.py` lives in the suite's private lab
repo (stutters-mcp-lab), not here. It is idempotent (`--check` shows what differs, `--delete` removes users and
roles, `--reset-passwords` re-applies the passwords from `.env`) and reads, from the fmc-mcp-server checkout:

- `.env.admin` (git-ignored, mode 600): `FMC_ADMIN_USERNAME` / `FMC_ADMIN_PASSWORD`, an FMC administrator.
- `.env`: `FMC_USERNAME` / `FMC_PASSWORD` (`mcp-api-rw`), `FMC_RO_USERNAME` / `FMC_RO_PASSWORD`
  (`mcp-api-ro`), `FMC_SVC_USERNAME` / `FMC_SVC_PASSWORD` (`mcp-api-svc`, the container),
  `FMC_UI_USERNAME` / `FMC_UI_PASSWORD` (`mcp-ui-svc`, role `mcp-rw`: the web-UI login that `fmc_test_realm`
  and `fmc_download_realm` use, because FMC's REST API can't test or download an AD/LDAP realm; a UI login
  ends the same user's REST session, so it is a separate user).

FMC 10.0's REST API **cannot** create roles or users (`users/authroles` answers 405 "Update only
resource", `users/users` 405). The script therefore uses the endpoints of the FMC web UI, logged in as the
administrator: `POST /auth/login` (multipart username/password/endSession), then `pjb.cgi`
`SF::Permission::getEditUserRolePageData` / `saveUserRole` / `deleteUserRole` for roles, and the
`/admin/user/user.cgi` form (`mode=create|edit|delete`, the custom role's UUID as a checkbox) for users.
These are not a public API; check them after an FMC upgrade. A REST login as the administrator ends its
UI session, so the script reads users over REST before it opens the UI session.

**By hand (GUI):**
1. Administration > Users > User Roles > **Create User Role** `mcp-ro`: tick the permissions in §1.
2. Same for `mcp-rw` with §1 + §2.
3. Administration > Users > User Accounts > **Create User** `mcp-api-svc`: internal authentication,
   password, *Maximum Number of Failed Logins* 5, no forced reset, role `mcp-rw` only. On a multi-domain FMC,
   assign the role in each domain the server manages (F19).
4. The REST API must be enabled (Administration > Configuration > REST API Preferences).

Store the hosted container's password as a Docker secret (`FMC_PASSWORD_FILE`, core
`docs/templates/docker-compose.secrets.yml`) in production. The lab compose file takes
`FMC_SVC_USERNAME` / `FMC_SVC_PASSWORD` from `.env`.

## 4. Verify (tested on FMC 10.0.1 build 1, FTDv 10.0.0, 2026-10-15)

```bash
uv run pytest -m live tests/live/test_least_privilege.py -s   # as mcp-api-ro
uv run pytest -m live tests/live                              # whole live suite as mcp-api-rw
```

`test_read_tier_as_readonly_user` (core `read_tier_report`, MCP caller role `ro`) calls every read tool
as `mcp-api-ro`:

| Result | Count | Tools |
|---|---|---|
| ok | 43 | every read tool with a sample, including packet tracer, show commands, hit counts, health, routing, intrusion policy and overrides on the real FTD |
| denied (expected, see §1) | 5 | `fmc_list_deployable_devices`, `fmc_list_deployments`, `fmc_pending_changes`, `fmc_list_backups`, `fmc_list_users` |
| skipped | 4 | `fmc_api_call` (dangerous tier), `fmc_get_ha_status`, `fmc_get_vpn_topology`, `fmc_get_task` (need an HA pair / topology / task id) |

`test_ro_user_cannot_write` confirms a `fmc_create_object` as `mcp-api-ro`: FMC answers 403.
The full live suite (writes, deploys, rollback, HA/VPN where the lab has them) runs as `mcp-api-rw`.

## 5. Lab rebuild

The seed script runs first in the FMC step of the lab rebuild script in the suite's private lab repo
(stutters-mcp-lab; it only needs the admin login), and that repo's rebuild runbook lists the roles and users
under FMC. On your own FMC, follow §3 by hand.

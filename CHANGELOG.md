# Changelog

## 0.8.0 (2026-10-15)

F13 third slice (DNS policy and domain blocking). Tools: 56 read, 61 write, 9 dangerous (126).

### Added
- **DNS policy (F13, third slice)**: `fmc_get_dns_policy` (read), `fmc_create_dns_policy`, `fmc_set_dns_policy`
  (an access policy's SI DNS policy), `fmc_dns_block` (write: each domain becomes a one-entry custom SI DNS list,
  uploaded as a multipart file, in rule `mcp-dns-block`; NXDOMAIN or DROP). Live: blocked a domain in
  `mcp-test-dns` linked to mcp-test-ftd-acp, deployed, unblocked, default DNS policy linked again, deployed.
  FMC's DNS rule actions are ALLOW / NXDOMAIN / DROP / SINKHOLE / MONITOR; `insertBefore` isn't accepted.

## 0.7.0 (2026-10-15)

F24 platform settings writes and F25 bulk object import. Tools: 55 read, 54 write -> 58, 9 dangerous (122).

### Added
- **Bulk object import (F25)**: `fmc_import_objects` (write): hosts, networks, ranges, FQDNs, ports and URLs,
  validated and checked against existing names in the preview, posted with FMC's bulk API per type;
  `skip_existing` resumes. Live: 30 mcp-test-bulk-* objects created, re-run is a no-op, deleted.
- **Platform settings writes (F24)**: `fmc_configure_ntp`, `fmc_configure_snmp` (enable, community, location,
  contact, manager hosts; FMC masks communities on read, so they must be given again and are never echoed),
  `fmc_configure_ssh_access`. Live on mcp-ftd1: NTP server (seen in the policy; FTD NTP runs on the management
  side), SNMP host + location in `show running-config snmp-server`, SSH from the inside network in
  `show running-config ssh`; all reverted.

### Fixed
- `fmc_run_show_command` explains FMC's 404 "The input command is invalid" (e.g. `show running-config ntp`: NTP
  is not in the data-plane config) instead of a generic "not found", and passes FMC's 404 text through otherwise.

## 0.6.0 (2026-10-15)

New roadmap items found overnight (F20-F23) and the second F13 slice. Tools: 51 read -> 55, 42 write -> 54,
9 dangerous (118 with every tier on).

### Added
- **Decryption policy (F13, second slice)**: `fmc_get_decryption_policy` (read), `fmc_create_decryption_policy`,
  `fmc_create_decryption_rule` (do-not-decrypt / block / monitor), `fmc_delete_decryption_rule`,
  `fmc_set_decryption_policy` (write). `fmc_get_access_policy` now shows the decryption and identity policies.
  Live: a do-not-decrypt rule for a TLS destination in `mcp-test-dec`, linked to mcp-test-ftd-acp and deployed,
  then removed and deployed again. FMC's API can't unlink a decryption policy from an access policy (null refused,
  omitted keeps it): the tool explains instead of pretending.
- **Change-management tickets (F22)**: `fmc_change_tickets` (read: on/off, tickets, a ticket's changes and
  validation) and `fmc_ticket` (write: open / submit / discard / release). An open ticket, or `FMC_TICKET`, is sent
  as `ticket-id` with every request. Roles gain view_tickets / modify_tickets. Live: change management switched on
  for ~10 s, a host created inside a ticket, the ticket's changes listed, the ticket discarded (FMC reverts the
  change in the background), switched off again.
- **Access rule export/import (F23)**: `fmc_export_access_rules` (rows or CSV with object names and literals like
  tcp/443, icmp/8) and `fmc_import_access_rules` (write; validates and resolves every row in the preview, refuses
  applications/users/VLAN/SGT conditions and duplicate names, posts with FMC's bulk API in chunks of 100). Live:
  mcp-test-acp exported, imported into a scratch policy and exported again identically.
- **Security Intelligence (F21)**: `fmc_get_security_intelligence` (read), `fmc_si_block` (block/unblock IPs, networks,
  URLs through the access policy's SI block list; each entry an `mcp-si-<value>` object). Live: blocking the
  outside gateway made packet tracer drop TCP 443 from the inside host; unblocked and deployed again. FMC accepts
  Host/Network/URL objects and SI lists in the SI block list, not network groups.
- **Prefilter writes (F20)**: `fmc_create_prefilter_policy`, `fmc_set_prefilter_policy`, `fmc_create_prefilter_rule`,
  `fmc_update_prefilter_rule`, `fmc_delete_prefilter_rule`. Live: a bidirectional FASTPATH rule for the inside host
  in `mcp-test-pf` linked to mcp-test-ftd-acp, deployed, packet tracer shows the prefilter fastpath; removed and
  the default prefilter policy linked again. FMC treats an access-policy PUT carrying the rules block as bulk (422),
  so only the policy's own fields are sent.

## 0.5.0 (2026-10-15)

Production gate (F16, F18, F19) and Later (F13 first slice, F14). Tools: 45 read -> 51, 35 write -> 42,
7 dangerous -> 9 (102 with every tier on). Core v0.9.0. F17 (version matrix) and F15 (cdFMC) skipped: they need
older FMC versions and an SCC tenant.

### Added
- **Admin operations (F14)**: `fmc_upgrade_status`, `fmc_list_backups`, `fmc_get_health_policy`, `fmc_list_users`,
  `fmc_list_object_overrides` (read); `fmc_update_health_policy` (module on/off and thresholds; per-alert
  thresholds follow), `fmc_set_object_override` (write); `fmc_backup_devices` (dangerous). Live: versions, health
  threshold change + revert, an override on mcp-ftd1 set/listed/removed; device backup is refused by FMC for FTDv
  (the tool explains it) so it is mock-tested. FMC 10.0.1 has no `backup/backuprecords` GET (405); backups come
  from `backup/files`. Change-management tickets are left for later.
- **Intrusion policy tuning (F13, first slice)**: `fmc_get_intrusion_policy`, `fmc_find_intrusion_rules` (read);
  `fmc_set_intrusion_rule_state`, `fmc_create_intrusion_policy`, `fmc_create_intrusion_rule`,
  `fmc_delete_intrusion_rule` (write); `fmc_update_access_rule` gains `intrusion_policy` ('' removes it).
  `fmc_set_device_licenses` (write) adds the IPS/malware/URL licence capabilities that such rules need. Live on
  the FTD: a custom Snort 3 ICMP rule set to DROP in `mcp-test-ips` on an allow rule, deployed, packet tracer
  drops in Snort; DEFAULT and removal restore it. Decryption, DNS and identity policy editing are left for later.
- **Multi-domain (F19)**: `fmc_list_domains` shows the domain tree (parent, leaf, devices per domain); every
  write preview names its domain; edits of objects or policies a descendant domain only inherits are blocked
  with the owner domain to use; device-level calls made from an ancestor domain go to the device's leaf domain
  (FMC refuses them in the ancestor), shown as `device_domain`. Live on a lab leaf domain `Global/mcp-test-leaf`
  holding mcp-ftd1 (`scripts/seed_domain.py`, UI automation because FMC's API can't create domains).
- **Deploy safety rails (F18)** on core's G7 rails: blast radius in physical devices (HA pair = 2, cluster =
  members) on deploy, rollback, register, delete device and HA tools; `FMC_DEPLOY_WINDOW` gates only the tools
  that change what runs on devices; `fmc_deploy(ignore_warning=true)` needs `FMC_ALLOW_IGNORE_WARNING=true` and
  lists the FMC warnings it ignores (recorded from a refused deploy of the same devices and pending version);
  rollback previews list every deployment they undo; dangerous previews name the domain.
- **Least-privilege FMC roles and API users (F16)**: `docs/least-privilege.md` defines the custom roles `mcp-ro`
  (read tier) and `mcp-rw` (write + deploy tiers) permission by permission, with the 403 matrix measured on FMC
  10.0.1; `scripts/seed_access.py` creates the roles and the users `mcp-api-ro` / `mcp-api-rw` / `mcp-api-svc`
  (FMC's REST API can't, so it drives the FMC UI endpoints as the administrator) and sets evaluation licensing;
  `tests/live/test_least_privilege.py` runs every read tool as `mcp-api-ro` (core `read_tier_report`) and checks
  FMC refuses a write from it. The whole live suite runs as `mcp-api-rw`.
- `docker-compose.yml` takes the container's own FMC user from `FMC_SVC_USERNAME` / `FMC_SVC_PASSWORD` (falls
  back to `FMC_USERNAME`), so the hosted server never shares a session with the CLI or the tests.

### Changed
- Core v0.6.0 -> v0.9.0: secrets (`FMC_PASSWORD_REF`), `/metrics`, OAuth, and several FMCs per server
  (`FMC_INSTANCES`, an `instance` argument on every tool). The release workflow is back on core's
  `python-release.yml@main` (fixed in core v0.8.1).
- The local `PromptRegistrar` workaround for prompt examples is gone (`ToolRegistrar.prompt(example=)` works
  since core v0.8.1).

## 0.4.0 (2026-10-15)

Roadmap "Next" (F8-F11). Tools: 41 read -> 45, 30 write -> 35, 7 dangerous (87 with every tier on),
prompts 1 -> 2. Core v0.6.0. Pull-only (ADR-003).

### Added
- `fmc_contain_host(ip, reason)` / `fmc_release_host(ip)` (F9, the FMC half of ise-mcp-server's
  `ise_quarantine_host`): map a host into the quarantine dynamic object (`FMC_QUARANTINE_OBJECT`, default
  `mcp-quarantine`). A missing object is created and missing BLOCK rules (`<object>-out` source,
  `<object>-in` destination) are proposed at the top of the assigned access policy; only that one-time
  setup needs a deployment, and the preview says so. Idempotent both ways. Live: ping from the CML
  inside host blocked ~5 s after containment with nothing to deploy, packet tracer drops on
  `mcp-quarantine-out`; restored after release.

- Prompt `fmc_onboard_ftd` (F8; dangerous tier, uses fmc + cml): preconditions (licence, already
  registered, the `configure manager add` step for re-registration), optional CML recipe build, register,
  interfaces and zones, default route and NAT, policies, deploy, then verify with show commands, packet
  tracer and real traffic. Live: a fresh FTDv (`mcp-ftd2`, CML lab `mcp-fmc-ha`) onboarded end to end
  by following the prompt; the inside host reached the lab gateway through PAT.
- HA depth (F10): `fmc_get_ha_status` (units and states, failover link, trigger criteria, monitored
  interfaces with active/standby IPs, failover MACs) and `fmc_configure_ha_monitoring` (monitor for
  failures, standby IP checked against the interface network, failover virtual MACs). Live on two new
  FTDv (CML lab `mcp-fmc-ha`): form HA, standby IPs + virtual MAC, deploy, `show failover` shows both
  units Monitored, switch (traffic kept flowing from the inside host through the new active unit),
  CLUSTER health alerts in `fmc_recent_activity`, break, re-form, delete.
- VPN depth (F11): `fmc_list_vpn_topologies` (kind incl. SD-WAN/AUTO_VPN, tunnels up/down),
  `fmc_get_vpn_topology` (endpoints, protected networks, NAT exemption, IKE/IPsec with the PSK masked,
  live tunnel rows), `fmc_create_s2s_vpn` (point-to-point IKEv2 PSK, policy- or route-based, managed FTD,
  HA pair or extranet peer; creates topology, IKE, IPsec and endpoints in order), `fmc_delete_s2s_vpn`,
  and `fmc_get_ravpn` (RA VPN policies, connection profiles, pools, AAA, gateway sessions; read-only).
  Live: policy-based tunnel between `mcp-ftd1` and the HA pair; pings 10.99.1.10 -> 10.99.2.10 went
  through it (`show crypto ipsec sa` 4/4 packets, `fmc_list_vpn_tunnels` TUNNEL_UP), then deleted.
  In FMC evaluation mode the builder picks DES policies (FMC refuses to deploy stronger crypto
  without export-controlled licensing) and blocks explicit strong choices with an explanation.

### Changed
- Core pinned to v0.6.0 (0.3.1 `fmc_get_definition(examples=True)`, 0.4.0 prompt test kit, 0.5.0 safety rails,
  0.6.0 roles; no code changes needed). `fmc_deploy` reports `blast_radius` (devices). The prompt kit is wired
  in: `tests/manifests/fmc.json` (regenerate with `uv run fmc-mcp-server tools --json --out tests/manifests/fmc.json`),
  cross-server reference and inbound checks, prompt snapshots. The VPN builder's payloads were checked
  against the spec examples. The remaining hand-coded defaults (OSPF process configuration) are still
  required by FMC 10.0.1, so they stay.
- `fmc_deploy` accepts HA pair names, and a unit's name deploys its pair (FMC lists the pair as one
  deployable container).

### Fixed
- VPN pre-shared keys are masked anywhere they appear in tool output.

## 0.3.0 (2026-10-15)

Roadmap "Now" (F1-F6). Tools: 35 read -> 41, 20 write -> 30, 7 dangerous (78 with every tier on)
plus the first workflow prompt. Pull-only (ADR-003).

### Added
- Prompt `fmc_why_blocked` (source, destination, protocol, port; optional device, ingress interface,
  policy): offline rule match with zones, live packet tracer, hit counts, pending changes and recent
  deployments, audit trail, then a preview-first fix. Exercised live against the FTDv (TCP 23 blocked,
  TCP 443 allowed, no-ARP drop) after real traffic from the inside host.

- Dynamic objects (F4): `fmc_list_dynamic_objects` (with current mappings), `fmc_create_dynamic_object`,
  `fmc_delete_dynamic_object` (blocked while an access rule references it) and `fmc_map_dynamic_object`
  (add/remove IPs; takes effect without a deployment; the preview lists the rules it affects).
  `fmc_create_access_rule` / `fmc_update_access_rule` take `source_dynamic_objects` /
  `destination_dynamic_objects`. Live: mapping the inside host blocked ping and TCP 443 within seconds,
  with nothing to deploy; unmapping restored it.
- `fmc_packet_tracer` names the rule Snort decided on (`verdict_rule`); with a Snort-evaluated rule
  (dynamic objects, applications, URLs) the ACCESS-LIST phase only shows a "send to Snort" permit.

- On-demand activity (F5, pull-only): `fmc_list_health_alerts` (alerts over a window across devices
  and the FMC itself, repeats collapsed with first/last seen and status changes) and
  `fmc_recent_activity` (health alerts, audit records and deployments merged by time; a failing
  source is reported, not fatal). Live: pulling the FTD management link raised APPLIANCE_HEARTBEAT
  YELLOW then RED within ~2 minutes, shown next to the rule edit (audit) and deploy rows.

- Platform settings (F3): `fmc_get_platform_settings` (syslog, NTP, SNMP with secrets masked, SSH/HTTP
  access, banner, DNS, assigned devices), `fmc_create_platform_settings_policy`, `fmc_configure_syslog`
  (servers with interface/protocol/port/EMBLEM/TLS, logging on/off, level to the servers, facility,
  RFC 5424 timestamps) and `fmc_set_access_logging` (ACP connection/intrusion/file events to the
  platform-settings syslog). Live: added a server, assigned, deployed and checked
  `show running-config logging` on the FTD, then removed it. The server never receives syslog (ADR-003).

- Routing depth (F6): `fmc_get_routing` (BGP per address family with neighbors and networks, OSPFv2
  processes and areas, OSPF interfaces, ECMP zones, PBR, BFD, VRFs), `fmc_configure_bgp` (set up BGP,
  add/change/remove neighbors, advertise/withdraw networks, remove BGP), `fmc_configure_ospf` (area
  networks, create/delete a process), `fmc_create_vrf` and `fmc_delete_vrf`. Live: eBGP and OSPF area 0
  to an IOL peer in CML came up after deploy (B and O routes on the FTD), then were removed.

### Changed
- Core pinned to stutters-mcp-core v0.3.0 (pull-only; `list_result` keeps `Page.more`; prompts via
  `reg.prompt`).
- `fmc_pending_changes` masks secret-looking fields (FMC shows encrypted passwords there).

### Fixed
- `fmc_create_static_route` refuses an exact duplicate (same table, interface, destinations and
  gateway) in the preview instead of letting FMC reject it at create or deploy time.

## 0.2.0 (2026-10-15)

Phase 2: gap analysis against the full FMC 10.0.1 API (`docs/GAP-ANALYSIS.md`) and live testing with
a real FTDv 10.0 managed by the lab FMC. Tools: 30 read -> 35, 14 write -> 20, 6 dangerous -> 7
(62 with every tier on).

### Added
- Troubleshooting (read): `fmc_run_show_command` (FMC's approved show commands on a device, with line
  filter), `fmc_packet_tracer` (verdict, drop reason and the matching access/prefilter rule),
  `fmc_get_hit_counts` (refresh + per-rule hits with the device rule id), `fmc_device_health` (non-green
  health modules, CPU and memory), `fmc_list_vpn_tunnels` (S2S tunnel status).
- Device configuration (read/write): `fmc_list_routes`, `fmc_update_interface` (logical name, zone, IPv4
  static/DHCP, MTU, admin state), `fmc_create_subinterface`, `fmc_delete_interface`,
  `fmc_create_static_route` (global table or VRF), `fmc_delete_static_route`, `fmc_assign_policy`
  (access, NAT, platform settings).
- Dangerous: `fmc_rollback_deployment` (defaults to the previous successful deployment).
- Live tests against a managed FTD (`tests/live/test_live_ftd.py`: onboarding, packet tracer, hit
  counts, health, change/deploy/rollback), enabled by `FMC_LIVE_FTD_HOST` / `FMC_LIVE_FTD_REG_KEY`.
- `scripts/capture_fixtures.py --ftd` records redacted device fixtures.

### Changed
- `fmc_register_device` waits for FMC's initial deployment after registration, and failures carry
  FMC's reason (Smart Licensing / evaluation mode, registration timeout) with next steps.
- `fmc_pending_changes` returns compact `Field: old -> new` changes and drops empty container rows.
- `fmc_list_device_interfaces` shows zone names and `Ethernet0/1.100`-style subinterface names, and
  skips interface kinds the model doesn't support (FTDv answers 405 for VLAN interfaces).
- `fmc_deploy` explains FMC validation warnings and points at `ignore_warning`.
- `fmc_delete_device` warns that the FTD forgets its manager.
- Server instructions describe the onboarding, change and "why is it blocked" workflows.

### Fixed
- `fmc_create_access_rule` / `fmc_update_access_rule` with a block action failed with the default
  logging (FMC rejects `logEnd` on block rules); block rules now log at the connection start.

## 0.1.1 (2026-10-15)

- Requires stutters-mcp-core 0.1.1.
- `fmc_api_call` fills `{domainUUID}` in spec paths with the default domain (FMC_DOMAIN or the login's
  domain), so paths from `fmc_search_spec` work as-is.
- Missing credentials raise the core's AuthError (local ValueError workaround removed).
- Added `.dockerignore`; the image now includes LICENSE.

## 0.1.0 (2026-10-15)

First release, built on stutters-mcp-core 0.1.0 and tested against FMC 10.0.1.

- FMC client: token login with refresh (three refreshes, then a new login), single-flight, back-off
  after a failed login, rate limiter (110 requests/min, 8 concurrent), offset/limit paging, domain
  resolution by name or UUID, and an FMC error-message extractor.
- 30 read tools: status, domains, audit records, tasks, licensing, devices, interfaces, HA pairs,
  clusters, policies of every kind, flattened access, NAT and prefilter rules, policy assignments,
  objects, find-by-value, where-used, unused objects, offline rule lookup, shadowed rules, deployable
  devices, pending changes, deployment history, and spec search/definition/GET.
- 14 preview-first write tools for objects, groups, security zones, access policies and rules
  (with insert position and move), and NAT policies and rules.
- 6 dangerous tools (deploy with task polling, register/delete device, form/break/switch HA, delete
  policy), plus raw `fmc_api_call`.
- Dockerfile and docker-compose.yml (port 8035), lab seeding and fixture capture scripts.

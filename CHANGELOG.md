# Changelog

## Unreleased

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
  by following the prompt; the inside host reached the dCloud gateway through PAT.
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

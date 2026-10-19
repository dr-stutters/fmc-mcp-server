# fmc-mcp-server

An MCP server for **Cisco Secure Firewall Management Center (FMC)**. It lets an AI assistant read
and change FMC through its REST API: device onboarding, interfaces and routes, access control and NAT
policies, objects, deployments (with rollback), HA pairs and the audit log. Its troubleshooting tools
answer "why is this traffic blocked?" (packet tracer, offline rule lookup, hit counts), "did my
change land?" (show commands on the FTD) and "where is this object used?".

It is built on [stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core) and runs either
over stdio for a local client or as an authenticated Streamable HTTP service in a container.

> **Not affiliated with or endorsed by Cisco Systems, Inc.** Cisco, Firepower and Secure Firewall are
> trademarks of Cisco Systems, Inc.

Tested against **FMC 10.0.1** (Global plus a leaf domain) with managed **FTDv 10.0**. FMC 7.2 and later
should work. Older versions are best-effort. `docs/GAP-ANALYSIS.md` maps the whole FMC API to the
tools.

## Quickstart (5 minutes)

You need: an FMC user for the server with the REST API enabled (**Administration > Configuration > REST API
Preferences**). Read-only is enough to start: a custom role `mcp-ro`, see
[docs/least-privilege.md](docs/least-privilege.md). Use a user of its own: every FMC login ends that user's other
sessions, so never the GUI `admin` or another integration's user.

**A. On your laptop (stdio), from a release wheel.** Every [GitHub release](https://github.com/dr-stutters/fmc-mcp-server/releases)
has a wheel with stutters-mcp-core bundled in; it needs only PyPI dependencies.

```bash
WHEEL=https://github.com/dr-stutters/fmc-mcp-server/releases/download/v0.13.2/fmc_mcp_server-0.13.2-py3-none-any.whl
export FMC_URL=https://fmc.example.com FMC_USERNAME=mcp-api-ro FMC_PASSWORD='...'
uvx --from "$WHEEL" fmc-mcp-server check            # preflight: TLS, token, domains, role, version, rate limit
claude mcp add fmc -e FMC_URL=$FMC_URL -e FMC_USERNAME=$FMC_USERNAME -e FMC_PASSWORD="$FMC_PASSWORD" \
  -- uvx --from "$WHEEL" fmc-mcp-server              # stdio is the default transport
```

Claude Desktop (`claude_desktop_config.json`), same idea:

```json
{
  "mcpServers": {
    "fmc": {
      "command": "uvx",
      "args": ["--from", "https://github.com/dr-stutters/fmc-mcp-server/releases/download/v0.13.2/fmc_mcp_server-0.13.2-py3-none-any.whl", "fmc-mcp-server"],
      "env": {"FMC_URL": "https://fmc.example.com", "FMC_USERNAME": "mcp-api-ro", "FMC_PASSWORD": "..."}
    }
  }
}
```

**B. On a shared host (HTTP), from the image.** Multi-arch (amd64/arm64), signed, with an SBOM:
`ghcr.io/dr-stutters/fmc-mcp-server:<version>` (or `:latest`).

```bash
docker run --rm -e FMC_URL=https://fmc.example.com -e FMC_USERNAME=mcp-api-ro -e FMC_PASSWORD='...' \
  ghcr.io/dr-stutters/fmc-mcp-server fmc-mcp-server check
docker run --rm ghcr.io/dr-stutters/fmc-mcp-server fmc-mcp-server token alice   # one token per person
cp .env.example .env && chmod 600 .env    # FMC_*, MCP_AUTH_TOKENS=alice:sha256:...
docker compose up -d                      # pulls the image; http://localhost:8035/mcp
```

For a team, use [docs/deploying.md](docs/deploying.md): read-only by default, per-user tokens in the audit
log, several FMCs, one FMC API user per server, the 120 requests/minute budget, TLS with Caddy, change
management tickets, upgrades.

**`check`** runs without an MCP client and exits 1 on a failure (`--json` for scripts, `--strict` to fail on
warnings, `--instance dr` for one FMC). It logs in once (token generation: reachability, TLS trust,
credentials) and reports the domains the user can see, the user's FMC roles against the enabled tiers, the FMC
version against the tested matrix and the server's rate limit against FMC's 120 requests/minute:

```text
  OK    reachability[api]      generatetoken answered (18 ms)
  OK    tls                    certificate verified against the system trust store
  OK    auth                   token generated for mcp-api-ro
  OK    role                   role 'mcp-ro' allows the enabled tier(s): read
  OK    version                Cisco Secure Firewall Management Center 10.0.1 (build 1): tested
  OK    domains                2 visible: Global, Global/Branch; default Global
  OK    rate_limit             110 requests/min (default; FMC allows 120/min per FMC), shared by every caller of this server
```

FMC shows a user's roles only to accounts with User Management (which `mcp-ro` / `mcp-rw` don't have); then
`role` can't tell and warns when writes are on. The check's login ends the same user's other FMC sessions.
`fmc-mcp-server serve --http` serves HTTP (needs `MCP_AUTH_TOKENS`); `fmc-mcp-server config` shows the effective
settings and where each came from, without contacting FMC.

## Safety model

| Tier | Enabled by | What it can do |
|---|---|---|
| read | always | All the tools under "Read" below. `fmc_api_call` is GET-only. |
| write | `MCP_ENABLE_WRITES=true` | Create, update and delete objects, groups, zones, access rules and NAT rules; configure device interfaces and static routes; assign policies. Nothing reaches a device before a deploy. |
| dangerous | `MCP_ENABLE_DANGEROUS=true` (also needs writes) | Deploy and roll back, register and delete devices, form and break HA pairs, delete whole policies, and send raw non-GET `fmc_api_call` requests. |

Every write is **preview-first**:

1. Calling a write tool without `confirm` changes nothing. It returns a preview and a single-use
   confirm token. The preview shows the exact request body, the field-by-field changes, the
   policies that use the object and the rule's position.
2. The assistant shows you the preview.
3. If you approve, the assistant repeats the identical call with `confirm=<token>`.

The token is refused if the arguments changed, or if the target changed on FMC after the preview
(for example, the object was edited or the rules were reordered).

Changes made in FMC reach the firewalls only after a **deployment** (`fmc_deploy`, dangerous tier).

## Tools

There are 153 tools when every tier is enabled (66 read, 76 write, 11 dangerous; the dangerous tier turns `fmc_api_call` into a raw call), and seven workflow prompts (`fmc_why_blocked`, `fmc_firewall_health_review`, `fmc_sdwan_troubleshoot`, `fmc_vpn_troubleshoot`; `fmc_rule_change_review` and `fmc_policy_cleanup`, write tier; `fmc_onboard_ftd`, dangerous tier).

**Read**

| Area | Tools |
|---|---|
| System | `fmc_status`, `fmc_list_domains`, `fmc_list_audit_records`, `fmc_get_task`, `fmc_license_status` |
| Activity (on demand) | `fmc_list_health_alerts`, `fmc_recent_activity` |
| Devices | `fmc_list_devices`, `fmc_get_device`, `fmc_list_device_interfaces`, `fmc_list_routes`, `fmc_get_routing`, `fmc_get_platform_settings`, `fmc_list_ha_pairs`, `fmc_get_ha_status`, `fmc_list_clusters` |
| VPN | `fmc_list_vpn_topologies` (incl. SD-WAN), `fmc_get_vpn_topology`, `fmc_get_ravpn`, `fmc_vpn_status` (every site-to-site topology's tunnels with each device's IKE and IPsec SAs, traffic each way, last rekey and the routes over the VTIs; degraded tunnels first), `fmc_sdwan_status` (per branch: WAN links with path metrics, the path each app route takes now and why, tunnels and iBGP, ranked degraded links) |
| Device templates (FMC 7.6+) | `fmc_list_device_templates`, `fmc_get_device_template` (interfaces, variables, model mappings, VPN/SD-WAN settings, overridable objects, devices it was applied to; passwords masked) |
| Troubleshooting | `fmc_packet_tracer`, `fmc_run_show_command`, `fmc_get_hit_counts`, `fmc_device_health`, `fmc_device_metrics` (CPU, memory, throughput, connections and drops over a window: min/avg/max, peaks, dips and a compact series), `fmc_list_vpn_tunnels`, `fmc_live_connections` (a host's or user's connections on one FTD: peers, state, bytes, duration, rule, user), `fmc_user_identity_sessions` (who is on an IP, where a user is logged in), `fmc_prove_policy` (a table of flows with expected verdicts, each packet-traced on the FTD it crosses: pass / fail / mismatch with the deciding rule and the user the device saw) |
| Policies | `fmc_list_policies`, `fmc_get_access_policy`, `fmc_list_access_rules`, `fmc_get_access_rule`, `fmc_list_nat_rules`, `fmc_list_prefilter_rules`, `fmc_list_policy_assignments` |
| Objects | `fmc_list_objects`, `fmc_get_object`, `fmc_find_object`, `fmc_where_used`, `fmc_unused_objects`, `fmc_list_dynamic_objects`, `fmc_find_address` (one IP, network or range across objects and groups, dynamic-object mappings, access, prefilter and NAT rules, static routes and VPN endpoints, ranked) |
| Security Intelligence | `fmc_get_security_intelligence` (block and do-not-block lists, the DNS policy's rules, and each feed's and custom list's entries, last update and status; without a policy: every SI feed and custom list) |
| Decryption / DNS | `fmc_get_decryption_policy` (rules, trusted CAs, TLS 1.3, access policies using it, `readiness`), `fmc_get_certificate` (internal CAs, internal certificates, trusted CAs: expiry, pending CSR, PEM to install on clients, where used; private keys never shown), `fmc_tls_decryption_check` (what decryption does to one flow and what a decrypt-resign rollout still lacks), `fmc_get_dns_policy` |
| Identity (AD/LDAP, ISE) | `fmc_get_realm` (directories, downloaded users and groups), `fmc_test_realm` (bind test from FMC; needs `FMC_UI_USERNAME`), `fmc_get_identity_policy` (rules, access policies using it), `fmc_get_identity_sources` (ISE/pxGrid connection, SGT download, realms, identity policies, sessions by source, per-device user-IP bindings, certificate expiry, what to fix), `fmc_user_ip_lookup` (who is on an IP / where a user is, with the user's realm groups) |
| Intrusion (Snort 3) | `fmc_get_intrusion_policy` (base, mode, usage, overridden rules), `fmc_find_intrusion_rules` (gid:sid, SID or text; per-policy state) |
| File / malware, network analysis | `fmc_get_file_policy` (settings and file rules; `catalog=true` lists file categories and types), `fmc_get_network_analysis_policy` (base, mode, access policies using it, inspector overrides) |
| Change management | `fmc_change_tickets` (status, tickets, a ticket's changes and validation) |
| Admin | `fmc_upgrade_status` (versions, upgrade history, packages), `fmc_list_backups`, `fmc_get_health_policy`, `fmc_list_users`, `fmc_list_object_overrides` |
| Analysis | `fmc_rule_lookup`, `fmc_shadowed_rules`, `fmc_policy_audit` (ranked hygiene findings with a fix each), `fmc_threat_posture` (intrusion and file policies and modes, TRUST/fastpath bypasses, SI and DNS coverage, decryption, device licences; findings with a fix each), `fmc_export_access_rules` (rows or CSV, re-importable) |
| Policy bundles | `fmc_export_policy_bundle` (an access policy with everything it references, as versioned YAML), `fmc_diff_policy_bundle` (two bundles, or a bundle against live FMC), `fmc_plan_policy_bundle_import` (what an import would create, reuse, update or need first) |
| Deployment | `fmc_list_deployable_devices`, `fmc_pending_changes`, `fmc_list_deployments` |
| API spec | `fmc_search_spec`, `fmc_get_definition`, `fmc_api_call` (GET only) |

Notes on some read tools:

- `fmc_list_policies` covers access, NAT, prefilter, intrusion, file, platform settings, DNS,
  identity, decryption, health, FlexConfig and VPN policies.
- `fmc_find_object` finds objects by IP address, subnet or port. `fmc_find_address` answers "where does
  10.1.2.3 appear?" in one call: objects and the groups that hold it, dynamic-object mappings, access and
  prefilter rules (either side; literal, object, nested group or dynamic object), NAT rules, static routes
  (destination or gateway) and VPN protected networks and extranet peers, exact matches first, each with the
  object chain it was found through. Narrow it with `device`, `access_policy` or `nat_policy`.
- `fmc_rule_lookup` works out, offline, which access rule handles traffic from a source to a
  destination and port. `fmc_packet_tracer` asks the device itself (FMC runs packet-tracer; nothing
  is transmitted) and names the rule that allowed or dropped the packet and why.
- `fmc_get_ha_status` reads the pair from FMC and, by default, each unit's own failover state through FMC
  (`show failover`, `show failover state`, `show failover history`): per unit Active / Standby Ready / Failed,
  active time, interface and snort/disk status and last failure reason; failover and state link status,
  versions, stateful replication counters, the last failover with its reason, and `checks` with
  `ready_for_switch`. FMC's own unit states trail a failover by up to a minute. `live=false` skips the units.
- `fmc_run_show_command` runs the show commands FMC's API spec lists for `operational/commands` (read from
  the spec at run time, FMC 10.0.1's list built in): `show route [bgp|ospf|...]`, `show crypto ikev2 sa`,
  `show failover`, `show interface ip brief`, `show running-config <section>`... Words after the second go to
  FMC as parameters. Anything else (`show bgp`, `show ospf`, `show path-monitoring`, `show policy-route`,
  `show conn`, `show nat`) is refused before FMC is called, with the alternatives.
- `fmc_get_hit_counts` refreshes the counters from the device first (packet-tracer packets count too).
- `fmc_live_connections` answers "what is this host talking to right now?". FMC 10.0.1 refuses `show conn`
  over its API, so it reads the device's syslog buffer (`show logging`: connection built/teardown messages and
  Snort connection events with the rule, user and application); the device's platform settings must log to the
  internal buffer at level informational (the tool says so when they don't). Where FMC's spec lists `show conn`,
  the live connection table is used instead. `fmc_user_identity_sessions` reads FMC's identity view
  (`analysis/activesessions`, `analysis/useractivity`; the FTD has no `show user-identity`): the account's role
  needs Events & Logs > Analysis > Users.
- `fmc_prove_policy` proves a policy in one call: each flow (source, destination, port, protocol, optional user,
  device and expected rule) is traced on its device (given, or the one whose connected subnets and routes carry
  it) and judged `pass`, `fail`, `mismatch` (right verdict for the wrong reason: another rule, a non-policy drop
  such as no route or ARP, or another user on the source IP) or `error`. The `fmc_prove_user_policy` prompt
  builds on it for user rules (alice allowed, bob blocked).
- `fmc_list_health_alerts` and `fmc_recent_activity` query FMC when called (no background collection):
  health alerts over a window with repeats collapsed, and one timeline of health alerts, audit records
  and deployments. The server never receives syslog or eStreamer; traffic events stay in the FMC UI or
  the customer's SIEM.

**Write**

| Area | Tools |
|---|---|
| Objects | `fmc_create_object`, `fmc_update_object`, `fmc_delete_object`, `fmc_create_group`, `fmc_update_group`, `fmc_create_security_zone`, `fmc_import_objects` (bulk, validated) |
| Access control | `fmc_create_access_policy`, `fmc_create_access_rule`, `fmc_update_access_rule` (both take URL categories with a reputation level: `url_categories=[{category, reputation}]`), `fmc_delete_access_rule`, `fmc_import_access_rules` (bulk, validated) |
| Prefilter | `fmc_create_prefilter_policy`, `fmc_set_prefilter_policy` (link to an access policy), `fmc_create_prefilter_rule`, `fmc_update_prefilter_rule`, `fmc_delete_prefilter_rule` (FASTPATH / ANALYZE / BLOCK) |
| NAT | `fmc_create_nat_policy`, `fmc_create_nat_rule`, `fmc_update_nat_rule`, `fmc_delete_nat_rule` |
| Device configuration | `fmc_update_interface`, `fmc_create_subinterface`, `fmc_create_interface` (loopback, VTI, EtherChannel, BVI), `fmc_delete_interface`, `fmc_create_static_route`, `fmc_delete_static_route`, `fmc_assign_policy` |
| Routing | `fmc_configure_bgp`, `fmc_configure_ospf`, `fmc_create_vrf`, `fmc_delete_vrf` |
| SD-WAN application-aware routing | `fmc_configure_wan_interface` (priority, ICMP path monitoring to the next hop or an IP, HTTP application monitoring), `fmc_configure_ecmp_zone`, `fmc_create_app_route` (applications, networks, ports or users out of the WAN link picked by order, priority, or lowest jitter / loss / RTT or highest MOS), `fmc_delete_app_route`; `fmc_get_routing` shows the routes and WAN settings |
| Platform settings / logging | `fmc_create_platform_settings_policy`, `fmc_configure_syslog`, `fmc_set_access_logging`, `fmc_configure_ntp`, `fmc_configure_snmp` (v2c; community write-only), `fmc_configure_ssh_access` |
| Dynamic objects | `fmc_create_dynamic_object`, `fmc_delete_dynamic_object`, `fmc_map_dynamic_object` |
| File / malware | `fmc_create_file_policy`, `fmc_create_file_rule` (DETECT, BLOCK, MALWARE_CLOUD_LOOKUP, BLOCK_MALWARE, with or without reset; by protocol, direction, file type and category), `fmc_delete_file_rule`; on ALLOW rules: `fmc_create_access_rule` / `fmc_update_access_rule(file_policy=...)` |
| Network analysis | `fmc_create_network_analysis_policy` (on a base policy; an access policy selects it in the UI, FMC's REST API has no field for that) |
| Intrusion tuning | `fmc_set_intrusion_rule_state` (ALERT/BLOCK/DROP/REJECT/PASS/DISABLE/DEFAULT per policy), `fmc_create_intrusion_policy`, `fmc_create_intrusion_rule` / `fmc_delete_intrusion_rule` (custom Snort 3 rules); `fmc_update_access_rule(intrusion_policy=...)` |
| Change management | `fmc_ticket` (open / submit / discard / release; an open ticket is sent as `ticket-id` with every change) |
| Decryption | `fmc_create_decryption_policy` / `fmc_update_decryption_policy` (default action, trusted CAs, TLS 1.3 decryption, untrusted issuers), `fmc_create_decryption_rule` (DECRYPT_RESIGN with an internal CA, DECRYPT_KNOWN_KEY, DO_NOT_DECRYPT, BLOCK, MONITOR; `insert_before`), `fmc_delete_decryption_rule`, `fmc_set_decryption_policy` |
| TLS certificates | `fmc_create_internal_ca` (FMC generates the key: self-signed, or a CSR for your CA), `fmc_install_internal_ca_cert` (the signed certificate for that CSR), `fmc_import_certificate_files` (an existing CA or server certificate + key read from `FMC_PKI_DIR` on the server host; only file names pass through MCP), `fmc_delete_certificate` |
| Identity (AD/LDAP) | `fmc_create_trusted_ca` (CA for LDAPS), `fmc_create_realm` (bind password write-only), `fmc_download_realm` (users and groups now; needs `FMC_UI_USERNAME`), `fmc_delete_realm`, `fmc_create_identity_policy`, `fmc_create_identity_rule` (PASSIVE / ACTIVE / NO), `fmc_delete_identity_rule`; access rules on users and groups: `fmc_create_access_rule` / `fmc_update_access_rule` `users=[...]` |
| DNS | `fmc_create_dns_policy`, `fmc_set_dns_policy`, `fmc_dns_block` (block/unblock domains via custom SI DNS lists; NXDOMAIN or drop) |
| Licences | `fmc_set_device_licenses` (IPS, MALWARE_DEFENSE, URL, ...) |
| Admin | `fmc_update_health_policy` (module on/off, thresholds), `fmc_set_object_override` (per-device object values) |
| Containment | `fmc_contain_host`, `fmc_release_host` (instant, no deploy); `fmc_si_block` (Security Intelligence block list for IPs, networks, URLs; logged; needs a deploy) |
| Security Intelligence feeds and lists | `fmc_create_si_feed` (IP, URL or DNS feed FMC downloads on a schedule), `fmc_upload_si_list` (custom list from text, validated; replaces its own lists), `fmc_set_si_lists` (feeds, custom lists and Talos categories into an access policy's SI block or do-not-block list; DNS ones into its DNS policy as block, allow or monitor rules), `fmc_delete_si_object` |
| HA | `fmc_configure_ha_monitoring` (monitored interfaces, standby IPs, failover MACs) |
| VPN | `fmc_create_s2s_vpn` (point-to-point IKEv2 PSK; policy- or route-based), `fmc_delete_s2s_vpn`; SD-WAN: `fmc_create_sdwan_topology` (wizard hub and spoke: hub DVTI, spoke pool, spokes on their WAN interfaces, backup hub, a second WAN tunnel per spoke through the companion topology `<name>-wan2`, iBGP overlay), `fmc_update_sdwan_topology` (add or remove spokes, their second WAN and the backup hub, ECMP) |
| VPN | `fmc_create_s2s_vpn` (point-to-point IKEv2 PSK; policy- or route-based), `fmc_delete_s2s_vpn` |
| Device templates | `fmc_create_device_template` (generated from a standalone FTD, or empty from a firewall mode and access policy), `fmc_delete_device_template` |

`fmc_create_access_rule` takes a position (`insert_before` or `insert_after`), a section and a
category. `fmc_update_access_rule` can move a rule with `move_to`. `fmc_update_interface` sets the
logical name, zone, IPv4 (static or DHCP), MTU and admin state of any existing interface;
`fmc_create_interface` adds loopbacks, static or dynamic VTIs (own /30 or a borrowed loopback address),
EtherChannels (LACP active/passive or static) and BVIs, checking members, used names and ids, and
overlapping subnets in the preview.
`fmc_map_dynamic_object` changes take effect on the devices **without a deployment** (only the rule
that references the object needs one). `fmc_configure_bgp` refuses to edit BGP while a neighbor has an
MD5 password, because FMC returns it masked and a PUT would replace it, unless you re-enter it with
`neighbor_password`.

**Dangerous (plus raw `fmc_api_call`)**

| Tool | What it does |
|---|---|
| `fmc_deploy` | Deploys pending changes and waits for the deployment task to finish. |
| `fmc_rollback_deployment` | Rolls a device back to an earlier successful deployment. |
| `fmc_register_device` | Registers a device with FMC and waits for the initial deployment. |
| `fmc_delete_device` | Removes a device from FMC. |
| `fmc_create_ha_pair` | Forms an HA pair: the failover link, and state replication over it or over a separate state link (`state_interface`). |
| `fmc_ha_action` | Breaks, switches or deletes an HA pair. |
| `fmc_delete_policy` | Deletes a whole policy. |
| `fmc_backup_devices` | Backs up device configurations to FMC (not supported on FTDv). |
| `fmc_apply_device_template` | Applies a device template to one standalone FTD with its variable values and object overrides (replaces its interface, routing, policy and VPN/SD-WAN configuration); the preview lists every variable and override. |

### Workflows

- **Onboard an FTD:** on the device, `configure manager add <fmc> <key>`; then `fmc_register_device`
  -> `fmc_update_interface` (name, zone, IP) -> `fmc_create_static_route` -> NAT policy and rules ->
  `fmc_assign_policy` -> `fmc_deploy` -> `fmc_run_show_command` to verify. FMC needs Smart Licensing or
  evaluation mode before it accepts devices.
- **Change safely:** change -> `fmc_pending_changes` -> `fmc_deploy` -> verify ->
  `fmc_rollback_deployment` if needed.
- **Why is this traffic blocked?** The `fmc_why_blocked` prompt runs `fmc_rule_lookup` ->
  `fmc_packet_tracer` -> `fmc_get_hit_counts` -> `fmc_pending_changes` / `fmc_list_deployments` ->
  `fmc_list_audit_records`, then proposes a preview-first fix.
- **Prove a user-based policy:** the `fmc_prove_user_policy` prompt checks each user offline
  (`fmc_rule_lookup` with identities), who ISE sees on the client, then has each user log in and proves the live
  verdict with `fmc_prove_policy` (deciding rule and the user the firewall saw), ending in a pass/fail table.
- **Block a host now:** `fmc_contain_host(ip, reason)` maps it into the quarantine dynamic object
  (`FMC_QUARANTINE_OBJECT`); the first call proposes the BLOCK rules and one deploy, later calls need no
  deployment. `fmc_release_host(ip)` undoes it. ise-mcp-server's `ise_quarantine_host` calls these.
- **Onboard an FTD, guided:** the `fmc_onboard_ftd` prompt (optionally builds the FTDv in CML first;
  with `template`, a device template configures it).
- **Roll out a branch from a template (FMC 7.6+):** `fmc_create_device_template(source_device=<a working
  branch>)` -> `fmc_get_device_template` (check the variables FMC created) -> `fmc_register_device` (the
  new FTD) -> `fmc_apply_device_template(template, device, variables, overrides)` -> `fmc_deploy` the branch
  and its hub(s) -> `fmc_get_vpn_topology`. Templates apply to standalone devices only.
- **HA:** `fmc_create_ha_pair` -> `fmc_configure_ha_monitoring` (standby IPs) -> `fmc_deploy` (the pair's
  name) -> `fmc_get_ha_status` / `show failover`; `fmc_ha_action` switch, break or delete.
- **Site-to-site VPN:** `fmc_create_s2s_vpn` -> `fmc_deploy` both peers -> `fmc_vpn_status` (tunnels, SAs and
  routes over the VTIs per device, degraded first) or `fmc_list_vpn_tunnels`. In FMC
  evaluation mode only DES crypto deploys; the tool picks it and says so.
- **SD-WAN branches:** zone the WAN and inside interfaces (`fmc_update_interface`) -> `fmc_create_sdwan_topology`
  (creates the hub's loopback, DVTI and spoke pool when missing, then the AUTO_VPN topology, IKEv2 and the
  endpoints; a failed step deletes what it created) -> `fmc_deploy` hubs and spokes -> `fmc_get_vpn_topology`,
  `show route bgp`. New branch: `fmc_update_sdwan_topology add_spokes=[...]`, then deploy the spoke and the hubs.
- **"The VPN to X is down":** the `fmc_vpn_troubleshoot` prompt starts from `fmc_vpn_status` and walks IKE (key
  mismatch vs dead path), IPsec (one-way traffic), routing over the tunnel, NAT exemption and access rules
  (`fmc_packet_tracer`, `fmc_rule_lookup`), then proposes one previewed fix.
- **Onboard an SD-WAN branch, end to end:** the `fmc_onboard_branch` prompt (dangerous tier) registers the FTD
  (the key comes from the server's `FMC_FTD_REG_KEY`, never from the conversation), configures it from a device
  template when one fits or by hand (interfaces and zones, underlay route, NAT, access policy, the hubs' return
  path), adds it with `fmc_update_sdwan_topology`, deploys the hubs and the branch by name, verifies the tunnel,
  overlay routes and a policy flow, and ends with a hand-off record of flows for `fmc_prove_policy`.
- **"Teams is slow at branch Y":** the `fmc_sdwan_troubleshoot` prompt walks `fmc_sdwan_status` (path metrics,
  degraded links) -> the app-route rule and the interface it picks now -> the overlay tunnels and BGP ->
  `fmc_packet_tracer`, then proposes one previewed fix.
- **Was the branch firewall busy during the outage?** `fmc_device_metrics(device, since='2026-10-18T09:30:00Z',
  until='2026-10-18T10:00:00Z')`: CPU, memory, throughput, connections and drops with their peaks.
- **What changed or broke in the last hour?** `fmc_recent_activity`.
- **Is everything healthy?** The `fmc_firewall_health_review` prompt checks devices, HA, deployments,
  licences, content versions, backups, VPN and recent alerts, and ranks the findings (critical, warning,
  info) with a next step for each.
- **Does the HA pair fail over cleanly?** The `fmc_ha_failover_check` prompt runs the pre-checks
  (`fmc_get_ha_status`: standby ready, links, monitored interfaces, config sync), a traffic baseline (packet
  tracer, and pings from a CML host with a loss series), the switch (`fmc_ha_action`, or in a lab the active
  unit powered off), then verifies roles, failover history and its reason, and reports the outage.
- **Is this rule change safe?** The `fmc_rule_change_review` prompt baselines the policy, runs sample flows
  through `fmc_rule_lookup` before and after, checks shadowing and overlap, previews the change and plans the
  deploy with a rollback.
- **Clean up a policy:** the `fmc_policy_cleanup` prompt turns `fmc_policy_audit` findings into grouped,
  approved changes, verifies them with `fmc_diff_policy_bundle` against a baseline bundle and a re-audit, and
  keeps the baseline for `fmc_import_policy_bundle` as a rollback.
- **How well does this policy stop threats?** The `fmc_threat_defense_review` prompt combines
  `fmc_threat_posture` (intrusion and file policies and their modes, TRUST and fastpath bypasses, SI and DNS
  coverage, decryption, device licences) with `fmc_policy_audit`, `fmc_get_security_intelligence` (feed status)
  and `fmc_get_intrusion_policy`, and ranks the findings with a fix and the tool that applies it.
- **Threat feeds and lists:** `fmc_create_si_feed` or `fmc_upload_si_list` -> `fmc_set_si_lists` (block,
  allow; DNS also monitor) -> `fmc_deploy` -> `fmc_get_security_intelligence` (entries and last update).
- **TLS decryption (decrypt-resign):** `fmc_create_internal_ca` (FMC generates the key) -> install its
  certificate (`fmc_get_certificate`) as a trusted root on the clients -> `fmc_create_decryption_policy`
  (`tls13_decryption=true`; `trusted_cas` for private server PKIs) -> `fmc_create_decryption_rule`
  (DO_NOT_DECRYPT exemptions first, then DECRYPT_RESIGN with `internal_ca`) -> `fmc_set_decryption_policy` ->
  `fmc_deploy`; `fmc_tls_decryption_check` says what one flow gets and what is missing. An existing CA or
  server key: `fmc_import_certificate_files` reads it from `FMC_PKI_DIR`, so a private key never travels
  through MCP arguments or results.
- **PoC to production:** `fmc_export_policy_bundle` -> `fmc_plan_policy_bundle_import` in the target domain or
  FMC -> `fmc_import_policy_bundle` -> `fmc_diff_policy_bundle` -> assign and `fmc_deploy`.
- **Rules on AD users and groups:** `fmc_create_trusted_ca` (for LDAPS) -> `fmc_create_realm` ->
  `fmc_test_realm` -> `fmc_download_realm` -> `fmc_create_identity_policy` + `fmc_create_identity_rule`
  (PASSIVE: user-IP mappings from ISE/pxGrid or an identity agent) -> select the identity policy in the
  access policy editor's Identity step (FMC 10.0's REST API silently ignores `identityPolicySetting`) ->
  `fmc_create_access_rule(users=['group'])` -> `fmc_deploy`. `fmc_rule_lookup` evaluates user/group rules
  offline with the user FMC has on the source IP and their groups (or `identities=[user, groups]`). FMC's REST API has no AD/LDAP realm test or download, so those two
  tools log in to FMC's web UI as `FMC_UI_USERNAME` (its own user, not the API user).
- **ISE as the identity source (pxGrid):** FMC 10.0.1's REST API can't configure the ISE connection, so it is
  set in the FMC UI (Integrations > Other Integrations > Identity Sources: pxGrid node, pxGrid and MNT server
  CAs from `fmc_create_trusted_ca`, FMC's client certificate as an internal certificate), then FMC's pxGrid
  client is approved in ISE. `fmc_get_identity_sources` shows whether it works end to end (FMC's ISE health
  module, SGTs downloaded, sessions by source, user-IP bindings on each device, certificate expiry) and what
  to fix; `fmc_user_ip_lookup` answers "who is on 192.0.2.57?" and "where is alice?". Reading FMC's identity
  sessions needs Events & Logs > Analysis > Users in the account's role.
- **Baseline a policy and see what changed:** `fmc_export_policy_bundle(policy)` returns one YAML bundle
  (schema 1): the access policy's settings and ordered rules, its prefilter, decryption, identity, NAT and
  intrusion policies (custom ones in full, built-in ones by name), and every object, group member, zone,
  interface group and time range it uses, keyed by name with ids stripped. Re-exporting an unchanged policy
  gives the same `digest` and the same text apart from `meta.exported_at`. Later,
  `fmc_diff_policy_bundle(a=<bundle>)` compares it with the live policy (or `b=` another bundle, e.g. from
  another domain or FMC): added, removed, changed (field by field) and moved items per section. One export
  of `mcp-test-acp` costs about 16 requests. With `FMC_BUNDLE_DIR` set, each export is also written there
  and both tools accept a bundle's file name; unset (the default, right for shared hosts) nothing is
  written.
- **Send FTD logs to a SIEM:** `fmc_configure_syslog` -> `fmc_assign_policy(kind='platform_settings')`
  -> `fmc_deploy` -> `fmc_run_show_command('show running-config logging')`.

Tools accept **names or UUIDs**. Rule conditions accept object names or literal values:

- addresses, subnets and ranges: `10.1.1.0/24`, `10.1.1.1-10.1.1.9`
- ports and protocols: `tcp/443`, `udp/1000-2000`, `icmp/8`
- URLs: `https://...`

### Multi-domain FMC (F19)

Every tool takes `domain=` (a name such as `Global/Branch`, a unique leaf name such as `Branch`, or a UUID),
defaulting to `FMC_DOMAIN` or the login's domain. `fmc_list_domains` shows the tree: parent, whether a domain
is a leaf, and the devices in each one. FMC's rules, which the tools follow:

- **Devices live only in leaf domains.** An ancestor domain sees them, but FMC refuses changes there
  ("Object does not belong to current domain"). Device tools called in an ancestor domain therefore send
  device-level calls (interfaces, routes, routing, HA, packet tracer) to the device's own leaf domain, and
  the preview shows it as `device_domain`. Deploys work from the ancestor.
- **Objects and policies are inherited downwards, read-only.** A leaf sees Global's objects and policies but
  can't change them: the preview is blocked and names the domain to use. Objects created in a leaf are not
  visible in Global.
- Every write preview shows the `domain` it changes.
- The API user's role applies to the domain where it is assigned and the domains below it.
- Several FMCs per server: core `FMC_INSTANCES` (an `instance` argument on every tool).


### Limits of `fmc_rule_lookup`, `fmc_shadowed_rules` and `fmc_policy_audit`

Both tools evaluate the access control policy offline. They resolve network and port objects,
including nested groups, to ranges, then walk the rules in order. The results are best-effort:

- They don't evaluate prefilter rules, NAT, Security Intelligence, decryption or rules inherited
  from a parent policy.
- Some rules depend on things that can't be known from addresses and ports: applications, URLs,
  users, SGTs, VLAN tags, dynamic objects and time ranges. These rules are reported as
  **conditional** ("may match first").
- FQDN objects and ICMP codes are not resolved, so rules that use them are also conditional.
- Zones are only checked when you pass `source_zone` or `destination_zone`.
- MONITOR rules are reported, but evaluation continues past them.
- `fmc_policy_audit` judges unused rules from hit counts summed across the assigned devices (HA members
  included, clusters not). Counters reset when a device reloads, packet-tracer runs count as hits, and a device
  FMC can't reach is reported in `notes` and left out.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `FMC_URL` | (required) | FMC address, e.g. `https://fmc.example.com` |
| `FMC_USERNAME`, `FMC_PASSWORD` | (required) | The API account (see below) |
| `FMC_VERIFY_SSL` | `true` | Verify FMC's TLS certificate. Set `false` only in labs. |
| `FMC_CA_BUNDLE` | | CA file for FMC's certificate |
| `FMC_DOMAIN` | the login's domain | Default domain: a name (`Global/Branch`) or a UUID |
| `FMC_RATE_LIMIT` | `110` | Client-side requests per minute. FMC allows about 120 per source IP. |
| `FMC_MAX_CONCURRENCY` | `8` | Concurrent requests. FMC allows 10 per source IP. |
| `FMC_TIMEOUT`, `FMC_RETRIES` | `30`, `2` | Request timeout in seconds, and retries |
| `FMC_QUARANTINE_OBJECT` | `mcp-quarantine` | Dynamic object that `fmc_contain_host` / `fmc_release_host` map hosts into |
| `FMC_DEPLOY_WINDOW` | off | Maintenance window for changes that reach devices (deploy, rollback, register, delete device, HA). Same syntax as `MCP_CHANGE_WINDOW`. See "Deploy safety rails". |
| `FMC_TICKET` | | Change-management ticket id sent with every request (FMC 7.6+ change management; `fmc_ticket` sets it at run time) |
| `FMC_UI_USERNAME`, `FMC_UI_PASSWORD` | | Optional FMC web-UI user for `fmc_test_realm` / `fmc_download_realm` (role with Integrations > Realms modify). Must differ from `FMC_USERNAME`: a UI login ends the same user's REST session. |
| `FMC_BUNDLE_DIR` | off | Directory `fmc_export_policy_bundle` also writes bundles to (and `fmc_diff_policy_bundle` reads bundle file names from). Off: bundles are only returned inline. |
| `FMC_PKI_DIR` | off | Directory on the server host that `fmc_import_certificate_files` reads PEM certificate, key and passphrase files from (keys never pass through MCP). Off: file imports are refused; `fmc_create_internal_ca` still works (FMC generates the key). In Docker, bind-mount it read-only (see `docker-compose.yml`). |
| `FMC_ALLOW_IGNORE_WARNING` | `false` | Allow `fmc_deploy(ignore_warning=true)` (the preview must then list the FMC warnings being ignored) |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `MCP_HOST`, `MCP_PORT`, `MCP_PATH` | `0.0.0.0`, `8000`, `/mcp` | HTTP listener |
| `MCP_AUTH_TOKENS` / `MCP_AUTH_TOKENS_FILE` | | Required for HTTP: `name:sha256:<hex>` entries |
| `MCP_ENABLE_WRITES`, `MCP_ENABLE_DANGEROUS` | `false` | Tool tiers |
| `MCP_CONFIRM_TTL` | `600` | Seconds a confirm token stays valid |
| `MCP_TASK_TIMEOUT` | `600` | Seconds to wait for deployment, registration and HA tasks |
| `MCP_CACHE_DIR` | `~/.cache/fmc-mcp-server` | Cache for the indexed API spec. Set it to `""` to disable the cache. |
| `MCP_MAX_RESPONSE_CHARS` | `40000` | Maximum size of one tool response |
| `MCP_AUDIT_LOG`, `LOG_LEVEL` | `stderr`, `INFO` | Where the audit log goes, and the log level |
| `MCP_ROLES` / `MCP_ROLES_FILE`, `MCP_DEFAULT_ROLE` | off, `ro` | Per-caller roles (`ro`/`rw`/`admin`) on top of the tiers (core `docs/PRODUCTION.md`) |
| `MCP_DRY_RUN`, `MCP_CHANGE_WINDOW`, `MCP_DENY_TOOLS`, `MCP_MAX_BLAST_RADIUS`, `MCP_BLAST_RADIUS_OVERRIDES`, `MCP_TWO_PERSON_TOOLS` | off | Core safety rails (core `docs/PRODUCTION.md`); see "Deploy safety rails" |

### Sessions and rate limits

FMC access tokens last 30 minutes and can be refreshed three times. **Every new login for a user can
end that user's other API sessions.** To avoid that, the server:

- logs in once and shares the token across concurrent requests;
- refreshes the token before it expires, and logs in again only when it has to;
- waits 30 seconds after a failed login before trying again, so bad credentials can't lock the
  account.

Give the server its **own FMC user**.

The client-side rate limiter keeps the server under FMC's per-source-IP limits. It is shared by every caller
of the server, and FMC's 120 requests/minute are shared by every API user of that FMC: on a shared host see
[docs/deploying.md](docs/deploying.md) (one FMC user per server instance, the request budget).

### Deploy safety rails (F18)

All off by default. A production setup could be:

```bash
MCP_BLAST_RADIUS_OVERRIDES=fmc_deploy=1,fmc_rollback_deployment=1   # one device per deploy (an HA pair counts as 2)
FMC_DEPLOY_WINDOW="Sat 22:00-04:00 Australia/Sydney"                # deploys only in the maintenance window
FMC_ALLOW_IGNORE_WARNING=false                                     # the default: fix FMC's warnings instead
MCP_TWO_PERSON_TOOLS=fmc_deploy,fmc_rollback_deployment,fmc_ha_action
MCP_ENABLE_DANGEROUS=false   # or MCP_DENY_TOOLS=fmc_api_call: no raw non-GET calls
```

- **Device count:** `fmc_deploy`, `fmc_rollback_deployment`, `fmc_register_device`, `fmc_delete_device`,
  `fmc_create_ha_pair` and `fmc_ha_action` report a blast radius in **physical devices**: an HA pair counts 2,
  a cluster its members. Core's `MCP_MAX_BLAST_RADIUS` / `MCP_BLAST_RADIUS_OVERRIDES` block anything larger
  (deploy per device or per pair instead).
- **Deploy window:** `FMC_DEPLOY_WINDOW` blocks those six tools outside the window; object and policy edits
  stay possible, because they reach devices only with a deploy. Core's `MCP_CHANGE_WINDOW` gates *every* write.
  Containment (`fmc_contain_host`, dynamic-object mappings) is deliberately not gated: it is incident response.
- **`ignore_warning`:** refused unless `FMC_ALLOW_IGNORE_WARNING=true`. Even then you can only ignore warnings
  you have seen: deploy without it first (FMC refuses with its warnings, nothing is deployed), then the
  `ignore_warning=true` preview lists each FMC warning verbatim, for the same devices and pending version.
  At confirm the server tries once more without ignoring: if FMC's warnings differ from the previewed ones,
  nothing is deployed. The deploy window is also re-checked at confirm.
- **Rollback:** defaults to the deployment before the current one; with an older `to_job` the preview lists
  every deployment it undoes.
- **Previews** name the domain and the devices (with HA/cluster unit counts).
- **Raw API calls:** `fmc_api_call` is GET-only unless the dangerous tier is on; keep it off in production or
  deny the tool with `MCP_DENY_TOOLS=fmc_api_call`.

### Least-privilege FMC account

Give the server its own FMC user with a custom role; never `admin`. [docs/least-privilege.md](docs/least-privilege.md)
has the tested role definitions (`mcp-ro` for the read tier, `mcp-rw` for writes and deploys), the 403
matrix, and the GUI steps to create the roles and users (FMC's REST API can't). Use one
user per running copy (container, CLI, tests, people): a login ends the same user's other sessions.

The REST API must be enabled under **Administration > Configuration > REST API Preferences**.

## Running from source

```bash
git clone https://github.com/dr-stutters/fmc-mcp-server && cd fmc-mcp-server
python3 scripts/bundle_core.py vendor       # bundles the pinned stutters-mcp-core as fmc_mcp._core (needs git)
uv sync
cp .env.example .env && chmod 600 .env      # set FMC_URL, FMC_USERNAME, FMC_PASSWORD
uv run fmc-mcp-server check                 # preflight (see the quickstart)
uv run fmc-mcp-server                       # run the stdio server
```

The shared [stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core) library is **bundled** into the
package as `fmc_mcp._core` (core ADR-005): the wheel, the sdist and the Docker image need nothing but their PyPI
dependencies, with no git dependency and no token. `uv build` writes a wheel that installs on its own
(`pip install dist/fmc_mcp_server-*.whl`); every GitHub release has one attached. The pinned core tag is
`[tool.bundle-core]` in `pyproject.toml` and `fmc_status` reports it as `core_version`. The vendored copy is
generated, not committed: `scripts/bundle_core.py vendor` writes it, `check` reports drift, and
`update --tag vX.Y.Z` moves the pin (then `uv lock`). A plain git checkout has no `fmc_mcp/_core`, so install
from a release wheel rather than `git+https://...`.

## Docker

```bash
docker run --rm ghcr.io/dr-stutters/fmc-mcp-server fmc-mcp-server token alice   # bearer token + its MCP_AUTH_TOKENS entry
# add MCP_AUTH_TOKENS=alice:sha256:... to .env
docker compose up -d                        # pulls ghcr.io/dr-stutters/fmc-mcp-server (MCP_IMAGE_TAG, default latest)
docker compose up -d --build                # or build from this checkout (no token: core is bundled)
curl http://localhost:8035/health
```

The compose file publishes port 8035 and runs the container as non-root with a read-only root filesystem, no
capabilities and a named volume for the spec cache. It is **read-only** unless `.env` sets
`MCP_ENABLE_WRITES=true` (and `MCP_ENABLE_DANGEROUS=true` for deploys). Shared hosts (TLS, several FMCs,
per-user tokens, the rate budget, upgrades): [docs/deploying.md](docs/deploying.md).

Connect Claude Code to the container:

```bash
claude mcp add --transport http fmc http://<host>:8035/mcp --header "Authorization: Bearer <token>"
```

## Development

```bash
uv run ruff check && uv run ruff format --check && uv run mypy && uv run pytest
uv run pytest tests/live -m live           # live tests; the whole run uses a single FMC login
# FTD, domain and realm inputs come from FMC_LIVE_* variables (docs/live-tests.md); unset = skipped
uv run python scripts/capture_fixtures.py  # refresh the redacted fixtures in tests/fixtures (--ftd: device ones)
```

The live write tests create `mcp-test-w-*` objects and policies, then delete them. [docs/live-tests.md](docs/live-tests.md) lists
the `FMC_LIVE_*` variables, what the FTD tests expect and the seeded `mcp-test-*` objects.

The live FTD tests onboard (or re-check) the FTD, configure interfaces, zones, a default route and
NAT, deploy and verify with show commands, run packet tracer and hit counts, and deploy and roll back a
subinterface. HA and clustering need two FTDs and are covered by unit tests with mocked FMC replies.

## License

MIT

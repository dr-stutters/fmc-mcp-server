# fmc-mcp-server

An MCP server for **Cisco Secure Firewall Management Center (FMC)**. It lets an AI assistant read
and change FMC through its REST API: device onboarding, interfaces and routes, access control and NAT
policies, objects, deployments (with rollback), HA pairs and the audit log. Its troubleshooting tools
answer "why is this traffic blocked?" (packet tracer, offline rule lookup, hit counts), "did my
change land?" (show commands on the FTD) and "where is this object used?".

It is built on [stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core) and runs either
over stdio for a local client or as an authenticated Streamable HTTP service in a container.

> **Disclaimer.** This is not an official Cisco product or repository, and it isn't supported or endorsed by
> Cisco. It's a personal project by [@dr-stutters](https://github.com/dr-stutters), for lab and learning use
> only: don't point it at production systems. It's provided as is, with no warranty (see the
> [license](LICENSE)). Cisco, Firepower and Secure Firewall are trademarks of Cisco Systems, Inc.

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
WHEEL=https://github.com/dr-stutters/fmc-mcp-server/releases/download/v0.18.0/fmc_mcp_server-0.18.0-py3-none-any.whl
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
      "args": ["--from", "https://github.com/dr-stutters/fmc-mcp-server/releases/download/v0.18.0/fmc_mcp_server-0.18.0-py3-none-any.whl", "fmc-mcp-server"],
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

There are 238 tools when every tier is enabled (93 read, 129 write, 16 dangerous; the dangerous tier turns `fmc_api_call` into a raw call), and fourteen workflow prompts (`fmc_why_blocked`, `fmc_firewall_health_review`, `fmc_sdwan_troubleshoot`, `fmc_vpn_troubleshoot`, `fmc_threat_defense_review`, `fmc_prove_user_policy`, `fmc_compliance_evidence`, `suite_change_check`; `fmc_rule_change_review` and `fmc_policy_cleanup`, write tier; `fmc_onboard_ftd`, `fmc_onboard_branch`, `fmc_ha_failover_check` and `fmc_replace_device`, dangerous tier). `FMC_TOOLSETS` loads only some areas of them (see "Toolsets").

**Read**

| Area | Tools |
|---|---|
| System | `fmc_status`, `fmc_list_domains`, `fmc_list_audit_records`, `fmc_get_task`, `fmc_license_status` |
| Activity (on demand) | `fmc_list_health_alerts`, `fmc_recent_activity` |
| Devices | `fmc_list_devices`, `fmc_get_device`, `fmc_list_device_interfaces`, `fmc_list_routes`, `fmc_get_routing`, `fmc_get_platform_settings`, `fmc_list_ha_pairs`, `fmc_get_ha_status`, `fmc_list_clusters`, `fmc_list_device_groups` (members; a group goes wherever devices do: `group:<name>`) |
| VPN | `fmc_list_vpn_topologies` (incl. SD-WAN), `fmc_get_vpn_topology`, `fmc_get_ravpn`, `fmc_vpn_status` (every site-to-site topology's tunnels with each device's IKE and IPsec SAs, traffic each way, last rekey and the routes over the VTIs; degraded tunnels first), `fmc_sdwan_status` (per branch: WAN links with path metrics, the path each app route takes now and why, tunnels and iBGP, ranked degraded links) |
| Device templates (FMC 7.6+) | `fmc_list_device_templates`, `fmc_get_device_template` (interfaces, variables, model mappings, VPN/SD-WAN settings, overridable objects, devices it was applied to; passwords masked) |
| Troubleshooting | `fmc_packet_tracer` (`ingress_hop` / `expect_next_hop`: the FTD leg of an SD-WAN service chain, `chain_leg` says where the flow entered and whether it leaves back to the edge), `fmc_service_chain_check` (an FTD as a Catalyst SD-WAN service-chain firewall: interfaces on the edge links, link state, zones, routes back to the edge, the access policy's verdict for the chained flows, each failure with its fix tool), `fmc_run_show_command` (one device, or up to 25 at once: `devices`, HA pairs, a device `group`; a row per device), `fmc_get_hit_counts`, `fmc_device_health`, `fmc_device_metrics` (CPU, memory, throughput, connections and drops over a window: min/avg/max, peaks, dips and a compact series), `fmc_list_vpn_tunnels`, `fmc_live_connections` (a host's or user's connections on one FTD: peers, state, bytes, duration, rule, user), `fmc_user_identity_sessions` (who is on an IP, where a user is logged in), `fmc_prove_policy` (a table of flows with expected verdicts, each packet-traced on the FTD it crosses: pass / fail / mismatch with the deciding rule and the user the device saw), `fmc_get_profiler_results` (a Snort rule or CPU profiler run's result) |
| Policies | `fmc_list_policies`, `fmc_get_access_policy` (base policy chain, lock holder, rule categories), `fmc_list_access_rules`, `fmc_get_access_rule`, `fmc_list_nat_rules`, `fmc_list_prefilter_rules`, `fmc_list_policy_assignments` |
| Objects | `fmc_list_objects`, `fmc_get_object`, `fmc_find_object`, `fmc_where_used`, `fmc_unused_objects`, `fmc_list_dynamic_objects`, `fmc_find_address` (one IP, network or range across objects and groups, dynamic-object mappings, access, prefilter and NAT rules, static routes and VPN endpoints, ranked), `fmc_find_application` (an application by exact name or app id with its risk, business relevance and categories; application filters; attribute values for `fmc_create_application_filter`) |
| Security Intelligence | `fmc_get_security_intelligence` (block and do-not-block lists, the DNS policy's rules, and each feed's and custom list's entries, last update and status; without a policy: every SI feed and custom list), `fmc_find_indicator` (one domain or URL across FQDN and URL objects and groups, access and decryption rules, each access policy's SI URL lists, DNS policy rules and the SI feeds and lists holding it, ranked like `fmc_find_address`; a file hash gets the answer that FMC's file lists and TID observables aren't searched) |
| Decryption / DNS | `fmc_get_decryption_policy` (rules in order with their TLS versions and cipher suite lists, trusted CAs, TLS 1.3, undecryptable actions, default-action logging, access policies using it, `readiness`), `fmc_list_cipher_suite_lists` (each list's weak and strong suites; `known_suites` lists what can go in one), `fmc_get_certificate` (internal CAs, internal certificates, trusted CAs: expiry, pending CSR, PEM to install on clients, where used; private keys never shown), `fmc_list_certificates` (every certificate FMC holds: device enrolments with their deployment and identity/CA status, internal certificates and CAs, trusted CAs, external certificates; ISO, OpenSSL and epoch dates normalised to `days_left` and a severity, critical at 30 days and warning at 90; `expiring_within_days`), `fmc_tls_decryption_check` (what decryption does to one flow, what TLS version and cipher suite rules would match, which undecryptable action applies when the flow can't be decrypted, and what a decrypt-resign rollout still lacks), `fmc_get_dns_policy` |
| Identity (AD/LDAP, ISE) | `fmc_get_realm` (directories, downloaded users and groups), `fmc_test_realm` (bind test from FMC; needs `FMC_UI_USERNAME`), `fmc_get_identity_policy` (rules, access policies using it), `fmc_get_identity_sources` (ISE/pxGrid connection, SGT download, realms, identity policies, sessions by source, per-device user-IP bindings, certificate expiry, what to fix), `fmc_user_ip_lookup` (who is on an IP / where a user is, with the user's realm groups) |
| Intrusion (Snort 3) | `fmc_get_intrusion_policy` (base, mode, usage, rule counts per state, rule recommendations, overridden rules), `fmc_find_intrusion_rules` (gid:sid, SID or text; per-policy state) |
| File / malware, network analysis | `fmc_get_file_policy` (settings and file rules; `catalog=true` lists file categories and types), `fmc_get_network_analysis_policy` (base, mode, access policies using it, inspector overrides) |
| Change management | `fmc_change_tickets` (status, tickets, a ticket's changes and validation) |
| Admin | `fmc_upgrade_status` (versions, upgrade history, packages), `fmc_list_backups`, `fmc_get_health_policy`, `fmc_list_users`, `fmc_list_object_overrides` |
| Analysis | `fmc_rule_lookup`, `fmc_shadowed_rules`, `fmc_policy_audit` (ranked hygiene findings with a fix each), `fmc_threat_posture` (intrusion and file policies and modes, TRUST/fastpath bypasses, SI and DNS coverage, decryption, device licences; findings with a fix each), `fmc_export_access_rules` (rows or CSV, re-importable; `evidence=true`: per rule its hits per device with first/last hit, logging, intrusion/file policy, last change and user from FMC's audit log, the deployment that pushed it, comments, the change ticket when change management is on, plus the policy's SI/DNS state) |
| Compliance | `fmc_hardening_check` (a device or platform settings policy against a YAML baseline, default `ftd-hardening-v1` = [docs/baselines/ftd-hardening.yaml](docs/baselines/ftd-hardening.yaml), editable, each check with its source: SSH/HTTPS/ICMP access, SNMPv3, syslog and RFC 5424, NTP, banner, external authentication, DNS, HA interface monitoring, rule/VDB age, licences, backups, pending deployments; ranked findings, each with the existing tool that fixes it); prompt `fmc_compliance_evidence` (the auditor's evidence pack for one access policy) |
| Device configuration | `fmc_export_device_config` (one FTD or HA pair by section: interfaces, routing, assigned policies, NAT rules, platform settings, VPN memberships, object overrides, out-of-band changes, versions and licences; versioned YAML, secrets masked), `fmc_diff_device_config` (two devices, a device and a template, or an export against the device now; field by field per section; with state sections: routes lost, tunnels down, interface changes, new alerts, hit-count deltas), `fmc_device_snapshot` (what up to 25 FTDs run now, for before/after evidence: routing table, interface state, failover, IKEv2/IPsec SAs, tunnels, hit counts, health alerts, deployed version, masked running-config sections; about ten requests per device), `fmc_snapshot` / `fmc_compare_snapshot` (core snapshot contract C53: a compact blob for a device group or name filter with deployment state, HA pair roles, interface link status, VPN tunnels and device health; the compare names what changed by severity; the FMC leg of the suite prompt `suite_change_check`) |
| FlexConfig | `fmc_flexconfig_review` (a FlexConfig policy, the one on a device, or all: assigned devices and the FlexConfig objects whose names match a feature FMC 10.0 configures natively (EIGRP, PBR, ECMP, VXLAN, timeouts, NetFlow, BFD, OSPF, BGP, DNS, ...) with where to configure it and the tool for it; FMC's REST API returns neither a policy's object list nor any object's CLI, so it gives the GUI path and classifies names passed as `objects`) |
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
  destination and port. Rules whose time range has ended are left out (`not_in_effect`, with `evaluated_at`),
  and source SGT rules are matched with the SGT of the source IP's newest ISE login (FMC user activity, not
  cross-checked with an active session) or `source_sgt`; an SGT it can't compare keeps the rule conditional.
  `fmc_packet_tracer` asks the device itself (FMC runs packet-tracer; nothing
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
  `show conn`, `show nat`) is refused before FMC is called, with the alternatives. With `devices=[...]` or
  `group=...` it runs on up to 25 devices in one call and returns a row per device (output, or why it failed;
  disconnected devices are not sent the command). FMC's `bulkcommands` is used where FMC enables it; FMC 10.0.1
  keeps it behind a feature flag (403), so the tool then asks each device, one at a time (FMC 10.0.1 answers
  concurrent show commands with each other's output), and `path` says so. A row whose output names another
  device (its `UUID` line, or a `show version` banner naming another device of the run) is a failure, not output.
- `fmc_get_hit_counts` refreshes the counters from the device first (packet-tracer packets count too).
- `fmc_live_connections` answers "what is this host talking to right now?". FMC 10.0.1 refuses `show conn`
  over its API, so it reads the device's syslog buffer (`show logging`: connection built/teardown messages
  302013-302021, which FTD ships disabled); the device's platform settings must log to the internal buffer at
  level informational (the tool says so when they don't). The buffer has no access rule or application: FTD 10
  sends Snort's connection events (430002/430003) only to syslog servers, and the note says so; timestamps on
  syslog messages are off by default too. Where FMC's spec lists `show conn`,
  the live connection table is used instead. `fmc_user_identity_sessions` reads FMC's identity view
  (`analysis/activesessions`, `analysis/useractivity`; the FTD has no `show user-identity`): the account's role
  needs Events & Logs > Analysis > Users. In a child domain these lookups fall back to the ancestor domains
  (see [Multi-domain FMC](#multi-domain-fmc-f19)).
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
| Objects | `fmc_create_object`, `fmc_update_object`, `fmc_delete_object`, `fmc_create_group`, `fmc_update_group`, `fmc_create_security_zone`, `fmc_import_objects` (bulk, validated; `mode='sync'` takes an IPAM export or CSV as the desired state: create, update, unchanged, group members, orphans under a prefix), `fmc_replace_object` (A becomes B in every access and prefilter rule, group, NAT rule and static route, found through FMC's usage API; optionally deletes A), `fmc_create_time_range` (absolute window plus daily or weekly recurrences), `fmc_create_application_filter` (applications plus risk, business relevance, category, tag and type) |
| Access control | `fmc_create_access_policy` (`base_policy=`: a child of a parent policy), `fmc_create_access_rule`, `fmc_update_access_rule` (`category=` moves a rule into a category; both take URL categories with a reputation level: `url_categories=[{category, reputation}]`, and `applications=`, `application_filters=`, `inline_app_filter={risks, business_relevance, categories, tags, types}` (an inline filter, no filter object), `vlan_tags=`, `time_range=`, `source_sgts=` / `destination_sgts=` (ISE or custom SGTs by name or tag number, shown with their tag in the preview); VLAN tags match only on inline sets), `fmc_delete_access_rule`, `fmc_import_access_rules` (bulk, validated) |
| Access policy structure | `fmc_create_category`, `fmc_rename_category`, `fmc_delete_category` (rule categories in the Mandatory or Default section; the delete shows where the category's rules went), `fmc_set_base_policy` (inheritance: the base's Mandatory rules run first, its Default rules last; loops refused, 'none' stops inheriting; the policy's Logging settings inherit from the new base only when FMC needs it (the base's send syslog, the policy's own have no syslog destination: FMC refuses that deployment) or with `inherit_logging=True`, and are otherwise left alone; a new child from `fmc_create_access_policy(base_policy=)` always inherits, as the FMC UI does), `fmc_policy_lock` (lock or unlock as the API user for a change window; another user's lock needs `break_lock=True`). Another user's lock blocks every access policy write preview with their name; `fmc_pending_changes` names locked policies in a deployment |
| Prefilter | `fmc_create_prefilter_policy`, `fmc_set_prefilter_policy` (link to an access policy), `fmc_create_prefilter_rule`, `fmc_update_prefilter_rule`, `fmc_delete_prefilter_rule` (FASTPATH / ANALYZE / BLOCK) |
| Bulk rule edits | `fmc_bulk_update_access_rules` (select rules by names, ids, text, action, enabled, section, category or no hits in N days; set enabled, logging, action, intrusion policy, extra source zones or a comment; one preview with every rule's diff, partial bulk PUTs of 50, stops at the first rule FMC refuses), `fmc_clear_hit_counts` (one device; the preview lists the counts that are lost) |
| NAT | `fmc_create_nat_policy`, `fmc_create_nat_rule`, `fmc_update_nat_rule`, `fmc_delete_nat_rule` |
| Device configuration | `fmc_update_interface` (incl. `mode`: routed, inline, passive), `fmc_create_subinterface`, `fmc_create_interface` (loopback, VTI, EtherChannel, BVI), `fmc_delete_interface`, `fmc_create_static_route` (`track=` an SLA monitor), `fmc_delete_static_route`, `fmc_create_sla_monitor`, `fmc_delete_sla_monitor` (dual-ISP failover), `fmc_assign_policy` |
| DHCP | `fmc_configure_dhcp` (a DHCP server pool on an interface with DNS, domain, lease and auto-config, or a DHCP relay agent to central servers; the preview refuses a pool outside the interface subnet or holding its address, and server plus relay on one interface; `fmc_get_device` and `fmc_export_device_config` show the settings) |
| IPS-only inline sets | `fmc_create_inline_set` (interface pairs as a bump in the wire: inline or tap mode, fail-open on Snort down / busy, link-state propagation, strict TCP; the preview blocks members with an address, a non-INLINE zone, another mode or an existing pair, and warns that tap mode drops nothing), `fmc_update_inline_set` (tap mode on/off for the pilot-to-inline cut-over, settings, add or remove pairs), `fmc_delete_inline_set`; `fmc_get_device` and `fmc_export_device_config` (section `inline_sets`) show them |
| Routing | `fmc_configure_bfd` (BFD template with timers, echo and authentication, applied single-hop on an interface or multi-hop between two addresses; the preview flags BGP neighbors without fall-over BFD and multi-hop toward a directly connected peer), `fmc_configure_bgp` (neighbors, fall-over BFD (`bfd`), networks, and route policy: neighbor route maps and prefix lists in/out, maximum prefix, default-originate, redistribution of connected/static/OSPF with a route map and metric; the preview diffs only the touched neighbor), `fmc_configure_ospf` (area networks, redistribution), `fmc_create_prefix_list` (IPv4 lines with ge/le), `fmc_create_route_map` (match prefix lists, communities, AS paths; set local preference, metric, weight, communities, AS-path prepend), `fmc_create_vrf`, `fmc_delete_vrf` |
| SD-WAN application-aware routing | `fmc_configure_wan_interface` (priority, ICMP path monitoring to the next hop or an IP, HTTP application monitoring), `fmc_configure_ecmp_zone`, `fmc_create_app_route` (applications, networks, ports or users out of the WAN link picked by order, priority, or lowest jitter / loss / RTT or highest MOS), `fmc_delete_app_route`; `fmc_get_routing` shows the routes and WAN settings |
| Platform settings / logging | `fmc_create_platform_settings_policy`, `fmc_configure_syslog`, `fmc_set_access_logging`, `fmc_configure_ntp`, `fmc_configure_snmp` (v2c; community write-only), `fmc_configure_ssh_access`, `fmc_configure_dns` (the DNS server group FQDN objects resolve with, created from server IPs; lookup interfaces, timers), `fmc_configure_netflow` (collectors, traffic classes, on/off), `fmc_configure_mgmt_access` (ICMP and HTTPS access to the data interfaces), `fmc_set_banner` |
| Dynamic objects | `fmc_create_dynamic_object`, `fmc_delete_dynamic_object`, `fmc_map_dynamic_object` |
| File / malware | `fmc_create_file_policy`, `fmc_create_file_rule` (DETECT, BLOCK, MALWARE_CLOUD_LOOKUP, BLOCK_MALWARE, with or without reset; by protocol, direction, file type and category), `fmc_delete_file_rule`; on ALLOW rules: `fmc_create_access_rule` / `fmc_update_access_rule(file_policy=...)` |
| Network analysis | `fmc_create_network_analysis_policy` (on a base policy; an access policy selects it in the UI, FMC's REST API has no field for that) |
| Intrusion tuning | `fmc_set_intrusion_rule_state` (ALERT/BLOCK/DROP/REJECT/PASS/DISABLE/DEFAULT per policy), `fmc_set_intrusion_recommendations` (Secure Firewall rule recommendations in a custom Snort 3 policy: generate and use, generate, use, refresh, stop using or remove, for protected network objects at security level 1-4; the preview warns that they need network discovery host data and that levels 3-4 can enable dropping rules), `fmc_create_intrusion_policy`, `fmc_create_intrusion_rule` / `fmc_delete_intrusion_rule` (custom Snort 3 rules); `fmc_update_access_rule(intrusion_policy=...)` |
| Snort profiling | `fmc_snort_profile` (Snort 3 rule profiler for 1-60 min: start, wait, stop; rules ranked by time with gid:sid for `fmc_find_intrusion_rules` / `fmc_set_intrusion_rule_state`), `fmc_cpu_profile` (Snort 3 module CPU profiler, 15-120 min, FMC stops it); no configuration change, but Snort is slower while they run; MCP tasks with `MCP_TASKS=true` |
| Change management | `fmc_ticket` (open / submit / discard / release; an open ticket is sent as `ticket-id` with every change); `change_ref` on every write tool: shown in the preview, added to access rule comments, and the open FMC ticket of that name carries the change |
| Decryption | `fmc_create_decryption_policy` / `fmc_update_decryption_policy` (default action and its logging, trusted CAs, TLS 1.3 decryption, untrusted issuers, undecryptable actions such as Unsupported Cipher Suite), `fmc_create_decryption_rule` (DECRYPT_RESIGN with an internal CA, DECRYPT_KNOWN_KEY, DO_NOT_DECRYPT, BLOCK, MONITOR; `tls_versions` and `cipher_suite_lists` on Block and Monitor rules; `insert_before`; warns when a decrypt rule would sit above a TLS Block rule), `fmc_update_decryption_rule` (an existing rule's `tls_versions`, `cipher_suite_lists`, `enabled`, `log`, or move it with `insert_before`; full-body PUT, previews each field from/to and the rule-order warning), `fmc_create_cipher_suite_list` (IANA names or codes checked against FMC's predefined suites; `preset='weak'`; the decryption rules using one: `fmc_where_used type='cipher_suite_list'`; delete an unused one with `fmc_delete_object type='cipher_suite_list'`, refused while a decryption rule uses it), `fmc_delete_decryption_rule`, `fmc_set_decryption_policy` |
| TLS certificates | `fmc_create_internal_ca` (FMC generates the key: self-signed, or a CSR for your CA), `fmc_install_internal_ca_cert` (the signed certificate for that CSR), `fmc_import_certificate_files` (an existing CA or server certificate + key read from `FMC_PKI_DIR` on the server host; only file names pass through MCP), `fmc_delete_certificate`, `fmc_create_cert_enrollment` (a device certificate enrollment: self-signed, PKCS12 read from `FMC_PKI_DIR` with its passphrase from a file there or `FMC_PKI_PASSPHRASE`, CA certificate only, SCEP or EST; the preview shows the certificate's subject, expiry and fingerprint, never the key or a password) |
| Identity (AD/LDAP) | `fmc_create_trusted_ca` (CA for LDAPS), `fmc_create_realm` (bind password write-only), `fmc_download_realm` (users and groups now; needs `FMC_UI_USERNAME`), `fmc_delete_realm`, `fmc_create_identity_policy`, `fmc_create_identity_rule` (PASSIVE / ACTIVE / NO), `fmc_delete_identity_rule`; access rules on users and groups: `fmc_create_access_rule` / `fmc_update_access_rule` `users=[...]` |
| DNS | `fmc_create_dns_policy`, `fmc_set_dns_policy`, `fmc_dns_block` (block/unblock domains via custom SI DNS lists; NXDOMAIN or drop) |
| Licences | `fmc_set_device_licenses` (IPS, MALWARE_DEFENSE, URL, ...; a device or a device group in one preview) |
| Device groups | `fmc_create_device_group`, `fmc_update_device_group` (add, remove, rename), `fmc_delete_device_group`; `fmc_deploy`, `fmc_assign_policy`, `fmc_backup_devices`, `fmc_set_device_licenses`, `fmc_device_metrics` and `fmc_sdwan_status(branch=...)` take a group |
| Admin | `fmc_update_health_policy` (module on/off, thresholds), `fmc_create_health_policy` (from the default or another policy, per-module thresholds, optional devices), `fmc_assign_health_policy` (devices or `group:<name>`; preview shows the threshold changes per device), `fmc_delete_health_policy` (refused while assigned), `fmc_set_object_override` (per-device object values) |
| Containment | `fmc_contain_host`, `fmc_release_host` (instant, no deploy); `fmc_si_block` (Security Intelligence block list for IPs, networks, URLs; logged; needs a deploy) |
| Security Intelligence feeds and lists | `fmc_create_si_feed` (IP, URL or DNS feed FMC downloads on a schedule), `fmc_upload_si_list` (custom list from text, validated; replaces its own lists), `fmc_set_si_lists` (feeds, custom lists and Talos categories into an access policy's SI block or do-not-block list; DNS ones into its DNS policy as block, allow or monitor rules), `fmc_delete_si_object` |
| HA | `fmc_configure_ha_monitoring` (monitored interfaces, standby IPs, failover MACs) |
| VPN | `fmc_create_s2s_vpn` (point-to-point IKEv2 PSK; policy- or route-based), `fmc_delete_s2s_vpn`; SD-WAN: `fmc_create_sdwan_topology` (wizard hub and spoke: hub DVTI, spoke pool, spokes on their WAN interfaces, backup hub, a second WAN tunnel per spoke through the companion topology `<name>-wan2`, iBGP overlay), `fmc_update_sdwan_topology` (add or remove spokes, their second WAN and the backup hub, ECMP) |
| VPN | `fmc_create_s2s_vpn` (point-to-point IKEv2 PSK; policy- or route-based), `fmc_delete_s2s_vpn` |
| Remote-access VPN | `fmc_create_address_pool` (IPv4 range + mask, or IPv6 start/prefix + count), `fmc_create_group_policy` (SSL/IKEv2, split tunnel with a standard ACL, DNS servers and split DNS, default domain, banner, pools, Secure Client VPN profile, idle timeout), `fmc_create_ravpn` (access zones, identity certificate from an F75 enrollment, Secure Client images, local realm; the preview names the identity NAT rule to add for NAT exemption), `fmc_set_connection_profile` (create or change a profile: group policy, AAA via ISE RADIUS or an AD realm, local or certificate authentication, pools, aliases, the policy's address assignment switches; shows the targeted devices). Uploading Secure Client packages and profiles stays in the FMC UI |
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
| `fmc_register_devices` | Registers several FTDs in one call (a lab or PoC rebuild): one preview for every row, one bulk request (one per device where FMC refuses bulk), one wait under one deadline for every registration and initial deployment, a result per device. Every row uses `FMC_FTD_REG_KEY` unless it has its own key; keys are never shown. An MCP background task with `MCP_TASKS=true`. |
| `fmc_delete_device` | Removes a device from FMC. |
| `fmc_copy_device_config` | FMC's Copy Configuration (an RMA, or a branch cloned onto a new box): copies a device's or HA pair's interfaces, routes and device settings (and, with `copy_shared_policies`, its shared policies) onto standalone FTDs, and follows FMC's task. The preview checks model and version, refuses an HA member or cluster node as a target, and lists what each target loses (from its export). Nothing reaches the device until `fmc_deploy`. |
| `fmc_create_ha_pair` | Forms an HA pair: the failover link, and state replication over it or over a separate state link (`state_interface`). |
| `fmc_ha_action` | Breaks, switches or deletes an HA pair. |
| `fmc_delete_policy` | Deletes a whole policy. |
| `fmc_delete_objects` | Deletes many objects in one preview: by names, a name prefix or every unused object, across value objects and groups, zones, dynamic objects and policies; refuses built-ins, objects an ancestor domain owns and anything still in use (naming what uses it), deletes in dependency order with FMC's bulk DELETE. |
| `fmc_backup_devices` | Backs up device configurations to FMC (not supported on FTDv). |
| `fmc_enroll_certificate` | Enrols a certificate enrollment on a device, or re-enrols, refreshes or deletes it there (at once, no deployment) and waits for FMC's task; the preview shows the device's current enrolment and the RA VPN, S2S and decryption policies that reference the enrollment (delete is blocked while anything does). |
| `fmc_migrate_flexconfig` | Runs FMC's FlexConfig migration for a FlexConfig policy on its devices (all assigned, or the ones named; a device not on the policy is refused): FMC turns FlexConfig for natively supported features into native routing, interface and platform configuration. The preview names `fmc_device_snapshot` as the step before and warns when no object name matches a native feature; the result follows FMC's task and points to `fmc_pending_changes`. Nothing reaches a device until `fmc_deploy`. |
| `fmc_apply_device_template` | Applies a device template to one standalone FTD with its variable values and object overrides (replaces its interface, routing, policy and VPN/SD-WAN configuration); the preview lists every variable and override. |

### Workflows

- **Onboard an FTD:** on the device, `configure manager add <fmc> <key>`; then `fmc_register_device`
  -> `fmc_update_interface` (name, zone, IP) -> `fmc_create_static_route` -> NAT policy and rules ->
  `fmc_assign_policy` -> `fmc_deploy` -> `fmc_run_show_command` to verify. FMC needs Smart Licensing or
  evaluation mode before it accepts devices. Several FTDs (an SD-WAN or HA lab from a CML recipe):
  `fmc_register_devices` registers them all in one call; the `fmc_onboard_ftd` prompt takes them as
  `devices` (name=host pairs from the recipe's FMC hand-off).
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
- **Snort CPU is high: which rules or inspectors?** `fmc_snort_profile(device, minutes=5)` while the traffic
  flows ranks the rules by time (gid:sid into `fmc_find_intrusion_rules`, then `fmc_set_intrusion_rule_state`
  in a custom intrusion policy); `fmc_cpu_profile(device, minutes=15)` ranks the Snort 3 modules. Both need the
  FMC role's Snort 3 profiling permission ([docs/least-privilege.md](docs/least-privilege.md)).
- **What changed or broke in the last hour?** `fmc_recent_activity`.
- **Is everything healthy?** The `fmc_firewall_health_review` prompt checks devices, HA, deployments,
  licences, content versions, backups, VPN and recent alerts, and ranks the findings (critical, warning,
  info) with a next step for each.
- **Does the HA pair fail over cleanly?** The `fmc_ha_failover_check` prompt runs the pre-checks
  (`fmc_get_ha_status`: standby ready, links, monitored interfaces, config sync), a traffic baseline (packet
  tracer, and pings from a CML host with a loss series), the switch (`fmc_ha_action`, or in a lab the active
  unit powered off), then verifies roles, failover history and its reason, and reports the outage.
- **Replace a failed FTD (RMA)?** The `fmc_replace_device` prompt snapshots the old unit (or exports its
  record), registers the new one, copies the configuration (`fmc_copy_device_config`), matches the licences,
  deploys, compares the two with `fmc_diff_device_config`, proves the policy and optionally unregisters the
  old record.
- **Is this rule change safe?** The `fmc_rule_change_review` prompt baselines the policy, runs sample flows
  through `fmc_rule_lookup` before and after, checks shadowing and overlap, previews the change and plans the
  deploy with a rollback.
- **Clean up a policy:** the `fmc_policy_cleanup` prompt turns `fmc_policy_audit` findings into grouped,
  approved changes (a group of identical rule edits is one `fmc_bulk_update_access_rules` preview), verifies them with `fmc_diff_policy_bundle` against a baseline bundle and a re-audit, and
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
- **Block old TLS and weak ciphers** (no decryption; FTD matches the version and suite the server picks, and
  logs them once a decryption policy is linked): `fmc_create_cipher_suite_list` (`preset='weak'`) ->
  `fmc_create_decryption_rule` (BLOCK_WITH_RESET with `tls_versions=['sslv3','tls10','tls11']`, another with
  `cipher_suite_lists`, both above any DECRYPT_RESIGN rule) -> `fmc_update_decryption_policy`
  (`undecryptable={'unsupported_cipher_suite': 'BLOCK_WITH_RESET'}`, else RC4 passes a resign rule
  undecrypted) -> `fmc_deploy`. FTD doesn't step a weak suite up: Decrypt-Resign gives the client the suite
  the server chose, though it strips RC4 from the ClientHello it forwards. Later: `fmc_update_decryption_rule`
  switches a rule to another list, changes its versions, disables or moves it; `fmc_where_used
  type='cipher_suite_list'` names the rules using a list, and `fmc_delete_object type='cipher_suite_list'`
  removes a list no rule uses.
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
  set in the FMC UI by an administrator, in the Global domain only (Integrations > Identity > Identity Sources:
  pxGrid node, pxGrid and MNT server CAs from `fmc_create_trusted_ca`, FMC's client certificate as an internal
  certificate, all in Global), then FMC's pxGrid client is approved in ISE. Why a connection fails shows only
  in that page's Test result. `fmc_get_identity_sources` shows whether it works end to end (FMC's ISE health
  module, SGTs downloaded, sessions by source, user-IP bindings on each device, certificate expiry) and what
  to fix; `fmc_user_ip_lookup` answers "who is on 192.0.2.57?" and "where is alice?". Reading FMC's identity
  sessions needs Events & Logs > Analysis > Users in the account's role. FMC keeps the source's sessions in
  Global; called in a child domain, the session lookups read Global when the child has none (below).
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
- **Is branch B configured like branch A? What changed on this FTD?** `fmc_export_device_config(device)`
  returns one YAML document (format `fmc-device-config`, version 1) by section: device (model, version,
  mode, licences, tier, Snort/VDB/LSP), interfaces of every kind keyed by hardware name, routing (static
  routes keyed by interface and destination, BGP, OSPF, EIGRP, PBR, ECMP, BFD, VRFs), assigned policies,
  the NAT policy's rules, the platform settings, VPN topology memberships, per-device object overrides,
  out-of-band changes, and for an HA pair its failover settings. Ids are stripped, items sorted and secrets
  masked (SNMP communities, BGP and OSPF keys, PSKs, secrets on CLI lines), so an unchanged device exports
  with the same `digest`. `fmc_diff_device_config(a, b)` compares two devices, a device with a device
  template (only what the template defines; its variables as applied to `a`), or a stored export with the
  device now (`b` omitted): added, removed and changed items per section with `fields` {path: {from, to}}.
  One export costs about 30 requests (a two-device diff about 50) and reads only FMC, so a disconnected
  FTD exports too. With `FMC_BUNDLE_DIR` set, exports are written there (`device-<name>-<time>.yaml`) and
  both tools take the file name. The `fmc_firewall_health_review` prompt's `compare_with` adds this as
  a drift check.
- **Hardening and audit evidence (F80):** `fmc_hardening_check(device=...)` (or `platform_settings=...`) checks
  the device's platform settings policy and the device against a baseline: SSH, HTTPS and ICMP access not
  open to any address, SNMP off or v3 only, syslog servers and RFC 5424 timestamps, NTP, the login banner,
  external authentication, DNS, and per device platform settings assigned, HA interface monitoring, intrusion
  rule and VDB age, licences, a recent backup and nothing pending, plus FMC's Smart Licensing, backup and
  content. The checklist is [docs/baselines/ftd-hardening.yaml](docs/baselines/ftd-hardening.yaml): each check
  has a severity, params, the tool that fixes it and its source (NIST SP 800-53 controls, RFCs, the CIS ASA
  benchmark's management-plane items, Cisco's guides). To change it, copy the file, give it its own `name`,
  put it in `FMC_BUNDLE_DIR` and pass `baseline='<file>.yaml'`. Findings come ranked, each with the fix as
  the existing tool call to preview. `fmc_export_access_rules(policy, evidence=true, since_days=30)` adds per
  rule what an auditor asks for: hits per device (first/last hit), logging, intrusion and file policy, the
  last change (FMC's 'Save Policy' audit record and its user), the deployment that put it on each device,
  rule comments, and the change ticket when FMC change management is on; the `fmc_compliance_evidence`
  prompt turns both into an evidence pack.
- **Before/after evidence for a change window:** `fmc_device_snapshot(devices, label='before CHG42')`
  captures what each FTD runs right now, as the same `fmc-device-config` document with state sections:
  the routing table (`show route`), interface status (`show interface ip brief`), failover state (HA
  units), IKEv2 SAs with the IKE/IPsec SA counts, FMC's tunnel rows, every access rule's hit count,
  the health modules that aren't green, the deployed configuration version and pending policies, and
  optionally masked `show running-config <section>` lines (`running_config=['route', 'nat']`). The show
  commands run once for all devices (FMC's bulkcommands where enabled, else one request per device);
  about ten requests per device. After the change, snapshot again and
  `fmc_diff_device_config(a=<before>, b=<after>)` (no FMC requests for two stored snapshots), or
  `a=<before>` alone against the device now: `findings` says "route lost", "interface Ethernet0/0:
  status up -> down", "tunnel ...: TUNNEL_UP -> TUNNEL_DOWN", "new health alert ...", a new deployment;
  hit-count changes and health readings (an alert's CPU or memory percentage) come as `deltas` and never
  make two snapshots differ. Route ages, SA lifetimes and alert times are left out, so an unchanged device
  compares identical. A snapshot against a named device (`b=<device>`) reads the device the same way. The `fmc_rule_change_review`
  prompt snapshots before the deploy and diffs after it; `fmc_firewall_health_review(baseline=<files>)`
  compares the devices with snapshots taken earlier.
- **Send FTD logs to a SIEM:** `fmc_configure_syslog` -> `fmc_assign_policy(kind='platform_settings')`
  -> `fmc_deploy` -> `fmc_run_show_command('show running-config logging')`.
- **Show it in a PoC:** [docs/demos.md](docs/demos.md) has three 15-minute stories as prompt sequences (a change
  with proof and rollback; adding an SD-WAN branch and failing a WAN link; "why is it blocked?" to fixed) and a
  threat-defense vignette, with what to point at and the `mcp-fw-demo-*` naming a reset relies on.

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
- **Identity sessions live in the identity source's domain.** FMC keeps `analysis/activesessions` and
  `analysis/useractivity` in the domain that owns the identity source, and FMC 10.0.1 offers the ISE source in
  Global only, so a leaf's own view is empty while its devices match user rules on Global's sessions. Every
  session lookup (`fmc_user_ip_lookup`, `fmc_user_identity_sessions`, `fmc_get_identity_sources`,
  `fmc_find_address`, `fmc_rule_lookup`, `fmc_live_connections(user=...)`, and `fmc_prove_policy` for a user
  flow without `source`) therefore reads the requested domain first and, only when it has no matching session,
  its ancestors up to Global (nearest first); `sessions_domain` (`history_domain` for login history) names the
  domain that answered. Read-only, and no extra request when the requested domain has sessions.
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
| `FMC_BUNDLE_DIR` | off | Directory `fmc_export_policy_bundle`, `fmc_export_device_config` and `fmc_device_snapshot` also write bundles, device exports and snapshots to (and `fmc_diff_policy_bundle` / `fmc_diff_device_config` read their file names from); `fmc_hardening_check` reads edited baselines from it (`baseline='<file>.yaml'`). Off: both are only returned inline. |
| `FMC_PKI_DIR` | off | Directory on the server host that `fmc_import_certificate_files` reads PEM certificate, key and passphrase files from, and `fmc_create_cert_enrollment` PKCS12, CA certificate and SCEP/EST password files (keys and passwords never pass through MCP). Off: file imports are refused; `fmc_create_internal_ca` and self-signed enrollments still work (FMC or the device generates the key). In Docker, bind-mount it read-only (see `docker-compose.yml`). |
| `FMC_PKI_PASSPHRASE` | | Passphrase of the PKCS12 files `fmc_create_cert_enrollment` reads from `FMC_PKI_DIR` when the call names no `passphrase_file` (also `_FILE` / `_REF`) |
| `FMC_TOOLSETS` | every area | Load only some areas of the tool surface, e.g. `troubleshoot,objects,deploy` or `all,-sdwan,-tls` (see "Toolsets"). The tiers still apply on top. |
| `FMC_ALLOW_IGNORE_WARNING` | `false` | Allow `fmc_deploy(ignore_warning=true)` (the preview must then list the FMC warnings being ignored) |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `MCP_HOST`, `MCP_PORT`, `MCP_PATH` | `0.0.0.0`, `8000`, `/mcp` | HTTP listener |
| `MCP_AUTH_TOKENS` / `MCP_AUTH_TOKENS_FILE` | | Required for HTTP: `name:sha256:<hex>` entries |
| `MCP_ENABLE_WRITES`, `MCP_ENABLE_DANGEROUS` | `false` | Tool tiers |
| `MCP_CONFIRM_TTL` | `600` | Seconds a confirm token stays valid |
| `MCP_TASK_TIMEOUT` | `600` | Seconds to wait for deployment, registration and HA tasks |
| `MCP_TASKS`, `MCP_TASKS_URL` | `false`, `memory://` | Run the long tools that support it (`fmc_register_devices`) as MCP background tasks: a client that supports tasks gets a handle at once and polls it for progress; others call them as usual (core `docs/PRODUCTION.md`, C12). `redis://...` keeps queued tasks across restarts. |
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

### Toolsets (`FMC_TOOLSETS`, F46)

With every tier on, the server registers 238 tools, and a client sends all their descriptions to the
model on every turn. Some clients also cap the number of tools. `FMC_TOOLSETS` loads only the areas you
name:

```bash
FMC_TOOLSETS=troubleshoot,policy,objects     # "why is this blocked?" and rule changes
FMC_TOOLSETS=vpn,sdwan,routing,deploy        # branch connectivity
FMC_TOOLSETS=all,-sdwan,-tls                 # everything but two areas
```

- `core` is always loaded: `fmc_status`, `fmc_search_spec`, `fmc_get_definition`, `fmc_api_call` (reaches
  any endpoint the loaded tools don't), `fmc_list_domains`, `fmc_list_devices`, `fmc_get_task`.
- The tiers still apply on top. For example, `objects` without `MCP_ENABLE_WRITES` gives only the object
  reads. `MCP_ALLOW_TOOLS` / `MCP_DENY_TOOLS` and roles also still apply.
- A workflow prompt is registered when its home areas are loaded (last column below). Optional steps in a
  prompt can name tools from other areas. When only some areas are loaded, the server instructions say
  which ones, and `fmc_status` lists them under `fmc.toolsets`.
- An unknown name stops the server at startup with the list of areas. Leave `FMC_TOOLSETS` unset to load
  everything (the default).

Every tool is in exactly one area. `fmc_mcp/toolsets.py` holds the table, and a contract test per toolset
checks it against the registered tools.

| Toolset | Tools (read/write/dangerous) | What it covers | Prompts (home area) |
|---|---|---|---|
| `core` | 9 (8/0/1) | always loaded: status, the API spec search and raw API call, domains, devices, tasks, change-check snapshots |  |
| `admin` | 11 (6/4/1) | FMC itself: backups, upgrades, health policy, users, audit log, Smart Licensing |  |
| `deploy` | 7 (4/1/2) | pending changes, deployments, rollback, change-management tickets | `fmc_onboard_branch`, `fmc_onboard_ftd`, `fmc_replace_device`, `fmc_rule_change_review` |
| `devices` | 30 (10/14/6) | device records, registration, licences, interfaces, DHCP, clusters, device groups, device templates, FlexConfig | `fmc_onboard_branch`, `fmc_onboard_ftd`, `fmc_replace_device` |
| `ha` | 5 (2/1/2) | FTD high-availability pairs: status, forming, switch/break, monitored interfaces | `fmc_ha_failover_check` |
| `identity` | 13 (6/7/0) | users in rules: realms (AD/LDAP), identity policies, ISE identity source, user-IP sessions | `fmc_prove_user_policy` |
| `intel` | 13 (3/10/0) | blocking by reputation: Security Intelligence feeds and lists, DNS policy, host containment |  |
| `migrate` | 6 (4/1/1) | move policy between FMCs or files: policy bundles, access-rule CSV import/export | `fmc_compliance_evidence` |
| `objects` | 24 (9/14/1) | network/port/URL objects and groups, zones, dynamic objects, overrides, where an address is used |  |
| `platform` | 12 (2/10/0) | platform settings: syslog, connection logging, NTP, SNMP, DNS, NetFlow, SSH/HTTPS/ICMP, banner, hardening | `fmc_compliance_evidence` |
| `policy` | 31 (9/21/1) | access control, NAT and prefilter: policies, rules, categories, inheritance, locks, assignments, hygiene | `fmc_policy_cleanup`, `fmc_rule_change_review`, `fmc_why_blocked` |
| `routing` | 13 (2/11/0) | static routes, SLA monitors, BGP, OSPF, BFD, VRFs, prefix lists and route maps |  |
| `sdwan` | 7 (1/6/0) | SD-WAN hub and spoke topologies, WAN interfaces, application-aware routing, branch health | `fmc_onboard_branch`, `fmc_sdwan_troubleshoot` |
| `threat` | 14 (5/9/0) | intrusion (IPS), file/malware and network analysis policies, an ACP's threat posture | `fmc_threat_defense_review` |
| `tls` | 18 (5/12/1) | TLS decryption policies and rules, cipher suite lists, certificates (days left, enrolment), readiness check |  |
| `troubleshoot` | 14 (12/2/0) | why is traffic blocked or slow: packet tracer, rule lookup, hit counts, show commands, live state, profiling | `fmc_firewall_health_review`, `fmc_prove_user_policy`, `fmc_why_blocked` |
| `vpn` | 11 (5/6/0) | site-to-site VPN topologies, tunnel status and troubleshooting, remote access VPN build and read | `fmc_vpn_troubleshoot` |

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

# Changelog

## 0.14.0 (2026-10-19)

Wave 5: scenarios, depth and demos, built and proven live in the firewall run of 2026-10-18/19 on FMC 10.0.1 with FTDv 10.0
in CML ([docs/wave5-proofs.md](docs/wave5-proofs.md): every item with its evidence, the overnight results and the morning
re-proof on `main`). 27 new tools and five new prompts: one address across the whole configuration, live connections and
identity sessions, device metrics over time, VPN status and troubleshooting, file/malware and network analysis policies,
Security Intelligence feeds and lists, URL categories in rules, TLS decryption readiness, the threat-defense review, HA
failover checks, interface kinds, policy proofs (also per user), branch onboarding into SD-WAN, `FMC_TOOLSETS`, and three
demo stories. 180 tools (79 read, 90 write, 11 dangerous) and eleven prompts.

### Added
- **`fmc_find_address`** (F59, #152): one IP, network or range across objects and groups, dynamic-object mappings,
  access/prefilter/NAT rules, static routes and VPN endpoints, ranked (exact, inside, contains, overlaps) with the object
  chain; with an identity source, the users FMC has a session for on the address (#186).
- **`fmc_live_connections` and `fmc_user_identity_sessions`** (F55, #156): a host's or user's connections on one FTD from
  its syslog buffer (FMC 10.0.1 refuses `show conn` over the API), open first, with bytes and teardown reason; FMC's
  active identity sessions and user activity.
- **`fmc_device_metrics`** (F57, #157): CPU, memory, throughput, connections and drops over a window from FMC's health
  monitor, summarised (min/avg/max, peaks, dips) with a compact series; used by `fmc_firewall_health_review` and
  pointed to by `fmc_sdwan_status`.
- **`fmc_vpn_status`** (F41, #151): every site-to-site, route-based and SD-WAN topology's tunnels with each device's IKE
  and IPsec SAs, traffic each way, rekey times and routes over the VTIs, degraded tunnels first; IKEv2 counters tell a
  key mismatch from a dead path. Prompt **`fmc_vpn_troubleshoot`** (F49, #154): a VPN symptom walked through IKE, IPsec,
  routing, NAT exemption and access rules to the cause and one previewed fix.
- **File/malware and network analysis policies** (F43, #153): `fmc_get_file_policy` (with the file type catalogue),
  `fmc_create_file_policy`, `fmc_create_file_rule`, `fmc_delete_file_rule`, `file_policy=` on access rules,
  `fmc_get_network_analysis_policy`, `fmc_create_network_analysis_policy`.
- **URL categories in access rules** (F63, #155): `url_categories=[{category, reputation}]` on `fmc_create_access_rule` /
  `fmc_update_access_rule` (levels from FMC's spec), `url_category` in `fmc_rule_lookup`.
- **Security Intelligence feeds and custom lists** (F61, #159): `fmc_create_si_feed` (IP, URL, DNS), `fmc_upload_si_list`,
  `fmc_set_si_lists` (block, do-not-block; DNS monitor), `fmc_delete_si_object`, feed and list status in
  `fmc_get_security_intelligence`.
- **`fmc_threat_posture`** and prompt **`fmc_threat_defense_review`** (F62, #160): an access policy's intrusion and file
  coverage, inspection bypasses, SI/DNS, decryption, network analysis and device licences, each finding with its fix.
- **TLS decryption** (F64, #179): `fmc_create_internal_ca`, `fmc_install_internal_ca_cert`, `fmc_import_certificate_files`
  (keys read from `FMC_PKI_DIR`, never through MCP), `fmc_get_certificate`, `fmc_delete_certificate`, DECRYPT_RESIGN and
  DECRYPT_KNOWN_KEY rules, `fmc_update_decryption_policy` (trusted CAs, TLS 1.3), and `fmc_tls_decryption_check` (what
  decryption does to a flow, rollout readiness).
- **HA under traffic** (F65, #180): `fmc_get_ha_status` reads each unit's own failover state (standby ready, links, last
  failover and why, replication, `ready_for_switch`), `fmc_create_ha_pair` takes a separate state link, prompt
  **`fmc_ha_failover_check`** (pre-checks, traffic, switch or lab failure, verify, report).
- **`fmc_create_interface`** (F58, #181): loopbacks, static and dynamic VTIs, EtherChannels and BVIs; `fmc_update_interface`
  and `fmc_delete_interface` understand those kinds.
- **`fmc_prove_policy`** and prompt **`fmc_prove_user_policy`** (F56, #158): a table of flows with expected verdicts, each
  packet-traced on the FTD it crosses: pass, fail or mismatch with the deciding rule and the user the device saw; a user
  flow without a source is traced from the user's current IP (#186).
- **ISE identity source** (F34, #178): `fmc_get_identity_sources` (ISE/pxGrid state, realms, identity policies, sessions,
  bindings, certificates) and `fmc_user_ip_lookup`; `fmc_rule_lookup` and `fmc_why_blocked` resolve the user on the
  source IP.
- Prompt **`fmc_onboard_branch`** (F54, #177): register a branch FTD with the server's key, configure it from a device
  template or by hand, join it to an SD-WAN topology, deploy hubs and branch, verify, and hand off `fmc_prove_policy` flows.
- **`FMC_TOOLSETS`** (F46, #187): load only some of 17 areas of the tool surface (`core` always on; the tiers still
  apply), listed in `fmc_status`; clearer descriptions for the tools added since v0.9.0.
- **[docs/demos.md](docs/demos.md)** (F60, #184): three 15-minute PoC stories (change with proof and rollback; SD-WAN
  add-a-branch and fail a WAN link; why is it blocked? to fixed) and a threat-defense vignette, with the `mcp-fw-demo-*`
  naming and the reset. All three were run on the reference lab from a reset.
- Read-only live tests for the Wave 5 tools and preview-parity tests against FMC's request models (#185).

### Changed
- Policy assignments include policies inherited from an ancestor domain (#183): `fmc_assign_policy`'s preview names a
  device's current policy in a leaf domain (was `from: null`), and `fmc_list_policy_assignments`, `fmc_find_address`
  (device-scoped NAT), threat posture, platform settings and bundle export see Global-owned assignments.
- `fmc_get_identity_sources` names FMC 10.0.1's ISE page (Integrations > Identity > Identity Sources, Global domain,
  administrator only), shows the ISE health parts and says a failed connection's cause is only in the UI's Test (#195);
  a just-saved source is `awaiting_health_check` instead of "No ISE identity source" (#196).

### Fixed
- `fmc_set_intrusion_rule_state` reported a Talos rule's keyword (e.g. ALERT) as its default state after a change; rows
  take the default from FMC's `defaultSetBy` (#188).
- `fmc_get_hit_counts` left out the default action once it had been hit (FMC's `fetchZeroHitCount` lists only never-hit
  rows); it is read by id and labelled `default` (#189).
- `fmc_tls_decryption_check` and `fmc_get_decryption_policy` counted FMC 10's default certificate fields as rule
  conditions, so every rule looked conditional (#190).
- `fmc_create_decryption_rule` sends every TLS version: FMC 10 stores none otherwise and refuses the deploy; existing
  rules with that problem are named (#191).
- `fmc_vpn_status` gave a DVTI hub a false "no routes over the VTIs" warning (FTD prints `V` routes on two lines) (#192).
- On a dead WAN, `fmc_vpn_status` / `fmc_sdwan_status` said only "no IKEv2 failures in the last N s" and
  `fmc_vpn_troubleshoot` went to the IKE policies; the counters are compared over 15 minutes and the path is checked
  first (#193).
- `fmc_create_interface` previewed EtherChannels on FTDv, which FMC refuses; the preview blocks them. A bridge-group member
  needs a SWITCHED zone; deleting a BVI says FMC keeps the members' logical names (#194).
- `fmc_user_identity_sessions(history=true)` / `fmc_user_ip_lookup(history=true)`: FMC 10.0.1 answers 422 "Invalid time
  field." to the documented `time=after:` filter, so the window is applied in the server (#199, #211).
- `fmc_get_security_intelligence` said "not downloaded yet" for a feed FMC had fetched (FMC 10.0.1 never fills
  `entryCount` or `feedUpdateTime`); it now counts the fetched entries (#218). Replacing a custom SI list sends the list's
  id, which FMC requires (#215).
- `fmc_create_decryption_rule` with `insert_before`: FMC answers 500 but creates the rule; the tool now reports the rule it
  finds (#216).
- From the operator eval: `fmc_unused_objects` no longer lists built-ins inherited from Global in a leaf domain (#197, #212);
  `fmc_prove_policy` traces an HA pair on its active unit (#198, #217); packet-tracer runs no longer show as changes or
  connections (#201/#202, #214). The Wave 5 parity live test reads update previews' `changes` (#213).

### Known issues
- From the operator eval (29 of 42 asks passed before the fixes above): markdown hides nested rows of single-object tools
  (#200); #203-#210 open.
- FMC 10.0.1 platform limits met on the way (documented in the tools): no EtherChannel on FTDv, no REST to link a
  network analysis policy, to manage the custom detection list or to unlink a decryption policy from an access policy;
  malware and URL lookups for URLs outside the local database need the Cisco cloud.
- FMC's ISE (pxGrid) identity source in the lab still presents a stale client certificate, so user-based enforcement
  (F34) and `fmc_prove_user_policy`'s user rows are proven only up to the tools (#79, #123).

## 0.13.2 (2026-10-18)

SD-WAN polish from the 0.13.1 re-proof: `fmc_create_sdwan_topology(overlay='ospf')` builds a working OSPF overlay
(unnumbered spoke VTIs borrowing a /32 loopback each; proven live on FMC 10.0.1 with the tool alone: OSPF routes on
every spoke, all host pairs reachable, spokes removed and re-added), and `fmc_sdwan_status` reports every ECMP next
hop, when a metric last changed, and FMC's early "unreachable" samples as pending. 153 tools, six prompts.

### Added
- **SD-WAN OSPF overlay (matrix R5).** `fmc_create_sdwan_topology(overlay='ospf')` takes `spoke_loopbacks` (a subnet
  outside the spoke pools, handed out in spoke order, or one address per spoke) and makes every spoke tunnel
  unnumbered: it creates a /32 loopback `sdwan-ospf-lo` on each spoke (or reuses one that has the address), adds the
  spokes, then PUTs each spoke VTI FMC generated with `ipAddressAssignmentType: BORROW_IP_FROM_INTERFACE` and
  `borrowIPfrom` that loopback (without `ipv4` and `managementOnly`). That addressing carried OSPF live on FMC 10.0.1
  (mcp-sdwan-t1: FULL adjacencies, OSPF routes on the spokes, all hosts reachable); with numbered spoke VTIs the
  spokes installed no routes. The 0.13.0 preview warning is replaced by a note on what to run next
  (`fmc_configure_ospf` on the hub and spokes, then deploy). `overlay='ospf'` with spokes now requires
  `spoke_loopbacks`; with a backup hub or `backup_wan_interface` it is blocked (not verified live).
  `fmc_update_sdwan_topology(add_spokes=..., spoke_loopbacks=...)` does the same for spokes added to an OSPF
  overlay. Live on FMC 10.0.1 (mcp-sdwan-t1, main 25d1ae7): one `fmc_create_sdwan_topology` call built the
  overlay with three unnumbered spokes, and after `fmc_configure_ospf` and one deploy every spoke installed OSPF
  routes and all host pairs pinged; removing a spoke and adding it back with `fmc_update_sdwan_topology` reused its
  loopback and restored its routes.

### Fixed
- **`fmc_sdwan_status`, from the 0.13.1 re-proof:**
  - `bgp_routes[].via` is now a list with every next hop of an ECMP route (`show route bgp` prints the extra next
    hops on indented lines; only the first was kept).
  - `wan_links[].sampled_at` is gone: FMC's health monitor repeats the last value at every step of the range, so the
    newest step looked current even for a value minutes old. Each link now has `changed_at` (the newest sample
    whose value changed, or the start of a series after a reachability flip) or, when nothing changed in the
    10-minute window, `unchanged_since`; the evidence says "changed at ..." or "value unchanged since ...".
  - While FMC's `pathmonitoring` series say `rechability: No` with zero values (the first ~5 minutes of a brownout
    on 10.0.1, while the device itself still reaches the peer), the reason reads "metrics pending or the peer
    unreachable per FMC" instead of "peer ... does not answer". The link stays critical in `degraded`. The
    `fmc_sdwan_troubleshoot` prompt explains both fields.
- docs/GAP-ANALYSIS.md no longer says `show access-list` is refused (`show access-list <name>` is in the spec's
  list). `fmc_run_show_command`'s description already matched the #136 allowlist; a unit test now checks that its
  examples pass the allowlist and every command it names as refused is refused.

## 0.13.1 (2026-10-18)

SD-WAN follow-up to 0.13.0, from the live matrix re-run on FMC 10.0.1 ([docs/sdwan-matrix.md](docs/sdwan-matrix.md)):
a spoke's second WAN tunnel now works (built as a companion AUTO_VPN topology on the same hub; a dead first WAN
fails over without a lost ping), `fmc_sdwan_status` gets path metrics from FMC's health monitor, show commands are
checked against the supported CLIs in FMC's API spec, and raw `fmc_api_call` previews mask secrets (core v0.14.2).
153 tools (66 read, 76 write, 11 dangerous), six prompts.

### Changed
- Bundled stutters-mcp-core v0.14.0 -> v0.14.2: raw `fmc_api_call` writes mask secret fields (`manualPreSharedKey`,
  `preSharedKey`, passwords, keys) in the preview and the result; the request sent to FMC is unchanged.
- `fmc_run_show_command` and the show commands `fmc_sdwan_status` runs check the command against the
  supported CLIs that FMC's API spec documents for `devices/devicerecords/{id}/operational/commands`
  (read from the spec index at run time; FMC 10.0.1's list is built in, plus the live-verified
  `show interface` and `show running-config <section>`). An unsupported command (`show bgp summary`,
  `show path-monitoring`, `show policy-route`, `show ospf ...`, `show conn`, plain `show running-config`)
  is refused before FMC is called, naming the alternative (`show route bgp`, `fmc_sdwan_status`,
  `fmc_get_routing`, ...) and the supported list. Words after the second still go to FMC as `parameters`;
  an unambiguous abbreviation of the second word is expanded (`show run nat`). `fmc_sdwan_status` no
  longer sends the three commands FMC 10.0.1 refuses (one request less per device each). Tool docs that
  suggested `show bgp summary` / `show policy-route` now point to `show route bgp` / `fmc_sdwan_status`.

### Fixed
- **`fmc_sdwan_status` reads path metrics from FMC's health monitor (SD-WAN matrix R2).** FMC 10.0.1 refuses
  `show path-monitoring`, but `health/metrics` answers `metric:pathmonitoring` (live; the spec documents only
  cpu, mem, interface, asp_drops, disk_stats and critical_process, and `path_monitoring` returns nothing): RTT
  and jitter in microseconds, loss in percent, MOS, and the peer's reachability per path-monitored interface,
  physical or VTI. The status now asks once per topology for every endpoint (an HA pair's members, preferring
  the active unit), fills `wan_links` with `rtt_ms`, `jitter_ms`, `loss_pct`, `mos`, `reachable`, `peer` and
  `sampled_at`, ranks a brownout (or an unreachable peer) as degraded and orders metric-based app routes by
  it. FMC's samples trailed the device by about 5 minutes (a CML brownout on mcp-sdwan-t1-spoke1's MPLS link:
  RTT 1.5 -> 307 ms, loss 0 -> 33 %, MOS 4.4 -> 0, tunnel 303 ms / 57 %); the status says so.
  `capture_fixtures.py --sdwan-metrics` records the response (`ftd_sdwan_pathmetrics.json`).
- **SD-WAN: a spoke's second WAN tunnel (`spokes[].backup_wan_interface`, matrix R1).** FMC 10.0.1 drops
  `backupInterfaces` on AUTO_VPN spokes, refuses it on hubs, and allows one endpoint per device per topology.
  `fmc_create_sdwan_topology` now builds the second tunnel as FMC accepts it (found live on mcp-sdwan-t1): a
  companion AUTO_VPN topology `<name>-wan2` with the same hub on a second DVTI (new `hub_backup_wan_interface`,
  `hub_backup_dvti`, `hub_backup_loopback`, `backup_wan_pool`: its own loopback and pool) and each spoke with
  `backup_wan_interface` on that WAN, with the same IKE, IPsec and iBGP settings. Live: two IKEv2 SAs and two
  iBGP sessions per spoke, and a dead first WAN (cable pulled, or 100% loss) moved traffic to the other tunnel
  without a lost ping. `fmc_update_sdwan_topology` adds a spoke's backup WAN to the companion, removes removed
  spokes from it too, and sets `multipath` on both. A backup WAN with a backup hub is blocked (not verified).
  The read-back-and-undo from 0.13.0 is gone with the field it checked.

### Notes
- Path metrics need the health monitor's path-monitoring module (`hm_pathmonitoring`) enabled in the devices'
  health policy and path monitoring on the WAN interfaces (`fmc_configure_wan_interface`); FMC's samples trail
  the device by about 5 minutes.
- The OSPF-overlay warning from 0.13.0 (R5) is conservative: the re-run got spokes to install OSPF routes with
  unnumbered spoke VTIs (each borrowing a /32 loopback), set by `fmc_api_call`. The tools don't automate that yet.
- Not re-proven live on 0.13.1: the companion-topology build through `fmc_create_sdwan_topology`, and brownout
  ranking in `fmc_sdwan_status` (both live-proven by API calls, unit-tested on recorded responses). The HA-hub
  cells stay blocked by a stuck cluster record on the lab FMC.

## 0.13.0 (2026-10-18)

Wave 4 Phase D, Firewall SD-WAN (F51 a–d): topology authoring, application-aware routing, SD-WAN status with a
troubleshooting prompt, and device templates; `fmc_register_device` takes the registration key from server config.
153 tools with every tier on (66 read, 76 write, 11 dangerous) and six prompts. Run live in the F53 matrix on
FMC 10.0.1 with 12 FTDv 10.0 (T1–T4 × C1–C5, [docs/sdwan-matrix.md](docs/sdwan-matrix.md)): 5 pass, 9 fail, 3 blocked;
the fixes for the failed cells are below (R1–R3, R5–R7). Failed cells are re-run after release.

### Added
- **SD-WAN status and troubleshooting (F51c, #107).** `fmc_sdwan_status(topology or branch)` reports, per
  branch and hub: the WAN links (path-monitoring status, type and monitored IP, interface priority, and RTT,
  jitter, loss and MOS parsed from `show path-monitoring`), the overlay tunnels (`health/tunnelstatuses`) and
  iBGP neighbors (`show bgp summary`), every application route (`routing/policybasedroutes`) with the interface
  it uses now and why (its ordering, by priority, order, jitter, loss, RTT or MOS, against the live link state;
  `show policy-route` as evidence), and one ranked list of degraded links and overlay faults (down, lossy, slow,
  jittery, low MOS, tunnel down, BGP neighbor not established) with the thresholds used. Show commands FMC
  refuses are reported as unavailable, not as errors; `max_devices` caps them (spokes first). Prompt
  `fmc_sdwan_troubleshoot(application, branch, ...)` ("app X is slow at branch Y"): path metrics -> app-route
  rule -> chosen interface -> overlay -> packet tracer -> one previewed fix. Read tier. `capture_fixtures.py
  --sdwan` also records the PBR entries and the three show commands.
- **SD-WAN topology authoring (F51a, #107).** `fmc_create_sdwan_topology` builds FMC's SD-WAN wizard topology
  (`AUTO_VPN` hub and spoke, FMC 7.6+) preview-first and in dependency order: the spoke tunnel address pool
  (an existing IPv4 address pool, or a subnet: the hub takes the first address on a new loopback), the hub's
  dynamic VTI (reused by logical name or created from the hub WAN interface, borrowing the loopback's address,
  in the overlay zone), the topology with iBGP overlay settings (AS, community tag, inside networks
  redistributed, ECMP) or `overlay='ospf'` (no generated BGP; OSPF via `fmc_configure_ospf`), IKEv2 (automatic
  or manual pre-shared key, DES defaults when FMC has no strong-crypto licence) and the endpoints: primary hub,
  optional backup hub with its own DVTI and pool, and spokes on their WAN interface plus an optional backup WAN.
  The preview blocks zone-less or unnamed WAN interfaces, a static VTI given as the hub DVTI, overlapping hub
  pools and an existing name; a failed step deletes what was created, newest first, with the key masked.
  `fmc_update_sdwan_topology` adds and removes spokes, adds or removes the backup hub and switches ECMP, and lists
  the devices to deploy. `fmc_get_vpn_topology` shows the primary hub, spoke pools and backup WAN interfaces.
  `scripts/capture_fixtures.py --sdwan` records a live topology for the unit tests (reads only). Unit-tested on
  fixtures; live verification is part of the F53 matrix.
- **SD-WAN application-aware routing (F51b, part of #107).** `fmc_configure_wan_interface` sets a routed
  interface's priority, ICMP path monitoring (`auto`/`auto4`/`auto6` toward the next hop, or `ip` with a
  monitored peer address) and HTTP-based application monitoring (with monitored applications), changing only
  what is passed. `fmc_configure_ecmp_zone` creates, changes or deletes ECMP zones (global table or a VRF; an
  interface already in another zone blocks). `fmc_create_app_route` matches applications (FMC's catalog, by
  name), source/destination networks, ports or realm users in a new extended access list named after the
  route, then adds a forwarding action to the policy-based route of the ingress interfaces (or creates one),
  with the egress interface picked by `order`, `priority` or the best measured path (`jitter`, `loss`, `rtt`,
  `mos`); metric ordering is blocked until every egress interface has path monitoring, ingress interfaces
  already in a different policy-based route block, and a failed route deletes the new access list again.
  `fmc_delete_app_route` removes the forwarding action (and the policy-based route when it was the last one)
  and deletes the access list unless another route still uses it. All write tier, preview-first.
- `scripts/capture_fixtures.py --sdwan-routing` records the F51b fixtures (GETs only) from an SD-WAN branch
  (`FMC_LIVE_SDWAN_DEVICE`).
- **Device templates (F51d, part of #107).** `fmc_list_device_templates` and `fmc_get_device_template`
  (read): a template's firewall mode, access policy and the other policies it assigns, validation messages,
  template interfaces (with `${variable}` addresses), variables (type and default; PASSWORD values masked),
  model mappings, VPN/SD-WAN settings (topology, hub or spoke role, tunnel interface and address
  variables), overridable host/network/range/FQDN objects, and the devices it was applied to with the last
  apply and sync status. `fmc_create_device_template` (write): generated from a standalone FTD
  (`generatetemplate`, a background task the tool waits for) or empty from a firewall mode and access
  policy; `fmc_delete_device_template` (write, destructive). `fmc_apply_device_template(template, device,
  variables, overrides, deploy)` (dangerous): the preview lists every variable (given or template default)
  and every overridable object (current and new value), the device's current template, the VPN topologies
  it joins and a model-mapping check; unknown names, missing values, values of the wrong type (AS number,
  IPv4/IPv6 host or network, range, router id, FQDN), HA or cluster members, a firewall-mode mismatch and a
  closed deploy window block it. Waits for the apply task; `deploy=true` sets `postApplyAction=DEPLOY`.
  The `fmc_onboard_ftd` prompt takes an optional `template` and links the template path otherwise.
  Unit tests replay FMC 10.0.1 spec examples (`tests/fixtures/devicetemplates.json`; the lab FMC had no
  templates yet); `scripts/capture_fixtures.py --templates` re-records them read-only. Not yet live-tested
  (F53 cell C4).

- **`FMC_FTD_REG_KEY`** (also `_FILE` / `_REF`): the FTD registration key `fmc_register_device` uses when
  `reg_key` is left out, so the key never passes through the conversation or an agent's tool arguments. The
  preview says where the key comes from (`registration_key: from server config`) and never shows it; a
  missing key is a clear error before anything is sent. `reg_key` is now optional and still overrides it.
  docs/deploying.md §9.

### Changed
- `fmc_get_routing` lists policy-based routes in full (match, egress interfaces, how one is picked) instead of
  a count, and adds `wan_interfaces` (priority, path monitoring, HTTP monitoring of each configured interface).
- `fmc_register_device`: `reg_key` is optional; left out, the key comes from `FMC_FTD_REG_KEY` (see Added).
- `fmc_get_vpn_topology` shows SD-WAN roles (primary and backup hub, spoke pools, backup WAN interfaces).
- Prompt `fmc_onboard_ftd` takes an optional device `template`.

### Fixed
- **SD-WAN, found by the F53 live matrix on FMC 10.0.1:**
  - `fmc_configure_wan_interface` and `fmc_update_interface` on a VTI got 400 "managementOnly must be excluded";
    VTI PUT bodies now drop the physical-only fields (R3, #130).
  - `fmc_update_sdwan_topology` got 422 on `ipsecSettings`; it now PUTs only the top-level topology fields plus
    `autoVpnSettings`. The preview warns that multipath across two hubs drops asymmetric traffic (R6, #131).
  - `spokes[].backup_wan_interface` was stored by nothing (FMC 10.0.1 answers 2xx and drops it) while the tool
    reported success; spokes are read back after the POST, and a dropped backup interface fails the call and
    undoes the change. The preview says so (R1, #132).
  - `fmc_sdwan_status` relied on `show path-monitoring`, `show policy-route` and `show bgp summary`, which FMC
    10.0.1's command API refuses. Each refused command is tried once and reported as "not available";
    `show route bgp` is the fallback; `show crypto ikev2 stats` tells a PSK mismatch from a dead path; links
    without metrics get health "not available" with a brownout note; each tunnel is ranked once and an all-down
    hub is one rolled-up entry; FMC's tunnel-monitor lag gets a warning; app routes are named; `path_now` leaves
    a down VTI. The `fmc_sdwan_troubleshoot` prompt no longer suggests refused commands or `backup_wan_interface`
    (R2, #133).
  - `fmc_sdwan_status` on an HA-pair hub: the hub is matched by the pair, its members and `<pair>[<unit>]`,
    `branch=<member>` resolves to the pair, `ha.units` reports failover states, and show commands run on the
    active unit (R7, #134).
  - `fmc_create_sdwan_topology(overlay='ospf')` now warns in the preview that FMC 10.0.1's AUTO_VPN addressing
    (unnumbered hub DVTI, numbered spoke VTIs, no OSPF network-type field) leaves spokes without OSPF routes (R5, #135).
- **`fmc_license_status` showed an empty smart-licence `metadata`.** FMC 10 returns `authStatus` (for example
  `OUT_OF_COMPLIANCE`), `virtualAccount`, `exportControl`, `evalUsed`, `evalExpiresInDays` and the last sync and
  renewal times in `items[].metadata` of `/license/smartlicenses`, and `slim()` dropped them. They are now lifted
  into each `smart_license` row. The VPN strong-crypto check reads `exportControl` from the same place, so a
  licence without export control again falls back to DES instead of being treated as strong-crypto capable.

### Notes
- F53 platform limits on FMC 10.0.1 (blocked cells): device templates can't be generated from FTDv for KVM
  ("version or model of the device is not supported"), and the FTDv cluster attempt on CML/KVM hung in FMC's
  cluster-create job. OSPF over the SD-WAN overlay carries no traffic (R5). A second WAN tunnel per spoke needs
  the FMC 10 wizard's payload, which is not captured yet (R1 follow-up).
- The metric `forwardingActionType` values (`SET_EGRESS_INTF_BY_JITTER`, `_LOST_PKTS`, `_RTT`, `_MOS`) are not
  in FMC 10.0.1's OpenAPI spec (only `_ORDER` and `_PRIORITY` are); Cisco's guide spells them
  `SET_EGRESS_INTERFACE_BY_*`. The INTF spelling matches working payloads; live verification is pending (F53).
  `tests/fixtures/sdwan_app_routing.json` is spec-shaped until it is recorded on an SD-WAN branch.

## 0.12.0 (2026-10-17)

Wave 4 Phase B: policy hygiene, policy bundles (export, diff, import) and three workflow prompts, all proven
live on FMC 10.0.1. 141 tools with every tier on (63 read, 68 write, 10 dangerous) and five prompts.

### Added
- **Prompt `fmc_firewall_health_review` (F48, #93).** Optional `domain`, `device` (name contains) and
  `lookback_hours` (default 24). Walks the aggregate tools once each (devices and `fmc_device_health` for the
  non-green ones, HA pairs and clusters, deployable devices and failed deployments, licences, software and
  VDB/SRU/LSP content age, backups, VPN tunnels, health alerts) within FMC's 120 requests/minute budget, and
  writes one ranked report (critical, warning, info) where each finding has its evidence and a next step with
  the tool call to make. Read tier; read-only.
- **`fmc_policy_audit` (F42, #87).** One ranked review of an access control policy: shadowed (high) and
  redundant rules, any-any ALLOW/TRUST rules, ALLOW rules without an intrusion policy, rules that log nothing,
  disabled rules, rules with no hits in `unused_days` (summed across the devices the policy is assigned to, HA
  pairs expanded to both members), rules on expired time ranges, duplicate objects (same value, different names;
  domain-wide, the ones this policy uses first) and adjacent rules that differ in one condition (merge
  candidates). Every finding carries a proposed fix as a tool call to preview; `checks` runs a subset. Read tier;
  the only operational call is the optional hit-count refresh.
- **Policy bundle export and diff (F44, #89).** `fmc_export_policy_bundle(policy)` exports an access policy with
  everything it depends on as one versioned YAML bundle (`schema: 1`, `meta` with policy, domain, FMC version,
  server version, `exported_at` and a `digest`): settings, default action and categories; rules in order in
  `fmc_export_access_rules`' row format plus `raw` for every setting that format can't carry (users with their
  realm, URL categories, file policy, variable set, syslog, ICMP codes, ...), so nothing is dropped; the
  prefilter, decryption, identity and intrusion policies it references and the NAT policies of its devices (or
  `nat_policies=[...]`), custom ones in full (intrusion: base policy, mode and rule overrides) and built-in ones by
  name; every object its rules use with groups expanded recursively, plus security zones, interface groups and
  time ranges. Ids, links and metadata are stripped, items keyed by name, objects sorted by type then name,
  group and condition members sorted, rules kept in order, so re-exporting an unchanged policy gives the same
  digest and text apart from `meta.exported_at`. Collections are loaded in bulk (about 16 requests for
  `mcp-test-acp`); bundles larger than one result page with `offset` / `next_offset`.
  `fmc_diff_policy_bundle(a, b | live)` compares two bundles, or a bundle with a fresh export of the live policy:
  per section (access/prefilter/decryption/identity/NAT settings and rules, intrusion policies, zones, interface
  groups, time ranges, objects by type) it lists `added` (with the new value and the rule it follows),
  `removed`, `changed` (field-level `{path: {from, to}}`) and `moved` (positions, `after`). Rules match by name;
  unnamed (NAT) rules and pure renames match by position. The changes turn `a` into `b`; F45's importer reuses
  this planner. Both are read tier.
- **`FMC_BUNDLE_DIR`**: when set, every export is also written there and both bundle tools accept a bundle's
  file name (plain names inside that directory only). Unset by default, so shared HTTP hosts write nothing.
- `scripts/capture_fixtures.py --bundle` records the GETs of a real export as `tests/fixtures/bundle_acp.json`.
- `pyyaml` is a direct dependency (it was already installed through fastmcp).
- **Policy bundle import (F45, #90).** `fmc_plan_policy_bundle_import` (read) and `fmc_import_policy_bundle`
  (dangerous tier; its preview is the plan) apply a bundle from `fmc_export_policy_bundle` to a target domain or
  FMC by name, in dependency order: missing objects are created (leaves in bulk per type, then groups level by
  level), identical ones reused, same name with a different value is a blocker unless `update_objects`; missing
  security zones and interface groups are created without interfaces; prefilter and NAT policies the target lacks
  are created with their rules (an existing one is reused and a difference reported); the access policy is
  created (default action, categories, prefilter/identity/decryption links, rules in order) or updated (default
  action, added rules inserted next to their neighbours in the same section/category, changed rules replaced,
  rules missing from the bundle deleted only with `delete_extra_rules`; reordering existing rules is reported, not
  applied). Identity, decryption and intrusion policies, time ranges, realms, file policies, variable sets and
  alerts must exist in the target (blockers otherwise). Stops at the first failure and lists what was applied;
  deploying stays a separate step. The change window and an open change ticket apply.
- **Prompts `fmc_rule_change_review` (F47, #92) and `fmc_policy_cleanup` (F50, #95), write tier.** The first
  reviews one access rule change: baseline bundle, sample flows through `fmc_rule_lookup` before and after,
  shadowing/overlap reasoning and `fmc_policy_audit` regressions, the change as a preview, what a deploy would
  push, and a deploy plan with rollback (`fmc_rollback_deployment`, or the baseline bundle with
  `fmc_diff_policy_bundle` / `fmc_import_policy_bundle`). The second turns `fmc_policy_audit` findings into a
  grouped cleanup plan (delete redundant and disabled rules, disable unused ones for a cycle, owner decisions
  for shadowed rules, inspection/logging fixes, object tidy-ups), opens a change ticket when FMC needs one,
  applies each approved change preview-first, verifies with a bundle diff and a re-audit, and plans the deploy.

### Changed
- `fmc_shadowed_rules` and `fmc_get_hit_counts` share their logic with the audit (`shadow_findings`,
  `rule_hits`); their output is unchanged.

### Fixed
- `fmc_policy_audit` failed on a policy whose rules use time ranges: FMC sends `timeRangeObjects` as a plain
  list, not an `{objects: [...]}` block. Found by the live hygiene seed; `tests/live/test_live_hygiene.py`
  (`FMC_LIVE_HYGIENE_POLICY`) now covers every static check on a real policy.
- `fmc_policy_audit`'s `unused` check no longer reports every rule as never hit on a device where the policy is
  assigned but not yet deployed (its next deployment would ADD the access policy): that device's hit counts are
  left out with a note, and with no device running the policy the check reports nothing.

## 0.11.0 (release candidates only; shipped in 0.12.0)

### Added
- **`fmc-mcp-server check` preflight (F36, #81; core C21).** Runs without an MCP client: token generation
  (`generatetoken`: reachability, TLS trust, credentials), the domains the API user can see (fails when none, or
  when `FMC_DOMAIN` doesn't exist), the user's FMC roles (its own `users/users` record) against the enabled tiers
  (fails when writes are on with `mcp-ro`, warns when a read-only server runs as Administrator or as the built-in
  `admin`, and when the roles are unreadable or unknown while writes are on), the FMC version against the tested
  matrix (10.0; 7.2 minimum) and `FMC_RATE_LIMIT` against FMC's 120 requests/minute (warns above it). Text or
  `--json`, `--strict`, `--instance`; exit 1 on a failure; every `FMC_INSTANCES` FMC. `serve --http` /
  `serve --stdio`. README quickstart for a release wheel (`uvx --from`) and for the image, with Claude Code /
  Claude Desktop config. PyPI publishing stays open (deferred).
- **Published image (F37, #82; core C22).** `release.yml` calls core `publish-image.yml`:
  `ghcr.io/dr-stutters/fmc-mcp-server` for amd64 and arm64, cosign keyless signature, SPDX SBOM attestation;
  `<version>` + `latest` on releases, `<version>-rcN` + `rc` on pre-release tags. `docker-compose.yml` pulls it
  (`MCP_IMAGE_TAG`; `--build` still builds locally).
- **Shared-host guide and example (F38, #83).** `docs/deploying.md` (read-only defaults, per-user tokens and the
  audit log, several FMCs with `FMC_INSTANCES`, one FMC API user per server instance, the 120 requests/minute
  budget and the shared limiter, Caddy TLS, the least-privilege user step by step, change-management tickets for
  regulated sites, upgrades and verifying signatures) and `examples/shared-host/` (server + Caddy, and a test
  override with two mocked FMCs). Contract tests pin the tier defaults (`tests/unit/test_tier_defaults.py`).

### Changed
- Bundled core v0.14.0.
- **`docker-compose.yml` no longer enables writes.** It set `MCP_ENABLE_WRITES: "true"`; the container is now
  read-only unless `.env` sets `MCP_ENABLE_WRITES=true` (and `MCP_ENABLE_DANGEROUS=true`). Operators who relied
  on the compose default must add it to `.env`.
- **stutters-mcp-core is bundled into the package (F35, #80; core C20 / ADR-005).** The wheel, sdist and image
  carry core v0.13.0 as `fmc_mcp._core`, so installing needs no git dependency and Docker needs no
  `CORE_READ_TOKEN`. The pin is `[tool.bundle-core]` (tag + commit) in `pyproject.toml`; core's runtime
  dependencies are listed in the server's own. `scripts/bundle_core.py` vendors it (`vendor`, after a clone),
  checks for drift (`check`) and moves the pin (`update --tag`). Code and tests import `fmc_mcp._core`; importing
  the package without the bundle says how to fix it.
- `fmc_status` reports the bundled core version (`server.core_version`).
- CI: the core `bundle-core.yml` job vendors, fails on drift, builds the wheel and sdist, installs the wheel
  with `pip install --no-index` in a clean venv and runs the unit + contract suite against it. The release
  builds the image from the bundled wheel.
- README: `uvx` installs from the release wheel; a git checkout no longer installs without `vendor`.

- **Live tests are environment-driven (F39, #84).** Inputs that depend on one FMC/FTD (device name, FTD
  addresses, packet tracer and ping targets, leaf domain, realm, group, identity policy) come from documented
  `FMC_LIVE_*` variables (environment or `.env`); a test whose variables are unset skips and names them. New:
  `FMC_LIVE_FTD_OUTSIDE_IP`, `FMC_LIVE_FTD_GATEWAY`, `FMC_LIVE_TRACE_TARGET`, `FMC_LIVE_FTD_NO_ARP_IP`,
  `FMC_LIVE_NTP_SERVER`, `FMC_LIVE_LEAF_DOMAIN`, `FMC_LIVE_REALM`, `FMC_LIVE_REALM_GROUP`,
  `FMC_LIVE_IDENTITY_POLICY`; `FMC_LIVE_DEVICE` is now required (no built-in default) and
  `FMC_LIVE_PING_TARGET` defaults to `FMC_LIVE_FTD_GATEWAY`. All of them are listed in the new
  `docs/live-tests.md` and, commented, in `.env.example`.
- `scripts/capture_fixtures.py --ftd` takes the device from `FMC_LIVE_DEVICE` and the trace target from
  `FMC_LIVE_TRACE_TARGET`; its redaction no longer names a lab platform.

### Removed
- The git source for stutters-mcp-core and `CORE_READ_TOKEN` (Dockerfile build secret, compose, workflows).
- Lab seed scripts `scripts/seed_lab.py`, `seed_access.py`, `seed_domain.py` and `seed_identity.py` (F39, #84):
  they moved to the suite's private lab repo (stutters-mcp-lab). `docs/least-privilege.md` keeps the GUI steps
  and the description of the endpoints the role/user script uses; `docs/live-tests.md` describes the seeded
  `mcp-test-*` objects the read tests expect.

## 0.10.1 (2026-10-16)

Tools unchanged (59 read, 68 write, 9 dangerous).

### Changed
- `scripts/seed_identity.py` prefers LDAPS: the realm points at `dc01.mitchcloud.lab:636` with the lab CA when
  FMC's directory test passes, otherwise it keeps (or restores) plain LDAP to 198.18.130.11:389 and says why
  (`--ldap` skips the attempt). Directory edits omit `dirPassword`, which FMC keeps.

### Found live (DC now has its LDAPS certificate, CN=DC01.mitchcloud.lab, no IP SAN)
- FMC validates the LDAPS server certificate against the configured host: LDAPS to the IP fails FMC's test.
- FMC's DNS (198.18.128.1, 8.8.8.8) can't resolve `dc01.mitchcloud.lab`: even plain LDAP to the name fails, so
  LDAPS to the name fails too. LDAPS works once FMC resolves the name (FMC's DNS server set to the DC, a manual
  FMC system setting) or the certificate carries the IP.

## 0.10.0 (2026-10-16)

F13 identity slice (roadmap item moved back to Next once the lab got a real AD). Core pin unchanged (v0.12.4).
Tools: 59 read, 68 write, 9 dangerous (136).

### Added
- **AD/LDAP realms:** `fmc_get_realm` (directories, bind user, include/exclude groups, schedule, downloaded
  users and groups with the last sync time), `fmc_create_realm` (AD or LDAP, several directory servers,
  `ldaps://` / `starttls://` with a trusted CA; the bind password is write-only: never shown, its hash binds the
  confirm), `fmc_delete_realm` (blocked while identity rules use it), `fmc_create_trusted_ca` (PEM import,
  duplicate fingerprint check).
- **Realm test and download:** `fmc_test_realm` and `fmc_download_realm`. FMC 10.0's REST API has no AD/LDAP realm
  test or download (`testrealms` and `realms/operational/download` are Azure AD / SAML only), so these log in to
  FMC's web UI as the new optional `FMC_UI_USERNAME` / `FMC_UI_PASSWORD` (its own user: a UI login ends the same
  user's REST session) and call the realm page's functions; the download waits for FMC's task message and reports
  groups/users before and after.
- **Identity policies:** `fmc_get_identity_policy` (rules, the access policies using it),
  `fmc_create_identity_policy`, `fmc_create_identity_rule` (PASSIVE / ACTIVE captive portal / NO, realm, zones,
  networks, ports; placed in the standard category), `fmc_delete_identity_rule`.
- **Access rules on AD users and groups:** `fmc_create_access_rule` / `fmc_update_access_rule` take `users`
  (`group`, `realm\\name`, `user:name`); the preview is blocked when the access policy has no identity policy or
  that policy has no rule for the realm (FMC's own refusal, explained). Update previews show users before/after.
- **`fmc_rule_lookup(identities=[user, groups])`** evaluates user/group rules; without it they stay conditional.
- `scripts/seed_identity.py`: trusted CA, realm, download, identity policy + passive rule, and the access policy
  link (Playwright, UI only). `scripts/seed_access.py` adds `identity_realms.modify` to `mcp-rw` and the UI user
  `mcp-ui-svc`.

### Fixed
- `scripts/seed_domain.py` (and the new seed script) find FMC 10.0.1's login fields by label; the old
  `input[type=text]` selector no longer matched.

### Known FMC limits (documented in the tools)
- An access policy's identity policy can't be set over REST: FMC accepts `identityPolicySetting` on PUT and
  silently drops it (the UI saves it over GWT-RPC). Select it in the access policy editor's Identity step.
- User-to-IP mappings need a passive source (ISE/pxGrid, identity agent) or captive portal; FMC has no REST call
  to inject them.

## 0.9.1 (2026-10-15)

Core pinned to v0.12.4. Tools unchanged: 56 read, 61 write, 9 dangerous (126).

### Fixed
- **Write previews show what a PUT removes**: every update whose preview is a field diff and whose apply sends the
  whole object now uses `field_changes(..., replace=True)`, so a field the replacement drops is listed as
  `"removed": true` instead of being hidden: `fmc_update_access_rule` (switching a rule away from ALLOW drops its
  intrusion and file policy), `fmc_update_prefilter_rule`, `fmc_update_object` (a port object set to all ports
  drops `port`; ICMP set to any drops `icmpType`/`code`), `fmc_update_nat_rule`, `fmc_configure_syslog` (basic
  logging, syslog settings) and `fmc_set_access_logging`. FMC has no PATCH endpoints, so nothing stays partial.

## 0.9.0 (2026-10-15)

Operator-eyes quality pass (F26-F33): 12 operator tasks run through the tools against the live FMC 10.0.1 + FTDv.
Core pinned to v0.12.2 (truncation note kept next to a tool's note; `server_version` in fmc_status; FMC examples in the spec tools' descriptions). Tools unchanged:
56 read, 61 write, 9 dangerous (126).

### Fixed
- **Audit lookups (F26)**: FMC returns only the newest 100 audit records per request and logs every API read, so
  `fmc_list_audit_records` and `fmc_recent_activity` saw only the last few minutes ("who changed it?" -> no
  results). The window is now read newest first in `endtime` slices (up to 2500 records, a note says how far back
  it got), reads and operational requests (hit-count refresh, packet tracer, show commands) are skipped by default
  (`changes_only`), API URLs are shortened, and the timeline drops API rows that repeat a worded row and the
  deployment request/task rows its deploy rows already show.
- **Hit-count times (F27)**: FMC reports them in its local time zone with a `Z`; they were up to hours off. The
  offset is learned from the refresh and the times are converted to UTC (else labelled FMC local time).
- **Dynamic objects in rule views (F28)**: `fmc_list_access_rules` hid the src/dst dynamic-object conditions (the
  quarantine rules looked like block any-any); columns no rule uses are left out. `fmc_rule_lookup` checks dynamic
  objects against their current mappings: an empty quarantine no longer shows as 'may match', a contained host
  matches the block rule.
- **NAT lookup by IP (F30)**: `fmc_list_nat_rules(address=..., device=...)` keeps rules whose original or translated
  addresses contain the IP through objects or groups (text search found nothing) and shows object values.
- **Rule update previews (F29)**: replacing a condition showed only the new part (core's field_changes walks only the
  new body), so a literal replaced by an object vanished unseen; conditions are now shown as labels before/after.
- **Cross-references (F32)**: fmc_delete_device named a non-existent `fmc_break_ha_pair`, fmc_list_vpn_tunnels and
  fmc_get_platform_settings pointed at old routes; a contract test checks every `fmc_*` name in descriptions,
  argument help, instructions and prompts.

### Changed
- **Flow context (F31)**: `fmc_rule_lookup` takes `device` (policy and ingress/egress zones from its interface
  subnets and static routes, reported under `device`; `policy` is now optional); `fmc_packet_tracer`'s
  `input_interface` is optional (picked from the source IP). The `fmc_why_blocked` prompt drops its discovery steps.
- **Token trims (F33)**: access-rule create/update results are the flattened rule (was FMC's full echo), `show route`
  drops the codes legend, rollback previews show each deployment's note, the rule export carries the default action.

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

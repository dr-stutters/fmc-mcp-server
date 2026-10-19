# Wave 5 live proofs (firewall run, 2026-10-18/19)

The Wave 5 tools (F34, F41, F43, F49, F54-F65) run against FMC 10.0.1 with FTDv 10.0 in CML, in domain
`Global/mcp-test-leaf`, on a server built from the merge-chain head of the 15 Wave 5 PRs (180 tools, 11 prompts).
Each proof uses the new tool itself, then confirms on the device (`fmc_run_show_command`, packet tracer, the FTD
console through cml-mcp) or with traffic from the lab hosts.

Lab addresses and hostnames are not in this file. Placeholders:

| Placeholder | What it is |
|---|---|
| `<client>` | the 802.1X client behind `mcp-ftd-identity` (inside) |
| `<client-net>` | the client's /24 |
| `<outside-host>` | the web/DNS server outside `mcp-ftd-identity` |
| `<si-hit>` | a second address on the outside host, listed in the SI IP feed |
| `<feed-host>` | the HTTP server that serves the SI feeds (`mcp-fw-feed`) |
| `<dnd-host>` | the outside host's second address, exempted from decryption |
| `<branch-wan>`, `<carrier-leg>` | the new branch FTD's WAN address and the internet carrier's leg it routes to |
| `<gambling-hostname>` | a public hostname in the Gambling URL category, resolved to `<outside-host>` with `curl --resolve` |

Status: **pass**, **fail** (a tool bug; root cause given), **blocked** (a lab, licence, role or platform limit), or **not run**.

## Summary

| # | Item | Status | Evidence (one line) |
|---|---|---|---|
| 1 | F59 `fmc_find_address` | blocked | seeds in place (host, group, access rule, unassigned NAT policy, dynamic-object mapping); the tool was not callable (B0) |
| 2 | F55 `fmc_live_connections` / `fmc_user_identity_sessions` | blocked | buffer logging live on the device with real built/teardown lines for the client's long-lived flow; tool not callable (B0); identity sessions 403 (B1) |
| 3 | F57 `fmc_device_metrics` | blocked | a 3-minute burst is visible in FMC's raw `health/metrics` (bytes, packets, data-plane CPU); tool not callable (B0) |
| 4 | F43 file policy | partial | `mcp-fw-file` (block MSEXE, reset) built from the tools' previews via `fmc_api_call` during proof 8: `.exe` over HTTP and HTTPS reset; the tools themselves not callable (B0) |
| 5 | F63 URL category in access rules | partial | rule with category Gambling (body from the tool's preview, sent via `fmc_api_call`) resets HTTP and decrypted HTTPS to a gambling hostname, rule hit counted; tool not callable (B0) |
| 6 | F61 SI feeds + custom lists | blocked | tools not callable (B0); FMC downloads a feed from `<feed-host>` at create time (probe), see the feed-status finding |
| 7 | F62 IPS on traffic + `fmc_threat_defense_review` | split | IPS **pass** (Talos 1:498 and 1:58723 drop the client's requests, normal page loads); posture tool and prompt not callable (B0) |
| 8 | F64 TLS decryption | pass (traffic), 2 bugs | client trusts the resigning CA; HTTPS to `<outside-host>` re-signed and verified, `.exe` / EICAR / IPS trigger / blocked category reset inside TLS; `<dnd-host>` untouched; `fmc_tls_decryption_check` mis-reads FMC's default certificate-status block (R1); rules need `tlsVersions` or the deploy is refused (R2) |
| 9 | F41 + F49 VPN status / troubleshoot | pass (status, wrong PSK); dead WAN partial | `mcp-fw-t1` (hub + 3 spokes) built with `fmc_create_sdwan_topology`; `fmc_vpn_status` shows 3 tunnels, both ends' SAs, IPsec counters, BGP routes; wrong PSK named from growing authentication failures; dead WAN reported TUNNEL_DOWN but without the dead-path verdict (R2); false overlay-routing warning on a DVTI hub (R1) |
| 10 | F54 `fmc_onboard_branch` | pass | prompt followed end to end: register without a key argument, manual path (no template), join `mcp-fw-t1`, deploy hub + branch only; tunnel READY, BGP routes both ends, host pings, packet tracer, `fmc_prove_policy` hand-off 3/3 pass |
| 11 | F58 interface kinds | pass (loopback, VTI, BVI); EtherChannel blocked | bodies from `fmc_create_interface` previews accepted by FMC; deployed and on the device; FMC refuses EtherChannel on FTDv (the preview should say so, R1); the delete guard (VTI borrows the loopback) works |
| 12 | F65 HA under traffic | pass | `fmc_ha_failover_check` walked: planned switch hitless (0/600 pings lost, a 5 Mbit/s TCP flow never dipped); active unit powered off: one 15.2 s gap (= the 15 s hold time), the TCP flow resumed on the same connection; `fmc_get_ha_status(live=True)` read the survivor while the other unit was off and named each failover's reason |
| 13 | F34 ISE identity source | not run | |
| 14 | F56 `fmc_prove_policy` | not run | |

## Proofs

### Blockers that apply to several proofs

- **B0, stale tool list in the agent's MCP client (all new tools).** The server reported 180 tools (`fmc_status`), but the
  client session the live agent ran in had connected before the redeploy and still listed main's 153 tools, so no Wave 5
  tool or new argument could be called. Lab-side setup and device-side checks were done with the existing tools; each
  blocked proof is one tool call once the client reconnects.
- **B1, FMC role.** `analysis/activesessions` and `analysis/useractivity` answer 403 "The user is not authorized" for the
  API role (it needs Events & Logs > Analysis > Users).

### 1. F59 `fmc_find_address` (blocked: B0)

Seeded in `Global/mcp-test-leaf` for `<client>`: host `mcp-fw-client`, network group `mcp-fw-clients-grp` (holding the host),
access rule `mcp-fw-find-client` in `mcp-fw-threat-acp` (source = the group), NAT policy `mcp-fw-nat` (not assigned) with an auto
interface-PAT rule for the host, dynamic object `mcp-fw-dyn` with `<client>` mapped (`fmc_map_dynamic_object`). Next:
`fmc_find_address('<client>')`, then with `device='mcp-ftd-identity'` and with `<client-net>`.

### 2. F55 live connections (blocked: B0, B1)

Device side ready: platform settings `mcp-fw-ps` on `mcp-ftd-identity` (buffer at informational, 1 MiB, the 3020xx connection
messages enabled, RFC 5424 timestamps). The FTD logs the client's flows as:

```
2026-10-18T23:00:57Z: %FTD-6-302013: Built inbound TCP connection 29 for inside:<client>/58778 (<ftd-outside>/58778) to outside:<outside-host>/80 (<outside-host>/80) -1 -1
2026-10-18T23:00:57Z: %FTD-6-302014: Teardown TCP connection 29 for inside:<client>/58778 to outside:<outside-host>/80 duration 0:00:00 bytes 318 TCP FINs from outside -1 -1
2026-10-18T23:00:58Z: %FTD-6-302020: Built inbound ICMP connection for faddr <client>/2712 gaddr <outside-host>/0 laddr <outside-host>/0 type 8 code 0 Internal-Data0/-1:RX[-1]
```

All interfaces share one security level, so an inside-initiated flow is "inbound" with the initiator first (ICMP: `faddr`).
No Snort 430002/430003 lines reach the buffer. `fmc_user_identity_sessions`: the endpoints it reads answer 403 (B1).

### 3. F57 device metrics (blocked: B0)

Burst: iperf from the HA inside host to `<feed-host>` through `mcp-fw-ha` (active unit `mcp-fw-ha-a`), 180 s at 142-175 Mbit/s.
FMC's raw `health/metrics` for the active unit shows it: interface `all` input bytes rise ~1.1 GB per one-minute sample for four
samples, average packet size goes from ~75 to ~1280 bytes, `lina_dp_avg` CPU peaks at 10.3 % (0 before), `snort_avg` stays ~0
(no IPS on that policy). The samples trail the traffic by 60-90 s.

### 4-6. F43, F63, F61 (blocked: B0)

All three need tools or arguments the client could not call. Facts for the re-run:

- `mcp-ftd-identity` has the MALWARE_DEFENSE, IPS and URL licences; its health reports "Unable to reach Cisco Cloud from the
  device", so malware cloud lookups and URL category lookups get no verdict here (EICAR: use a custom detection list).
- **F61 feed status (likely tool bug, see the run notes).** A probe feed created with `fmc_api_call` on `<feed-host>`: FMC fetched
  it at create time (`metadata.validEntries` lists all 4 entries seconds later), but `metadata.entryCount` stays 0 and there is
  no `feedUpdateTime`; only `metadata.timestamp` moves when the download lands. `fmc_get_security_intelligence`'s feed status reads
  `feedUpdateTime`/`entryCount`, so it would report a downloaded feed as "not downloaded yet".

### 7. F62 IPS on traffic (pass) and the threat-defense review (blocked: B0)

- `fmc_find_intrusion_rules`: 1:498 "INDICATOR-COMPROMISE id check returned root" is DISABLE in Balanced; 1:58723 (Log4j) is BLOCK.
- `fmc_create_intrusion_policy('mcp-fw-ips', base Balanced, PREVENTION)`, `fmc_set_intrusion_rule_state(1:498, BLOCK)`,
  `fmc_update_access_rule(intrusion_policy='mcp-fw-ips')` on both ALLOW rules, deploy `mcp-ftd-identity` only.
- From the client, before -> after:

| Request | Before | After |
|---|---|---|
| `curl http://<outside-host>/uid.txt` (body `uid=0(root) ...`) | `200`, 39 bytes | headers `200`, body 0 bytes, timeout (1:498 dropped the response) |
| `curl -H 'X-Api-Version: ${jndi:ldap://test/a}' http://<outside-host>/` | `200` | `000`, timeout (1:58723) |
| `curl http://<outside-host>/index.html` | `200` | `200` |

- FTD console: `show snort statistics` "Blacklisted Flows 2"; `show asp drop` "Blocked or blacklisted by the IPS preprocessor
  (ips-preproc) 2". A long-lived download through the same rule survived both deploys.
- One deploy was refused by FMC's pre-deploy validation: "Syslog servers not configured in Threat Defense Platform settings.
  Access Control Logging is configured to use Threat Defense Platform settings for sending syslog." Adding a syslog server to
  the platform settings cleared it.

### 8. F64 TLS decryption, decrypt-resign (pass on traffic; bugs R1, R2)

Setup (`Global/mcp-test-leaf`, device `mcp-ftd-identity`):

- Resigning CA: a 30-day throwaway CA generated in the agent's scratch directory and uploaded as internal CA `mcp-fw-resign-ca` by
  the lab script `fw_resign_ca.py` (it reads the PEM files itself; the PKCS#8 key was accepted by FMC 10.0.1). `fmc_get_certificate`
  shows it (internal CA, self-signed, 29 days left) with its PEM, which was installed in the client's trust store.
- The outside host's server certificate is self-signed, so it was imported as trusted CA `mcp-fw-outside-host-ca` and added to the
  decryption policy's trusted CAs (otherwise FMC re-signs it as untrusted).
- Decryption policy `mcp-fw-dec` (FMC defaults: TLS 1.3 decryption on, untrusted issuers not re-signed as trusted): rule 1
  `mcp-fw-dnd` DO_NOT_DECRYPT to `<dnd-host>`, rule 2 `mcp-fw-resign` DECRYPT_RESIGN to `<outside-host>` tcp/443 with the internal CA,
  logged. Linked to `mcp-fw-threat-acp`, which also carries `mcp-fw-ips` (proof 7), file policy `mcp-fw-file` (block MSEXE with reset)
  and `mcp-fw-url-block` (URL category Gambling, BLOCK_RESET).
- B0 applied: the new write tools (`fmc_create_decryption_rule action='DECRYPT_RESIGN'`, `fmc_update_decryption_policy`,
  `fmc_create_file_policy`/`_file_rule`, `file_policy=` and `url_categories=` on access rules) were run as previews on the chain-head
  code and their exact bodies sent with `fmc_api_call`; FMC accepted every body unchanged.

From the client (curl without `-k` unless noted), before and after the deploy:

| Request | Before | After |
|---|---|---|
| `https://<outside-host>/index.html` | certificate error (self-signed) | `200`; issuer `O=MCP Lab, OU=throwaway, CN=mcp-fw-resign-ca`, subject = the server's CN, "SSL certificate verify ok" |
| `https://<outside-host>/test.exe` | `200`, 1024 bytes (with `-k`) | `200` headers, 0 bytes, connection reset (file policy, inside TLS) |
| `https://<outside-host>/eicar.com` | `200`, 68 bytes (with `-k`) | 0 bytes, timeout (IPS 1:37732 "eicar test string", inside TLS) |
| `https://<outside-host>/uid.txt` | `200`, 39 bytes (with `-k`) | 0 bytes, timeout (IPS 1:498, inside TLS) |
| `https://<gambling-hostname>/` resolved to `<outside-host>` (with `-k`: the re-signed certificate keeps the server's name) | | reset (`mcp-fw-url-block`, 2 hits) |
| `https://<dnd-host>/` | | not re-signed: issuer stays the server's own CN; `/uid.txt` with `-k` still `200`, 39 bytes (not inspected) |
| `http://<outside-host>/test.exe` | `200`, 1024 bytes | reset (F43 file policy over HTTP) |

FTD console: `show asp drop` counts "Blocked or blacklisted by the file process preprocessor" 2 and "by the IPS preprocessor" 5.

`fmc_tls_decryption_check(<client>, <outside-host>, device='mcp-ftd-identity')` found the access policy link, the ingress/egress zones
and, after the deploy, `deployed: ok`, but its verdict was wrong:

- **R1 (fail):** "No rule matches definitively -> default action DO_NOT_DECRYPT", with `mcp-fw-resign` only under `may_match_first`
  (`depends_on: certificateStatuses`). FMC 10.0.1 returns a `certificateStatuses` block with every status `ANY` and a `tlsVersions`
  block on every rule, even when they were never set, and the check counts any non-empty block as a certificate condition. Expected:
  DECRYPT_RESIGN by `mcp-fw-resign` (and DO_NOT_DECRYPT by `mcp-fw-dnd` for `<dnd-host>`). `fmc_get_decryption_policy` lists the
  same two blocks as `cert_conditions`.
- **R2 (fail):** a decryption rule created without `tlsVersions` is stored with every version `false`, and FMC's pre-deploy validation
  then refuses the deploy: "Support for SSL Versions selection for Do not decrypt rule is deprecated ..." (same for Decrypt - Resign).
  With all five versions `true` in the rule the deploy passes. `fmc_create_decryption_rule` should send that block.

### 9. F41 `fmc_vpn_status` + F49 `fmc_vpn_troubleshoot` (pass; R1, R2)

Built with the released tools: `fmc_create_sdwan_topology('mcp-fw-t1')` on `mcp-sdwan-t1-hub` + spokes 1-3, hub DVTI `mcp-fw-dvti` on
the internet carrier with a new loopback `mcp-fw-dvti-lo` and pool `mcp-fw-t1-pool`, iBGP overlay, the existing overlay zone of the
T1 access policy; one deploy of the four devices.

- Device side: the hub has 3 IKEv2 SAs READY (AES-GCM-256, DH 21, PSK) and BGP routes to the three spoke LANs via the spokes' tunnel
  addresses; host-to-host pings across the overlay 3/3.
- `fmc_vpn_status(topology='mcp-fw-t1')`: 3 tunnels TUNNEL_UP; per tunnel `device_says` READY on both ends with IPsec packet
  counts; per device the IKE SAs, IPsec SAs (the hub's virtual-access interfaces), l2l sessions, IKEv2 counters; the spokes'
  `overlay_routes` list the 3 BGP routes over the tunnel. `device=<spoke>, tunnel_details=True` limits the view to that spoke;
  its `fmc_details` came back empty (no reason given; nit).
- **R1 (fail):** a false warning on the hub: "3 IKE SA(s) READY but no routes over the VTIs (mcp-fw-dvti)". FTD prints the routes to
  a DVTI's peers as two-line `V` entries (`V <addr> 255.255.255.255` then `connected by VPN (advertised), <dvti>_va<N>`), and the route
  parser doesn't attach the second line's interface, so the hub's BGP next hops don't resolve to the VTI.

Wrong pre-shared key (topology switched to a manual key, deployed to one spoke only, its SA cleared): the `fmc_vpn_troubleshoot`
prompt's step 1/2 walk with two `fmc_vpn_status` calls a minute apart gives **critical TUNNEL_DOWN** with "IKEv2 authentication
failures rose by 3 in the last 73 s: a pre-shared key (or certificate) mismatch, not a dead path" on both ends, and
`fmc_pending_changes` on the hub shows the undeployed IKEv2 authentication change: verdict "key mismatch, one end not deployed",
fix "deploy both ends". Restored (automatic keys, four devices deployed).

Dead WAN (the spoke's internet link down in CML): **critical TUNNEL_DOWN**, but "no IKEv2 failures in the last 73 s" (and 133 s).
- **R2 (gap):** after DPD removes the SA, the spoke re-initiates IKE only every few minutes, so the retransmit counters rarely grow
  between two calls a minute or two apart; the CML link-down also leaves the FTD interface up/up. The prompt then points at
  "compare the IKE policies". Pinging the spoke's carrier gateway (no answer) is what names the dead path. The tool should treat
  "no SA, no authentication failures, retransmit / initial-exchange failures on record" as "the peer doesn't answer", and the prompt
  should check the path before the IKE policies when nothing grows.

### 10. F54 `fmc_onboard_branch` (pass)

Lab fix first: the internet carrier of the T1 lab (Docker IOL, console silent) got its new leg toward the bridge through its day-0
configuration (`cml_set_node_config` on the wiped node, the recipe's config without the lines that hold secrets, plus the new
interface) and a restart; the leg answered on the bridge. The branch FTD (`mcp-fw-branch` lab) was wiped and given four more NICs
before registration (proof 11).

The prompt (`name='mcp-fw-branch1'`, `topology='mcp-fw-t1'`, `access_policy='mcp-fw-base-acp'`, WAN `<branch-wan>/18` via
`<carrier-leg>`, inside `/24`, test destination = the hub's host) was followed step by step:

| Step | Tool calls | Result |
|---|---|---|
| 0 | `fmc_license_status`, `fmc_list_devices`, `fmc_get_device` (a spoke) | licence authorised; branch not registered; spokes FTDv5 ESSENTIALS |
| 1 | `cml_run_commands` 'show managers' | FMC listed, registration Pending (day-0 holds the server's key) |
| 2 | `fmc_register_device(..., no reg_key)` | preview: "registration_key: from server config (FMC_FTD_REG_KEY)"; discovery succeeded; six data interfaces seen |
| 3 | `fmc_list_device_templates` | none: manual path |
| 4 | `fmc_update_interface` x2, `fmc_create_static_route` (default via the carrier leg), `fmc_create_access_rule` (inside <-> overlay zone), hub return route (`show route <branch-wan>` was "% Network not in table") | branch-only deploy OK; underlay pings to the carrier OK |
| 5 | `fmc_update_sdwan_topology(add_spokes=[branch on inet, inside])` | endpoint added; hubs + branch to deploy |
| 6 | `fmc_pending_changes` (hub: the topology, spoke, route and object only), `fmc_deploy([hub, branch])` | both SUCCEEDED |
| 7 | `show crypto ikev2 sa`, `show route bgp` (both ends), `cml_check_reachability`, `fmc_packet_tracer`, `fmc_sdwan_status(branch)` | IKEv2 READY; branch learns the hub and the 3 spoke LANs, hub learns the branch LAN via the branch's tunnel address; branch host -> hub host and spoke1 host 3/3 at the first attempt; tracer: allow, egress the SD-WAN VTI, rule `mcp-fw-branch-overlay`; `degraded` empty |
| 8 | `fmc_prove_policy` with the hand-off flows | **3/3 pass**: branch -> hub icmp allow (`mcp-fw-branch-overlay`), hub -> branch icmp allow (the T1 policy's overlay rule), branch -> hub tcp/25 block (default action) |

Nit: `fmc_update_sdwan_topology`'s preview doesn't show the new spoke's tunnel address (the prompt's step 5 says it does).

### 11. F58 `fmc_create_interface` (pass for loopback, VTI, BVI; EtherChannel blocked by the platform; R1)

On `mcp-fw-branch1` (four spare NICs added in CML before registration). B0 applied: each body came from the new tool's preview
and was sent unchanged with `fmc_api_call`; FMC accepted it.

- Loopback10 `mcp-fw-lo` (/32), static VTI Tunnel20 `mcp-fw-vti` (source the WAN, borrowing the loopback's address, zoned) and
  BVI1 `mcp-fw-bvi` (bridge group 1 on two spare NICs, /29). Branch-only deploy SUCCEEDED. `show interface ip brief`: BVI1 and
  Loopback10 up/up, Tunnel20 down/down (no VPN uses it yet, as the tool's side effect says). `show running-config interface`:
  `ip unnumbered mcp-fw-lo` + `tunnel source interface inet` on Tunnel20, `bridge-group 1` on both members.
- **EtherChannel:** the preview passed, FMC refused the POST: "Etherchannel interface is not supported on 'Virtual' Threat
  Defense." **R1:** the preview should block `kind='etherchannel'` on FTDv.
- The new `fmc_delete_interface` guard works: deleting the loopback is blocked while the VTI borrows it. Nit: the BVI delete
  preview says its members are released unconfigured, but FMC keeps their logical names.
- A ROUTED security zone on a bridge-group member is refused by FMC ("Security zone should be in same mode as of Interface mode
  type"): members need a SWITCHED zone.

Then `mcp-fw-t1` was torn down (topology, hub DVTI and loopback, pool, the hub's return route, the overlay rule, the F58
interfaces) and the five devices deployed; the hub has no IKEv2 SAs left. `mcp-fw-branch1` stays registered.

### 12. F65 HA under traffic, `fmc_ha_failover_check` (pass)

Pair `mcp-fw-ha` (two FTDv, failover and state on one link, outside/inside/management monitored with standby addresses). Test
host behind the pair; target: the bridge gateway; long-lived flow: `iperf -c <feed-host> -b 5M` (TCP).

The prompt (`action='switch'`) was followed step by step:

| Step | What | Result |
|---|---|---|
| 1 | `fmc_get_ha_status(live=True, history=5)` | primary Active, secondary Standby Ready, link up (shared with state), versions equal, HEALTHY_CONFIG, 11 checks ok, `ready_for_switch` true |
| 2 | `fmc_packet_tracer` on the active unit, `cml_check_reachability` x10 | allow (inside-to-outside rule, PAT); 10/10 |
| 4 | ping series (600 x 0.2 s) + iperf started, then `fmc_ha_action(switch)` | FMC task "Successfully switched active peer"; device history: switch 1 s after the confirm |
| 5 | `fmc_get_ha_status` (34 s after the switch) | secondary **Active**, primary **Standby Ready** already; `last_failover`: secondary "Other unit wants me Active (Set by the config command)", primary "Set by the config command (no failover active)" |
| 6 | tracer on the new active unit, 10 pings, the logs | allow; **600/600 replies, 0 % loss** (max RTT 26 ms); iperf: 132 one-second samples, none below 5.24 Mbit/s: the flow never noticed |

Unplanned (`action='fail_active'` done by hand: `cml_set_node_state stop` on the active unit's node, then start):

- Ping series: one gap of **76 probes = 15.2 s** (the pair's 15 s peer hold time), 824/900 received; iperf at 0 bit/s for 25 s
  (TCP backoff after the 15 s gap) and then back to 5.24 Mbit/s **on the same connection** (no reset): the replicated state kept it.
- `fmc_get_ha_status(live=True)` with that unit powered off **fell back to the survivor** (its show commands for the dead unit came
  back as FMC 500 "No response from device", kept as notes): survivor Active, other unit Failed ("Comm Failure"), `last_failover`
  "HELLO not heard from peer (failover link up, no response from peer)", blocker `standby_ready` failed, and a note that FMC's
  own unit states still showed the pre-failover roles (FMC lags; the units are current). The call takes about 80 s while one
  unit is off (its commands time out one by one).
- The stopped unit was started again and rejoined as standby (App Sync, then Standby Ready).

Separate state link (new `fmc_create_ha_pair` parameters): the pair was broken (`fmc_ha_action break`) and formed again with the
body from the tool's preview (`state_interface='Ethernet0/3'`, its own /30; sent with `fmc_api_call` under B0).

- FMC first refused it: "Primary and Secondary devices are not compatible. One or both Peers are dirty, One or both peer
  deployment is in progress" (the primary had an undeployed policy change). After deploying that unit the same body was accepted
  and the pair formed in about 8 minutes. **R1 (gap):** the preview should check that both units have nothing pending.
- `fmc_get_ha_status(live=True)` afterwards: failover link Ethernet0/2 up with `same_link_for_state: false`, state link Ethernet0/3
  up, primary Active, secondary Standby Ready. It also warned that re-forming had dropped the standby addresses of outside and
  inside (`monitoring_config`); restoring them with `fmc_configure_ha_monitoring` and deploying the pair cleared every warning.
  Traffic through the pair passes as before.


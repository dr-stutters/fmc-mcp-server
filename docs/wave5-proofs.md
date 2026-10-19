# Wave 5 live proofs (firewall run, 2026-10-18/19)

The Wave 5 tools (F34, F41, F43, F49, F54-F65) run against FMC 10.0.1 with FTDv 10.0 in CML, in domain
`Global/mcp-test-leaf`. Overnight (2026-10-18/19) the server was built from the merge-chain head of the 15 Wave 5 PRs; the
morning re-proof (2026-10-19, section "Re-proof on main") ran on `main` after all Wave 5 PRs and their follow-up fixes were
merged (180 tools, 11 prompts), calling every tool through MCP: preview, read, confirm, one call at a time. Each proof uses the
new tool itself, then confirms on the device (`fmc_run_show_command`, packet tracer, the FTD console through cml-mcp) or with
traffic from the lab hosts.

Lab addresses and hostnames are not in this file. Placeholders:

| Placeholder | What it is |
|---|---|
| `<client>` | the 802.1X client behind `mcp-ftd-identity` (inside) |
| `<client-net>` | the client's /24 |
| `<outside-host>` | the web/DNS server outside `mcp-ftd-identity` |
| `<si-hit>` | a second address on the outside host, listed in the SI IP feed |
| `<url-feed-host>` | a hostname listed only in the SI URL feed, resolved to `<outside-host>` with `curl --resolve` |
| `<feed-host>` | the HTTP server that serves the SI feeds (`mcp-fw-feed`) |
| `<dnd-host>` | the outside host's second address, exempted from decryption |
| `<branch-wan>`, `<carrier-leg>` | the new branch FTD's WAN address and the internet carrier's leg it routes to |
| `<gambling-hostname>` | a public hostname in the Gambling URL category, resolved to `<outside-host>` with `curl --resolve` |
| `<ise-fqdn>`, `<lab-root-ca>`, `<ad-realm>` | ISE's pxGrid node name, the lab's root CA (and FMC's trusted-CA object for it), the AD realm on FMC |
| `<ha-host>`, `<branch-host>`, `<hub-wan>` | the test host behind `mcp-fw-ha`, the host behind `mcp-fw-branch1`, the T1 hub's internet address |

Status: **pass**, **fail** (a tool bug; root cause given), **blocked** (a lab, licence, role or platform limit), or **not run**.

## Summary

Final status after the morning re-proof on `main`. "Overnight" in the evidence column refers to the sections further down.

| # | Item | Status | Evidence (one line) |
|---|---|---|---|
| 1 | F59 `fmc_find_address` | **pass** | 12 places for `<client>` ranked exact first (dynamic-object mapping, host, group, access rule, NAT rule), then the networks holding it; with `device=` the device's inherited NAT policy is now searched (overnight R1, fixed by #183) |
| 2 | F55 `fmc_live_connections` / `fmc_user_identity_sessions` | **pass**; sessions empty (pxGrid); history bug fixed in #211 | 60 connections of `<client>` from the device's buffer (open/closed, bytes, teardown reason); the role fix removed the 403: no session for `<client>` while FMC's ISE source is not connected; `history=true` hit FMC's 422 "Invalid time field." (R1, PR #211) |
| 3 | F57 `fmc_device_metrics` | **pass** | the overnight HA burst read back from FMC hours later: 155.5 Mbit/s in / 152.9 Mbit/s out, 15,261 pps, peak minute named, per interface |
| 4 | F43 file policy | **pass** | `fmc_create_file_policy` + three `fmc_create_file_rule` (MSEXE block, EICAR file-type block, BLOCK_MALWARE without reset), attached with `fmc_update_access_rule`: `.exe` reset over HTTP and inside decrypted HTTPS, EICAR reset by the file policy (device file-process drops 4 -> 8) |
| 5 | F63 URL category in access rules | **pass** (rule mechanics); category lookups beyond the local DB need the cloud | `fmc_create_access_rule(url_categories=[Gambling])` -> HTTP and decrypted HTTPS to `<gambling-hostname>` reset, other hostnames 200, 2 hits; `fmc_rule_lookup(url_category=...)` names the rule; packet tracer can only show it pending (no URL in a trace) |
| 6 | F61 SI feeds + custom lists | **pass** (traffic); 2 bugs, fix PRs #218, #215 | IP and URL feeds from `<feed-host>` and a custom list in the block list: `<si-hit>` and a URL-feed host blocked, packet tracer "Blocked ... by the reputation preprocessor" (about 30 min after create); feed status misread as "not downloaded yet" (R1), list replace refused (R2) |
| 7 | F62 IPS on traffic + `fmc_threat_defense_review` | **pass** | IPS drops (overnight); posture + prompt followed on `mcp-fw-threat-acp`: ranked report with a fix per finding |
| 8 | F64 TLS decryption | **pass** (traffic overnight; R1/R2 fixed by #190/#191 and re-proven); new R3 | `fmc_tls_decryption_check` now names `mcp-fw-resign` -> DECRYPT_RESIGN and `mcp-fw-dnd` -> DO_NOT_DECRYPT; a rule made by `fmc_create_decryption_rule` deploys without FMC's TLS-version refusal; `insert_before` makes FMC answer 500 although the rule is created (R3, fix PR #216) |
| 9 | F41 + F49 VPN status / troubleshoot | **pass** (R1, R2 fixed by #192/#193, re-proven) | `mcp-fw-t1` rebuilt: hub overlay routes resolve through the DVTI's `V` routes, no false warning; dead WAN now **critical** "the peer doesn't answer (dead WAN path ...)" on both ends, the path check confirms it; then torn down |
| 10 | F54 `fmc_onboard_branch` | **pass** | overnight: prompt end to end, `fmc_prove_policy` hand-off 3/3 |
| 11 | F58 interface kinds | **pass** (loopback, VTI, BVI); EtherChannel: platform limit, now refused in the preview (#194) | `fmc_create_interface(kind='etherchannel')` on the FTDv branch returns `blocked` with FMC's own message |
| 12 | F65 HA under traffic | **pass** | overnight: hitless switch, 15.2 s gap on power-off, separate state link |
| 13 | F34 ISE identity source | **partial**; enforcement **blocked: pxGrid** | tools report the failing source correctly; FMC still presents an old client certificate to ISE (B2, handled separately) |
| 14 | F56 `fmc_prove_policy` + `fmc_prove_user_policy` | **pass** (tool, prompt); alice/bob rows **blocked: pxGrid** | 4 of 6 flows pass, the 2 user rows report "no user on `<client>`" (true while B2 lasts) |
| - | Read-only live tests | pass | overnight: 7 passed, 1 skipped (the role 403, since fixed) |

## Blockers that apply to several proofs

- **B0, stale tool list in the agent's MCP client (overnight only).** The server reported 180 tools (`fmc_status`), but the
  client session the overnight live agents ran in had connected before the redeploy and still listed main's 153 tools, so no
  Wave 5 tool or new argument could be called. Resolved for the morning re-proof (the client reconnected).
- **B1, FMC role (resolved in the morning).** `analysis/activesessions` and `analysis/useractivity` answered 403 "The user is not
  authorized" for the API role overnight; the role now has Events & Logs > Analysis > Users and both answer.
- **B2, FMC's pxGrid client certificate (lab, handled separately).** Overnight the lab's FMC client certificate came from an earlier
  root of the lab CA, so ISE refused it. It was re-issued from the current root and loaded into FMC's certificate object; ISE
  accepts the new certificate when it is presented directly, but FMC's own Test still fails with "certificate unknown" (FMC keeps
  presenting the old one). Until that is fixed no user reaches the firewall, so user rules can't be proven on traffic (F34, F56).

## Re-proof on main (2026-10-19 morning)

Server: `main` with every Wave 5 PR and the overnight fix PRs merged (#183 assignment lists, #186 identity hooks, #188/#189 IPS and
hit-count fixes, #190/#191 decryption, #192/#193 VPN status, #194 interfaces, #195/#196 identity sources), 180 tools, 11 prompts.
Each write: preview, read, then the same call with the confirm token; deploys name `mcp-ftd-identity` (or the four T1 devices)
only. New findings got their own fix PRs (#211, #215, #216, #218), listed per item.

### F59 `fmc_find_address` (pass)

- `fmc_find_address('<client>')`: 12 rows. Exact: the dynamic object `mcp-fw-dyn` (mapping), host `mcp-fw-client`, group
  `mcp-fw-clients-grp` (via the host), access rule `mcp-fw-threat-acp` #4 `mcp-fw-find-client` (source, via group > host), the auto
  NAT rule of `mcp-fw-nat` (original source). Then "contains": the lab's client network object and the identity FTD's NAT rule on it,
  the inside supernet, FMC's RFC 1918 objects, two `mcp-test-*` rules on 10/8. 6 matches only through `any` counted, not listed.
- `device='mcp-ftd-identity'`: searched 1 access policy, **1 NAT policy** and lists the device's NAT rule on `<client-net>` (overnight
  R1: 0 NAT policies, because FMC lists a Global policy's assignment only in Global's list; fixed by #183).
- `fmc_find_address('<client-net>')`: the network object and its NAT rule exact, the five seeds `inside`.

### F55 live connections and identity sessions (pass; R1 fixed in #211)

- `fmc_live_connections(device='mcp-ftd-identity', host='<client>')`: 60 connections from the syslog buffer, 2 open (the long-lived
  download and the newest request), closed ones with bytes, duration and FTD's teardown reason, initiator `inside <client>:<port>`.
  Nits seen: the reason keeps FTD 10's trailing " -1 -1"; packet-tracer flows show up as connections ("Free the flow created as
  result of packet injection"; the eval's #214 filters them).
- `fmc_user_identity_sessions(ip='<client>')`: no 403 any more (role fixed); 0 sessions, "No active session ... no identity source
  reports this IP" (true: the ISE source isn't connected, B2).
- **R1 (fail, fixed in #211):** `history=true` (also `fmc_user_ip_lookup(history=true)`) -> FMC 422 "Invalid time field." on
  `analysis/useractivity`. FMC 10.0.1 refuses the `time=after:<epoch>` filter its own spec documents in every form tried (encoded or
  raw colon, `after:..,before:..`, milliseconds, ISO 8601); without `time` it answers 200. The fix applies the window in the server.

### F57 `fmc_device_metrics` (pass)

`fmc_device_metrics(device='mcp-fw-ha-a', since=<burst start - 7 min>, until=<burst end + 7 min>, metric='throughput')`, read about
five hours after the overnight burst: total in 155.5 Mbit/s, out 152.9 Mbit/s, 15,261 pps in, all peaking in the same minute, the
peak window named; per interface inside (in) and outside (out) carry it, the failover link stays at a few kbit/s.

### F43 file policy (pass)

- `fmc_create_file_policy('mcp-fw-file-av')`, then `fmc_create_file_rule` three times: BLOCK (reset) MSEXE over HTTP downloads
  (stored as `BLOCK_WITH_RESET`); BLOCK (reset) file type **EICAR**, any protocol and direction (FMC 10.0.1 has an EICAR file type,
  so no cloud and no custom detection list are needed; the custom detection list's SHA-256 entries are not in FMC's REST API, they are
  a system object edited in the UI); BLOCK_MALWARE on PDF with `reset=False` (FMC accepts `BLOCK_MALWARE` without reset; overnight
  this was an open question).
- `fmc_update_access_rule(file_policy='mcp-fw-file-av')` on `mcp-fw-baseline` and `mcp-fw-lab-extra` (preview: from `mcp-fw-file`
  to `mcp-fw-file-av`), plus a new ALLOW rule `mcp-fw-file-noips` to `<dnd-host>` tcp/80 with the file policy and no intrusion policy,
  so EICAR meets the file policy and not IPS rule 1:37732. Deploy `mcp-ftd-identity`: SUCCEEDED.

| From the client | Before | After |
|---|---|---|
| `http://<dnd-host>/eicar.com` | `200`, 0 bytes, timeout (IPS drop) | `200`, 0 bytes, **reset** (file policy) |
| `http://<dnd-host>/test.exe` | reset (overnight file policy) | reset |
| `http://<outside-host>/test.exe`, `https://<outside-host>/test.exe` (decrypted) | | reset, reset |
| `http://<dnd-host>/index.html`, `https://<outside-host>/index.html` | `200` | `200` |

FTD console: `show asp drop` "Blocked or blacklisted by the file process preprocessor" 4 -> **8** (the four blocks), IPS
preprocessor drops unchanged (6). Hit counts: `mcp-fw-file-noips` 3; `fmc_get_hit_counts` now lists the Default Action row too
(overnight nit, fixed by #189).

Nit: `fmc_get_file_policy(policy=...)` in markdown shows the rules as bare ids (the JSON has protocol, direction, types and action);
the same flattening hides `fmc_get_intrusion_policy`'s overridden rules. Its `used_by` is empty for a policy two rules use.

### F63 URL category in access rules (pass for the rule mechanics; what needs the cloud)

- `fmc_create_access_rule('mcp-fw-url-block', BLOCK_RESET, zones inside -> outside, url_categories=[{category: 'Gambling',
  reputation: 'ANY_AND_UNKNOWN'}], insert_before=1)`: preview shows `urlCategoriesWithReputation` with Gambling's id and "every site
  in the category"; deployed with F43.
- Client: `curl --resolve <gambling-hostname>:80:<outside-host>` -> `000`, reset; the same over HTTPS (decrypted) -> reset; another
  hostname to the same server -> `200`. `fmc_get_hit_counts`: `mcp-fw-url-block` 2 hits at the time of the two requests.
- `fmc_rule_lookup(<client> -> <outside-host> tcp/80, url_category='Gambling', device)`: "Rule 1 'mcp-fw-url-block' -> BLOCK_RESET".
- `fmc_packet_tracer` for the same 5-tuple: the access list sends the flow to Snort under `mcp-fw-url-block`, Snort says "no url or
  host" and allows: a trace carries no HTTP host, so it can only show the URL rule as pending (the tool reports `action: allow` with
  `verdict_rule: mcp-fw-url-block`; nit: it could say the verdict is provisional).
- What needs the Cisco cloud: the category and reputation of a URL that isn't in the device's local URL database (cloud lookup), and
  updates to that database. The gambling hostname was already in the local database, so the block worked without cloud access.

### F61 SI feeds and custom lists (pass on traffic; R1, R2 fixed in PRs)

- `fmc_create_si_feed(kind='ip', name='mcp-fw-ip-feed', url='http://<feed-host>/ip-feed.txt', refresh=30)` and the same for
  `kind='url'` (`mcp-fw-url-feed`); `fmc_upload_si_list(kind='ip')` twice: `mcp-fw-ip-list` (two documentation entries) and
  `mcp-fw-ip-list-hit` (`<si-hit>`); `fmc_set_si_lists(policy='mcp-fw-threat-acp', list_type='block')` with the feeds and lists
  (FMC stores the custom lists as `CustomSIIPListObject`; the tool sent the list type from FMC's catalog and FMC accepted it).
  Deploys of `mcp-ftd-identity` SUCCEEDED.
- **Traffic.** Right after the deploys (three tries over five minutes) `http://<si-hit>/` still answered `200` and packet tracer had
  no Security Intelligence phase. About 30 minutes after the feeds were created (the feeds' first refresh, and one more deploy for
  F64 in between) the device blocked: `http://<si-hit>/` -> `000` (connection refused at once), `curl --resolve
  <url-feed-host>:80:<outside-host>` (a host only in the URL feed) -> timeout, the decrypted HTTPS page to `<outside-host>` still
  `200`; `fmc_packet_tracer` to `<si-hit>` tcp/80: **drop, "(reputation) Blocked or blacklisted by the reputation preprocessor"**,
  phase SNORT. (Nit: the tool still names the access-list rule that handed the flow to Snort as `verdict_rule`.)
- **R1 (fail, fix PR #218):** `fmc_create_si_feed` and `fmc_get_security_intelligence` say "not downloaded yet, entries 0" for both
  feeds, before and after the device started blocking. FMC 10.0.1's feed object has `metadata.validEntries` = the feed's lines
  (read at create time) but keeps `entryCount` 0 and no `feedUpdateTime`; the tool keys only on those two. The fix reports
  "fetched: N valid entries; FMC doesn't report the load over REST" with a sample, and says how to check (packet tracer, drop reason
  `reputation`).
- **R2 (fail, fix PR #215):** replacing a list (`fmc_upload_si_list` again with the same name; the preview correctly says what it
  replaces) -> FMC 400 "Request UUID and data does not match.": the multipart PUT has no `id` field.

### F62 IPS + `fmc_threat_defense_review` (pass)

The prompt (arguments: `mcp-fw-threat-acp`, the leaf domain) was followed step by step:

1. `fmc_threat_posture`: default action BLOCK; 4 ALLOW rules: `mcp-fw-baseline` and `mcp-fw-lab-extra` with `mcp-fw-ips` (Balanced,
   PREVENTION) and `mcp-fw-file-av`, `mcp-fw-file-noips` with the file policy only, `mcp-fw-find-client` with neither; network analysis
   policy Balanced (PREVENTION); decryption `mcp-fw-dec`; identity policy `mcp-fw-idp`; device licences ESSENTIALS, IPS,
   MALWARE_DEFENSE, URL. Findings: medium `si_no_talos_network`; low `default_action_no_logging`, `allow_no_file_policy`
   (`mcp-fw-find-client`), `si_no_talos_url`, `dns_no_talos` (FMC's read-only default DNS policy), each with a tool call as the fix.
2. `fmc_policy_audit(checks=[no_intrusion, no_logging, permissive, shadowed])`: `no_intrusion` (medium) on `mcp-fw-file-noips` and
   `mcp-fw-find-client`; nothing shadowed or permissive.
3. `fmc_get_security_intelligence`: the run's feeds and lists in the block lists; both feeds "not downloaded yet" -> **high** per the
   prompt (the policy blocks less than it shows; see F61).
4. `fmc_get_intrusion_policy('mcp-fw-ips')`: Balanced base, PREVENTION, one override (1:498 BLOCK); nothing weakened.
5. `fmc_list_policies(kind='network_analysis')`: the four system NAPs; Balanced is used by this policy.
6. Report (ranked): high: both SI feeds "not downloaded yet" (as the tool reported them; F61's R1 shows FMC had fetched them and
   the device blocked their entries later); medium: no Talos network categories, two ALLOW rules without IPS; low: default action
   not logged, a rule without a file policy, no Talos URL categories, no DNS policy of its own. Fixes were not applied (step 7 offers
   them one preview at a time).

### F64 TLS decryption (pass; R1, R2 fixed and re-proven; R3 fixed in #216)

- `fmc_tls_decryption_check(<client> -> <outside-host>:443, device)`: **"Rule 2 'mcp-fw-resign' -> DECRYPT_RESIGN"**, inspection
  "Decrypted ...", readiness: link ok, CA expiry warning (throwaway 30-day CA), TLS 1.3 on, deployed. To `<dnd-host>`: **"Rule 1
  'mcp-fw-dnd' -> DO_NOT_DECRYPT"**. Overnight both said "default action" (R1, fixed by #190). `fmc_get_decryption_policy` lists no
  certificate conditions and no TLS-version problem.
- `fmc_create_decryption_rule('mcp-fw-dnd-doc', DO_NOT_DECRYPT, a documentation address, tcp/443, insert_before=1)`: the body now
  carries all TLS versions on (R2, fixed by #191) and the deploy of `mcp-ftd-identity` passed FMC's validation.
- **R3 (fail, fixed in #216):** with `insert_before` FMC 10.0.1 answered 500 "JsonNull" but stored the rule at index 1; the tool
  reported an error. Nit: `fmc_get_decryption_policy` lists rules in FMC's list order, not by index.
- HTTPS through the policy after these changes: `.exe` still reset inside TLS (F43 table), index page `200`.

### F41 `fmc_vpn_status` + F49 dead WAN (pass; R1 and R2 fixed and re-proven)

`mcp-fw-t1` rebuilt with `fmc_create_sdwan_topology` (hub + spokes 1-3 on the internet carrier, new DVTI, loopback and pool,
iBGP overlay, the T1 policy's existing overlay zone) and the four T1 devices deployed (SUCCEEDED).

- `fmc_vpn_status(topology='mcp-fw-t1', device=<hub>)` ten seconds after the deploy: 3 IKEv2 SAs READY (AES-GCM-256, DH 21, PSK),
  3 IPsec SAs on the DVTI's virtual-access interfaces, the hub's `overlay_routes` = the 3 spoke LANs over BGP via the spokes'
  tunnel addresses, which now resolve through the DVTI's `V` routes (FTD prints them on two lines; overnight R1, fixed by #192):
  **no "no routes over the VTIs" warning**. The only warnings: FMC's tunnel monitor still said UNKNOWN while the hub had READY SAs
  (FMC lags; the tool says so).
- Dead WAN (the prompt's dead-path case, overnight R2, fixed by #193): spoke2's internet link down in CML, then
  `fmc_vpn_status(device=<spoke2>)` four times over about two minutes (the server keeps the earlier counter readings):
  1. 34 s after: the hub already dropped spoke2's IPsec SA and BGP route, the spoke still showed its IKE SA READY (it notices only
     after DPD); `degraded` empty.
  2. 89 s: no IKE SA on either end; FMC still TUNNEL_UP -> warning "FMC shows TUNNEL_UP but ... has no IKE SA ... (FMC's tunnel
     monitor lags the device)".
  3. 140 s: FMC TUNNEL_DOWN -> **critical**, on both ends: "IKEv2 exchanges time out with no authentication failures: the peer
     doesn't answer (dead WAN path or UDP 500/4500 blocked)" (retransmit-limit counters grew by 1 in the window, authentication
     failures 0). Overnight the same case said only "no IKEv2 failures in the last 73 s".
  4. Path check as the prompt now says: `cml_check_reachability` from spoke2 to its carrier gateway and to the hub's WAN address:
     0/5 each -> dead WAN path on spoke2, nothing on FMC fixes it. Link restored.
- Then `mcp-fw-t1` was deleted again (`fmc_delete_s2s_vpn`, the hub's DVTI and loopback with `fmc_delete_interface`, the pool with
  `fmc_api_call` DELETE) and the four T1 devices deployed (SUCCEEDED).

### F58 `fmc_create_interface` EtherChannel on FTDv (pass)

`fmc_create_interface(device='mcp-fw-branch1', kind='etherchannel', members=[two spare NICs], lacp_mode='active')` returns
**`blocked`**: "mcp-fw-branch1 is an FTDv (Cisco Secure Firewall Threat Defense for KVM): FMC doesn't support EtherChannel interfaces
on virtual Threat Defense (FMC 10.0.1 refuses the POST with \"Etherchannel interface is not supported on 'Virtual' Threat
Defense\"). Use separate interfaces, or a bvi to bridge them." (overnight R1, fixed by #194). Nothing was sent to FMC.

### F34 / F56 user rows (blocked: pxGrid, handled separately)

Not re-run: FMC's ISE source still can't connect (B2). The tools' behaviour against the failing source was proven overnight
(sections 13 and 14); the alice/bob enforcement rows wait for the pxGrid fix.

## Overnight proofs (chain head, 2026-10-18/19)

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

### 13. F34 ISE identity source (partial; enforcement blocked: B2)

FMC 10.0.1's REST API has no identity-source object, so the lab seed script configures it in the web UI (Playwright) and the new
read tools check it. The script's selectors were unproven; the live run fixed them:

- The lab's UI service role has no Identity Sources page (Integrations shows only Dynamic Attributes Connector and Realms), so the
  step ran as the FMC administrator. FMC 10.0.1 offers the ISE source **in the Global domain only**: in a leaf domain the page is
  read-only (every service type disabled). The source and the internal certificate it references live in Global; the identity
  policy and the access-policy link stay in the leaf.
- Page: Integrations > Identity > Identity Sources (`/ui/identity-sources/ise`), Advanced Configuration: primary host, pxGrid
  Client Certificate, MNT Server CA, pxGrid Server CA (searchable comboboxes), Session Directory and SXP topics, Test (a Status modal
  with Additional Logs), Save. FMC refuses an identity policy description with a comma (alphanumerics, `_`, `.`, `-` and spaces).
- Created: internal certificate `mcp-fw-fmc-pxgrid` (Global), identity policy `mcp-fw-idp` with a PASSIVE rule for `<ad-realm>` on
  `<client-net>` (leaf), the ISE source (host `<ise-fqdn>`, client certificate `mcp-fw-fmc-pxgrid`, both server CAs = the existing
  trusted CA for `<lab-root-ca>`), `mcp-fw-idp` selected in `mcp-fw-threat-acp`; deployed to `mcp-ftd-identity` only.
- FMC's Test: "Primary host: Failure ... sslv3 alert certificate unknown ... AccountActivate failed: Request failed with a timeout".
  FMC reaches the node and resolves its name; ISE refuses the client certificate (B2). ISE lists no pxGrid client for FMC, so there
  was nothing to approve. Saved anyway so the remaining steps could run; the fix is to replace the certificate object.

| Step | Tool | Result |
|---|---|---|
| before | `fmc_get_identity_sources` | ISE `not_configured` with the UI steps under `configure`; realm with 5 users and 5 groups; sessions: the B1 403 text; every device 0 user-IP bindings |
| after Save | `fmc_get_identity_sources` | first sample: still `not_configured` (FMC's health module lags about 10 minutes, although the SGT list no longer answers "disabled"); then **`failed`, RED "Check connectivity to ISE"**, verdict "ISE/pxGrid connection FAILED", `next` names the certificate checks |
| alice logged in (recipe action) | `fmc_user_ip_lookup(ip=<client>, history=true)` | the 403 with the missing permission named (B1) |
| | `fmc_user_ip_lookup(user='mcp-bob')` | realm user with group `mcp-contractors`, plus `sessions_error` |
| rule `mcp-fw-contractors-telnet` (BLOCK_RESET, group `mcp-contractors`, tcp/23) above the baseline, deployed | `fmc_rule_lookup(device, <client> -> <outside-host>, tcp/23)` | no identities: `identity.error` (403), the contractors rule listed as conditional on users, baseline ALLOW; `identities=['mcp-bob']`: groups added from the realm download, **rule 1 contractors -> BLOCK_RESET**; `identities=['mcp-alice']`: group `mcp-employees`, **baseline -> ALLOW** |
| bob logged in | client `telnet` check, `fmc_packet_tracer` | port 23 **open**; tracer: the access list hands the flow to Snort for the user rule, Snort allows it by the baseline with "user 9999999" (no user on the IP) |
| | prompt `fmc_why_blocked` (followed) | rule lookup with the user from ISE -> contractors block; tracer -> allow, no user; hit counts: contractors 0; nothing pending; audit: the policy saves. Report: the policy blocks bob, the device can't, because it has no user for `<client>` (B2) |

The tools behave as designed against a failing identity source; the alice/bob enforcement proof waits for B2. Re-run after the fix:
replace `mcp-fw-fmc-pxgrid` with the re-issued certificate, Test in the UI, then repeat the table above (expect `connected`, SGTs,
bindings on `mcp-ftd-identity`, and bob's telnet reset).

**Findings:** R1 (wording): `fmc_get_identity_sources`' `configure`/`settings` text names "Integrations > Other Integrations >
Identity Sources"; FMC 10.0.1 has Integrations > Identity > Identity Sources, in Global only, for an admin-type role.
R2 (minor): right after Save the state stays `not_configured` until FMC's health module runs, although the SGT list is readable.

### 14. F56 `fmc_prove_policy` and `fmc_prove_user_policy` (pass; alice/bob blocked: B2)

One call, six flows, each with its device:

| # | Flow | Device | Expect | Result | Deciding rule |
|---|---|---|---|---|---|
| 1 | alice: `<client>` -> `<outside-host>` tcp/23 (user `mcp-alice`) | `mcp-ftd-identity` | allow | mismatch | baseline; "the device sees no user on `<client>`, not mcp-alice" |
| 2 | bob: same flow (user `mcp-bob`, rule = contractors) | `mcp-ftd-identity` | block | fail | baseline (allow); "sees no user" |
| 3 | `<client>` -> `<outside-host>` tcp/80 | `mcp-ftd-identity` | allow | pass | baseline |
| 4 | `<client>` -> `<outside-host>` tcp/25 | `mcp-ftd-identity` | block | pass | default action (drop) |
| 5 | `<ha-host>` -> `<feed-host>` tcp/80 | `mcp-fw-ha-a` (active) | allow | pass | `mcp-fw-inside-to-outside` |
| 6 | `<branch-host>` -> `<hub-wan>` tcp/443 | `mcp-fw-branch1` | allow | pass | `mcp-fw-inside-to-outside` |

Rows 1 and 2 are the real state (B2): the tool's user check turns "right verdict for an unknown host" into a mismatch instead of
a false pass. On the hosts: the client's tcp/80 answers 200, tcp/25 doesn't connect, tcp/23 connects for both users; the HA host
fetches a file from `<feed-host>`; the branch's default route points at the carrier.

The prompt `fmc_prove_user_policy` (allowed alice, blocked bob, tcp/23, both rules named) was followed: device and identity policy
(linked, PASSIVE rule for the realm); offline lookups per user (alice ALLOW by the baseline, bob BLOCK_RESET by the contractors
rule: the policy is right); ISE sessions for each user on `<client>`; live rows per user after each login (bob retried once after
60 s): mismatch / fail, no user seen; verbose packet tracer: Snort's identity phase "user id: unknown ... username: none";
contractors rule 0 hits; nothing pending. Report: the policy is right, the device has no user-IP mapping, cause B2.

### Read-only live tests (run on the chain head)

`uv run pytest -m live -k ...` (leaf domain, device `mcp-fw-branch1` for the interface test): **7 passed, 1 skipped** in 35 s:
`test_ha_failover_state_from_the_units` (F65, the re-formed pair), `test_ha_status_when_paired`, `test_vpn_and_ravpn_reads`,
`test_interface_kinds_and_create_preview` (F58), `test_file_and_network_analysis_reads` (F43), `test_si_feeds_and_lists_read`
(F61), `test_identity_sources_read` (F34, state `failed`); `test_user_ip_lookup_live` skipped on the B1 role 403. The tests log in as
the test user; the server's own FMC session was not ended (its login count did not change).

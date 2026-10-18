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
| 9 | F41 + F49 VPN status / troubleshoot | not run | |
| 10 | F54 `fmc_onboard_branch` | not run | |
| 11 | F58 interface kinds | not run | |
| 12 | F65 HA under traffic | not run | |
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

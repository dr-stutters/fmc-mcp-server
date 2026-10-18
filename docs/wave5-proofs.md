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

Status: **pass**, **fail** (a tool bug; root cause given), **blocked** (a lab, licence, role or platform limit), or **not run**.

## Summary

| # | Item | Status | Evidence (one line) |
|---|---|---|---|
| 1 | F59 `fmc_find_address` | not run | |
| 2 | F55 `fmc_live_connections` / `fmc_user_identity_sessions` | not run | |
| 3 | F57 `fmc_device_metrics` | not run | |
| 4 | F43 file policy | not run | |
| 5 | F63 URL category in access rules | not run | |
| 6 | F61 SI feeds + custom lists | not run | |
| 7 | F62 IPS on traffic + `fmc_threat_defense_review` | not run | |
| 8 | F64 TLS decryption | not run | |
| 9 | F41 + F49 VPN status / troubleshoot | not run | |
| 10 | F54 `fmc_onboard_branch` | not run | |
| 11 | F58 interface kinds | not run | |
| 12 | F65 HA under traffic | not run | |
| 13 | F34 ISE identity source | not run | |
| 14 | F56 `fmc_prove_policy` | not run | |

## Proofs

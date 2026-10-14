# FMC API gap analysis (Phase 2)

Against **FMC 10.0.1** (`/api/api-explorer/fmc.json`, Swagger 2.0, the spec the server indexes for
`fmc_search_spec`). Live work used a real **FTDv 10.0.0** registered to that FMC (CML lab
`mcp-cml-ftd`, recipe `ftd-fmc` in cml-mcp-server).

## 1. API surface

779 paths, **1446 operations**, in five surfaces:

| Surface | Operations | What it is |
|---|---:|---|
| `fmc_config` | 1352 | Objects, policies, devices, interfaces, routing, deployment, health, HA, VPN, ... |
| `fmc_platform` | 43 | Version/domains, audit, licensing, upgrades, system configuration |
| `fmc_tid` | 21 | Threat Intelligence Director |
| `fmc_troubleshoot` | 20 | Packet tracer (+ PCAP), CPU/Snort profilers, RADKit |
| `fmc_netmap` | 10 | Network map hosts / vulnerabilities |

Of these, **241 (17 %) are behind curated tools, 1175 (81 %) are reachable through `fmc_api_call`
(spec-guided by `fmc_search_spec` / `fmc_get_definition`), and 30 (2 %) can't usefully go through
MCP**: multipart uploads (Secure Client packages and profiles, custom Security Intelligence lists,
intrusion rule upload, PCAP upload for packet tracer, device import, bulk registration CSV) and
binary downloads (backups, deployment/pending-change report ZIPs, certificate exports).

The count is skewed by breadth: `object/*` alone has 124 collections and 533 operations, most of them
VPN, PKI, routing-policy and identity objects that are edited rarely and in big structured payloads.
Measured by **operator workflows**, the day-to-day work is covered by curated tools (section 3).

### Operations per area

Columns: total operations, curated, `fmc_api_call` only, not usable through MCP.

| Area | Ops | Curated | api_call | No |
|---|---:|---:|---:|---:|
| Objects (124 collections) | 533 | 89 | 423 | 21 |
| Device routing (static, BGP, OSPF, EIGRP, PBR, ECMP, VRF, BFD) | 114 | 27 | 87 | 0 |
| Platform settings (FTD) | 79 | 3 | 76 | 0 |
| Device interfaces (physical, sub, EtherChannel, VLAN, VTI, loopback, BVI, inline sets, VNI) | 70 | 28 | 42 | 0 |
| VPN (S2S, RA, dynamic access, tunnel status) | 64 | 7 | 57 | 0 |
| Chassis (multi-instance) | 43 | 0 | 43 | 0 |
| Access control (rules, categories, SI, logging, hit counts) | 38 | 13 | 25 | 0 |
| Integrations (cloud, Umbrella, AIOps, external storage) | 37 | 0 | 37 | 0 |
| Devices (records, onboarding, settings, model migration) | 33 | 4 | 25 | 4 |
| Device templates | 29 | 0 | 29 | 0 |
| Zero trust | 27 | 0 | 27 | 0 |
| Chassis platform settings | 26 | 0 | 26 | 0 |
| Users / external auth / SSO | 25 | 0 | 25 | 0 |
| NAT (auto, manual) | 23 | 15 | 8 | 0 |
| Intrusion / network analysis | 21 | 6 | 15 | 0 |
| Threat intelligence (TID) | 21 | 0 | 21 | 0 |
| DNS / Umbrella DNS | 20 | 3 | 17 | 0 |
| Prefilter | 18 | 6 | 12 | 0 |
| Upgrades / content updates | 16 | 0 | 15 | 1 |
| Identity, Decryption, File/malware | 38 | 9 | 29 | 0 |
| HA (failover pairs) | 13 | 5 | 8 | 0 |
| Health (alerts, events, metrics) | 12 | 5 | 7 | 0 |
| Deployment (pending, deploy, history, rollback) | 11 | 6 | 4 | 1 |
| Backup | 9 | 0 | 8 | 1 |
| Clustering | 9 | 1 | 8 | 0 |
| Device DHCP / DDNS | 9 | 0 | 9 | 0 |
| Troubleshoot (packet tracer, profilers, RADKit) | 20 | 1 | 18 | 1 |
| Device operational (show commands, metrics, out-of-band) | 8 | 1 | 7 | 0 |
| Domains, license, system configuration, info, audit | 27 | 5 | 22 | 0 |
| Change management (tickets) | 6 | 0 | 6 | 0 |
| Network map, analysis, search, device groups, alerts, FlexConfig, policy locks, tasks, assignment | 47 | 7 | 39 | 1 |

## 2. Gaps, scored by operator value

Value = how often a firewall engineer needs it x how error-prone it is through raw `fmc_api_call`
(multi-step flows, id lookups, async tasks, big payloads) x risk of getting it wrong.
H/M/L. **Built** = new curated tool in this phase.

| Gap (before Phase 2) | Need | Raw-call pain | Risk | Decision |
|---|---|---|---|---|
| Show commands on the FTD (verify a deploy) | H | M (2-word split, device id) | none | **Built** `fmc_run_show_command` |
| Packet tracer ("why is it blocked") | H | H (device+interface refs with names, verbose phases) | none | **Built** `fmc_packet_tracer` (verdict, drop reason, matching rule) |
| Rule hit counts | H | H (refresh task, then FMC lists only the default action unless rule ids are passed) | none | **Built** `fmc_get_hit_counts` |
| Interface config (nameif, zone, IP, enable) | H | H (full-object PUT, zone refs, 405 on unsupported kinds) | M | **Built** `fmc_update_interface` |
| Subinterfaces | M | M | M | **Built** `fmc_create_subinterface`, `fmc_delete_interface` |
| Static routes (global and VRF) | H | H (network objects by value, gateway literal, VRF path) | M | **Built** `fmc_list_routes`, `fmc_create_static_route`, `fmc_delete_static_route` |
| Policy assignment (NAT, platform settings, ACP) | H | H (read-modify-write of the assignment's target list) | M | **Built** `fmc_assign_policy` |
| Deployment rollback | M | H (pick the right job per device) | H | **Built** `fmc_rollback_deployment` (dangerous) |
| Device health (alerts + CPU/memory) | H | H (Prometheus JSON inside a string) | none | **Built** `fmc_device_health` |
| S2S VPN tunnel status | M | L | none | **Built** `fmc_list_vpn_tunnels` |
| CLI preview of a deployment (`pendingchangesrequests` CLI_DIFF) | M | H | none | api_call: the result is a **PDF inside a ZIP**, not text. `fmc_pending_changes` (policy diff) covers preview |
| BGP / OSPF / EIGRP / PBR / ECMP / BFD config | M | H (big nested models) | H | api_call (+ `fmc_list_routes` reports which are configured). Rarely changed; the payloads are best built with `fmc_get_definition` |
| EtherChannel, VTI, loopback, BVI, inline sets create | M | M | M | api_call; `fmc_update_interface`/`fmc_delete_interface` handle them once they exist |
| DHCP server/relay, DDNS | L | M | L | api_call |
| Prefilter rule writes | M | M | M | api_call (reads + hit counts are curated); fastpath/block rules are uncommon edits |
| Intrusion / file / SSL / DNS / identity policy editing | M | H | H | api_call; `fmc_list_policies` lists them, `fmc_create_access_rule` attaches intrusion policies. Their editors are rule-group/rule-state models that are poorly served by thin wrappers |
| Platform settings (syslog, SNMP, NTP, SSH, HTTP, banner) | M | H | M | api_call (79 ops across 20 sub-resources) |
| RA VPN, S2S topology build | M | H | H | api_call; status is curated. Topologies need many crypto objects first |
| HA monitored interfaces, failover MACs | L | M | M | api_call (form/break/switch are curated) |
| Clustering create / readiness | L | H | H | api_call; no cluster-capable lab |
| Change management tickets | L | M | L | api_call (feature off by default; `ticket-id` header) |
| Backups (device backup, list) | L | M | M | api_call; downloads are binary |
| Upgrades / content updates | L | H (long tasks) | H | api_call; not worth automating from chat |
| Users / roles / external auth | L | M | M | api_call |
| Object overrides | L | M | M | api_call (`object/*/{id}/overrides`) |
| Device templates, chassis, zero trust, TID, netmap, integrations | L | - | - | api_call |
| Packet capture | - | - | - | **Not in the FMC 10.0.1 REST API** (no capture endpoints; only PCAP replay into packet tracer) |

## 3. Operator workflows

| Workflow | Tools | Live-tested on the FTDv |
|---|---|---|
| Onboard an FTD end to end | `fmc_register_device` (waits for registration + initial deployment) -> `fmc_update_interface` -> `fmc_create_security_zone` -> `fmc_create_static_route` -> `fmc_create_nat_policy`/`fmc_create_nat_rule` -> `fmc_assign_policy` -> `fmc_deploy` -> `fmc_run_show_command` | yes, plus delete + re-register |
| Change -> preview -> deploy -> verify -> undo | `fmc_pending_changes` -> `fmc_deploy` -> `fmc_run_show_command`, `fmc_list_deployments` -> `fmc_rollback_deployment` | yes |
| Why is this traffic blocked? | `fmc_packet_tracer` (live verdict + rule) + `fmc_rule_lookup` (offline) + `fmc_get_hit_counts` | yes (allowed, blocked and no-ARP cases) |
| Is the device healthy? | `fmc_list_devices`, `fmc_device_health`, `fmc_list_vpn_tunnels` | yes (VPN: mocks; no tunnels in the lab) |
| Who changed what? | `fmc_list_audit_records`, `fmc_list_deployments` | yes (Phase 1) |

## 4. Review of the existing tools

| Finding | Fix |
|---|---|
| `fmc_create_access_rule` with `action=BLOCK` failed with the default `log="end"`: FMC 10.0.1 rejects `logEnd` on block rules | Block actions log at the connection start; updating a rule to a block action flips existing end-logging too |
| `fmc_register_device` failure said only `REGISTRATION_FAILED`; the reason (Smart Licensing not registered, registration timed out) is in the task's `description` | Failure messages include the description, plus next-step hints (evaluation mode; `configure manager add` / TCP 8305) |
| `fmc_register_device` returned while FMC was still running the first deployment ("DISCOVERY_SUCCESS_DEPLOYMENT_IN_PROGRESS") | With `wait`, it also waits for the "Deployment after registration" job |
| `fmc_delete_device` didn't say that the FTD forgets its manager (`show managers` -> none) | Stated in the preview: re-registering needs `configure manager add` on the device |
| `fmc_deploy` refused by FMC validation warnings ("changes to Virtual Routers may cause traffic disruption") gave a bare 400 | The error says nothing was deployed and to repeat with `ignore_warning=true` |
| `fmc_pending_changes` dumped raw `valueAdded/valueUpdated` JSON and empty container rows | Flattened to `Field: old -> new` strings; container rows dropped |
| `fmc_list_device_interfaces` showed zone UUIDs (FMC returns zone refs without names), named subinterfaces after their parent, and failed on kinds the model doesn't support (FTDv: VLAN interfaces -> 405) | Zone names resolved, `Ethernet0/1.100` naming, unsupported kinds noted instead of failing |
| `task_state` for FMC tasks was unverified against real payloads | Verified live: deployment `Deployed`, rollback `taskType=DEVICE_ROLLBACK`, registration `SUCCESS`/`FAILED`, hit-count refresh `SUCCESS` |

## 5. Lab findings (FMC 10.0.1 + FTDv 10.0.0)

- Registration needs Smart Licensing **or evaluation mode** (`POST /api/fmc_platform/v1/license/smartlicenses`
  `{"registrationType":"EVALUATION"}`); otherwise the task fails at once.
- FTDv interfaces are `Ethernet0/0`, `Ethernet0/1`, ... (not GigabitEthernet); VLAN and bridge-group
  interface collections answer **405** on FTDv.
- An auto NAT rule's zones must map to one interface per device: adding a subinterface to a zone used
  by an auto NAT rule is refused ("Auto nat rules can not be configured on more than one ... Interface").
- Hit counts: `GET .../operational/hitcounts?filter=deviceId:X` returns **only the default action**
  unless `ids:<rule ids>` is in the filter. Timestamps look like UTC (`...Z`) but are FMC local time
  (UTC-4 here). The device rule id (`metadata.deviceRuleId`) is the `rule-id` in packet tracer and
  syslog, and the rule's UUID ends with it (`...-000268434474`). Packet tracer packets count as hits.
- Packet tracer POST needs `name` in both the device and the interface references ("Device value is
  missing" otherwise); `interface.name` is the logical name.
- The show-command API runs an allowlist of mostly configuration commands (`show version`, `show route`,
  `show interface ip brief`, `show failover`, `show running-config <section>`) and refuses `show conn`,
  `show xlate`, `show nat`, `show arp`, `show access-list`, `show access-control-config` and plain
  `show running-config`. At most two words in `command`; the rest go in `parameters`.
- Rollback to the registration deployment is refused ("Cannot rollback the device ... to
  deploymentJobId provided"); rolling back to a later deployment works and shows as `Rollback_Job_N`.
  After a rollback FMC marks every policy out of date, so the next deploy pushes everything.
- Deleting a device clears the FTD's manager entry (`show managers` -> "No managers configured").
- The pending-changes CLI preview (`pendingchangesrequests` with `CLI_DIFF`) produces a ZIP holding a PDF.
- Health metrics come back as a Prometheus query result serialized as a JSON string inside
  `items[].response`.

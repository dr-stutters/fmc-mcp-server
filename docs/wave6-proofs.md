# Wave 6 live proofs (fleet run, 2026-10-20/21)

The Wave 6 Now tools (F66-F74, issues #161-#169) run against FMC 10.0.1 with FTDv 10.0 in CML, in domain
`Global/mcp-test-leaf`. The run had three stages:

- **Stage 2 (live-A, live-B1, live-B2)** ran on `main` after the nine feature PRs were merged (#234 #242 #238 #241 #243 #240 #245
  #246 #251; 200 tools: 85 read, 102 write, 13 dangerous; 11 prompts). Every finding got its own fix PR (#252-#271).
- **Stage 3 (final-live)** re-ran each failed or partial proof on `main` after the 20 fix PRs were merged, then restored the lab.

Every write went through MCP one call at a time: preview, read, then the same call with the confirm token. Deploys named the
devices explicitly (never "all deployable"). Each proof uses the new tool itself, then checks the device (`fmc_run_show_command`,
packet tracer, the FTD console through cml-mcp), FMC's own read-back, or traffic from the lab hosts with hit counts.

Labs: `mcp-cml-ftd` (`mcp-ftd1`, routed, with an inside host and an IOL peer), `mcp-cml-identity` (`mcp-ftd-identity`, an 802.1X
client, ISE over pxGrid), `mcp-sdwan-t1` (hub and three spokes, no VPN topology at the time), and `mcp-w6-bulk` (four new FTDv,
a copy of the `ftd-sdwan-single` recipe, built for F74). Everything the run created is named `mcp-w6-*`.

Lab addresses and hostnames are not in this file. Placeholders:

| Placeholder | What it is |
|---|---|
| `<inside-host>`, `<inside-net>` | the Linux host behind `mcp-ftd1` (inside) and its /24 |
| `<internet-host>` | a public web server reached through `mcp-ftd1` (HTTP and HTTPS) |
| `<fmc>`, `<ise>` | FMC's and ISE's management addresses, used as SSH/HTTP/HTTPS destinations from `<inside-host>` |
| `<dns-server>` | the lab resolver put into the DNS server group |
| `<dmz-net>` | the VLAN 100 subinterface's /24 on `mcp-ftd1` |
| `<client>`, `<outside-host>` | the 802.1X client behind `mcp-ftd-identity` and the server outside it |
| `<bulk-1>`..`<bulk-4>` | the management addresses of the four `mcp-w6-bulk-*` FTDv |
| `<spoke1-gw>` | a next hop on `mcp-sdwan-t1-spoke1`'s inside network (test static route) |
| `<lab-root-ca>`, `<fmc-fqdn>` | the lab's root CA (FMC's trusted-CA object for it) and FMC's pxGrid certificate subject |

Documentation addresses (192.0.2.x, 198.51.100.x) are the real values of the `mcp-w6-*` seed objects.

Status: **pass**, **fail** (a tool bug; root cause and fix PR given), **blocked** (a lab or FMC 10.0.1 limit), or **not run**.

## Summary

Final status after the re-proof on `main`.

| # | Item | Status | Evidence (one line) |
|---|---|---|---|
| 1 | F66 access-rule conditions (#161) | **pass**; VLAN tags authored only (inline sets) | SSH allowed and HTTP blocked by application, an active and an expired time range, an ISE SGT rule (bob blocked by SGT Contractors, alice allowed), all on traffic with hit counts; app filters usable by name after #268; `fmc_rule_lookup` decides ended ranges and the session SGT (#261) |
| 2 | F67 bulk rule edits + clear hit counts (#162) | **pass** | one preview and one partial bulk PUT for 3 rules, bundle diff = only the intended fields; clearing one rule and all rules (the default action too); MONITOR logging skipped with a reason (#262) |
| 3 | F68 fleet show commands + device groups (#163) | **pass** after #252; bulkcommands **blocked** (feature flag) | six devices `show version` and a group `show interface ip brief`: a row per device with its own UUID and addresses; groups created, changed, deleted; deploy by group on the bulk FTDs |
| 4 | F69 platform settings (#164) | **pass** after #265/#266/#267/#269; two FMC limits | FQDN rule hit only after the DNS group; NetFlow v9 records at the collector; ICMP, HTTPS and banner deployed and read on the device; DNS can't be removed and a cleared banner isn't pushed (FMC 10.0.1) |
| 5 | F70 object lifecycle (#165) | **pass** after #258 | replace A -> B in a rule, a group and a NAT rule, proven with a bundle diff; bulk and prefix deletes incl. nested groups; sync create/update/orphans, second run a no-op |
| 6 | F71 `fmc_list_certificates` (#166) | **pass**; device certificates none enrolled | internal and trusted-CA rows with days left, 106 bundled roots hidden by default, the expiry filter consistent; `system` flag fixed in `fmc_get_certificate` (#270) |
| 7 | F72 export + compare (#167) | **pass**; template compare unit-only | stable digest, spoke1 vs spoke2, before/after a static route (one change, then identical), `mcp-ftd1` vs `mcp-ftd-identity` with no secret in the output |
| 8 | F73 snapshot + state diff (#168) | **pass** after #252/#256/#257 | WAN link down: one finding (FMC's INTERFACE alert), restore: identical; two-device snapshot holds each device's own state; one digest across labels and vs live |
| 9 | F74 `fmc_register_devices` (#169) | **pass** | four FTDv registered in one bulk call in 290 s including their initial deployments (serial: about 24-40 min); licence AUTHORIZED |

## What is out of reach

**FMC 10.0.1 limits** (documented in the tools since the fixes):

- **bulkcommands:** `POST devicerecords/operational/bulkcommands` answers 403 "Feature Flag : bulk_device_command_execution is
  disabled". Turning the flag on is an FMC system setting, so the bulk path is built on FMC's schema only; every fleet run took the
  per-device path, one command at a time (#252: FMC mixes up the answers of concurrent show commands).
- **Application filters:** a filter created over REST is never listed (`GET applicationfilters` empty, GET and DELETE by id 404), yet
  a rule can use it by id and FMC checks the id when the rule is saved (400 "Object for Type ApplicationFilter and UUID ... is not
  found"). Deleting one is a UI step (Objects > Object Management > Application Filters).
- **DNS:** once a platform settings policy has a DNS server group, every PUT needs a default group ("One DNS server group must be
  set as the default group"); the group can't be removed over REST. Assigning another platform settings policy takes it off the
  device.
- **Banner:** a cleared banner deploys no `no banner`, so the device keeps the old text.
- Smaller ones met on the way: device-group descriptions are not stored; MONITOR rules keep their logging (200, nothing changed);
  the `unusedOnly` filter lists no network group; NetFlow collectors take interface groups only; ICMP access entries need an ICMP
  service object; `analysis/useractivity` holds only about the last hour and refuses its `time` filter (422); FMC's command API
  has its own rate limit (a 429 for four parallel show commands).

**Lab limits:**

- **CML link stop keeps FTDv carrier:** the data plane is cut (ping 0/5) but the interface stays up/up, so F73's interface-down
  and route-lost findings can't be produced live; they are unit-tested on the recorded WAN-down run (`wan_down_live`).
- **No inline set:** VLAN tag conditions match only on inline sets, and `mcp-ftd1` is routed, so the VLAN rule is authored and
  read back, and its non-match is shown (the VLAN 100 ping went to the default action).
- **No enrolled device certificates** until F75 (`devices/certificates` is empty), so F71's device rows are proven empty only.
- No device templates on this FMC/FTDv (F81 #223), no VPN topology on `mcp-sdwan-t1` (no VTIs to compare), no RBAC-only API user
  (#249), no prompt client in the agents' session (prompts are snapshot-tested), `MCP_TASKS` off in the deployment (F74 ran
  synchronously).

## F66 access-rule conditions (#161, PR #241; fixes #260 #261 #263 #264 #268) — pass

Policy `mcp-w6-acp` on `mcp-ftd1`; the SGT rule in `mcp-fw-threat-acp` on `mcp-ftd-identity` (the run's one exception to the
`mcp-w6-*` scope).

Stage 2 (live-B1):

- `fmc_find_application('HTTP')`: app id 676, risk Very Low, categories and tags, 10 similar names; `('SSH', kind='application')`:
  id 846, risk **High**; `kind='attribute'` lists risk and relevance values. The catalogue (8393 apps) is indexed once per hour:
  FMC ignores `filter=` on `object/applications`.
- `fmc_create_time_range`: `mcp-w6-tr-now` (every day 00:00-23:59 until two days later) and `mcp-w6-tr-expired` (ended
  2026-10-02; the preview warns that rules using it never match). With no start sent, FMC stores `effectiveStartDateTime: "Started"`.
- `fmc_create_application_filter('mcp-w6-appfilter', risks=[High, Very High])`: 201 (no `type` needed in `appConditions`), but the
  filter can't be read back (see the limits above): the rule writers couldn't find it by name or id, so the filter rule was posted
  raw in Stage 2. **Fail, fixed by #268.**
- Rules: `mcp-w6-expired` (tcp/80 to `<internet-host>`, expired range), `mcp-w6-app-ssh` (SSH to `<fmc>`), `mcp-w6-http-block`
  (BLOCK HTTP to `<internet-host>`), `mcp-w6-time-now` (tcp/443 to `<fmc>`, active range), `mcp-w6-appfilter-rule` (the filter, to
  `<ise>`), `mcp-w6-vlan` (`vlan_tags=[100]`, last). Read-backs carry the application ids, time range, VLAN literal and filter.
  Deployed to `mcp-ftd1` only.

| Rule | Hits after traffic | What the traffic was |
|---|---|---|
| `mcp-w6-expired` | 0 | HTTP to `<internet-host>`, which it would match without the range: **expired range honoured** |
| `mcp-w6-app-ssh` | 1 | SSH to `<fmc>` |
| `mcp-w6-http-block` | 2 | two HTTP fetches from `<internet-host>` (timed out); HTTPS to the same address passed |
| `mcp-w6-time-now` | 2 | HTTPS to `<fmc>`: **active range matches** |
| `mcp-w6-appfilter-rule` | 1 | SSH to `<ise>` (High risk); HTTP to `<ise>` (Very Low) fell through to the baseline: hit counts follow Snort's decided rule |
| `mcp-w6-vlan` | 0 | a VLAN 100 ping into `<dmz-net>` went to the **default action** (2 -> 3): VLAN tags don't match on a routed subinterface |

- SGT: `mcp-w6-sgt-block` (BLOCK, `source_sgts=['Contractors']`, tcp/23) at #1, preview label "Contractors (SGT 5)", deployed.
  bob logged in (recipe action): telnet from `<client>` to `<outside-host>` timed out, `mcp-w6-sgt-block` 2 hits, the user rule
  below it untouched; alice logged in: telnet succeeded, the baseline +2. A destination SGT (`PCI_Servers`) is accepted by FMC 10.0.1.
  Rule removed and the device deployed.
- Update semantics: `applications` added to and cleared (`[]` -> any) with the ports and time range kept; the time range cleared.
- Findings: `fmc_live_connections` rows never carry the rule or app (FTD sends Snort's connection events only to syslog servers;
  timestamps are off) (#260); `fmc_rule_lookup` listed the expired rule as conditional and didn't use the session's SGT (#261);
  `fmc_pending_changes` returned a 115 KB row (#263); live rule shapes replaced made-up test fixtures (#264).

Re-proof (final-live):

- **#268:** a rule with a random filter UUID: the preview sends it as given; FMC refuses the save with 400 "... is not found" and
  creates nothing. `fmc_update_access_rule(mcp-w6-app-ssh, application_filters=['mcp-w6-appfilter'])` after a server restart
  resolved the name from the rule that uses it, to the right id; confirmed, read back, reverted.
- **#261:** HTTP from `<inside-host>` to `<internet-host>`: `mcp-w6-expired` under `not_in_effect` ("ended 2026-10-02T23:59"). With
  a temporary SGT rule: `source_sgt='Contractors'` gives a definite BLOCK by the SGT rule; `'Contractorz'` gives a note ("not in
  FMC's SGT catalogue") and keeps the SGT rule conditional; with no argument, right after bob's login the SGT comes from FMC's user
  activity (BLOCK), after alice's it is Employees (ALLOW). The rule was removed and the device deployed.
- **#263:** the 115 KB inspector row is cut with "[114,791 more characters]" and a note.

Out of reach: a live VLAN-tag match (inline sets); deleting application filters over REST; the automatic SGT older than about
an hour (FMC's user-activity window). Follow-ups: inline application filters (#272); preview wording for filter ids,
`fmc_find_application` after a restart, the "(30 days)" caveat (#273).

## F67 bulk access-rule edits + clear hit counts (#162, PR #243; fix #262) — pass

Stage 2 (live-B1), on unassigned `mcp-w6-hygiene-acp` (a copy of the seeded hygiene policy) and on `mcp-w6-acp` / `mcp-ftd1`:

- `fmc_policy_audit` offers `bulk_fixes` (no intrusion policy on 3 ALLOW rules) with the exact bulk call.
- `fmc_bulk_update_access_rules(select={enabled: true, action: ALLOW}, set={log: begin_and_end, comment})`: one preview, 3 rows
  with their diffs, "1 bulk PUT of up to 50 rules (partialUpdate)"; applied 3 in 1 request. The audit's own call: 3 rules get the
  intrusion policy. `fmc_diff_policy_bundle(before, after)`: only those fields (log, intrusion policy, comment) plus the system
  intrusion policy now referenced. Refusals: an unknown rule name and an empty selection are blocked.
- MONITOR rule with `log='none'`: FMC answered 200 and kept the logging, the tool counted it as applied. **Fail, fixed by #262.**
- `fmc_clear_hit_counts(rules=['mcp-w6-http-block'])`: preview lists what is lost (3 hits); after: that rule 0, every other count
  unchanged. FMC's DELETE answers `{}`. Without `rules`: 10 rules cleared **and the default action's counter reset** (now stated in
  the preview). New traffic counts up from zero. `select={zero_hits_days: 1}` previews exactly the six zero-hit rules.

Re-proof (final-live), **#262:** a temporary MONITOR rule with `log='none'` in a bulk preview is skipped with the reason, and the
side effects promise the `kept_by_fmc` read-back. Not confirmed; the rule was deleted.

Out of reach: the chunk-refusal bisect is unit-only (FMC refused nothing live). Follow-up #273 (`newComments` verification and the
single-rule MONITOR previews).

## F68 fleet show commands + device groups (#163, PR #246; fixes #252 #253 #254) — pass after #252; bulkcommands blocked

Stage 2 (live-A):

- `fmc_run_show_command(devices=[t1 hub, spoke1..3, mcp-ftd1, mcp-ftd-identity], 'show version')`: 6 rows, path per-device, the
  note quotes FMC's feature-flag 403. **But rows held other devices' output** (banners and UUIDs of a different device; a new mix
  each run; single calls correct): FMC 10.0.1 answers concurrent `operational/commands` requests with each other's output. **Fail,
  fixed by #252** (one show command at a time per FMC connection; a `show version` naming another device is re-asked once, then a
  failure row).
- `fmc_create_device_group('mcp-w6-t1', 4 t1 FTDs)` and `('mcp-w6-bulk', 4 bulk FTDs)`: FMC takes members as `{id, type, name}` and
  the expanded list carries them. `fmc_update_device_group` add and remove `mcp-ftd1`: applied; the description is not stored by
  FMC 10.0.1 although the tool said "changed" (**#254**).
- `fmc_deploy(['group:mcp-w6-t1'])`: the preview named only the four t1 devices. The first confirm hit the client timeout with no
  job and no hint (**#253**, 180 s and an explanation now); the second was refused by FMC's pre-deploy validation (rules on zones
  without interfaces in `mcp-sdwan-acp`, a policy outside the run's scope). `fmc_deploy(['group:mcp-w6-bulk'])`: one target (the
  hub), the spokes listed under `skipped_no_pending_changes`; deployed. `fmc_assign_policy(group=...)` with the policy the devices
  already had: blocked "Already assigned".

Re-proof (final-live), **#252:** six devices `show version` with `match='UUID'`: 6/6 rows, each UUID equal to its device's FMC id;
again right after with `max_lines=3`: each row its own banner. `group='mcp-w6-t1'` `show interface ip brief`: each spoke and the hub
its own addresses, equal to single-device calls. `fmc_deploy(['group:mcp-w6-bulk'])` preview: the group expanded to the four bulk
FTDs, all skipped (nothing pending), nothing else named.

Out of reach: bulkcommands (feature flag); the t1 group deploy (lab policy state); licences, backup, metrics and `fmc_sdwan_status`
by group are unit-tested; #253 has no safe live trigger (unit test). A fleet run now costs about 1-3 s per device and command.

## F69 platform settings: DNS, NetFlow, ICMP/HTTPS, banner, FQDN warning (#164, PR #242; fixes #265 #266 #267 #269) — pass

Stage 2 (live-B2), platform settings `mcp-w6-ps` assigned to `mcp-ftd1`:

- `fmc_get_platform_settings`: the DNS section says "No DNS server group: FQDN objects in rules never resolve".
- FQDN warning: `fmc_create_object(type='fqdn', 'mcp-w6-fqdn')` warns for every device of the domain without DNS (10 named,
  "and 10 more"); the rule preview `mcp-w6-fqdn-allow` (tcp/443 to the FQDN) warns only for `mcp-ftd1`.
- `fmc_configure_dns(servers=[<dns-server>], server_group='mcp-w6-dns', interfaces=[outside zone])`: creates the group, then the
  settings; the same rule preview now has no warning. Deployed: `show running-config dns` lists the group; the FQDN rule took 2 hits
  from HTTPS to `<internet-host>`, and `fmc_packet_tracer` names it as the verdict rule.
- `fmc_configure_netflow(collector=<inside-host>, port=2055, interfaces=[a zone])`: confirm refused by FMC ("Only Interface Group
  object of type Management/ Routed/ Switched is allowed"). **Fail, fixed by #269.** With an interface group: applied, deployed;
  `show running-config flow-export` / `policy-map` show the collector and `class-default`; a bounded `tcpdump` on `<inside-host>`
  caught 20 NetFlow packets and a CML link capture 23 (v9 templates and data records).
- `fmc_configure_mgmt_access(kind='icmp')` without `icmp_service`: FMC refused ("'icmpService' configuration missing"). **Fail,
  fixed by #265.** With an ICMPv4 "any" object: applied. `kind='http'`: the allow entry turns the HTTPS server on.
- `fmc_set_banner` (two lines): `show banner` shows it; `show running-config banner` prints nothing on FTD 10.0 (verify hint, **#267**).
- Undo: NetFlow, ICMP and HTTPS removed and deployed. `fmc_configure_dns(disable=True)` failed on confirm (default group mandatory,
  **#266**); `fmc_set_banner(text='')` succeeded but the device kept the banner (**#267**).

Re-proof (final-live):

- **#269:** the zone call is blocked in the preview with FMC's reason, the interface-group POST to make, and a note that
  `collector_name` is unused (the collector address already has a host object); the interface-group call applied.
- **#265:** ICMP access without `icmp_service` reused the existing ICMPv4 "any" object (no second object).
- **#267:** a one-line banner deployed; `show banner` shows it. Clearing it warns in the preview and the result that FMC 10.0.1 sends
  no `no banner`. **#266:** `disable=True` is blocked in the preview with FMC's reason and the alternative.
- Deploy, then on the device: `flow-export destination inside <inside-host> 2055`, `icmp permit <inside-net> inside`, the banner.
  Restoring `mcp-ftd1`'s original platform settings removed the DNS group, NetFlow and ICMP from the device.

Out of reach: removing a DNS group over REST; clearing a deployed banner (the final-live test banner stays on `mcp-ftd1`).
Follow-up #273: removing the last HTTPS entry leaves the HTTPS server enabled.

## F70 object lifecycle at scale (#165, PR #238; fixes #258 #259) — pass after #258

Stage 2 (live-B2):

- `fmc_replace_object(old='mcp-w6-a', new='mcp-w6-b')` (192.0.2.10 -> 192.0.2.11): "3 places" found by FMC's usage API: the group
  `mcp-w6-grp`, rule `mcp-w6-f70-uses-a` in `mcp-w6-acp`, the auto NAT rule of `mcp-w6-nat`. `fmc_diff_policy_bundle(before)`: only
  the reference swaps (no rule holds both, nothing moved); `fmc_where_used(mcp-w6-a)` afterwards: not in use.
- `fmc_delete_objects(prefix='mcp-w6-unused', unused_only=True)`: exactly the three unused seeds (host, network, port), one bulk
  DELETE per type; `fmc_unused_objects` before/after differs by those three. Refusals (dry run): an object inherited from Global, an
  object in use (with its users), built-ins in Global.
- `fmc_import_objects(mode='sync', prefix='mcp-w6-sync-')`: create 1, update 1, unchanged 1, group membership, orphan listed (never
  deleted); the same call again: blocked "Nothing to change"; a third run drops a member from the group.
- Prefix cleanup refused the group and its members: FMC's `unusedOnly` filter lists no network group, and the tool trusted it
  (`fmc_unused_objects` never listed unused groups either). **Fail, fixed by #258.** A description-only sync row read
  "from <same value>" (**#259**).

Re-proof (final-live), **#258:** nested groups `mcp-w6-grp-inner` (host `mcp-w6-b`) in `mcp-w6-grp-outer`: `fmc_unused_objects`
lists the outer group (checked with FMC's usage API) and not the inner one. `fmc_delete_objects(prefix='mcp-w6-grp-',
unused_only=True)` deletes the outer group and skips the inner one as in use; the same call then deletes the inner one. The seed
group and host were untouched. The wrap-up used the tool too: `prefix='mcp-w6-', unused_only=True, exclude=['mcp-w6-grp']` deleted
three leftover objects.

Out of reach: #259 is unit-tested. Follow-up #273 (NAT row label in the replace preview, the reason given for a built-in in a leaf).

## F71 `fmc_list_certificates` (#166, PR #234; fixes #270 #271) — pass

Stage 2 (live-B2), read-only:

- All kinds: 3 rows (two internal certificates for `<fmc-fqdn>` with 727 days left, the trusted CA `<lab-root-ca>` with 3648), all
  ok, `bundled_roots_hidden: 106`. `include_bundled=True`: 107 rows, bundled ones flagged. Dates checked by hand; FMC's OpenSSL
  form with a double space before a one-digit day parses.
- `expiring_within_days=400`: none, with `bundled_roots_expiring: 1` (a bundled root at 251 days, shown with `include_bundled`);
  `=30`: none. `kind='device'` and `device='mcp-ftd-identity'`: empty (nothing enrolled).
- Finding: `fmc_get_certificate` called Global's certificates "system" when read from the leaf (**#270**, F64's tool). FMC's
  subject fields of some bundled roots carry mojibake or are cut at a comma; recorded as a test fixture (**#271**).

Re-proof (final-live), **#270:** `fmc_get_certificate('mcp-fw-fmc-pxgrid')` no longer says `system: true` and names domain Global;
the lab CA is listed in the leaf.

Out of reach: device certificates (F75 enrols the first); an RBAC-only API user (#249); the health-review certificate step is
snapshot-tested. Follow-up #273 (take subject and issuer from the PEM).

## F72 export one device's configuration + compare (#167, PR #245) — pass

Stage 2 (live-A):

- `fmc_export_device_config('mcp-sdwan-t1-spoke1')`: device, interfaces (5), routing (3), policies (2) and the empty sections listed
  in `meta.sections`; YAML and markdown give the same digest.
- `fmc_diff_device_config(spoke1, spoke2)`: interface addresses and spoke1's WAN path monitoring and priority, the three WAN route
  gateways; device and policies identical.
- A test static route (`mcp-w6-route-net` 192.0.2.0/24 via `<spoke1-gw>`) added: the diff against the stored export shows exactly
  one change, the added route; route and object deleted: identical again, the digest back to the stored one.
- `mcp-ftd1` vs `mcp-ftd-identity`: 15 changes (interfaces, the VLAN subinterface, BGP/OSPF/default route, the three policies, NAT
  rules, platform-settings logging); no community, password or key value in the output.

Re-proof (final-live): covered by F73's digest check (stored and live documents agree).

Out of reach: comparing with a device template (no templates on FMC 10.0.1 with FTDv: F81 #223, unit-tested); VTI peers (no VPN
topology on t1); the health-review `compare_with` step is snapshot-tested.

## F73 pre/post-change snapshot + state diff (#168, PR #251; fixes #252 #256 #257) — pass

Stage 2 (live-A), `mcp-sdwan-t1-spoke1`:

- `fmc_device_snapshot(label='before-wan-down', running_config=['route'])`: route table (11), interface state (5), failover
  "standalone", SAs 0/0, hit counts, non-green health alerts, deployed version and pending changes. Diff against live: identical.
- `cml_set_link_state` on spoke1's MPLS link (down): ping across it 0/5, but the FTDv kept Ethernet0/0 up/up. The after snapshot
  diff has one finding: FMC's INTERFACE alert now names Ethernet0/0 too. No route or interface finding, because the device never saw
  the link go down (lab limit). Link restored; after the next health run the restored snapshot is identical to the before one.
- A two-device snapshot (hub + spoke1) put spoke1's state in the hub's document (F68's root cause, **#252**); snapshot digests
  differed for identical bodies (the label was hashed, **#257**); alert details kept FMC's `<br>` (**#256**).

Re-proof (final-live):

- **#252:** `fmc_device_snapshot([hub, spoke1], sections=[route_table, interface_state, vpn_sas])`: each document holds its own
  device's routes and interfaces.
- **#257:** three spoke1 snapshots with different labels over 77 s share one digest; stored vs stored and stored vs live are
  identical, and the live digest is the same.

Out of reach: interface-down and route-lost findings on traffic (CML link stop keeps FTDv carrier; unit-tested on the recorded
run); the prompt steps are snapshot-tested.

## F74 register several FTDs in one call (#169, PR #240; tests #255) — pass

Stage 2 (live-A), the four `mcp-w6-bulk-*` FTDv (`<bulk-1>`..`<bulk-4>`), waiting for registration:

- A preview with a duplicate name is blocked ("row 2 ...: the name is also row 1").
- `fmc_register_devices(4 rows, access_policy='mcp-w6-bulk-acp', license_caps=['ESSENTIALS'], performance_tier='FTDv5')`, no
  `reg_key` (the server's key; the preview says so per row): one bulk POST; FMC answered **one** TaskStatus for the batch (the spec's
  example shape). Result: method bulk, 4 deployed, **290 s** from confirm to the last initial deployment. FMC registers in parallel but
  starts the initial deployments one after another (rows at 169, 230, 260 and 290 s). A serial run at 6-10 min per FTDv would take
  about 24-40 min.
- `fmc_get_task(<batch>)`: "Total:4 ... SUCCESS:4" with a sub-task per device (target, status, message), which the tool reads.
  `fmc_list_devices`: four connected devices on the bulk policy; `fmc_license_status`: AUTHORIZED, 23 devices.
- The live answers replaced the spec example in the unit tests (**#255**).

Wrap-up (final-live): both device groups and the four FTDs deleted (each previewed); licence AUTHORIZED, 19 devices.

Out of reach: MCP task mode (`MCP_TASKS` off in the deployment, so the call ran synchronously); the single-POST fallback (FMC took
the bulk request; unit-tested); the `fmc_onboard_ftd(devices=...)` prompt (snapshot-tested). Follow-up #274 (two wall-clock-dependent
unit tests).

## Fixes found live (all merged before the re-proof)

| PR | Item | What the live run found | Fix | Re-proven |
|---|---|---|---|---|
| #252 | F68, F73 | FMC answers concurrent show commands with each other's output | one show command at a time per FMC connection; a `show version` naming another device is re-asked, then a failure row | final-live A1 |
| #253 | F68 | the deployment POST timed out on the client with no hint | 180 s; on a timeout, say whether a deployment started and to preview again | unit |
| #254 | F68 | FMC keeps no device-group description | preview note, result warning | unit (live fixture) |
| #255 | F74 | tests used the spec example | live bulk answer, batch task and jobs in the tests | tests |
| #256 | F73 | alert details kept FMC's `<br>` | plain text, order-insensitive compare | unit (live fixture) |
| #257 | F73 | the snapshot digest covered the label | label left out; the live side records the read settings | final-live A2 |
| #258 | F70 | FMC's unused filter lists no network group | groups decided with the usage API | final-live A3 |
| #259 | F70 | sync row showed "from <same value>" | description change shown | unit |
| #260 | F66 | live connections without rule, app or time | notes say why and what to enable | unit |
| #261 | F66 | ended ranges and the session SGT treated as unknowable | `not_in_effect`; SGT from user activity or `source_sgt` | final-live A5 |
| #262 | F67 | MONITOR logging kept by FMC, reported as applied | MONITOR skipped; read-back reports `kept_by_fmc` | final-live (preview) |
| #263 | F66 | a 115 KB pending-changes row | change text capped | final-live (read) |
| #264 | F66 | made-up test shapes | live rule GETs and filter answers in the tests | tests |
| #265 | F69 | FMC needs an ICMP service object | an "any" object reused or created | final-live A6 |
| #266 | F69 | DNS can't be disabled once set | blocked in the preview with the alternative | final-live A6 (preview) |
| #267 | F69 | a cleared banner isn't pushed; wrong verify hint | warning; `show banner` | final-live A6 |
| #268 | F66 | API-created application filters can't be read back | names from created filters and from rules; ids sent as given | final-live A4 |
| #269 | F69 | NetFlow refuses zones | interface groups only; a zone blocked in the preview | final-live A6 |
| #270 | F71 (F64's tool) | Global's certificates called "system" in a leaf | `system` only for bundled roots; domain named | final-live (read) |
| #271 | F71 | FMC's damaged subject fields | live reads in the tests | tests |

## Follow-ups

- [#272](https://github.com/dr-stutters/fmc-mcp-server/issues/272): inline application filters in the access-rule writers (F66).
- [#273](https://github.com/dr-stutters/fmc-mcp-server/issues/273): small fixes from the run and the fix reviews, including one
  found in the wrap-up: `fmc_assign_policy` POSTs the first assignment of an ancestor-owned policy in the child domain and FMC 10.0.1
  answers 406 (workaround: the same call with `domain='Global'`).
- [#274](https://github.com/dr-stutters/fmc-mcp-server/issues/274): two unit tests that depend on the wall clock.
- cml-mcp-server [#33](https://github.com/dr-stutters/cml-mcp-server/issues/33) (`cml_get_link` fails on a stopped link) and
  [#34](https://github.com/dr-stutters/cml-mcp-server/issues/34) (`cml_configure_node` refuses a backgrounded `tcpdump`).
- Device templates stay Later as F81 ([#223](https://github.com/dr-stutters/fmc-mcp-server/issues/223)).

## State left after the run

- `mcp-ftd1` back on its original access, NAT and platform settings policies and deployed; `mcp-ftd-identity` back on
  `mcp-fw-threat-acp` with its own three rules, deployed. The four bulk FTDs and both device groups deleted (19 devices).
- Kept as unassigned seeds for later runs: `mcp-w6-acp`, `mcp-w6-ps`, `mcp-w6-hygiene-acp`, `mcp-w6-bulk-acp`, `mcp-w6-nat` and
  the objects they use, plus `mcp-w6-grp` and the interface group `mcp-w6-nf-ifg`.
- UI-only leftovers: the application filters `mcp-w6-appfilter` (used by `mcp-w6-appfilter-rule`) and `mcp-w6-appfilter2`.
- On `mcp-ftd1`: the login banner "mcp-w6 test banner (final-live)" (FMC sends no `no banner`; needs `no banner motd` on the device).
- CML: `mcp-w6-bulk` (kept defined), `mcp-sdwan-t1` and `mcp-cml-ftd` stopped; `mcp-cml-identity` running with alice logged in.

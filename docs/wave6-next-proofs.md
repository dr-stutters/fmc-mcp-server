# Wave 6 Next live proofs (2026-10-21)

The Wave 6 Next tools (F75-F80, issues #170-#175) and the follow-ups from Wave 6 Now (#248 #249 #250 #272 #273 #274) run
against FMC 10.0.1 with FTDv 10.0 in CML, in domain `Global/mcp-test-leaf`. The run had three stages:

- **Stage 1** built each item in its own PR (#279 #280 #281 #282 #288 #290; follow-ups #284 #286 #287 #289 #291 #292 #293 #294
  #295 #296), each reviewed before gate 1 merged them (main 4a913ab: 216 tools, 89 read, 113 write, 14 dangerous; 12 prompts).
  A probe read FMC's shapes first (profilers, inheritance, locks, enrollments, change management, TID).
- **Stage 2 (live-A: F75, F76, F80; live-B: F77, F78, F79 and the follow-ups)** ran on that `main`. Every finding got its own fix
  PR (#297-#312), reviewed and merged at gate 2 (main 09d9cef); Stage 3's findings got #316 (cosmetic) and #318 (F77-6), proven
  live by the coordinator before the release.
- **Stage 3 (final-live)** re-ran each failed or partial proof on `main` 09d9cef, then restored the lab and closed the issues.

Every write was previewed, read, then confirmed with the token, one call at a time. Deploys named the devices explicitly (never
"all deployable"). Everything the run created is named `mcp-w6-*`.

## How the tools were called: three paths

The agents' MCP session fetched its fmc-mcp tool list when it started, before gate 1 redeployed the server, and a redeploy doesn't
refresh a connected client's list. Nobody could reconnect the session during the run. So the tools added since 0.15.0 (16 at gate
1) were not visible to it, and each proof names the path it used:

| Path | What it is | Used for |
|---|---|---|
| **session tool** | The MCP tool the session can see, served by the redeployed container (the merged code). New **scalar** arguments of existing tools (`base_policy=`, `category=`, `evidence=`, `default_originate_route_map=`) passed through the old client schema. New **list and dict** arguments (`redistribute=[...]`, `inline_app_filter={...}`) were sent as JSON strings and refused by validation. | existing tools, and their new scalar arguments |
| **new tool in-process** | The new tool run from the `main` checkout with `scripts/mcp_call.py`: the same code as the container, called in-process. Reads and previews only, **never confirmed** (no `--yes`). It logs in as a second API user, not the container's. | reads and previews of the new tools |
| **preview parity** | The write sent with `fmc_api_call` (a session tool, with its own preview and confirm) carrying **exactly** the body the new tool's preview showed, then checked with the new tool's read or preview. | writes of the new tools |

A PKCS12 bundle never went through `fmc_api_call` (it would have put key material in a tool argument), so F75's PKCS12 path is
proven up to the preview and waits for the real tool ([Re-proof after a session restart](#re-proof-after-a-session-restart)).

Because the in-process server logs in as a second API user, the "locked by another user" path of F76, planned as unit-only (one
admin), ran live too.

## Labs and placeholders

Labs: `mcp-cml-ftd` (`mcp-ftd1`, routed, with an inside host and an IOL peer), `mcp-cml-identity` (`mcp-ftd-identity`, IPS
licence, ISE over pxGrid) and `mcp-sdwan-t1` (a hub and three spokes on mpls/inet/lte carriers, no VPN topology). The IOL
consoles didn't answer (CML's docker shim), so F77 used the two FTDs `mcp-sdwan-t1-hub` and `mcp-sdwan-t1-spoke1` as the BGP pair,
with a TRUST access policy `mcp-w6-t1-acp` assigned (their own `mcp-sdwan-acp` references empty zones, so FMC refuses their deploys).

Lab addresses and hostnames are not in this file. Placeholders:

| Placeholder | What it is |
|---|---|
| `<inside-host>` | the Linux host behind `mcp-ftd1` (inside) |
| `<internet-host>` | a public web server reached through `mcp-ftd1` (HTTP) |
| `<hub-inside>`, `<spoke1-inside>` | the inside /24 of the t1 hub and of spoke1 (each advertised in BGP) |
| `<hub-inet>`, `<hub-lte>`, `<hub-mpls>` | the hub's inet, lte and mpls /24s (connected routes) |
| `<hub-mpls-ip>`, `<spoke1-mpls-ip>` | the BGP peering addresses on the mpls carrier |

`mcp-w6-fqdn` holds `cisco.com`, and `mcp-test-url` holds `https://example.com`: the seed objects' real values.

Status: **pass**, **partial** (proven up to a point; what is missing is named), **fail** (a tool bug; root cause and fix PR given),
**blocked** (a lab or FMC 10.0.1 limit) or **unit-only**.

## Summary

Final status after the re-proof on `main` 09d9cef.

| # | Item | Status | Path | Evidence (one line) |
|---|---|---|---|---|
| 1 | F75 certificate enrolment (#170, open) | **pass** self-signed; PKCS12 **partial** (preview only) | new tool in-process + preview parity | self-signed ENROLL, RE_ENROLL (same key), REFRESH, DELETE on `mcp-ftd1`, each task SUCCESS and each step in `fmc_list_certificates`; the PKCS12 preview opens the file and shows no key material; create + enrol wait for the real tool |
| 2 | F76 categories, base policy, locks (#171, closed) | **pass** after #297/#298/#299/#300 | session tool (new scalar args) + new tool in-process + preview parity | child policy with base, its first deploy passes after #298; categories created, renamed, deleted, a rule moved Default -> Mandatory and back (#297); lock holder shown, another user's write blocked |
| 3 | F77 route policy (#172, closed) | **pass** after #306/#307/#308/#310; F77-6 fixed in #318 and proven | session tool (scalar args) + new tool in-process + preview parity (`redistribute`) | prefix lists and a route map from the tool's body (#306); iBGP hub <-> spoke1 with redistribution through a route map, an inbound prefix list and default-originate by route map: spoke1 `B* 0.0.0.0/0` via the hub; put back to no BGP |
| 4 | F78 Snort/CPU profiling (#173, open) | **blocked** (role permission); 403 wording and previews **pass** | new tool in-process | both API roles get 403 on the profilers (packet tracer works): the tools name the missing Snort 3 Profiling permission; previews state duration and CPU cost |
| 5 | F79 `fmc_find_indicator` (#174, closed) | **pass** after #309 | new tool in-process | a domain, a URL under a URL object, a hash (0 requests), a request budget with named skips, device narrowing; a child's inherited rule labelled |
| 6 | F80 hardening + evidence (#175, closed) | **pass** after #303 | new tool in-process + session tools | SSH from any and SNMP v2c give two high findings with the fix calls; fixed: "No findings."; an edited baseline skips a check; per-rule evidence after traffic; the ticket column is 403 for the role |
| 7 | #248 packet tracer on a disconnected HA unit (closed) | **pass** | session tool | both branches live while FMC's records flapped (standby listed connected, then not) |
| 8 | #249 RBAC read-only objects (closed) | **unit-only** | - | no read-only FMC user in the lab; creating users is off limits |
| 9 | #250 `fmc_set_si_lists` inherited DNS policy (closed) | **pass** | session tool | the leaf way first, then the Global alternative with its reach |
| 10 | #272 inline application filters (closed) | **pass** by preview parity | new tool in-process + preview parity + session read | FMC's stored shape recorded; `fmc_get_access_rule` reads it back |
| 11 | #273 small fixes (closed) | **pass** live where the lab allowed (#286 #293 #295 #296 #311), the rest unit-tested | session tool | `mcp-ftd1`'s Global-owned policies assigned back from the leaf (the 406 is gone); CN-less and mojibake certificate names |
| 12 | #274 flaky tests (closed) | **unit-only** (by nature) | - | one injectable wall clock, frozen in the tests; full suites under load pass |

## FMC 10.0.1 findings

Settled live in this run (the tools follow them since the fixes):

- **A rule moved into a category is re-created.** `PUT accessrules?bulk=true&category=<name>` moves the rule, but the old id then
  answers 404, and the id in the PUT's own answer is not the stored one either. Renaming a category keeps the rule's id; deleting a
  category leaves its rules uncategorized (`--Undefined--`) with their ids. A category itself can't be moved: 10.0.1's category PUT
  takes no position. `aboveCategory` takes the category's name. An empty category reports `startIndex`/`endIndex` 0 (the spec
  example says -1).
- **A REST child policy keeps its own Logging settings.** After `inheritancesettings` sets the base, the child's `loggingsettings`
  stay its own (no syslog destination), and the first deploy of a child whose base's rules send syslog fails: "Access Control
  Policy Logging configuration is invalid ...". `loggingsettings` PUT `inheritFromParent: true` fixes it (FMC answers with the base's
  setting). A child's `accessrules` listing carries the base's rules with the base's ids (`metadata.accessPolicy` = the base). A base
  is cleared by an `inheritancesettings` PUT without `basePolicy`.
- **Lock holder:** `metadata.lockingStatus.metadata.lockedByUser.name` on the policy record (no `userName` key). The lock list with
  nothing locked is `{items: [{}]}`.
- **Route-map references need the prefix list's type.** FMC's non-expanded `object/ipv4prefixlists` rows carry no `type` (the route
  maps listing does), and a route map whose `ipv4PrefixListAddresses` ref has `type: null` gets HTTP 500 "Prefix lists cannot be
  added inside Access Lists and vice versa ...". With `type: IPV4PrefixList` it is created. A neighbour prefix-list filter tolerates
  the null; a prefix list POSTed without `type` is accepted (FMC answers `IPV4PrefixList`).
- **Default-originate needs a route map.** `neighborDefaultOriginate: {}` (or `{type}`) is answered 200 and stored as nothing. With
  `{routeMap}` it is stored on an update (PUT) and deploys as `neighbor ... default-originate route-map ...`. But when BGP is created
  from scratch in one POST, FMC drops the neighbour's default-originate route map too and answers OK (**F77-6**, below); a prefix-list
  filter in the same POST is kept.
- **Profilers, change-management tickets and TID answer 403 for the lab's API role** ("The user is not authorized."), for both API
  users, while `fmc_troubleshoot` packet tracer files answer 200 on the same login: RBAC, not a feature flag. The role needs the
  Snort 3 Profiling permission (UI: Devices > Troubleshoot > Snort 3 Profiling), the ticket permissions and a TID read permission.
  Change management is off in practice (writes without a ticket are applied); the TID enabled state is unknown.
- **Certificates:** `devices/operational/managecertificates` answers with a task (`metadata.task.id`, status "200" as a string); the
  task goes RUNNING -> COMPLETED with a SUCCESS subtask message. RE_ENROLL of a self-signed enrolment re-issues the certificate on
  the **same key** (public key hash unchanged). A device's `devices/certificates` row disappears with its last enrolment. FMC fills
  validation usage (IPsec client + SSL client) and revocation defaults on the enrollment object.
- **SNMP:** a community must be 1-32 letters and digits; FMC's 400 for anything else echoes the value back. A community is read back
  as a fixed mask. Turning SNMP off keeps the stored community; only a PUT without `communityString` clears it.
- **Inline application filters** are stored as `{applicationDefaultPort: false, inlineApplicationFilters: [{risks: [{type, name,
  id}]}]}`, with no `type` on the filter condition.
- Smaller ones: OSPFv2 passive interfaces are not in the REST model (OSPFv3 only); `show bgp summary` is not in FMC's command list
  (the FTD console answered it); FMC briefly listed a stopped HA standby as connected and green; three creates in a row got FMC 429
  while GETs kept working.

## What is out of reach

- **F78 profiler runs:** both API roles lack the Snort 3 Profiling permission, and changing roles was off limits for the run. A real
  run, the stop semantics and the result JSON are built from FMC's spec examples and unit-tested.
- **F80 ticket column:** change management is off and its API is 403 for the role (a system setting, not changed). Unit-tested.
- **F79 TID section:** not built (the owner's open question; the role gets 403 on `fmc_tid`). FMC's file lists (clean list, custom
  detection list) have no REST endpoints, so a hash makes no request and says so.
- **#249:** the lab has no read-only FMC user, and creating users is off limits.
- **#248:** the HA lab stayed stopped: the proof used FMC's own records of the disconnected pair.
- **Lab:** IOL consoles don't answer (F77 moved to the FTD pair); no custom DNS policy rule or `fmc_dns_block` list exists to hit
  (F79's DNS-rule match is unit-tested); the CML read tier refuses `wget`, so traffic ran through `cml_configure_node` in exec mode.

## F75 certificate enrolment lifecycle (#170, PR #279; fixes #301 #302 #305) — pass (self-signed), partial (PKCS12)

On `mcp-ftd1`. Writes by preview parity (`fmc_api_call` with the preview's `body`); reads with the session tool
`fmc_list_certificates` (F71) and `fmc_run_show_command`.

Stage 2 (live-A):

- `fmc_create_cert_enrollment(name='mcp-w6-enr-self', kind='self_signed', subject={common_name, organization})` (new tool
  in-process): preview body `SELF_SIGNED_CERTFICATE` (FMC's spelling), `includeFQDN NONE`, key RSA 2048 named after the enrollment.
  POSTed by preview parity: created, with FMC's defaults filled in.
- `fmc_enroll_certificate(device='mcp-ftd1', enrollment='mcp-w6-enr-self', action='enroll')` preview: device connected, on-device
  "not enrolled", `used_by` empty (no RA VPN, site-to-site or decryption policy references it), `body` = the exact
  `managecertificates` POST. Performed by parity: task RUNNING -> COMPLETED, subtask "The certificate is successfully enrolled on
  the target device." about 20 s later. `fmc_list_certificates(device='mcp-ftd1')`: one row SUCCESS / identity AVAILABLE, expires in
  ten years, **days_left 3649**. `show crypto ca certificates` shows the trustpoint.
- Blockers (previews): enrolling again is blocked ("already enrolled ...: re_enroll replaces the certificate, refresh re-reads its
  status"); deleting when not enrolled is blocked.
- **RE_ENROLL:** task SUCCESS; a new serial and start date on the device, **the same public key hash**: the preview's "the device
  generates key pair ..." was wrong for this case (**fixed by #301**, re-worded per enrolment type). **REFRESH:** task SUCCESS, row
  unchanged. **DELETE:** preview `used_by` empty (every usage read answered, so no fail-closed blocker), task SUCCESS "successfully
  deleted"; `fmc_list_certificates` then 0 rows.
- `show crypto ca certificates` masked both "Public Key" lines as secrets (**fixed by #302**).
- **PKCS12:** a throwaway CA and a 7-day certificate, wrapped as PKCS12 with OpenSSL 3's defaults (AES-256/PBKDF2) and a random
  passphrase, were placed in the server's `FMC_PKI_DIR` (the passphrase in a file next to it; neither ever printed).
  `fmc_create_cert_enrollment(name='mcp-w6-enr-p12', kind='pkcs12', pkcs12_file=..., passphrase_file=...)` preview (new tool
  in-process): `base64Certificate` "<3536 bytes from FMC_PKI_DIR/..., sent to FMC only>", `passPhrase` `********`; identity subject,
  issuer, validity, SHA-1 and key; one CA certificate; warnings for the file mode (group-readable, needed by the container's user)
  and the 6-day expiry. The output was scanned before it was read: no passphrase, no base64 run of 60+ characters, no "PRIVATE KEY".
  So OpenSSL 3's default PKCS12 opens locally. **Not created:** `fmc_api_call` would carry the bundle in an argument.
- The live task answers and device rows replaced the spec-built shapes in the tests (**#305**).

Re-proof (final-live):

- To have a certificate on the device for #302, `mcp-w6-enr-self` was enrolled again (in-process preview, parity POST): task
  SUCCESS, `fmc_list_certificates` one row, days_left 3649.
- `show crypto ca certificates`: **"Public Key Type: RSA (2048 bits)"** in clear (Stage 2: masked); `show crypto key mypubkey rsa`:
  "Key name: ...", "Key pair was generated at", "Key Data:" in clear. **Residual (cosmetic):** the labels "Public Key Hashes:" and
  "Key Size (bits):" are still masked (`Public Key ********`, `Key ******** (bits)`).
- `show running-config snmp-server` and `aaa-server` on `mcp-ftd1` and `mcp-ftd-identity` hold no secret, so masking real secrets in
  show output stays unit-tested (#302's review added the cases it must keep masked).
- Then deleted from the device (task SUCCESS; the key pair is gone too, `show crypto key mypubkey rsa` lists only the default key),
  and both enrollment objects deleted.

Unit-only by design: SCEP and EST (no lab server), HA/cluster enrolment (not built), the usage scan's RA VPN / site-to-site hits
(the leaf has none), `manual_ca_only`'s `base64Content` without PEM headers. **Waits for the re-proof:** the PKCS12 create and
enrol, and `fmc_enroll_certificate`'s own wait loop through the real tool. The issue stays open for it.

## F76 access policy structure: categories, base policy, locks (#171, PR #281; fixes #297 #298 #299 #300 #305) — pass

Child `mcp-w6-child-acp` with base `mcp-w6-acp` (12 rules, assigned to `mcp-ftd1`).

Stage 2 (live-A):

- `fmc_create_access_policy(name='mcp-w6-child-acp', base_policy='mcp-w6-acp')` (session tool, the new argument passed through):
  the preview showed the inherited rules and the `inheritancesettings` PUT; the result named the base. The child's record has
  `metadata.inherit` and `parentPolicy`; its rule list holds the parent's 12 rules with the parent's ids; `fmc_get_access_policy`
  shows `parent_policy`.
- Categories (new tool in-process, parity writes): `mcp-w6-cat-a` (default), `mcp-w6-cat-m` (mandatory), `mcp-w6-cat-b` with
  `above_category='mcp-w6-cat-a'` (FMC takes the name; it landed directly above). Rename kept the rule's id; delete left the rule
  uncategorized at the same index. A rule in an unknown category is blocked ("create it first (fmc_create_category)").
- `fmc_update_access_rule(rule='mcp-w6-child-icmp', category='mcp-w6-cat-b')` (session tool): FMC applied the move, but the confirm
  returned an error: a 404 on the rule's old id (FMC re-created the rule). **Fail, fixed by #297.**
- Assigned to `mcp-ftd1`: `fmc_pending_changes` listed the 12 inherited rules as ADD with the child. The first deploy got FMC 400
  (the child's own Logging settings, see the findings above). **Fail, fixed by #298.** After a `loggingsettings` PUT
  `inheritFromParent: true` the deploy succeeded; packet tracer allowed web traffic by the **parent's** IPS rule and ICMP by the
  child's own rule.
- Locks: the policy locked by the container's API user (parity POST): `fmc_get_access_policy` lock `{LOCKED, locked_by <that user>}`;
  a session write preview notes "locked by you" and isn't blocked. As the second API user (in-process): `fmc_create_category` and
  `fmc_policy_lock` lock / unlock **blocked** naming the holder; `break_lock=True` previews taking the lock away. Unlocked by the
  holder. FMC's holder field was not where the tool looked (**#300**), and an empty category read rules "0" (**#299**).
- `fmc_set_base_policy`: a loop is blocked; a preview of a new base for `mcp-w6-acp` lists the child that inherits from it
  (`inherited_by`, with its device); `base='none'` and back applied by parity (FMC clears the base when `basePolicy` is omitted).

Re-proof (final-live):

- **#297:** `fmc_update_access_rule(policy='mcp-w6-child-acp', rule='mcp-w6-child-icmp', category='mcp-w6-cat-m')` (session tool):
  the preview says "FMC re-creates the rule in the category: it gets a new id" and that it moves from the default into the mandatory
  section; confirm **applied**, no error, `now_at` mandatory / `mcp-w6-cat-m`, `id_changed {from, to}`. Moved back into
  `mcp-w6-cat-a` the same way (another new id).
- **#298:** `fmc_create_access_policy(name='mcp-w6-child2-acp', base_policy='mcp-w6-acp')` (in-process preview, then the session tool
  confirmed): preview and result `logging "inherited from 'mcp-w6-acp'"` with the side effect explaining why; GET `loggingsettings`
  `inheritFromParent true`. Assigned to `mcp-ftd1`: **the first deploy succeeded**. `fmc_set_base_policy(policy='mcp-w6-child-acp',
  base='mcp-w6-hygiene-acp')` preview (not confirmed): logging "unchanged" (the new base sends no syslog), body = the inheritance PUT
  only. `mcp-w6-acp` assigned back, `mcp-w6-child2-acp` deleted (the base kept its 12 rules).
- **#300:** `mcp-w6-acp` locked by the container's user: `fmc_get_access_policy` names the holder; the session's
  `fmc_create_access_rule` preview says "locked by you" and isn't blocked; the second user's `fmc_create_category` and unlock
  previews are blocked naming the holder. Unlocked.
- **#299:** the empty `mcp-w6-cat-m` reads rules "none".

Not built: moving a category itself (no position in 10.0.1's PUT). Unit-only: `include_parents` locks. Cosmetic leftovers: the
`rules_now` count in `fmc_create_access_rule` previews and the rule count in `fmc_delete_policy` previews of a child include the
base's inherited rules (which a delete doesn't remove). **Waits for the re-proof:** the five new tools by their real MCP names.

## F77 BGP/OSPF route policy (#172, PR #282; fixes #306 #307 #308 #310 #312 #318) — pass after the fixes

iBGP between `mcp-sdwan-t1-hub` and `mcp-sdwan-t1-spoke1` over the mpls carrier (a private AS). Before state recorded first: no BGP
and no OSPF on either device (`fmc_get_routing`: three static routes each; `show running-config router` empty).

Plan: the hub advertises `<hub-inside>` and redistributes connected routes through route map `mcp-w6-t1-rm-conn` (prefix list
`mcp-w6-t1-pl-conn` = `<hub-inet>` and `<hub-lte>`, so the mpls transport subnet stays out and the session can't recurse through
itself) and originates a default route; spoke1 advertises `<spoke1-inside>` and filters inbound with prefix list `mcp-w6-t1-pl-in`
(deny `<hub-lte>`, permit the rest `le 32`).

Stage 2 (live-B):

- `fmc_create_prefix_list` (new tool in-process): entries as `seq 5 permit ...`, `le 32` -> `maxPrefixLength`; POSTed by parity
  without `type`: accepted. A duplicate is blocked ("already exists (2 entries); pass replace=true").
- `fmc_create_route_map(name='mcp-w6-t1-rm-conn', entries=[{action: permit, match_prefix_list: ['mcp-w6-t1-pl-conn']}])`: the
  preview's prefix-list ref had `type: null` and FMC answered **500** to exactly that body. **Fail, fixed by #306.** Created with the
  type set by hand.
- `fmc_configure_bgp(..., redistribute=[...], default_originate=True)` (session tool): the stale client refused the list argument,
  so preview parity; the preview listed steps but no bodies (**#307**), so the bodies were rebuilt from the code. FMC stored the
  neighbour's `neighborDefaultOriginate: {}` as nothing: the preview and result claimed a default route that never reached the
  device. **Fail, fixed by #310** (default-originate now needs a route map). With `default_originate_route_map` (a permit-all route
  map, update PUT) it was stored.
- `fmc_pending_changes` masked "Send Community attribute to this neighbor" (a true/false) as a secret (**#308**).
- Deployed both: spoke1 `show route bgp` had `B* 0.0.0.0/0`, `<hub-inside>` and `<hub-inet>` via `<hub-mpls-ip>`, and no `<hub-lte>`
  (filtered inbound); the hub's own BGP table held `<hub-lte>` as redistributed and no `<hub-mpls>` (kept out by the route map).
  `fmc_get_routing` (session tool) named the route map and prefix list per neighbour and the redistribution's route map. Put back
  with `remove_bgp=True` on both, deployed, verified against the before state; every object deleted.

Re-proof (final-live):

- **#306:** `fmc_create_route_map('mcp-w6-t1-rm-conn', ...)` in-process preview: the ref carries `type: IPV4PrefixList`; POSTed with
  exactly that body: **created**. The permit-all `mcp-w6-t1-rm-default` the same way. Spoke1's neighbour prefix-list filter sends the
  typed ref too (it used to send null); FMC accepts it.
- **#310:** `fmc_configure_bgp(hub, ..., default_originate=True)` without a route map (session tool): an **error before any write**
  naming `default_originate_route_map` and how to make a permit-all route map.
- **#307:** in-process previews of the hub's create with throwaway MD5 passwords (one of them the flag-like `on`): `requests` = the
  two POSTs with `neighborSecret: "********"`; neither value appears anywhere in the output. The redistribution `requests[0]` PUT
  body was sent **verbatim** with `fmc_api_call` (the list argument can't pass the stale client) and applied.
- Hub, session tool with the new scalar arguments: `fmc_configure_bgp(hub, local_as, router_id, neighbor, remote_as, advertise,
  default_originate=True, default_originate_route_map='mcp-w6-t1-rm-default')`: preview `requests` = POST general settings + POST bgp
  with `neighborDefaultOriginate {routeMap}`; applied. **But FMC stored `neighborFiltering: {}`** (GET, and the next preview's
  re-read): **new bug F77-6** (below). The same arguments on the update path (PUT, BGP now there) were stored; `fmc_get_routing`:
  `default_originate {route_map mcp-w6-t1-rm-default}`, the redistribution and the network.
- Spoke1 (session tool, from scratch, `neighbor_prefix_list_in='mcp-w6-t1-pl-in'`): stored (a filter in the from-scratch POST is
  kept; only default-originate is dropped).
- **#308:** `fmc_pending_changes(device='mcp-sdwan-t1-hub')` before the deploy: "Send Community attribute to this neighbor: false",
  "Generate default routes: true".
- Deployed both. Hub running-config: `neighbor <spoke1-mpls-ip> default-originate route-map mcp-w6-t1-rm-default`, `network <hub-inside>`,
  `redistribute connected route-map mcp-w6-t1-rm-conn`; spoke1: `neighbor <hub-mpls-ip> prefix-list mcp-w6-t1-pl-in in`. Spoke1
  `show route bgp`: **"Gateway of last resort is `<hub-mpls-ip>`", `B* 0.0.0.0 0.0.0.0 [200/0]`**, `<hub-inside>` and `<hub-inet>`; no
  `<hub-lte>` (prefix list), no `<hub-mpls>` (route map). Hub: `<spoke1-inside>` via `<spoke1-mpls-ip>`.
- Put back: `remove_bgp=True` on both (preview `requests`: DELETE bgp, DELETE general settings), deployed, `show running-config
  router` empty, `show route` identical to the before table, `fmc_get_routing` = before. Route maps, prefix lists and the two
  network objects deleted.

**F77-6 (fixed in #318, proven live; #172 closed):** `fmc_configure_bgp(default_originate=True, default_originate_route_map=...)`
on a device **without BGP** sends the default-originate block in the create POST; FMC 10.0.1 answers OK but stores nothing (the
update path stores it). Since #318 the tool re-reads the new model after the create, sends dropped neighbour filters again in one
update and re-reads once more. Live after the release fixes (coordinator, 2026-10-22, deployed main db1f52f, session tool):
`mcp-<t1-hub>` without BGP, `fmc_configure_bgp(local_as=65110, router_id=<hub>, neighbor=<spoke1 mpls>, remote_as=65110,
default_originate=True, default_originate_route_map='mcp-w6-t1-rm-default')` -> applied 'create bgp general settings', 'create bgp',
'update bgp: neighbor filters FMC left out of the create', `verified: FMC 10.0.1 left these neighbor filters out of the create
(<spoke1>: default_originate); the update sent them again and the re-read shows them stored`; `fmc_get_routing` showed the
neighbour's `default_originate {route_map mcp-w6-t1-rm-default}`. Put back with `remove_bgp` (FMC-side proof, not deployed; the
device-side default route was proven over the update path above).

Unit-only: OSPF `redistribute=` (the live plan was BGP); community and AS-path list refs (types from the spec). Not built: OSPFv2
passive interfaces (not in FMC 10.0.1's REST model). **Waits for the re-proof:** `fmc_create_prefix_list` / `fmc_create_route_map` by
their real names and `fmc_configure_bgp(redistribute=[...])` through a client that sends the list.

## F78 Snort rule and CPU profiling (#173, PR #290) — blocked by the role; 403 wording and previews pass

On `mcp-ftd-identity` (IPS licence, Snort 3), all new tool in-process. No profiler was started.

- Probe (Stage 1): `GET` and `POST` of `snortprofiler/<device>/rules` and `cpuprofiler/<device>/modules` -> **403 "The user is not
  authorized."** for the container's API user, on two devices and in two domains; packet tracer files on the same API answer 200.
  The spec has a duration only for the CPU profiler (15-120 minutes); the Snort rule profiler runs until stopped.
- live-B, as the second API user (the same 403): `fmc_get_profiler_results(device='mcp-ftd-identity')` for `snort` and `cpu` answers
  "The FMC user's role lacks the Snort 3 profiling permission (FMC's page for it: Devices > Troubleshoot > Snort 3 Profiling) ...
  This isn't a login problem when other calls work with the same account (fmc_packet_tracer is the same API family)", not the
  generic credentials hint.
- `fmc_snort_profile(minutes=5)` preview: blocked by the same text; it states the duration ("the server starts the profiler, waits,
  stops it and reads the result (FMC's rule profiler has no duration of its own)"), the requests, the CPU and latency cost with a
  headroom check (`fmc_device_metrics`), the last run and what happens if the server stops mid-run. `fmc_cpu_profile(minutes=15,
  wait=false)`: the same, "FMC stops it by itself; its range is 15-120 min"; `minutes=10` is refused before any request.

**Unit-only** (from the spec examples, because of the permission): the POST answer, "running" in the latest result, stop via
`DISABLED`, the shortest useful rule profile, real rule and module JSON (multi-instance rows), the file GET by name, FMC's 15-minute
CPU floor. The issue stays open for the owner: add the Snort 3 Profiling permission to the lab API role and run the PR's live calls,
or accept F78 as mock-tested.

## F79 `fmc_find_indicator` (#174, PR #280; fix #309) — pass

All new tool in-process, read only.

Stage 2 (live-B):

- `value='cisco.com'`: the exact FQDN object `mcp-w6-fqdn` and rule `mcp-w6-acp #3 mcp-w6-fqdn-allow` (destination via the object),
  and the same rule again under the child policy as `mcp-w6-child-acp #4` with no hint that it is inherited (**#309**). 50 requests
  (objects 6, SI policies 15, DNS policies 1 / rules 4, access policies 15 / rules 58, decryption 2 / rules 3).
- `value='https://example.com/payload.exe'`: `contains` matches on URL object `mcp-test-url` and its rule in two policies; 50 requests.
- `value='bad.example.net', areas=['dns_rules', 'si_lists', 'security_intelligence']`: 0 results, 32 requests; `limits` says Talos and
  custom SI list entries aren't in the REST API and `fmc_dns_block` lists are matched by name.
- A SHA-256 value: **0 FMC requests**, `not_checked` names FMC's file lists (no REST endpoints) and TID.
- `max_requests=15`: stops at 15 with the skipped reads named (10 is refused by validation); `device='mcp-ftd1'`: only its policy,
  20 requests.

Re-proof (final-live): `value='cisco.com'`: the child's row reads **`mcp-w6-child-acp #4 mcp-w6-fqdn-allow (ALLOW) [inherited from
mcp-w6-acp]`**, and `limits` explains it; 50 requests.

Not built: the TID section. Unit-tested: the DNS-rule and `fmc_dns_block` list matches (no seed exists), SI feeds' entries.
**Waits for the re-proof:** the same calls through the container (the in-process run used the second API user).

## F80 compliance pack: hardening check and per-rule evidence (#175, PR #288; fixes #303 #304) — pass

`mcp-w6-ps` on `mcp-ftd1`.

Stage 2 (live-A):

- `fmc_hardening_check(platform_settings='mcp-w6-ps')` (new tool in-process), before: 6 findings (VDB content age on FMC and the
  device, external authentication, RFC 5424 timestamps, login banner, ICMP), 11 passed (Smart Licensing, FMC backup, SSH, HTTPS,
  SNMP off, syslog servers, NTP, DNS, assignment, licences, nothing pending), 3 not applicable with reasons (SNMP hosts: server off;
  HA monitoring: not an HA unit; device backup: FTDv has none). The fix calls name the policy's owner domain.
- Findings appear: SSH access from any IPv4 and SNMP v2c on with a manager (session tools `fmc_configure_ssh_access`,
  `fmc_configure_snmp`) -> **2 high findings**, `ssh-access-restricted` and `snmp-v3-only`, each naming its fix call. A community with
  a hyphen got FMC 400, which echoed it (**fixed by #303**); the finding's wording read "SNMP is on with a community string is set"
  (**#304**). Fixes applied as named -> **"No findings."**; the stored community was cleared with a PUT without it (FMC behaviour, see
  above) and `mcp-ftd1` deployed (`show running-config snmp-server`: `no snmp-server enable`).
- Edited baseline: a copy of `docs/baselines/ftd-hardening.yaml` named `mcp-w6-baseline` with `login-banner` disabled, in
  `FMC_BUNDLE_DIR`: `baseline='mcp-w6-baseline.yaml'` reports it from there, and `login-banner` is absent from the checks run.
- Evidence: HTTP from `<inside-host>` to `<internet-host>` through `mcp-w6-ips-allow`, then `fmc_export_access_rules(policy='mcp-w6-acp',
  evidence=true, since_days=2)` (session tool, new arguments passed through): per rule the hits on `mcp-ftd1` with first and last
  hit, logging, the IPS policy and variable set, the last 'Save Policy mcp-w6-acp:<rev>' audit record with its user, the deploy job
  that pushed it, comments; for the policy the default action's hits, SI and DNS policy, saves in the window, and
  `change_management` "not readable by this account (403): no ticket column".

Re-proof (final-live): **#303:** `fmc_configure_snmp(policy='mcp-w6-ps', enabled=True, community=<a community with hyphens>, ...)`
preview (session tool, not confirmed): **blocked**, "The SNMP community must be 1 to 32 letters and digits ... The value isn't
shown here."; the community shows as "set (hidden)" and its value appears nowhere in the answer.

Unit-only: the ticket column (change management off, 403); #304's wording (needs SNMP on with a community again); `fix_tool: null`
findings (no tool for SNMPv3 users or external authentication: they point at the UI). **Waits for the re-proof:**
`fmc_hardening_check` through the container, including `baseline='mcp-w6-baseline.yaml'` from its bundle directory.

## Follow-ups from Wave 6 Now

### #248 packet tracer / prove on a disconnected HA active unit (PR #287) — pass

Session `fmc_packet_tracer(device='mcp-fw-ha', ...)`, read only, with the HA lab stopped. First call: FMC itself briefly listed the
standby unit as connected and green, and the row said the active unit is disconnected, named the connected standby, warned that
FMC's failover state may be stale, and traced on neither. A minute later FMC listed the standby as unreachable, and the row said "no
other unit of mcp-fw-ha is connected ...: FMC can't reach the pair." Both branches ran live; `fmc_prove_policy` shares the check
(unit-tested on the recorded HA layout).

### #249 a read-only API user's objects (PR #291) — unit-only

`is_system()` decides objects whose `readOnly.reason` is RBAC by type and FMC's built-in ids; the writers keep refusing them, naming
the role (`role_read_only()`). Tested on a read-only user's recording; the review checked every caller for writer-side regressions.
No read-only user exists in the lab.

### #250 `fmc_set_si_lists` and an inherited DNS policy (PR #289) — pass

Session `fmc_set_si_lists(policy='mcp-w6-acp', names=['DNS Phishing'], kind='dns', list_type='block')`, preview only: the first
blocker gives the leaf way (a DNS policy of the leaf's own: `fmc_create_dns_policy` -> `fmc_set_dns_policy` -> `fmc_set_si_lists`,
then deploy), the second the Global alternative with the 15 access policies and 17 devices it reaches. No "read-only default"
wording; `fmc_threat_posture`'s wording is unit-tested.

### #272 inline application filters (PRs #284, #294; fixture #312) — pass by preview parity

The stale client sent the dict `inline_app_filter` as a string, so the preview ran in-process: label `inline-filter:risk High or
Very High`, the "lives in this rule only" note, body `applications.inlineApplicationFilters [{risks [...]}]`. That body was POSTed
with `fmc_api_call`: a disabled rule `mcp-w6-inline-filter` in `mcp-w6-acp`. FMC's stored shape (above) is now the test fixture.
Session `fmc_get_access_rule` read it back as `inline-filter:risk High or Very High`; the delete preview showed the same label.
Not run: a hit-count match on high-risk traffic (the rule was disabled). **Waits for the re-proof:** the create through a client
that sends the dict.

### #273 small fixes (PRs #286 #293 #294 #295 #296, follow-up #311) — pass where the lab allowed

- **#286 `fmc_assign_policy` in the owner domain**, as the final restore of `mcp-ftd1`: from `Global/mcp-test-leaf`,
  `kind='access', policy='mcp-test-ftd-acp'` previewed `assigned_in 'Global'` with the 406 side effect and was **applied** (0.15.0
  got FMC 406); `kind='platform_settings', policy='mcp-test-ps'` the same. Called from Global, the preview shows the leaf-owned
  policy it replaces as `from` (it was empty).
- **#293 + #311 certificate names from the PEM:** NetLock's root (FMC's fields are mojibake) -> subject "NetLock Arany (Class Gold)
  Főtanúsítvány", organization "NetLock Kft."; SECOM RootCA2 (no CN; FMC cuts the organization at its comma) -> organization "SECOM
  Trust Systems CO.,LTD." and, after #311, subject = issuer = "Security Communication RootCA2" (the OU), `self_signed` true.
- **#295:** `fmc_bulk_update_access_rules` added a comment to two rules of `mcp-w6-hygiene-acp`: applied 2, one GET to verify, the
  comment in both rules' history.
- **#296:** `fmc_replace_object(scope=['nat_rules'])` preview row "mcp-w6-nat auto NAT of mcp-w6-b (DYNAMIC)" (not confirmed).
- Unit-tested: the HTTPS-server-stays-on note, leaf built-ins named built-in, pending-change lines cut per side, the device-group
  description compare, the application-filter id note and `fmc_find_application(kind='filter')` from rules (#294), the
  `fmc_rule_lookup` SGT window wording, single-rule MONITOR logging.

### #274 two flaky tests (PR #292) — unit-only

The mocks stamped jobs at setup while the code read the clock at request time; under load the job was filtered as older and the
wait polled to its deadline. `dangerous.wall_clock()` is now the single wall-clock read of both registration waits, frozen in the
tests, with confirms bounded by 60 s. Full suites under load have passed since (gate 2: 1584 passed).

## Fixes found live (all merged before the re-proof)

| PR | Item | What the live run found | Fix | Re-proven |
|---|---|---|---|---|
| #297 | F76 | a move into a category errored (404): FMC re-creates the rule | re-find the rule by name; `id_changed`; the preview warns | final-live A1 |
| #298 | F76 | a new child's first deploy failed: its own Logging settings | inherit the base's Logging on create; `fmc_set_base_policy` only when the base sends syslog (or `inherit_logging=True`) | final-live A2 |
| #299 | F76 | an empty category read rules "0" (FMC: 0/0) | "none" | final-live A9 |
| #300 | F76 | the lock holder sits in the record's nested metadata | read it there; an own lock no longer blocks own writes | final-live A9 |
| #301 | F75 | re_enroll claimed the device generates a key | wording per enrolment type and state | unit (live wording) |
| #302 | F75 | show output masked public key labels | label shapes skipped; real secrets kept masked (review) | final-live A4 (two labels left) |
| #303 | F80 | a hyphenated community reached FMC (400 echoing it) | blocked in the preview, value not shown | final-live A8 |
| #304 | F80 | finding wording | "SNMP is on, but ..." | unit |
| #305 | F75, F76 | spec-built test shapes | live task, device-row and inheritance answers | tests |
| #306 | F77 | route-map prefix-list ref `type: null` -> FMC 500 | the collection's type for typeless rows | final-live A3 |
| #307 | F77 | BGP/OSPF previews had no bodies | `requests` (method, path, body), secrets masked whatever the value | final-live A3 |
| #308 | F77 | "Send Community attribute" true/false masked | allow-listed flag labels shown; real communities masked | final-live A5 |
| #309 | F79 | a child's inherited rule reported twice, unlabelled | "[inherited from <base>]" (also in `fmc_find_address`) | final-live A6 |
| #310 | F77 | default-originate without a route map dropped by FMC | refused, naming a permit-all route map | final-live A3 |
| #311 | #273 | a CN-less certificate had no subject or issuer | CN, else OU, else O; `self_signed` from the PEM | final-live A7 |
| #312 | F77, #272 | spec-built route-policy and inline-filter shapes | live answers in the tests | tests |

Found in the re-proof (open): **F77-6** (#172, above); #302's two remaining labels; `fmc_delete_policy`'s rule count for a child.

## Re-proof after a session restart

These calls ran only by the in-process or preview-parity paths, or not at all, because the session's tool list predates the
release. After the owner restarts the Claude session (which fetches the current tool list), run them through the real MCP tools
(the container's API user), in domain `Global/mcp-test-leaf`, each preview read before confirming:

1. **F75 PKCS12** (start `mcp-cml-ftd` first): `fmc_create_cert_enrollment(name='mcp-w6-enr-p12', kind='pkcs12',
   pkcs12_file='mcp-w6-enr-p12.p12', passphrase_file='mcp-w6-enr-p12.pass')` -> `fmc_enroll_certificate(device='mcp-ftd1',
   enrollment='mcp-w6-enr-p12')` (and re_enroll / refresh / delete through the tool's own wait loop) -> `fmc_list_certificates
   (expiring_within_days=30)` -> a GET of the object (bundle and passphrase masked) -> the container log searched for the passphrase
   (`grep -c -F -f <the .pass file>`, expect 0) -> delete the enrolment, the object and both files. The throwaway certificate expires
   2026-10-28.
2. **F76:** `fmc_create_category` / `fmc_rename_category` / `fmc_delete_category` / `fmc_set_base_policy` / `fmc_policy_lock` by name on
   a scratch `mcp-w6-*` child policy.
3. **F77** (start `mcp-sdwan-t1`): `fmc_create_prefix_list` / `fmc_create_route_map` by name; `fmc_configure_bgp(redistribute=[...])`
   through the real client; F77-6 after its fix; then `remove_bgp`, deploy and delete the objects.
4. **#272:** `fmc_create_access_rule(inline_app_filter={'risks': ['High', 'Very High']})` on a disabled `mcp-w6-*` rule; read back;
   delete.
5. **F79, F78, F80 through the container:** `fmc_find_indicator`; `fmc_get_profiler_results` and the `fmc_snort_profile` /
   `fmc_cpu_profile` previews (a real run only after the owner grants Snort 3 Profiling); `fmc_hardening_check`, including
   `baseline='mcp-w6-baseline.yaml'` from the container's bundle directory.

## Also in v0.16.0: F82/F83 (another session)

The TLS version and cipher suite rules (F82, #276) and Undecryptable Actions with default-action logging (F83, #277) came from the
TLS cipher lab (Cookbook recipe `ftd-tls-cipher-policy`) in PRs #285, #313, #314 and #315, proven live on that lab's FTD by that session.
Their evidence (the `tls-matrix` and `tls-events` runs, FMC's cipher suite acceptance, the RC4 finding) is in those PR bodies.

## State left after the run

- `mcp-ftd1` back on its original access, NAT and platform settings policies (`mcp-test-ftd-acp`, `mcp-test-ftd-nat`, `mcp-test-ps`,
  all Global), deployed, nothing pending, no certificate enrolled.
- `mcp-sdwan-t1-hub` and `-spoke1`: BGP as before (none), `mcp-sdwan-acp` assigned again; FMC refuses that deploy (empty zones, its
  state before the run, like spoke2/spoke3), so both are pending and keep running `mcp-w6-t1-acp`, which is kept.
- Deleted: `mcp-w6-child-acp` (with its categories), `mcp-w6-child2-acp`, the enrollments `mcp-w6-enr-self` and `mcp-w6-enr-probe`,
  and every F77 object. Kept as seeds: `mcp-w6-acp`, `mcp-w6-ps`, `mcp-w6-hygiene-acp`, `mcp-w6-bulk-acp`, `mcp-w6-nat`,
  `mcp-w6-t1-acp`, their objects, `mcp-w6-grp` and `mcp-w6-nf-ifg`. FMC keeps the comment history added to two
  `mcp-w6-hygiene-acp` rules (#295).
- No policy locked, no profiler started.
- Files for the re-proof: the throwaway PKCS12 and its passphrase file in the server's PKI directory, the edited baseline in its
  bundle directory (delete the PKCS12 files after the F75 re-proof).
- CML: `mcp-cml-ftd` and `mcp-sdwan-t1` stopped; `mcp-cml-identity` running.

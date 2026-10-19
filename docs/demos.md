# Demo storylines (F60)

Three single-product stories for a proof of concept, each a 15-minute sequence of prompts: what to ask,
what to point at in the answer, and what the audience should come away having seen. A five-minute
threat-defense vignette closes. Every story runs against a real FMC with FTDs; story 2 also uses CML (or
any other way to fail a WAN link). Addresses are placeholders (`<client>`, `<server>`, ...); the
"reference lab" names are the suite's own lab, so swap in yours.

| Story | The point | Server tiers | Minutes |
|---|---|---|---|
| [1. Change with proof and rollback](#story-1-change-with-proof-and-rollback) | Every change is previewed, proven on the device and undoable | write + dangerous (deploy, rollback) | 15 |
| [2. SD-WAN: add a branch, fail a WAN link](#story-2-sd-wan-add-a-branch-fail-a-wan-link) | A branch joins the overlay in one conversation; a dead WAN link is survived and diagnosed | write + dangerous (registration, deploy) | 15 |
| [3. Why is it blocked? to fixed](#story-3-why-is-it-blocked-to-fixed) | From a user complaint to the cause, the fix and the proof | write + dangerous (deploy) | 15 |
| [Vignette: threat-defense review](#vignette-threat-defense-review) | A security review of a policy in a minute, every finding with its fix | read | 5 |

## Before any demo

- **Server:** `MCP_ENABLE_WRITES=true` and `MCP_ENABLE_DANGEROUS=true` (deploys, rollback, registration);
  story 2 also needs `FMC_FTD_REG_KEY` set on the server (the key never enters the conversation). The server has
  an FMC user of its own: a login ends that user's other sessions, so nobody else (GUI, scripts, tests) logs in as
  it during the demo. With FMC domains, pass `domain` on every call or set `FMC_DOMAIN` (reference lab:
  `Global/mcp-test-leaf`).
- **Check:** `fmc_status` (version, tools per tier, prompts listed), `fmc_license_status` (registration and
  deploys need Smart Licensing or evaluation mode), and `fmc_pending_changes` for every device a story deploys:
  it must show nothing, or someone else's change goes out with yours.
- **Names:** every object a demo creates is named `mcp-fw-demo-*`: access rules, network and port objects,
  policies, VPN topologies (the SD-WAN tool names its pools after the topology, so they match too). That is the
  contract the reset relies on.
- **Previews:** every write answers with a preview first. Confirm in front of the audience: reading the preview
  (what changes, which devices, what traffic it interrupts) is part of the story, not a step to skip.
- **Timing:** an FTDv deploy takes 1-3 minutes; FMC's tunnel monitor trails the devices by a few minutes (the
  device's own view, `device_says`, is current); health-monitor metrics trail by up to ~5 minutes. Talk through
  the waits; the stories below leave room for them.
- **Reset** before and after each story: see [Reset](#reset).

## Story 1: change with proof and rollback

> "Security wants telnet from the inside to the server blocked. Show me the change before it happens, prove it
> on the firewall, then undo it."

| Cast | What it is | Reference lab |
|---|---|---|
| `<FTD>` | one standalone FTD, connected, with a recent successful deployment | `mcp-ftd-identity` |
| `<policy>` | the access policy assigned to `<FTD>` (best: no other device uses it) | its `mcp-fw-*` access policy |
| `<client>` | a host behind the inside interface | the identity lab's client |
| `<server>` | a host beyond the outside interface with telnet (tcp/23) and http (tcp/80) open, both allowed today | the identity lab's outside server |

**Before the audience arrives:** reset; `fmc_list_deployments` for `<FTD>` shows at least one successful
deployment (rollback returns to the one before the demo's); from `<client>`, telnet to `<server>` connects and
http returns 200.

| # | Min | Ask | Point at | The audience sees |
|---|---|---|---|---|
| 1 | 0-1 | "Is `<FTD>` healthy and is anything waiting to deploy?" (`fmc_get_device`, `fmc_pending_changes`) | connected, `<policy>` assigned, no pending changes | a clean starting point |
| 2 | 1-5 | Prompt `fmc_rule_change_review` with policy=`<policy>`, rule=`mcp-fw-demo-block-telnet`, source=`<client>`, destination=`<server>`, protocol=`tcp`, port=`23`; give the change when asked: BLOCK, tcp/23, from `<client>` to `<server>`, at the top, logging on | the baseline bundle it keeps as the rollback point; the before verdicts (telnet ALLOW by the baseline rule, a neighbouring flow such as http also ALLOW); the `fmc_create_access_rule` preview (the rule as FMC will store it, position 1) and Claude's shadowing check | the change explained in policy terms before anything changes |
| 3 | 5-6 | "Approved, make it." | the confirmed create; the after verdicts: telnet BLOCK by `mcp-fw-demo-block-telnet`, http still ALLOW by the baseline rule; whether the re-run audit finds anything new | the verdict changed only where intended |
| 4 | 6-7 | "What would a deploy push?" (`fmc_pending_changes` device=`<FTD>`) | one access policy change, by the server's user | nothing else rides along |
| 5 | 7-10 | "Deploy it to `<FTD>` only." (`fmc_deploy` devices=[`<FTD>`]) | the preview: one device, the out-of-date policies, whether traffic is interrupted; then the task SUCCEEDED | a deploy that names its device and waits for the result |
| 6 | 10-12 | "Prove it on the firewall." (`fmc_prove_policy` flows: telnet `expect: block`, `rule: mcp-fw-demo-block-telnet`; http `expect: allow`) then the same from `<client>` | both rows `pass` with the deciding rule; telnet now fails from the client, http still 200; `fmc_get_hit_counts` on the new rule | proof from the device itself, not from FMC's configuration |
| 7 | 12-14 | "Roll `<FTD>` back to before this change." (`fmc_rollback_deployment` device=`<FTD>`) then `fmc_prove_policy` with the same flows | the preview: recent deployments and the one it returns to; after it: the telnet row is now `fail` (allowed again), and the client connects | an undo that is proven, not assumed |
| 8 | 14-15 | "Is FMC back where it was?" (`fmc_pending_changes`; `fmc_diff_policy_bundle` with a=the baseline bundle, compared with the live policy) | rollback restores the device, not FMC: the rule is still in `<policy>` and shows as pending. Delete it (`fmc_delete_access_rule`, preview) or keep it for the next deploy | both states visible, and how to reconcile them |

**If it goes wrong:** "No earlier successful deployment to roll back to" means the device has only one
deployment in its history: deploy any harmless change once before the demo. A `snort-blacklist` drop in packet
tracer is a cached verdict from an earlier blocked flow: repeat with another `source_port`. A deploy refused for
FMC warnings: read them out; that is the safety rail working. Right after the rollback the FTD may have lost its
ARP entry for `<server>`: a trace then shows `allow (drop) no-v4-adjacency`. Let `<client>` connect once, then
prove again. The next deploy after a rollback pushes the whole device configuration and takes a little longer.

## Story 2: SD-WAN: add a branch, fail a WAN link

> "We open branches every month. Add this one to the SD-WAN, prove it, then show me what happens when a WAN link
> dies."

| Cast | What it is | Reference lab |
|---|---|---|
| `<hub>` | the SD-WAN hub FTD | `mcp-sdwan-t1-hub` |
| `<spoke>` | an existing spoke with two WAN links: a primary tunnel and a backup tunnel to the hub | `mcp-sdwan-t1-spoke1` |
| `<branch>` | the new branch FTD: pointing at FMC (pending), or already registered and in no topology | `mcp-fw-branch1` |
| `<hub-host>`, `<spoke-host>`, `<branch-host>` | a host on each site's inside network | the SD-WAN lab's hosts |
| `<spoke-wan-link>` | the CML link of the spoke's primary WAN | the spoke's link to its primary carrier |
| `<acp>` | the access policy the spokes use (allows the inside zone to and from the overlay zone) | the SD-WAN lab's policy |

**Before the audience arrives (about 20 minutes):** reset; build the overlay with `fmc_create_sdwan_topology`
name=`mcp-fw-demo-sdwan`: `<hub>` with `hub_inside_interfaces`, the overlay `tunnel_zone`, a `spoke_pool`,
`hub_backup_wan_interface` and a `backup_wan_pool` (the tool builds the second-WAN tunnels as the companion
topology `mcp-fw-demo-sdwan-wan2`), and `<spoke>` with its primary WAN and `backup_wan_interface`. Deploy `<hub>`
and the spokes by name and wait until `fmc_sdwan_status` shows every tunnel up. The branch's WAN must reach the
hub's DVTI address. Registration takes 5-10 minutes: register `<branch>` beforehand when the slot is tight (the
prompt skips registration for a device that is registered, connected and in no topology).

| # | Min | Ask | Point at | The audience sees |
|---|---|---|---|---|
| 1 | 0-1 | "How healthy is the SD-WAN?" (`fmc_sdwan_status` topology=`mcp-fw-demo-sdwan`) | hub and spokes, WAN links, tunnels, iBGP neighbours; `degraded` empty | a working overlay to add to |
| 2 | 1-8 | Prompt `fmc_onboard_branch` with name=`<branch>`, host=`<branch mgmt>`, topology=`mcp-fw-demo-sdwan`, access_policy=`<acp>`, wan_ip, wan_gateway, inside_ip, inside_host=`<branch-host>`, test_destination=`<hub-host>` (and `domain`) | the preconditions; the template check (no template fits an FTDv on FMC 10.0.1, so it says so and takes the manual path); interfaces, underlay route and an underlay ping; the `fmc_update_sdwan_topology` preview (tunnel address from the pool, devices to deploy: `<hub>` and `<branch>` only); the deploy by name. Tell Claude up front to name anything it creates `mcp-fw-demo-*` (e.g. `mcp-fw-demo-branch-lan`, `mcp-fw-demo-branch-nat`) | one conversation takes a box from "registered" to "on the overlay", every change previewed |
| 3 | 8-10 | "Prove the branch works." (`fmc_sdwan_status` branch=`<branch>`, `fmc_vpn_status` device=`<branch>`, then the prompt's hand-off `fmc_prove_policy` flows) and a ping from `<branch-host>` to `<hub-host>` | tunnel up, IKE READY with child-SA counters both ways, the hub's networks over the VTI; prove-policy rows `pass` (branch to hub, hub to branch, one flow the policy blocks) | the new site proven end to end, with a record to re-run after every change |
| 4 | 10-12 | "Fail the spoke's primary WAN." (`cml_set_link_state` lab=`<the spoke's CML lab>`, link=`<spoke-wan-link>`, state=`down`) then a ping series from `<spoke-host>` to `<hub-host>` (`cml_check_reachability` rounds) and `fmc_sdwan_status` branch=`<spoke>` | the pings keep answering (with ECMP across both tunnels no loss; without it, a gap of about 20-25 s in the reference lab while iBGP moves to the backup tunnel); the primary tunnel down, the backup up, the primary WAN in `degraded` | the overlay survives a dead link |
| 5 | 12-14 | Prompt `fmc_vpn_troubleshoot` with symptom="the spoke's primary tunnel to the hub is down", device=`<spoke>`, topology=`mcp-fw-demo-sdwan`, source=`<spoke-host>`, destination=`<hub-host>` | `device_says` and the IKEv2 counters: retransmits only, no authentication failures, so a dead path rather than a key mismatch; the route and interface checks; packet tracer leaving by the backup tunnel; the verdict "an upstream path or carrier problem: no FMC change fixes it" | the phase and the evidence named, and an honest answer about what FMC can't fix |
| 6 | 14-15 | "Bring the link back." (`cml_set_link_state` state=`up`) then `fmc_sdwan_status` a minute later | both tunnels up (the reference lab: within about 30 s); the primary WAN stays in `degraded` for about 5 minutes, because the health monitor's samples trail the device | recovery confirmed by the same tool that saw the failure |

**Variants:** a brownout instead of a dead link (`cml_apply_link_scenario` brownout, undo with
`cml_clear_link_scenarios`) shows loss and delay in `fmc_sdwan_status` path metrics when path monitoring is on,
but those trail by up to ~5 minutes: better in a longer session. A wrong pre-shared key (authentication failures
growing between two `fmc_vpn_status` calls) is the other fault `fmc_vpn_troubleshoot` tells apart.

**If it goes wrong:** a tunnel FMC reports as UNKNOWN right after the deploy while `device_says` shows READY is
the monitor's lag: ask again in a minute. A branch that can't ping the hub's WAN address can't build a tunnel:
fix the underlay (the prompt's step 4g) before joining the topology.

## Story 3: why is it blocked? to fixed

> "Since this morning the client can't reach the web app. Find out why, fix it, and prove nothing else opened up."

| Cast | What it is | Reference lab |
|---|---|---|
| `<FTD>`, `<policy>`, `<client>`, `<server>` | as in story 1; http (tcp/80) to `<server>` is allowed by the policy's baseline rule | as in story 1 |

**Before the audience arrives:** reset, then plant the break with the tools (preview, confirm):
`fmc_create_access_rule` policy=`<policy>`, name=`mcp-fw-demo-break-web`, action BLOCK, source `<client>`,
destination `<server>`, tcp/80, insert_before=1, comment "CHG-1234 tighten web access", then `fmc_deploy`
devices=[`<FTD>`]. Try http from `<client>` a few times so the rule has hits.

| # | Min | Ask | Point at | The audience sees |
|---|---|---|---|---|
| 1 | 0-1 | The ticket: "`<client>` can't reach the web app on `<server>` since this morning." | | a real-world starting point |
| 2 | 1-6 | Prompt `fmc_why_blocked` with source=`<client>`, destination=`<server>`, protocol=`tcp`, port=`80`, device=`<FTD>` | step 1 (offline walk, `fmc_rule_lookup`): first definite match `mcp-fw-demo-break-web` BLOCK at position 1, above the rule that allows http; step 2 (`fmc_packet_tracer`): DROP, acl-drop, phase ACCESS-LIST, the same rule by name and device rule id; step 3: its hit count; step 4: nothing pending, the last deployment succeeded (the device runs what FMC shows); step 5 (`fmc_list_audit_records`): who added the rule and when | the cause with evidence from the configuration, the device, the counters and the audit trail, in one answer |
| 3 | 6-8 | "Is the block wider than web?" (`fmc_rule_lookup` with tcp/443 and with another client) | only tcp/80 from `<client>` matches it | a precise diagnosis, not "the firewall is blocking" |
| 4 | 8-10 | "Disable that rule; keep it for the post-mortem." (`fmc_update_access_rule` rule=`mcp-fw-demo-break-web`, enabled=false) then `fmc_pending_changes` | the preview's field change (enabled true -> false); one pending change | the smallest fix, reviewed before it lands |
| 5 | 10-12 | "Deploy to `<FTD>`." (`fmc_deploy`) | one device, task SUCCEEDED | |
| 6 | 12-14 | "Prove it, and prove nothing else opened." (`fmc_prove_policy` flows: http `expect: allow` with the baseline rule as `rule`; a flow the policy must still block, e.g. tcp/3389 to `<server>`, `expect: block`) and http from `<client>` | both rows `pass`, deciding rules named; the client gets 200 | fixed, and still closed where it should be |
| 7 | 14-15 | "Who changed what today?" (`fmc_list_audit_records` since_minutes=60, text=`<policy>`) | the break and the fix as two saves of `<policy>` (FMC logs a rule edit as "Save Policy <policy>:<revision>", without the rule name), each with user and time; `fmc_pending_changes` names the rule before a deploy | an audit trail a change board can read |

## Vignette: threat-defense review

> "How well does this policy actually stop threats?"

Prompt `fmc_threat_defense_review` with policy=`<policy>` (and `domain`). Point at the posture summary (default
action; how many ALLOW rules carry an intrusion policy, a file policy and logging; intrusion policies and their
modes; Security Intelligence lists and feed status; DNS policy; decryption; network analysis; device licences),
then the ranked findings, each with its evidence and the exact tool call that fixes it. The audience sees a
security review in a minute that changes nothing and makes every finding actionable.

Five more minutes, when the devices have the IPS licence: apply one fix live. `fmc_create_intrusion_policy`
name=`mcp-fw-demo-ips` on a Balanced base policy, put it on the ALLOW rule for http with `fmc_update_access_rule`
(note the old value from the preview: the reset doesn't undo edits to existing rules) and deploy.
`fmc_find_intrusion_rules` with query `58723` shows that Snort rule 1:58723 (Log4j) drops in it. Then, from
`<client>`, a harmless request that matches it:

```bash
curl -m 5 -H 'X-Api-Version: ${jndi:ldap://test/a}' http://<server>/   # reset by the firewall
curl -m 5 http://<server>/                                              # still 200
```

## Reset

Everything the stories create is named `mcp-fw-demo-*`, so a reset finds it by name: VPN topologies first
(`fmc_list_vpn_topologies`, `fmc_delete_s2s_vpn`; the SD-WAN companion `mcp-fw-demo-sdwan-wan2` too), then
access rules (`fmc_list_access_rules` per policy, `fmc_delete_access_rule`), then policies (`fmc_delete_policy`;
FMC refuses one that is still assigned), then groups and objects (`fmc_list_objects` with
name_or_value=`mcp-fw-demo-`, `fmc_delete_object`) and the SD-WAN spoke pools. A static route that references a
demo object (story 2's hub return route to the branch) blocks that object's delete: remove the route first
(`fmc_list_routes`, `fmc_delete_static_route`). Then `fmc_pending_changes` and
`fmc_deploy` for the devices those touched (the policy's devices; the topology's hub, spokes and branch), named
one by one. The maintainers' lab has a script for this (`fw_demo_reset.py` in the suite's private lab repo,
stutters-mcp-lab), dry run by default.

A reset does not undo: edits to objects or rules that existed before (note the old values from the previews),
a branch's registration and interface configuration (the onboarding prompt reuses a registered, connected
branch), the hub's DVTIs and loopbacks (the SD-WAN tool reuses them; remove them with `fmc_delete_interface`, DVTI first), or a rollback's effect on the device (the
next deploy replaces it).

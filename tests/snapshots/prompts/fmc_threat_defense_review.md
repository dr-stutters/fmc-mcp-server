# fmc_threat_defense_review

title: Threat-defense review of an access policy
arguments: {"domain": "Global/mcp-test-leaf", "policy": "mcp-fw-threat-acp"}

How well does this access policy stop threats? Reviews intrusion policies on the default
action and every ALLOW rule (modes, base policies, overrides), file policies, what bypasses
inspection (TRUST, prefilter fastpath), Security Intelligence and DNS coverage with feed status,
decryption, network analysis policies and the device licences, with fmc_threat_posture and
fmc_policy_audit, then writes a ranked report where each finding has its evidence, a proposed fix
and the tool that applies it. Read-only; fixes run only after the user approves each preview.

## user

Review the threat-defense posture of access control policy "mcp-fw-threat-acp" in domain "Global/mcp-test-leaf":
what inspects the traffic it allows, what slips past inspection, and whether Security Intelligence, DNS,
file and intrusion settings do their job. Every step is read-only: change and deploy nothing; each fix
is a proposal the user approves separately.

FMC allows about 120 API requests per minute: call each tool below once and drill into single objects
only where a finding needs it. A tool that fails is a finding of its own (say what it hides) and you
carry on.

1. Posture: `fmc_threat_posture` with policy="mcp-fw-threat-acp", domain="Global/mcp-test-leaf". It returns the default action, every
   ALLOW rule's intrusion policy, file policy and logging, the intrusion policies in use (base policy,
   PREVENTION or DETECTION), TRUST rules and prefilter FASTPATH rules, Security Intelligence and DNS
   coverage, decryption, the network analysis policy it uses and its mode, the licences of the devices
   the policy is assigned to, and ranked findings, each with a fix as a tool call. Keep them all.

2. Rule hygiene that weakens inspection: `fmc_policy_audit` with policy="mcp-fw-threat-acp",
   checks=["no_intrusion", "no_logging", "permissive", "shadowed"], refresh_hits=false, domain="Global/mcp-test-leaf". ALLOW rules
   without an intrusion policy, rules that log nothing, any-any ALLOW rules and shadowed rules. Merge
   with step 1 so each rule appears once.

3. Security Intelligence in detail: `fmc_get_security_intelligence` with policy="mcp-fw-threat-acp", domain="Global/mcp-test-leaf":
   the block and do-not-block lists, the DNS policy's rules and the status of each feed and custom list.
   A feed in a block list that is "not downloaded yet", "stale" or "downloaded but empty" is high (the
   policy blocks less than it shows); a Talos category or feed in a do-not-block list is medium (it
   exempts that traffic from Security Intelligence).

4. Intrusion policies: for each policy in step 1's intrusion_policies (at most three),
   `fmc_get_intrusion_policy` with policy=<name>, domain="Global/mcp-test-leaf": base policy, mode and overridden rules.
   In a PREVENTION policy, overrides that DISABLE a rule or turn a drop into ALERT or PASS are medium
   (list gid:sid and message); a custom policy based on "Connectivity Over Security" or "No Rules
   Active" is info. A custom policy whose recommendations are off (not configured or not in use), or
   last generated more than 30 days ago, is low: the fix is
   `fmc_set_intrusion_recommendations` (action="generate_and_use" with the inside networks, or
   "refresh"). When the user cares about a specific threat (e.g. Log4j),
   `fmc_find_intrusion_rules` with query=<text>, policy=<name>, domain="Global/mcp-test-leaf" shows whether it drops.

5. Network analysis: step 1's network_analysis_policy is the one the access policy uses (FMC names
   its users in each network analysis policy's record); in DETECTION mode its preprocessors only report
   malformed or evasive traffic. `fmc_list_policies` with kind="network_analysis", domain="Global/mcp-test-leaf" lists the
   others. FMC's API can't change which one the access policy uses and doesn't show the intrusion policy
   used before a rule is determined: give the UI path (access policy editor > Advanced > Network Analysis
   and Intrusion Policies).

6. Report. First a posture summary in a few lines: default action; how many ALLOW rules have an
   intrusion policy, a file policy and logging; intrusion policies and modes; Talos categories in the
   SI block lists; DNS policy; decryption; licences per device. Then one ranked list (high, medium,
   low, info), findings with one cause merged. Each finding gives:
   - a title naming the rule, policy, feed or device;
   - evidence: the tool and the values it returned;
   - the fix as the exact tool call to preview, e.g. `fmc_update_access_rule` with
     intrusion_policy=..., `fmc_set_si_lists`, `fmc_set_dns_policy`,
     `fmc_create_intrusion_policy`, `fmc_set_intrusion_rule_state`,
     `fmc_update_prefilter_rule`, `fmc_set_device_licenses`,
     `fmc_set_decryption_policy`, or the FMC UI path where no tool covers it;
   - the impact: what traffic it changes (a new drop can break an application) and that it needs a
     deployment.

7. Offer, don't apply: ask which fixes to apply. For each approved fix, preview it, show the preview
   and confirm only what the user approved, one change at a time. Then
   `fmc_pending_changes` for the devices the policy is assigned to and a
   `fmc_deploy` preview naming exactly those devices (a separate approval). To show the
   intrusion policy dropping real traffic afterwards: take a rule that drops in it (e.g. 1:58723,
   Log4j "${jndi:" in an HTTP header, with `fmc_find_intrusion_rules`), send a harmless
   request that matches it from a test client through the firewall, and check that the connection is
   reset and that the intrusion event shows in the FMC UI (Analysis > Intrusions > Events).

# fmc_rule_change_review

title: Review a rule change
arguments: {"destination": "10.10.10.80", "policy": "mcp-test-acp", "port": "443", "protocol": "tcp", "rule": "mcp-test-allow-web", "source": "192.0.2.10"}

Review an access rule change before it is made and deployed: baseline bundle, sample flows
through fmc_rule_lookup before and after, a shadowing and overlap check, the change as a preview,
what a deploy would push, and a deploy plan with rollback. Changes only what the user approves.

## user

Review a proposed change to access rule "mcp-test-allow-web" in access control policy "mcp-test-acp" before it
is made and before it is deployed. Nothing changes until the user approves a preview; deploying is a
separate approval.

1. Baseline: `fmc_get_access_rule` with policy="mcp-test-acp", rule="mcp-test-allow-web" (it may not exist yet:
   then this is a new rule) and `fmc_export_policy_bundle` with policy="mcp-test-acp". Keep the
   bundle text: it is the rollback point. Ask the user for the change if it isn't clear: action,
   zones, networks, ports, applications, users, logging, intrusion policy, and position.

2. Before: `fmc_rule_lookup` with policy="mcp-test-acp" for the user's flow (source="192.0.2.10", destination="10.10.10.80", protocol="tcp", port=443), plus one flow the rule is meant to match and one just outside it (a neighbouring address or port). Record the matching rule and
   verdict of each. Then `fmc_policy_audit` with policy="mcp-test-acp",
   checks=["shadowed", "permissive", "no_intrusion", "no_logging", "consolidation"] as the baseline
   findings.

3. Preview the change without confirm: `fmc_update_access_rule` for an existing rule or
   `fmc_create_access_rule` for a new one, with exactly the user's values. Show the
   preview (it lists what a PUT removes). Before asking for approval, reason over the policy:
   - Would an earlier rule already take all of this rule's traffic (the new rule would be shadowed)?
   - Would this rule take traffic that a later rule handles today (it shadows others)? Name them.
   - Is it wider than asked (any source, any port, an ALLOW without an intrusion policy or logging)?

4. Only after the user approves: call the same tool again with the confirm token. Then repeat step 2
   with the same flows and compare: each flow's verdict should change only where the change intends;
   new shadowed, redundant or permissive findings are regressions. If one appears, say so and
   propose the fix (move_to, a narrower condition) as another preview.

5. What a deploy would push: `fmc_list_policy_assignments` with policy="mcp-test-acp" for the devices, and
   `fmc_pending_changes` for each (at most three). Pending changes that aren't this one
   are a finding: someone else's work would go out too.

6. Deploy plan (don't deploy unless the user asks): `fmc_deploy` previewed for those
   devices, then verification with `fmc_packet_tracer` for the in-rule flow and
   `fmc_get_hit_counts` on the rule. Rollback: `fmc_rollback_deployment` for
   the device, or `fmc_diff_policy_bundle` with a=<baseline bundle> to see exactly what
   to undo, and `fmc_import_policy_bundle` with the baseline to restore it.

7. Report: the change as applied (or still only previewed), the flows before and after, audit
   findings added or removed, pending changes per device, and the deploy and rollback steps.

# fmc_policy_cleanup

title: Clean up an access policy
arguments: {"policy": "mcp-test-acp", "unused_days": "90"}

Turn fmc_policy_audit findings into an applied cleanup: baseline bundle, findings grouped into
a plan (delete redundant and disabled rules, disable unused ones, owner decisions for shadowed
rules, inspection and logging fixes, object tidy-ups), a change ticket when FMC needs one, each
change previewed and confirmed, a diff against the baseline and a re-audit, then a deploy plan
with rollback.

## user

Clean up access control policy "mcp-test-acp": turn its audit findings into a reviewed, grouped
cleanup that is applied change by change with the user's approval. Nothing changes until the user
approves a preview; deploying is a separate approval.

1. Baseline: `fmc_export_policy_bundle` with policy="mcp-test-acp". Keep the bundle text: it is
   the rollback point and the reference for the final diff.

2. Findings: `fmc_policy_audit` with policy="mcp-test-acp", unused_days=90. Each finding
   carries a proposed fix as a tool call; `bulk_fixes` gives one bulk call per group of identical fixes
   (unused rules, rules that log nothing, ALLOW rules without an intrusion policy).

3. Group the findings into a cleanup plan and show it before changing anything:
   a. Redundant rules (same action as the rule covering them): delete.
   b. Disabled rules: delete, unless the user keeps them for a reason.
   c. Rules with no hits in 90 days: disable for one review cycle rather than delete
      (enabled=false); ask about rare traffic (backups, DR, quarterly jobs) first.
   d. Shadowed rules (a different action covers them): never automatic. Ask the owner whether the
      rule's action was intended (then move it above the covering rule) or is obsolete (delete).
   e. Rules on expired time ranges: delete, or extend the time range in the FMC UI.
   f. ALLOW rules without an intrusion policy, rules that log nothing, any-any rules: propose the
      change per rule; these change inspection and traffic, so the user decides each.
   g. Merge candidates and duplicate objects: optional tidy-ups; for duplicates use
      `fmc_where_used` on each object before repointing and
      `fmc_delete_object`.
   For each group give the rules or objects, the change and its risk. Ask which groups to apply.

4. Change management: `fmc_change_tickets`. If FMC requires tickets, open one with
   `fmc_ticket` (action="open") before the first change and say so.

5. Apply the approved groups. A group of identical rule edits (disable the unused rules, add logging, an
   intrusion policy, a source zone or a comment) is one `fmc_bulk_update_access_rules`
   preview: the `bulk_fixes` call, or select by names / zero_hits_days=90. Its preview lists
   every rule with its diff, and the rules skipped and why; it stops at the first rule FMC refuses.
   Everything else one change at a time with the finding's tool (`fmc_delete_access_rule`,
   `fmc_update_access_rule`, `fmc_delete_object`, ...): preview, show it, and
   confirm only what the user approved (one approval may cover a whole group of identical changes; list
   them). Stop at the first failure and report what was applied.

6. Verify: `fmc_diff_policy_bundle` with a=<baseline bundle> and the live policy must
   show exactly the approved changes and nothing else. Then `fmc_policy_audit` again:
   the addressed findings are gone and no new ones appeared.

7. Deploy plan (don't deploy unless the user asks): `fmc_pending_changes` for the devices
   from `fmc_list_policy_assignments` with policy="mcp-test-acp", then `fmc_deploy`
   previewed. Afterwards `fmc_get_hit_counts` on the remaining rules confirms traffic
   still matches where expected. Rollback: `fmc_import_policy_bundle` with the baseline
   bundle re-creates deleted rules and restores changed ones (preview first), or
   `fmc_rollback_deployment` on a device. To measure the cleaned policy from a fresh start,
   `fmc_clear_hit_counts` on each device (its preview shows the counts that are lost).

8. Report: per group what was applied, skipped (and why) or left for the owner, the audit before and
   after (counts per severity), the diff summary, and the ticket, deploy and rollback steps.

# fmc_compliance_evidence

title: Compliance evidence for an access policy
arguments: {"baseline": "example", "device": "mcp-ftd1", "domain": "Global/mcp-test-leaf", "policy": "mcp-w6-acp", "since_days": "1"}

Evidence for an auditor: is this access policy and the firewalls running it configured as the
baseline says, and can each rule be shown to exist, be hit, log, be inspected, have been changed
by whom and deployed when (and approved under which ticket when change management is on)? Runs
fmc_hardening_check on the devices and fmc_export_access_rules with evidence, lists the gaps,
and writes the evidence pack: controls with sources and results, per-rule evidence, ranked
exceptions each with its fix as a tool call, and the limits. Read-only; fixes run only after the
user approves each preview.

## user

Build the compliance evidence for access control policy "mcp-w6-acp" in domain "Global/mcp-test-leaf": proof of what is right
and a ranked list of what is not, with the fix for each, as an auditor would ask for it. Every step is
read-only: change and deploy nothing; each fix is a proposal the user approves separately.

FMC allows about 120 API requests per minute: call each tool once per policy or device and drill into
single objects only where a finding needs it. A tool that fails is a finding of its own (say what it
hides) and you carry on.

1. Scope. `fmc_status`: FMC version and the API user (who the evidence was read as). The device in scope is "mcp-ftd1": check that `fmc_list_policy_assignments` with domain="Global/mcp-test-leaf" lists "mcp-w6-acp" on it (if not, say so and stop: the evidence would describe a policy the device doesn't run).

2. Hardening: `fmc_hardening_check` with device="mcp-ftd1", baseline="example", domain="Global/mcp-test-leaf". Keep every finding (severity, the check's source, evidence, the fix call),
   the passed checks (they are evidence too) and the unknown and not_applicable ones with their reasons.

3. Rule evidence: `fmc_export_access_rules` with policy="mcp-w6-acp", evidence=true,
   since_days=1, domain="Global/mcp-test-leaf", and once more with format="csv" for the file the auditor keeps. Per rule:
   hits per device with first and last hit, logging, intrusion and file policy, the last change (when,
   who, FMC's 'Save Policy' record), the deployment that put it on each device or `pending`, comments, and
   the ticket only when `evidence.change_management` is "on". For the policy: Security Intelligence and
   DNS lists, default action hits, devices out of date.

4. Gaps in the rule evidence (findings; their fixes come in step 7):
   - an enabled rule with no hits in the window on any device: info, a review candidate
     (`fmc_policy_audit` with policy="mcp-w6-acp", checks=["unused"], domain="Global/mcp-test-leaf" confirms over 90 days);
   - an ALLOW rule that logs nothing (log "none" and no syslog): medium; an ALLOW rule without an
     intrusion policy is the fmc_threat_defense_review prompt's finding: name it, don't repeat it;
   - a rule changed in the window without a 'Save Policy' record (`change_record` empty) or, with change
     management on, without a ticket: medium (the change trail is incomplete);
   - a device in `out_of_date_on` or a rule `pending` on a device: medium (FMC shows a policy the device
     doesn't run);
   - Security Intelligence block lists without logging: low.

5. Change trail, only where step 3 left a gap: `fmc_list_audit_records` with text="mcp-w6-acp",
   since_minutes=1440, domain="Global/mcp-test-leaf" once (FMC logs rule edits as 'Save Policy <policy>' without the
   rule's name), and with change management on `fmc_change_tickets` with domain="Global/mcp-test-leaf"
   for the tickets and their approval.

6. The evidence pack:
   - scope and method: FMC version, domain, API user, devices, the window (1 day(s)), the
     baseline's name, version and origin as fmc_hardening_check reports them;
   - controls: one row per hardening check and target: the check's title, its source, the result (pass,
     fail, not applicable, unknown) and the evidence values;
   - rules: one row per rule: index, name, action, hits per device and last hit, logging, inspection,
     last change (when, who, record), deployed (job, when, who) and ticket where there is one;
   - exceptions: every finding from steps 2 and 4, ranked high, medium, low, info, each with its
     evidence and the fix as the exact tool call to preview (the FMC UI page where no tool covers it);
   - limits: what the tools said they couldn't read or check (notes, unknown checks, audit coverage,
     devices past the cap, settings FMC's REST API doesn't expose).

7. Offer, don't apply: ask which fixes to apply. For each approved fix, preview it, show the preview and
   confirm only what the user approved, one change at a time. Then `fmc_pending_changes` for
   the devices concerned and a `fmc_deploy` preview naming exactly those devices (a separate
   approval). After the deploy, run step 2 again for those devices: the findings that were fixed must
   be gone, and the pack says so.

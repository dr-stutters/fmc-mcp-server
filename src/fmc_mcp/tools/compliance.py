"""The fmc_compliance_evidence prompt (F80): an auditor's evidence pack for one access policy and its devices,
from fmc_hardening_check and fmc_export_access_rules(evidence=true). Read-only; fixes are proposals."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated

from pydantic import Field

from fmc_mcp._core import InvalidRequest, ToolRegistrar, tool_ref
from fmc_mcp.baseline import DEFAULT_BASELINE
from fmc_mcp.tools.prompts import _q

MAX_DEVICES = 3  # devices whose hardening is checked one by one before the prompt asks for platform_settings


def compliance_evidence_text(
    policy: str, device: str | None, since_days: int, baseline: str, domain: str | None
) -> str:
    """fmc_compliance_evidence: scope, hardening, rule evidence, gaps, change trail, pack, offer."""
    if not 1 <= since_days <= 365:
        raise InvalidRequest("since_days must be between 1 and 365.")
    pol = _q(policy, "policy")
    base = _q(baseline, "baseline")
    dom = _q(domain, "domain") if domain else None
    d = f", domain={dom}" if dom else ""
    where = f" in domain {dom}" if dom else ""
    w = f" with domain={dom}" if dom else ""
    if device:
        dev = _q(device, "device")
        scope = (
            f"The device in scope is {dev}: check that {tool_ref('fmc_list_policy_assignments')}{w} lists "
            f"{pol} on it (if not, say so and stop: the evidence would describe a policy the device "
            "doesn't run)."
        )
        hardening = f"{tool_ref('fmc_hardening_check')} with device={dev}, baseline={base}{d}."
    else:
        scope = (
            f"{tool_ref('fmc_list_policy_assignments')}{w}: the devices {pol} is "
            "assigned to (HA pairs by name) and the platform settings policy of each."
        )
        hardening = (
            f"{tool_ref('fmc_hardening_check')} with device=<device>, baseline={base}{d} for each device "
            f"from step 1 (at most {MAX_DEVICES}; with more, once with platform_settings=<their policy> per "
            "platform settings policy, which checks up to 10 of its devices)."
        )
    return f"""Build the compliance evidence for access control policy {pol}{where}: proof of what is right
and a ranked list of what is not, with the fix for each, as an auditor would ask for it. Every step is
read-only: change and deploy nothing; each fix is a proposal the user approves separately.

FMC allows about 120 API requests per minute: call each tool once per policy or device and drill into
single objects only where a finding needs it. A tool that fails is a finding of its own (say what it
hides) and you carry on.

1. Scope. {tool_ref("fmc_status")}: FMC version and the API user (who the evidence was read as). {scope}

2. Hardening: {hardening} Keep every finding (severity, the check's source, evidence, the fix call),
   the passed checks (they are evidence too) and the unknown and not_applicable ones with their reasons.

3. Rule evidence: {tool_ref("fmc_export_access_rules")} with policy={pol}, evidence=true,
   since_days={since_days}{d}, and once more with format="csv" for the file the auditor keeps. Per rule:
   hits per device with first and last hit, logging, intrusion and file policy, the last change (when,
   who, FMC's 'Save Policy' record), the deployment that put it on each device or `pending`, comments, and
   the ticket only when `evidence.change_management` is "on". For the policy: Security Intelligence and
   DNS lists, default action hits, devices out of date.

4. Gaps in the rule evidence (findings; their fixes come in step 7):
   - an enabled rule with no hits in the window on any device: info, a review candidate
     ({tool_ref("fmc_policy_audit")} with policy={pol}, checks=["unused"]{d} confirms over 90 days);
   - an ALLOW rule that logs nothing (log "none" and no syslog): medium; an ALLOW rule without an
     intrusion policy is the fmc_threat_defense_review prompt's finding: name it, don't repeat it;
   - a rule changed in the window without a 'Save Policy' record (`change_record` empty) or, with change
     management on, without a ticket: medium (the change trail is incomplete);
   - a device in `out_of_date_on` or a rule `pending` on a device: medium (FMC shows a policy the device
     doesn't run);
   - Security Intelligence block lists without logging: low.

5. Change trail, only where step 3 left a gap: {tool_ref("fmc_list_audit_records")} with text={pol},
   since_minutes={since_days * 1440}{d} once (FMC logs rule edits as 'Save Policy <policy>' without the
   rule's name), and with change management on {tool_ref("fmc_change_tickets")}{w}
   for the tickets and their approval.

6. The evidence pack:
   - scope and method: FMC version, domain, API user, devices, the window ({since_days} day(s)), the
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
   confirm only what the user approved, one change at a time. Then {tool_ref("fmc_pending_changes")} for
   the devices concerned and a {tool_ref("fmc_deploy")} preview naming exactly those devices (a separate
   approval). After the deploy, run step 2 again for those devices: the findings that were fixed must
   be gone, and the pack says so.
"""


def register(reg: ToolRegistrar) -> None:
    @reg.prompt(
        title="Compliance evidence for an access policy",
        example={"policy": "mcp-w6-acp", "device": "mcp-ftd1", "domain": "Global/mcp-test-leaf"},
    )
    def fmc_compliance_evidence(
        policy: Annotated[str, Field(description="Access control policy name or UUID")],
        device: Annotated[
            str | None,
            Field(
                description="Only this device (name or UUID); default: every device the policy is assigned to"
            ),
        ] = None,
        since_days: Annotated[
            int, Field(ge=1, le=365, description="Evidence window in days (audit records, deployments)")
        ] = 30,
        baseline: Annotated[
            str, Field(description="Hardening baseline (bundled name or a file name in FMC_BUNDLE_DIR)")
        ] = DEFAULT_BASELINE,
        domain: Annotated[
            str | None, Field(description="FMC domain name or UUID; the server's default domain if omitted")
        ] = None,
    ) -> str:
        """Evidence for an auditor: is this access policy and the firewalls running it configured as the
        baseline says, and can each rule be shown to exist, be hit, log, be inspected, have been changed
        by whom and deployed when (and approved under which ticket when change management is on)? Runs
        fmc_hardening_check on the devices and fmc_export_access_rules with evidence, lists the gaps,
        and writes the evidence pack: controls with sources and results, per-rule evidence, ranked
        exceptions each with its fix as a tool call, and the limits. Read-only; fixes run only after the
        user approves each preview."""
        return compliance_evidence_text(policy, device, since_days, baseline, domain)

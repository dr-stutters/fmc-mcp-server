"""Workflow prompts (MCP prompts) that chain this server's tools for common operator questions."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import json
import re
from typing import Annotated, Literal

from pydantic import Field

from fmc_mcp._core import InvalidRequest, Tier, ToolRegistrar, tool_ref

# Prompt arguments end up inside instructions: keep them to one line of plain characters.
_SAFE = re.compile(r"^[\w.:/@ ()+,-]{1,200}$")


def _q(value: str, what: str) -> str:
    """A user-supplied value as a quoted literal, refusing anything that could carry instructions."""
    v = value.strip()
    if not _SAFE.match(v):
        raise InvalidRequest(f"{what} {value!r} has characters that aren't allowed here.")
    return json.dumps(v)


def _why_blocked_text(
    source: str,
    destination: str,
    protocol: str,
    port: int | None,
    device: str | None,
    ingress_interface: str | None,
    policy: str | None,
) -> str:
    """The fmc_why_blocked instructions for one flow."""
    proto = protocol.strip().lower()
    if proto not in ("tcp", "udp", "icmp"):
        raise InvalidRequest(f"protocol must be tcp, udp or icmp, not {protocol!r}.")
    if proto == "icmp":
        port = None
    src, dst = _q(source, "source"), _q(destination, "destination")
    source, destination = json.loads(src), json.loads(dst)
    flow = f"{proto} {source} -> {destination}" + (f" port {port}" if port is not None else "")
    port_arg = f", port={port}" if port is not None else ""
    tracer_port = f", destination_port={port}" if port is not None else ""
    dev = _q(device, "device") if device else "<the device>"
    iface = _q(ingress_interface, "ingress_interface") if ingress_interface else "<the ingress interface>"
    pol = _q(policy, "policy") if policy else "<the device's access control policy>"
    pol_ref = pol if policy else "<the policy rule_lookup reports>"
    find_device = (
        f"The device is {dev}."
        if device
        else f"Find the FTD that carries this flow with {tool_ref('fmc_list_devices')}. With several, "
        f"{tool_ref('fmc_rule_lookup')} with device=<candidate> shows under `device.ingress` whether its "
        f"interfaces or routes covers {source}."
    )
    policy_arg = f", policy={pol}" if policy else ""
    iface_arg = f", input_interface={iface}" if ingress_interface else ""
    zone_note = (
        f"The ingress interface is {iface}: pass its zone as source_zone."
        if ingress_interface
        else "It finds the device's access policy and the ingress/egress zones from the interface subnets "
        "and static routes itself (reported under `device`)."
    )
    return f"""Explain why this traffic is blocked (or confirm it is allowed): {flow}.
Work through the steps in order, keep notes of what each step shows, and stop early only when a step
gives a definite answer that the later steps cannot change. All steps before step 7 are read-only.

0. Context. {find_device}

1. Offline policy walk: {tool_ref("fmc_rule_lookup")} with device={dev}{policy_arg}, source={src},
   destination={dst}, protocol="{proto}"{port_arg}. {zone_note} If `device.egress` is null, no route
   covers {destination}. Note the first definite match, any earlier 'conditional' rules (application,
   URL or user conditions) and the default action. This is what FMC's configuration says.

2. Live verdict: {tool_ref("fmc_packet_tracer")} with device={dev}{iface_arg}, protocol="{proto}",
   source_ip={src}, destination_ip={dst}{tracer_port} (it picks the ingress interface from the source).
   Read `action`, `drop_reason`, the phase that dropped it and `matched_rules`:
   - acl-drop with a matched rule: the access (or prefilter) rule named there blocks it;
   - no-v4-adjacency / no-adjacency: the policy allows it but the FTD has no ARP entry for the
     next hop. This is not a policy problem; check the next hop is up (route, ARP, cabling);
   - no-route / route lookup failure: a routing problem, see {tool_ref("fmc_list_routes")};
   - a NAT phase drop or an unexpected translation: see the NAT policy;
   - allow: the device would pass it. Then the problem is elsewhere (return path, another device, the
     host itself) or the test doesn't match the real flow (ports, interface).
   A drop "snort-blacklist" means an earlier flow with the same 5-tuple was blocked and is still
   cached; repeat with another source_port to see what a new connection gets.
   If packet tracer and the offline walk disagree, the device runs a different configuration than
   FMC holds: go to step 4.

3. Is the rule actually hit? {tool_ref("fmc_get_hit_counts")} with policy={pol_ref}, device={dev} and
   rule=<the matched rule name>. A rule with zero hits while users report blocks means real traffic
   takes another path or matches a different rule. Note the device rule id; it matches packet
   tracer's rule id.

4. Was the configuration deployed? {tool_ref("fmc_pending_changes")} for device={dev} shows edits not
   yet on the device (a 'System' UPDATE with "Data not available" is FMC housekeeping after a
   reboot or upgrade, not an edit); {tool_ref("fmc_list_deployments")} with device={dev} and
   since_hours=24 shows recent deployments and whether they succeeded.

5. Who changed it? {tool_ref("fmc_list_audit_records")} with since_minutes=1440 and text=<the matched
   rule name or the policy name> lists recent edits, by whom and when.

6. Report: the verdict (blocked or allowed), the exact cause (rule name and position, default
   action, ARP/route or NAT problem), the evidence from each step, and whether the device matches FMC.

7. Fix proposal (only if the user wants it changed), always preview-first:
   - allow it: {tool_ref("fmc_create_access_rule")} (an ALLOW rule placed above the blocking one with
     insert_before) or {tool_ref("fmc_update_access_rule")} on the blocking rule;
   - block it: an access rule with action BLOCK above the rule that allows it, or for single hosts
     map them into a dynamic object that a BLOCK rule already references with
     {tool_ref("fmc_map_dynamic_object")} (no deployment needed; see {tool_ref("fmc_list_dynamic_objects")}).
   Show the preview and wait for the user's approval before confirming. Access rule changes reach
   the device only after {tool_ref("fmc_deploy")}; check {tool_ref("fmc_pending_changes")} first, deploy
   (preview-first too), then rerun {tool_ref("fmc_packet_tracer")} to prove the fix.
"""


def _onboard_text(
    name: str,
    host: str | None,
    recipe: str | None,
    access_policy: str,
    outside_interface: str,
    outside_ip: str,
    gateway: str,
    inside_interface: str,
    inside_ip: str,
    nat_policy: str | None,
    platform_settings: str | None,
    test_destination: str | None,
    template: str | None = None,
) -> str:
    """The fmc_onboard_ftd instructions."""
    if not host and not recipe:
        raise InvalidRequest("Give the FTD's management `host`, or a CML `recipe` to build it from.")
    try:
        for v in (gateway, test_destination, host):
            if v:
                ipaddress.ip_address(v.strip())
        inside_iface = ipaddress.ip_interface(inside_ip.strip())
        ipaddress.ip_interface(outside_ip.strip())
    except ValueError as e:
        raise InvalidRequest(f"Not an IP address: {e}") from None
    dev = _q(name, "name")
    acp = _q(access_policy, "access_policy")
    out_if, in_if = _q(outside_interface, "outside_interface"), _q(inside_interface, "inside_interface")
    out_ip, in_ip = _q(outside_ip, "outside_ip"), _q(inside_ip, "inside_ip")
    gw = _q(gateway, "gateway")
    host_q = _q(host, "host") if host else "<the management IP from the recipe's address_plan>"
    natp = _q(nat_policy, "nat_policy") if nat_policy else None
    psp = _q(platform_settings, "platform_settings") if platform_settings else None
    dest = _q(test_destination, "test_destination") if test_destination else gw
    inside_net = json.dumps(str(inside_iface.network))
    if template:
        tpl = _q(template, "template")
        template_step = f"""
2b. Device template {tpl} (a branch like an existing one): {tool_ref("fmc_get_device_template")}
   template={tpl} lists its variables (type and default), interfaces, overridable objects and VPN/SD-WAN
   settings. Fill the variables for {dev} (interface addresses such as {out_ip} and {in_ip}, AS numbers,
   router id) and call {tool_ref("fmc_apply_device_template")} template={tpl}, device={dev},
   variables={{...}}, overrides={{...}} for per-branch objects. It is dangerous-tier and replaces the
   device's configuration: show the preview (every variable, given or default, and every override) and
   wait for approval. The template brings the interfaces, zones, routes, NAT and policy assignments and
   the SD-WAN/VPN membership, so in steps 3-5 only check what {tool_ref("fmc_pending_changes")} shows and
   fill gaps the template doesn't carry. In step 6 deploy {dev} and the hub(s) of its VPN topology, and
   verify the tunnels with {tool_ref("fmc_get_vpn_topology")}.
"""
    else:
        template_step = f"""
   Rolling out a branch like an existing one? A device template does steps 3-5 (and SD-WAN/VPN
   membership) in one call: {tool_ref("fmc_list_device_templates")}, then run this prompt again with
   template=<its name> ({tool_ref("fmc_create_device_template")} makes one from a working branch).
"""
    if recipe:
        build = (
            f"1. Build the FTD in CML: {tool_ref('cml_build_recipe')} with recipe={_q(recipe, 'recipe')} "
            "(preview first; the FTDv boots in 15-30 minutes, so build with wait=false and then "
            f"{tool_ref('cml_wait_for_converged')}). Then {tool_ref('cml_verify_recipe')} for the same "
            "recipe: "
            "the 'show managers' probe must show the FMC as pending. The recipe's fmc_side and "
            "credentials sections give the management IP and registration key."
        )
    else:
        build = (
            f"1. The FTD exists at {host_q}. It must point at this FMC: on its CLI, `show managers` lists "
            "the FMC (status Pending). If not, run `configure manager add <fmc-ip> <reg-key>` on the FTD "
            f"(in CML: {tool_ref('cml_configure_node')} with mode='exec')."
        )
    nat_step = (
        f"Use NAT policy {natp}: {tool_ref('fmc_assign_policy')} kind='nat', policy={natp}, devices=[{dev}]."
        if natp
        else f"Create NAT policy {json.dumps(json.loads(dev) + '-nat')} with "
        f"{tool_ref('fmc_create_nat_policy')}, then {tool_ref('fmc_create_nat_rule')} kind='auto', "
        f"original_source={inside_net} (a network object; "
        f"create it with {tool_ref('fmc_create_object')} if needed), translated_source='interface', "
        f"nat_type='DYNAMIC', source_interface=<the inside zone>, destination_interface=<the outside zone>; "
        f"then {tool_ref('fmc_assign_policy')} kind='nat', devices=[{dev}]."
    )
    ps_step = (
        f" Assign platform settings {psp}: {tool_ref('fmc_assign_policy')} kind='platform_settings', "
        f"policy={psp}, devices=[{dev}]."
        if psp
        else ""
    )
    return f"""Onboard the FTD {dev} into this FMC and bring it to a working, verified deployment.
Every write below is preview-first: show each preview and wait for the user's approval before
confirming. Keep notes of what each step returned. Stop and report if a step fails; don't improvise
around a failed registration or deployment.

0. Preconditions. {tool_ref("fmc_status")} (FMC reachable, API user). {tool_ref("fmc_license_status")}:
   FMC must be registered with Smart Licensing or be in evaluation mode, otherwise registration fails
   ("license" errors). {tool_ref("fmc_list_devices")}: if {dev} is already registered, stop and ask
   the user whether to delete and re-register it. To re-register: {tool_ref("fmc_delete_device")},
   wait 1-2 minutes until the FTD's `show managers` no longer says "in the process of
   Unregistration", then run `configure manager add <fmc-ip> <reg-key>` on the FTD again.
   Check {acp} exists ({tool_ref("fmc_list_policies")} kind='access').

{build}

2. Register: {tool_ref("fmc_register_device")} with name={dev}, host={host_q}, access_policy={acp},
   wait=true; leave out reg_key when the server has FMC_FTD_REG_KEY (the preview says where the key
   comes from), otherwise ask the user for the registration key. This waits for the registration task
   and FMC's initial deployment (5-10 minutes). Then {tool_ref("fmc_get_device")} name={dev}: it must be
   connected, with its model and version. A failure saying the device is unreachable or the key is wrong
   means the FTD's `configure manager add` does not match: fix it (step 1) and retry.
{template_step}
3. Interfaces and zones: {tool_ref("fmc_list_device_interfaces")} device={dev} (FTDv names them
   Ethernet0/0, Ethernet0/1, ...). Create zones if they don't exist
   ({tool_ref("fmc_list_objects")} type='security_zone', {tool_ref("fmc_create_security_zone")};
   e.g. <name>-outside and <name>-inside, interface_mode='ROUTED').
   Then {tool_ref("fmc_update_interface")} device={dev}:
   - interface={out_if}, logical_name='outside', enabled=true, security_zone=<outside zone>, ipv4={out_ip};
   - interface={in_if}, logical_name='inside', enabled=true, security_zone=<inside zone>, ipv4={in_ip}.

4. Routing and NAT: {tool_ref("fmc_create_static_route")} device={dev}, interface='outside',
   networks=['any-ipv4'], gateway={gw}. {nat_step}

5. Policies: {acp} was assigned at registration; make sure it allows the traffic you will test (its
   rules reference zones, so add the new zones to an allow rule with {tool_ref("fmc_update_access_rule")}
   if needed).{ps_step}

6. Deploy: {tool_ref("fmc_pending_changes")} device={dev} (expect the interface, route, NAT and policy
   changes), then {tool_ref("fmc_deploy")} devices=[{dev}] with wait=true. Check
   {tool_ref("fmc_list_deployments")} device={dev}: the job must have succeeded.

7. Verify:
   - {tool_ref("fmc_run_show_command")} device={dev}, command='show interface ip brief' (both data
     interfaces up with their addresses) and 'show route' (default route via {gw});
   - {tool_ref("fmc_packet_tracer")} device={dev}, input_interface='inside', protocol='icmp',
     source_ip=<an inside host address>, destination_ip={dest}: expect allow with the NAT translation
     (a drop with no-v4-adjacency right after the deploy only means the FTD has no ARP entry for the
     next hop yet: send real traffic first, then trace again);
   - with a CML lab, real traffic first: {tool_ref("cml_run_commands")} on an inside host,
     'ping -c 3 {json.loads(dest)}'.

8. Report: device, version, interfaces and zones, route, NAT, assigned policies, deployment result
   and the verification evidence. Mention that re-registration needs `configure manager add` on the
   FTD after a delete (step 0).
"""


def _health_review_text(domain: str | None, device: str | None, lookback_hours: int) -> str:
    """The fmc_firewall_health_review instructions."""
    if not 1 <= lookback_hours <= 720:
        raise InvalidRequest(f"lookback_hours must be 1-720, not {lookback_hours}.")
    dom = _q(domain, "domain") if domain else None
    dev = _q(device, "device") if device else None
    d = f", domain={dom}" if dom else ""  # after a tool's other arguments
    wd = f" with domain={dom}" if dom else ""  # a tool's only argument
    minutes = lookback_hours * 60
    if dev:
        scope = f"the devices whose name contains {dev}" + (f" in domain {dom}" if dom else "")
        inventory = f"{tool_ref('fmc_list_devices')} with name={dev}{d}"
        keep = " Keep only the rows of the devices from step 1 (and, for alerts, the FMC's own)."
    else:
        scope = f"every device in domain {dom}" if dom else "every managed device"
        inventory = f"{tool_ref('fmc_list_devices')}{wd}"
        keep = ""
    return f"""Review the health of {scope} and of the FMC itself over the last
{lookback_hours} hours, and write one ranked report with next steps. Every step is read-only:
change, deploy or back up nothing; the report only proposes next steps.

FMC allows about 120 API requests per minute, and each tool call costs one or more. Call each
aggregate tool below once and drill into single devices only where a finding needs it: at most
10 per-device calls in all; report any further devices from the aggregate rows. A tool that
fails or times out is a finding of its own (a warning when it hides a whole check, else info):
note it and carry on.

1. Devices and connectivity: {inventory}. Note each device's health, connected, deployment
   status, version and access policy. A disconnected device is critical. For each device that is
   not green or not connected, {tool_ref("fmc_device_health")} with device=<name>{d}: the failing
   modules, their details and since when, and CPU/memory (above 90 % is a warning). A RED module
   is critical and a YELLOW one a warning, except an INTERFACE module saying an interface "is not
   receiving any packets": a warning on an idle link (a lab, an unused port), critical on one that
   should carry traffic. Say which you assumed.

2. HA and clusters: {tool_ref("fmc_list_ha_pairs")}{wd} and {tool_ref("fmc_list_clusters")}{wd}. For
   each HA pair with a unit in scope, {tool_ref("fmc_get_ha_status")} with ha_pair=<name>{d}. One
   Active and one Standby unit is healthy; no active unit, two active units, or a failed or
   unknown standby is critical. Only the management interface monitored is info. A cluster with a
   missing or disabled data node is critical.

3. Deployments: {tool_ref("fmc_list_deployable_devices")}{wd}.{keep} A device with pending changes
   is a warning (it doesn't run what FMC holds). For up to three of them,
   {tool_ref("fmc_pending_changes")} with device=<name>{d} says what is waiting and who changed it
   (a 'System' UPDATE with "Data not available" is FMC housekeeping: info).
   Then {tool_ref("fmc_list_deployments")} with since_hours={lookback_hours}{d}.{keep} A FAILED
   job is critical while the device has had no successful deployment since; info once a later
   job succeeded.

4. Licences: {tool_ref("fmc_license_status")}. UNREGISTERED, an authStatus other than AUTHORIZED
   (OUT_OF_COMPLIANCE, AUTHORIZATION_EXPIRED) or regStatus EVALUATION with evalExpiresInDays 0 is
   critical; evalUsed alone on a registered FMC is not. Any other EVALUATION is a warning: give
   evalExpiresInDays and the virtualAccount, and point at
   System > Licenses > Smart Licenses in the FMC UI. Device licences are
   listed by device UUID: match them to the names from step 1. A device in scope without a
   licence entry is a warning.

5. Software and content: {tool_ref("fmc_upgrade_status")} with response_format="json"{d}. Devices on
   different versions, above all within one HA pair or cluster, are a warning; so is a device in
   maintenance mode. The VDB, SRU and LSP versions carry dates: content older than 30 days is a
   warning (updates are failing or not scheduled). Upgrade packages FMC already holds are info.

6. Backups: {tool_ref("fmc_list_backups")}{wd}. No FMC backup, or none in the last 7 days, is a
   warning; the same for each device in scope. Give the newest date per device.

7. VPN: {tool_ref("fmc_list_vpn_tunnels")}{wd}.{keep} TUNNEL_DOWN is critical and UNKNOWN a
   warning; no tunnels at all is info.

8. Health alerts: {tool_ref("fmc_list_health_alerts")} with since_minutes={minutes}{d}.{keep}
   Repeats are collapsed with first/last seen and a count. An alert last seen in the last hour is
   current and counts at its level; older ones are history (info, unless the same alert keeps
   coming back). Note what the FMC reports about itself (Security Intelligence and Talos feeds,
   NTP, its own interfaces, processes restarting). APPLIANCE_HEARTBEAT means a device lost contact
   with FMC (critical while current). Only for a critical finding where you need to know what
   changed just before it: {tool_ref("fmc_recent_activity")} with since_minutes={minutes},
   device=<name>{d} (audit records and deployments around it).

9. Report: one list, critical first, then warning, then info; within a level, what affects
   traffic (devices, HA, VPN) comes before what affects management (licences, content, backups).
   Merge findings with one cause (a red device and its INTERFACE alerts). Each finding gives:
   - its level and a one-line title naming the device or the FMC;
   - evidence: the tool and the values it returned (status, module, count, dates);
   - the next step: a concrete action and the tool call to make, e.g.
     {tool_ref("fmc_device_health")} with include_green=true, {tool_ref("fmc_run_show_command")} with
     'show interface' or 'show failover', {tool_ref("fmc_pending_changes")} then
     {tool_ref("fmc_deploy")}, {tool_ref("fmc_backup_devices")}, or an FMC UI step where no tool
     covers it.
   End with one line: counts per level, the devices reviewed and the checks that could not run.
   Mark which next steps change anything (deploys, backups): those are preview-first and run only
   after the user approves.
"""


def _rule_change_review_text(
    policy: str,
    rule: str,
    source: str | None,
    destination: str | None,
    protocol: str,
    port: int | None,
) -> str:
    """The fmc_rule_change_review instructions."""
    pol = _q(policy, "policy")
    rul = _q(rule, "rule")
    flows: list[str] = []
    if bool(source) != bool(destination):
        raise InvalidRequest("A sample flow needs both source and destination (or neither).")
    if source and destination:
        for value, what in ((source, "source"), (destination, "destination")):
            try:
                ipaddress.ip_address(value.strip())
            except ValueError:
                raise InvalidRequest(f"{what} {value!r} is not an IP address.") from None
        flow = f"source={_q(source, 'source')}, destination={_q(destination, 'destination')}"
        flow += f", protocol={_q(protocol, 'protocol')}"
        if port and protocol != "icmp":
            flow += f", port={port}"
        flows.append(f"the user's flow ({flow})")
    sample = (
        f"{flows[0]}, plus " if flows else ""
    ) + "one flow the rule is meant to match and one just outside it (a neighbouring address or port)"
    return f"""Review a proposed change to access rule {rul} in access control policy {pol} before it
is made and before it is deployed. Nothing changes until the user approves a preview; deploying is a
separate approval.

1. Baseline: {tool_ref("fmc_get_access_rule")} with policy={pol}, rule={rul} (it may not exist yet:
   then this is a new rule) and {tool_ref("fmc_export_policy_bundle")} with policy={pol}. Keep the
   bundle text: it is the rollback point. Ask the user for the change if it isn't clear: action,
   zones, networks, ports, applications, users, logging, intrusion policy, and position.

2. Before: {tool_ref("fmc_rule_lookup")} with policy={pol} for {sample}. Record the matching rule and
   verdict of each. Then {tool_ref("fmc_policy_audit")} with policy={pol},
   checks=["shadowed", "permissive", "no_intrusion", "no_logging", "consolidation"] as the baseline
   findings.

3. Preview the change without confirm: {tool_ref("fmc_update_access_rule")} for an existing rule or
   {tool_ref("fmc_create_access_rule")} for a new one, with exactly the user's values. Show the
   preview (it lists what a PUT removes). Before asking for approval, reason over the policy:
   - Would an earlier rule already take all of this rule's traffic (the new rule would be shadowed)?
   - Would this rule take traffic that a later rule handles today (it shadows others)? Name them.
   - Is it wider than asked (any source, any port, an ALLOW without an intrusion policy or logging)?

4. Only after the user approves: call the same tool again with the confirm token. Then repeat step 2
   with the same flows and compare: each flow's verdict should change only where the change intends;
   new shadowed, redundant or permissive findings are regressions. If one appears, say so and
   propose the fix (move_to, a narrower condition) as another preview.

5. What a deploy would push: {tool_ref("fmc_list_policy_assignments")} with policy={pol} for the devices, and
   {tool_ref("fmc_pending_changes")} for each (at most three). Pending changes that aren't this one
   are a finding: someone else's work would go out too.

6. Deploy plan (don't deploy unless the user asks): {tool_ref("fmc_deploy")} previewed for those
   devices, then verification with {tool_ref("fmc_packet_tracer")} for the in-rule flow and
   {tool_ref("fmc_get_hit_counts")} on the rule. Rollback: {tool_ref("fmc_rollback_deployment")} for
   the device, or {tool_ref("fmc_diff_policy_bundle")} with a=<baseline bundle> to see exactly what
   to undo, and {tool_ref("fmc_import_policy_bundle")} with the baseline to restore it.

7. Report: the change as applied (or still only previewed), the flows before and after, audit
   findings added or removed, pending changes per device, and the deploy and rollback steps.
"""


def _policy_cleanup_text(policy: str, unused_days: int) -> str:
    """The fmc_policy_cleanup instructions."""
    if not 1 <= unused_days <= 3650:
        raise InvalidRequest(f"unused_days must be 1-3650, not {unused_days}.")
    pol = _q(policy, "policy")
    return f"""Clean up access control policy {pol}: turn its audit findings into a reviewed, grouped
cleanup that is applied change by change with the user's approval. Nothing changes until the user
approves a preview; deploying is a separate approval.

1. Baseline: {tool_ref("fmc_export_policy_bundle")} with policy={pol}. Keep the bundle text: it is
   the rollback point and the reference for the final diff.

2. Findings: {tool_ref("fmc_policy_audit")} with policy={pol}, unused_days={unused_days}. Each finding
   carries a proposed fix as a tool call.

3. Group the findings into a cleanup plan and show it before changing anything:
   a. Redundant rules (same action as the rule covering them): delete.
   b. Disabled rules: delete, unless the user keeps them for a reason.
   c. Rules with no hits in {unused_days} days: disable for one review cycle rather than delete
      (enabled=false); ask about rare traffic (backups, DR, quarterly jobs) first.
   d. Shadowed rules (a different action covers them): never automatic. Ask the owner whether the
      rule's action was intended (then move it above the covering rule) or is obsolete (delete).
   e. Rules on expired time ranges: delete, or extend the time range in the FMC UI.
   f. ALLOW rules without an intrusion policy, rules that log nothing, any-any rules: propose the
      change per rule; these change inspection and traffic, so the user decides each.
   g. Merge candidates and duplicate objects: optional tidy-ups; for duplicates use
      {tool_ref("fmc_where_used")} on each object before repointing and
      {tool_ref("fmc_delete_object")}.
   For each group give the rules or objects, the change and its risk. Ask which groups to apply.

4. Change management: {tool_ref("fmc_change_tickets")}. If FMC requires tickets, open one with
   {tool_ref("fmc_ticket")} (action="open") before the first change and say so.

5. Apply the approved groups one change at a time with the finding's tool
   ({tool_ref("fmc_delete_access_rule")}, {tool_ref("fmc_update_access_rule")},
   {tool_ref("fmc_delete_object")}, ...): preview, show it, and confirm only what the user approved
   (one approval may cover a whole group of identical changes; list them). Stop at the first
   failure and report what was applied.

6. Verify: {tool_ref("fmc_diff_policy_bundle")} with a=<baseline bundle> and the live policy must
   show exactly the approved changes and nothing else. Then {tool_ref("fmc_policy_audit")} again:
   the addressed findings are gone and no new ones appeared.

7. Deploy plan (don't deploy unless the user asks): {tool_ref("fmc_pending_changes")} for the devices
   from {tool_ref("fmc_list_policy_assignments")} with policy={pol}, then {tool_ref("fmc_deploy")}
   previewed. Afterwards {tool_ref("fmc_get_hit_counts")} on the remaining rules confirms traffic
   still matches where expected. Rollback: {tool_ref("fmc_import_policy_bundle")} with the baseline
   bundle re-creates deleted rules and restores changed ones (preview first), or
   {tool_ref("fmc_rollback_deployment")} on a device.

8. Report: per group what was applied, skipped (and why) or left for the owner, the audit before and
   after (counts per severity), the diff summary, and the ticket, deploy and rollback steps.
"""


def _sdwan_troubleshoot_text(
    application: str,
    branch: str,
    destination: str | None,
    source: str | None,
    topology: str | None,
) -> str:
    """fmc_sdwan_troubleshoot: path metrics -> app route -> chosen interface -> overlay -> fix."""
    app, br = _q(application, "application"), _q(branch, "branch")
    topo = _q(topology, "topology") if topology else None
    dst = _q(destination, "destination") if destination else None
    src = _q(source, "source") if source else None
    t_arg = f", topology={topo}" if topo else ""
    flow = f"traffic from {src or '<a branch inside host>'} to {dst or '<the application server>'}"
    tracer = (
        f"{tool_ref('fmc_packet_tracer')} with device={br}, protocol=<tcp or udp>, "
        f"source_ip={src or '<an inside host>'}, destination_ip={dst or '<the server>'}, "
        "destination_port=<the application port>"
    )
    return f"""{app} is slow or failing at branch {br}. Find out which WAN path it takes, whether
that path is degraded, and propose a fix. Steps 1-5 are read-only; any change in step 6 is
preview-first and runs only after the user approves it.

1. Path metrics: {tool_ref("fmc_sdwan_status")} with branch={br}{t_arg}. Note each WAN link's health,
   status, RTT, jitter, loss and MOS, the overlay tunnels (and how many are up), the iBGP neighbors and
   the `degraded` list. A link that is down, or above the loss/RTT/jitter thresholds (or below the MOS
   one) the result lists, is a suspect. If a show command was "not available" (FMC 10.0.1 refuses
   show path-monitoring, show policy-route and show bgp summary), say so: wan_links then carry the
   path-monitoring status only (health "not available"), so a brownout on a link that is still up
   can't be seen through FMC; ask the user for the device's 'show path-monitoring' from its console.
   Metrics from FMC's health monitor trail the device by a few minutes: `changed_at` says when a link's
   values last changed, `unchanged_since` that they are at least that old. A link FMC reports as
   unreachable with "metrics pending" is still degraded, but in the first ~5 minutes of a brownout FMC
   says this while the device still reaches the peer: call again before calling the path dead.

2. App route: in the same result's `app_routes`, find the rule whose `match` (an extended ACL or an
   application/network object) covers {app}. Confirm with {tool_ref("fmc_get_routing")} with
   device={br} (policy-based routes); for the ACL's entries, {tool_ref("fmc_api_call")} GET
   object/extendedaccesslists with params={{"expanded": true}} and find the ACL by name.
   No matching rule means {app} follows the routing table: check {tool_ref("fmc_run_show_command")}
   with device={br}, command='show route' for the destination (overlay BGP, ECMP or the
   default route).

3. Chosen interface: the rule's `path_now` and `why` say which egress interface carries {app} now and
   why (the configured ordering: priority, order, or lowest jitter, loss, RTT or best MOS, against the
   live metrics). Compare with step 1: a priority- or order-based rule that keeps {app} on a degraded
   link while a healthy one is listed is the likely cause. 'show policy-route' in `evidence` shows
   what the device actually applies.

4. Overlay: {tool_ref("fmc_get_vpn_topology")} with topology=<the topology from step 1> and
   {tool_ref("fmc_list_vpn_tunnels")}. A tunnel down or an iBGP neighbor not Established on the chosen
   path sends {app} to the hub over another path, or nowhere. For a down tunnel, the reasons in
   `degraded` read the IKEv2 counters: authentication failures growing between two status calls mean
   a pre-shared key mismatch, retransmits alone mean the peer doesn't answer (dead path). Use
   {tool_ref("fmc_run_show_command")} with device={br} and 'show crypto ikev2 sa', 'show crypto ikev2
   stats' or 'show route bgp' for detail (FMC's tunnel states can lag the device by minutes), and
   {tool_ref("fmc_list_health_alerts")} with since_minutes=60, device={br} for interface or tunnel
   alerts.

5. Live check: {tracer}, i.e. {flow}. The egress interface in the result must match step 3;
   a drop names the phase and rule (the {tool_ref("fmc_why_blocked")} prompt takes over for an
   access-policy drop).

6. Report and fix: give the cause with its evidence (the metric values, the rule, the interface, the
   tunnel state), then propose one change and preview it, for example:
   - order the rule's interfaces by a metric that suits {app} (jitter or MOS for voice and video,
     loss for bulk transfers) instead of priority: change the policy-based route through the
     app-routing tools when this server has them, else {tool_ref("fmc_api_call")} PUT on the device's
     routing/policybasedroutes entry (show the body; preview first);
   - when the branch has a single WAN tunnel: say so. A second tunnel on another WAN lives in the
     companion topology '<topology>-wan2' (a second hub DVTI on that WAN): add the branch there with
     {tool_ref("fmc_update_sdwan_topology")} (add_spokes, its backup WAN) when the companion exists,
     else rebuild with {tool_ref("fmc_create_sdwan_topology")}(hub_backup_wan_interface=...,
     backup_wan_pool=...);
   - when the carrier link itself is bad, say so: no FMC change fixes it.
   Then {tool_ref("fmc_pending_changes")} with device={br} and, after approval, {tool_ref("fmc_deploy")}
   (the branch, and the hubs when the topology changed). Re-run {tool_ref("fmc_sdwan_status")} with
   branch={br} afterwards to show the new path.
"""


def register(reg: ToolRegistrar) -> None:
    @reg.prompt(
        title="Why is this traffic blocked?",
        example={
            "source": "10.99.1.10",
            "destination": "198.18.134.76",
            "protocol": "tcp",
            "port": "23",
            "device": "mcp-ftd1",
            "ingress_interface": "inside",
            "policy": "mcp-test-ftd-acp",
        },
    )
    def fmc_why_blocked(
        source: Annotated[str, Field(description="Source IP address of the flow, e.g. 10.99.1.10")],
        destination: Annotated[str, Field(description="Destination IP address, e.g. 198.18.134.76")],
        protocol: Annotated[Literal["tcp", "udp", "icmp"], Field(description="tcp, udp or icmp")] = "tcp",
        port: Annotated[
            int | None,
            Field(ge=1, le=65535, description="Destination port for tcp/udp; omit for icmp or any port"),
        ] = None,
        device: Annotated[
            str | None, Field(description="FTD device name or UUID; found from the source if omitted")
        ] = None,
        ingress_interface: Annotated[
            str | None,
            Field(
                description="Ingress interface logical name (e.g. inside); found from the source if omitted"
            ),
        ] = None,
        policy: Annotated[
            str | None,
            Field(description="Access control policy name; the device's assigned policy if omitted"),
        ] = None,
    ) -> str:
        """Why is this traffic blocked? Walks one flow (source, destination, protocol and port) through
        an FTD: the offline rule match, a live packet-tracer verdict and drop reason, hit counts on the
        matching rule, pending changes and recent deployments, and who changed the rule. Ends with the
        cause and a preview-first fix proposal."""
        return _why_blocked_text(source, destination, protocol, port, device, ingress_interface, policy)

    @reg.prompt(
        title="Onboard an FTD",
        uses=["fmc", "cml"],
        tier=Tier.DANGEROUS,
        example={
            "name": "mcp-ftd2",
            "access_policy": "mcp-test-ha-acp",
            "outside_ip": "198.18.128.163/18",
            "gateway": "198.18.128.1",
            "inside_ip": "10.99.2.1/24",
            "host": "198.18.128.161",
            "test_destination": "198.18.128.1",
            "recipe": "ftd-fmc",
            "outside_interface": "Ethernet0/0",
            "inside_interface": "Ethernet0/1",
            "nat_policy": "mcp-test-ha-nat",
            "platform_settings": "mcp-test-ps",
            "template": "mcp-sdwan-spoke-tmpl",
        },
    )
    def fmc_onboard_ftd(
        name: Annotated[str, Field(description="Display name for the FTD in FMC, e.g. mcp-ftd2")],
        access_policy: Annotated[str, Field(description="Access control policy to assign at registration")],
        outside_ip: Annotated[str, Field(description="Outside interface address, e.g. 198.18.128.163/18")],
        gateway: Annotated[str, Field(description="Default gateway on the outside, e.g. 198.18.128.1")],
        inside_ip: Annotated[str, Field(description="Inside interface address, e.g. 10.99.2.1/24")],
        host: Annotated[
            str | None, Field(description="FTD management IP (omit when building from a CML recipe)")
        ] = None,
        recipe: Annotated[
            str | None, Field(description="CML recipe to build the FTD from first, e.g. ftd-fmc")
        ] = None,
        outside_interface: Annotated[str, Field(description="Outside physical interface")] = "Ethernet0/0",
        inside_interface: Annotated[str, Field(description="Inside physical interface")] = "Ethernet0/1",
        nat_policy: Annotated[
            str | None, Field(description="Existing NAT policy to assign; omit to create <name>-nat with PAT")
        ] = None,
        platform_settings: Annotated[
            str | None, Field(description="Platform settings policy to assign (optional)")
        ] = None,
        test_destination: Annotated[
            str | None, Field(description="Address to test from the inside (default: the gateway)")
        ] = None,
        template: Annotated[
            str | None,
            Field(
                description="Device template to apply after registration (fmc_list_device_templates), "
                "e.g. an SD-WAN spoke template"
            ),
        ] = None,
    ) -> str:
        """Onboard an FTD end to end: optionally build it in CML from a recipe, check licensing,
        register it with FMC, set outside/inside interfaces and zones, default route and NAT, assign
        policies, deploy, and verify with show commands, packet tracer and real traffic. With
        `template`, a device template sets the interfaces, routing, policies and SD-WAN/VPN membership
        in one call (fmc_apply_device_template). Explains the `configure manager add` step for
        re-registration."""
        return _onboard_text(
            name,
            host,
            recipe,
            access_policy,
            outside_interface,
            outside_ip,
            gateway,
            inside_interface,
            inside_ip,
            nat_policy,
            platform_settings,
            test_destination,
            template,
        )

    @reg.prompt(
        title="Firewall health review",
        example={"domain": "Global", "device": "mcp-ftd", "lookback_hours": "24"},
    )
    def fmc_firewall_health_review(
        domain: Annotated[
            str | None, Field(description="FMC domain name or UUID; the server's default domain if omitted")
        ] = None,
        device: Annotated[
            str | None,
            Field(description="Only devices whose name contains this (case-insensitive); all if omitted"),
        ] = None,
        lookback_hours: Annotated[
            int, Field(ge=1, le=720, description="How far back to read health alerts and deployments")
        ] = 24,
    ) -> str:
        """Is the firewall estate healthy? Reviews device health and connectivity, HA pairs and
        clusters, the deployment backlog and failed deployments, licences, software and VDB/SRU/LSP
        content age, backups, VPN tunnels and recent health alerts with the aggregate tools, and
        writes one ranked report (critical, warning, info), each finding with its evidence and a
        concrete next step. Read-only."""
        return _health_review_text(domain, device, lookback_hours)

    @reg.prompt(
        title="Review a rule change",
        tier=Tier.WRITE,
        example={
            "policy": "mcp-test-acp",
            "rule": "mcp-test-allow-web",
            "source": "192.0.2.10",
            "destination": "10.10.10.80",
            "protocol": "tcp",
            "port": "443",
        },
    )
    def fmc_rule_change_review(
        policy: Annotated[str, Field(description="Access control policy name or UUID")],
        rule: Annotated[str, Field(description="Rule to change, or the name of the new rule")],
        source: Annotated[str | None, Field(description="Sample flow source IP (optional)")] = None,
        destination: Annotated[str | None, Field(description="Sample flow destination IP (optional)")] = None,
        protocol: Annotated[Literal["tcp", "udp", "icmp"], Field(description="Sample flow protocol")] = "tcp",
        port: Annotated[
            int | None, Field(ge=1, le=65535, description="Sample flow destination port (tcp/udp)")
        ] = None,
    ) -> str:
        """Review an access rule change before it is made and deployed: baseline bundle, sample flows
        through fmc_rule_lookup before and after, a shadowing and overlap check, the change as a preview,
        what a deploy would push, and a deploy plan with rollback. Changes only what the user approves."""
        return _rule_change_review_text(policy, rule, source, destination, protocol, port)

    @reg.prompt(
        title="Clean up an access policy",
        tier=Tier.WRITE,
        example={"policy": "mcp-test-acp", "unused_days": "90"},
    )
    def fmc_policy_cleanup(
        policy: Annotated[str, Field(description="Access control policy name or UUID")],
        unused_days: Annotated[
            int, Field(ge=1, le=3650, description="Rules with no hits in this many days count as unused")
        ] = 90,
    ) -> str:
        """Turn fmc_policy_audit findings into an applied cleanup: baseline bundle, findings grouped into
        a plan (delete redundant and disabled rules, disable unused ones, owner decisions for shadowed
        rules, inspection and logging fixes, object tidy-ups), a change ticket when FMC needs one, each
        change previewed and confirmed, a diff against the baseline and a re-audit, then a deploy plan
        with rollback."""
        return _policy_cleanup_text(policy, unused_days)

    @reg.prompt(
        title="Troubleshoot an SD-WAN application",
        example={
            "application": "Teams",
            "branch": "mcp-sdwan-t1-spoke1",
            "destination": "52.112.0.10",
            "source": "10.111.0.10",
            "topology": "mcp-sdwan-t1",
        },
    )
    def fmc_sdwan_troubleshoot(
        application: Annotated[
            str, Field(description="The application or service that is slow, e.g. Teams or 'web to 10.1.2.3'")
        ],
        branch: Annotated[str, Field(description="The branch (spoke) FTD name")],
        destination: Annotated[
            str | None, Field(description="Application server IP, for packet tracer")
        ] = None,
        source: Annotated[str | None, Field(description="A branch inside host IP, for packet tracer")] = None,
        topology: Annotated[str | None, Field(description="SD-WAN topology name (optional)")] = None,
    ) -> str:
        """ "App X is slow at branch Y": walks the SD-WAN path from the path metrics (fmc_sdwan_status) to
        the app-route rule, the interface it picks now and why, the overlay tunnels and BGP, and a packet
        tracer check, then proposes one previewed fix. Read-only until the user approves the fix."""
        return _sdwan_troubleshoot_text(application, branch, destination, source, topology)

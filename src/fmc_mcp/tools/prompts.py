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

2. Register: {tool_ref("fmc_register_device")} with name={dev}, host={host_q}, reg_key=<the registration
   key>, access_policy={acp}, wait=true. This waits for the registration task and FMC's initial
   deployment (5-10 minutes). Then {tool_ref("fmc_get_device")} name={dev}: it must be connected, with
   its model and version. A failure saying the device is unreachable or the key is wrong means the
   FTD's `configure manager add` does not match: fix it (step 1) and retry.

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

4. Licences: {tool_ref("fmc_license_status")}. UNREGISTERED or an expired evaluation is critical.
   EVALUATION is a warning: it ends 90 days after it began, and the API doesn't give the date, so
   say so and point at System > Licenses > Smart Licenses in the FMC UI. Device licences are
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
    ) -> str:
        """Onboard an FTD end to end: optionally build it in CML from a recipe, check licensing,
        register it with FMC, set outside/inside interfaces and zones, default route and NAT, assign
        policies, deploy, and verify with show commands, packet tracer and real traffic. Explains the
        `configure manager add` step for re-registration."""
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

"""Workflow prompts (MCP prompts) that chain this server's tools for common operator questions."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import json
import re
from typing import Annotated, Literal

from pydantic import Field
from stutters_mcp_core import InvalidRequest, ToolRegistrar, tool_ref

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
    find_device = (
        f"The device is {dev}."
        if device
        else f"Find the FTD that carries this flow: {tool_ref('fmc_list_devices')}, then "
        f"{tool_ref('fmc_list_device_interfaces')} on each candidate and pick the one with an interface "
        f"subnet containing {source}."
    )
    find_iface = (
        f"The ingress interface is {iface}."
        if ingress_interface
        else f"The ingress interface is the named interface whose subnet contains {source} (from "
        f"{tool_ref('fmc_list_device_interfaces')}); if none contains it, the one the route to {source} "
        "points out of."
    )
    find_policy = (
        f"Use access control policy {pol}."
        if policy
        else f"Find the device's access control policy with {tool_ref('fmc_list_policy_assignments')} "
        f"(device={dev})."
    )
    return f"""Explain why this traffic is blocked (or confirm it is allowed): {flow}.
Work through the steps in order, keep notes of what each step shows, and stop early only when a step
gives a definite answer that the later steps cannot change. All steps before step 7 are read-only.

0. Context. {find_device} {find_iface} {find_policy}

1. Offline policy walk: {tool_ref("fmc_rule_lookup")} with policy={pol}, source={src},
   destination={dst}, protocol="{proto}"{port_arg}, source_zone=<the ingress interface's
   zone> and destination_zone=<the zone of the interface the route to {destination} leaves by> (both
   from {tool_ref("fmc_list_device_interfaces")}; {tool_ref("fmc_list_routes")} for the egress). Without
   the zones, rules with zone conditions show up only under `may_match_first`. Note the first definite
   match, any earlier 'conditional' rules (application, URL or user conditions) and the default
   action. This is what FMC's configuration says.

2. Live verdict: {tool_ref("fmc_packet_tracer")} with device={dev}, input_interface={iface},
   protocol="{proto}", source_ip={src}, destination_ip={dst}{tracer_port}.
   Read `action`, `drop_reason`, the phase that dropped it and `matched_rules`:
   - acl-drop with a matched rule: the access (or prefilter) rule named there blocks it;
   - no-v4-adjacency / no-adjacency: the policy allows it but the FTD has no ARP entry for the
     next hop. This is not a policy problem; check the next hop is up (route, ARP, cabling);
   - no-route / route lookup failure: a routing problem, see {tool_ref("fmc_list_routes")};
   - a NAT phase drop or an unexpected translation: see the NAT policy;
   - allow: the device would pass it. Then the problem is elsewhere (return path, another device, the
     host itself) or the test doesn't match the real flow (ports, interface).
   If packet tracer and the offline walk disagree, the device runs a different configuration than
   FMC holds: go to step 4.

3. Is the rule actually hit? {tool_ref("fmc_get_hit_counts")} with policy={pol}, device={dev} and
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
   - block it: an access rule with action BLOCK above the rule that allows it.
   Show the preview and wait for the user's approval before confirming. Access rule changes reach
   the device only after {tool_ref("fmc_deploy")}; check {tool_ref("fmc_pending_changes")} first, deploy
   (preview-first too), then rerun {tool_ref("fmc_packet_tracer")} to prove the fix.
"""


def register(reg: ToolRegistrar) -> None:
    @reg.prompt(title="Why is this traffic blocked?")
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

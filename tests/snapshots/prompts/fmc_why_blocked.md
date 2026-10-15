# fmc_why_blocked

title: Why is this traffic blocked?
arguments: {"destination": "198.18.134.76", "device": "mcp-ftd1", "ingress_interface": "inside", "policy": "mcp-test-ftd-acp", "port": "23", "protocol": "tcp", "source": "10.99.1.10"}

Why is this traffic blocked? Walks one flow (source, destination, protocol and port) through
an FTD: the offline rule match, a live packet-tracer verdict and drop reason, hit counts on the
matching rule, pending changes and recent deployments, and who changed the rule. Ends with the
cause and a preview-first fix proposal.

## user

Explain why this traffic is blocked (or confirm it is allowed): tcp 10.99.1.10 -> 198.18.134.76 port 23.
Work through the steps in order, keep notes of what each step shows, and stop early only when a step
gives a definite answer that the later steps cannot change. All steps before step 7 are read-only.

0. Context. The device is "mcp-ftd1". The ingress interface is "inside". Use access control policy "mcp-test-ftd-acp".

1. Offline policy walk: `fmc_rule_lookup` with policy="mcp-test-ftd-acp", source="10.99.1.10",
   destination="198.18.134.76", protocol="tcp", port=23, source_zone=<the ingress interface's
   zone> and destination_zone=<the zone of the interface the route to 198.18.134.76 leaves by> (both
   from `fmc_list_device_interfaces`; `fmc_list_routes` for the egress). Without
   the zones, rules with zone conditions show up only under `may_match_first`. Note the first definite
   match, any earlier 'conditional' rules (application, URL or user conditions) and the default
   action. This is what FMC's configuration says.

2. Live verdict: `fmc_packet_tracer` with device="mcp-ftd1", input_interface="inside",
   protocol="tcp", source_ip="10.99.1.10", destination_ip="198.18.134.76", destination_port=23.
   Read `action`, `drop_reason`, the phase that dropped it and `matched_rules`:
   - acl-drop with a matched rule: the access (or prefilter) rule named there blocks it;
   - no-v4-adjacency / no-adjacency: the policy allows it but the FTD has no ARP entry for the
     next hop. This is not a policy problem; check the next hop is up (route, ARP, cabling);
   - no-route / route lookup failure: a routing problem, see `fmc_list_routes`;
   - a NAT phase drop or an unexpected translation: see the NAT policy;
   - allow: the device would pass it. Then the problem is elsewhere (return path, another device, the
     host itself) or the test doesn't match the real flow (ports, interface).
   A drop "snort-blacklist" means an earlier flow with the same 5-tuple was blocked and is still
   cached; repeat with another source_port to see what a new connection gets.
   If packet tracer and the offline walk disagree, the device runs a different configuration than
   FMC holds: go to step 4.

3. Is the rule actually hit? `fmc_get_hit_counts` with policy="mcp-test-ftd-acp", device="mcp-ftd1" and
   rule=<the matched rule name>. A rule with zero hits while users report blocks means real traffic
   takes another path or matches a different rule. Note the device rule id; it matches packet
   tracer's rule id.

4. Was the configuration deployed? `fmc_pending_changes` for device="mcp-ftd1" shows edits not
   yet on the device (a 'System' UPDATE with "Data not available" is FMC housekeeping after a
   reboot or upgrade, not an edit); `fmc_list_deployments` with device="mcp-ftd1" and
   since_hours=24 shows recent deployments and whether they succeeded.

5. Who changed it? `fmc_list_audit_records` with since_minutes=1440 and text=<the matched
   rule name or the policy name> lists recent edits, by whom and when.

6. Report: the verdict (blocked or allowed), the exact cause (rule name and position, default
   action, ARP/route or NAT problem), the evidence from each step, and whether the device matches FMC.

7. Fix proposal (only if the user wants it changed), always preview-first:
   - allow it: `fmc_create_access_rule` (an ALLOW rule placed above the blocking one with
     insert_before) or `fmc_update_access_rule` on the blocking rule;
   - block it: an access rule with action BLOCK above the rule that allows it, or for single hosts
     map them into a dynamic object that a BLOCK rule already references with
     `fmc_map_dynamic_object` (no deployment needed; see `fmc_list_dynamic_objects`).
   Show the preview and wait for the user's approval before confirming. Access rule changes reach
   the device only after `fmc_deploy`; check `fmc_pending_changes` first, deploy
   (preview-first too), then rerun `fmc_packet_tracer` to prove the fix.

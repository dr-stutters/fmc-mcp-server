# fmc_ha_failover_check

title: HA failover check
arguments: {"action": "switch", "destination": "198.51.100.1", "domain": "Global/mcp-test-leaf", "ha_pair": "mcp-fw-ha", "lab": "mcp-fw-ha", "port": "1", "protocol": "icmp", "source": "192.0.2.10", "target": "198.51.100.1", "test_node": "inside-host"}

Does this HA pair fail over cleanly? Pre-checks with fmc_get_ha_status (standby ready,
failover and state links up, monitored interfaces, config in sync, versions, replication
errors), a traffic baseline (packet tracer, and real pings from a CML host), then a planned
switch (fmc_ha_action) or, in a lab, the active unit powered off, with a ping series for the
loss; then the roles, the failover history and its reason, and the traffic again, and a
report with the outage. The change runs only after the user approves its preview.

## user

Check that FTD HA pair "mcp-fw-ha" in domain "Global/mcp-test-leaf" fails over cleanly: pre-checks, a traffic baseline,
a planned switch of the active unit, verification, the traffic afterwards and a report. Steps 1-3 are read-only; step 4 changes the pair and runs only after the user approves its preview.

`fmc_get_ha_status` runs a few show commands on the units each time (FMC allows about 120
API requests per minute): call it once per step, and when you wait for a state, at most 5 times.

1. Pre-checks: `fmc_get_ha_status` with ha_pair="mcp-fw-ha", live=true, history=5, domain="Global/mcp-test-leaf". Note per
   unit the device, role, FMC state and device_state (the unit's own: Active, Standby Ready, Failed,
   ...), active time, interface and module status and last_failure; the failover and state links
   (interface, status, separate or shared), monitored_interfaces, config_status, versions,
   stateful_replication (TCP/UDP connections replicated, errors), last_failover (when, which unit,
   why) and every entry of `checks`. FMC's unit states trail a failover by up to a minute; the
   device_state is current.
   - `ready_for_switch` false: don't go past step 3; report each failed blocker with its fix:
     a monitored interface Failed or No Link: cabling or the switch port on that unit
     (`fmc_run_show_command` with device=<unit>, command='show interface ip brief');
     standby not Standby Ready: it is still syncing (Cold Standby, Bulk Sync), call again, or it is
     Failed (its interfaces, snort, disk); failover link down: the link between the units;
     config_status not HEALTHY_CONFIG: `fmc_pending_changes` and `fmc_deploy`
     for the pair; versions differ: finish the upgrade (`fmc_upgrade_status`); a module
     (snort, disk) not up: `fmc_device_health` for that unit.
   - Warnings don't stop it, but say what a failover will cost: a state link that is down or
     unconfigured, or replication errors, means connections drop; a data interface that is not
     monitored or has no standby IP means its failure wouldn't trigger a failover
     (`fmc_configure_ha_monitoring`); state replication over the failover link is fine
     for a lab, a separate state link is better under load (set when the pair is formed:
     `fmc_create_ha_pair` with state_interface).

2. Traffic before. Run each of these and keep the results as the baseline:
   - `fmc_packet_tracer` with device=<the active unit>, protocol="icmp", source_ip="192.0.2.10", destination_ip="198.51.100.1", domain="Global/mcp-test-leaf": the verdict (expect allow), the ingress and egress interfaces and the matched rule
   - `cml_check_reachability` with lab="mcp-fw-ha", nodes=["inside-host"], targets=["198.51.100.1"], count=10: success percent and average RTT of real packets through the pair

3. Failover history before: each unit's `history` from step 1 (newest first) and last_failover.
   The full table: `fmc_run_show_command` with device=<unit>, command='show failover
   history', domain="Global/mcp-test-leaf". Keep the newest entry per unit so the report can show what the event added.

4. Switch: dangerous, preview-first.
   First, so the loss can be measured, start a ping series on the test host that runs through the
   event (a Linux host; 600 probes at 5 per second, about 2 minutes): `cml_configure_node`
   with lab="mcp-fw-ha", node="inside-host", mode="exec",
   lines=["nohup ping -i 0.2 -c 600 198.51.100.1 > /tmp/ha-failover-ping.log 2>&1 &"] (preview-first: show it
   and confirm after approval). Optional: a long-lived TCP flow from the same host, e.g.
   "nohup iperf -c <a server beyond the pair> -t 300 -i 1 > /tmp/ha-failover-iperf.log 2>&1 &" when
   an iperf server exists: its per-second throughput drops for the outage and recovers on the same
   connection when the connection's state was replicated; the client reports a reset when it wasn't.
   Then, within a minute:
   `fmc_ha_action` with ha_pair="mcp-fw-ha", action="switch",
   wait=true, domain="Global/mcp-test-leaf". Show the preview (both units, their FMC states, the effect) and confirm only after
   the user approves. Note when you confirm and when the task finishes: that is how long FMC took,
   not the outage.

5. Verify: `fmc_get_ha_status` again (live=true, history=5, domain="Global/mcp-test-leaf").
   After the switch the former standby is Active and the other unit is
   Standby Ready; it passes through Cold Standby, Sync Config and Bulk Sync first, and until then
   `standby_ready` fails: call again, at most 5 times.
   last_failover must be new: the unit that took over, when, and why (a planned switch reads like
   "Set by the config command" or "Other unit wants me Active"; an unplanned one like "HELLO not heard
   from mate", "Interface check" or "Failover state check"). Every other blocker check passes.

6. Traffic after: repeat step 2 with device=<the unit that is active now>. Then the loss during the event: `cml_configure_node` with lab="mcp-fw-ha",
   node="inside-host", mode="exec", lines=["tail -n 3 /tmp/ha-failover-ping.log"] (after the series has
   ended): packets transmitted vs received; at 0.2 s per probe, lost probes x 0.2 s estimates the
   outage. The iperf log, if started, shows whether the long-lived connection survived. Compare
   stateful_replication with step 1: its TCP and UDP conn counters grow as connections are
   replicated to the standby.

7. Report: per unit, role, device_state before and after and active time; the failover and state
   links; each check before and after; when the switch happened and how long until a unit was
   Standby Ready again; the traffic before and after, with the loss and the outage estimate, and
   whether long-lived connections survived; the history entries the event added (time, from, to,
   reason); anything that failed, with its next step. Mark what you could not measure (no test host,
   a command FMC refused) as not measured instead of guessing.

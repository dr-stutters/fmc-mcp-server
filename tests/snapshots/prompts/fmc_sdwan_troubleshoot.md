# fmc_sdwan_troubleshoot

title: Troubleshoot an FTD SD-WAN application (deprecated name)
arguments: {"application": "Teams", "branch": "mcp-sdwan-t1-spoke1", "destination": "52.112.0.10", "source": "10.111.0.10", "topology": "mcp-sdwan-t1"}

Deprecated: use fmc_ftdsdwan_troubleshoot (fmc_sdwan_troubleshoot was renamed in 0.20.0 and goes in 0.21.0). The same workflow as fmc_ftdsdwan_troubleshoot.

## user

(renamed_to: fmc_ftdsdwan_troubleshoot. Deprecated: use fmc_ftdsdwan_troubleshoot (fmc_sdwan_troubleshoot was renamed in 0.20.0 and goes in 0.21.0).)

"Teams" is slow or failing at FTD SD-WAN branch "mcp-sdwan-t1-spoke1". Find out which WAN path it takes, whether
that path is degraded, and propose a fix. Steps 1-5 are read-only; any change in step 6 is
preview-first and runs only after the user approves it.

1. Path metrics: `fmc_ftdsdwan_status` with branch="mcp-sdwan-t1-spoke1", topology="mcp-sdwan-t1". Note each WAN link's health,
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
   application/network object) covers "Teams". Confirm with `fmc_get_routing` with
   device="mcp-sdwan-t1-spoke1" (policy-based routes); for the ACL's entries, `fmc_api_call` GET
   object/extendedaccesslists with params={"expanded": true} and find the ACL by name.
   No matching rule means "Teams" follows the routing table: check `fmc_run_show_command`
   with device="mcp-sdwan-t1-spoke1", command='show route' for the destination (overlay BGP, ECMP or the
   default route).

3. Chosen interface: the rule's `path_now` and `why` say which egress interface carries "Teams" now and
   why (the configured ordering: priority, order, or lowest jitter, loss, RTT or best MOS, against the
   live metrics). Compare with step 1: a priority- or order-based rule that keeps "Teams" on a degraded
   link while a healthy one is listed is the likely cause. 'show policy-route' in `evidence` shows
   what the device actually applies.

4. Overlay: `fmc_get_vpn_topology` with topology=<the topology from step 1> and
   `fmc_list_vpn_tunnels`. A tunnel down or an iBGP neighbor not Established on the chosen
   path sends "Teams" to the hub over another path, or nowhere. For a down tunnel, the reasons in
   `degraded` read the IKEv2 counters: authentication failures growing between two status calls mean
   a pre-shared key mismatch, retransmits alone mean the peer doesn't answer (dead path); nothing
   growing within a minute or two doesn't rule out a dead path (the FTD retries IKE only every few
   minutes once DPD has removed the SA): check the path and call the status again 3-5 minutes later. Use
   `fmc_run_show_command` with device="mcp-sdwan-t1-spoke1" and 'show crypto ikev2 sa', 'show crypto ikev2
   stats' or 'show route bgp' for detail (FMC's tunnel states can lag the device by minutes), and
   `fmc_list_health_alerts` with since_minutes=60, device="mcp-sdwan-t1-spoke1" for interface or tunnel
   alerts.

5. Live check: `fmc_packet_tracer` with device="mcp-sdwan-t1-spoke1", protocol=<tcp or udp>, source_ip="10.111.0.10", destination_ip="52.112.0.10", destination_port=<the application port>, i.e. traffic from "10.111.0.10" to "52.112.0.10". The egress interface in the result must match step 3;
   a drop names the phase and rule (the `fmc_why_blocked` prompt takes over for an
   access-policy drop).

6. Report and fix: give the cause with its evidence (the metric values, the rule, the interface, the
   tunnel state), then propose one change and preview it, for example:
   - order the rule's interfaces by a metric that suits "Teams" (jitter or MOS for voice and video,
     loss for bulk transfers) instead of priority: change the policy-based route through the
     app-routing tools when this server has them, else `fmc_api_call` PUT on the device's
     routing/policybasedroutes entry (show the body; preview first);
   - when the branch has a single WAN tunnel: say so. A second tunnel on another WAN lives in the
     companion topology '<topology>-wan2' (a second hub DVTI on that WAN): add the branch there with
     `fmc_update_ftdsdwan_topology` (add_spokes, its backup WAN) when the companion exists,
     else rebuild with `fmc_create_ftdsdwan_topology`(hub_backup_wan_interface=...,
     backup_wan_pool=...);
   - when the carrier link itself is bad, say so: no FMC change fixes it.
   Then `fmc_pending_changes` with device="mcp-sdwan-t1-spoke1" and, after approval, `fmc_deploy`
   (the branch, and the hubs when the topology changed). Re-run `fmc_ftdsdwan_status` with
   branch="mcp-sdwan-t1-spoke1" afterwards to show the new path.

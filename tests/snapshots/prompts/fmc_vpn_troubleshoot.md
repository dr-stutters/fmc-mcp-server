# fmc_vpn_troubleshoot

title: Troubleshoot a site-to-site VPN
arguments: {"destination": "10.2.2.10", "device": "mcp-sdwan-t1-spoke1", "port": "1", "protocol": "icmp", "source": "10.1.1.10", "symptom": "branch-a cannot reach 10.2.2.10 over the VPN", "topology": "mcp-fw-t1"}

"The VPN to X is down" or "traffic doesn't cross the tunnel": starts from fmc_vpn_status
(tunnel state and what each device says) and walks the phases in order: IKE (key mismatch vs
dead path from the IKEv2 counters, proposals), IPsec (child SAs, one-way traffic), routing
over the tunnel (routes via the VTI or protected networks), NAT exemption and access rules
(packet tracer and rule lookup), then names the likely cause with its evidence and proposes
one previewed fix. Read-only until the user approves the fix.

## user

A site-to-site VPN problem: "branch-a cannot reach 10.2.2.10 over the VPN". Find the phase where it breaks (IKE, IPsec, routing over
the tunnel, NAT exemption or access rules), name the likely cause with its evidence, and propose one
fix. Steps 1-7 are read-only; the fix in step 8 is preview-first and runs only after the user approves
it. FMC allows about 120 API requests per minute: call each tool once per step unless a step says to
call it again.

1. Status: `fmc_vpn_status` with device="mcp-sdwan-t1-spoke1", topology="mcp-fw-t1". Find the tunnel(s) the symptom is about: their `state`, `device_says` (what each
   device's IKE and IPsec SAs say) and the `degraded` entries for them, worst first. Note the topology
   (route-based or policy-based; SD-WAN topologies are route-based), both endpoints, each end's VTI,
   the protected networks and NAT exemption. Then go to the phase the evidence points at:
   - no tunnel at all for the topology ("FMC monitors no tunnel"): not deployed. Check
     `fmc_pending_changes` for both devices and `fmc_list_deployments` with
     since_hours=24; an undeployed change is the cause.
   - FMC says TUNNEL_DOWN or UNKNOWN but a device has a READY IKE SA (or the reverse): FMC's tunnel
     monitor lags the devices by minutes. Trust `device_says`; call `fmc_vpn_status` again
     after a minute before calling the tunnel down.
   - a device that is disconnected from FMC can't be checked here: say so.
   If the symptom is about remote-access (Secure Client) users, this walk doesn't apply: report what
   `fmc_get_ravpn` shows (profiles, pools, AAA, gateways and sessions) and stop.

2. IKE (phase 1): no READY IKE SA between the two ends. Read the IKEv2 counters in the `degraded`
   reasons and call `fmc_vpn_status` with device="mcp-sdwan-t1-spoke1", topology="mcp-fw-t1" a second time (a minute later) so it can compare them:
   - Authentication Failures growing: a pre-shared key or certificate mismatch. Check
     `fmc_get_vpn_topology` (`ike`: authentication type, which policies; the key is
     masked): for an extranet peer, its key differs from FMC's; for two managed devices, one end
     wasn't deployed after the key changed (step 1's pending changes).
   - only Retransmit limit exceeded / Initial exchange failed growing: the peer doesn't answer. Check
     the path: `fmc_run_show_command` with device="mcp-sdwan-t1-spoke1" and 'show route <the peer's
     address>' (it must leave by the outside interface), 'show interface ip brief', and
     `fmc_list_health_alerts` with since_minutes=60, device="mcp-sdwan-t1-spoke1" for a down interface.
     UDP 500/4500 blocked or NATed upstream gives the same picture: say so when the path looks fine.
   - nothing grew ("no new IKEv2 failures in the last N s"): that proves little. Once DPD has removed
     the SA the FTD retries IKE only every few minutes, so a dead path is often quiet for a minute or
     two. Check the path first, as in the bullet above, and have the peer's WAN address and the WAN
     gateway pinged from the device's CLI or the WAN router (FMC's API runs only show commands): a link
     that is down beyond the FTD (a carrier, a lab link) leaves the FTD's interface up/up and its route
     in place, so neither 'show interface ip brief' nor 'show route' shows it. Call
     `fmc_vpn_status` again 3-5 minutes after the first call: it compares the counters with
     every reading of the last 15 minutes and catches the next attempt. Retransmits counted before with
     no authentication failures also point to the path.
   - SAs that stay IN-NEG, or the path answers and still no failures: compare the IKE policies (cipher,
     integrity, DH group) of both ends in `fmc_get_vpn_topology`; an extranet peer must
     offer one of them.

3. IPsec (phase 2): IKE is READY but traffic fails. In `device_says` and the devices' `ipsec_sas`:
   - no child SA: the IPsec proposals or PFS group don't match (`fmc_get_vpn_topology`
     `ipsec`), or, policy-based, the protected networks of the two ends don't mirror each other
     (local_network/remote_network of the SAs vs `protected_networks`).
   - one-way traffic (packets out but none in, or the reverse; the `tunnel traffic` findings): the
     side that sends nothing back is the problem: its routing (step 4), its NAT exemption (step 5) or
     its access rules (step 6) for the return traffic.
   - IPsec send/receive errors: MTU or anti-replay trouble on the path; note them.
   For detail: `fmc_run_show_command` with device="mcp-sdwan-t1-spoke1" and 'show crypto ipsec sa peer
   <the peer's address>'.

4. Routing over the tunnel:
   - route-based: the device's `overlay_routes` must hold a route to "10.2.2.10" via its VTI. None (the
     `overlay routing` finding) or a route out of another interface is the cause. Check
     `fmc_get_routing` with device="mcp-sdwan-t1-spoke1" (BGP or OSPF neighbors on the VTI) and
     `fmc_list_routes` with device="mcp-sdwan-t1-spoke1" (static routes via the VTI); do the same on
     <the device at the far end> for the return route. `fmc_run_show_command` with 'show route <destination>'
     shows what the device uses now.
   - policy-based: "10.2.2.10" must be inside the far end's protected networks and the route to it must
     leave by the interface the crypto map is on (usually the default route out of outside).

5. NAT exemption: traffic between the protected networks must not be translated. Check
   `fmc_list_nat_rules` with device="mcp-sdwan-t1-spoke1" (and <the device at the far end>): a manual identity rule (source and
   destination translated to themselves) for local -> remote networks must sit above any dynamic PAT
   that also matches the inside networks; for policy-based topologies the endpoint's `nat_exempt`
   (enableNATExempt with the inside zone) adds it. A PAT rule that matches first translates the
   source, so the traffic no longer matches the protected networks and never enters the tunnel.

6. Access rules and the live path: `fmc_packet_tracer` with device="mcp-sdwan-t1-spoke1", protocol="icmp", source_ip="10.1.1.10", destination_ip="10.2.2.10". Read the phases: ROUTE-LOOKUP (egress: the VTI or the
   outside interface), NAT (no translation for VPN traffic), ACCESS-LIST (the rule) and VPN
   (encrypt). A drop names the phase and rule; an ACL drop hands over to the
   `fmc_why_blocked` prompt. Confirm offline with `fmc_rule_lookup` with device="mcp-sdwan-t1-spoke1", source="10.1.1.10", destination="10.2.2.10", protocol="icmp". Route-based traffic is
   inspected by the access policy in both directions (rules need the VTI's security zone); for
   policy-based tunnels FMC can bypass the access policy for decrypted traffic:
   `fmc_api_call` GET policy/ftds2svpns/<topology id>/advancedsettings,
   advancedTunnelSetting.bypassAccessControlTrafficForDecryptedTraffic.

7. Report: the phase that breaks, the cause, and the evidence (state and `device_says`, the counter
   values and how they grew, the missing route, the NAT rule that matches first, the dropping rule).
   Say what was not checked (devices skipped, FMC's monitor lag, a far end FMC doesn't manage).

8. Fix: propose one change and preview it, for example:
   - not deployed: `fmc_deploy` both ends (after `fmc_pending_changes`);
   - key mismatch: set the same pre-shared key on both ends (an extranet peer's own config, or the
     topology's IKE settings with `fmc_api_call` PUT on
     policy/ftds2svpns/<id>/ikesettings/<id>, a raw call that needs the dangerous tier; the preview
     masks the key), then deploy;
   - missing route over the tunnel: `fmc_create_static_route` with device="mcp-sdwan-t1-spoke1",
     interface=<the VTI's logical name>, networks=<the far networks> and gateway=<the far end's VTI
     address>, or a BGP/OSPF neighbor over the VTI (`fmc_configure_bgp`);
   - missing NAT exemption: `fmc_create_nat_rule` with policy=<the device's NAT policy>,
     kind="manual", original_source=<the local networks> and no translated_source (identity),
     original_destination and translated_destination=<the remote networks>, source_interface and
     destination_interface=<the inside and outside zones>, section="before_auto";
   - access rule: `fmc_create_access_rule` allowing the flow (from or to the VTI's zone
     for route-based tunnels);
   - an upstream path or carrier problem: say so; no FMC change fixes it.
   After the user approves and the change is confirmed: `fmc_pending_changes` and
   `fmc_deploy` for the devices it touches (both ends where both changed), then run
   `fmc_vpn_status` with device="mcp-sdwan-t1-spoke1", topology="mcp-fw-t1" again and the packet tracer from step 6 to show the tunnel up and the flow passing.
   FTD SD-WAN WAN-link problems (loss, delay, the path an application takes): the
   `fmc_ftdsdwan_troubleshoot` prompt.

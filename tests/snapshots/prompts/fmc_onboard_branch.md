# fmc_onboard_branch

title: Onboard an SD-WAN branch
arguments: {"access_policy": "mcp-fw-base-acp", "domain": "Global/mcp-test-leaf", "host": "192.0.2.13", "inside_host": "10.77.14.10", "inside_interface": "Ethernet0/1", "inside_ip": "10.77.14.1/24", "name": "mcp-fw-branch1", "template": "mcp-fw-branch-tmpl", "test_destination": "10.77.0.10", "topology": "mcp-fw-t1", "variables": "{\"wanIp\": \"198.51.100.14/24\", \"insideIp\": \"10.77.14.1/24\"}", "wan_gateway": "198.51.100.1", "wan_interface": "Ethernet0/0", "wan_ip": "198.51.100.14/24"}

Onboard a branch FTD into an SD-WAN topology end to end: register it (the key comes from the
server's FMC_FTD_REG_KEY, never from the conversation), configure it from a device template when
one fits or by hand (interfaces and zones, underlay route, NAT, access policy, hub return path),
add it as a spoke with fmc_update_sdwan_topology, deploy the hubs and the branch, verify the
tunnel, the overlay routes and a policy flow (packet tracer and real traffic), and end with a
hand-off record of flows for fmc_prove_policy. Every write is previewed and approved first.

## user

Onboard the branch FTD "mcp-fw-branch1" (management "192.0.2.13") into the SD-WAN topology "mcp-fw-t1" and prove it
works: register it, configure it from a device template or by hand, add it as a spoke, deploy the hubs
and the branch, verify the tunnel, the overlay routes and a policy flow, and end with a hand-off record
for `fmc_prove_policy`.
Pass domain="Global/mcp-test-leaf" on every FMC call.
Every write is preview-first: show each preview and wait for the user's approval before confirming.
Deployments name their devices (the branch and this topology's hubs), never every deployable device.
Stop and report when a step fails; keep notes of what each step returned.

0. Preconditions (read-only).
   - `fmc_status` and `fmc_license_status`: registration needs Smart Licensing or
     evaluation mode.
   - `fmc_list_devices`: "mcp-fw-branch1" must not be registered yet. If it is, connected and in no
     topology, skip step 2; otherwise stop and ask the user.
   - `fmc_get_vpn_topology` topology="mcp-fw-t1": it must be an SD-WAN (AUTO_VPN) topology. Note
     the hubs (primary and backup) and the WAN address each hub's DVTI listens on (the branch's WAN
     must reach it), the spokes and their WAN interface names, the overlay zone and
     routing (`sdwan`: iBGP or OSPF; an OSPF overlay needs spoke_loopbacks for a new spoke) and the spoke
     tunnel pool. A companion topology '<name>-wan2' means the spokes also have a second WAN tunnel.
   - `fmc_get_device` on one existing spoke: model, version, licences, access, NAT and
     platform settings policies. The new branch should match it; "mcp-fw-branch1" gets the same access policy
     unless the user named one.
   - `fmc_sdwan_status` topology="mcp-fw-t1": the hubs must be healthy before a branch joins.

1. The FTD must point at this FMC: `show managers` on its CLI lists the FMC as pending (CML:
   `cml_run_commands` on the FTD node, 'show managers'). If it doesn't, the operator sets the
   manager on the device (day-0 or `configure manager add`) with the site's registration key. Never ask
   for the key and never put it in a tool argument.

2. Register: `fmc_register_device` with name="mcp-fw-branch1", host="192.0.2.13", access_policy="mcp-fw-base-acp",
   license_caps and performance_tier like the other spokes, wait=true, and NO reg_key: the server uses
   FMC_FTD_REG_KEY (the preview says where the key comes from). If it refuses with "No registration
   key", stop: the operator sets FMC_FTD_REG_KEY on the server. The call waits for the registration task
   and FMC's initial deployment (5-10 minutes). Then `fmc_get_device` device="mcp-fw-branch1": connected,
   with model and version. "Unreachable" or a key error means the FTD's manager setting doesn't match
   (step 1).

3. Device template, when one fits: `fmc_get_device_template` template="mcp-fw-branch-tmpl": firewall mode,
   model mapping, variables (type, default) and VPN/SD-WAN settings. It fits when its SD-WAN settings make the
   device a spoke of "mcp-fw-t1" and its model and firewall mode match "mcp-fw-branch1" (step 2).
   Apply it: `fmc_apply_device_template` template="mcp-fw-branch-tmpl", device="mcp-fw-branch1", variables={"wanIp": "198.51.100.14/24", "insideIp": "10.77.14.1/24"},
   overrides={<object>: <value>} for the branch's own objects (its inside network "10.77.14.0/24"). It is
   dangerous-tier and replaces the device's interfaces, routing, policies and VPN membership: check every
   variable in the preview against the branch's values, wait for approval, then confirm. Keep PASSWORD
   variables out of this conversation: their template default applies. Afterwards
   `fmc_pending_changes` device="mcp-fw-branch1" shows what the template set; fill only the gaps (step 4
   items it doesn't carry). If its SD-WAN settings already joined "mcp-fw-t1", step 5 only checks that.
   FMC 10.0.1 can't generate a template from an FTDv for KVM ("The version or model of the device is not
   supported") and a template made from parameters alone can't be applied (blocker B1 of the SD-WAN
   runs). When no template fits, or the preview or the apply task fails, take the manual path (step 4)
   and say why in the report.

4. Manual path (no template).
   a. Zones: the WAN interface must be in a security zone (the topology builds the spoke's VTI on it).
      Reuse the zones the other spokes' WAN and inside interfaces are in
      (`fmc_list_device_interfaces` on a spoke); create one only if it's missing
      (`fmc_create_security_zone`, interface_mode='ROUTED').
   b. Interfaces: `fmc_update_interface` device="mcp-fw-branch1":
      - interface="Ethernet0/0", logical_name=<the other spokes' WAN name, e.g. outside>, enabled=true,
        security_zone=<WAN zone>, ipv4="198.51.100.14/24";
      - interface="Ethernet0/1", logical_name='inside', enabled=true, security_zone=<inside zone>, ipv4="10.77.14.1/24".
   c. Underlay route: `fmc_create_static_route` device="mcp-fw-branch1", interface=<WAN logical name>,
      networks=['any-ipv4'], gateway="198.51.100.1". It must cover the hubs' WAN addresses (step 0); when they sit
      behind a carrier network instead, route that network (a network object) via "198.51.100.1" as well.
   d. NAT for local internet breakout, if the other spokes have it: their NAT policy
      (`fmc_assign_policy` kind='nat') when it isn't tied to their addresses, else
      `fmc_create_nat_policy` and `fmc_create_nat_rule` kind='auto',
      original_source=<a network object for "10.77.14.0/24">, translated_source='interface',
      nat_type='DYNAMIC', source_interface=<inside zone>, destination_interface=<WAN zone>, then
      `fmc_assign_policy`. Keep the PAT on the WAN zone, never 'any': overlay traffic leaves
      through the VTI and must keep its addresses. Platform settings: the other spokes' policy
      (`fmc_assign_policy` kind='platform_settings').
   e. Access policy "mcp-fw-base-acp": it must allow the inside zone to and from the overlay zone (branch to hub
      networks and back) and inside to WAN for breakout. Check offline with `fmc_rule_lookup`
      policy="mcp-fw-base-acp", source="10.77.14.10", destination="10.77.0.10", protocol='icmp', source_zone=<inside zone>,
      destination_zone=<overlay zone>, and the reverse flow. Missing: add the zones to an allow rule
      (`fmc_update_access_rule`) or create one (`fmc_create_access_rule`). The policy
      is shared, so its other devices get the change on their next deployment: say so in the preview
      summary.
   f. Hub return path: every hub must reach 198.51.100.14 over its WAN. `fmc_run_show_command`
      device=<hub>, command='show route 198.51.100.14' must show a route out of the hub's WAN (a default
      route counts); "% Network not in table" means the hub can't answer the branch: add a static route
      on the hub (preview; a hub change).
   g. Deploy the branch alone: `fmc_pending_changes` device="mcp-fw-branch1", then `fmc_deploy`
      devices=["mcp-fw-branch1"], wait=true. Underlay check: `fmc_run_show_command` device="mcp-fw-branch1",
      'show interface ip brief' (both interfaces up with their addresses) and 'show route' (the route via
      "198.51.100.1"); with CML, `cml_run_commands` on the branch FTD node: 'ping <a hub WAN address>'. A
      tunnel can't come up over an underlay that doesn't work: fix this before step 5.

5. Join the topology: `fmc_update_sdwan_topology` topology="mcp-fw-t1",
   add_spokes=[{"device": "mcp-fw-branch1", "wan_interface": <the WAN logical name>, "inside_interfaces": ["inside"]}]
   (add backup_wan_interface when the other spokes have a second WAN tunnel, and spoke_loopbacks for an
   OSPF overlay). The preview lists the endpoints before and after, the tunnel address from the spoke
   pool and the devices to deploy (the hubs and "mcp-fw-branch1"); a pool without free addresses blocks it.

6. Deploy the hubs and the branch: `fmc_pending_changes` for each hub and for "mcp-fw-branch1": expect the
   topology change only. A hub with someone else's pending changes: stop and ask, they would go out too.
   Then `fmc_deploy` devices=[<the hubs>, "mcp-fw-branch1"], wait=true, and
   `fmc_list_deployments` device="mcp-fw-branch1": every job succeeded.

7. Verify (read-only). FMC's tunnel states trail the device by a few minutes: call again before calling
   a tunnel down.
   a. Tunnel: `fmc_sdwan_status` topology="mcp-fw-t1", branch="mcp-fw-branch1": the WAN link, the tunnel to
      every hub up, the overlay neighbours established, `degraded` empty. `fmc_list_vpn_tunnels`
      device="mcp-fw-branch1": TUNNEL_UP. Detail: `fmc_run_show_command` device="mcp-fw-branch1", 'show crypto ikev2
      sa' (READY) and 'show crypto ipsec sa' (encaps and decaps both counting).
   b. Routes: `fmc_run_show_command` device="mcp-fw-branch1", command='show route bgp' ('show route ospf'
      for an OSPF overlay): the hubs' and the other branches' inside networks over the tunnel. On each
      hub the same command shows "10.77.14.0/24" via the branch's tunnel address.
   c. Policy flow: real traffic first with CML (`cml_run_commands` on a branch inside host,
      'ping -c 3 10.77.0.10'), then `fmc_packet_tracer` device="mcp-fw-branch1", input_interface='inside',
      protocol='icmp', source_ip="10.77.14.10", destination_ip="10.77.0.10": allow, out through the tunnel (VTI), no NAT
      translation. A drop: the `fmc_why_blocked` prompt walks it.
   d. Application routes: if the other branches have app routes (`app_routes` in step 7a), "mcp-fw-branch1" doesn't
      inherit them; list them as follow-up (`fmc_configure_wan_interface`,
      `fmc_create_app_route`), each its own previewed change.

8. Report and hand-off. The report: device (model, version, how it was registered), the path taken
   (template name, or manual and why), interfaces, zones, routes, NAT and policies, topology membership
   (hubs, tunnel address), deployments (job, result) and the evidence of step 7. Then the hand-off record,
   verbatim, so the branch can be proven now and after every later change:

   branch "mcp-fw-branch1" | topology "mcp-fw-t1" | hubs <names> | WAN "Ethernet0/0" "198.51.100.14/24" via "198.51.100.1" |
   inside "10.77.14.0/24" | overlay zone <zone> | access policy "mcp-fw-base-acp"
   `fmc_prove_policy` flows=[
     {"name": "branch to hub LAN", "source": "10.77.14.10", "destination": "10.77.0.10",
       "protocol": "icmp", "device": "mcp-fw-branch1", "expect": "allow"},
     {"name": "hub LAN to branch", "source": "10.77.0.10", "destination": "10.77.14.10",
       "protocol": "icmp", "device": "<the primary hub>", "expect": "allow"},
     {"name": "<a flow the policy blocks>", "source": "10.77.14.10", "destination": "<address>",
       "protocol": "tcp", "port": <port>, "device": "mcp-fw-branch1", "expect": "block"}
   ]
   The third flow is one the access policy must block between the sites (from step 4e); leave it out
   and say so when the policy allows everything. Run `fmc_prove_policy` with these flows once
   now (read-only): every row `pass` proves the branch; put its table in the report. For user-based rules
   at the branch, `fmc_prove_user_policy` takes over.

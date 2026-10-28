# fmc_onboard_ftd

title: Onboard an FTD
arguments: {"access_policy": "mcp-test-ha-acp", "devices": "mcp-ftd2=198.18.128.161, mcp-ftd3=198.18.128.162", "gateway": "198.18.128.1", "health_policy": "mcp-edge", "host": "198.18.128.161", "inside_interface": "Ethernet0/1", "inside_ip": "10.99.2.1/24", "name": "mcp-ftd2", "nat_policy": "mcp-test-ha-nat", "outside_interface": "Ethernet0/0", "outside_ip": "198.18.128.163/18", "platform_settings": "mcp-test-ps", "recipe": "ftd-fmc", "template": "mcp-sdwan-spoke-tmpl", "test_destination": "198.18.128.1"}

Onboard an FTD end to end: optionally build it in CML from a recipe, check licensing,
register it with FMC, set outside/inside interfaces and zones, default route and NAT, assign
policies, deploy, and verify with show commands, packet tracer and real traffic. With
`template`, a device template sets the interfaces, routing, policies and SD-WAN/VPN membership
in one call (fmc_apply_device_template). With `devices` (or a recipe whose hand-off lists
several FTDs), every FTD is registered in one fmc_register_devices call. Explains the
`configure manager add` step for re-registration.

## user

Onboard the FTD "mcp-ftd2" into this FMC and bring it to a working, verified deployment.
Every write below is preview-first: show each preview and wait for the user's approval before
confirming. Keep notes of what each step returned. Stop and report if a step fails; don't improvise
around a failed registration or deployment.

0. Preconditions. `fmc_status` (FMC reachable, API user). `fmc_license_status`:
   FMC must be registered with Smart Licensing or be in evaluation mode, otherwise registration fails
   ("license" errors). `fmc_list_devices`: if any of "mcp-ftd2", "mcp-ftd3" is already registered, stop and ask
   the user whether to delete and re-register it. To re-register: `fmc_delete_device`,
   wait 1-2 minutes until the FTD's `show managers` no longer says "in the process of
   Unregistration", then run `configure manager add <fmc-ip> <reg-key>` on the FTD again.
   Check "mcp-test-ha-acp" exists (`fmc_list_policies` kind='access').

1. Build the FTD in CML: `cml_build_recipe` with recipe="ftd-fmc" (preview first; the FTDv boots in 15-30 minutes, so build with wait=false and then `cml_wait_for_converged`). Then `cml_verify_recipe` for the same recipe: the 'show managers' probe must show the FMC as pending. The recipe's fmc_side and credentials sections give the management IP and registration key.

2. Register all 2 FTDs in one call: `fmc_register_devices` with devices=[{"name": "mcp-ftd2", "host": "198.18.128.161"}, {"name": "mcp-ftd3", "host": "198.18.128.162"}],
   access_policy="mcp-test-ha-acp" and NO reg_key (every row uses the server's FMC_FTD_REG_KEY; the preview says so per
   row and blocks duplicate names or hosts). It sends one bulk request and waits for every registration
   and initial deployment under one deadline (timeout_minutes); a client that supports MCP tasks runs it
   in the background, so report its progress. The result has a row per device (deployed / registered /
   failed / refused / running) and the wall-clock time; `fmc_get_device` name="mcp-ftd2" must then
   be connected. A failed or refused row: fix that FTD (step 1) and call `fmc_register_devices`
   again with only the rows that did not register. Steps 3-7 configure "mcp-ftd2"; for each other FTD run
   this prompt again with its name and addresses (it is registered by then: skip steps 0-2), or pass
   template=... so one `fmc_apply_device_template` per FTD does steps 3-5.

2b. Device template "mcp-sdwan-spoke-tmpl" (a branch like an existing one): `fmc_get_device_template`
   template="mcp-sdwan-spoke-tmpl" lists its variables (type and default), interfaces, overridable objects and VPN/SD-WAN
   settings. Fill the variables for "mcp-ftd2" (interface addresses such as "198.18.128.163/18" and "10.99.2.1/24", AS numbers,
   router id) and call `fmc_apply_device_template` template="mcp-sdwan-spoke-tmpl", device="mcp-ftd2",
   variables={...}, overrides={...} for per-branch objects. It is dangerous-tier and replaces the
   device's configuration: show the preview (every variable, given or default, and every override) and
   wait for approval. The template brings the interfaces, zones, routes, NAT and policy assignments and
   the SD-WAN/VPN membership, so in steps 3-5 only check what `fmc_pending_changes` shows and
   fill gaps the template doesn't carry. In step 6 deploy "mcp-ftd2" and the hub(s) of its VPN topology, and
   verify the tunnels with `fmc_get_vpn_topology`.

3. Interfaces and zones: `fmc_list_device_interfaces` device="mcp-ftd2" (FTDv names them
   Ethernet0/0, Ethernet0/1, ...). Create zones if they don't exist
   (`fmc_list_objects` type='security_zone', `fmc_create_security_zone`;
   e.g. <name>-outside and <name>-inside, interface_mode='ROUTED').
   Then `fmc_update_interface` device="mcp-ftd2":
   - interface="Ethernet0/0", logical_name='outside', enabled=true, security_zone=<outside zone>, ipv4="198.18.128.163/18";
   - interface="Ethernet0/1", logical_name='inside', enabled=true, security_zone=<inside zone>, ipv4="10.99.2.1/24".

4. Routing and NAT: `fmc_create_static_route` device="mcp-ftd2", interface='outside',
   networks=['any-ipv4'], gateway="198.18.128.1". Use NAT policy "mcp-test-ha-nat": `fmc_assign_policy` kind='nat', policy="mcp-test-ha-nat", devices=["mcp-ftd2"].

5. Policies: "mcp-test-ha-acp" was assigned at registration; make sure it allows the traffic you will test (its
   rules reference zones, so add the new zones to an allow rule with `fmc_update_access_rule`
   if needed). Assign platform settings "mcp-test-ps": `fmc_assign_policy` kind='platform_settings', policy="mcp-test-ps", devices=["mcp-ftd2"]. Health policy "mcp-edge": `fmc_get_health_policy` policy="mcp-edge" (it must exist; otherwise `fmc_create_health_policy` name="mcp-edge" from the default with this device class's thresholds), then `fmc_assign_health_policy` policy="mcp-edge", devices=["mcp-ftd2"]; `fmc_get_health_policy` policy="mcp-edge" then lists the device.

6. Deploy: `fmc_pending_changes` device="mcp-ftd2" (expect the interface, route, NAT and policy
   changes), then `fmc_deploy` devices=["mcp-ftd2"] with wait=true. Check
   `fmc_list_deployments` device="mcp-ftd2": the job must have succeeded.

7. Verify:
   - `fmc_run_show_command` device="mcp-ftd2", command='show interface ip brief' (both data
     interfaces up with their addresses) and 'show route' (default route via "198.18.128.1");
   - `fmc_packet_tracer` device="mcp-ftd2", input_interface='inside', protocol='icmp',
     source_ip=<an inside host address>, destination_ip="198.18.128.1": expect allow with the NAT translation
     (a drop with no-v4-adjacency right after the deploy only means the FTD has no ARP entry for the
     next hop yet: send real traffic first, then trace again);
   - with a CML lab, real traffic first: `cml_run_commands` on an inside host,
     'ping -c 3 198.18.128.1'.

8. Report: device, version, interfaces and zones, route, NAT, assigned policies, deployment result
   and the verification evidence. Mention that re-registration needs `configure manager add` on the
   FTD after a delete (step 0).

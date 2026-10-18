# Firewall SD-WAN live matrix (F53)

The F51 SD-WAN tools run against FMC 10.0.1 with FTDv 10.0 in CML, one cell per topology x component.
The suite is `tests/live/test_live_sdwan_matrix.py` (variables in [live-tests.md](live-tests.md)). Fault
injection (link down, brownout, hub down) goes through cml-mcp. Lab addresses aren't in this file: the
CML recipes `ftd-sdwan-single`, `ftd-sdwan-dual-hub` and `ftd-sdwan-ha-hub` in cml-mcp-server have the address plan.

Status: **pass**, **fail** (a tool bug; the root cause is under the table), **blocked** (a lab or
platform limit), or **not run**.

## Topologies and components

| | Topology |
|---|---|
| T1 | single hub, 3 spokes, each FTD on three WAN carriers (MPLS-like, internet, LTE-like) |
| T2 | dual hub (primary/backup), 2 spokes |
| T3 | HA-pair hub, 2 spokes (cluster attempt bounded to 45 min) |
| T4 | spoke-to-spoke through the hub, on the T1 devices |

| | Component |
|---|---|
| C1 | build, deploy, teardown (`fmc_create_sdwan_topology`, `fmc_deploy`, `fmc_delete_s2s_vpn`) |
| C2 | overlay routing: iBGP (generated) and OSPF |
| C3 | multi-WAN: `fmc_configure_wan_interface`, `fmc_create_app_route`, failover under link impairment |
| C4 | onboarding a branch from a device template (`fmc_create_device_template`, `fmc_apply_device_template`) |
| C5 | `fmc_sdwan_status` and the `fmc_sdwan_troubleshoot` prompt with injected faults |

## Matrix

Run 2026-10-18 against main (F51 a-d, #116, #119) in domain `Global/mcp-test-leaf`. T1/T4 by the first matrix
agent; T2 and the T3 SD-WAN cells by the next one.

| | C1 | C2 | C3 | C4 | C5 |
|---|---|---|---|---|---|
| T1 | **pass** | iBGP **pass**, OSPF **fail** (R5) | **fail** (R1, R3) | **blocked** (B1) | **fail** (R2) |
| T2 | not run | not run | not run | not run | not run |
| T3 | HA pair formed (setup); cells not run; cluster deferred (B2) | not run | not run | not run | not run |
| T4 | n/a (T1) | through hub **pass**; direct spoke-to-spoke not offered by the tools | **fail** (R1) | n/a (T1) | covered by T1 C5 |

So far: T1 has C1 pass, C2 split (iBGP pass, OSPF fail), C3 fail, C4 blocked and C5 fail; T4 has C2 pass and C3 fail
(C1 and C4 are T1's, C5 is covered by T1). Every fail has a root cause below.

## FMC-side setup before the cells

The recipes leave the data interfaces unconfigured, so the T1 underlay is built with the MCP tools first (kept
between runs; only the SD-WAN objects are torn down):

1. Zones `mcp-sdwan-wan`, `mcp-sdwan-inside`, `mcp-sdwan-overlay` (`fmc_create_security_zone`).
2. On the hub and every spoke (`fmc_update_interface`): Ethernet0/0 `mpls`, 0/1 `inet`, 0/2 `lte` in
   `mcp-sdwan-wan`; 0/3 `inside` in `mcp-sdwan-inside`; addresses from the recipe's address plan.
3. One network object per carrier (`mcp-sdwan-mpls-net`, `-inet-net`, `-lte-net`) and one static route per
   carrier per device toward that carrier's gateway (`fmc_create_static_route`). Each spoke then reaches the hub
   on all three carriers (`cml_check_reachability`).
4. An ALLOW rule `mcp-sdwan-allow-overlay` (inside + overlay zones, both directions) in the devices' access policy.
   Add the overlay zone only once the topology exists: a rule using a zone without interfaces makes FMC's
   deploy validation warn, and this server doesn't ignore warnings.

## Evidence per cell

**T1 C1 (pass).** `fmc_create_sdwan_topology` (hub DVTI on `mpls`, new loopback and spoke pool, 3 spokes,
iBGP) -> deploy of the 4 devices -> 3 IKEv2 SAs READY on the hub (`show crypto ikev2 sa`), `fmc_list_vpn_tunnels`
3 TUNNEL_UP. Teardown: `fmc_delete_s2s_vpn` + deploy -> no SAs, no BGP, spoke VTIs removed. The hub DVTI,
loopback and pool stay (`fmc_delete_interface`; the pool needs `fmc_api_call` DELETE `object/ipv4addresspools`,
since `fmc_delete_object` doesn't know pools).

**T1 C2 iBGP (pass).** Hub: 3 iBGP neighbours, one prefix each; every spoke learns the hub and the other
spokes' inside networks (`show route bgp`); all 12 host pairs ping.

**T1 C2 OSPF (fail, R5).** Topology with `overlay='ospf'` (reusing the DVTI, loopback and pool) plus
`fmc_configure_ospf` area 0 on all four: adjacencies FULL on the hub's virtual-access interfaces, LSDB in sync, the hub
learns the 3 spoke networks, but the spokes install no OSPF routes, so no traffic crosses.

**T1 C3 (fail, R1 + R3).** `fmc_configure_wan_interface` on the physical WANs works (priority, path monitoring).
`fmc_create_app_route` correctly refuses `order_by='rtt'` when the egress has no path monitoring; a route by
priority over the tunnel deploys (`set adaptive-interface cost <tunnel>`; `fmc_packet_tracer` shows the
PBR-LOOKUP phase choosing it). Brownout on spoke1's MPLS link: host RTT 10 -> 315 ms with 50% loss; the FTD's own
path monitoring shows RTT 156 ms, 23% loss, MOS 0.99. Dead WAN (MPLS link down): no failover, 0% for 94 s, because
the spokes have no backup tunnel (R1). Recovery 47 s after the link came back. `path_monitoring='auto'` gives
peer 0.0.0.0 when the interface has no default route; use `ip` with the carrier gateway.

**T1 C4 (blocked, B1).** Fallback check: removing spoke3 and adding it back with `fmc_update_sdwan_topology`
works (it reaches the hub and both spokes).

**T1 C5 (fail, R2).** `fmc_sdwan_status`:
- dead WAN: critical TUNNEL_DOWN (detected);
- hub down (hub MPLS link down): every tunnel critical, each counted from both ends, with no single "hub
  unreachable" finding (detected); recovery 41 s;
- brownout: not detected (`degraded` empty, WAN health `unknown`; R2);
- wrong PSK (topology switched to a manual key, hub-only deploy): critical TUNNEL_DOWN with no message, so it
  looks the same as a dead WAN (R2: path metrics would show the WAN is healthy);
- leaked route (spoke advertises an underlay prefix with `fmc_configure_bgp`): FMC's generated outbound
  community route-map drops untagged prefixes, so the hub never receives it (contained). Deploying device BGP on a
  spoke reset its overlay session.

The `fmc_sdwan_troubleshoot` prompt walks the right steps and copes with "not available" evidence, but step 4
suggests `show bgp summary` (refused) and step 6 suggests a backup WAN (R1).

**T4 (on T1).** Spoke-to-spoke through the hub: all pairs ping (11-19 ms vs 7-10 ms to the hub). The tools don't
offer direct spoke-to-spoke tunnels. C3 has the same backup-tunnel gap (R1).

**T3 setup.** `fmc_create_ha_pair` `mcp-sdwan-t3-hub-ha` (hub primary, hub2 secondary, Ethernet0/4): High
Availability configured; `show failover` Primary Active / Secondary Standby Ready. FMC first refused with "One or
both Peers are dirty" until both hubs were deployed.

## Root causes (tool bugs)

- **R1 `fmc_create_sdwan_topology` / `fmc_update_sdwan_topology`, `spokes[].backup_wan_interface`.** The tool
  sends `backupInterfaces: [{"interface": <ref>}]` on the AUTO_VPN spoke endpoint (it matches the spec's
  `IVpnBackupInterface`). FMC 10.0.1 accepts it and stores nothing: the endpoint GET has no `backupInterfaces`, its
  `vtiInterfaceMetadataList` holds one VTI, and a PUT with the field is also a silent no-op. No backup tunnel is
  built and the tool reports success. Fix: read the endpoint back and fail when the backup is missing; the payload
  FMC uses for a second spoke WAN in AUTO_VPN is still to be captured from the FMC 10 SD-WAN wizard (probably a
  second hub DVTI on another WAN plus one `vtiInterfaceMetadataList` entry per spoke WAN).
- **R2 `fmc_sdwan_status` (and the C3/C5 evidence).** FMC 10.0.1's `operational/commands` refuses
  `show path-monitoring`, `show policy-route`, `show bgp summary` and `show bgp neighbors` (400 "Either command is
  not supported or entered command is an invalid command"), so the status never has path metrics: WAN health stays
  `unknown`, brownouts aren't detected, a PSK mismatch looks like a dead WAN. `show route bgp` and
  `show crypto ikev2 sa` work. Fix: use the allowed commands (and health-monitor metrics if FMC exposes path
  monitoring there), and report "not available" rather than `unknown`. Also: `app_routes[].name` is null and
  `path_now` stays on a tunnel that is down.
- **R3 `fmc_configure_wan_interface` on a VTI** (`interface='<spoke tunnel>'`, `priority=1`,
  `path_monitoring='ip'`): PUT `devices/devicerecords/{id}/virtualtunnelinterfaces/{id}` -> 400 "Fields:
  { managementOnly } must be excluded from json payload." The tool echoes the GET body; for VTIs it must drop
  `managementOnly` (and other physical-only fields). Without it, app routes over tunnels can't be ordered by
  metric.
- **R4 minor.** `fmc_create_device_template` doesn't validate the description (FMC 500 "invalid characters" for
  parentheses); `fmc_apply_device_template` aborts in preview when the object-overrides read fails instead of
  reporting it; `fmc_api_call` previews show `manualPreSharedKey` in clear text.
- **R5 C2 OSPF (not proven a tool bug).** The hub DVTI is unnumbered (borrows a /32 loopback) while spoke VTIs get a
  /24 from the pool; with `fmc_configure_ospf` defaults the spokes compute no routes. This probably needs an OSPF
  interface network type or matching masks, which `fmc_configure_ospf` doesn't expose.

## Blockers

- **B1 device templates on FTDv for KVM.** `fmc_create_device_template(source_device=<spoke>)` -> FMC 400 "A
  template could not be generated from the device ... The version or model of the device is not supported."
  An empty template made from parameters exists, but every sub-resource read fails ("Node is not found: -1") and it
  can't be applied. C4 needs a supported hardware model (or a later FMC).
- **B2 T3 clustering, deferred.** Only the two T3 hubs are cabled for a cluster control link (Ethernet0/4-0/5), and
  they are the HA pair the T3 HA cells need. The plan puts the cluster attempt after those cells. Next step:
  break the HA pair, then `fmc_api_call` POST `deviceclusters/ftddevicecluster` with `action=CREATE_CLUSTER`,
  `clusterMode=INDIVIDUAL`, `controlDevice` = hub, `dataDevices` = [hub2], and `commonBootstrap` with `cclInterface`
  Ethernet0/5, `cclNetwork`, `vniNetwork` and `clusterKey`. The 45-minute limit starts then.
- **Lab:** the IOL carriers' consoles are silent on this controller (they forward traffic fine), so carrier-side
  checks run from the FTDs.

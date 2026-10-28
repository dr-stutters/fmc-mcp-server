# FTD SD-WAN live matrix (F53)

The F51 FTD SD-WAN tools (`fmc_*_ftdsdwan_*`; `fmc_*_sdwan_*` before 0.20.0) run against FMC 10.0.1 with
FTDv 10.0 in CML, one cell per topology x component.
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
| C1 | build, deploy, teardown (`fmc_create_ftdsdwan_topology`, `fmc_deploy`, `fmc_delete_s2s_vpn`) |
| C2 | overlay routing: iBGP (generated) and OSPF |
| C3 | multi-WAN: `fmc_configure_wan_interface`, `fmc_create_app_route`, failover under link impairment |
| C4 | onboarding a branch from a device template (`fmc_create_device_template`, `fmc_apply_device_template`) |
| C5 | `fmc_ftdsdwan_status` and the `fmc_ftdsdwan_troubleshoot` prompt with injected faults |

## Matrix

Run 2026-10-18 against main (F51 a-d, #116, #119) in domain `Global/mcp-test-leaf`. T1/T4 by the first matrix
agent (01:00-02:00 UTC); T2 and T3 by the second (02:05-03:50 UTC).

| | C1 | C2 | C3 | C4 | C5 |
|---|---|---|---|---|---|
| T1 | **pass** | iBGP **pass**, OSPF **fail** (R5) | **fail** (R1, R3) | **blocked** (B1) | **fail** (R2) |
| T2 | **pass** | iBGP **pass** (backup hub takes over; R6 to get there), OSPF **fail** (R5) | **fail** (R1, R3) | **blocked** (B1) | **fail** (R2) |
| T3 | **pass** (HA-pair hub); cluster **blocked** (B2) | iBGP **pass** incl. HA switch with the overlay up | **fail** (R1, R3) | **blocked** (B1) | **fail** (R2, R7); standby takeover itself works |
| T4 | n/a (T1) | through hub **pass**; direct spoke-to-spoke not offered by the tools | **fail** (R1) | n/a (T1) | covered by T1 C5 |

Counts over T1-T3 x C1-C5 (15 cells): **pass 4** (C1 on T1, T2, T3; C2 on T3), **split 2** (C2 on T1 and T2:
iBGP pass, OSPF fail), **fail 6** (C3 and C5 on T1, T2, T3), **blocked 3** (C4 on T1, T2, T3: B1). T3 C2 ran iBGP only:
the OSPF failure (R5) comes from how FMC's AUTO_VPN addresses the tunnels and reproduced on T1 and T2. T4 has C2 pass
and C3 fail. The T3 cluster attempt is
B2. Every fail has a root cause below. Tunnels, iBGP, the backup hub and HA failover all work on the devices; the gaps
are in what the tools send or read (R1-R3, R6, R7) and in OSPF over FMC's AUTO_VPN addressing (R5).

## Re-run on v0.13.0 (2026-10-18, 08:00-08:45 UTC)

The cells the 0.13.0 fixes target, re-run by the `rerun` agent with the released fmc-mcp 0.13.0 (R1-R3, R5-R7 in it)
and cml-mcp main, in `Global/mcp-test-leaf`. The `mcp-sdwan-health` policy (path monitoring on) was assigned to
the 12 SD-WAN FTDs. Every topology was torn down afterwards.

| Cell | Result | Root cause |
|---|---|---|
| T1 C3, VTI WAN settings (`fmc_configure_wan_interface` on a spoke tunnel) | **pass** | R3 fixed |
| T1 C3, dead WAN, second WAN tunnel built as a companion topology | **pass** | R1 payload (#138) |
| T1 C3, app route by RTT over the two tunnels follows WAN health | **fail** | R9 (new) |
| T4 C3 (spoke-to-spoke over the same app route and tunnels) | failover **pass**, metric routing **fail** | R9 |
| T1 C5, wrong PSK told apart from a dead WAN | **pass** | R2 fixed |
| T1 C5, brownout detected by `fmc_ftdsdwan_status` | **fail** on 0.13.0 | R2 rest, fixed in #137 (not live) |
| T2 C2, `fmc_update_ftdsdwan_topology(multipath=False)` + backup-hub takeover | **pass** | R6 fixed |
| T3 C1, C2, C5 on a rebuilt HA pair | **blocked** | B3 (new) |
| T1 C2 OSPF with unnumbered spoke VTIs | **pass** | R5: working addressing found |

Matrix after the re-run (cells not re-run keep their first-run result):

| | C1 | C2 | C3 | C4 | C5 |
|---|---|---|---|---|---|
| T1 | **pass** | iBGP **pass**, OSPF **pass** (unnumbered spoke VTIs) | **fail** (R9); R1, R3 fixed | **blocked** (B1) | **fail** (brownout, #137); PSK and dead WAN **pass** |
| T2 | **pass** | iBGP **pass** (R6 fixed, backup hub takes over), OSPF not re-run | **fail** (not re-run; R9 expected) | **blocked** (B1) | **fail** (not re-run) |
| T3 | **pass** (first run) | **pass** (first run) | **fail** (not re-run) | **blocked** (B1) | **fail** (R7 fix not verified live: B3) |
| T4 | n/a (T1) | through hub **pass** | failover **pass**, metric routing **fail** (R9) | n/a (T1) | covered by T1 C5 |

Counts over T1-T3 x C1-C5 (15 cells): **pass 5** (C1 on T1, T2, T3; C2 on T1, T3), **split 1** (T2 C2: iBGP pass,
OSPF not re-run), **fail 6** (C3 on T1, T2, T3; C5 on T1, T2, T3), **blocked 3** (C4: B1). The failures left are R9
(the FTD's metric-based app routing doesn't override the routing table over VTIs), the brownout part of C5 (fixed in
#137, waiting for a release) and the cells B3 kept from re-running.

**T1 C3 and T4 C3.** `fmc_create_ftdsdwan_topology` built `mcp-sdwan-t1` (hub DVTI on `mpls`, 3 spokes) and a companion
`mcp-sdwan-t1-wan2` (a second hub DVTI on `inet` with its own loopback and pool, spoke1 on `inet`, same AS and community),
which is the second-WAN payload from #138. 0.13.0's create tool built the companion directly: its loopback and tunnel
ids didn't collide with the first topology's because the first one existed already. One deploy: spoke1 had tunnels on
`mpls` and `inet` and ECMP routes over both hubs' tunnel addresses.
- `fmc_configure_wan_interface` on both spoke1 tunnels (priority 1 and 2, path monitoring `ip` to each hub tunnel
  address) applied and deployed: **R3 is fixed**. `show path-monitoring` on the device lists both tunnels.
- `fmc_create_app_route(order_by='rtt')` over the two tunnels (to the hub and spoke2 networks) passed its checks and
  deployed: `set adaptive-interface rtt mpls_static_vti_1 inet_static_vti_2`.
- Brownout on spoke1's `inet` link: `show route-map` shows the measured RTTs (`mpls` tunnel about 3 ms, `inet` tunnel
  about 311 ms), but `fmc_packet_tracer` (PBR-LOOKUP phase) and the tunnel counters (`show traffic`: about 130 more
  packets out of the `inet` tunnel during a 100-ping burst) show the traffic still leaving through the `inet` tunnel.
  With the brownout on `mpls` instead, the path stayed on `inet` too. With `multipath=False` (one BGP best path, via
  the `mpls` tunnel) and the brownout on `mpls`, the route still picked `mpls` (RTT about 306 ms against 3 ms), and the
  host saw about 300 ms and 32-42% loss to the hub and to spoke2. The PBR result always matches the routing table's
  choice (the ECMP hash or the best path): see R9.
- Dead WAN (spoke1's `mpls` cable pulled) with `multipath=False`: traffic moved to the `inet` tunnel after about
  21-25 s (the ping started a few seconds after the pull; its first 41 pings at 0.5 s intervals were lost, then none). With ECMP (the backup-wan run) no ping was lost.
  Spoke-to-spoke traffic uses the same tunnels.

**T1 C5.** `fmc_ftdsdwan_status` on 0.13.0:
- dead WAN: the tunnel is critical `TUNNEL_DOWN` with the reason "IKEv2 exchanges time out with no authentication
  failures: the peer doesn't answer (dead WAN path or UDP 500/4500 blocked)".
- wrong PSK (the companion topology's automatic key length changed, which makes FMC generate a new key; deployed to the
  hub only, and spoke1's `inet` link bounced to force a new IKE exchange): about 3 minutes later the tunnel is critical
  with "IKEv2 authentication failures rose by 6 in the last 168 s: a pre-shared key (or certificate) mismatch, not a dead
  path". **R2 is fixed** for this case. No key was typed: FMC generated it.
- brownout: `wan_links` health is "not available" with the reason (no longer `unknown`), and `degraded` is empty. 0.13.0
  can't see a brownout; #137 reads FMC's `pathmonitoring` health metric, which showed it in the metrics run.
- Still in 0.13.0: the status sends `show path-monitoring`, `show policy-route` and `show bgp summary` and gets 400s
  (#136 stops that), and `app_routes[].path_now` names the `mpls` tunnel ("first usable interface in order") while that
  tunnel is down.

**T2 C2.** `fmc_create_ftdsdwan_topology` with `backup_hub`, then `fmc_update_ftdsdwan_topology(multipath=False)` on 0.13.0:
applied without the 422, **R6 is fixed**. After a deploy of the 4 devices every spoke routes the DC and the other spoke
via the primary hub, and all 6 host pairs ping. Primary hub down (its `mpls` and `inside` links down, the DC host's
gateway moved to hub2): the spokes route via hub2 and every pair answers again within about 33 s. Links and the
gateway were restored afterwards.

**T3 (blocked, B3).** The T3 HA pair could not be rebuilt; see B3.

**OSPF (bounded attempt, about 15 minutes): pass.** Topology `mcp-sdwan-t1-ospf` (`overlay='ospf'`, reusing the hub
DVTI, loopback and pool; spoke1 and spoke2 on `mpls`). Then, with `fmc_api_call`, a /32 loopback on each spoke (POST
`loopbackinterfaces`, from a block outside the spoke pool) and a PUT of each FMC-generated spoke VTI with
`ipAddressAssignmentType: BORROW_IP_FROM_INTERFACE` and `borrowIPfrom` set to that loopback (without
`managementOnly`; FMC accepted it on a VTI the topology owns). `fmc_configure_ospf` area 0: hub with the overlay pool
network and the inside networks, spokes with the loopback block and the inside networks. After one deploy both ends are
unnumbered: the hub has two FULL neighbours on its virtual-access interfaces, each spoke has one, and **the spokes
install OSPF routes** to the hub's network, the other spoke's network and its loopback. Every pair of the hub and spoke hosts
pings (5-10 ms).

## Re-proof on v0.13.1 (2026-10-18, 10:25-10:55 UTC)

The two features 0.13.1 ships for SD-WAN were re-proven live with the released fmc-mcp 0.13.1 (core 0.14.2) and
cml-mcp main, on `mcp-sdwan-t1` in `Global/mcp-test-leaf`, using the tools only (no `fmc_api_call` for the
topology). Everything was torn down afterwards.

| Cell | Result | Evidence |
|---|---|---|
| T1 C1/C3, `fmc_create_ftdsdwan_topology` with `backup_wan_interface` (R1) | **pass** | one call built `mcp-sdwan-t1` and the companion `mcp-sdwan-t1-wan2` (second hub DVTI, loopback and pool); one deploy; each backup-WAN spoke has two IKEv2 SAs and ECMP routes over both hub tunnel addresses; all host pairs ping |
| T1 C3, dead WAN on the primary WAN (spoke1 `mpls` cable pulled) | **pass** | 0 % loss in the reachability rounds that started within about 5 s of the pull; routes on the second-WAN tunnel only about 31 s after the pull; ECMP back about 10 s after the link returned, with no loss |
| T1 C5, brownout detected by `fmc_ftdsdwan_status` (R2) | **pass** | `mpls` and its tunnel critical in `degraded` from the first poll (2 min); numbers at about 6.5 min: RTT 302 ms, jitter 40 ms, loss 30 %, MOS 0 (baseline 1.5 ms, 0 %, 4.4); the second WAN stayed ok |

The matrix's T1 C5 brownout part is now **pass**, so T1 C5 is pass. T1 C3 stays **fail** only because of R9 (device
behaviour).

Notes from the run:
- For the first ~5 minutes of the brownout, FMC's `pathmonitoring` series for `mpls` reported `rechability: No` with
  zero values, while the device's `show path-monitoring` said reachable, 302 ms and 30 % loss. In that window
  `fmc_ftdsdwan_status` says "path monitoring peer ... does not answer" (critical) instead of giving numbers. After that,
  the measured values came through.
- `sampled_at` is the last step of the health-monitor range, and FMC repeats stale values at every step, so it can
  look current while the value is minutes old.
- `bgp_routes` in `fmc_ftdsdwan_status` keeps only the first next hop of an ECMP route.
- The three points above are fixed after 0.13.1 (Unreleased): `bgp_routes[].via` lists every next hop, each link
  says `changed_at` or `unchanged_since`, and FMC's "rechability No" window reads "metrics pending or the peer
  unreachable per FMC" (still critical).
- `fmc_delete_s2s_vpn`'s preview names the companion topology, and both deletes plus the DVTI, loopback and pool
  cleanup left 0 topologies and no SAs.

## OSPF overlay with the tool on main (2026-10-18, 12:15-12:45 UTC)

`fmc_create_ftdsdwan_topology(overlay='ospf', spoke_loopbacks=...)` and `fmc_update_ftdsdwan_topology(add_spokes=...,
spoke_loopbacks=...)` from #143 were run live on `mcp-sdwan-t1` (main 25d1ae7, core 0.14.2) in `Global/mcp-test-leaf`,
with the tools only (no `fmc_api_call` for the overlay). Everything was torn down afterwards.

| Cell | Result | Evidence |
|---|---|---|
| T1 C2 OSPF, build with `spoke_loopbacks` (R5) | **pass** | one call (spoke_loopbacks `10.255.9.8/29`, 3 spokes on `mpls`) created the pool, hub DVTI and loopback, `sdwan-ospf-lo` 10.255.9.9-.11/32 on the spokes and the endpoints, then switched each FMC-generated `Tunnel1` to `BORROW_IP_FROM_INTERFACE` from that loopback |
| T1 C2 OSPF, routes and traffic | **pass** | after `fmc_configure_ospf` area 0 and one deploy: every spoke installs O routes via 10.255.1.1 (hub inside, the other spokes' insides and /32 loopbacks); the hub has the 3 spoke networks via the loopbacks; all 12 host pairs ping (4-8 ms) |
| T1 C2 OSPF, `fmc_update_ftdsdwan_topology` remove and re-add a spoke | **pass** | remove spoke3: its tunnel and routes go; re-add with spoke_loopbacks `10.255.9.11`: the tool reuses the loopback left on spoke3, the new tunnel borrows it, and spoke3 has its 5 O routes and reaches every host again |

The matrix's T1 C2 OSPF is now **pass with the tool alone**. Notes:
- `fmc_ftdsdwan_status` works on an OSPF overlay but has no OSPF view: it runs `show route bgp` (empty `bgp_routes`) and
  shows no OSPF routes. Tunnel states from FMC's monitor lagged (one tunnel UNKNOWN while its SA was up), which the
  status ranks as a `degraded` warning.
- Removing a spoke from an OSPF overlay keeps its `sdwan-ospf-lo` loopback (delete it with `fmc_delete_interface`, or
  give its address again when re-adding the spoke).

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

T2 and T3 use the same steps with only `mpls`, `inet` and `inside` per FTD and their own carrier objects
(`mcp-sdwan-t2-mpls-net`, `-inet-net`, `mcp-sdwan-t3-mpls-net`, `-inet-net`). On T3 the hub interfaces are set on the
HA pair's primary and the standby addresses with `fmc_configure_ha_monitoring` (`show failover`: four monitored
interfaces Normal on both units).

## Evidence per cell

**T1 C1 (pass).** `fmc_create_ftdsdwan_topology` (hub DVTI on `mpls`, new loopback and spoke pool, 3 spokes,
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

**T1 C4 (blocked, B1).** Fallback check: removing spoke3 and adding it back with `fmc_update_ftdsdwan_topology`
works (it reaches the hub and both spokes).

**T1 C5 (fail, R2).** `fmc_ftdsdwan_status`:
- dead WAN: critical TUNNEL_DOWN (detected);
- hub down (hub MPLS link down): every tunnel critical, each counted from both ends, with no single "hub
  unreachable" finding (detected); recovery 41 s;
- brownout: not detected (`degraded` empty, WAN health `unknown`; R2);
- wrong PSK (topology switched to a manual key, hub-only deploy): critical TUNNEL_DOWN with no message, so it
  looks the same as a dead WAN (R2: path metrics would show the WAN is healthy);
- leaked route (spoke advertises an underlay prefix with `fmc_configure_bgp`): FMC's generated outbound
  community route-map drops untagged prefixes, so the hub never receives it (contained). Deploying device BGP on a
  spoke reset its overlay session.

The `fmc_ftdsdwan_troubleshoot` prompt walks the right steps and copes with "not available" evidence, but step 4
suggests `show bgp summary` (refused) and step 6 suggests a backup WAN (R1).

**T4 (on T1).** Spoke-to-spoke through the hub: all pairs ping (11-19 ms vs 7-10 ms to the hub). The tools don't
offer direct spoke-to-spoke tunnels. C3 has the same backup-tunnel gap (R1).

**T2 C1 (pass).** `fmc_create_ftdsdwan_topology` with `backup_hub` (hub and hub2 each get a DVTI on `mpls`, a loopback
and their own pool; two spokes on `mpls`). FMC builds two VTIs per spoke, one per hub (the endpoint lists the second as
`backup_interfaces`). Deploy of the 4 devices OK; each hub has 2 IKEv2 SAs READY. Teardown as on T1 (topology, deploy,
both DVTIs and loopbacks, both pools): no SAs, no spoke tunnels.

**T2 C2 iBGP (pass, after R6).** With the default `multipath=True` the spokes install the DC network over both hubs
(ECMP), and branch-to-DC pings fail: the DC host's gateway is the primary hub, so flows hashed to the backup hub come back
asymmetrically and the FTDs drop them (spoke-to-spoke works). `fmc_update_ftdsdwan_topology(multipath=False)` fails (R6);
the same change sent with `fmc_api_call` works, and then every spoke uses the primary hub and all 6 host pairs ping.
Primary hub down (its `mpls` and `inside` links down, the DC host's gateway moved to hub2 as an FHRP stand-in): spokes
switch to the backup hub (`show route bgp` via the hub2 tunnel) and every host pair answers again within 34 s. When
the hub comes back, its tunnels re-form in about 1.5 min and the routes move back to the primary hub.

**T2 C2 OSPF (fail, R5).** Topology `overlay='ospf'` reusing the DVTIs, loopbacks and pools, `fmc_configure_ospf` area 0
(overlay /22 and inside /16) on all four. Adjacencies FULL (spoke on both tunnels, the hubs also over the DC LAN), the
hubs learn the spoke networks, the spokes install no OSPF route. On a spoke, `show ospf database router <hub>` says
**"Adv Router is not-reachable"**: the hub's point-to-point links carry an ifIndex (0.0.0.15, 0.0.0.16) as link data
because the DVTI is unnumbered, while the spoke VTIs are numbered /24s, so the spoke's SPF can't resolve a next hop.

**T2 C3 (fail, R1 + R3).** `fmc_configure_wan_interface` on spoke1 `mpls` (priority 1, path monitoring to the carrier) and
`inet` (priority 2) works; on the tunnel it fails again with R3. `fmc_create_app_route` by `order` over the two hub tunnels
for the DC network deploys (`set interface mpls_static_vti_1 mpls_static_vti_2`). Primary hub WAN down: traffic leaves
through the backup-hub tunnel after 21 s. Brownout on spoke1's `mpls`: host RTT 326 ms with 30% loss; the FTD's path
monitoring shows `mpls` RTT 73 ms, jitter 124 ms, 10% loss, MOS 2.42 against `inet` MOS 4.40, but the route can't
react to it (metric ordering needs path monitoring on the tunnels: R3), and both tunnels ride `mpls` (no tunnel on a
second WAN: R1).

**T2 C4 (blocked, B1).** `fmc_create_device_template(source_device=<t2 spoke>)`: the same FMC 400. Fallback: removing
spoke2 and adding it back with `fmc_update_ftdsdwan_topology` gives it tunnels to both hubs again (2 SAs) and it reaches the
DC and spoke1.

**T2 C5 (fail, R2).** `fmc_ftdsdwan_status`:
- hub down and dead spoke WAN: critical TUNNEL_DOWN, but only 2-3 minutes after the failure (FMC's tunnel monitor
  lags; a minute after the hub went down the status still said all 4 tunnels UP); recovery 45 s;
- brownout: not detected (`degraded` empty, health `unknown`);
- wrong PSK (manual key deployed to hub2 only, hub2's WAN flapped): spoke-to-hub2 critical TUNNEL_DOWN with no message,
  the underlay pings fine. The spoke's `show crypto ikev2 stats` counts 7 authentication failures, and FMC's
  command API allows that command, so the status could tell a key mismatch from a dead WAN (R2);
- leaked route: not re-injected; the T2 spokes carry the same generated `FMC_VPN_RMAP_COMMUNITY_OUT_*` (deny 100) that
  contained it on T1.
Minor: the backup-hub tunnel shows up in `wan_links` with health `unknown`, the hubs' own WAN links are missing,
`app_routes[].name` is null and `path_now` stays on a tunnel that is down.

**T3 setup.** `fmc_create_ha_pair` `mcp-sdwan-t3-hub-ha` (hub primary, hub2 secondary, Ethernet0/4): High
Availability configured; `show failover` Primary Active / Secondary Standby Ready. FMC first refused with "One or
both Peers are dirty" until both hubs were deployed.

**T3 C1 (pass).** `fmc_create_ftdsdwan_topology(hub='mcp-sdwan-t3-hub-ha')` takes the HA pair as the hub (DVTI, loopback and
pool on the pair). Deploy to the pair and two spokes OK; 2 SAs on the active unit; all 6 host pairs ping. Teardown as
on T1.

**T3 C2 iBGP (pass).** `fmc_ha_action(action='switch')` with the overlay up: SUCCESS; every host pair answers again
within 34 s. The IKEv2 SAs survive on the new active unit (their age keeps counting: replicated), but the iBGP sessions
restart, so the outage is the BGP re-establishment.

**T3 C3 (fail, R1 + R3).** `fmc_configure_wan_interface` on the HA hub's `mpls` deploys to the pair; the active unit
measures the path, the standby says "Statistics not available on standby node". `fmc_create_app_route(order_by='rtt')`
over the spoke tunnel is correctly blocked (no path monitoring on the egress), and the fix for that is R3. Brownout on
the hub side of the MPLS carrier: host RTT 250 ms with 50% loss, the hub's path monitoring RTT 184 ms, 33% loss, MOS 0.0.

**T3 C4 (blocked, B1).** Same model as T1/T2. Fallback: removing spoke2 from the HA-hub topology and adding it back works
(reaches the DC and spoke1 within 7 s).

**T3 C5 (fail, R2 + R7).** Standby takeover: the active unit's `mpls` link down -> that unit Failed ("Ifc Failure, mpls:
Failed"), the other unit Active, the SAs move with it, every host pair answers again within 39 s. `fmc_ftdsdwan_status`
reports nothing: `degraded` is empty, the hub row has no WAN links and no tunnels (the spokes' rows name the peer
`mcp-sdwan-t3-hub-ha[mcp-sdwan-t3-hub]`), the failed unit isn't mentioned, and `branch='mcp-sdwan-t3-hub'` answers
"is in no SD-WAN topology" (R7). The hub-side brownout isn't detected either (R2).

## Root causes (tool bugs)

- **R1 `fmc_create_ftdsdwan_topology` / `fmc_update_ftdsdwan_topology`, `spokes[].backup_wan_interface`.** The tool
  sends `backupInterfaces: [{"interface": <ref>}]` on the AUTO_VPN spoke endpoint (it matches the spec's
  `IVpnBackupInterface`). FMC 10.0.1 accepts it and stores nothing: the endpoint GET has no `backupInterfaces`, its
  `vtiInterfaceMetadataList` holds one VTI, and a PUT with the field is also a silent no-op. No backup tunnel is
  built and the tool reports success. Fix: read the endpoint back and fail when the backup is missing; the payload
  FMC uses for a second spoke WAN in AUTO_VPN is still to be captured from the FMC 10 SD-WAN wizard (probably a
  second hub DVTI on another WAN plus one `vtiInterfaceMetadataList` entry per spoke WAN).
  **Follow-up (2026-10-18, live on mcp-sdwan-t1): a payload that works.** `vtiInterfaceMetadataList` is read-only
  (in `metadata`; a top-level one gets 422 "Unrecognized Field"), and each entry is one spoke VTI per
  (tunnel source, hub). The hub refuses `backupInterfaces` (400 "Backup interfaces should not be configured on hub
  devices"), a second HUB endpoint for the same device is refused (400 "This endpoint is already part of the
  topology"), and the spoke's `backupInterfaces` stays a no-op with a second hub DVTI in place. What works is a
  **second AUTO_VPN topology on the same hub**: a second DVTI sourced from the hub's `inet` with its own loopback
  and pool, and the spoke on `inet`, with the same iBGP AS and community. After one deploy the spoke has Tunnel1
  (mpls) and Tunnel2 (inet), two IKEv2 SAs, two iBGP neighbours (one per hub DVTI address) and ECMP routes over
  both; FMC merges both topologies into one `router bgp`. Failover: spoke1's `mpls` cable pulled -> the first
  ping round from the host behind spoke1 (started about 5 s later) lost nothing, the mpls neighbour went Idle and the
  routes stayed on the inet tunnel; 100% loss on `mpls` with the cable up -> no lost pings either, neighbour Idle
  within seconds (the WAN has path monitoring); both tunnels back about 20 s after the link returned. The tools now
  build it as the companion topology `<name>-wan2` (`hub_backup_wan_interface`, `backup_wan_pool`), recorded in
  `tests/fixtures/sdwan_backup_wan.json`. Not verified yet: a backup WAN together with a backup hub (the tools block
  that combination).
- **R2 `fmc_ftdsdwan_status` (and the C3/C5 evidence).** FMC 10.0.1's `operational/commands` refuses
  `show path-monitoring`, `show policy-route`, `show bgp summary` and `show bgp neighbors` (400 "Either command is
  not supported or entered command is an invalid command"), so the status never has path metrics: WAN health stays
  `unknown`, brownouts aren't detected, a PSK mismatch looks like a dead WAN. `show route bgp` and
  `show crypto ikev2 sa` work, and so does `show crypto ikev2 stats` (authentication failures: tells a PSK mismatch
  from a dead WAN; checked on T2). Fix: use the allowed commands (and health-monitor metrics if FMC exposes path
  monitoring there), and report "not available" rather than `unknown`. FMC's tunnel states also lag 2-3 minutes
  behind the devices, so the status should say how old they are. Also: `app_routes[].name` is null and
  `path_now` stays on a tunnel that is down.
  Follow-up (2026-10-18): the health monitor has the numbers. `health/metrics` with `metric:pathmonitoring`
  (not `path_monitoring`, which returns an empty result) returns RTT/jitter (microseconds), loss (%), MOS and
  peer reachability per path-monitored interface, including VTIs. A CML brownout on t1-spoke1's MPLS link showed
  up as RTT 307 ms, loss 33 %, MOS 0 about 5 minutes after it started (the device's console had 287 ms / 23 %
  within a minute). The data was there under `Initial_Health_Policy` with `hm_pathmonitoring` disabled too; the
  run's devices now use `mcp-sdwan-health` (module on). `health/pathmonitoredinterfaces` holds the settings only
  (no status). `fmc_ftdsdwan_status` reads the metric (PR after 0.13.0).
- **R3 `fmc_configure_wan_interface` on a VTI** (`interface='<spoke tunnel>'`, `priority=1`,
  `path_monitoring='ip'`): PUT `devices/devicerecords/{id}/virtualtunnelinterfaces/{id}` -> 400 "Fields:
  { managementOnly } must be excluded from json payload." The tool echoes the GET body; for VTIs it must drop
  `managementOnly` (and other physical-only fields). Without it, app routes over tunnels can't be ordered by
  metric.
- **R4 minor.** `fmc_create_device_template` doesn't validate the description (FMC 500 "invalid characters" for
  parentheses); `fmc_apply_device_template` aborts in preview when the object-overrides read fails instead of
  reporting it; `fmc_api_call` previews show `manualPreSharedKey` in clear text.
- **R5 C2 OSPF (`fmc_create_ftdsdwan_topology(overlay='ospf')` + `fmc_configure_ospf`).** The hub DVTI is unnumbered
  (it borrows a /32 loopback) while the spoke VTIs get numbered /24s from the pool. The hub's router LSA therefore
  carries an ifIndex as the link data of each point-to-point link, and the spokes mark the hub "Adv Router is
  not-reachable" (T2 evidence), so they install no OSPF routes while the hubs do. The OSPF interface API
  (`routing/ospfinterface`) has no network-type field in the 10.0.1 spec. Fix: `overlay='ospf'` should refuse (or warn
  in the preview) until a working addressing is found, e.g. unnumbered spoke VTIs or point-to-multipoint on both ends;
  BGP is the overlay FMC's AUTO_VPN supports.
  **Re-run (pass):** unnumbered spoke VTIs work. With `fmc_api_call`, POST a /32 loopback on each spoke and PUT the
  FMC-generated spoke VTI with `ipAddressAssignmentType: BORROW_IP_FROM_INTERFACE` and `borrowIPfrom: <loopback ref>`
  (no `managementOnly`); run OSPF over the hub's pool network, the spokes' loopback block and the inside networks. Both
  tunnel ends are then unnumbered, and the spokes install the OSPF routes. **Tool:** `overlay='ospf'` with
  `spoke_loopbacks` now creates the spoke loopbacks and switches the spoke VTIs after the endpoints exist (also for
  spokes added with `fmc_update_ftdsdwan_topology`); live pass on main 25d1ae7 (see "OSPF overlay with the tool on main").
- **R6 `fmc_update_ftdsdwan_topology(multipath=...)`.** The tool PUTs `policy/ftds2svpns/{id}` with the whole GET body
  minus `links`/`metadata`, so `ipsecSettings`, `ikeSettings`, `advancedSettings` and `endpoints` go along as nested
  references -> FMC 422 "Invalid value 'either need to be mapped to concrete types, have custom deserializer, or
  contain additional type information' for field 'ipsecSettings'". The PUT that works (sent with `fmc_api_call`) has
  only `id`, `name`, `type`, `topologyType`, `routeBased`, `ikeV1Enabled`, `ikeV2Enabled` and `autoVpnSettings` (the
  sub-resources have their own endpoints). Without it a dual-hub topology can't leave ECMP, and ECMP over two hubs
  breaks branch-to-DC traffic whenever the DC side routes through one hub.
- **R7 `fmc_ftdsdwan_status` with an HA-pair hub.** The hub row has `wan_links: []` and `tunnels: []` although the pair's
  `mpls` has path monitoring and two tunnels are up (FMC names the tunnel peer `<pair>[<active unit>]`, which isn't
  matched to the pair); `branch=<HA member>` answers "is in no SD-WAN topology"; a failed HA unit isn't reported. Fix:
  key hub rows by the pair and its members, and add the pair's failover state (`fmc_get_ha_status`) to the hub row.
- **R8 minor.** `fmc_api_call` timed out on the cluster POST although FMC had answered 202 Accepted (audit log) and
  went on to create the cluster; one `fmc_configure_wan_interface` preview hit a transient FMC 500 on GET
  `subinterfaces` ("Batch update returned unexpected row count") and worked on the retry.

- **R9 app routes ordered by a metric over VTIs (device behaviour, FTDv 10.0).** `fmc_create_app_route(order_by='rtt')`
  over two spoke tunnels deploys `set adaptive-interface rtt <tunnel1> <tunnel2>` and `show route-map` shows the live
  RTT of each tunnel, but the PBR lookup always returns the routing table's next hop: the ECMP hash with `multipath` on,
  the BGP best path with it off, even when that tunnel measures about 100 times the RTT of the other. FMC generated
  this line itself from the tool's request, so no tool payload bug has been found so far. Check it on a physical FTD
  or with TAC. Until then, failover on these labs comes from BGP over the second WAN
  tunnel (R1 payload), not from the app route. `fmc_ftdsdwan_status`'s `path_now` should not claim an egress the device
  doesn't use (it names the first listed tunnel when metrics are missing, even while it is down).

## Blockers

- **B1 device templates on FTDv for KVM.** `fmc_create_device_template(source_device=<spoke>)` -> FMC 400 "A
  template could not be generated from the device ... The version or model of the device is not supported."
  An empty template made from parameters exists, but every sub-resource read fails ("Node is not found: -1") and it
  can't be applied. C4 needs a supported hardware model (or a later FMC).
- **B2 T3 clustering (blocked, bounded attempt 03:05-03:50 UTC).** After the HA cells: `fmc_ha_action(action='break')`
  (SUCCESS), then `fmc_api_call` POST `deviceclusters/ftddevicecluster` with `action=CREATE_CLUSTER`,
  `clusterMode=INDIVIDUAL`, control = hub, data = hub2, `cclInterface` Ethernet0/5 (direct cable). FMC's checks on the
  way: the CCL IPs must be among the first 16 addresses of a CCL network that starts on a .0 (a /29 at .8 is refused),
  the VTEP network (`vniNetwork`) must be a /27, and the control unit may have no IPv4 on data interfaces (cleared
  and deployed first). The fourth POST was accepted (202 in the audit log; `fmc_api_call` itself timed out, R8), FMC
  created `mcp-sdwan-t3-cluster` and queued "Cluster create" (Deploy_Job_68), which stayed DEPLOYING with no device
  status for 35 minutes; both FTDv kept answering "Clustering is not configured" and logged nothing about it. A PUT
  `action=BREAK` on the record returned HTTP 500. So FTDv clustering doesn't come up on this FMC 10.0.1 + FTDv 10.0
  for KVM in CML. Left behind: the cluster record (DELETE was not tried, since it may unregister both hubs) and the
  hub's data interfaces without addresses; clean up in the FMC UI (Devices > the cluster > Break) or once the job
  times out.
- **B3 T3 HA pair can't be rebuilt (re-run, 2026-10-18).** The B2 cluster-create job (Deploy_Job_68, System) is still
  DEPLOYING, so FMC refuses every way out over REST: DELETE `deviceclusters/ftddevicecluster/<id>` -> 500 "Unable to
  delete cluster as FTD CLUSTER CREATE is in progress for device mcp-sdwan-t3-hub ... mcp-sdwan-t3-hub2", and
  `fmc_delete_device` on hub2 -> 400 "Cluster node ... cannot be unregistered because a deployment task is in progress
  for cluster 'mcp-sdwan-t3-cluster'" (the earlier PUT BREAK, PUT DELETE_CLUSTER and job abort also failed). The HA pair,
  and with it T3 C1/C2/C5 and the live check of the R7 fix, needs the cluster removed in the FMC UI or the job cleared
  by an FMC restart, which this run may not do.
- **Lab:** the IOL carriers' consoles are silent on this controller (they forward traffic fine), so carrier-side
  checks run from the FTDs.

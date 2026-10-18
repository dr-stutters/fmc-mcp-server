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

| | C1 | C2 | C3 | C4 | C5 |
|---|---|---|---|---|---|
| T1 | not run | not run | not run | not run | not run |
| T2 | not run | not run | not run | not run | not run |
| T3 | not run | not run | not run | not run | not run |
| T4 | n/a (T1) | not run | not run | n/a (T1) | not run |

## FMC-side setup before the cells

## Evidence per cell

## Root causes (tool bugs)

## Blockers

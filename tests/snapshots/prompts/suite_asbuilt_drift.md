# suite_asbuilt_drift

title: As-built drift: NetBox vs Catalyst Center
arguments: {"checks": "interfaces,cables", "device": "example", "servers": "example", "site": "branch-1"}

Has the documentation drifted from the wiring? Compares one site's NetBox interfaces, VLANs and cables
(the intent) with Catalyst Center's interfaces and CDP/LLDP topology (as built) and reports every
difference with the side to fix: NetBox (the record is stale), the network (the device or patching
departs from the intent) or a site visit (cannot tell from here). Needs both the NetBox and the
Catalyst Center server. Read-only: proposes fixes, applies none.

## user

This suite workflow uses these servers: netbox (NetBox), catc (Catalyst Center).
Skipped legs (server not connected); say so in the first lines of your answer:
- netbox leg skipped: server not connected; not checked: the documented intent (NetBox devices, interfaces, VLANs and cables).
- catc leg skipped: server not connected; not checked: the network as built (Catalyst Center devices, interfaces, VLANs and CDP/LLDP links).
None of these servers is connected, so there is nothing to run: say so and stop.

# suite_segmentation_audit

title: Segmentation audit across products
arguments: {"framework": "PCI DSS 4.0 req 1.3", "intent": "Corporate->IoT:tcp/443", "lab": "secure-branch", "segments": "IoT, Corporate", "servers": "example", "site": "br1"}

Can segment A reach segment B? Inventory the segments on every connected platform (SD-WAN service
VPNs, route leaking, data policy and edge firewall; ISE SGTs and the TrustSec egress matrix; FMC rules
between zones and networks; Catalyst Center SD-Access virtual networks and extranet policies), then per
segment pair: each layer's intended verdict with the tool it came from, the observed verdict from a live
CML reachability test, and a status (pass, leak, over-blocked, policy conflict, untested). Ends with an
evidence pack: a markdown report plus one JSON document. Skips the platforms whose server is not
connected and says so. Read-only.

## user

This suite workflow uses these servers: catsdwan (Catalyst SD-WAN Manager), ise (Cisco ISE), fmc (Secure Firewall Management Center), catc (Catalyst Center), cml (Cisco Modeling Labs).
Skipped legs (server not connected); say so in the first lines of your answer:
- catsdwan leg skipped: server not connected; not checked: SD-WAN service VPNs per edge, route leaking between them (control policy, OMP routes), and the data policy and edge firewall that permit or drop between them.
- ise leg skipped: server not connected; not checked: TrustSec: the SGTs, the IP-to-SGT mappings and the egress matrix (SGACL) between every SGT pair.
- fmc leg skipped: server not connected; not checked: FMC access rules between the segments' zones and networks, and the deciding rule per pair.
- catc leg skipped: server not connected; not checked: SD-Access virtual networks at the fabric site, their IP pools, extranet policies leaking between them, and the SGACLs a fabric edge enforces.
- cml leg skipped: server not connected; not checked: the observed verdict: a live reachability test from a test host in each segment to every other.
None of these servers is connected, so there is nothing to run: say so and stop.

# suite_change_check

title: Change check across products (pre/post)
arguments: {"before": "example", "change": "banner change on br1", "expected": "mcp-banner", "phase": "post", "servers": "example", "site": "br1"}

Did anything else break? Snapshot every connected product before a change (phase=pre), then compare
after it (phase=post): SD-WAN overlay, ISE authentication, Catalyst Center health and the firewalls, one
report of what changed by severity, expected effects apart, and configuration objects that changed
outside the change (snapshot config sections). Skips the products whose server is not connected and says
so. Read-only: the snapshots are kept in the conversation, never on a server.

## user

This suite workflow uses these servers: catsdwan (Catalyst SD-WAN Manager), ise (Cisco ISE), catc (Catalyst Center), fmc (Secure Firewall Management Center).
Skipped legs (server not connected); say so in the first lines of your answer:
- catsdwan leg skipped: server not connected; not checked: the SD-WAN overlay (BFD sessions, OMP peers, app-route SLA, control connections, alarms).
- ise leg skipped: server not connected; not checked: ISE (authentication and failure rates per NAD, node health, pxGrid clients).
- catc leg skipped: server not connected; not checked: Catalyst Center (device and site health, compliance, open issues).
- fmc leg skipped: server not connected; not checked: the firewalls (deployment state, HA, interface and VPN status).
None of these servers is connected, so there is nothing to run: say so and stop.

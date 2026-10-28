# suite_decommission_site

title: Decommission a site across products
arguments: {"dns_zone": "example.com", "servers": "example", "site": "br9", "subnets": "192.0.2.0/24, 198.51.100.0/26"}

Remove one site everywhere it exists, without leaving orphans: SD-WAN edges and their configuration
group association, ISE NADs and the site's location group, the Catalyst Center site with its devices,
fabric site and pool reservations, FMC network objects for the site's subnets, and the Windows DHCP scope
and DNS records. First an inventory per product (read-only), then a removal preview per product; each
product is removed only after the user approves its preview, one product at a time. Ends with a verify
pass that must come back empty. Never removes controllers or management appliances. Dangerous: deletes
devices and sites, no undo.

## user

This suite workflow uses these servers: catsdwan (Catalyst SD-WAN Manager), catc (Catalyst Center), ise (Cisco ISE), fmc (Secure Firewall Management Center), win (Windows Server (Active Directory)).
Skipped legs (server not connected); say so in the first lines of your answer:
- catsdwan leg skipped: server not connected; not checked: the site's WAN edges, their configuration group or device template, and their removal from the Manager.
- catc leg skipped: server not connected; not checked: the Catalyst Center site and its child sites, assigned devices, SD-Access fabric site and IP pool reservations.
- ise leg skipped: server not connected; not checked: the site's network devices (NADs) and its location network device group.
- fmc leg skipped: server not connected; not checked: FMC network objects and groups for the site's subnets and name, and what still references them.
- win leg skipped: server not connected; not checked: the site's DHCP scope (with leases and reservations) and its DNS records.
None of these servers is connected, so there is nothing to run: say so and stop.

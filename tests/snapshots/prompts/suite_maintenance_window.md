# suite_maintenance_window

title: Maintenance window across products
arguments: {"catc_image": "cat9k_iosxe.17.15.04.SPA.bin", "ise_patch": "3", "mode": "upgrade", "sdwan_version": "17.18.03", "servers": "example", "site": "br2", "window": "Sat 02:00-04:00"}

Run one maintenance window at a site across products: inventory what runs where, write one plan
(order, blast radius, rollback, go/no-go), take the pre snapshots, then upgrade product by product with
each product's preview-first upgrade tool: SD-WAN edges (install, activate), Catalyst Center switches
(SWIM distribute, then activate one device at a time) and the ISE patch check with a backup first (ISE
patches install from its GUI). Each product is compared against its pre snapshot before the next starts;
the window ends with a post compare on every product and one report. mode=stage copies images only (no
reload). Dangerous: devices reload.

## user

This suite workflow uses these servers: catsdwan (Catalyst SD-WAN Manager), catc (Catalyst Center), ise (Cisco ISE).
Skipped legs (server not connected); say so in the first lines of your answer:
- catsdwan leg skipped: server not connected; not checked: the site's WAN edges: software they run and have installed, the repository and release ceiling, and their install and activation.
- catc leg skipped: server not connected; not checked: the site's switches and other Catalyst Center devices: running image against the golden image, and SWIM distribution and activation.
- ise leg skipped: server not connected; not checked: the ISE patch level on every node, deployment health and a configuration backup before patching.
None of these servers is connected, so there is nothing to run: say so and stop.

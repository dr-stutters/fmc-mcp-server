# fmc_firewall_health_review

title: Firewall health review
arguments: {"compare_with": "example", "device": "mcp-ftd", "domain": "Global", "group": "example", "lookback_hours": "24"}

Is the firewall estate healthy? Reviews device health and connectivity (with CPU, memory,
throughput and drops over the review window for the devices that need it), HA pairs and
clusters, the deployment backlog and failed deployments, licences, software and VDB/SRU/LSP
content age, backups, certificate expiry, VPN tunnels and recent health alerts with the
aggregate tools, optionally configuration drift against a reference device, template or
stored export (compare_with), and writes one ranked report (critical, warning, info), each
finding with its evidence and a concrete next step. Read-only.

## user

Review the health of the devices of device group "example" whose name contains "mcp-ftd" in domain "Global" and of the FMC itself over the last
24 hours, and write one ranked report with next steps. Every step is read-only:
change, deploy or back up nothing; the report only proposes next steps.

FMC allows about 120 API requests per minute, and each tool call costs one or more. Call each
aggregate tool below once and drill into single devices only where a finding needs it: at most
10 per-device calls in all; report any further devices from the aggregate rows. Where several
devices need the same check, make it one fleet call (`fmc_run_show_command` with
devices=[...] or group=..., up to 25 devices, one row per device) instead of one call per device.
A tool that fails or times out is a finding of its own (a warning when it hides a whole check,
else info): note it and carry on.

1. Devices and connectivity: `fmc_list_device_groups` with group="example", domain="Global" (its members), then `fmc_list_devices` with name="mcp-ftd", domain="Global" for their rows. Note each device's health, connected, deployment
   status, version and access policy. A disconnected device is critical. For each device that is
   not green or not connected, `fmc_device_health` with device=<name>, domain="Global": the failing
   modules, their details and since when, and CPU/memory (above 90 % is a warning). A RED module
   is critical and a YELLOW one a warning, except an INTERFACE module saying an interface "is not
   receiving any packets": a warning on an idle link (a lab, an unused port), critical on one that
   should carry traffic. Say which you assumed. For a device that is not green, near its CPU or
   memory limit, or behind a finding in a later step (a down tunnel, an HA event, a burst of alerts),
   `fmc_device_metrics` with device=<name>, since="24h", domain="Global" shows its load
   over the review window: CPU and memory peaks with their times, throughput, connections and drops.
   A peak at the time of an alert ties them together; sustained CPU or memory above the limits the
   result flags is a finding of its own. These calls count towards the per-device limit; device="group:example" runs it on every device of the group (at most 10) in one call.

2. HA and clusters: `fmc_list_ha_pairs` with domain="Global" and `fmc_list_clusters` with domain="Global". For
   each HA pair with a unit in scope, `fmc_get_ha_status` with ha_pair=<name>, domain="Global". One
   Active and one Standby unit is healthy; no active unit, two active units, or a failed or
   unknown standby is critical. Only the management interface monitored is info. A cluster with a
   missing or disabled data node is critical. Each unit's own view, for every pair in scope in one
   call: `fmc_run_show_command` with devices=[the pairs], command='show failover state', domain="Global".

3. Deployments: `fmc_list_deployable_devices` with domain="Global". Keep only the rows of the group's devices whose name contains "mcp-ftd" (and, for alerts, the FMC's own). A device with pending changes
   is a warning (it doesn't run what FMC holds). For up to three of them,
   `fmc_pending_changes` with device=<name>, domain="Global" says what is waiting and who changed it
   (a 'System' UPDATE with "Data not available" is FMC housekeeping: info).
   Then `fmc_list_deployments` with since_hours=24, domain="Global". Keep only the rows of the group's devices whose name contains "mcp-ftd" (and, for alerts, the FMC's own). A FAILED
   job is critical while the device has had no successful deployment since; info once a later
   job succeeded.

4. Licences: `fmc_license_status`. UNREGISTERED, an authStatus other than AUTHORIZED
   (OUT_OF_COMPLIANCE, AUTHORIZATION_EXPIRED) or regStatus EVALUATION with evalExpiresInDays 0 is
   critical; evalUsed alone on a registered FMC is not. Any other EVALUATION is a warning: give
   evalExpiresInDays and the virtualAccount, and point at
   System > Licenses > Smart Licenses in the FMC UI. Device licences are
   listed by device UUID: match them to the names from step 1. A device in scope without a
   licence entry is a warning.

5. Software and content: `fmc_upgrade_status` with response_format="json", domain="Global". Devices on
   different versions, above all within one HA pair or cluster, are a warning; so is a device in
   maintenance mode. The VDB, SRU and LSP versions carry dates: content older than 30 days is a
   warning (updates are failing or not scheduled). Upgrade packages FMC already holds are info.

6. Backups: `fmc_list_backups` with domain="Global". No FMC backup, or none in the last 7 days, is a
   warning; the same for each device in scope. Give the newest date per device.

7. Certificates: `fmc_list_certificates` with expiring_within_days=90, domain="Global". Of the device rows keep those of the group's devices; the other certificates are FMC-wide. Each
   row has days_left and a severity: expired or within 30 days is critical, within 90 days a
   warning. A device enrolment whose deployment FAILED or whose identity or CA certificate is
   PENDING or NOT_AVAILABLE is at least a warning (its problems say why). Say what each one
   serves where the row shows it (a device enrolment: RA or site-to-site VPN on that device; a
   trusted CA: LDAPS, ISE/pxGrid or decryption trust; an internal certificate or CA: decryption or
   FMC's pxGrid client); for an internal certificate, internal CA or trusted CA that is due,
   `fmc_get_certificate` with certificate=<name>, domain="Global" shows what uses it (counts towards
   the per-device limit). FMC's bundled public roots are hidden; a bundled_roots_expiring count
   is info (FMC's updates replace them). The next step is a renewal: re-enrol or import the new
   certificate on FMC before days_left reaches 0.

8. VPN: `fmc_list_vpn_tunnels` with domain="Global". Keep only the rows of the group's devices whose name contains "mcp-ftd" (and, for alerts, the FMC's own). TUNNEL_DOWN is critical and UNKNOWN a
   warning; no tunnels at all is info. For the devices with such a tunnel, their own IKE view in
   one call: `fmc_run_show_command` with devices=[those devices], command='show crypto ikev2 sa', domain="Global"
   (a device that is not connected fails its row: that is the finding, not the tool).

9. Health alerts: `fmc_list_health_alerts` with since_minutes=1440, domain="Global". Keep only the rows of the group's devices whose name contains "mcp-ftd" (and, for alerts, the FMC's own).
   Repeats are collapsed with first/last seen and a count. An alert last seen in the last hour is
   current and counts at its level; older ones are history (info, unless the same alert keeps
   coming back). Note what the FMC reports about itself (Security Intelligence and Talos feeds,
   NTP, its own interfaces, processes restarting). APPLIANCE_HEARTBEAT means a device lost contact
   with FMC (critical while current). Only for a critical finding where you need to know what
   changed just before it: `fmc_recent_activity` with since_minutes=1440,
   device=<name>, domain="Global" (audit records and deployments around it).

10. Configuration drift against "example": `fmc_diff_device_config` with a=<device>, b="example", domain="Global"
   for each device in scope, at most three (each call reads both sides, about 30 requests per device).
   `b` may be another device or HA pair, a stored export or a device template. A difference in
   assigned policies, routing, NAT, VPN membership or interface zones is a warning (the device
   doesn't run what its reference does); addresses, VTI peers and object overrides that differ per
   site are info. Give each difference with its section, key and from/to values; `identical: true`
   is an info finding of its own. Sections under `not_compared` weren't checked: say which.

11. Report: one list, critical first, then warning, then info; within a level, what affects
   traffic (devices, HA, VPN and their certificates) comes before what affects management
   (licences, content, backups).
   Merge findings with one cause (a red device and its INTERFACE alerts). Each finding gives:
   - its level and a one-line title naming the device or the FMC;
   - evidence: the tool and the values it returned (status, module, count, dates);
   - the next step: a concrete action and the tool call to make, e.g.
     `fmc_device_health` with include_green=true, `fmc_run_show_command` with
     'show interface' or 'show failover', `fmc_pending_changes` then
     `fmc_deploy`, `fmc_backup_devices`, or an FMC UI step where no tool
     covers it.
   End with one line: counts per level, the devices reviewed and the checks that could not run.
   Mark which next steps change anything (deploys, backups): those are preview-first and run only
   after the user approves.

# fmc_replace_device

title: Replace an FTD (RMA)
arguments: {"copy_shared_policies": "true", "delete_old": "false", "domain": "Global/mcp-test-leaf", "new_host": "192.0.2.13", "new_name": "mcp-ftd3", "old_device": "mcp-ftd2", "old_reachable": "true"}

Replace a failed FTD (RMA) or clone one onto a new box with FMC's Copy Configuration: snapshot
the old unit (or export its record), register the new one, fmc_copy_device_config, match the
licences, deploy, compare the two configurations, prove the policy on the new unit, and
optionally unregister the old record. Every write is previewed and approved first.

## user

Replace FTD "mcp-ftd2" with a new unit "mcp-ftd3" at "192.0.2.13" (RMA, or a clone of the same box): FMC's
Copy Configuration procedure. Work through the steps in order and stop at the first failure. Every
write is preview-first: show each preview to the user and confirm only after they approve it.

0. Preconditions (read-only). `fmc_status`; `fmc_get_device` with device="mcp-ftd2", domain="Global/mcp-test-leaf":
   note its model, software version, licences, performance tier, access policy and whether it is in an
   HA pair or cluster. An HA unit or cluster node is not replaced this way: stop and say so (an HA
   RMA re-joins the new unit to the pair instead). `fmc_list_devices` with name="mcp-ftd3", domain="Global/mcp-test-leaf":
   if "mcp-ftd3" is already registered, go to step 3. The new FTD must run the same model and software
   version as "mcp-ftd2" (reimage or upgrade it first) and point at this FMC (`configure manager add
   <fmc> <reg_key>` on its CLI; the key is the server's FMC_FTD_REG_KEY, never typed here).

1. Before: `fmc_device_snapshot` with devices=["mcp-ftd2"], label="before rma", domain="Global/mcp-test-leaf"
   (routes, interfaces, tunnels, the deployed version; read-only). Keep the file or YAML: step 6
   compares the new unit with it.

2. Register the new unit: `fmc_register_device` with name="mcp-ftd3", host="192.0.2.13",
   access_policy=<"mcp-ftd2"'s access policy>, license_caps=<"mcp-ftd2"'s licences>,
   performance_tier=<"mcp-ftd2"'s tier, FTDv only>, domain="Global/mcp-test-leaf", wait=true. It waits for the registration and FMC's
   initial deployment; `fmc_get_device` with device="mcp-ftd3" must then be connected.

3. Copy the configuration: `fmc_copy_device_config` with source="mcp-ftd2", targets=["mcp-ftd3"],
   copy_shared_policies=true, domain="Global/mcp-test-leaf". Read the preview: no blockers (model and version match, "mcp-ftd3" is
   standalone), and `targets_lose` lists what "mcp-ftd3" gives up (a freshly registered unit has little).
   Confirm after approval; the result is FMC's finished task (or `fmc_get_task` with its id).

4. Licences: `fmc_get_device` with device="mcp-ftd3" and compare its licences with "mcp-ftd2"'s from
   step 0. Add any missing one with `fmc_set_device_licenses` with device="mcp-ftd3", add=[...], domain="Global/mcp-test-leaf".

5. Deploy: `fmc_pending_changes` with device="mcp-ftd3", domain="Global/mcp-test-leaf" (expect the copied interfaces, routes and
   policies), then `fmc_deploy` with devices=["mcp-ftd3"], wait=true, domain="Global/mcp-test-leaf". The new unit now uses the old
   unit's data-interface addresses: the old one must be off the network (or its interfaces down).

6. Compare: `fmc_diff_device_config` with a=<the step 1 snapshot or export>, b="mcp-ftd3", domain="Global/mcp-test-leaf". Expected
   differences are only the device's own: name, management address, serial and, for a clone,
   interface addresses. Any difference in routing, assigned policies, NAT or VPN membership is a
   failure: name its section and key.

7. Prove the policy: `fmc_prove_policy` with device="mcp-ftd3", domain="Global/mcp-test-leaf" and the flows the old unit carried
   (ask the user, or take them from the change record: inside to outside allowed, a blocked flow, a
   VPN flow), each with its expected verdict. Every row must be `pass`. When "mcp-ftd2" is still registered
   and reachable (a clone), run the same table with device="mcp-ftd2": both must give the same verdicts.

8. The old record "mcp-ftd2" stays (delete_old=false). Once the RMA is closed it can be
   removed with `fmc_delete_device` (dangerous); say so in the report.

9. Report: old and new unit (model, version, serial), each step with its result, the diff of step 6,
   the prove table of step 7, and what is left (licences, the old record, VPN peers to update).

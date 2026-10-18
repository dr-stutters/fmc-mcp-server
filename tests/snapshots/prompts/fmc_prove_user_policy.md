# fmc_prove_user_policy

title: Prove a user-based policy
arguments: {"allow_rule": "mcp-fw-allow-staff", "allowed_user": "alice", "block_rule": "mcp-fw-block-contractors", "blocked_user": "bob", "client_ip": "10.99.1.10", "destination": "192.0.2.80", "device": "mcp-ftd-identity", "port": "80", "protocol": "tcp"}

Prove that user-based access rules work: one client IP, one user who should reach a
destination and one who should not. Checks the configuration offline per user (fmc_rule_lookup
with identities), who ISE sees on the client, then has each user log in and proves the live
verdict with fmc_prove_policy (verdict, deciding rule and the user the firewall saw), and
reports a pass/fail table with the cause of any failure.

## user

Prove the user-based policy for one client: "alice" may reach "192.0.2.80" (tcp port 80) and "bob"
may not, from client "10.99.1.10". The firewall applies user rules from its live user-to-IP mapping (ISE/pxGrid,
passive AD or captive portal), so each user has to be logged in on "10.99.1.10" when their flow is traced. Steps 0-2,
4 and 5 are read-only; step 3 needs the users to log in and out (ask the operator, or in the lab run the
login/logoff actions); step 6 changes the policy only if the user asks and approves the preview. Keep a
table of what each step shows.

0. Context. The firewall is "mcp-ftd-identity". Note its access control policy (from `fmc_get_device`) and the
   identity policy linked to it (`fmc_get_identity_policy`): the identity rule must cover
   the client's zone and network with the realm that holds both users, or no user is ever seen.

1. What the configuration says, per user (offline): `fmc_rule_lookup` with device="mcp-ftd-identity",
   source="10.99.1.10", destination="192.0.2.80", protocol="tcp", port=80 and identities=["alice", <its groups>], then
   again with identities=["bob", <its groups>]. Group membership comes from AD (`fmc_get_realm`
   lists the downloaded users and groups). Expect "alice": a definite ALLOW rule; "bob": a BLOCK rule or the
   default action. If both give the same verdict the policy itself is wrong: stop and report it.

2. Who is on the client now: ISE's active sessions for "10.99.1.10" (`ise_find_session` or
   `ise_list_active_sessions`) show the user and whether the session reached FMC (pxGrid).

3. Live proof, one user at a time:
   a. With "alice" logged in on "10.99.1.10": `fmc_prove_policy` with flows=[{"source": "10.99.1.10", "destination": "192.0.2.80", "protocol": "tcp", "port": 80, "device": "mcp-ftd-identity", "user": "alice", "expect": "allow", "rule": "mcp-fw-allow-staff", "name": "alice allow"}].
   b. Log "alice" off and "bob" on (same client), wait until ISE shows "bob" on "10.99.1.10", then
      `fmc_prove_policy` with flows=[{"source": "10.99.1.10", "destination": "192.0.2.80", "protocol": "tcp", "port": 80, "device": "mcp-ftd-identity", "user": "bob", "expect": "block", "rule": "mcp-fw-block-contractors", "name": "bob block"}].
   Each row must be `pass`: the verdict matches, `user_seen` is the expected user, and (when given) the
   deciding rule is the expected one. `user_seen` empty or another user means the device's mapping is
   stale or missing: wait for ISE/pxGrid and retry once before calling it a failure.

4. If a row is fail or mismatch: `fmc_packet_tracer` with the same flow (verbose) shows every
   phase including Snort's identity phase; `fmc_get_hit_counts` on the deciding rule;
   `fmc_pending_changes` for the device (an undeployed user rule is the usual cause).

5. Report: a table per user with the offline verdict (step 1), the live verdict and deciding rule (step 3),
   the user the device saw, and pass/fail; then the cause of anything that failed and the evidence.

6. Fix (only if the user asks for one), preview-first: `fmc_update_access_rule` (users=[...] on
   the right rule, or move_to above the rule that wins) or `fmc_create_access_rule`; show the
   preview, wait for approval, confirm, `fmc_deploy` (preview-first), then rerun step 3.

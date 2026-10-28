# suite_access_review

title: Privileged access review across platforms
arguments: {"scope": "privileged", "servers": "example", "stale_days": "90"}

Who can change what, on every connected platform: admin accounts, roles and the external groups that
grant them on ISE, Catalyst Center, FMC, SD-WAN Manager and CML, with Active Directory resolving those
groups to people. One table of accounts (platform, role, source, enabled, last login) and one list of
findings: shared or generic admins, extra local admins, stale or disabled people still privileged,
groups that grant more than intended, external auth without a local fallback. Skips the platforms whose
server is not connected and says so. Read-only.

## user

This suite workflow uses these servers: ise (Cisco ISE), catc (Catalyst Center), fmc (Secure Firewall Management Center), catsdwan (Catalyst SD-WAN Manager), cml (Cisco Modeling Labs), win (Windows Server (Active Directory)).
Skipped legs (server not connected); say so in the first lines of your answer:
- ise leg skipped: server not connected; not checked: ISE admin accounts, admin groups, their RBAC menu and data access, and the AD groups mapped to them.
- catc leg skipped: server not connected; not checked: Catalyst Center users, roles and external authentication.
- fmc leg skipped: server not connected; not checked: FMC user accounts, roles and their permissions, external authentication (LDAP/RADIUS group maps).
- catsdwan leg skipped: server not connected; not checked: SD-WAN Manager users, user groups and AAA order (RADIUS/TACACS, local fallback).
- cml leg skipped: server not connected; not checked: CML users, admin rights and the authentication backend (local or LDAP).
- win leg skipped: server not connected; not checked: Active Directory: members of Domain Admins and of the AD groups the platforms map to admin roles.
None of these servers is connected, so there is nothing to run: say so and stop.

# Changelog

## 0.1.1 (2026-10-15)

- Requires stutters-mcp-core 0.1.1.
- `fmc_api_call` fills `{domainUUID}` in spec paths with the default domain (FMC_DOMAIN or the login's
  domain), so paths from `fmc_search_spec` work as-is.
- Missing credentials raise the core's AuthError (local ValueError workaround removed).
- Added `.dockerignore`; the image now includes LICENSE.

## 0.1.0 (2026-10-15)

First release, built on stutters-mcp-core 0.1.0 and tested against FMC 10.0.1.

- FMC client: token login with refresh (three refreshes, then a new login), single-flight, back-off
  after a failed login, rate limiter (110 requests/min, 8 concurrent), offset/limit paging, domain
  resolution by name or UUID, and an FMC error-message extractor.
- 30 read tools: status, domains, audit records, tasks, licensing, devices, interfaces, HA pairs,
  clusters, policies of every kind, flattened access, NAT and prefilter rules, policy assignments,
  objects, find-by-value, where-used, unused objects, offline rule lookup, shadowed rules, deployable
  devices, pending changes, deployment history, and spec search/definition/GET.
- 14 preview-first write tools for objects, groups, security zones, access policies and rules
  (with insert position and move), and NAT policies and rules.
- 6 dangerous tools (deploy with task polling, register/delete device, form/break/switch HA, delete
  policy), plus raw `fmc_api_call`.
- Dockerfile and docker-compose.yml (port 8035), lab seeding and fixture capture scripts.

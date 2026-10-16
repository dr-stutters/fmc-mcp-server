# Deploying fmc-mcp-server on a shared host

One container serves a team: each person gets their own token, the server is read-only until you decide
otherwise, TLS ends at a reverse proxy, and one server can reach several FMCs. Everything below is in
[`examples/shared-host/`](../examples/shared-host/); a laptop (stdio) setup is in the README quickstart.

FMC has two limits that shape a shared deployment, and both are **per FMC user / per FMC**, not per person:

- **One session per FMC user.** Every login (REST or web UI) ends that user's other sessions. Give each running
  server instance its **own FMC API user**: never the GUI `admin`, never a person's account, never the user of
  another integration (SOAR, ticketing, backup scripts...), and not the user of a second copy of this server.
- **About 120 API requests per minute per FMC**, shared by every API client of that FMC.

## 1. What is safe by default

| Setting | Default | What it means |
|---|---|---|
| `MCP_ENABLE_WRITES` | `false` | write tools (objects, rules, NAT, interfaces, routes, policy assignment...) are **not registered** |
| `MCP_ENABLE_DANGEROUS` | `false` | deploy and rollback, device registration and deletion, HA actions, policy deletes and raw non-GET `fmc_api_call`: not registered; needs writes on too |
| `MCP_AUTH_TOKENS` | none | the HTTP transport **refuses to start** without at least one token (or OAuth) |
| `MCP_DEFAULT_ROLE` | `ro` | once `MCP_ROLES` is set, a caller with no entry gets read tools only (without `MCP_ROLES` every token can use every enabled tier) |
| `FMC_VERIFY_SSL` | `true` | FMC's certificate is checked; set `FMC_CA_BUNDLE` for a private CA |
| `FMC_RATE_LIMIT` | `110` | requests per minute this server sends to one FMC, for all its callers together |

Turning on writes is two decisions: the server (`MCP_ENABLE_WRITES=true` in `.env`) and who may use them
(`MCP_ROLES`). Every write tool is preview-first: nothing changes until the caller repeats the call with the
confirm token, and nothing reaches a firewall before a deployment (dangerous tier). The shipped
`docker-compose.yml` no longer turns writes on (it did until 0.10); set them in `.env` if you want them. The
contract tests (`tests/unit/test_tier_defaults.py`) fail if a default or a shipped config turns writes on.

## 2. The FMC API user (least privilege, step by step)

Give the server its own FMC user with a custom role sized to the tiers you enable. Full permission list, the
reasons and the tools each permission unlocks: [least-privilege.md](least-privilege.md).

1. **Administration > Configuration > REST API Preferences**: make sure the REST API is enabled.
2. **Administration > Users > User Roles > Create User Role** `mcp-ro`: tick the view permissions in
   least-privilege.md §1 (Dashboard, Audit, the security and network policies, Objects, Devices, Secure
   Connections, Realms, Health, Packet Tracer + Modify Packet Tracer, Threat Defense CLI, Product Upgrades /
   Content Updates / Smart Licenses, View tickets). No *Modify* permission and no Deploy.
3. Only if you enable writes: **Create User Role** `mcp-rw` with everything in `mcp-ro` plus least-privilege.md
   §2 (the *Modify* permissions, **Deploy Configuration to Devices**, Modify tickets, Backup Management). The
   same role covers the dangerous tier: deploys, registration, HA and rollback need no Administration
   permission.
4. **Administration > Users > User Accounts > Create User**, e.g. `mcp-api-ro`: internal authentication, a
   long random password, *Maximum Number of Failed Logins* 5, no forced password reset, role `mcp-ro` only
   (`mcp-rw` for a server with writes; use a separate user such as `mcp-api-rw`). On a multi-domain FMC assign
   the role in every domain the server should see.
5. Keep the password out of `.env`: `FMC_PASSWORD_FILE=/run/secrets/fmc_password` (Docker secret) or
   `FMC_PASSWORD_REF=vault:...` (core `docs/PRODUCTION.md`, "Secrets").
6. Run the preflight; it logs in once and compares what the user can do with the enabled tiers:

   ```bash
   docker compose exec fmc-mcp-server fmc-mcp-server check
   ```

   `domains` fails when the user sees no domain (or `FMC_DOMAIN` doesn't exist). `role` fails when an enabled
   tier isn't allowed and warns when the user holds more than the server needs (an Administrator behind a
   read-only server). FMC shows a user's roles only to accounts with User Management, which `mcp-ro` / `mcp-rw`
   deliberately lack: then `role` is ok for a read-only server and warns "could not tell" when writes are on
   (compare the role with least-privilege.md yourself). `version` and `rate_limit` are described below.
   The check's login ends the server's own FMC session; the server simply logs in again on its next call.

`fmc_status` reports the same at run time (version, domains, API user, login count, rate limit).

## 3. Per-user tokens (names in the audit log)

Give each person their own token; the token's name is the caller identity in previews, the audit log and
roles. Never share one token.

```bash
docker run --rm ghcr.io/dr-stutters/fmc-mcp-server fmc-mcp-server token alice
# prints the token (give it to alice) and the line for the server:  alice:sha256:<hex>
```

Collect the lines in `MCP_AUTH_TOKENS=alice:sha256:...,bob:sha256:...` (or one per line in a file named by
`MCP_AUTH_TOKENS_FILE`). Revoke a person by deleting their entry and restarting. With writes on, say who may
use them:

```bash
MCP_ROLES=alice:rw,bob:ro,oncall-*:admin    # ro = read, rw = + write, admin = + dangerous (deploys)
```

The example writes the audit log to `/cache/fmc-audit.log` (rotated at 50 MB, 5 files): one JSON line per
call, e.g. `{"audit": {"event": "tool_call", "tool": "fmc_status", "caller": "alice", "args": {...},
"outcome": "ok"}}`, plus `preview` / `applied` events for writes. Ship it to your log platform, or set
`MCP_AUDIT_LOG=stderr` and use the container log driver.

FMC's own audit log (`fmc_list_audit_records`, System > Monitoring > Audit) names the **FMC API user** for every
change the server makes, whoever asked for it. The MCP audit log is where the person is recorded; keep both.

## 4. Several FMCs from one host

```bash
FMC_URL=https://fmc-prod.corp.example        # the default instance
FMC_USERNAME=mcp-api-ro
FMC_PASSWORD_FILE=/run/secrets/fmc_password
FMC_INSTANCES=dr                             # more FMCs, each with its own variables:
FMC_DR_URL=https://fmc-dr.corp.example
FMC_DR_USERNAME=mcp-api-ro
FMC_DR_PASSWORD_FILE=/run/secrets/fmc_dr_password
FMC_DR_CA_BUNDLE=/certs/dr-ca.pem            # URL, credentials and TLS are never inherited
FMC_DR_READ_ONLY=true                        # optional: block writes on this FMC only
```

Every tool then takes an optional `instance` argument (`default` or `dr`); `check` reports each FMC
(`--instance dr` for one). Each FMC has its own session, its own 120 requests/minute and its own limiter in
this server. One FMC with several domains is not several instances: use the `domain` argument (`FMC_DOMAIN`
for the default).

**One FMC API user per server instance.** If you run two copies of this server against the same FMC (say a
read-only one for the team and a write-enabled one for change windows), give each its own FMC user. Two
servers with the same user keep ending each other's sessions; each recovers by logging in again, but every
login costs requests and can lock the user out after too many failures.

## 5. The 120 requests/minute budget

FMC allows about 120 REST requests per minute **per FMC** (and 10 concurrent connections per source IP); above
that it answers 429. That budget is shared by every API user of the FMC, so this server leaves room for others:

- `FMC_RATE_LIMIT` (default `110`) and `FMC_MAX_CONCURRENCY` (default `8`) cap what this server sends to one
  FMC. The limiter is **shared by all callers** of the server: five people asking at once each wait their turn
  rather than each getting 110/minute. Lower it (e.g. `60`) when other integrations use the same FMC heavily.
  `check` reports the value in its `rate_limit` row and warns above 120.
- `MCP_CALLER_RATE_LIMIT` (core) caps tool calls per caller, so one person's agent can't use the whole budget.
- Prefer the aggregate tools: `fmc_status`, `fmc_recent_activity`, `fmc_rule_lookup`, `fmc_where_used`,
  `fmc_get_routing` or `fmc_export_access_rules` each answer with one tool call what would otherwise take dozens
  of small calls, and analysis tools reuse object catalogs for 60 seconds.
- The token is shared by all callers and refreshed rather than renewed, so logins don't eat the budget.

## 6. Change management (regulated sites)

FMC 7.6+ can require every configuration change to be made inside a **change-management ticket** that an
approver accepts before it can be deployed (Administration > Configuration > Change Management). The server
supports it (F22):

- `fmc_change_tickets` (read) shows whether change management is on, this API user's tickets and which ticket
  the server currently sends; with `ticket=...` it lists the ticket's changes and FMC's validation results.
- `fmc_ticket` (write) opens a ticket, submits it for approval, discards it (FMC reverts its changes) or
  releases it from the server. Approval itself happens in the FMC UI, by a person.
- `FMC_TICKET=CHG0012345` sends that ticket id (`ticket-id` header) with every request from the start, for
  example when the change number comes from your ITSM process.

Tickets belong to the FMC user, and this server has one FMC user: an open ticket is used for **every caller's**
changes until it is submitted or released. On a regulated site:

1. Run a read-only server for the team and a separate write-enabled server (its own FMC user, `mcp-rw`) that only
   the change implementers can reach (`MCP_ROLES`).
2. Implementer opens the ticket named after the approved change (`fmc_ticket action=open name=CHG...`), makes the
   changes (each one previewed and confirmed, and recorded with the caller's name in the MCP audit log), checks
   `fmc_change_tickets ticket=CHG...` and submits it.
3. The approver approves in FMC; then deploy (dangerous tier, `FMC_DEPLOY_WINDOW` and
   `MCP_BLAST_RADIUS_OVERRIDES` as in the README "Deploy safety rails").

The role needs *View tickets* (read) and *Modify tickets* (write) for this (least-privilege.md).

## 7. TLS with a reverse proxy (Caddy)

The server speaks plain HTTP inside the compose network; Caddy terminates TLS on 443:

```bash
cd examples/shared-host
cp .env.example .env && chmod 600 .env       # fill in FMC, tokens, MCP_HOSTNAME
docker compose up -d
curl https://mcp-fmc.corp.example/health     # {"status":"ok"}
```

- `MCP_HOSTNAME=mcp-fmc.corp.example` and `CADDY_TLS=you@corp.example`: a public name gets a Let's Encrypt
  certificate (ports 80/443 reachable from the internet).
- An internal name: `CADDY_TLS=internal` (Caddy's own CA; copy `/data/caddy/pki/authorities/local/root.crt`
  from the `caddy-data` volume to clients) or mount your own certificate and put
  `tls /certs/mcp.crt /certs/mcp.key` in the `Caddyfile`.
- The MCP server port is not published; only Caddy is. `flush_interval -1` keeps streamed responses flowing.

Clients then use `https://mcp-fmc.corp.example/mcp` with `Authorization: Bearer <their token>`.

**Try it first without FMC:** `docker compose -f docker-compose.yml -f docker-compose.mock.yml up -d` starts two
mocked FMCs (`default`, `dr`) and a demo token (`mock-alice-token`); `docker compose -f docker-compose.yml -f
docker-compose.mock.yml exec fmc-mcp-server fmc-mcp-server check` checks both, and
`curl -k https://localhost:8443/health` goes through Caddy.

## 8. Upgrades

- Images: `ghcr.io/dr-stutters/fmc-mcp-server:<version>` (and `:latest`); release candidates are
  `:<version>-rcN` and `:rc`, never `:latest`. Pin a version on a shared host (`MCP_IMAGE_TAG=0.11.0`), read the
  [CHANGELOG](../CHANGELOG.md), then `docker compose pull && docker compose up -d`.
- Verify what you run (keyless cosign signature from the release workflow, plus a signed SBOM):

  ```bash
  cosign verify ghcr.io/dr-stutters/fmc-mcp-server:0.11.0 \
    --certificate-identity-regexp '^https://github.com/dr-stutters/stutters-mcp-core/.github/workflows/publish-image.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-github-workflow-repository dr-stutters/fmc-mcp-server
  ```

- After an upgrade run `check` again; a release that needs a new FMC permission says so in the CHANGELOG.
- Roll back by setting `MCP_IMAGE_TAG` to the previous version. The server keeps no state besides the spec
  cache and the audit log (both in the `/cache` volume), so a rollback needs nothing else.
- Upgrading FMC: run `check`; `version` warns on a release outside the tested matrix (10.0 today; 7.2+ should
  work) and fails below 7.2. FMC upgrades can change role permissions: re-check the role against
  least-privilege.md.

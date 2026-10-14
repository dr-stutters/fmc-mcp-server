# fmc-mcp-server

An MCP server for **Cisco Secure Firewall Management Center (FMC)**. It lets an AI assistant read
and change FMC through its REST API: devices, HA pairs, access control and NAT policies, objects,
deployments and the audit log. It also has analysis tools that answer questions such as "which rule
would match this flow?", "where is this object used?" and "which rules are shadowed?".

It is built on [stutters-mcp-core](https://github.com/dr-stutters/stutters-mcp-core) and runs either
over stdio for a local client or as an authenticated Streamable HTTP service in a container.

> **Not affiliated with or endorsed by Cisco Systems, Inc.** Cisco, Firepower and Secure Firewall are
> trademarks of Cisco Systems, Inc.

Tested against **FMC 10.0.1** with a single domain. FMC 7.2 and later should work. Older versions
are best-effort.

## Safety model

| Tier | Enabled by | What it can do |
|---|---|---|
| read | always | All the tools under "Read" below. `fmc_api_call` is GET-only. |
| write | `MCP_ENABLE_WRITES=true` | Create, update and delete objects, groups, zones, access rules and NAT rules. |
| dangerous | `MCP_ENABLE_DANGEROUS=true` (also needs writes) | Deploy, register and delete devices, form and break HA pairs, delete whole policies, and send raw non-GET `fmc_api_call` requests. |

Every write is **preview-first**:

1. Calling a write tool without `confirm` changes nothing. It returns a preview and a single-use
   confirm token. The preview shows the exact request body, the field-by-field changes, the
   policies that use the object and the rule's position.
2. The assistant shows you the preview.
3. If you approve, the assistant repeats the identical call with `confirm=<token>`.

The token is refused if the arguments changed, or if the target changed on FMC after the preview
(for example, the object was edited or the rules were reordered).

Changes made in FMC reach the firewalls only after a **deployment** (`fmc_deploy`, dangerous tier).

## Tools

There are 50 tools when every tier is enabled: 30 read (29 when the dangerous tier turns `fmc_api_call` into a raw call), 14 write and 6 dangerous plus `fmc_api_call`.

**Read (30)**

| Area | Tools |
|---|---|
| System | `fmc_status`, `fmc_list_domains`, `fmc_list_audit_records`, `fmc_get_task`, `fmc_license_status` |
| Devices | `fmc_list_devices`, `fmc_get_device`, `fmc_list_device_interfaces`, `fmc_list_ha_pairs`, `fmc_list_clusters` |
| Policies | `fmc_list_policies`, `fmc_get_access_policy`, `fmc_list_access_rules`, `fmc_get_access_rule`, `fmc_list_nat_rules`, `fmc_list_prefilter_rules`, `fmc_list_policy_assignments` |
| Objects | `fmc_list_objects`, `fmc_get_object`, `fmc_find_object`, `fmc_where_used`, `fmc_unused_objects` |
| Analysis | `fmc_rule_lookup`, `fmc_shadowed_rules` |
| Deployment | `fmc_list_deployable_devices`, `fmc_pending_changes`, `fmc_list_deployments` |
| API spec | `fmc_search_spec`, `fmc_get_definition`, `fmc_api_call` (GET only) |

Notes on some read tools:

- `fmc_list_policies` covers access, NAT, prefilter, intrusion, file, platform settings, DNS,
  identity, decryption, health, FlexConfig and VPN policies.
- `fmc_find_object` finds objects by IP address, subnet or port.
- `fmc_rule_lookup` works out, offline, which access rule handles traffic from a source to a
  destination and port.

**Write (14)**

| Area | Tools |
|---|---|
| Objects | `fmc_create_object`, `fmc_update_object`, `fmc_delete_object`, `fmc_create_group`, `fmc_update_group`, `fmc_create_security_zone` |
| Access control | `fmc_create_access_policy`, `fmc_create_access_rule`, `fmc_update_access_rule`, `fmc_delete_access_rule` |
| NAT | `fmc_create_nat_policy`, `fmc_create_nat_rule`, `fmc_update_nat_rule`, `fmc_delete_nat_rule` |

`fmc_create_access_rule` takes a position (`insert_before` or `insert_after`), a section and a
category. `fmc_update_access_rule` can move a rule with `move_to`.

**Dangerous (6, plus raw `fmc_api_call`)**

| Tool | What it does |
|---|---|
| `fmc_deploy` | Deploys pending changes and waits for the deployment task to finish. |
| `fmc_register_device` | Registers a device with FMC. |
| `fmc_delete_device` | Removes a device from FMC. |
| `fmc_create_ha_pair` | Forms an HA pair. |
| `fmc_ha_action` | Breaks, switches or deletes an HA pair. |
| `fmc_delete_policy` | Deletes a whole policy. |

Tools accept **names or UUIDs**. Rule conditions accept object names or literal values:

- addresses, subnets and ranges: `10.1.1.0/24`, `10.1.1.1-10.1.1.9`
- ports and protocols: `tcp/443`, `udp/1000-2000`, `icmp/8`
- URLs: `https://...`

On multi-domain FMCs, pass `domain=` with a name such as `Global/Branch` or a UUID.

### Limits of `fmc_rule_lookup` and `fmc_shadowed_rules`

Both tools evaluate the access control policy offline. They resolve network and port objects,
including nested groups, to ranges, then walk the rules in order. The results are best-effort:

- They don't evaluate prefilter rules, NAT, Security Intelligence, decryption or rules inherited
  from a parent policy.
- Some rules depend on things that can't be known from addresses and ports: applications, URLs,
  users, SGTs, VLAN tags, dynamic objects and time ranges. These rules are reported as
  **conditional** ("may match first").
- FQDN objects and ICMP codes are not resolved, so rules that use them are also conditional.
- Zones are only checked when you pass `source_zone` or `destination_zone`.
- MONITOR rules are reported, but evaluation continues past them.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `FMC_URL` | (required) | FMC address, e.g. `https://fmc.example.com` |
| `FMC_USERNAME`, `FMC_PASSWORD` | (required) | The API account (see below) |
| `FMC_VERIFY_SSL` | `true` | Verify FMC's TLS certificate. Set `false` only in labs. |
| `FMC_CA_BUNDLE` | | CA file for FMC's certificate |
| `FMC_DOMAIN` | the login's domain | Default domain: a name (`Global/Branch`) or a UUID |
| `FMC_RATE_LIMIT` | `110` | Client-side requests per minute. FMC allows about 120 per source IP. |
| `FMC_MAX_CONCURRENCY` | `8` | Concurrent requests. FMC allows 10 per source IP. |
| `FMC_TIMEOUT`, `FMC_RETRIES` | `30`, `2` | Request timeout in seconds, and retries |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `MCP_HOST`, `MCP_PORT`, `MCP_PATH` | `0.0.0.0`, `8000`, `/mcp` | HTTP listener |
| `MCP_AUTH_TOKENS` / `MCP_AUTH_TOKENS_FILE` | | Required for HTTP: `name:sha256:<hex>` entries |
| `MCP_ENABLE_WRITES`, `MCP_ENABLE_DANGEROUS` | `false` | Tool tiers |
| `MCP_CONFIRM_TTL` | `600` | Seconds a confirm token stays valid |
| `MCP_TASK_TIMEOUT` | `600` | Seconds to wait for deployment, registration and HA tasks |
| `MCP_CACHE_DIR` | `~/.cache/fmc-mcp-server` | Cache for the indexed API spec. Set it to `""` to disable the cache. |
| `MCP_MAX_RESPONSE_CHARS` | `40000` | Maximum size of one tool response |
| `MCP_AUDIT_LOG`, `LOG_LEVEL` | `stderr`, `INFO` | Where the audit log goes, and the log level |

### Sessions and rate limits

FMC access tokens last 30 minutes and can be refreshed three times. **Every new login for a user can
end that user's other API sessions.** To avoid that, the server:

- logs in once and shares the token across concurrent requests;
- refreshes the token before it expires, and logs in again only when it has to;
- waits 30 seconds after a failed login before trying again, so bad credentials can't lock the
  account.

Give the server its **own FMC user**.

The client-side rate limiter keeps the server under FMC's per-source-IP limits.

### Least-privilege FMC account

Create a user for the server under **System > Users**, with a custom role:

- **Read only:** base the role on *Security Analyst (Read Only)*. It needs view access to devices,
  access control, intrusion, NAT and prefilter policies, the object manager and the audit log.
- **Writes:** add modify rights for *Object Manager*, *Access Control Policy* and *NAT Policy*.
- **Dangerous tier:** also add *Deploy Configuration to Devices* and *Device Management*.

The REST API must be enabled under **System > Configuration > REST API Preferences**.

## Running

```bash
uv sync
cp .env.example .env && chmod 600 .env      # set FMC_URL, FMC_USERNAME, FMC_PASSWORD
uv run fmc-mcp-server check                 # connect and print fmc_status
uv run fmc-mcp-server                       # run the stdio server
```

### Claude Code over stdio

```bash
claude mcp add fmc \
  --env FMC_URL=https://fmc.example.com --env FMC_USERNAME=mcp-api --env FMC_PASSWORD=... \
  -- uvx --from git+https://github.com/dr-stutters/fmc-mcp-server fmc-mcp-server
```

### HTTP container

```bash
uv run fmc-mcp-server token alice   # prints a bearer token and its MCP_AUTH_TOKENS entry
# add MCP_AUTH_TOKENS=alice:sha256:... to .env
CORE_READ_TOKEN=$(gh auth token) docker compose up -d --build
curl http://localhost:8035/health
```

The compose file:

- publishes port 8035;
- runs the container with a read-only root filesystem, no capabilities and a named volume for the
  spec cache;
- enables writes, and keeps the dangerous tier off.

Connect Claude Code to the container:

```bash
claude mcp add --transport http fmc http://<host>:8035/mcp --header "Authorization: Bearer <token>"
```

## Development

```bash
uv run ruff check && uv run ruff format --check && uv run mypy && uv run pytest
uv run python scripts/seed_lab.py          # create the mcp-test-* objects the live tests expect
uv run pytest tests/live -m live           # live tests; the whole run uses a single FMC login
uv run python scripts/capture_fixtures.py  # refresh the redacted fixtures in tests/fixtures
```

The live write tests create `mcp-test-w-*` objects and policies, then delete them.

Deployment, registration and HA can't be tested on a lab FMC with no managed devices. Unit tests
cover them with mocked FMC replies.

## License

MIT

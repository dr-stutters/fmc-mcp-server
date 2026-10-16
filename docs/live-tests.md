# Live tests

`tests/live` runs the tools against a real FMC (and, for most write tests, a managed FTD). Nothing there runs
in CI: `uv run pytest` only collects `tests/unit`.

```bash
uv run pytest tests/live -m live            # the whole run uses a single FMC login
uv run pytest tests/live -m live -rs        # also list why tests were skipped
```

Every test skips cleanly when what it needs is missing, and the skip reason names the variable:

- no `FMC_URL` / credentials in `.env`, or the FMC is unreachable: every test that talks to FMC;
- no read-only user (`FMC_RO_USERNAME` / `FMC_RO_PASSWORD`, role `mcp-ro` from
  [least-privilege.md](least-privilege.md)): `test_least_privilege.py`;
- no `FMC_LIVE_*` value a test needs (below): that test.

## FMC_LIVE_* variables

Inputs that depend on your own FMC and FTD come from these variables, in the environment or in `.env` (see
`.env.example`). The values below are examples, not defaults.

| Variable | Example | Used by |
|---|---|---|
| `FMC_LIVE_DEVICE` | `ftd1` | FMC's name for the managed FTD the device tests use (registered under this name by `test_live_ftd.py`) |
| `FMC_LIVE_FTD_HOST` | `192.0.2.151` | The FTD's management address, for registration |
| `FMC_LIVE_FTD_REG_KEY` | `example-key` | The registration key given to `configure manager add` on the FTD |
| `FMC_LIVE_FTD_OUTSIDE_IP` | `192.0.2.155/24` | Address with prefix length the tests put on the FTD's outside interface Ethernet0/0 |
| `FMC_LIVE_FTD_GATEWAY` | `192.0.2.1` | Next hop of the default route on the outside interface |
| `FMC_LIVE_TRACE_TARGET` | `198.51.100.10` | A reachable address beyond the outside interface; packet tracer flows from the inside host go to it (TCP 23 is blocked, TCP 443 allowed) |
| `FMC_LIVE_PING_TARGET` | `192.0.2.1` | Optional (default `FMC_LIVE_FTD_GATEWAY`): ICMP/SI/prefilter target in the intrusion, Security Intelligence, prefilter and least-privilege tests |
| `FMC_LIVE_NTP_SERVER` | `192.0.2.1` | Optional (default `FMC_LIVE_FTD_GATEWAY`): NTP server in `test_live_platform_access.py` |
| `FMC_LIVE_FTD_NO_ARP_IP` | `192.0.2.199` | Optional: an unused address on the outside subnet; adds the "no ARP entry" case to the `fmc_why_blocked` test |
| `FMC_LIVE_FTD_REREGISTER` | `1` | Optional: delete and re-register the FTD (then re-run `configure manager add` on it) |
| `FMC_LIVE_NO_PEER` | `1` | Optional: skip the BGP/OSPF test when there is no `peer1` router on the inside network |
| `FMC_LIVE_LEAF_DOMAIN` | `Global/mcp-test-leaf` | A leaf domain holding `FMC_LIVE_DEVICE`, for `test_live_multidomain.py` |
| `FMC_LIVE_REALM` | `mcp-test-ad` | An AD/LDAP realm already set up in FMC, for `test_live_identity.py` |
| `FMC_LIVE_REALM_GROUP` | `mcp-contractors` | A group in that realm (expected after a download; the group rule uses it) |
| `FMC_LIVE_IDENTITY_POLICY` | `mcp-test-idp` | An identity policy on the realm, selected in `mcp-test-ftd-acp` (FMC's REST API can't select it; use the access policy editor) |

The FTD tests (`needs_ftd`) need `FMC_LIVE_DEVICE`, `FMC_LIVE_FTD_HOST`, `FMC_LIVE_FTD_REG_KEY`,
`FMC_LIVE_FTD_OUTSIDE_IP`, `FMC_LIVE_FTD_GATEWAY` and `FMC_LIVE_TRACE_TARGET`.
`scripts/capture_fixtures.py --ftd` reads `FMC_LIVE_DEVICE` and `FMC_LIVE_TRACE_TARGET` from the environment.

## What the FTD tests expect

An FTDv (performance tier FTDv5) that already points at this FMC, with Ethernet0/0 as outside and Ethernet0/1
as inside. The inside side is fixed: `10.99.1.1/24` on the FTD, a host at `10.99.1.10` and, for the routing
test, a router `peer1` at `10.99.1.2` (AS 65001, loopbacks 172.31.1.1 in BGP and 172.31.2.1 in OSPF area 0).
The CML recipe `ftd-fmc` in [cml-mcp-server](https://github.com/dr-stutters/cml-mcp-server) builds this
topology. The tests create and keep their own `mcp-test-ftd-*` zones, objects and policies on the FMC.

## Seeded objects

`test_live_read.py`, `test_live_rule_io.py`, `test_least_privilege.py` and `scripts/capture_fixtures.py`
expect a fixed set of `mcp-test-*` objects and policies: hosts `mcp-test-web` (10.10.10.80), `mcp-test-db`
(10.10.20.5) and `mcp-test-unused` (10.99.99.99), networks, a range, port objects, groups, the zones
`mcp-test-inside` / `mcp-test-outside`, the access policy `mcp-test-acp` (allow, block, redundant and
shadowed rules) and the NAT policy `mcp-test-nat`. `tests/fixtures` holds recorded, redacted FMC replies for
that set. Without `mcp-test-acp` the read tests skip.

The live write tests create `mcp-test-w-*` objects and policies, then delete them.

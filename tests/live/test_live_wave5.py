"""Wave 5 read-only live proofs: the new read tools against a lab FMC, and preview parity for the new
write tools.

Nothing here changes FMC. Read tools are called as they are; write tools are called WITHOUT `confirm`, so
they only return a preview, and the test checks the body each would send against FMC's own API model (field
names and enum values from the spec the server ships) and, where the lab already holds the same kind of
object (created by hand or with fmc_api_call), against what FMC stored. A mismatch is a tool bug.

Inputs (environment or ./.env; a test whose inputs are unset is skipped, naming them):

- `FMC_LIVE_W5_DOMAIN` (`Global/leaf`): domain of every call (default FMC_LIVE_LEAF_DOMAIN, else the login's)
- `FMC_LIVE_W5_DEVICE` (`ftd-identity`): FTD the client sits behind; `FMC_LIVE_W5_ACP` is assigned to it
- `FMC_LIVE_W5_ACP` (`fw-threat-acp`): that FTD's access policy
- `FMC_LIVE_W5_CLIENT` (`192.0.2.100`): client address seeded into a host object, a network group, an
  access rule, a NAT rule (in a NAT policy assigned to no device) and a dynamic-object mapping
- `FMC_LIVE_W5_CLIENT_NET` (`192.0.2.0/24`): the client's subnet (an `inside` lookup)
- `FMC_LIVE_W5_SERVER` (`198.51.100.10`): server beyond the FTD; tcp/80 allowed, tcp/25 default-blocked
- `FMC_LIVE_W5_SEED` (`fw`): prefix of the seeded names `<seed>-client`, `-clients-grp`, `-find-client`,
  `-nat`, `-dyn`
- optional `FMC_LIVE_W5_HA_DEVICE` / `_HA_SRC` / `_HA_DST`: a tcp/80 flow through an HA pair's active unit
- optional `FMC_LIVE_W5_HA_PAIR`: HA pair for fmc_get_ha_status(live=True)
- optional `FMC_LIVE_W5_VPN_DEVICE`: a device for fmc_vpn_status
- optional `FMC_LIVE_W5_FEED_BASE` (`http://203.0.113.20`): serves ip-feed.txt, url-feed.txt, dns-feed.txt
- optional `FMC_LIVE_W5_EXPECT_CONNECTIONS=1`: the client has connections in the FTD's syslog buffer

Run: `uv run pytest tests/live/test_live_wave5.py -m live -s` (outputs are printed for the proof record).
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from .live_env import live_env, need

pytestmark = pytest.mark.live

API = "/api/fmc_config/v1/domain/{domainUUID}"


def domain() -> str | None:
    return live_env("FMC_LIVE_W5_DOMAIN") or live_env("FMC_LIVE_LEAF_DOMAIN") or None


def seed(suffix: str) -> str:
    return f"{live_env('FMC_LIVE_W5_SEED', 'mcp-fw')}-{suffix}"


UNSCOPED = {"fmc_status", "fmc_get_definition", "fmc_search_spec", "fmc_api_call"}


async def call(client: Client[Any], name: str, args: dict[str, Any], *, show: bool = True) -> Any:
    args = {**args}
    if domain() and "domain" not in args and name not in UNSCOPED:
        args["domain"] = domain()
    result = await client.call_tool(name, args)
    data = result.structured_content
    if data is None:
        data = json.loads(result.content[0].text)  # type: ignore[union-attr]
    if isinstance(data, dict) and set(data) == {"result"}:
        data = data["result"]
    if show:
        text = json.dumps(data, default=str)
        print(f"\n### {name} {json.dumps({k: v for k, v in args.items() if k != 'domain'})}\n{text[:6000]}")
    return data


async def tool_error(client: Client[Any], name: str, args: dict[str, Any]) -> str:
    """The error text of a call expected to fail (e.g. a missing permission)."""
    try:
        data = await call(client, name, args)
    except ToolError as e:
        print(f"\n### {name} -> error\n{e}")
        return str(e)
    return json.dumps(data, default=str)


# --- FMC model checks (spec only, no FMC request) ---------------------------------------------------


async def request_fields(client: Client[Any], operation: str) -> dict[str, str]:
    """request field -> description of an FMC operation, from the spec the server ships."""
    data = await call(client, "fmc_get_definition", {"name": operation}, show=False)
    ops = data["operations"] if isinstance(data, dict) and "operations" in data else [data]
    return dict(ops[0].get("request_fields") or {})


def allowed_values(description: str) -> set[str] | None:
    """Enum values named in a field description: 'enum: A|B' or '... (A, B, C).'"""
    m = re.search(r"enum: ([A-Za-z0-9_|]+)", description)
    if m:
        return set(m.group(1).split("|"))
    m = re.search(r"\(([A-Z0-9_]+(?:, [A-Z0-9_]+)+)\)", description)
    return set(m.group(1).split(", ")) if m else None


def model_problems(body: dict[str, Any], fields: dict[str, str]) -> list[str]:
    """Top-level keys the model doesn't know, and scalar/list values outside a field's enum."""
    problems = []
    for key, value in body.items():
        if key not in fields:
            problems.append(f"unknown field {key!r}")
            continue
        enum = allowed_values(fields[key])
        if enum is None:
            continue
        values = value if isinstance(value, list) else [value]
        for v in values:
            if isinstance(v, str) and v not in enum:
                problems.append(f"{key}={v!r} not in {sorted(enum)}")
    return problems


def preview_body(preview: dict[str, Any]) -> dict[str, Any]:
    assert preview.get("status") == "preview", preview
    assert "confirm" in preview  # never used: these tests don't apply anything
    body = preview["preview"].get("body")
    assert isinstance(body, dict), preview
    return body


async def get(client: Client[Any], path: str, **params: Any) -> Any:
    domain_uuid = await leaf_uuid(client)
    return await call(
        client,
        "fmc_api_call",
        {"method": "GET", "path": path.replace("{domainUUID}", domain_uuid), "params": params or None},
        show=False,
    )


_UUID: dict[str, str] = {}


async def leaf_uuid(client: Client[Any]) -> str:
    if "uuid" not in _UUID:
        status = await call(client, "fmc_status", {}, show=False)
        want = domain()
        for d in status["fmc"]["domains"]:
            if want in (d["name"], d["uuid"]) or (want is None and d == status["fmc"]["default_domain"]):
                _UUID["uuid"] = d["uuid"]
        _UUID.setdefault("uuid", status["fmc"]["default_domain"]["uuid"])
    return _UUID["uuid"]


async def by_name(client: Client[Any], path: str, name: str) -> dict[str, Any] | None:
    data = await get(client, path, expanded="true", limit=200)
    return next((i for i in data.get("items") or [] if i.get("name") == name), None)


# --- read tools ---------------------------------------------------------------------------------------


async def test_wave5_find_address(client: Client[Any]) -> None:
    """F59: one address across objects, a group, an access rule, a NAT rule (unassigned policy) and a
    dynamic-object mapping; then device-scoped (only that FTD's policies) and by the /24."""
    ip = need("FMC_LIVE_W5_CLIENT")
    out = await call(client, "fmc_find_address", {"address": ip, "response_format": "json"})
    rows = out["results"]
    text = json.dumps(rows)
    for name in (seed("client"), seed("clients-grp"), seed("find-client"), seed("dyn")):
        assert name in text, f"{name} missing from {text[:2000]}"
    areas = {r["area"] for r in rows}
    assert {"objects", "dynamic_objects", "access_rules", "nat_rules"} <= areas, areas
    exact = [r for r in rows if r["match"] == "exact"]
    assert exact and rows[0]["match"] == "exact", rows[:3]
    nat = [r for r in rows if r["area"] == "nat_rules"]
    assert any(seed("nat") in json.dumps(r) for r in nat), nat

    device = need("FMC_LIVE_W5_DEVICE")
    scoped = await call(
        client, "fmc_find_address", {"address": ip, "device": device, "response_format": "json"}
    )
    stext = json.dumps(scoped["results"])
    assert seed("find-client") in stext, stext[:2000]
    assert seed("nat") not in stext, "an unassigned NAT policy was searched for a device-scoped lookup"
    # The device's own NAT policy must be searched. FMC 10.0.1's assignment/policyassignments LIST can
    # leave out a NAT assignment that GET assignment/policyassignments/{policyId} shows, so ask per policy.
    nat_policies = await get(client, f"{API}/policy/ftdnatpolicies", limit=100)
    assigned = []
    for pol in nat_policies.get("items") or []:
        try:
            a = await get(client, f"{API}/assignment/policyassignments/{pol['id']}")
        except ToolError:  # 404: assigned to nothing
            continue
        if any(t.get("name") == device for t in a.get("targets") or []):
            assigned.append(pol["name"])
    print(f"### NAT policies assigned to {device} (per-policy GET): {assigned}")
    if assigned:
        assert scoped["searched"].get("nat_policies", 0) >= 1, (assigned, scoped["searched"])

    net = need("FMC_LIVE_W5_CLIENT_NET")
    wide = await call(
        client,
        "fmc_find_address",
        {"address": net, "areas": ["objects", "access_rules"], "response_format": "json"},
    )
    assert any(r["match"] in ("inside", "exact") for r in wide["results"]), wide["results"][:5]


async def test_wave5_live_connections(client: Client[Any]) -> None:
    """F55: connections of the client from the FTD's syslog buffer (needs buffer logging on the device), and
    the identity sessions read (FMC answers 403 when the role lacks Events & Logs > Analysis > Users)."""
    device = need("FMC_LIVE_W5_DEVICE")
    ip = need("FMC_LIVE_W5_CLIENT")
    out = await call(
        client, "fmc_live_connections", {"device": device, "host": ip, "response_format": "json"}
    )
    assert isinstance(out, dict), out
    if live_env("FMC_LIVE_W5_EXPECT_CONNECTIONS"):
        assert out.get("results"), out
        assert all(ip in json.dumps(r) for r in out["results"]), out["results"][:3]
    sessions = await tool_error(client, "fmc_user_identity_sessions", {"ip": ip, "response_format": "json"})
    assert sessions, sessions


async def test_wave5_device_metrics(client: Client[Any]) -> None:
    """F57: CPU / throughput series of the FTD over the last 30 minutes."""
    device = need("FMC_LIVE_W5_DEVICE")
    out = await call(client, "fmc_device_metrics", {"device": device, "since": "30m"})
    assert isinstance(out, dict) and out, out


async def test_wave5_vpn_status(client: Client[Any]) -> None:
    """F41: VPN status of one device (topologies it is in, FMC tunnel states, device view)."""
    device = need("FMC_LIVE_W5_VPN_DEVICE")
    out = await call(client, "fmc_vpn_status", {"device": device})
    assert isinstance(out, dict) and out, out


async def test_wave5_threat_posture(client: Client[Any]) -> None:
    """F62: the access policy's threat posture (IPS, file policy, SI, DNS, decryption, NAP, licences)."""
    acp = need("FMC_LIVE_W5_ACP")
    out = await call(client, "fmc_threat_posture", {"policy": acp})
    assert isinstance(out, dict) and out.get("findings") is not None, out


async def test_wave5_prove_policy(client: Client[Any]) -> None:
    """F56: packet-tracer proof table: an allowed flow and a default-block flow through the FTD (and one
    through the HA pair's active unit when given)."""
    device = need("FMC_LIVE_W5_DEVICE")
    src, dst = need("FMC_LIVE_W5_CLIENT"), need("FMC_LIVE_W5_SERVER")
    flows: list[dict[str, Any]] = [
        {
            "name": "http allowed",
            "source": src,
            "destination": dst,
            "protocol": "tcp",
            "port": 80,
            "expect": "allow",
        },
        {
            "name": "smtp blocked",
            "source": src,
            "destination": dst,
            "protocol": "tcp",
            "port": 25,
            "expect": "block",
        },
    ]
    ha = live_env("FMC_LIVE_W5_HA_DEVICE")
    if ha and live_env("FMC_LIVE_W5_HA_SRC") and live_env("FMC_LIVE_W5_HA_DST"):
        flows.append(
            {
                "name": "ha http allowed",
                "source": live_env("FMC_LIVE_W5_HA_SRC"),
                "destination": live_env("FMC_LIVE_W5_HA_DST"),
                "protocol": "tcp",
                "port": 80,
                "expect": "allow",
                "device": ha,
            }
        )
    out = await call(
        client, "fmc_prove_policy", {"flows": flows, "device": device, "response_format": "json"}
    )
    rows = out["results"]
    assert len(rows) == len(flows), rows
    by = {r["name"]: r for r in rows}
    assert by["http allowed"]["result"] == "pass", by["http allowed"]
    assert by["smtp blocked"]["result"] == "pass", by["smtp blocked"]
    if "ha http allowed" in by:
        assert by["ha http allowed"]["result"] == "pass", by["ha http allowed"]


async def test_wave5_ha_status_live(client: Client[Any]) -> None:
    """F65: HA status with the units' own view (show failover / state / history)."""
    pair = need("FMC_LIVE_W5_HA_PAIR")
    out = await call(client, "fmc_get_ha_status", {"ha_pair": pair, "live": True})
    text = json.dumps(out)
    assert "Active" in text and "Standby" in text, text[:2000]


async def test_wave5_tls_check_and_certificates(client: Client[Any]) -> None:
    """F64 reads: decryption check for client -> server:443 on the FTD, and the certificate listing."""
    device = need("FMC_LIVE_W5_DEVICE")
    out = await call(
        client,
        "fmc_tls_decryption_check",
        {"source": need("FMC_LIVE_W5_CLIENT"), "destination": need("FMC_LIVE_W5_SERVER"), "device": device},
    )
    assert isinstance(out, dict) and out, out
    certs = await call(client, "fmc_get_certificate", {"response_format": "json"})
    assert isinstance(certs, dict), certs
    every = await call(
        client,
        "fmc_get_certificate",
        {"kind": "trusted_ca", "include_system": True, "response_format": "json"},
        show=False,
    )
    rows = every["results"]
    meta = {k: v for k, v in every.items() if k != "results"}
    print(f"\n### trusted CAs incl. system: {len(rows)} rows; listing metadata: {meta}")
    # Every trusted CA FMC lists (names only: expanded pages carry the PEMs and outgrow fmc_api_call's
    # response cap) must be in the include_system listing.
    stored = await get(client, f"{API}/object/externalcacertificates", limit=1000)
    names = {c["name"] for c in stored.get("items") or []}
    missing = sorted(names - {r["name"] for r in rows})
    count = stored["paging"]["count"]
    print(f"### FMC lists {len(names)} trusted CAs (paging count {count}); not in the tool: {missing}")
    # The listing may be cut to fit the response budget; then it must say so (total / truncation note).
    assert not missing or every.get("total", len(rows)) > len(rows) or "truncat" in json.dumps(meta), missing


async def test_wave5_file_policy_reads(client: Client[Any]) -> None:
    """F43 reads: file policies (+ the type/category catalog) and network analysis policies."""
    out = await call(client, "fmc_get_file_policy", {"catalog": True, "response_format": "json"}, show=False)
    print(f"\n### fmc_get_file_policy catalog: {sorted(out)[:20]}")
    assert out, out
    naps = await call(client, "fmc_get_network_analysis_policy", {"response_format": "json"})
    assert naps, naps


async def test_wave5_si_reads(client: Client[Any]) -> None:
    """F61 reads: feeds and custom lists with status, and the access policy's SI view."""
    out = await call(client, "fmc_get_security_intelligence", {"response_format": "json"})
    for row in out.get("feeds") or []:
        assert row["kind"] in ("ip", "url", "dns") and row.get("status"), row
    acp = need("FMC_LIVE_W5_ACP")
    si = await call(client, "fmc_get_security_intelligence", {"policy": acp, "response_format": "json"})
    assert "network_block" in si, si


# --- write tools: preview parity (never confirmed) ----------------------------------------------------


async def test_wave5_parity_file_policy(client: Client[Any]) -> None:
    """F43: fmc_create_file_policy / fmc_create_file_rule previews against the FMC model; if the lab holds a
    file policy with a rule, the same rule's preview against FMC's stored rule."""
    pol = preview_body(
        await call(
            client, "fmc_create_file_policy", {"name": seed("file-parity"), "description": "preview only"}
        )
    )
    fields = await request_fields(client, f"POST {API}/policy/filepolicies")
    assert not model_problems(pol, fields), model_problems(pol, fields)

    stored = await get(client, f"{API}/policy/filepolicies", expanded="true", limit=50)
    policies = stored.get("items") or []
    if not policies:
        pytest.skip("no file policy in the domain to preview a file rule against")
    rfields = await request_fields(client, f"POST {API}/policy/filepolicies/{{containerUUID}}/filerules")
    for policy in policies:
        rules = await get(client, f"{API}/policy/filepolicies/{policy['id']}/filerules", expanded="true")
        for rule in rules.get("items") or []:
            action = rule["action"]
            tool_action, reset = {
                "DETECT": ("DETECT", False),
                "BLOCK": ("BLOCK", False),
                "BLOCK_WITH_RESET": ("BLOCK", True),
                "DETECT_MALWARE": ("MALWARE_CLOUD_LOOKUP", False),
                "BLOCK_MALWARE": ("BLOCK_MALWARE", False),
                "BLOCK_MALWARE_WITH_RESET": ("BLOCK_MALWARE", True),
            }[action]
            args: dict[str, Any] = {
                "policy": policy["name"],
                "action": tool_action,
                "reset": reset,
                "protocol": rule.get("protocol", "ANY"),
                "direction": rule.get("direction", "ANY"),
            }
            if rule.get("fileTypes"):
                args["file_types"] = [t["name"] for t in rule["fileTypes"]]
            if rule.get("fileCategories"):
                args["file_categories"] = [c["name"] for c in rule["fileCategories"]]
            print(f"\n### stored file rule in {policy['name']}: {json.dumps(rule)[:1500]}")
            preview = await call(client, "fmc_create_file_rule", args)
            if preview.get("status") == "blocked":
                print(f"preview blocked (e.g. duplicate rule): {preview.get('reasons')}")
                continue
            body = preview_body(preview)
            assert not model_problems(body, rfields), model_problems(body, rfields)
            assert body["action"] == action, (body["action"], action)
            for key in ("protocol", "direction"):
                assert body.get(key, "ANY") == rule.get(key, "ANY"), (key, body.get(key), rule.get(key))
            want = {t["id"] for t in rule.get("fileTypes") or []}
            got = {str(t["id"]) for t in body.get("fileTypes") or []}
            assert got == want, (got, want)
            return
    pytest.skip("the domain's file policies have no rules to compare with")


async def test_wave5_parity_url_categories(client: Client[Any]) -> None:
    """F63: access-rule preview with a URL category + reputation: categories resolve to FMC's
    object/urlcategories ids and the body follows the AccessRule model."""
    acp = need("FMC_LIVE_W5_ACP")
    cats = await get(client, f"{API}/object/urlcategories", limit=200)
    names = {c["name"]: c["id"] for c in cats.get("items") or []}
    category = "Malware Sites" if "Malware Sites" in names else sorted(names)[0]
    preview = await call(
        client,
        "fmc_create_access_rule",
        {
            "policy": acp,
            "name": seed("url-parity"),
            "action": "BLOCK_RESET",
            "url_categories": [{"category": category, "reputation": "ANY_AND_UNKNOWN"}],
            "insert_before": 1,
        },
    )
    body = preview_body(preview)
    fields = await request_fields(client, f"POST {API}/policy/accesspolicies/{{containerUUID}}/accessrules")
    assert not model_problems(body, fields), model_problems(body, fields)
    entries = body["urls"]["urlCategoriesWithReputation"]
    assert entries[0]["category"]["id"] == names[category], (entries, names[category])
    # A rule FMC stored with categories (created by hand / fmc_api_call): same shape as the preview.
    rules = await get(
        client,
        f"{API}/policy/accesspolicies/{(await acp_id(client, acp))}/accessrules",
        expanded="true",
        limit=200,
    )
    for rule in rules.get("items") or []:
        stored_entries = (rule.get("urls") or {}).get("urlCategoriesWithReputation")
        if stored_entries:
            print(f"\n### stored rule with categories {rule['name']}: {json.dumps(stored_entries)}")
            assert set(stored_entries[0]) >= set(entries[0]) - {"type"}, (stored_entries[0], entries[0])
            assert set(stored_entries[0]["category"]) >= {"id", "name"}, stored_entries[0]


async def acp_id(client: Client[Any], name: str) -> str:
    found = await by_name(client, f"{API}/policy/accesspolicies", name)
    assert found, name
    return str(found["id"])


async def test_wave5_parity_file_policy_on_rule(client: Client[Any]) -> None:
    """F43: fmc_update_access_rule(file_policy=...) preview puts filePolicy on an ALLOW rule (needs a file
    policy in the domain)."""
    acp = need("FMC_LIVE_W5_ACP")
    stored = await get(client, f"{API}/policy/filepolicies", limit=50)
    policies = stored.get("items") or []
    if not policies:
        pytest.skip("no file policy in the domain")
    rules = await call(
        client, "fmc_list_access_rules", {"policy": acp, "action": "ALLOW", "response_format": "json"}
    )
    rule = rules["results"][0]["name"]
    preview = await call(
        client, "fmc_update_access_rule", {"policy": acp, "rule": rule, "file_policy": policies[0]["name"]}
    )
    body = preview_body(preview)
    assert body["filePolicy"]["id"] == policies[0]["id"], body.get("filePolicy")
    assert body.get("logFiles") is True, body.get("logFiles")


async def test_wave5_parity_si(client: Client[Any]) -> None:
    """F61: SI feed / custom list / policy-list previews against the FMC models; feeds the lab already holds
    (created with fmc_api_call) against the preview for the same URL."""
    base = need("FMC_LIVE_W5_FEED_BASE").rstrip("/")
    kinds = {"ip": "sinetworkfeeds", "url": "siurlfeeds", "dns": "sidnsfeeds"}
    for kind, coll in kinds.items():
        preview = await call(
            client,
            "fmc_create_si_feed",
            {"kind": kind, "name": seed(f"{kind}-parity"), "url": f"{base}/{kind}-feed.txt", "refresh": 30},
        )
        body = preview_body(preview)
        fields = await request_fields(client, f"POST {API}/object/{coll}")
        assert not model_problems(body, fields), (kind, model_problems(body, fields))
        stored = await get(client, f"{API}/object/{coll}", expanded="true", limit=200)
        for feed in stored.get("items") or []:
            if feed.get("feedURL") == body.get("feedURL"):
                print(f"\n### stored {kind} feed: {json.dumps(feed)[:1500]}")
                for key in ("feedURL", "updateFrequency", "type"):
                    if key in body:
                        assert str(feed.get(key)) == str(body[key]), (kind, key, feed.get(key), body[key])
    lst = await call(
        client,
        "fmc_upload_si_list",
        {"kind": "ip", "name": seed("ip-list-parity"), "entries": ["192.0.2.66", "198.51.100.0/24"]},
    )
    assert lst.get("status") == "preview", lst
    acp = need("FMC_LIVE_W5_ACP")
    si = await call(client, "fmc_set_si_lists", {"policy": acp, "names": ["Malware"], "list_type": "block"})
    assert si.get("status") in ("preview", "blocked"), si


async def test_wave5_parity_nap_and_internal_ca(client: Client[Any]) -> None:
    """F43 / F64: network analysis policy and internal CA previews against the FMC models."""
    nap = preview_body(await call(client, "fmc_create_network_analysis_policy", {"name": seed("nap-parity")}))
    fields = await request_fields(client, f"POST {API}/policy/networkanalysispolicies")
    assert not model_problems(nap, fields), model_problems(nap, fields)
    ca = await call(
        client, "fmc_create_internal_ca", {"name": seed("ca-parity"), "common_name": seed("ca-parity")}
    )
    assert ca.get("status") == "preview", ca
    subject = ca["preview"]["subject"]  # the internal CA preview shows the subject, not the whole body
    cfields = await request_fields(client, f"POST {API}/object/internalcas")
    assert not model_problems(subject, cfields), model_problems(subject, cfields)


def test_wave5_inputs_are_addresses() -> None:
    """Guard: the address inputs parse (so a typo is not reported as a tool failure)."""
    for name in ("FMC_LIVE_W5_CLIENT", "FMC_LIVE_W5_SERVER"):
        value = live_env(name)
        if value:
            ipaddress.ip_address(value)
    if live_env("FMC_LIVE_W5_CLIENT_NET"):
        ipaddress.ip_network(live_env("FMC_LIVE_W5_CLIENT_NET"), strict=False)

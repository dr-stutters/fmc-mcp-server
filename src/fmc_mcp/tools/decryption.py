"""Decryption policy (F13 slice 2, F64, F82, F83): read decryption policies and their rules, create and
tune a policy (trusted CAs, TLS 1.3 decryption, untrusted server certificates, undecryptable actions,
default-action logging), add, change, move or delete rules (DECRYPT_RESIGN with an internal CA,
DECRYPT_KNOWN_KEY with a server's own certificate, DO_NOT_DECRYPT exemptions for banking or health sites,
BLOCK on old TLS versions or weak cipher suites), cipher suite list objects, and link a decryption policy to
an access control policy.

The certificate objects live in fmc_mcp.tools.pki; fmc_tls_decryption_check (decryption_check.py) explains
what happens to one flow; the cipher suite table is fmc_mcp.cipher_suites."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import BaseModel, ConfigDict, Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    UpstreamError,
    get_client,
    list_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.cipher_suites import PRESETS, SUITES, Suite, find_suite, suite_of_literal
from fmc_mcp.client import FmcApp
from fmc_mcp.preview import fmc_preview
from fmc_mcp.refs import RefResolver
from fmc_mcp.rules import app_labels, has_value, url_labels
from fmc_mcp.tools.common import Domain, block_labels, ref_label, resolve_in
from fmc_mcp.tools.object_writes import applied
from fmc_mcp.tools.pki import (
    KINDS,
    ca_problems,
    ref,
    resolve_cert,
    resolve_trusted,
    trusted_group,
)
from fmc_mcp.tools.policies import ACCESS, acp_settings_body, all_rules
from fmc_mcp.tools.policy_writes import NetsParam, PortsParam, UrlsParam, UsersParam, ZonesParam
from fmc_mcp.tools.render import object_reply

DECRYPTION = "policy/decryptionpolicies"
PolicyRef = Annotated[str, Field(description="Decryption policy name or UUID")]
DECRYPT_ACTIONS = ("DECRYPT_RESIGN", "DECRYPT_KNOWN_KEY", "DECRYPT_REPLACE_CERT")
RuleAction = Literal[
    "DO_NOT_DECRYPT", "DECRYPT_RESIGN", "DECRYPT_KNOWN_KEY", "BLOCK", "BLOCK_WITH_RESET", "MONITOR"
]
DefaultAction = Literal["DO_NOT_DECRYPT", "BLOCK", "BLOCK_WITH_RESET"]
# Rule conditions an offline check can't evaluate from addresses and ports.
CERT_CONDITIONS = (
    "subjectDNs",
    "issuerDNs",
    "certificateStatuses",
    "externalCertificates",
    "cipherSuiteLists",
    "tlsVersions",
    "clientThreat",
)
# Every TLS/SSL version. FMC 10.0.1 stores all five false for a rule created without `tlsVersions`, then
# refuses the deploy of DO_NOT_DECRYPT and DECRYPT_RESIGN rules that select versions ("Support for SSL
# Versions selection for Do not decrypt rule is deprecated", the same for Decrypt - Resign).
ALL_TLS_VERSIONS = {"sslv3": True, "tls10": True, "tls11": True, "tls12": True, "tls13": True}
NO_VERSION_SELECTION = {"DO_NOT_DECRYPT": "Do not decrypt", "DECRYPT_RESIGN": "Decrypt - Resign"}
TlsVersion = Literal["sslv3", "tls10", "tls11", "tls12", "tls13"]
CIPHER_LISTS = "object/ciphersuitelists"
BLOCKING = ("BLOCK", "BLOCK_WITH_RESET")
# Rule actions that take TLS version and cipher suite conditions (F82). FMC 10.0.1 accepts and deploys
# them on Block rules; it refuses version selection on Do-not-decrypt and Decrypt-Resign rules at deploy,
# and Cisco's guide says these conditions interfere with ClientHello processing in decrypt rules.
TLS_CONDITION_ACTIONS = ("BLOCK", "BLOCK_WITH_RESET", "MONITOR")
# FMC DecryptionPolicyUndecryptableActions, as (our name, FMC field, what it covers).
UNDECRYPTABLE = (
    ("compressed_session", "compressedSession", "compressed session"),
    ("sslv2_session", "sslV2Session", "SSLv2 session"),
    ("unknown_cipher_suite", "unknownCipherSuite", "unknown cipher suite"),
    ("unsupported_cipher_suite", "unsupportedCipherSuite", "unsupported cipher suite (RC4, for example)"),
    ("session_not_cached", "sessionNotCached", "session not cached"),
    ("handshake_errors", "handshakeErrors", "handshake errors"),
    ("decryption_errors", "decryptionErrors", "decryption errors"),
)
UndecryptableAction = Literal["INHERIT_DEFAULT_ACTION", "DO_NOT_DECRYPT", "BLOCK", "BLOCK_WITH_RESET"]


class Undecryptable(BaseModel):
    """What the FTD does with TLS sessions it can't decrypt (the policy's Undecryptable Actions); fields
    left out stay as they are. INHERIT_DEFAULT_ACTION = the policy's default action."""

    model_config = ConfigDict(extra="forbid")

    compressed_session: UndecryptableAction | None = Field(None, description="TLS compression is on")
    sslv2_session: UndecryptableAction | None = Field(None, description="SSLv2")
    unknown_cipher_suite: UndecryptableAction | None = Field(None, description="A suite FTD doesn't know")
    unsupported_cipher_suite: UndecryptableAction | None = Field(
        None,
        description="A suite FTD can't decrypt, such as RC4. With the default (inherit Do not decrypt), a "
        "Decrypt-Resign rule passes an RC4-only session undecrypted; BLOCK_WITH_RESET resets it",
    )
    session_not_cached: UndecryptableAction | None = Field(
        None, description="A resumed session FTD has no cached keys for"
    )
    handshake_errors: UndecryptableAction | None = Field(None, description="The TLS handshake fails")
    decryption_errors: Literal["BLOCK", "BLOCK_WITH_RESET"] | None = Field(
        None, description="Decryption fails mid-session (block only)"
    )


TrustedParam = Annotated[
    list[str] | None,
    Field(
        description="Trusted CA objects or groups (name or UUID; import with fmc_create_trusted_ca) the FTD "
        "accepts as server-certificate issuers, e.g. your internal PKI root or a lab server's CA"
    ),
]
Tls13Param = Annotated[
    bool | None,
    Field(
        description="Decrypt TLS 1.3 sessions (FMC advancedOptions.tls13Decryption). Off, TLS 1.3 traffic "
        "(curl and current browsers default to it) is not decrypted by the rules"
    ),
]
PropagateParam = Annotated[
    bool | None,
    Field(
        description="FMC disallowUntrustedIssuerResign: true = a server certificate whose issuer is not "
        "among the trusted CAs is not re-signed with the internal CA, so the client still sees an untrusted "
        "certificate (recommended); false = such servers are re-signed too and look trusted to clients"
    ),
]


def cert_conditions(r: dict[str, Any]) -> list[str]:
    """The certificate and TLS conditions that really narrow a rule (CERT_CONDITIONS keys).

    FMC 10.0.1 returns every rule with `certificateStatuses` (all ten statuses "ANY"), `tlsVersions` (five
    flags) and `clientThreat` "ANY", whether the rule uses them or not. A status block counts only when a
    status is YES or NO; a version block only when some versions are on and others off (all on = every
    version; all off is what FMC stores for a rule created without versions); a client threat level only
    when it isn't ANY."""
    out: list[str] = []
    for c in CERT_CONDITIONS:
        v = r.get(c)
        if c == "certificateStatuses":
            narrows = isinstance(v, dict) and any(str(s).upper() in ("YES", "NO") for s in v.values())
        elif c == "tlsVersions":
            flags = [f for f in v.values() if isinstance(f, bool)] if isinstance(v, dict) else []
            narrows = any(flags) and not all(flags)
        elif c == "clientThreat":
            narrows = isinstance(v, str) and v.upper() not in ("", "ANY")
        else:
            narrows = has_value(v)
        if narrows:
            out.append(c)
    return out


def rule_row(r: dict[str, Any]) -> dict[str, Any]:
    meta = r.get("metadata") or {}
    row = {
        "index": r.get("ruleIndex") or meta.get("ruleIndex"),
        "name": r.get("name"),
        "action": r.get("ruleAction"),
        "enabled": r.get("enabled"),
        "resign_ca": block_labels(r.get("decryptionCerts")) or None,
        "known_key_certs": block_labels(r.get("internalCerts")) or None,
        "replace_key_only": True if r.get("replacePublicKey") else None,
        "src_zones": block_labels(r.get("sourceZones")) or None,
        "dst_zones": block_labels(r.get("destinationZones")) or None,
        "src_networks": block_labels(r.get("sourceNetworks")) or None,
        "dst_networks": block_labels(r.get("destinationNetworks")) or None,
        "dst_ports": block_labels(r.get("destinationPorts")) or None,
        "users": block_labels(r.get("users")) or None,
        "applications": app_labels(r.get("applications")) or None,
        "urls": url_labels(r.get("urls")) or None,
        "tls_versions": versions_on(r),
        "cipher_suite_lists": block_labels(r.get("cipherSuiteLists")) or None,
        # the two above have their own keys
        "cert_conditions": [c for c in cert_conditions(r) if c not in ("tlsVersions", "cipherSuiteLists")]
        or None,
        "log": True if (r.get("logging") or {}).get("logEnd") else None,
        "id": r.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


def versions_on(r: dict[str, Any]) -> list[str] | None:
    """The TLS/SSL versions a rule is limited to, or None when it matches every version (all on; or all off,
    which is what FMC stores for a rule created without them)."""
    v = r.get("tlsVersions")
    if not isinstance(v, dict):
        return None
    on = [k for k in ALL_TLS_VERSIONS if v.get(k) is True]
    return on if on and len(on) < len(ALL_TLS_VERSIONS) else None


def tls_block(r: dict[str, Any]) -> bool:
    """An enabled Block rule with a TLS version or cipher suite condition."""
    return (
        r.get("enabled", True) is not False
        and r.get("ruleAction") in BLOCKING
        and bool(versions_on(r) or has_value(r.get("cipherSuiteLists")))
    )


def _zone_ids(block: Any) -> set[str]:
    objs = block.get("objects") if isinstance(block, dict) else None
    return {str(o.get("id") or o.get("name")) for o in objs or [] if isinstance(o, dict)}


def _port_ranges(block: Any) -> list[tuple[str, int, int]] | None:
    """A destinationPorts block as (protocol, low, high) ranges; None when it is empty or holds objects
    (or a literal without a port), which this check doesn't resolve."""
    if not isinstance(block, dict) or block.get("objects") or not block.get("literals"):
        return None
    out = []
    for lit in block["literals"]:
        lo, _, hi = str(lit.get("port") or "").partition("-")
        if not lo.isdigit() or not (hi or lo).isdigit():
            return None
        out.append((str(lit.get("protocol")), int(lo), int(hi or lo)))
    return out


def disjoint(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """True when no session can match both rules: both name source (or destination) zones and none is
    shared, or both list destination ports as literals and none overlaps. Anything else may overlap."""
    for field in ("sourceZones", "destinationZones"):
        za, zb = _zone_ids(a.get(field)), _zone_ids(b.get(field))
        if za and zb and not za & zb:
            return True
    pa, pb = _port_ranges(a.get("destinationPorts")), _port_ranges(b.get("destinationPorts"))
    if pa is not None and pb is not None:
        return not any(x[0] == y[0] and x[1] <= y[2] and y[1] <= x[2] for x in pa for y in pb)
    return False


def order_problems(rules: list[dict[str, Any]]) -> list[str]:
    """Decrypt rules above overlapping TLS version / cipher suite Block rules (F82 live finding: decryptable
    weak suites then pass decrypted and allowed)."""
    out = []
    live = [r for r in rules if r.get("enabled", True) is not False]
    for d in live:
        if d.get("ruleAction") not in DECRYPT_ACTIONS:
            continue
        below = [
            b for b in live if tls_block(b) and (_index(d) or 0) < (_index(b) or 0) and not disjoint(d, b)
        ]
        if below:
            out.append(
                f"{d.get('ruleAction')} rule {_index(d)} {d.get('name')!r} is above Block rule(s) "
                f"{_labels(below)} with TLS version or cipher suite conditions: the sessions it decrypts "
                "never reach them, so weak suites FTD can decrypt (3DES, RSA key exchange, CBC) pass "
                "decrypted and allowed. Put the Block rules first."
            )
    return out


def _labels(rules: list[dict[str, Any]]) -> str:
    return ", ".join(f"{_index(r)} {r.get('name')!r}" for r in rules)


def version_problem(r: dict[str, Any]) -> str | None:
    """Why FMC 10 will refuse to deploy this rule's TLS version selection, or None."""
    action = str(r.get("ruleAction") or "")
    v = r.get("tlsVersions")
    flags = {k: f for k, f in v.items() if isinstance(f, bool)} if isinstance(v, dict) else {}
    if action not in NO_VERSION_SELECTION or not flags or all(flags.values()):
        return None
    off = ", ".join(k for k, f in flags.items() if not f) + " off" if any(flags.values()) else "all off"
    return (
        f"{action} rule {r.get('name')!r} selects TLS/SSL versions ({off}; FMC stores all off for a rule "
        "created without them): FMC 10 refuses the deploy ('Support for SSL Versions selection for "
        f"{NO_VERSION_SELECTION[action]} rule is deprecated'). Turn every version on: "
        f"fmc_update_decryption_rule rule={r.get('name')!r} tls_versions=[]."
    )


def undecryptable_row(p: dict[str, Any]) -> dict[str, str]:
    """A policy's undecryptable actions under our names (FMC's values)."""
    u = p.get("undecryptableActions") or {}
    return {ours: str(u[fmc]) for ours, fmc, _ in UNDECRYPTABLE if u.get(fmc)}


def effective_undecryptable(p: dict[str, Any]) -> dict[str, str]:
    """What each undecryptable case really gets: INHERIT_DEFAULT_ACTION resolved to the default action."""
    default = (p.get("defaultAction") or {}).get("policyAction") or "DO_NOT_DECRYPT"
    return {k: (default if v == "INHERIT_DEFAULT_ACTION" else v) for k, v in undecryptable_row(p).items()}


def default_logged(p: dict[str, Any]) -> bool:
    """Whether the default action logs connections at their end: the policy's `logging` (FMC 10.0.1 keeps
    that) or defaultAction.eventLogAction (accepted on a PUT but stored as LOG_NONE)."""
    return bool((p.get("logging") or {}).get("logEnd")) or (
        (p.get("defaultAction") or {}).get("eventLogAction") == "LOG_FLOW_END"
    )


def advanced_row(p: dict[str, Any]) -> dict[str, Any]:
    adv = p.get("advancedOptions") or {}
    row = {
        "tls13_decryption": adv.get("tls13Decryption"),
        "propagate_untrusted_certs": adv.get("disallowUntrustedIssuerResign"),
        "quic_decryption": adv.get("quicDecryption"),
        "adaptive_probe": adv.get("adaptiveProbe"),
        "strip_http3": adv.get("stripHTTP3"),
    }
    return {k: v for k, v in row.items() if v is not None}


def trusted_labels(p: dict[str, Any]) -> list[str]:
    return [ref_label(r) for r in trusted_refs(p.get("trustedCAs"))]


def trusted_refs(t: Any) -> list[dict[str, Any]]:
    """A policy's trusted CAs as one reference list. FMC answers with `groups` and `objects` apart, but its
    request schema (TrustedCAs) has only `objects`, holding CA objects and CA groups alike."""
    if not isinstance(t, dict):
        return []
    out: list[dict[str, Any]] = []
    for r in (t.get("groups") or []) + (t.get("objects") or []):
        if isinstance(r, dict) and r.get("id") and all(r["id"] != o["id"] for o in out):
            out.append({f: v for f, v in r.items() if f != "links"})
    return out


def policy_body(p: dict[str, Any]) -> dict[str, Any]:
    """A decryption policy as FMC takes it back in a PUT (no metadata or links; trusted CAs in `objects`)."""
    body = acp_settings_body(p)
    if "trustedCAs" in body:
        body["trustedCAs"] = {"objects": trusted_refs(body["trustedCAs"])}
    return body


async def acps_using(app: FmcApp, policy_id: str | None, domain: str | None) -> dict[str, list[str]]:
    """Decryption policy id -> names of the access policies that use it."""
    page = await app.all(await app.config_path(ACCESS, domain))
    out: dict[str, list[str]] = {}
    for acp in page.items:
        link = acp.get("decryptionPolicySetting") or {}
        if link.get("id") and (policy_id is None or link["id"] == policy_id):
            out.setdefault(str(link["id"]), []).append(str(acp.get("name")))
    return out


async def readiness(
    app: FmcApp, p: dict[str, Any], rules: list[dict[str, Any]], domain: str | None
) -> list[str]:
    """What stands between this policy and working decrypt-resign / known-key rules."""
    notes: list[str] = []
    enabled = [r for r in rules if r.get("enabled", True)]
    decrypting = [r for r in enabled if r.get("ruleAction") in DECRYPT_ACTIONS]
    if decrypting and not (p.get("advancedOptions") or {}).get("tls13Decryption"):
        notes.append(
            f"TLS 1.3 decryption is off in {p.get('name')!r}: TLS 1.3 sessions are not decrypted "
            "(fmc_update_decryption_policy tls13_decryption=true)."
        )
    seen: set[str] = set()
    for r in decrypting:
        for o in ((r.get("decryptionCerts") or {}).get("objects") or [])[:5]:
            if not o.get("id") or o["id"] in seen:
                continue
            seen.add(o["id"])
            try:
                _, ca = await resolve_cert(app, str(o["id"]), [KINDS["internal_ca"]], domain)
            except NotFound:
                notes.append(
                    f"Rule {r.get('name')!r} re-signs with {ref_label(o)!r}, which no longer exists."
                )
                continue
            notes += [f"Rule {r.get('name')!r}: {m}" for m in ca_problems(ca)]
        if r.get("ruleAction") == "DECRYPT_RESIGN" and not (r.get("decryptionCerts") or {}).get("objects"):
            notes.append(f"DECRYPT_RESIGN rule {r.get('name')!r} has no internal CA.")
    notes += [m for m in (version_problem(r) for r in enabled) if m]
    notes += order_problems(rules)
    return notes


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Decryption policies")
    async def fmc_get_decryption_policy(
        ctx: Context,
        policy: Annotated[
            str | None, Field(description="Decryption policy name or UUID; omit to list all")
        ] = None,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List decryption (TLS/SSL) policies, or show one: mode, default action and its logging, trusted
        CAs, advanced options (TLS 1.3 decryption, untrusted server certificates), undecryptable actions, the
        access policies using it, its rules in order (DO_NOT_DECRYPT, DECRYPT_RESIGN with the internal CA,
        DECRYPT_KNOWN_KEY, BLOCK, with zones, networks, ports, users, URLs, TLS versions and cipher suite
        lists) and what keeps decryption or the TLS block rules from working (`readiness`)."""
        app: FmcApp = get_client(ctx)
        if not policy:
            page = await app.all(await app.config_path(DECRYPTION, domain))
            used = await acps_using(app, None, domain)
            rows = [
                {
                    "name": p.get("name"),
                    "mode": p.get("mode"),
                    "default_action": (p.get("defaultAction") or {}).get("policyAction"),
                    "used_by": ", ".join(used.get(str(p.get("id")), [])) or None,
                    "id": p.get("id"),
                }
                for p in page.items
            ]
            return list_result(page_of(rows, limit=1000, offset=0), fmt=response_format)
        p = await resolve_in(app, DECRYPTION, policy, "decryption policy", domain)
        rules = await all_rules(
            app, await app.config_path(f"{DECRYPTION}/{p['id']}/decryptionpolicyrules", domain)
        )
        out = {
            "name": p.get("name"),
            "mode": p.get("mode"),
            "default_action": (p.get("defaultAction") or {}).get("policyAction"),
            "default_log": default_logged(p),
            "trusted_cas": trusted_labels(p) or None,
            "advanced": advanced_row(p) or None,
            "undecryptable": undecryptable_row(p) or None,
            "used_by": (await acps_using(app, str(p["id"]), domain)).get(str(p["id"]), []),
            # FMC 10.0.1 lists rules in creation order, not by index
            "rules": [rule_row(r) for r in sorted(rules.items, key=lambda x: _index(x) or 1_000_000)],
            "readiness": await readiness(app, p, rules.items, domain),
            "id": p.get("id"),
        }
        return object_reply({k: v for k, v in out.items() if v is not None}, fmt=response_format)

    @reg.write(title="Create decryption policy")
    async def fmc_create_decryption_policy(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New policy name")],
        description: Annotated[str | None, Field(description="Description")] = None,
        default_action: Annotated[
            DefaultAction, Field(description="What happens to TLS traffic no rule matches")
        ] = "DO_NOT_DECRYPT",
        trusted_cas: TrustedParam = None,
        tls13_decryption: Tls13Param = None,
        propagate_untrusted_certs: PropagateParam = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a decryption policy (expert mode; default action do-not-decrypt unless given). It trusts
        FMC's Cisco-Trusted-Authorities group of public roots, plus `trusted_cas`. For decrypt-resign, turn
        on tls13_decryption, then add rules with fmc_create_decryption_rule (DO_NOT_DECRYPT exemptions
        first, then DECRYPT_RESIGN with an internal CA from fmc_create_internal_ca) and link it with
        fmc_set_decryption_policy. fmc_tls_decryption_check shows what a flow will get."""
        app: FmcApp = get_client(ctx)
        blockers = []
        try:
            await resolve_in(app, DECRYPTION, name, "decryption policy", domain)
            blockers.append(f"A decryption policy named {name!r} already exists.")
        except NotFound:
            pass
        body: dict[str, Any] = {
            "name": name,
            "type": "DecryptionPolicy",
            "defaultAction": {"policyAction": default_action, "eventLogAction": "LOG_NONE"},
        }
        if description:
            body["description"] = description
        if trusted_cas:
            extra = await resolve_trusted(app, trusted_cas, domain)
            group = await trusted_group(app, domain)
            refs = ([group] if group else []) + [e for e in extra if not group or e["id"] != group["id"]]
            body["trustedCAs"] = {"objects": refs}
        advanced = {
            k: v
            for k, v in (
                ("tls13Decryption", tls13_decryption),
                ("disallowUntrustedIssuerResign", propagate_untrusted_certs),
            )
            if v is not None
        }
        path = await app.config_path(DECRYPTION, domain)

        async def apply() -> Any:
            res = await app.api.post(path, body)
            if not advanced:
                return res
            # FMC fills the advanced options with its defaults on create; change only the ones given.
            item = f"{path}/{res['id']}"
            fresh = policy_body(await app.api.get(item))
            fresh["advancedOptions"] = {**(fresh.get("advancedOptions") or {}), **advanced}
            return await app.api.put(item, fresh)

        details: dict[str, Any] = {"body": body}
        if advanced:
            details["advanced"] = advanced
        return await fmc_preview(
            ctx,
            tool="fmc_create_decryption_policy",
            args={
                "name": name,
                "description": description,
                "default_action": default_action,
                "trusted_cas": trusted_cas,
                "tls13_decryption": tls13_decryption,
                "propagate_untrusted_certs": propagate_untrusted_certs,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(f"Create decryption policy {name!r}", details=details, blockers=blockers),
            apply=lambda: applied(app, apply),
        )

    @reg.write(title="Update decryption policy settings")
    async def fmc_update_decryption_policy(
        ctx: Context,
        policy: PolicyRef,
        default_action: Annotated[
            DefaultAction | None, Field(description="What happens to TLS traffic no rule matches")
        ] = None,
        add_trusted_cas: TrustedParam = None,
        remove_trusted_cas: Annotated[
            list[str] | None,
            Field(description="Trusted CA objects or groups to stop trusting (name or UUID)"),
        ] = None,
        tls13_decryption: Tls13Param = None,
        propagate_untrusted_certs: PropagateParam = None,
        undecryptable: Annotated[
            Undecryptable | None,
            Field(
                description="Undecryptable Actions to change, e.g. {'unsupported_cipher_suite': "
                "'BLOCK_WITH_RESET'} so RC4 sessions a Decrypt-Resign rule can't decrypt are reset"
            ),
        ] = None,
        default_log: Annotated[
            bool | None,
            Field(
                description="Log connections the default action handles, at their end, to FMC (the "
                "policy's logging logEnd and sendEvents; FMC 10.0.1 ignores defaultAction.eventLogAction)"
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a decryption policy's settings: default action and its logging, trusted CAs (the issuers
        the FTD accepts for server certificates; a private or lab server's CA must be here for its
        re-signed certificate to look trusted), TLS 1.3 decryption, how untrusted server certificates are
        handled, and the Undecryptable Actions (what happens to compressed or SSLv2 sessions, unknown or
        unsupported cipher suites such as RC4, uncached sessions, handshake and decryption errors). Rules are
        unchanged. Current settings: fmc_get_decryption_policy; the effect on one flow:
        fmc_tls_decryption_check. Takes effect after a deploy of the devices whose access policy uses it."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, DECRYPTION, policy, "decryption policy", domain)
        path = await app.config_path(f"{DECRYPTION}/{p['id']}", domain)
        cur = await app.api.get(path)
        desired = policy_body(cur)
        changes: dict[str, Any] = {}
        blockers: list[str] = []
        if cur.get("mode") == "STANDARD":
            blockers.append(
                f"{cur.get('name')!r} is a standard-mode policy; convert it to expert mode in the FMC UI "
                "first."
            )
        if default_action is not None:
            now = (cur.get("defaultAction") or {}).get("policyAction")
            if now != default_action:
                desired["defaultAction"] = {
                    **(cur.get("defaultAction") or {}),
                    "policyAction": default_action,
                }
                changes["default_action"] = {"from": now, "to": default_action}
        if add_trusted_cas or remove_trusted_cas:
            refs = trusted_refs(cur.get("trustedCAs"))
            before = trusted_labels(cur)
            for r in await resolve_trusted(app, add_trusted_cas or [], domain):
                if all(r["id"] != o.get("id") for o in refs):
                    refs.append(r)
            drop = {r["id"] for r in await resolve_trusted(app, remove_trusted_cas or [], domain)}
            refs = [r for r in refs if r.get("id") not in drop]
            desired["trustedCAs"] = {"objects": refs}
            after = trusted_labels(desired)
            if before != after:
                changes["trusted_cas"] = {"from": before, "to": after}
            if not after:
                blockers.append("That would leave the policy with no trusted CAs.")
        adv_now = cur.get("advancedOptions") or {}
        adv = dict(adv_now)
        for arg, field, value in (
            ("tls13_decryption", "tls13Decryption", tls13_decryption),
            ("propagate_untrusted_certs", "disallowUntrustedIssuerResign", propagate_untrusted_certs),
        ):
            if value is not None and adv_now.get(field) != value:
                adv[field] = value
                changes[arg] = {"from": adv_now.get(field), "to": value}
        desired["advancedOptions"] = adv
        if undecryptable is not None:
            u_now = cur.get("undecryptableActions") or {}
            u = dict(u_now)
            for ours, fmc, _ in UNDECRYPTABLE:
                value = getattr(undecryptable, ours)
                if value is not None and u_now.get(fmc) != value:
                    u[fmc] = value
                    changes.setdefault("undecryptable", {})[ours] = {"from": u_now.get(fmc), "to": value}
            desired["undecryptableActions"] = u
        if default_log is not None and default_log != default_logged(cur):
            desired["defaultAction"] = {
                **(desired.get("defaultAction") or {}),
                "eventLogAction": "LOG_FLOW_END" if default_log else "LOG_NONE",
            }
            desired["logging"] = {
                **(cur.get("logging") or {}),
                "logEnd": default_log,
                "sendEvents": default_log,
            }
            changes["default_log"] = {"from": default_logged(cur), "to": default_log}
        if not changes and not blockers:
            blockers.append("Nothing to change.")

        async def apply() -> Any:
            res = await app.api.put(path, desired)
            if "default_log" in changes and isinstance(res, dict) and default_logged(res) != default_log:
                res = {
                    **res,
                    "warning": f"FMC answered without default-action logging {'on' if default_log else 'off'}"
                    "; check it with fmc_get_decryption_policy.",
                }
            return res

        return await fmc_preview(
            ctx,
            tool="fmc_update_decryption_policy",
            args={
                "policy": policy,
                "default_action": default_action,
                "add_trusted_cas": add_trusted_cas,
                "remove_trusted_cas": remove_trusted_cas,
                "tls13_decryption": tls13_decryption,
                "propagate_untrusted_certs": propagate_untrusted_certs,
                "undecryptable": undecryptable.model_dump(exclude_none=True) if undecryptable else None,
                "default_log": default_log,
                "domain": domain,
            },
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Update decryption policy {cur.get('name')!r}",
                details={"changes": changes},
                fingerprint={"policy": p["id"], "current": policy_body(cur)},
                blockers=blockers,
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, apply),
        )

    @reg.write(title="Create decryption rule")
    async def fmc_create_decryption_rule(
        ctx: Context,
        policy: PolicyRef,
        name: Annotated[str, Field(min_length=1, max_length=50, description="Rule name")],
        action: Annotated[
            RuleAction,
            Field(
                description="DO_NOT_DECRYPT exempts the traffic (banking, health, pinned apps); "
                "DECRYPT_RESIGN decrypts outbound TLS, re-signing server certificates with internal_ca; "
                "DECRYPT_KNOWN_KEY decrypts inbound TLS to your own server with its certificate and key; "
                "BLOCK / BLOCK_WITH_RESET with tls_versions or cipher_suite_lists stop old TLS or weak "
                "suites without decrypting"
            ),
        ] = "DO_NOT_DECRYPT",
        internal_ca: Annotated[
            str | None,
            Field(
                description="DECRYPT_RESIGN: the internal CA (fmc_create_internal_ca / fmc_get_certificate)"
            ),
        ] = None,
        internal_certificates: Annotated[
            list[str] | None,
            Field(
                description="DECRYPT_KNOWN_KEY: the servers' internal certificates "
                "(fmc_import_certificate_files)"
            ),
        ] = None,
        replace_key_only: Annotated[
            bool,
            Field(
                description="DECRYPT_RESIGN only: replace just the public key, so a self-signed server "
                "certificate stays visibly self-signed to the client"
            ),
        ] = False,
        source_zones: ZonesParam = None,
        destination_zones: ZonesParam = None,
        source_networks: NetsParam = None,
        destination_networks: NetsParam = None,
        destination_ports: PortsParam = None,
        urls: UrlsParam = None,
        users: UsersParam = None,
        tls_versions: Annotated[
            list[TlsVersion] | None,
            Field(
                description="BLOCK, BLOCK_WITH_RESET or MONITOR only: match sessions the server negotiates "
                "with these versions, e.g. ['sslv3', 'tls10', 'tls11'] to block old TLS; default every "
                "version"
            ),
        ] = None,
        cipher_suite_lists: Annotated[
            list[str] | None,
            Field(
                description="BLOCK, BLOCK_WITH_RESET or MONITOR only: cipher suite list objects (name or "
                "UUID; fmc_create_cipher_suite_list). Matches the suite the server picks in its "
                "ServerHello, even when the client offered a strong one first"
            ),
        ] = None,
        insert_before: Annotated[
            int | None,
            Field(
                ge=1,
                description="Rule index to insert before (1 = first); default: the end. Put DO_NOT_DECRYPT "
                "exemptions and TLS version / cipher suite Block rules above the DECRYPT_RESIGN rules: "
                "rules match top-down",
            ),
        ] = None,
        log: Annotated[bool, Field(description="Log matching connections at their end to FMC")] = False,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a rule to a decryption policy (at the end, or before rule `insert_before`). DECRYPT_RESIGN
        needs an internal CA that clients trust. Block old TLS or weak cipher suites with a BLOCK_WITH_RESET
        rule and tls_versions or cipher_suite_lists (no decryption needed: FTD matches the server's
        ServerHello). The preview warns when the policy can't decrypt TLS 1.3, when an exemption would land
        below a decrypt rule, when a decrypt rule would sit above a TLS version / cipher suite Block rule
        (decryptable weak suites then pass decrypted), or when an existing rule's TLS version selection will
        make FMC refuse the deploy. Takes effect after a deploy of the devices whose access policy uses the
        decryption policy (fmc_set_decryption_policy)."""
        app: FmcApp = get_client(ctx)
        versions = [v for v in ALL_TLS_VERSIONS if v in (tls_versions or [])]
        if len(versions) == len(ALL_TLS_VERSIONS):
            versions = []  # all five = every version, no condition
        if (versions or cipher_suite_lists) and action not in TLS_CONDITION_ACTIONS:
            given = " and ".join(
                n for n, v in (("tls_versions", versions), ("cipher_suite_lists", cipher_suite_lists)) if v
            )
            raise InvalidRequest(
                f"{given} only go on BLOCK, BLOCK_WITH_RESET or MONITOR rules, not {action}: FMC 10 refuses "
                "to deploy a Do-not-decrypt or Decrypt-Resign rule that selects TLS versions, and Cisco's "
                "guide warns that version and cipher suite conditions on decrypt rules interfere with "
                "ClientHello processing. Add a BLOCK_WITH_RESET rule with the condition above the "
                f"{action} rule instead."
            )
        if internal_ca and action != "DECRYPT_RESIGN":
            raise InvalidRequest("internal_ca is only for action='DECRYPT_RESIGN'.")
        if internal_certificates and action != "DECRYPT_KNOWN_KEY":
            raise InvalidRequest("internal_certificates is only for action='DECRYPT_KNOWN_KEY'.")
        if replace_key_only and action != "DECRYPT_RESIGN":
            raise InvalidRequest("replace_key_only is only for action='DECRYPT_RESIGN'.")
        if action == "DECRYPT_KNOWN_KEY" and not internal_certificates:
            raise InvalidRequest(
                "DECRYPT_KNOWN_KEY needs internal_certificates (the server's certificate and key, imported "
                "with fmc_import_certificate_files)."
            )
        p = await resolve_in(app, DECRYPTION, policy, "decryption policy", domain)
        resolver = RefResolver(app, domain)
        body: dict[str, Any] = {
            "name": name,
            "type": "DecryptionPolicyRule",
            "ruleAction": action,
            "enabled": True,
            "tlsVersions": {v: v in versions for v in ALL_TLS_VERSIONS}
            if versions
            else dict(ALL_TLS_VERSIONS),
        }
        lists = [await cipher_list(app, c, domain) for c in cipher_suite_lists or []]
        if lists:
            body["cipherSuiteLists"] = {
                "objects": [{"id": c["id"], "name": c.get("name"), "type": "CipherSuiteList"} for c in lists]
            }
        for field, values, kind in (
            ("sourceZones", source_zones, "zone"),
            ("destinationZones", destination_zones, "zone"),
            ("sourceNetworks", source_networks, "network"),
            ("destinationNetworks", destination_networks, "network"),
            ("destinationPorts", destination_ports, "port"),
            ("urls", urls, "url"),
            ("users", users, "user"),
        ):
            block = await resolver.block(values, kind)
            if block:
                body[field] = block
        blockers: list[str] = []
        warnings: list[str] = []
        cert_fp: list[Any] = []
        if action == "DECRYPT_RESIGN":
            if not internal_ca:
                blockers.append(
                    "DECRYPT_RESIGN needs internal_ca: create one with fmc_create_internal_ca (or list "
                    "them with fmc_get_certificate kind='internal_ca')."
                )
            else:
                k, ca = await resolve_cert(app, internal_ca, [KINDS["internal_ca"]], domain)
                body["decryptionCerts"] = {"objects": [ref(ca, k)]}
                body["replacePublicKey"] = replace_key_only
                cert_fp.append(ca.get("certFingerprint"))
                for m in ca_problems(ca):
                    (warnings if " expires in " in m else blockers).append(m)
                warnings.append(
                    f"Clients must trust {ca.get('name')!r} (SHA-1 {ca.get('certFingerprint')}) or they get "
                    "certificate errors; fmc_get_certificate gives its PEM to install as a trusted root. "
                    "Apps that pin certificates break: exempt them with DO_NOT_DECRYPT rules above this one."
                )
            if not (p.get("advancedOptions") or {}).get("tls13Decryption"):
                warnings.append(
                    f"TLS 1.3 decryption is off in {p.get('name')!r}, so TLS 1.3 sessions won't be "
                    "decrypted: fmc_update_decryption_policy tls13_decryption=true."
                )
        if action == "DECRYPT_KNOWN_KEY":
            certs = []
            for c_ref in internal_certificates or []:
                k, c = await resolve_cert(app, c_ref, [KINDS["internal_cert"]], domain)
                certs.append(ref(c, k))
                cert_fp.append(c.get("certFingerprint"))
                for m in ca_problems(c):
                    (warnings if " expires in " in m else blockers).append(m)
            body["internalCerts"] = {"objects": certs}
        if log:
            body["logging"] = {"logEnd": True, "sendEvents": True}
        base = await app.config_path(f"{DECRYPTION}/{p['id']}/decryptionpolicyrules", domain)
        existing = await all_rules(app, base)
        if any(str(r.get("name", "")).lower() == name.lower() for r in existing.items):
            blockers.append(f"{p.get('name')!r} already has a rule named {name!r}.")
        warnings += [m for m in (version_problem(r) for r in existing.items if r.get("enabled", True)) if m]
        count = len(existing.items)
        if insert_before is not None and insert_before > count:
            blockers.append(
                f"insert_before={insert_before}, but {p.get('name')!r} has {count} rule(s); omit it to add "
                "the rule at the end."
            )
        match_all = not any(
            (
                source_zones,
                destination_zones,
                source_networks,
                destination_networks,
                destination_ports,
                urls,
                users,
                versions,
                lists,
            )
        )
        if match_all and action != "DO_NOT_DECRYPT":
            blockers.append(
                f"A {action} rule without conditions would match all TLS traffic; add a condition."
            )
        if tls_versions and not versions:
            warnings.append("tls_versions lists all five versions: that is every version, no condition.")
        position = insert_before or count + 1
        # the new rule takes `position`; existing rules from `position` on end up below it
        if action in DECRYPT_ACTIONS:
            below = [
                r
                for r in existing.items
                if tls_block(r) and (_index(r) or 0) >= position and not disjoint(body, r)
            ]
            if below:
                last = max(_index(r) or 0 for r in below)
                warnings.append(
                    f"This {action} rule lands at {position}, above Block rule(s) {_labels(below)} with TLS "
                    "version or cipher suite conditions: the sessions it decrypts never reach them, so weak "
                    "suites FTD can decrypt (3DES, RSA key exchange, CBC) pass decrypted and allowed. Put it "
                    + (
                        f"below them (insert_before={last + 1})."
                        if last < count
                        else "below them (omit insert_before to add it at the end)."
                    )
                )
        elif tls_block(body):
            above = [
                r
                for r in existing.items
                if r.get("enabled", True) is not False
                and r.get("ruleAction") in DECRYPT_ACTIONS
                and (_index(r) or 0) < position
                and not disjoint(body, r)
            ]
            if above:
                first = min(_index(r) or position for r in above)
                warnings.append(
                    f"This rule lands at {position}, below decrypt rule(s) {_labels(above)}: the sessions "
                    "they decrypt never reach it, so weak suites FTD can decrypt (3DES, RSA key exchange, "
                    f"CBC) pass decrypted and allowed. Use insert_before={first} to check it first."
                )
        if action in ("DO_NOT_DECRYPT", "MONITOR"):
            above = [
                rule_row(r)
                for r in existing.items
                if r.get("enabled", True)
                and r.get("ruleAction") in DECRYPT_ACTIONS
                and (_index(r) or 0) < position
            ]
            if above:
                labels = ", ".join(f"{a.get('index')} {a.get('name')!r}" for a in above)
                warnings.append(
                    f"Rules match top-down and this rule lands at {position}, below decrypt rule(s) "
                    f"{labels}: traffic they match is decrypted before reaching it. Use insert_before="
                    f"{min(a.get('index') or position for a in above)} to exempt it first."
                )
        where = f"before rule {insert_before}" if insert_before else "at the end"
        params = {"insertBefore": insert_before} if insert_before else None
        known = {r.get("id") for r in existing.items}

        async def create() -> Any:
            try:
                return await app.api.post(base, body, params=params)
            except UpstreamError as e:
                if (e.status_code or 0) < 500:
                    raise
                made = await created_anyway(app, base, name, known)
                if made is None:
                    raise
                return {
                    **made,
                    "warning": f"FMC answered {e.status_code} ({e}) but created the rule (FMC 10.0.1 does "
                    f"this for a POST with insertBefore); it is rule {_index(made)}. Check it with "
                    "fmc_get_decryption_policy; don't create it again.",
                }

        return await fmc_preview(
            ctx,
            tool="fmc_create_decryption_rule",
            args={
                "policy": policy,
                "name": name,
                "action": action,
                "internal_ca": internal_ca,
                "internal_certificates": internal_certificates,
                "replace_key_only": replace_key_only,
                "source_zones": source_zones,
                "destination_zones": destination_zones,
                "source_networks": source_networks,
                "destination_networks": destination_networks,
                "destination_ports": destination_ports,
                "urls": urls,
                "users": users,
                "tls_versions": tls_versions,
                "cipher_suite_lists": cipher_suite_lists,
                "insert_before": insert_before,
                "log": log,
                "domain": domain,
            },
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Add decryption rule {name!r} ({action}) to {p.get('name')!r} {where}",
                details={
                    "rule": rule_row(body),
                    # all versions on is no condition (FMC 10's default for rules without a selection)
                    "tls_versions": versions or "all",
                    "position": position,
                    "rules_now": count,
                },
                fingerprint={
                    "policy": p["id"],
                    "rules": [r.get("id") for r in existing.items],
                    "certs": cert_fp,
                    "cipher_suite_lists": [(c["id"], c.get("literals")) for c in lists],
                },
                blockers=blockers,
                side_effects=[*warnings, "Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, create),
        )

    @reg.write(title="Update decryption rule")
    async def fmc_update_decryption_rule(
        ctx: Context,
        policy: PolicyRef,
        rule: Annotated[str, Field(description="Rule name, UUID or 1-based index")],
        tls_versions: Annotated[
            list[TlsVersion] | None,
            Field(
                description="BLOCK, BLOCK_WITH_RESET or MONITOR rules: the versions to match, replacing the "
                "rule's, e.g. ['sslv3', 'tls10', 'tls11']; [] or all five = every version (no condition)"
            ),
        ] = None,
        cipher_suite_lists: Annotated[
            list[str] | None,
            Field(
                description="BLOCK, BLOCK_WITH_RESET or MONITOR rules: cipher suite list objects (name or "
                "UUID) replacing the rule's; [] removes the condition"
            ),
        ] = None,
        enabled: Annotated[bool | None, Field(description="Enable or disable the rule")] = None,
        log: Annotated[bool | None, Field(description="Log matching connections at their end to FMC")] = None,
        insert_before: Annotated[
            int | None,
            Field(
                ge=1,
                description="Move the rule just above the rule now at this index (1 = first; the rule "
                "count + 1 = the end)",
            ),
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change an existing decryption rule in place: its TLS versions and cipher suite lists (switch a
        Block rule to another list, narrow or widen the versions), enable or disable it, its logging, or
        move it (insert_before). Its action and other conditions stay; FMC's PUT gets the whole rule back.
        The preview shows each field from/to and the index, and warns when the result leaves a decrypt rule
        above an overlapping TLS version / cipher suite Block rule (decryptable weak suites then pass
        decrypted). A Do-not-decrypt or Decrypt-Resign rule FMC stored with no version selected (FMC 10
        refuses to deploy it) gets every version back. Current rules: fmc_get_decryption_policy. Takes
        effect after a deploy of the devices whose access policy uses the decryption policy."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, DECRYPTION, policy, "decryption policy", domain)
        base = await app.config_path(f"{DECRYPTION}/{p['id']}/decryptionpolicyrules", domain)
        existing = await all_rules(app, base)
        cur = find_rule(existing.items, rule, str(p.get("name")))
        action = str(cur.get("ruleAction") or "")
        versions = [v for v in ALL_TLS_VERSIONS if v in (tls_versions or [])]
        if len(versions) == len(ALL_TLS_VERSIONS):
            versions = []  # all five = every version, no condition
        if (versions or cipher_suite_lists) and action not in TLS_CONDITION_ACTIONS:
            given = " and ".join(
                n for n, v in (("tls_versions", versions), ("cipher_suite_lists", cipher_suite_lists)) if v
            )
            raise InvalidRequest(
                f"{given} only go on BLOCK, BLOCK_WITH_RESET or MONITOR rules; {cur.get('name')!r} is "
                f"{action}: FMC 10 refuses to deploy a Do-not-decrypt or Decrypt-Resign rule that selects "
                "TLS versions, and Cisco's guide warns that version and cipher suite conditions on decrypt "
                "rules interfere with ClientHello processing. Put the condition on a BLOCK_WITH_RESET rule "
                "above it (fmc_create_decryption_rule)."
            )
        desired = rule_body(cur)
        changes: dict[str, Any] = {}
        blockers: list[str] = []
        warnings: list[str] = []
        if tls_versions is not None:
            desired["tlsVersions"] = (
                {v: v in versions for v in ALL_TLS_VERSIONS} if versions else dict(ALL_TLS_VERSIONS)
            )
            if len(tls_versions) == len(ALL_TLS_VERSIONS):
                warnings.append("tls_versions lists all five versions: that is every version, no condition.")
        elif action in NO_VERSION_SELECTION and _versions_label(cur) == NONE_SELECTED:
            # what FMC stores for a rule created without tlsVersions: every version, but sent back as is the
            # deploy stays refused
            desired["tlsVersions"] = dict(ALL_TLS_VERSIONS)
            warnings.append(
                f"{cur.get('name')!r} has no TLS version selected (FMC stores that for a rule created "
                f"without versions, then refuses to deploy a {action} rule with it): the update sends every "
                "version."
            )
        if _versions_label(desired) != _versions_label(cur):
            changes["tls_versions"] = {"from": _versions_label(cur), "to": _versions_label(desired)}
        warnings += [m for m in [version_problem(desired)] if m]
        lists = [await cipher_list(app, c, domain) for c in cipher_suite_lists or []]
        if cipher_suite_lists is not None:
            if lists:
                desired["cipherSuiteLists"] = {
                    "objects": [
                        {"id": c["id"], "name": c.get("name"), "type": "CipherSuiteList"} for c in lists
                    ]
                }
            else:  # none = any suite, the empty block FMC 10.0.1 returns (and takes back) for it
                desired["cipherSuiteLists"] = {}
            if sorted(_list_ids(cur)) != sorted(_list_ids(desired)):
                changes["cipher_suite_lists"] = {
                    "from": block_labels(cur.get("cipherSuiteLists")),
                    "to": [c.get("name") for c in lists],
                }
        if enabled is not None and bool(cur.get("enabled", True)) != enabled:
            desired["enabled"] = enabled
            changes["enabled"] = {"from": bool(cur.get("enabled", True)), "to": enabled}
        logged = bool((cur.get("logging") or {}).get("logEnd"))
        if log is not None and log != logged:
            desired["logging"] = {**(cur.get("logging") or {}), "logEnd": log, "sendEvents": log}
            changes["log"] = {"from": logged, "to": log}
        count = len(existing.items)
        index = _index(cur) or count
        position = index
        params: dict[str, Any] | None = None
        if insert_before is not None:
            if insert_before > count + 1:
                blockers.append(
                    f"insert_before={insert_before}, but {p.get('name')!r} has {count} rule(s); "
                    f"insert_before={count + 1} moves the rule to the end."
                )
            elif insert_before < index:
                position, params = insert_before, {"insertBefore": insert_before}
            elif insert_before > index + 1:
                # after the rule now just above `insert_before`: indexes as they are before the move
                position, params = insert_before - 1, {"insertAfter": insert_before - 1}
            if params:
                changes["index"] = {"from": index, "to": position}
                anchor = next(
                    (r for r in existing.items if _index(r) == (params.get("insertBefore") or position)), None
                )
                here, there = _category(cur), _category(anchor)
                if anchor is not None and here != there:
                    blockers.append(
                        f"Rule {_index(anchor)} is in category {there!r} and {cur.get('name')!r} in "
                        f"{here!r}; moves stay within a category (delete and re-create the rule to "
                        "change it)."
                    )
        # a rule that already matches everything (a catch-all decrypt rule) can still be disabled or moved
        if changes and action != "DO_NOT_DECRYPT" and matches_all(desired) and not matches_all(cur):
            blockers.append(
                f"{cur.get('name')!r} ({action}) would have no condition left and match all TLS traffic."
            )
        if not changes and not blockers:
            blockers.append("Nothing to change.")
        after_rules = moved(existing.items, cur["id"], desired, position)
        name_ref = repr(cur.get("name"))
        warnings += [f"After this change: {m}" for m in order_problems(after_rules) if name_ref in m]
        item = f"{base}/{cur['id']}"

        async def apply() -> Any:
            failed: UpstreamError | None = None
            try:
                res = await app.api.put(item, desired, params=params)
            except UpstreamError as e:
                if (e.status_code or 0) < 500:
                    raise
                failed, res = e, await app.api.get(item)
            landed: int | None = None
            if params:
                rows = (await all_rules(app, base)).items
                landed = _index(next((r for r in rows if r.get("id") == cur["id"]), {}))
            if failed is not None:
                # FMC 10.0.1 answers 500 "JsonNull" to a PUT that moves the rule, and moves it: the answer
                # counts only when FMC holds the change and the rule sits where it should
                if not same_rule(res, desired) or (params and landed != position):
                    raise failed
                res = {
                    **res,
                    "warning": f"FMC answered {failed.status_code} ({failed}) but saved the change; check it "
                    "with fmc_get_decryption_policy.",
                }
            elif isinstance(res, dict) and res.get("id") and not same_rule(res, desired):
                res = {
                    **res,
                    "warning": "FMC's answer doesn't show the change; check the rule with "
                    "fmc_get_decryption_policy.",
                }
            if not params:
                return res
            res = {**(res if isinstance(res, dict) else {}), "index": landed}
            if landed != position:
                res["warning"] = (
                    f"{res.get('warning', '')} FMC put the rule at index {landed}, not {position}; check the "
                    "order with fmc_get_decryption_policy."
                ).strip()
            return res

        return await fmc_preview(
            ctx,
            tool="fmc_update_decryption_rule",
            args={
                "policy": policy,
                "rule": rule,
                "tls_versions": tls_versions,
                "cipher_suite_lists": cipher_suite_lists,
                "enabled": enabled,
                "log": log,
                "insert_before": insert_before,
                "domain": domain,
            },
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Update decryption rule {cur.get('name')!r} ({action}) in {p.get('name')!r}",
                details={"rule": rule_row(cur), "index": index, "changes": changes},
                # the rule, the policy's order (FMC lists by creation, so with indexes) and the lists' suites
                fingerprint={
                    "policy": p["id"],
                    "rule": rule_body(cur),
                    "order": [(r.get("id"), _index(r)) for r in existing.items],
                    "cipher_suite_lists": [(c["id"], c.get("literals")) for c in lists],
                },
                blockers=blockers,
                side_effects=[*warnings, "Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, apply),
        )

    @reg.write(title="Delete decryption rule", destructive=True)
    async def fmc_delete_decryption_rule(
        ctx: Context,
        policy: PolicyRef,
        rule: Annotated[str, Field(description="Rule name or UUID")],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete a decryption rule (after the next deploy, matching traffic follows the next rule or the
        default action)."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, DECRYPTION, policy, "decryption policy", domain)
        base = await app.config_path(f"{DECRYPTION}/{p['id']}/decryptionpolicyrules", domain)
        rules = await all_rules(app, base)
        hits = [
            r for r in rules.items if r.get("id") == rule or str(r.get("name", "")).lower() == rule.lower()
        ]
        if len(hits) != 1:
            raise NotFound(f"No single rule {rule!r} in {p.get('name')!r}.", 404)
        r = hits[0]
        return await fmc_preview(
            ctx,
            tool="fmc_delete_decryption_rule",
            args={"policy": policy, "rule": rule, "domain": domain},
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Delete decryption rule {r.get('name')!r} from {p.get('name')!r}",
                details={"rule": rule_row(r)},
                fingerprint=r.get("id"),
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(f"{base}/{r['id']}")),
        )

    @reg.write(title="Link decryption policy to access policy")
    async def fmc_set_decryption_policy(
        ctx: Context,
        access_policy: Annotated[str, Field(description="Access control policy name or UUID")],
        decryption_policy: Annotated[
            str,
            Field(
                description="Decryption policy name or UUID (FMC's API can't remove the link: '' is refused)"
            ),
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Make an access control policy use a decryption policy. Takes effect on the next deploy. FMC's
        API can't remove the link again ('' is refused with an explanation); a policy whose default action
        is DO_NOT_DECRYPT and has no rules decrypts nothing."""
        app: FmcApp = get_client(ctx)
        acp = await resolve_in(app, ACCESS, access_policy, "access policy", domain)
        target = (
            await resolve_in(app, DECRYPTION, decryption_policy, "decryption policy", domain)
            if decryption_policy
            else None
        )
        path = await app.config_path(f"{ACCESS}/{acp['id']}", domain)
        cur = await app.api.get(path)
        now = cur.get("decryptionPolicySetting") or {}
        blockers = ["Nothing to change."] if now.get("id") == (target or {}).get("id") else []
        if target is None and now:
            blockers = [
                "FMC's REST API can't remove an access policy's decryption policy (null is refused, "
                "omitting it keeps it). Link a policy whose default action is DO_NOT_DECRYPT instead, "
                "or remove it in the UI."
            ]

        async def apply() -> Any:
            fresh = await app.api.get(path)
            body = acp_settings_body(fresh)
            body["decryptionPolicySetting"] = (
                {"id": target["id"], "type": "DecryptionPolicy", "name": target.get("name")}
                if target
                else None
            )
            return await applied(app, lambda: app.api.put(path, body))

        return await fmc_preview(
            ctx,
            tool="fmc_set_decryption_policy",
            args={"access_policy": access_policy, "decryption_policy": decryption_policy, "domain": domain},
            confirm=confirm,
            owned=[acp],
            plan=Plan(
                f"{acp.get('name')!r} uses decryption policy {(target or {}).get('name') or 'none'}",
                details={"from": ref_label(now) if now else None, "to": (target or {}).get("name")},
                fingerprint={"current": now.get("id"), "target": (target or {}).get("id")},
                blockers=blockers,
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=apply,
        )

    @reg.read(title="Cipher suite lists")
    async def fmc_list_cipher_suite_lists(
        ctx: Context,
        name: Annotated[
            str | None, Field(description="One cipher suite list (name or UUID) to show in full")
        ] = None,
        known_suites: Annotated[
            bool,
            Field(
                description="List the suites this server can put in a list instead: IANA name, code, why it "
                "is weak, whether FMC 10.0.1 accepted it, and the presets"
            ),
        ] = False,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
        offset: Annotated[int, Field(ge=0)] = 0,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List cipher suite list objects (the Cipher Suite condition of decryption Block rules) with how
        many of their suites are weak and which strong ones they hold, or show one list's suites. With
        known_suites=true, the suites fmc_create_cipher_suite_list accepts and its `weak` preset."""
        app: FmcApp = get_client(ctx)
        if known_suites:
            rows = [
                {
                    "name": s.name,
                    "code": s.code,
                    "hex": f"0x{s.code:04X}",
                    "weak": s.weak,
                    "fmc_10_0_1": s.fmc or "not tried",
                    "weak_preset": True if s in PRESETS["weak"] else None,
                }
                for s in SUITES
            ]
            return list_result(page_of(rows, limit=limit, offset=offset), fmt=response_format)
        if name:
            c = await cipher_list(app, name, domain)
            suites = []
            for lit in c.get("literals") or []:
                s = suite_of_literal(lit)
                suites.append(
                    {
                        "name": lit.get("name"),
                        "code": lit.get("value"),
                        "weak": (s.weak or "no") if s else "unknown to this server",
                    }
                )
            return object_reply(
                {"name": c.get("name"), "suites": suites, "id": c.get("id")}, fmt=response_format
            )
        page = await app.all(await app.config_path(CIPHER_LISTS, domain))
        return list_result(
            page_of([list_row(c) for c in page.items], limit=limit, offset=offset), fmt=response_format
        )

    @reg.write(title="Create cipher suite list")
    async def fmc_create_cipher_suite_list(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New list name")],
        suites: Annotated[
            list[str] | None,
            Field(
                description="Cipher suites: IANA names (TLS_RSA_WITH_AES_128_CBC_SHA) or codes ('47', "
                "'0x002F'); fmc_list_cipher_suite_lists known_suites=true lists them"
            ),
        ] = None,
        preset: Annotated[
            Literal["weak"] | None,
            Field(
                description="'weak': the 23 weak suites FMC 10.0.1 accepts (NULL, EXPORT, DES, RC4, 3DES, "
                "RSA key exchange, CBC with SHA-1); `suites` are added to it"
            ),
        ] = None,
        description: Annotated[str | None, Field(description="Description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a cipher suite list object for the Cipher Suite condition of a decryption rule
        (fmc_create_decryption_rule action='BLOCK_WITH_RESET' cipher_suite_lists=[name]: blocks sessions
        whose server picks one of these suites, without decrypting). FMC refuses a suite outside its
        predefined set with 400 "The SHA is incorrect" and names none, so the preview checks each suite and
        names the bad ones."""
        app: FmcApp = get_client(ctx)
        chosen: list[Suite] = list(PRESETS[preset]) if preset else []
        unknown: list[str] = []
        for ref_ in suites or []:
            s = find_suite(ref_)
            if s is None:
                unknown.append(ref_)
            elif s not in chosen:
                chosen.append(s)
        blockers: list[str] = []
        warnings: list[str] = []
        try:
            await resolve_in(app, CIPHER_LISTS, name, "cipher suite list", domain)
            blockers.append(f"A cipher suite list named {name!r} already exists.")
        except NotFound:
            pass
        if unknown:
            blockers.append(
                f"Not a cipher suite this server knows: {', '.join(unknown)} (IANA names or codes; "
                "fmc_list_cipher_suite_lists known_suites=true)."
            )
        refused = [s.name for s in chosen if s.fmc == "refused"]
        if refused:
            blockers.append(
                f"FMC 10.0.1 refuses {', '.join(refused)} (not in its predefined suites): leave them out."
            )
        if not chosen and not unknown:
            blockers.append("Give suites or preset='weak'.")
        untried = [s.name for s in chosen if s.fmc is None]
        if untried:
            warnings.append(
                f"Not yet seen accepted by FMC 10.0.1: {', '.join(untried)}. If FMC answers 'The SHA is "
                "incorrect', one of them is outside its predefined set."
            )
        strong = [s.name for s in chosen if s.weak is None]
        if strong:
            warnings.append(
                f"Strong suites in the list: {', '.join(strong)}. A Block rule using it blocks sessions "
                "that negotiate them too."
            )
        body: dict[str, Any] = {
            "name": name,
            "type": "CipherSuiteList",
            "literals": [s.literal() for s in chosen],
        }
        if description:
            body["description"] = description
        path = await app.config_path(CIPHER_LISTS, domain)

        async def create() -> Any:
            try:
                return await app.api.post(path, body)
            except UpstreamError as e:
                if "SHA is incorrect" not in str(e):
                    raise
                hint = f" Suites not yet seen accepted: {', '.join(untried)}." if untried else ""
                raise UpstreamError(
                    f"{e} FMC refused a suite outside its predefined set.{hint}", e.status_code
                ) from e

        return await fmc_preview(
            ctx,
            tool="fmc_create_cipher_suite_list",
            args={
                "name": name,
                "suites": suites,
                "preset": preset,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create cipher suite list {name!r} ({len(chosen)} suites)",
                details={
                    "suites": [{"name": s.name, "code": s.code, "weak": s.weak or "no"} for s in chosen]
                },
                blockers=blockers,
                side_effects=warnings,
            ),
            apply=lambda: applied(app, create),
        )


def list_row(c: dict[str, Any]) -> dict[str, Any]:
    """One cipher suite list: suite count, weak count, the strong suites and literals this server doesn't
    know."""
    lits = c.get("literals") or []
    known = [(lit, suite_of_literal(lit)) for lit in lits]
    row = {
        "name": c.get("name"),
        "suites": len(lits),
        "weak": sum(1 for _, s in known if s and s.weak),
        "strong": [s.name for _, s in known if s and s.weak is None] or None,
        "unknown": [str(lit.get("name") or lit.get("value")) for lit, s in known if s is None] or None,
        "id": c.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


async def created_anyway(app: FmcApp, base: str, name: str, known: set[Any]) -> dict[str, Any] | None:
    """After a 5xx on a rule POST: the new rule named `name` if FMC created it anyway (not one of the
    `known` ids from before the POST), else None. FMC 10.0.1 answers 500 "JsonNull" to a decryption rule
    POST with insertBefore but stores the rule at the requested index."""
    rules = await all_rules(app, base)
    made = [
        r
        for r in rules.items
        if r.get("id") not in known and str(r.get("name", "")).lower() == name.strip().lower()
    ]
    return made[0] if len(made) == 1 else None


NONE_SELECTED = "none selected"
# Rule conditions besides the certificate and TLS ones (CERT_CONDITIONS).
MATCH_FIELDS = (
    "sourceZones",
    "destinationZones",
    "sourceNetworks",
    "destinationNetworks",
    "sourcePorts",
    "destinationPorts",
    "vlanTags",
    "urls",
    "users",
    "applications",
)


def rule_body(r: dict[str, Any]) -> dict[str, Any]:
    """A decryption rule as FMC takes it back in a PUT (no metadata or links)."""
    return {k: v for k, v in r.items() if k not in ("metadata", "links")}


def find_rule(rules: list[dict[str, Any]], ref: str, policy: str) -> dict[str, Any]:
    """One rule of a policy by UUID, name (case-insensitive) or 1-based index."""
    key = ref.strip()
    hits = [r for r in rules if r.get("id") == key or str(r.get("name", "")).lower() == key.lower()]
    if not hits and key.isdigit():
        hits = [r for r in rules if _index(r) == int(key)]
    if len(hits) != 1:
        raise NotFound(f"No single rule {ref!r} in {policy!r} (fmc_get_decryption_policy lists them).", 404)
    return hits[0]


async def cipher_list(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    """A cipher suite list with its suites (`literals`)."""
    c = await resolve_in(app, CIPHER_LISTS, ref, "cipher suite list", domain)
    if "literals" not in c:  # a by-name listing isn't expanded
        c = await app.api.get(f"{await app.config_path(CIPHER_LISTS, domain)}/{c['id']}")
    return c


def _category(r: dict[str, Any] | None) -> str | None:
    return (((r or {}).get("metadata") or {}).get("category") or {}).get("name")


def _list_ids(r: dict[str, Any]) -> list[str]:
    return [str(o.get("id")) for o in (r.get("cipherSuiteLists") or {}).get("objects") or []]


def _versions_label(r: dict[str, Any]) -> list[str] | str:
    """The versions a rule matches: a list, 'all', or NONE_SELECTED (all five off: FMC's matching treats it
    as every version, its deploy of a Do-not-decrypt or Decrypt-Resign rule refuses it)."""
    v = r.get("tlsVersions")
    if isinstance(v, dict) and v and not any(v.get(k) for k in ALL_TLS_VERSIONS):
        return NONE_SELECTED
    return versions_on(r) or "all"


def matches_all(r: dict[str, Any]) -> bool:
    """A rule with no condition at all: it matches every TLS session."""
    return not any(has_value(r.get(f)) for f in MATCH_FIELDS) and not cert_conditions(r)


def moved(rules: list[dict[str, Any]], rid: str, new: dict[str, Any], to: int) -> list[dict[str, Any]]:
    """The policy's rules with rule `rid` replaced by `new` at index `to`, re-indexed."""
    out = [r for r in sorted(rules, key=lambda x: _index(x) or 1_000_000) if r.get("id") != rid]
    out.insert(to - 1, {**new, "id": rid})
    return [{**r, "metadata": {**(r.get("metadata") or {}), "ruleIndex": i}} for i, r in enumerate(out, 1)]


def same_rule(got: Any, want: dict[str, Any]) -> bool:
    """Whether FMC holds what an update sent (the fields fmc_update_decryption_rule changes)."""
    if not isinstance(got, dict):
        return False

    def key(r: dict[str, Any]) -> tuple[Any, ...]:
        v = r.get("tlsVersions") or {}
        return (
            tuple(bool(v.get(k)) for k in ALL_TLS_VERSIONS),
            sorted(_list_ids(r)),
            r.get("enabled", True) is not False,
            bool((r.get("logging") or {}).get("logEnd")),
        )

    return key(got) == key(want)


def _index(r: dict[str, Any]) -> int | None:
    idx = r.get("ruleIndex") or (r.get("metadata") or {}).get("ruleIndex")
    return idx if isinstance(idx, int) else None

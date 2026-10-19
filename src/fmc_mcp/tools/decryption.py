"""Decryption policy (F13 slice 2, F64): read decryption policies and their rules, create and tune a
policy (trusted CAs, TLS 1.3 decryption, untrusted server certificates), add or delete rules
(DECRYPT_RESIGN with an internal CA, DECRYPT_KNOWN_KEY with a server's own certificate, DO_NOT_DECRYPT
exemptions for banking or health sites, BLOCK), and link a decryption policy to an access control policy.

The certificate objects live in fmc_mcp.tools.pki; fmc_tls_decryption_check (decryption_check.py) explains
what happens to one flow."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    NotFound,
    Plan,
    ResponseFormat,
    ToolRegistrar,
    get_client,
    list_result,
    object_result,
)
from fmc_mcp._core.http import page_of
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
        "cert_conditions": cert_conditions(r) or None,
        "log": True if (r.get("logging") or {}).get("logEnd") else None,
        "id": r.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


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
        f"{NO_VERSION_SELECTION[action]} rule is deprecated'). Turn every version on (fmc_api_call PUT of "
        "the rule with tlsVersions all true) or re-create it with fmc_create_decryption_rule (sends them)."
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
        """List decryption (TLS/SSL) policies, or show one: mode, default action, trusted CAs, advanced
        options (TLS 1.3 decryption, untrusted server certificates), the access policies using it, its rules
        in order (DO_NOT_DECRYPT, DECRYPT_RESIGN with the internal CA, DECRYPT_KNOWN_KEY, BLOCK, with zones,
        networks, ports, users, URLs) and what blocks decryption from working (`readiness`)."""
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
            "trusted_cas": trusted_labels(p) or None,
            "advanced": advanced_row(p) or None,
            "used_by": (await acps_using(app, str(p["id"]), domain)).get(str(p["id"]), []),
            "rules": [rule_row(r) for r in rules.items],
            "readiness": await readiness(app, p, rules.items, domain),
            "id": p.get("id"),
        }
        return object_result({k: v for k, v in out.items() if v is not None}, fmt=response_format)

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
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Change a decryption policy's settings: default action, trusted CAs (the issuers the FTD accepts
        for server certificates; a private or lab server's CA must be here for its re-signed certificate to
        look trusted), TLS 1.3 decryption and how untrusted server certificates are handled. Rules are
        unchanged. Takes effect after a deploy of the devices whose access policy uses it."""
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
        if not changes and not blockers:
            blockers.append("Nothing to change.")
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
            apply=lambda: applied(app, lambda: app.api.put(path, desired)),
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
                "DECRYPT_KNOWN_KEY decrypts inbound TLS to your own server with its certificate and key"
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
        insert_before: Annotated[
            int | None,
            Field(
                ge=1,
                description="Rule index to insert before (1 = first); default: the end. Put DO_NOT_DECRYPT "
                "exemptions above the DECRYPT_RESIGN rules: rules match top-down",
            ),
        ] = None,
        log: Annotated[bool, Field(description="Log matching connections at their end to FMC")] = False,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a rule to a decryption policy (at the end, or before rule `insert_before`). DECRYPT_RESIGN
        needs an internal CA that clients trust; the preview warns when the policy can't decrypt TLS 1.3,
        when an exemption would land below a decrypt rule, or when an existing rule's TLS version selection
        will make FMC refuse the deploy. The rule matches every TLS/SSL version. Takes effect after a deploy
        of the devices whose access policy uses the decryption policy (fmc_set_decryption_policy)."""
        app: FmcApp = get_client(ctx)
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
            "tlsVersions": dict(ALL_TLS_VERSIONS),
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
            )
        )
        if match_all and action != "DO_NOT_DECRYPT":
            blockers.append(
                f"A {action} rule without conditions would match all TLS traffic; add a condition."
            )
        position = insert_before or count + 1
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
                "insert_before": insert_before,
                "log": log,
                "domain": domain,
            },
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Add decryption rule {name!r} ({action}) to {p.get('name')!r} {where}",
                details={
                    # all versions on is no condition (FMC 10's default; it refuses version selection)
                    "rule": rule_row({k: v for k, v in body.items() if k != "tlsVersions"}),
                    "tls_versions": "all",
                    "position": position,
                    "rules_now": count,
                },
                fingerprint={
                    "policy": p["id"],
                    "rules": [r.get("id") for r in existing.items],
                    "certs": cert_fp,
                },
                blockers=blockers,
                side_effects=[*warnings, "Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.post(base, body, params=params)),
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


def _index(r: dict[str, Any]) -> int | None:
    idx = r.get("ruleIndex") or (r.get("metadata") or {}).get("ruleIndex")
    return idx if isinstance(idx, int) else None

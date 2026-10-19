"""fmc_tls_decryption_check (F64): what the decryption policy does to one TLS flow, and whether a
decrypt-resign rollout is ready for it (CA, TLS 1.3, trusted issuers, the access policy link, deploys).

Offline and best-effort like fmc_rule_lookup: the rule walk uses zones, networks, ports, users and, with
`server_name`, URL objects; URL categories, applications and certificate conditions (issuer, status,
TLS version, cipher suites) can't be known in advance, so rules using them are reported as conditional."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import ipaddress
import re
from typing import Annotated, Any

from fastmcp import Context
from pydantic import Field

from fmc_mcp._core import InvalidRequest, NotFound, ToolRegistrar, UpstreamError, get_client
from fmc_mcp.catalog import Catalog
from fmc_mcp.client import FmcApp
from fmc_mcp.flow import access_policy_of, device_context
from fmc_mcp.rules import has_value
from fmc_mcp.tools.analysis import _ip, _net_match, _port_match, _user_match, _zone_match
from fmc_mcp.tools.common import PROTO_NUMBERS, Domain, block_labels, ref_label, resolve_in
from fmc_mcp.tools.decryption import (
    DECRYPTION,
    _index,
    advanced_row,
    cert_conditions,
    rule_row,
    trusted_labels,
    version_problem,
)
from fmc_mcp.tools.deploy import deployable, deployable_row
from fmc_mcp.tools.device_config import resolve_device
from fmc_mcp.tools.pki import KINDS, ca_problems, resolve_cert
from fmc_mcp.tools.policies import ACCESS, all_rules

URL_PATHS = {"Url": "object/urls", "UrlGroup": "object/urlgroups"}
URL_LOOKUP_CAP = 20  # URL objects/groups read per check
LIMITS = (
    "Offline, best-effort walk of the decryption policy only. URL categories, applications and certificate "
    "conditions (issuer/subject DN, certificate status, TLS version, cipher suites, client threat level) "
    "can't be known before the handshake, so rules using them are 'conditional' (FMC's defaults, all "
    "statuses ANY and all TLS versions, don't count); URL objects are matched against server_name "
    "(the SNI) when you give it. Users are evaluated only with `identities`. What the access policy then "
    "does with the (decrypted) flow: fmc_rule_lookup; the device's live verdict: fmc_packet_tracer."
)
INSPECTION = {
    "DECRYPT_RESIGN": (
        "Decrypted: the FTD ends the client's TLS session with a copy of the server certificate re-signed by "
        "the internal CA and opens its own session to the server. Access rules (applications, URLs), the "
        "file/malware policy and the intrusion policy see the HTTP inside."
    ),
    "DECRYPT_KNOWN_KEY": (
        "Decrypted with the server's own certificate and key (inbound to your server): the client sees the "
        "real certificate; file/malware and intrusion inspection see the traffic inside."
    ),
    "DECRYPT_REPLACE_CERT": (
        "Decrypted (replace certificate): file/malware and intrusion inspection see the traffic inside."
    ),
    "DO_NOT_DECRYPT": (
        "Not decrypted: inspection sees only the TLS handshake (SNI and server certificate). URL categories "
        "can still match on the SNI, but file/malware and intrusion rules can't see the payload."
    ),
    "BLOCK": "Blocked during the TLS handshake.",
    "BLOCK_WITH_RESET": "Blocked during the TLS handshake with a TCP reset.",
}
HOST_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(?:[^@/]*@)?([^/:?#]+)")


def host_of(url: str) -> str:
    m = HOST_RE.match(url.strip().lower())
    return (m.group(1) if m else url.strip().lower()).rstrip(".")


def host_matches(server_name: str, value: str) -> bool:
    """A URL object value against the SNI: the same host, or a subdomain of it."""
    host, want = server_name.strip().lower().rstrip("."), host_of(value)
    return bool(want) and (host == want or host.endswith("." + want))


async def url_values(
    app: FmcApp, block: Any, domain: str | None, cache: dict[str, list[str] | None]
) -> list[str] | None:
    """Every URL of a rule's urls block (literals, objects, groups); None when one can't be read."""
    if not isinstance(block, dict):
        return []
    out = [str(lit.get("url")) for lit in block.get("literals") or [] if lit.get("url")]
    for o in block.get("objects") or []:
        oid, kind = str(o.get("id") or ""), str(o.get("type") or "")
        if oid not in cache:
            if kind not in URL_PATHS or len(cache) >= URL_LOOKUP_CAP:
                return None
            try:
                obj = await app.api.get(f"{await app.config_path(URL_PATHS[kind], domain)}/{oid}")
            except (NotFound, UpstreamError):
                cache[oid] = None
            else:
                if kind == "Url":
                    cache[oid] = [str(obj.get("url"))] if obj.get("url") else None
                else:
                    cache[oid] = await url_values(app, obj, domain, cache)
        got = cache[oid]
        if got is None:
            return None
        out += got
    return out


def _has_categories(block: Any) -> bool:
    return isinstance(block, dict) and bool(block.get("urlCategoriesWithReputation"))


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="What TLS decryption does to a flow")
    async def fmc_tls_decryption_check(
        ctx: Context,
        source: Annotated[str, Field(description="Client IP address, e.g. 192.0.2.10")],
        destination: Annotated[str, Field(description="Server IP address, e.g. 203.0.113.10")],
        port: Annotated[int, Field(ge=1, le=65535, description="Server port")] = 443,
        protocol: Annotated[str, Field(description="tcp or udp (QUIC)")] = "tcp",
        server_name: Annotated[
            str | None,
            Field(description="The host name the client asks for (TLS SNI), e.g. www.example.com"),
        ] = None,
        identities: Annotated[
            list[str] | None,
            Field(description="The client's AD/LDAP user and groups, to evaluate rules on users"),
        ] = None,
        source_zone: Annotated[str | None, Field(description="Ingress security zone")] = None,
        destination_zone: Annotated[str | None, Field(description="Egress security zone")] = None,
        device: Annotated[
            str | None,
            Field(
                description="FTD the flow crosses: gives the access policy, the zones and whether changes "
                "are still undeployed"
            ),
        ] = None,
        access_policy: Annotated[
            str | None, Field(description="Access control policy (default: the device's)")
        ] = None,
        decryption_policy: Annotated[
            str | None,
            Field(description="Decryption policy to evaluate (default: the one the access policy uses)"),
        ] = None,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Explain what TLS decryption will do to one flow: which decryption rule (or the default action)
        takes it, whether it is decrypted (re-signed with which internal CA, or with the server's own key),
        exempted or blocked, and what file, malware, intrusion and URL inspection can see as a result. Also
        checks a decrypt-resign rollout for the flow: the CA (CSR pending, expiry, clients must trust it),
        TLS 1.3 decryption, trusted issuers for the server certificate, the access policy link and pending
        deploys. Use it before and after fmc_create_decryption_rule; best-effort and offline (see
        `limits`)."""
        app: FmcApp = get_client(ctx)
        src, dst = _ip(source, "source"), _ip(destination, "destination")
        proto = PROTO_NUMBERS.get(protocol.strip().upper(), protocol.strip())
        if proto not in ("6", "17"):
            raise InvalidRequest("protocol must be tcp or udp: TLS runs over TCP (or QUIC over UDP).")
        dev = await resolve_device(app, device, domain) if device else None
        acp: dict[str, Any] | None = None
        if access_policy:
            acp = await resolve_in(app, ACCESS, access_policy, "access policy", domain)
        elif dev is not None:
            ref_ = await access_policy_of(app, dev, domain)
            if ref_ is not None:
                acp = ref_
        acp_full = await app.api.get(await app.config_path(f"{ACCESS}/{acp['id']}", domain)) if acp else None
        linked = (acp_full or {}).get("decryptionPolicySetting") or {}
        checks: list[dict[str, Any]] = []
        if decryption_policy:
            pol = await resolve_in(app, DECRYPTION, decryption_policy, "decryption policy", domain)
            if acp_full is not None and linked.get("id") != pol.get("id"):
                checks.append(
                    {
                        "check": "access policy link",
                        "ok": False,
                        "detail": f"{acp_full.get('name')!r} uses "
                        f"{ref_label(linked) if linked else 'no decryption policy'}, "
                        f"not {pol.get('name')!r}: "
                        "fmc_set_decryption_policy, then deploy.",
                    }
                )
        elif linked.get("id"):
            pol = await app.api.get(await app.config_path(f"{DECRYPTION}/{linked['id']}", domain))
        elif acp_full is not None:
            return {
                "access_policy": acp_full.get("name"),
                "verdict": "Not decrypted: the access policy has no decryption policy.",
                "action": None,
                "inspection": INSPECTION["DO_NOT_DECRYPT"],
                "next": "fmc_create_decryption_policy -> fmc_create_internal_ca -> "
                "fmc_create_decryption_rule (DO_NOT_DECRYPT exemptions, then DECRYPT_RESIGN) -> "
                "fmc_set_decryption_policy -> fmc_deploy.",
                "limits": LIMITS,
            }
        else:
            raise InvalidRequest(
                "Give the device the flow crosses (device=...), its access policy (access_policy=...) or the "
                "decryption policy (decryption_policy=...)."
            )
        if acp_full is not None and pol.get("id") == linked.get("id"):
            checks.append(
                {
                    "check": "access policy link",
                    "ok": True,
                    "detail": f"{acp_full.get('name')!r} uses {pol.get('name')!r}.",
                }
            )

        rules = await all_rules(
            app, await app.config_path(f"{DECRYPTION}/{pol['id']}/decryptionpolicyrules", domain)
        )
        cat = Catalog(app, domain)
        await cat.load_networks()
        await cat.load_ports()
        dev_info: dict[str, Any] | None = None
        if dev is not None and (source_zone is None or destination_zone is None):
            dc = await device_context(app, dev, cat, domain)
            src_leg = dc.leg(ipaddress.ip_address(source.strip()))
            dst_leg = dc.leg(ipaddress.ip_address(destination.strip()))
            if source_zone is None and src_leg and src_leg.zone:
                source_zone = src_leg.zone
            if destination_zone is None and dst_leg and dst_leg.zone:
                destination_zone = dst_leg.zone
            dev_info = {
                "name": dev.get("name"),
                "ingress": src_leg.as_dict() if src_leg else None,
                "egress": dst_leg.as_dict() if dst_leg else None,
            }

        url_cache: dict[str, list[str] | None] = {}
        conditional: list[dict[str, Any]] = []
        monitored: list[dict[str, Any]] = []
        match: dict[str, Any] | None = None
        match_raw: dict[str, Any] | None = None
        for r in sorted(rules.items, key=lambda x: _index(x) or 1_000_000):
            if not r.get("enabled", True):
                continue
            tests: dict[str, bool | None] = {
                "source_zone": _zone_match(r.get("sourceZones"), source_zone),
                "destination_zone": _zone_match(r.get("destinationZones"), destination_zone),
                "source": _net_match(cat, r.get("sourceNetworks"), src),
                "destination": _net_match(cat, r.get("destinationNetworks"), dst),
                "destination_port": _port_match(cat, r.get("destinationPorts"), proto, port),
                "source_port": _port_match(cat, r.get("sourcePorts"), proto, None),
                "users": _user_match(r.get("users"), identities),
            }
            urls = r.get("urls")
            if has_value(urls):
                if _has_categories(urls):
                    tests["url_category"] = None
                if block_labels(urls):
                    values = await url_values(app, urls, domain, url_cache)
                    if values is None or server_name is None:
                        tests["url"] = None
                    else:
                        hit = any(host_matches(server_name, v) for v in values)
                        # objects and categories are alternatives: a category may still match
                        tests["url"] = True if hit else (None if _has_categories(urls) else False)
            if any(v is False for v in tests.values()):
                continue
            unknown = [k for k, v in tests.items() if v is None]
            unknown += [c for c in ("applications", "vlanTags") if has_value(r.get(c))]
            unknown += cert_conditions(r)
            row = rule_row(r)
            if unknown:
                conditional.append({**row, "depends_on": unknown})
                continue
            if r.get("ruleAction") == "MONITOR":
                monitored.append(row)
                continue
            match, match_raw = row, r
            break

        default = (pol.get("defaultAction") or {}).get("policyAction") or "DO_NOT_DECRYPT"
        action = str(match.get("action")) if match else default
        out: dict[str, Any] = {
            "access_policy": (acp_full or {}).get("name"),
            "decryption_policy": pol.get("name"),
            "flow": {
                "source": source,
                "destination": destination,
                "protocol": protocol,
                "port": port,
                "server_name": server_name,
                "source_zone": source_zone,
                "destination_zone": destination_zone,
                **({"identities": identities} if identities is not None else {}),
            },
        }
        if dev_info:
            out["device"] = dev_info
        if match is not None:
            out["verdict"] = f"Rule {match.get('index')} {match.get('name')!r} -> {action}"
            out["matched_rule"] = match
        else:
            out["verdict"] = f"No rule matches definitively -> default action {default}"
        out["action"] = action
        out["inspection"] = INSPECTION.get(action, action)
        if conditional:
            out["may_match_first"] = conditional[:20]
            out["note"] = (
                "Earlier rules in may_match_first could take this flow first, depending on the listed "
                "conditions (e.g. the server's URL category or certificate)."
            )
        if monitored:
            out["monitor_rules_logged"] = monitored

        # --- readiness ------------------------------------------------------------------------------
        adv = advanced_row(pol)
        decrypting = action in ("DECRYPT_RESIGN", "DECRYPT_KNOWN_KEY", "DECRYPT_REPLACE_CERT")
        if match_raw is not None and action == "DECRYPT_RESIGN":
            cas = (match_raw.get("decryptionCerts") or {}).get("objects") or []
            if not cas:
                checks.append(
                    {"check": "internal CA", "ok": False, "detail": "The rule names no internal CA."}
                )
            for o in cas[:3]:
                try:
                    _, ca = await resolve_cert(app, str(o.get("id")), [KINDS["internal_ca"]], domain)
                except NotFound:
                    checks.append(
                        {"check": "internal CA", "ok": False, "detail": f"{ref_label(o)!r} no longer exists."}
                    )
                    continue
                problems = ca_problems(ca)
                checks.append(
                    {
                        "check": "internal CA",
                        "ok": not problems,
                        "detail": " ".join(problems)
                        or f"{ca.get('name')!r} (CN {ca.get('subjectCommonName')}, valid until "
                        f"{ca.get('validityEndDate')}, SHA-1 {ca.get('certFingerprint')}).",
                    }
                )
                checks.append(
                    {
                        "check": "clients trust the CA",
                        "ok": None,
                        "detail": f"Can't be seen from FMC: the client must have {ca.get('name')!r} as a "
                        "trusted root (fmc_get_certificate gives its PEM), or it shows certificate errors.",
                    }
                )
            trusted = trusted_labels(pol)
            if adv.get("propagate_untrusted_certs") is False:
                detail = (
                    "Server certificates from issuers outside the trusted CAs are re-signed too, so clients "
                    "can't tell a bad server certificate from a good one."
                )
            else:
                detail = (
                    "If the server's certificate isn't issued by one of the trusted CAs (a private PKI or a "
                    "self-signed lab server), the client still sees an untrusted certificate: import its "
                    "issuer with fmc_create_trusted_ca and add it with fmc_update_decryption_policy "
                    "add_trusted_cas."
                )
            checks.append(
                {
                    "check": "trusted issuers",
                    "ok": None,
                    "detail": f"Trusted CAs: {', '.join(trusted) or 'none'}. {detail}",
                }
            )
        # any rule of the policy, matched or not: FMC refuses the deploy of the whole policy
        versions = [m for m in (version_problem(r) for r in rules.items if r.get("enabled", True)) if m]
        if versions:
            checks.append({"check": "TLS versions", "ok": False, "detail": " ".join(versions[:3])})
        if decrypting:
            tls13 = adv.get("tls13_decryption")
            checks.append(
                {
                    "check": "TLS 1.3 decryption",
                    "ok": bool(tls13),
                    "detail": "On."
                    if tls13
                    else "Off: TLS 1.3 sessions (curl and current browsers negotiate it by default) are not "
                    "decrypted; fmc_update_decryption_policy tls13_decryption=true.",
                }
            )
            if proto == "17" and not adv.get("quic_decryption"):
                checks.append(
                    {
                        "check": "QUIC",
                        "ok": False,
                        "detail": "UDP/QUIC sessions aren't decrypted (quicDecryption off); browsers fall "
                        "back to TCP when QUIC is blocked.",
                    }
                )
        if dev is not None:
            if acp is None:
                checks.append(
                    {
                        "check": "device policy",
                        "ok": False,
                        "detail": f"{dev.get('name')} has no access policy.",
                    }
                )
            try:
                pending = [deployable_row(d) for d in await deployable(app, domain)]
            except UpstreamError:
                pending = []
            mine = [
                d
                for d in pending
                if d.get("device_id") == dev.get("id") or d.get("device") == dev.get("name")
            ]
            if mine:
                stale = ", ".join(mine[0].get("out_of_date_policies") or []) or "see fmc_pending_changes"
                checks.append(
                    {
                        "check": "deployed",
                        "ok": False,
                        "detail": f"{dev.get('name')} has undeployed changes ({stale}): what the device does "
                        "now may differ until fmc_deploy.",
                    }
                )
            else:
                checks.append(
                    {"check": "deployed", "ok": True, "detail": f"{dev.get('name')} is up to date."}
                )
        if checks:
            out["readiness"] = checks
        out["limits"] = LIMITS
        return out

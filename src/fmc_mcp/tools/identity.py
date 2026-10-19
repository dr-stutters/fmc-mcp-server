"""Identity (F13, identity slice): AD/LDAP realms (create, test, download users and groups), trusted CA
certificates for LDAPS, and identity policies with their rules. Access rules then match realm users and
groups through fmc_create_access_rule / fmc_update_access_rule (`users`), and fmc_rule_lookup evaluates
them with `identities`.

FMC 10.0's REST API gaps (verified live): AD/LDAP realm test and download exist only in the web UI
(fmc_mcp.ui drives them with FMC_UI_USERNAME), and an access policy's identity policy link is read-only
(`identityPolicySetting` is silently dropped on PUT; the UI saves it over GWT-RPC)."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import asyncio
import base64
import binascii
import hashlib
import ipaddress
import re
import time
from typing import Annotated, Any, Literal

from fastmcp import Context
from fastmcp.tools import ToolResult
from pydantic import Field, SecretStr

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
from fmc_mcp.refs import REALM_GROUPS, REALM_USERS, RefResolver
from fmc_mcp.tools.common import Domain, block_labels, ref_label, resolve_in
from fmc_mcp.tools.object_writes import applied
from fmc_mcp.tools.policies import ACCESS, all_rules
from fmc_mcp.tools.policy_writes import NetsParam, PortsParam, ZonesParam
from fmc_mcp.ui import FmcUiSession, ui_credentials

REALMS = "object/realms"
CA_CERTS = "object/externalcacertificates"
IDENTITY = "policy/identitypolicies"
DOWNLOAD_WAIT = 60  # seconds fmc_download_realm waits for FMC's download task by default
MEMBER_CAP = 200  # users/groups listed per realm

RealmRef = Annotated[str, Field(description="Realm name or UUID (fmc_get_realm)")]
PolicyRef = Annotated[str, Field(description="Identity policy name or UUID")]
AuthType = Literal["PASSIVE", "ACTIVE", "NO"]
ActiveProtocol = Literal["HTTP_BASIC", "NTLM", "KERBEROS", "HTTP_NEGOTIATE", "HTTP_RESPONSE_PAGE"]
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", re.S)
TAG_RE = re.compile(r"<[^>]+>")


# --- shaping ------------------------------------------------------------------------------------------


def directory_row(d: dict[str, Any]) -> dict[str, Any]:
    row = {
        "host": d.get("hostname"),
        "port": d.get("port"),
        "encryption": d.get("encryptionProtocol"),
        "ca_certificate": ref_label(d["encryptionCert"]) if d.get("encryptionCert") else None,
        "interface": ref_label(d["interface"]) if d.get("interface") else None,
    }
    return {k: v for k, v in row.items() if v is not None}


def realm_row(r: dict[str, Any]) -> dict[str, Any]:
    meta = r.get("metadata") or {}
    row = {
        "name": r.get("name"),
        "type": r.get("realmType"),
        "enabled": r.get("enabled"),
        "ad_domain": r.get("adPrimaryDomain"),
        "directories": [directory_row(d) for d in r.get("directoryConfigurations") or []] or None,
        "base_dn": r.get("baseDn"),
        "group_dn": r.get("groupDn"),
        "bind_user": r.get("dirUsername"),  # dirPassword is never shown (FMC masks it anyway)
        "include_groups": r.get("includedGroups") or None,
        "exclude_groups": r.get("excludedGroups") or None,
        "download_schedule": f"every {r.get('updateInterval')} h from {r.get('updateHour')}:00"
        if r.get("updateInterval")
        else None,
        "downloading": meta.get("isDownloading") or None,
        "id": r.get("id"),
    }
    return {k: v for k, v in row.items() if v not in (None, [], "")}


def identity_rule_row(r: dict[str, Any]) -> dict[str, Any]:
    meta = r.get("metadata") or {}
    row = {
        "index": meta.get("index") or meta.get("ruleIndex"),
        "name": r.get("name"),
        "enabled": r.get("enabled"),
        "auth": r.get("authenticationType"),
        "realm": ref_label(r["realm"]) if r.get("realm") else None,
        "protocol": r.get("authenticationProtocol") if r.get("authenticationType") == "ACTIVE" else None,
        "src_zones": block_labels(r.get("sourceZones")) or None,
        "dst_zones": block_labels(r.get("destinationZones")) or None,
        "src_networks": block_labels(r.get("sourceNetworks")) or None,
        "dst_networks": block_labels(r.get("destinationNetworks")) or None,
        "dst_ports": block_labels(r.get("destinationPorts")) or None,
        "guest_fallback": r.get("guestAccessFallback") or None,
        "id": r.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


def pem_body(pem: str) -> tuple[str, bytes]:
    """The single certificate in `pem` (normalised PEM text, DER bytes)."""
    found = PEM_RE.findall(pem or "")
    if len(found) != 1:
        raise InvalidRequest("Give exactly one PEM certificate (-----BEGIN CERTIFICATE----- ... END).")
    b64 = re.sub(r"\s+", "", found[0])
    try:
        der = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidRequest("The PEM certificate is not valid base64.") from None
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    text = "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"
    return text, der


def fmc_fingerprint(der: bytes) -> str:
    """SHA-1 as FMC shows it (certFingerprint 'AB:CD:...')."""
    return ":".join(f"{b:02X}" for b in hashlib.sha1(der, usedforsecurity=False).digest())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def parse_directory(text: str) -> tuple[str, int, str]:
    """'host', 'host:port', 'ldaps://host[:port]', 'starttls://host[:port]' -> (host, port, encryption)."""
    t = text.strip()
    enc = "NONE"
    m = re.match(r"^(ldaps|ldap|starttls)://(.+)$", t, re.I)
    if m:
        enc = {"ldaps": "LDAPS", "ldap": "NONE", "starttls": "STARTTLS"}[m.group(1).lower()]
        t = m.group(2)
    t = t.rstrip("/")
    host, port = t, 0
    if t.count(":") == 1:
        host, p = t.split(":")
        if not p.isdigit() or not 0 < int(p) < 65536:
            raise InvalidRequest(f"Bad port in directory server {text!r}.")
        port = int(p)
    if not host or " " in host:
        raise InvalidRequest(f"Bad directory server {text!r}; use host, host:port or ldaps://host:port.")
    return host, port or (636 if enc == "LDAPS" else 389), enc


async def members_of(app: FmcApp, realm_id: str, domain: str | None) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for key, path in (("groups", REALM_GROUPS), ("users", REALM_USERS)):
        page = await app.all(await app.config_path(path, domain))
        out[key] = [i for i in page.items if (i.get("realm") or {}).get("id") == realm_id]
    return out


async def policies_using(app: FmcApp, idp_id: str | None, domain: str | None) -> dict[str, list[str]]:
    """Identity policy id -> names of the access policies that use it (expanded ACP listing)."""
    page = await app.all(await app.config_path(ACCESS, domain))
    out: dict[str, list[str]] = {}
    for acp in page.items:
        link = acp.get("identityPolicySetting") or {}
        if link.get("id") and (idp_id is None or link["id"] == idp_id):
            out.setdefault(str(link["id"]), []).append(str(acp.get("name")))
    return out


async def resolve_realm(app: FmcApp, realm: str, domain: str | None) -> dict[str, Any]:
    r = await resolve_in(app, REALMS, realm, "realm", domain)
    if r.get("realmType") not in ("AD", "LDAP"):
        raise InvalidRequest(
            f"{r.get('name')!r} is a {r.get('realmType')} realm; these tools handle AD/LDAP."
        )
    return r


def _strip(text: Any) -> str:
    return re.sub(r"\s+", " ", TAG_RE.sub(" ", str(text or ""))).strip()


async def download_messages(ui: FmcUiSession, realm_name: str) -> list[dict[str, Any]]:
    """FMC's task notifications about this realm's user/group downloads (newest first)."""
    data = await ui.pjb("SF::Messaging::PJB::fetchInitial", [])
    tasks = ((data or {}).get("messages") or {}).get("task") or []
    pattern = re.compile(r"\bfrom\s+" + re.escape(realm_name) + r"(?![\w.-])", re.I)
    out = [
        m
        for m in tasks
        if isinstance(m, dict)
        and "download" in str(m.get("category", "")).lower()
        and pattern.search(_strip(m.get("body")))
    ]
    return sorted(out, key=lambda m: _int(m.get("seq")), reverse=True)


def _int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def register(reg: ToolRegistrar) -> None:
    # --- read -----------------------------------------------------------------------------------------

    @reg.read(title="Realms (AD/LDAP)")
    async def fmc_get_realm(
        ctx: Context,
        realm: Annotated[str | None, Field(description="Realm name or UUID; omit to list all realms")] = None,
        members: Annotated[
            Literal["groups", "users", "both", "none"],
            Field(description="Downloaded identities to list for one realm"),
        ] = "groups",
        text: Annotated[str | None, Field(description="Only users/groups whose name contains this")] = None,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List identity realms, or show one AD/LDAP realm: directory servers (host, port, LDAPS/STARTTLS and
        the trusted CA), base and group DN, bind user (never the password), included/excluded groups, the
        download schedule, and the users and groups FMC has downloaded (with the last sync time). Access
        rules can only match downloaded users and groups; fmc_download_realm refreshes them."""
        app: FmcApp = get_client(ctx)
        if not realm:
            page = await app.all(await app.config_path(REALMS, domain))
            rows = []
            for r in page.items:
                rows.append(
                    {
                        "name": r.get("name"),
                        "type": r.get("realmType"),
                        "enabled": r.get("enabled"),
                        "ad_domain": r.get("adPrimaryDomain"),
                        "directories": ", ".join(
                            f"{d.get('hostname')}:{d.get('port')} {d.get('encryptionProtocol')}"
                            for d in r.get("directoryConfigurations") or []
                        )
                        or None,
                        "id": r.get("id"),
                    }
                )
            return list_result(page_of(rows, limit=1000, offset=0), fmt=response_format)
        r = await resolve_realm(app, realm, domain)
        out = realm_row(r)
        mem = await members_of(app, r["id"], domain)
        synced = [int((i.get("metadata") or {}).get("lastSynced") or 0) for i in mem["groups"] + mem["users"]]
        out["downloaded"] = {"groups": len(mem["groups"]), "users": len(mem["users"])}
        if any(synced):
            out["last_download"] = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(max(synced)))
        elif not mem["groups"] and not mem["users"]:
            out["note"] = (
                "Nothing downloaded yet: run fmc_download_realm (or wait for the schedule). Access rules "
                "can't reference users or groups until then."
            )
        needle = (text or "").lower()
        for key in ("groups", "users"):
            if members not in (key, "both"):
                continue
            names = sorted(str(i.get("name")) for i in mem[key] if needle in str(i.get("name", "")).lower())
            out[key] = names[:MEMBER_CAP]
            if len(names) > MEMBER_CAP:
                out[f"{key}_truncated"] = f"{len(names)} match; showing {MEMBER_CAP} (narrow with text)"
        return object_result(out, fmt=response_format)

    @reg.read(title="Test realm directory connection")
    async def fmc_test_realm(
        ctx: Context,
        realm: RealmRef,
        domain: Domain = None,
    ) -> dict[str, Any]:
        """Have FMC bind to each of an AD/LDAP realm's directory servers with the stored bind user and
        password (the realm page's Test button) and report which work. Needs FMC_UI_USERNAME: FMC's REST
        API has no AD/LDAP realm test. It is in the read tier because it changes nothing, but it logs in
        to FMC's web UI (ending that UI user's other UI session). FMC only says pass/fail; on failure
        check the host and port from FMC's side, the bind user/password, and for LDAPS the CA
        certificate and the server name in it (fmc_get_realm shows them). After a pass:
        fmc_download_realm."""
        app: FmcApp = get_client(ctx)
        r = await resolve_realm(app, realm, domain)
        full = await app.api.get(await app.config_path(f"{REALMS}/{r['id']}", domain))
        dirs = full.get("directoryConfigurations") or []
        if not dirs:
            raise InvalidRequest(f"Realm {full.get('name')!r} has no directory servers.")
        results = []
        async with FmcUiSession(app.settings) as ui:
            for idx, d in enumerate(dirs):
                started = time.monotonic()
                res = await ui.pjb("SF::IdentityRealm::RealmTest::testDirectoryConnection", [full, idx])
                ok = isinstance(res, dict) and str(res.get("status")) == "0"
                results.append(
                    {
                        **directory_row(d),
                        "result": "ok" if ok else "failed",
                        "seconds": round(time.monotonic() - started, 1),
                    }
                )
        out: dict[str, Any] = {"realm": full.get("name"), "servers": results}
        failed = [x for x in results if x["result"] != "ok"]
        out["verdict"] = (
            "All directory servers answered the bind."
            if not failed
            else f"{len(failed)} of {len(results)} directory servers failed the bind test."
        )
        if failed:
            out["check"] = [
                "FMC reaches the host and port (FMC's management interface, or the routed interface for "
                "RA VPN realms)",
                "bind user and password (fmc_create_realm stores them; FMC never shows the password)",
                "LDAPS/STARTTLS: the CA certificate (fmc_create_trusted_ca) and that the server's "
                "certificate names the host as written",
            ]
        return out

    @reg.read(title="Identity policies")
    async def fmc_get_identity_policy(
        ctx: Context,
        policy: Annotated[str | None, Field(description="Identity policy name or UUID; omit to list")] = None,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List identity policies, or show one: its rules in order (traffic conditions -> realm and
        authentication: PASSIVE (ISE/pxGrid, passive agent, TS agent), ACTIVE (captive portal) or NO) and
        the access control policies that use it. Linking an identity policy to an access policy is not
        possible through FMC's REST API (it silently drops identityPolicySetting); do it in the access
        policy editor: Identity step > choose the policy > Apply > Save. Add rules with
        fmc_create_identity_rule; whether sessions reach FMC at all: fmc_get_identity_sources."""
        app: FmcApp = get_client(ctx)
        if not policy:
            page = await app.all(await app.config_path(IDENTITY, domain))
            used = await policies_using(app, None, domain)
            rows = [
                {
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "used_by": ", ".join(used.get(str(p.get("id")), [])) or None,
                    "id": p.get("id"),
                }
                for p in page.items
            ]
            return list_result(page_of(rows, limit=1000, offset=0), fmt=response_format)
        p = await resolve_in(app, IDENTITY, policy, "identity policy", domain)
        rules = await all_rules(app, await app.config_path(f"{IDENTITY}/{p['id']}/identityrules", domain))
        used = await policies_using(app, p["id"], domain)
        out = {
            "name": p.get("name"),
            "description": p.get("description"),
            "rules": [identity_rule_row(r) for r in rules.items],
            "used_by": used.get(str(p["id"]), []),
            "id": p.get("id"),
        }
        if not out["used_by"]:
            out["note"] = (
                "No access policy uses it. Select it in the access policy editor (Identity step); FMC's "
                "REST API can't set the link."
            )
        return object_result(out, fmt=response_format)

    # --- realm writes ---------------------------------------------------------------------------------

    @reg.write(title="Create trusted CA certificate")
    async def fmc_create_trusted_ca(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="Certificate object name")],
        pem: Annotated[str, Field(description="One CA certificate in PEM format (public, no private key)")],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Import a CA certificate as a trusted CA object (Objects > PKI > Trusted CAs), e.g. the AD root
        CA so a realm can use LDAPS or STARTTLS (fmc_create_realm ca_certificate=...), or a server's issuer
        a decryption policy should trust (fmc_update_decryption_policy add_trusted_cas=...). List them
        with fmc_get_certificate(kind='trusted_ca')."""
        app: FmcApp = get_client(ctx)
        if "PRIVATE KEY" in pem:
            raise InvalidRequest("That text contains a private key; give only the CA certificate.")
        text, der = pem_body(pem)
        fp = fmc_fingerprint(der)
        page = await app.all(await app.config_path(CA_CERTS, domain))
        blockers = []
        for c in page.items:
            if str(c.get("name", "")).lower() == name.lower():
                blockers.append(f"A trusted CA named {c.get('name')!r} already exists.")
            elif str(c.get("certFingerprint", "")).upper() == fp:
                blockers.append(f"This certificate is already imported as {c.get('name')!r}; use that name.")
        body = {"name": name, "type": "ExternalCACertificate", "cert": text}
        path = await app.config_path(CA_CERTS, domain)

        async def apply() -> Any:
            res = await app.api.post(path, body)
            return {
                k: res.get(k)
                for k in ("name", "id", "subjectCommonName", "issuerCommonName", "validityEndDate")
            }

        return await fmc_preview(
            ctx,
            tool="fmc_create_trusted_ca",
            args={"name": name, "pem": fp, "domain": domain},
            confirm=confirm,
            plan=Plan(
                f"Import trusted CA certificate {name!r}",
                details={"sha1_fingerprint": fp, "bytes": len(der)},
                blockers=blockers,
            ),
            apply=lambda: applied(app, apply),
        )

    @reg.write(title="Create AD/LDAP realm")
    async def fmc_create_realm(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="Realm name")],
        directory_servers: Annotated[
            list[str],
            Field(
                min_length=1,
                description="Directory servers in order: 'host', 'host:port', 'ldaps://host[:636]' or "
                "'starttls://host[:389]' (LDAPS/STARTTLS need ca_certificate and a host name that matches "
                "the server certificate)",
            ),
        ],
        base_dn: Annotated[str, Field(description="Where user searches start, e.g. DC=example,DC=com")],
        bind_user: Annotated[
            str, Field(description="Directory user FMC binds with, e.g. svc-ldap@example.com (read-only)")
        ],
        bind_password: Annotated[SecretStr, Field(description="Its password (stored by FMC, never shown)")],
        ad_domain: Annotated[
            str | None, Field(description="AD primary domain, e.g. example.com (required for AD realms)")
        ] = None,
        group_dn: Annotated[
            str | None, Field(description="Where group searches start, e.g. OU=Groups,DC=example,DC=com")
        ] = None,
        realm_type: Annotated[Literal["AD", "LDAP"], Field(description="Directory type")] = "AD",
        ca_certificate: Annotated[
            str | None, Field(description="Trusted CA object name or UUID for LDAPS/STARTTLS")
        ] = None,
        include_groups: Annotated[
            list[str] | None, Field(description="Download only these groups (default: all)")
        ] = None,
        exclude_groups: Annotated[list[str] | None, Field(description="Groups not to download")] = None,
        group_attribute: Annotated[
            str, Field(min_length=1, description="Group membership attribute (member, uniqueMember, ...)")
        ] = "member",
        description: Annotated[str | None, Field(description="Description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an AD or LDAP realm: the directory FMC downloads users and groups from, so identity and
        access rules can use them. Next: fmc_test_realm, fmc_download_realm, then an identity policy rule
        for the realm (fmc_create_identity_rule). The bind password is sent to FMC only, never shown."""
        app: FmcApp = get_client(ctx)
        if realm_type == "AD" and not ad_domain:
            raise InvalidRequest("An AD realm needs ad_domain (the AD primary domain, e.g. example.com).")
        servers = [parse_directory(s) for s in directory_servers]
        blockers: list[str] = []
        cert_ref = None
        if any(enc != "NONE" for _, _, enc in servers):
            if not ca_certificate:
                blockers.append(
                    "LDAPS/STARTTLS needs ca_certificate (import the directory's CA with "
                    "fmc_create_trusted_ca)."
                )
            else:
                c = await resolve_in(app, CA_CERTS, ca_certificate, "trusted CA certificate", domain)
                cert_ref = {"id": c["id"], "type": "ExternalCACertificate", "name": c.get("name")}
            for host, _, enc in servers:
                if enc != "NONE" and _is_ip(host):
                    blockers.append(
                        f"{host} is an IP address: with {enc} FMC checks the server certificate's name, so "
                        "use the DC's DNS name (and make sure FMC resolves it) unless the certificate has "
                        "that IP."
                    )
        elif ca_certificate:
            blockers.append("ca_certificate is only used with ldaps:// or starttls:// servers.")
        try:
            await resolve_in(app, REALMS, name, "realm", domain)
            blockers.append(f"A realm named {name!r} already exists.")
        except NotFound:
            pass
        dirs = []
        for idx, (host, port, enc) in enumerate(servers):
            d: dict[str, Any] = {
                "id": idx,
                "hostname": host,
                "port": port,
                "encryptionProtocol": enc,
                "useRoutingToSelectInterface": False,
            }
            if enc != "NONE" and cert_ref:
                d["encryptionCert"] = cert_ref
            dirs.append(d)
        body: dict[str, Any] = {
            "name": name,
            "type": "Realm",
            "realmType": realm_type,
            "baseDn": base_dn,
            "groupDn": group_dn or base_dn,
            "groupAttribute": group_attribute,
            "dirUsername": bind_user,
            "directoryConfigurations": dirs,
            "updateHour": 0,
            "updateInterval": 24,
            "includedGroups": include_groups or [],
            "excludedGroups": exclude_groups or [],
            "enabled": True,
        }
        if ad_domain:
            body["adPrimaryDomain"] = ad_domain
        if description:
            body["description"] = description
        shown = realm_row(body)
        secret = bind_password.get_secret_value()
        if not secret:
            blockers.append("bind_password is empty.")
        path = await app.config_path(REALMS, domain)

        async def apply() -> Any:
            res = await app.api.post(path, {**body, "dirPassword": secret})
            return {
                "realm": realm_row(res),
                "next": "fmc_test_realm, then fmc_download_realm (users and groups)",
            }

        return await fmc_preview(
            ctx,
            tool="fmc_create_realm",
            args={
                "name": name,
                "directory_servers": directory_servers,
                "base_dn": base_dn,
                "bind_user": bind_user,
                # binds the confirm to the previewed password without revealing it
                "bind_password": "sha256:" + hashlib.sha256(secret.encode()).hexdigest()[:16],
                "ad_domain": ad_domain,
                "group_dn": group_dn,
                "realm_type": realm_type,
                "ca_certificate": ca_certificate,
                "include_groups": include_groups,
                "exclude_groups": exclude_groups,
                "group_attribute": group_attribute,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create {realm_type} realm {name!r}",
                details={"realm": shown, "bind_password": "set (hidden)"},
                fingerprint={"body": body},
                blockers=blockers,
                side_effects=[
                    "FMC downloads users and groups on the schedule (daily from 00:00); run "
                    "fmc_download_realm to do it now."
                ],
            ),
            apply=lambda: applied(app, apply),
        )

    @reg.write(title="Download realm users and groups")
    async def fmc_download_realm(
        ctx: Context,
        realm: RealmRef,
        wait: Annotated[
            int, Field(ge=0, le=300, description="Seconds to wait for FMC's download task (0 = don't wait)")
        ] = DOWNLOAD_WAIT,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Download an AD/LDAP realm's users and groups now (the realm page's download button), so new
        directory groups can be used in access rules. Changes no policy; devices get new memberships with
        the next deploy of a policy using the realm. Needs FMC_UI_USERNAME: FMC's REST API can't start an
        AD/LDAP download. Check the result with fmc_get_realm (users, groups, last sync)."""
        app: FmcApp = get_client(ctx)
        r = await resolve_realm(app, realm, domain)
        before = await members_of(app, r["id"], domain)
        blockers = []
        if (r.get("metadata") or {}).get("isDownloading"):
            blockers.append("FMC is already downloading this realm; check fmc_get_realm in a minute.")
        if not r.get("enabled", True):
            blockers.append("The realm is disabled; FMC doesn't download disabled realms.")
        try:
            ui_credentials(app.settings)
        except InvalidRequest as e:
            blockers.append(str(e))

        async def apply() -> Any:
            async with FmcUiSession(app.settings) as ui:
                seen = {m.get("uuid") for m in await download_messages(ui, str(r.get("name")))}
                await ui.pjb("SF::IdentityRealm::IdentityRealm::refreshRealm", [r["id"]])
                result: dict[str, Any] = {"realm": r.get("name"), "status": "started"}
                started = time.monotonic()
                deadline = time.monotonic() + wait
                while wait and time.monotonic() < deadline:
                    await asyncio.sleep(3)
                    new = [
                        m
                        for m in await download_messages(ui, str(r.get("name")))
                        if m.get("uuid") not in seen
                    ]
                    done = [
                        m
                        for m in new
                        if str(m.get("status") or "").lower() not in ("", "running", "pending", "in progress")
                    ]
                    if not done and new and time.monotonic() - started > 15:
                        cur = await app.api.get(await app.config_path(f"{REALMS}/{r['id']}", domain))
                        if not (cur.get("metadata") or {}).get("isDownloading"):
                            done = new
                    if done:
                        result["status"] = str(done[0].get("status")).lower()
                        result["fmc_message"] = _strip(done[0].get("body"))[:400]
                        break
                else:
                    if wait:
                        result["status"] = "running"
                        result["note"] = f"Not finished after {wait} s; check fmc_get_realm later."
            after = await members_of(app, r["id"], domain)
            result["downloaded"] = {
                "groups": {"before": len(before["groups"]), "after": len(after["groups"])},
                "users": {"before": len(before["users"]), "after": len(after["users"])},
            }
            added = sorted(
                {str(g.get("name")) for g in after["groups"]} - {str(g.get("name")) for g in before["groups"]}
            )
            if added:
                result["new_groups"] = added[:MEMBER_CAP]
            return result

        return await fmc_preview(
            ctx,
            tool="fmc_download_realm",
            args={"realm": realm, "wait": wait, "domain": domain},
            confirm=confirm,
            owned=[r],
            plan=Plan(
                f"Download users and groups of realm {r.get('name')!r} now",
                details={
                    "realm": realm_row(r),
                    "downloaded_now": {"groups": len(before["groups"]), "users": len(before["users"])},
                },
                fingerprint=r.get("id"),
                blockers=blockers,
                side_effects=[
                    "A directory download task on FMC (LDAP reads only); no policy changes.",
                    "Logs in to the FMC web UI as FMC_UI_USERNAME for the duration (ends that user's other "
                    "UI session).",
                ],
            ),
            apply=lambda: applied(app, apply),
        )

    @reg.write(title="Delete realm", destructive=True)
    async def fmc_delete_realm(
        ctx: Context,
        realm: RealmRef,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete an AD/LDAP realm and its downloaded users and groups. Refused while identity rules or
        access rules use it (remove those first: fmc_get_identity_policy shows the identity rules)."""
        app: FmcApp = get_client(ctx)
        r = await resolve_realm(app, realm, domain)
        blockers = []
        page = await app.all(await app.config_path(IDENTITY, domain))
        users = []
        for p in page.items:
            rules = await all_rules(app, await app.config_path(f"{IDENTITY}/{p['id']}/identityrules", domain))
            users += [
                f"{p.get('name')} / {x.get('name')}"
                for x in rules.items
                if (x.get("realm") or {}).get("id") == r["id"]
            ]
        if users:
            blockers.append(f"Identity rules use this realm: {'; '.join(users)}. Delete them first.")
        acps = await app.all(await app.config_path(ACCESS, domain))
        in_rules = []
        for acp in acps.items:
            rows = await all_rules(app, await app.config_path(f"{ACCESS}/{acp['id']}/accessrules", domain))
            in_rules += [
                f"{acp.get('name')} / {x.get('name')}"
                for x in rows.items
                if any(
                    (o.get("realm") or {}).get("id") == r["id"]
                    for o in ((x.get("users") or {}).get("objects") or [])
                )
            ]
        if in_rules:
            blockers.append(
                f"Access rules use its users or groups: {'; '.join(in_rules[:10])}. "
                "Change or delete them first."
            )
        path = await app.config_path(f"{REALMS}/{r['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_realm",
            args={"realm": realm, "domain": domain},
            confirm=confirm,
            owned=[r],
            plan=Plan(
                f"Delete realm {r.get('name')!r}",
                details={"realm": realm_row(r)},
                fingerprint=r.get("id"),
                blockers=blockers,
                side_effects=["Access rules can no longer match its users and groups."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )

    # --- identity policy writes -----------------------------------------------------------------------

    @reg.write(title="Create identity policy")
    async def fmc_create_identity_policy(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="New policy name")],
        description: Annotated[str | None, Field(description="Description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create an empty identity policy. Add rules with fmc_create_identity_rule (which realm, how users
        are identified), then select it in the access policy editor's Identity step (FMC's REST API
        can't set that link) and deploy."""
        app: FmcApp = get_client(ctx)
        blockers = []
        try:
            await resolve_in(app, IDENTITY, name, "identity policy", domain)
            blockers.append(f"An identity policy named {name!r} already exists.")
        except NotFound:
            pass
        body: dict[str, Any] = {"name": name, "type": "IdentityPolicy"}
        if description:
            body["description"] = description
        path = await app.config_path(IDENTITY, domain)

        async def apply() -> Any:
            res = await app.api.post(path, body)
            return {"name": res.get("name"), "id": res.get("id"), "next": "fmc_create_identity_rule"}

        return await fmc_preview(
            ctx,
            tool="fmc_create_identity_policy",
            args={"name": name, "description": description, "domain": domain},
            confirm=confirm,
            plan=Plan(f"Create identity policy {name!r}", details={"body": body}, blockers=blockers),
            apply=lambda: applied(app, apply),
        )

    @reg.write(title="Create identity rule")
    async def fmc_create_identity_rule(
        ctx: Context,
        policy: PolicyRef,
        name: Annotated[str, Field(min_length=1, max_length=50, description="Rule name")],
        authentication: Annotated[
            AuthType,
            Field(
                description="PASSIVE: take user-IP mappings from ISE/pxGrid, the passive identity agent or "
                "TS agent; ACTIVE: captive portal (needs the policy's active-auth certificate and port); "
                "NO: don't identify users for this traffic"
            ),
        ] = "PASSIVE",
        realm: Annotated[
            str | None, Field(description="Realm name or UUID (required unless authentication is NO)")
        ] = None,
        active_protocol: Annotated[
            ActiveProtocol | None, Field(description="Captive portal method (ACTIVE only)")
        ] = None,
        guest_fallback: Annotated[
            bool, Field(description="ACTIVE: let users who fail to authenticate in as guests")
        ] = False,
        source_zones: ZonesParam = None,
        destination_zones: ZonesParam = None,
        source_networks: NetsParam = None,
        destination_networks: NetsParam = None,
        destination_ports: PortsParam = None,
        enabled: Annotated[bool, Field(description="Create the rule enabled")] = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Add a rule to an identity policy (appended to its standard rules): traffic matching the zones,
        networks and ports gets its user from the realm by the chosen method. Identity rules don't match
        users or groups themselves; access rules do (fmc_create_access_rule users=[...]). Deploy the
        devices whose access policy uses the identity policy."""
        app: FmcApp = get_client(ctx)
        if authentication != "NO" and not realm:
            raise InvalidRequest(f"A {authentication} identity rule needs a realm.")
        if active_protocol and authentication != "ACTIVE":
            raise InvalidRequest("active_protocol is only for ACTIVE (captive portal) rules.")
        p = await resolve_in(app, IDENTITY, policy, "identity policy", domain)
        body: dict[str, Any] = {
            "name": name,
            "type": "IdentityPolicyRule",
            "enabled": enabled,
            "authenticationType": authentication,
        }
        if realm:
            rr = await resolve_realm(app, realm, domain)
            body["realm"] = {"id": rr["id"], "type": "IdentityRealm", "name": rr.get("name")}
        if authentication == "ACTIVE":
            body["authenticationProtocol"] = active_protocol or "HTTP_BASIC"
            body["guestAccessFallback"] = guest_fallback
        resolver = RefResolver(app, domain)
        for field, values, kind in (
            ("sourceZones", source_zones, "zone"),
            ("destinationZones", destination_zones, "zone"),
            ("sourceNetworks", source_networks, "network"),
            ("destinationNetworks", destination_networks, "network"),
            ("destinationPorts", destination_ports, "port"),
        ):
            block = await resolver.block(values, kind)
            if block:
                # identity rules take zones as a plain list of references
                body[field] = block.get("objects", []) if kind == "zone" else block
        base = await app.config_path(f"{IDENTITY}/{p['id']}/identityrules", domain)
        existing = await all_rules(app, base)
        cats = await app.all(await app.config_path(f"{IDENTITY}/{p['id']}/identitycategories", domain))
        standard = next((c for c in cats.items if c.get("name") == "standard_category"), None)
        blockers = []
        if standard is None:
            blockers.append("The identity policy has no standard rule category (FMC's built-in one).")
        if any(str(r.get("name", "")).lower() == name.lower() for r in existing.items):
            blockers.append(f"{p.get('name')!r} already has a rule named {name!r}.")
        side = ["Takes effect on devices after the next deployment."]
        if authentication == "ACTIVE":
            side.append(
                "Captive portal also needs the identity policy's active authentication settings (server "
                "certificate, port 885) and a routed interface; set those in the FMC UI."
            )
        if authentication == "PASSIVE":
            side.append(
                "Users are only known on the device once a passive source (ISE/pxGrid, passive identity "
                "agent, TS agent) reports user-IP mappings to FMC."
            )
        params = {"intoCategory": (standard or {}).get("id", "")}
        return await fmc_preview(
            ctx,
            tool="fmc_create_identity_rule",
            args={
                "policy": policy,
                "name": name,
                "authentication": authentication,
                "realm": realm,
                "active_protocol": active_protocol,
                "guest_fallback": guest_fallback,
                "source_zones": source_zones,
                "destination_zones": destination_zones,
                "source_networks": source_networks,
                "destination_networks": destination_networks,
                "destination_ports": destination_ports,
                "enabled": enabled,
                "domain": domain,
            },
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Add identity rule {name!r} ({authentication}) to {p.get('name')!r}",
                details={"rule": identity_rule_row(body), "rules_now": len(existing.items)},
                fingerprint={"policy": p["id"], "rules": [r.get("id") for r in existing.items], "body": body},
                blockers=blockers,
                side_effects=side,
            ),
            apply=lambda: applied(app, lambda: app.api.post(base, body, params=params)),
        )

    @reg.write(title="Delete identity rule", destructive=True)
    async def fmc_delete_identity_rule(
        ctx: Context,
        policy: PolicyRef,
        rule: Annotated[str, Field(description="Rule name or UUID")],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete an identity rule (fmc_get_identity_policy lists them). FMC refuses it while access rules
        still use a user or group of the rule's realm in an access policy that uses this identity policy."""
        app: FmcApp = get_client(ctx)
        p = await resolve_in(app, IDENTITY, policy, "identity policy", domain)
        base = await app.config_path(f"{IDENTITY}/{p['id']}/identityrules", domain)
        rules = await all_rules(app, base)
        hits = [
            r for r in rules.items if r.get("id") == rule or str(r.get("name", "")).lower() == rule.lower()
        ]
        if len(hits) != 1:
            raise NotFound(f"No single identity rule {rule!r} in {p.get('name')!r}.", 404)
        r = hits[0]
        return await fmc_preview(
            ctx,
            tool="fmc_delete_identity_rule",
            args={"policy": policy, "rule": rule, "domain": domain},
            confirm=confirm,
            owned=[p],
            plan=Plan(
                f"Delete identity rule {r.get('name')!r} from {p.get('name')!r}",
                details={"rule": identity_rule_row(r)},
                fingerprint=r.get("id"),
                side_effects=["Takes effect on devices after the next deployment."],
            ),
            apply=lambda: applied(app, lambda: app.api.delete(f"{base}/{r['id']}")),
        )

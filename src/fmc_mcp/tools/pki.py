"""PKI objects for TLS decryption (F64): internal CAs (the CA a decrypt-resign rule re-signs server
certificates with), internal certificates (a server's own certificate and key, for decrypt-known-key) and
trusted CAs (the issuers the FTD trusts when it checks a server's certificate).

Private keys never pass through MCP arguments or results. fmc_create_internal_ca has FMC generate the key
pair itself (a self-signed CA, or a CSR for the organisation's CA to sign, finished with
fmc_install_internal_ca_cert); fmc_import_certificate_files reads an existing certificate and key from
FMC_PKI_DIR on the server host (like CML's image directory), so only file names travel. FMC masks keys on
read ('********'), and these tools never return them."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
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
    UpstreamError,
    get_client,
    list_result,
)
from fmc_mcp._core.http import page_of
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.preview import fmc_preview
from fmc_mcp.tools.common import Domain, is_system, pick_by_name
from fmc_mcp.tools.identity import PEM_RE, fmc_fingerprint, pem_body
from fmc_mcp.tools.object_writes import applied
from fmc_mcp.tools.render import object_reply

INTERNAL_CAS = "object/internalcas"
INTERNAL_CERTS = "object/internalcertificates"
TRUSTED_CAS = "object/externalcacertificates"
TRUSTED_CA_GROUPS = "object/externalcacertificategroups"
DECRYPTION = "policy/decryptionpolicies"
REALMS = "object/realms"
DEFAULT_TRUSTED_GROUP = "Cisco-Trusted-Authorities"  # FMC's system group of public root CAs
EXPIRY_WARN_DAYS = 30
USED_BY_POLICY_CAP = 25  # decryption policies scanned for references
MAX_PKI_FILE = 256 * 1024  # bytes; PEM certificates, chains and keys are a few KB
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
# '-----BEGIN <kind>-----' of a private key: RSA/EC/PKCS#8, ENCRYPTED for an encrypted PKCS#8 key.
KEY_HEADER_RE = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY)-----")


@dataclass(frozen=True)
class CertKind:
    key: str  # our name
    path: str  # collection under the domain
    fmc_type: str  # "type" in references
    label: str  # for messages


KINDS: dict[str, CertKind] = {
    k.key: k
    for k in (
        CertKind("internal_ca", INTERNAL_CAS, "InternalCA", "internal CA"),
        CertKind("internal_cert", INTERNAL_CERTS, "InternalCertificate", "internal certificate"),
        CertKind("trusted_ca", TRUSTED_CAS, "ExternalCACertificate", "trusted CA"),
    )
}
CertKindName = Literal["internal_ca", "internal_cert", "trusted_ca"]
CertRef = Annotated[str, Field(description="Certificate object name or UUID (fmc_get_certificate)")]


# --- shaping ------------------------------------------------------------------------------------------


def parse_date(text: Any) -> datetime | None:
    """FMC's validity dates: ISO 8601 ('2032-03-01T23:24:38Z') on internal objects, OpenSSL style
    ('Jan 12 20:26:32 2042 GMT') on trusted CAs."""
    s = " ".join(str(text or "").split())
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        pass
    try:
        return datetime.strptime(s, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=UTC)
    except ValueError:
        return None


def has_cert(c: dict[str, Any]) -> bool:
    return bool(str(c.get("cert") or "").strip())


def csr_pending(c: dict[str, Any]) -> bool:
    """An internal CA created as a CSR whose signed certificate isn't installed yet."""
    return bool(str(c.get("csr") or "").strip()) and not has_cert(c)


def cert_row(c: dict[str, Any], kind: CertKind, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    end = parse_date(c.get("validityEndDate"))
    subject, issuer = c.get("subjectCommonName"), c.get("issuerCommonName")
    row: dict[str, Any] = {
        "name": c.get("name"),
        "kind": kind.key,
        "subject": subject or None,
        "organization": c.get("subjectOrganization") or None,
        "issuer": issuer or None,
        "self_signed": (subject == issuer and c.get("subjectOrganization") == c.get("issuerOrganization"))
        if subject and issuer
        else None,
        "valid_until": c.get("validityEndDate") or None,
        "days_left": (end - now).days if end else None,
        "expired": (end < now) if end else None,
        "csr_pending": True if csr_pending(c) else None,
        "fingerprint": c.get("certFingerprint") or None,
        "system": True if is_system(c) else None,
        "id": c.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


def ca_problems(c: dict[str, Any], now: datetime | None = None) -> list[str]:
    """Why an internal CA can't (or soon won't) re-sign certificates; [] when it is ready."""
    now = now or datetime.now(UTC)
    name = c.get("name")
    if csr_pending(c):
        return [
            f"{name!r} is still a CSR: sign it with your CA (as a subordinate CA) and install the signed "
            "certificate with fmc_install_internal_ca_cert."
        ]
    if not has_cert(c):
        return [f"{name!r} has no certificate."]
    end = parse_date(c.get("validityEndDate"))
    if end and end < now:
        return [f"{name!r} expired on {c.get('validityEndDate')}."]
    if end and (end - now).days < EXPIRY_WARN_DAYS:
        return [f"{name!r} expires in {(end - now).days} days ({c.get('validityEndDate')})."]
    return []


def ref(c: dict[str, Any], kind: CertKind) -> dict[str, Any]:
    return {"id": c["id"], "type": c.get("type") or kind.fmc_type, "name": c.get("name")}


# --- lookups ------------------------------------------------------------------------------------------


async def resolve_cert(
    app: FmcApp, ref_: str, kinds: list[CertKind], domain: str | None
) -> tuple[CertKind, dict[str, Any]]:
    """One certificate object by UUID or name among `kinds`, fully read (cert, CSR, validity)."""
    ref_ = ref_.strip()
    if not ref_:
        raise InvalidRequest("Empty certificate name.")
    if is_uuid(ref_):
        for k in kinds:
            try:
                obj = await app.api.get(f"{await app.config_path(k.path, domain)}/{ref_}")
            except NotFound:
                continue
            if isinstance(obj, dict) and obj.get("id"):
                return k, obj
        raise NotFound(f"No {' / '.join(k.label for k in kinds)} with id {ref_}.", 404)
    found: list[tuple[CertKind, dict[str, Any]]] = []
    every: list[dict[str, Any]] = []
    for k in kinds:
        page = await app.all(await app.config_path(k.path, domain), expanded=False)
        every += page.items
        try:
            found.append((k, pick_by_name(page.items, ref_, k.label)))
        except NotFound:
            continue
    if len(found) > 1:
        which = ", ".join(f"{k.key} {o.get('id')}" for k, o in found)
        raise InvalidRequest(f"{ref_!r} names several certificates ({which}); pass `kind` or the id.")
    if not found:
        what = " / ".join(k.label for k in kinds)
        pick_by_name(every, ref_, what)  # raises NotFound with close matches
        raise NotFound(f"No {what} named {ref_!r}.", 404)
    k, hit = found[0]
    full = await app.api.get(f"{await app.config_path(k.path, domain)}/{hit['id']}")
    return k, full


async def used_by(app: FmcApp, cert_id: str, domain: str | None) -> list[str]:
    """Where a certificate object is referenced: decryption rules (resign CA / known-key certificate),
    decryption policies (trusted CAs) and AD/LDAP realms (LDAPS CA)."""
    out: list[str] = []
    pols = await app.all(await app.config_path(DECRYPTION, domain))
    for p in pols.items[:USED_BY_POLICY_CAP]:
        trusted = p.get("trustedCAs") or {}
        refs = (trusted.get("objects") or []) + (trusted.get("groups") or [])
        if any(r.get("id") == cert_id for r in refs):
            out.append(f"decryption policy {p.get('name')} (trusted CA)")
        rules = await app.all(
            await app.config_path(f"{DECRYPTION}/{p['id']}/decryptionpolicyrules", domain), cap=1000
        )
        for r in rules.items:
            for field, what in (("decryptionCerts", "resign CA"), ("internalCerts", "known-key cert")):
                if any(o.get("id") == cert_id for o in (r.get(field) or {}).get("objects") or []):
                    out.append(f"decryption rule {p.get('name')}/{r.get('name')} ({what})")
    try:
        realms = await app.all(await app.config_path(REALMS, domain))
    except UpstreamError:
        realms = None
    for realm in realms.items if realms else []:
        for d in realm.get("directoryConfigurations") or []:
            if (d.get("encryptionCert") or {}).get("id") == cert_id:
                out.append(f"realm {realm.get('name')} (LDAPS CA)")
                break
    return out


async def trusted_group(app: FmcApp, domain: str | None) -> dict[str, Any] | None:
    """FMC's system group of public root CAs (the default trusted CAs of a decryption policy)."""
    page = await app.all(await app.config_path(TRUSTED_CA_GROUPS, domain), expanded=False)
    for g in page.items:
        if g.get("name") == DEFAULT_TRUSTED_GROUP:
            return {"id": g["id"], "type": "ExternalCACertificateGroup", "name": g["name"]}
    return None


async def resolve_trusted(app: FmcApp, names: list[str], domain: str | None) -> list[dict[str, Any]]:
    """Trusted CA objects or trusted CA groups by name or UUID, as references."""
    out: list[dict[str, Any]] = []
    groups = None
    for n in names:
        try:
            k, c = await resolve_cert(app, n, [KINDS["trusted_ca"]], domain)
            out.append(ref(c, k))
            continue
        except NotFound:
            pass
        if groups is None:
            groups = (await app.all(await app.config_path(TRUSTED_CA_GROUPS, domain), expanded=False)).items
        hits = [g for g in groups if g.get("id") == n or str(g.get("name", "")).lower() == n.strip().lower()]
        if not hits:
            raise NotFound(
                f"No trusted CA or trusted CA group named {n!r}. Import the server's issuing CA with "
                "fmc_create_trusted_ca first.",
                404,
            )
        g = hits[0]
        out.append({"id": g["id"], "type": "ExternalCACertificateGroup", "name": g.get("name")})
    return out


# --- files from FMC_PKI_DIR ---------------------------------------------------------------------------


@dataclass
class PkiFile:
    path: Path
    text: str
    identity: tuple[int, int, int, int]  # device, inode, size, mtime_ns: a confirm needs the same file
    group_or_world_readable: bool


def read_pki_file(pki_dir: Path | None, name: str, what: str) -> PkiFile:
    """A file inside FMC_PKI_DIR (no paths outside it, also not through symlinks), read as text."""
    if not pki_dir:
        raise InvalidRequest(
            "Certificate file import is off: set FMC_PKI_DIR to a directory on the MCP server host that "
            "holds the certificate and key files (read there and sent to FMC only, never through MCP). "
            "Or let FMC generate the key with fmc_create_internal_ca."
        )
    try:
        root = Path(os.path.expanduser(str(pki_dir))).resolve()
        if not root.is_dir():
            raise InvalidRequest(f"FMC_PKI_DIR {str(root)!r} is not a directory")
        candidate = (root / name).resolve()
        inside = candidate != root and root in candidate.parents
        st = candidate.stat() if inside and candidate.is_file() else None
    except (OSError, ValueError) as e:
        raise InvalidRequest(f"Bad {what} name {name!r}: {e}") from None
    if not inside:
        raise InvalidRequest(f"{what} {name!r} is outside FMC_PKI_DIR")
    if st is None or not stat.S_ISREG(st.st_mode):
        raise InvalidRequest(f"No file {name!r} in FMC_PKI_DIR ({what})")
    if st.st_size > MAX_PKI_FILE:
        raise InvalidRequest(f"{what} {name!r} is {st.st_size} bytes; a PEM file is a few KB")
    try:
        text = candidate.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        raise InvalidRequest(f"{what} {name!r} is not a PEM text file") from None
    return PkiFile(
        candidate,
        text,
        (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns),
        bool(st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)),
    )


def pem_chain(text: str) -> tuple[str, str]:
    """(normalised PEM chain, SHA-1 fingerprint of the first certificate) of 1+ certificates."""
    blocks = PEM_RE.findall(text or "")
    if not blocks:
        raise InvalidRequest("No PEM certificate found (-----BEGIN CERTIFICATE----- ... END).")
    parts, first_fp = [], ""
    for i, b in enumerate(blocks):
        pem, der = pem_body(f"-----BEGIN CERTIFICATE-----\n{b}\n-----END CERTIFICATE-----")
        parts.append(pem)
        if i == 0:
            first_fp = fmc_fingerprint(der)
    return "".join(parts), first_fp


def key_kind(text: str) -> tuple[str, bool]:
    """(the key's PEM label, encrypted?) of the one private key in a key file."""
    found = KEY_HEADER_RE.findall(text)
    if len(found) != 1:
        raise InvalidRequest("The key file must hold exactly one PEM private key.")
    label = found[0]
    return label, label.startswith("ENCRYPTED") or "Proc-Type: 4,ENCRYPTED" in text


# --- tools --------------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.read(title="Certificates for TLS decryption")
    async def fmc_get_certificate(
        ctx: Context,
        certificate: Annotated[
            str | None, Field(description="Certificate object name or UUID; omit to list")
        ] = None,
        kind: Annotated[
            CertKindName | None,
            Field(
                description="internal_ca (re-signs for DECRYPT_RESIGN), internal_cert (server certificate "
                "+ key for DECRYPT_KNOWN_KEY) or trusted_ca; default: all three"
            ),
        ] = None,
        include_system: Annotated[
            bool, Field(description="List FMC's ~100 built-in public root CAs too (trusted_ca)")
        ] = False,
        domain: Domain = None,
        response_format: ResponseFormat = "markdown",
    ) -> ToolResult:
        """List the certificate objects TLS decryption uses (internal CAs, internal certificates, custom
        trusted CAs) with subject, issuer, expiry and fingerprint, or show one with its PEM certificate
        (public; private keys are never shown), a pending CSR, what references it, and what to do next
        (e.g. the PEM to install as a trusted root on clients before a decrypt-resign rollout). Create
        them with fmc_create_internal_ca, fmc_import_certificate_files or fmc_create_trusted_ca; what
        decryption does to one flow: fmc_tls_decryption_check."""
        app: FmcApp = get_client(ctx)
        kinds = [KINDS[kind]] if kind else list(KINDS.values())
        if not certificate:
            rows: list[dict[str, Any]] = []
            for k in kinds:
                page = await app.all(await app.config_path(k.path, domain))
                rows += [
                    cert_row(c, k)
                    for c in page.items
                    if include_system or k.key != "trusted_ca" or not is_system(c)
                ]
            return list_result(page_of(rows, limit=1000, offset=0), fmt=response_format)
        k, c = await resolve_cert(app, certificate, kinds, domain)
        out: dict[str, Any] = cert_row(c, k)
        if has_cert(c):
            out["certificate_pem"] = str(c["cert"])
        if csr_pending(c):
            out["csr_pem"] = str(c["csr"])
        out["used_by"] = await used_by(app, str(c["id"]), domain)
        notes: list[str] = []
        if k.key == "internal_ca":
            notes += ca_problems(c)
            if has_cert(c):
                notes.append(
                    "Clients must trust this CA before decrypt-resign: install certificate_pem as a trusted "
                    "root (GPO, MDM, or the OS/browser trust store). Then fmc_create_decryption_rule "
                    f"action='DECRYPT_RESIGN' internal_ca={c.get('name')!r}."
                )
        elif k.key == "internal_cert":
            notes.append(
                "For inbound decryption of your own server: fmc_create_decryption_rule "
                f"action='DECRYPT_KNOWN_KEY' internal_certificates=[{c.get('name')!r}] with the server as "
                "destination."
            )
        if notes:
            out["notes"] = notes
        return object_reply(out, fmt=response_format)

    @reg.write(title="Create internal CA (key generated on FMC)")
    async def fmc_create_internal_ca(
        ctx: Context,
        name: Annotated[str, Field(min_length=1, max_length=64, description="Internal CA object name")],
        common_name: Annotated[
            str,
            Field(
                min_length=1, max_length=64, description="Subject CN, e.g. 'Example Corp TLS Inspection CA'"
            ),
        ],
        organization: Annotated[str | None, Field(max_length=64, description="Subject O")] = None,
        organization_unit: Annotated[str | None, Field(max_length=64, description="Subject OU")] = None,
        country: Annotated[
            str | None, Field(pattern=r"^[A-Za-z]{2}$", description="Subject C, two letters (ISO 3166)")
        ] = None,
        state: Annotated[str | None, Field(max_length=64, description="Subject ST")] = None,
        locality: Annotated[str | None, Field(max_length=64, description="Subject L")] = None,
        csr: Annotated[
            bool,
            Field(
                description="false: FMC makes a self-signed CA (clients must trust it); true: FMC makes a "
                "CSR for your organisation's CA to sign as a subordinate CA (clients that already trust "
                "that CA trust the result), finished with fmc_install_internal_ca_cert"
            ),
        ] = False,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create the internal CA a decrypt-resign rule re-signs server certificates with. FMC generates
        the key pair itself, so no private key is handled here: either a self-signed CA (quickest; push its
        certificate to clients as a trusted root) or a CSR for your enterprise CA (sign it, e.g. with a
        subordinate-CA template, then fmc_install_internal_ca_cert). To import an existing CA certificate
        and key instead, use fmc_import_certificate_files. Returns the CA certificate (or CSR) in PEM."""
        app: FmcApp = get_client(ctx)
        k = KINDS["internal_ca"]
        page = await app.all(await app.config_path(k.path, domain), expanded=False)
        blockers = []
        if any(str(c.get("name", "")).lower() == name.lower() for c in page.items):
            blockers.append(f"An internal CA named {name!r} already exists.")
        subject = {
            "subjectCommonName": common_name,
            "subjectOrganization": organization,
            "subjectOrganizationUnit": organization_unit,
            "subjectCountry": country.upper() if country else None,
            "subjectState": state,
            "subjectLocality": locality,
        }
        body: dict[str, Any] = {
            "name": name,
            "type": "InternalCA",
            **{f: v for f, v in subject.items() if v},
        }
        path = await app.config_path(k.path, domain)
        params = {"isCSR": "true" if csr else "false"}

        async def apply() -> Any:
            res = await app.api.post(path, body, params=params)
            full = await app.api.get(f"{path}/{res['id']}")
            out = cert_row(full, k)
            if has_cert(full):
                out["certificate_pem"] = str(full["cert"])
                out["next"] = (
                    "Install certificate_pem as a trusted root on the clients, then "
                    f"fmc_create_decryption_rule action='DECRYPT_RESIGN' internal_ca={name!r}."
                )
            if csr_pending(full):
                out["csr_pem"] = str(full["csr"])
                out["next"] = (
                    "Sign csr_pem with your CA as a subordinate CA (basicConstraints CA:TRUE), then "
                    f"fmc_install_internal_ca_cert ca={name!r} with the signed certificate."
                )
            return out

        return await fmc_preview(
            ctx,
            tool="fmc_create_internal_ca",
            args={
                "name": name,
                "common_name": common_name,
                "organization": organization,
                "organization_unit": organization_unit,
                "country": country,
                "state": state,
                "locality": locality,
                "csr": csr,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create internal CA {name!r} ({'CSR' if csr else 'self-signed'}, key generated on FMC)",
                details={
                    "subject": {f: v for f, v in subject.items() if v},
                    "method": "csr" if csr else "self_signed",
                },
                blockers=blockers,
                side_effects=[
                    "FMC generates and keeps the private key; this server never sees it.",
                    "Self-signed: FMC's default validity is 10 years; clients must trust the certificate "
                    "before decrypt-resign rules use it."
                    if not csr
                    else "Nothing re-signs until the signed certificate is installed "
                    "(fmc_install_internal_ca_cert).",
                ],
            ),
            apply=lambda: applied(app, apply),
        )

    @reg.write(title="Install signed certificate on an internal CA")
    async def fmc_install_internal_ca_cert(
        ctx: Context,
        ca: Annotated[str, Field(description="Internal CA created with csr=true (name or UUID)")],
        certificate: Annotated[
            str,
            Field(
                description="The signed CA certificate in PEM (public), optionally followed by its issuing "
                "chain; never a private key"
            ),
        ],
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Finish an internal CA created as a CSR (fmc_create_internal_ca csr=true): install the certificate
        your CA signed. FMC checks that it matches the key it generated. After this the CA can be used in
        DECRYPT_RESIGN rules; clients that trust your CA trust the re-signed certificates."""
        app: FmcApp = get_client(ctx)
        if "PRIVATE KEY" in certificate:
            raise InvalidRequest("That text contains a private key; give only the signed certificate (PEM).")
        chain, fp = pem_chain(certificate)
        k, c = await resolve_cert(app, ca, [KINDS["internal_ca"]], domain)
        blockers = []
        if has_cert(c) and not csr_pending(c):
            blockers.append(
                f"{c.get('name')!r} already has a certificate (fingerprint {c.get('certFingerprint')}); to "
                "rotate, create a new internal CA and point the decrypt-resign rules at it."
            )
        elif not csr_pending(c):
            blockers.append(f"{c.get('name')!r} has no pending CSR.")
        path = await app.config_path(f"{k.path}/{c['id']}", domain)
        body = {"id": c["id"], "name": c.get("name"), "type": "InternalCA", "cert": chain}

        async def apply() -> Any:
            await app.api.put(path, body)
            full = await app.api.get(path)
            out = cert_row(full, k)
            out["certificate_pem"] = str(full.get("cert") or chain)
            return out

        return await fmc_preview(
            ctx,
            tool="fmc_install_internal_ca_cert",
            args={"ca": ca, "certificate": fp, "domain": domain},
            confirm=confirm,
            owned=[c],
            plan=Plan(
                f"Install the signed certificate on internal CA {c.get('name')!r}",
                details={"sha1_fingerprint": fp, "certificates_in_chain": chain.count("BEGIN CERTIFICATE")},
                fingerprint={"ca": c["id"], "cert": fp, "csr": c.get("csr")},
                blockers=blockers,
            ),
            apply=lambda: applied(app, apply),
        )

    @reg.write(title="Import certificate and key files (FMC_PKI_DIR)")
    async def fmc_import_certificate_files(
        ctx: Context,
        kind: Annotated[
            Literal["internal_ca", "internal_cert"],
            Field(
                description="internal_ca: an existing CA certificate + key for DECRYPT_RESIGN; "
                "internal_cert: your server's certificate (+ chain) + key for DECRYPT_KNOWN_KEY"
            ),
        ],
        name: Annotated[str, Field(min_length=1, max_length=64, description="New object name")],
        cert_file: Annotated[
            str,
            Field(description="PEM certificate file name inside FMC_PKI_DIR (certificate first, then chain)"),
        ],
        key_file: Annotated[str, Field(description="PEM private key file name inside FMC_PKI_DIR")],
        passphrase_file: Annotated[
            str | None, Field(description="File in FMC_PKI_DIR holding the passphrase of an encrypted key")
        ] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Import an existing certificate and private key as an internal CA or internal certificate. The
        files are read by this server from FMC_PKI_DIR on its own host and sent to FMC; only their names
        pass through MCP, and the key is never shown (FMC masks it too). The preview shows the certificate
        fingerprint and the key type; the confirm is refused if a file changed since the preview. Prefer
        fmc_create_internal_ca (FMC generates the key) when you don't need an existing CA."""
        app: FmcApp = get_client(ctx)
        k = KINDS[kind]
        pki_dir = app.settings.pki_dir

        def load() -> tuple[str, str, str, str | None, bool, list[PkiFile]]:
            cert = read_pki_file(pki_dir, cert_file, "cert_file")
            key = read_pki_file(pki_dir, key_file, "key_file")
            if KEY_HEADER_RE.search(cert.text) or "PRIVATE KEY" in cert.text:
                raise InvalidRequest("cert_file contains a private key; keep the key in key_file only.")
            chain, fp = pem_chain(cert.text)
            label, encrypted = key_kind(key.text)
            files = [cert, key]
            phrase = None
            if passphrase_file:
                pf = read_pki_file(pki_dir, passphrase_file, "passphrase_file")
                phrase = pf.text.strip("\r\n")
                files.append(pf)
            return chain, fp, label, phrase, encrypted, files

        chain, fp, label, phrase, encrypted, files = load()
        if KEY_HEADER_RE.search(chain):  # pragma: no cover - pem_chain only keeps certificates
            raise InvalidRequest("Refusing to send a key as a certificate.")
        page = await app.all(await app.config_path(k.path, domain))
        blockers = []
        for c in page.items:
            if str(c.get("name", "")).lower() == name.lower():
                blockers.append(f"A {k.label} named {c.get('name')!r} already exists.")
            elif str(c.get("certFingerprint", "")).upper() == fp:
                blockers.append(f"This certificate is already imported as {c.get('name')!r}.")
        if encrypted and not phrase:
            blockers.append(
                "The key is encrypted: put its passphrase in a file in FMC_PKI_DIR (passphrase_file)."
            )
        warnings = [
            f"{f.path.name} is readable by group or others on the server host; chmod 600 it."
            for f in files[1:]
            if f.group_or_world_readable
        ]
        identities = [f.identity for f in files]
        path = await app.config_path(k.path, domain)

        async def apply() -> Any:
            chain2, fp2, _, phrase2, _, files2 = load()
            if [f.identity for f in files2] != identities or fp2 != fp:
                raise InvalidRequest("A file changed since the preview; nothing was imported. Preview again.")
            key_text = files2[1].text
            body: dict[str, Any] = {"name": name, "type": k.fmc_type, "cert": chain2, "privateKey": key_text}
            if phrase2:
                body["passPhrase"] = phrase2
            params = {"isCSR": "false"} if kind == "internal_ca" else None
            res = await app.api.post(path, body, params=params)
            full = await app.api.get(f"{path}/{res['id']}")
            out = cert_row(full, k)
            out["certificate_pem"] = str(full.get("cert") or "")
            return out

        return await fmc_preview(
            ctx,
            tool="fmc_import_certificate_files",
            args={
                "kind": kind,
                "name": name,
                "cert_file": cert_file,
                "key_file": key_file,
                "passphrase_file": passphrase_file,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Import {k.label} {name!r} from {cert_file} + {key_file}",
                details={
                    "sha1_fingerprint": fp,
                    "certificates_in_chain": chain.count("BEGIN CERTIFICATE"),
                    "key": f"{label}{' (encrypted)' if encrypted else ''}",
                    **({"warnings": warnings} if warnings else {}),
                },
                fingerprint={"files": identities, "cert": fp},
                blockers=blockers,
                side_effects=["The private key is sent to FMC only; this server never returns it."],
            ),
            apply=lambda: applied(app, apply),
        )

    @reg.write(title="Delete certificate object", destructive=True)
    async def fmc_delete_certificate(
        ctx: Context,
        certificate: CertRef,
        kind: Annotated[CertKindName | None, Field(description="Narrow the lookup to one kind")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Delete an internal CA, internal certificate or custom trusted CA. Blocked while a decryption rule,
        decryption policy or realm references it (the preview lists them; so does fmc_get_certificate) and
        for FMC's built-in CAs."""
        app: FmcApp = get_client(ctx)
        k, c = await resolve_cert(app, certificate, [KINDS[kind]] if kind else list(KINDS.values()), domain)
        blockers = []
        if is_system(c):
            blockers.append("Read-only system certificate.")
        users = await used_by(app, str(c["id"]), domain)
        if users:
            blockers.append(f"Still referenced by: {', '.join(users)}. Remove those references first.")
        path = await app.config_path(f"{k.path}/{c['id']}", domain)
        return await fmc_preview(
            ctx,
            tool="fmc_delete_certificate",
            args={"certificate": certificate, "kind": kind, "domain": domain},
            confirm=confirm,
            owned=[c],
            plan=Plan(
                f"Delete {k.label} {c.get('name')!r}",
                details={"certificate": cert_row(c, k)},
                fingerprint={"id": c["id"], "fingerprint": c.get("certFingerprint"), "used_by": users},
                blockers=blockers,
            ),
            apply=lambda: applied(app, lambda: app.api.delete(path)),
        )

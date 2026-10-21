"""F75: the FTD certificate enrolment lifecycle. fmc_create_cert_enrollment creates the enrollment object
(object/certenrollments: what the device's trustpoint holds and how it gets its certificate) and
fmc_enroll_certificate acts on one device with it (devices/operational/managecertificates: ENROLL,
RE_ENROLL, REFRESH, DELETE), which reaches the device at once, without a deployment. fmc_list_certificates
(F71) reads the result.

Kinds: self_signed (the device generates the key and a self-signed certificate), pkcs12 (an existing
identity certificate, its key and CA chain), manual_ca_only (only a CA certificate: a trustpoint for
validating peers; FMC's manual identity-certificate step is a CSR the REST API can't do), scep and est (the
device requests a certificate from a CA server). ACME and EXPORT (a binary download) stay in the FMC UI.

Secrets never pass through MCP arguments, previews, results or logs: a PKCS12 is read from a file in
FMC_PKI_DIR on the server host (binary or base64), its passphrase from a file next to it or the server's
FMC_PKI_PASSPHRASE, and a SCEP challenge / EST password from a file there too, as fmc_import_certificate_files
reads keys. FMC returns the PKCS12 bundle (the identity certificate and its encrypted key) on every read of
the object, so this module strips it from results and adds `base64Certificate` to the secret-key pattern
that masks fmc_api_call's answers and the audit log."""

# No `from __future__ import annotations`: FastMCP inspects signatures at runtime.
import base64
import binascii
import copy
import hashlib
import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs12
from fastmcp import Context
from pydantic import BaseModel, ConfigDict, Field

from fmc_mcp._core import (
    Confirm,
    InvalidRequest,
    Plan,
    TaskFailed,
    ToolRegistrar,
    UpstreamError,
    UpstreamTimeout,
    get_client,
    get_settings,
    poll_until,
)
from fmc_mcp._core import formatting as _formatting
from fmc_mcp._core.secrets import register_secret
from fmc_mcp.client import FmcApp, is_uuid
from fmc_mcp.preview import fmc_preview
from fmc_mcp.rails import check_deploy_window, deploy_window_blockers
from fmc_mcp.tools.certificates import DEVICE_CERTS, device_rows
from fmc_mcp.tools.common import Domain, pick_by_name, resolve_in
from fmc_mcp.tools.dangerous import Wait, task_id_of, task_state
from fmc_mcp.tools.devices import DEVICES, DeviceRef, membership_of
from fmc_mcp.tools.identity import fmc_fingerprint, pem_body
from fmc_mcp.tools.object_writes import applied
from fmc_mcp.tools.pki import DECRYPTION, pki_path
from fmc_mcp.tools.vpn import RAVPN, S2S

ENROLLMENTS = "object/certenrollments"
MANAGE = "devices/operational/managecertificates"
TOOL_CREATE = "fmc_create_cert_enrollment"
TOOL_ENROLL = "fmc_enroll_certificate"
MASK = "********"
PKI_OFF = (
    "Reading certificate files is off: set FMC_PKI_DIR to a directory on the MCP server host that holds the "
    "PKCS12 / CA certificate / password files (read there and sent to FMC only, never through MCP). Or use "
    "kind='self_signed', where the device generates its own key."
)

# Our kind -> FMC's enrollmentType (SELF_SIGNED_CERTFICATE is FMC's own spelling).
FMC_KIND = {
    "self_signed": "SELF_SIGNED_CERTFICATE",
    "pkcs12": "PKCS12",
    "manual_ca_only": "MANUAL",
    "scep": "SCEP",
    "est": "EST",
}
KIND_OF = {v: k for k, v in FMC_KIND.items()} | {"ACME": "acme"}
EnrollmentKind = Literal["self_signed", "pkcs12", "manual_ca_only", "scep", "est"]
KEY_SIZES = {"RSA": (2048, 3072, 4096), "ECDSA": (256, 384, 521), "EdDSA": (256,)}
DEFAULT_KEY_SIZE = {"RSA": 2048, "ECDSA": 256, "EdDSA": 256}
USAGE_FIELDS = {"ipsec_client": "ipsecClient", "ssl_client": "sslClient", "ssl_server": "sslServer"}
FINGERPRINT_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")

ACTIONS = {"enroll": "ENROLL", "re_enroll": "RE_ENROLL", "refresh": "REFRESH", "delete": "DELETE"}
EnrolAction = Literal["enroll", "re_enroll", "refresh", "delete"]
FAILED_STATES = {"FAILED", "ABORTED"}
BUSY_STATES = {"IN_PROGRESS"}
EXTRA_DONE = {"enrolled", "finished", "done"}  # task words beyond dangerous.DONE, in case FMC uses them
POLICY_CAP = 25  # RA VPN policies, S2S topologies and decryption policies scanned for references
# Where FMC 10.0.1's schemas let a policy reference an enrollment (FTDRAVpnModel, VpnIkeSettings).
REF_LABELS = {
    "accessInterfaceSettings.sslIdCertificate": "SSL identity certificate",
    "accessInterfaceSettings.ipsecIdCertificate": "IPsec-IKEv2 identity certificate",
    "accessInterfaceSettings.interfaceSettings[].idCertificate": "access interface identity certificate",
    "ikeV2Settings.certificateAuth": "IKEv2 certificate authentication",
    "ikeV1Settings.certificateAuth": "IKEv1 certificate authentication",
}


def _mask_pkcs12_bundles() -> None:
    """TODO(core): core's secret-key pattern doesn't know `base64Certificate`, the PKCS12 bundle (identity
    certificate + encrypted private key) FMC returns in full on every read of a PKCS12 enrollment (its
    passPhrase comes back masked). Extend the pattern until core covers it (CORE-REQUESTS.md, fmc F75), so
    fmc_api_call previews and results and the audit log mask it. FMC uses the key nowhere else (10.0.1
    schemas: only IVpnPkcs12ContentModel)."""
    if not _formatting.is_secret_key("base64Certificate"):
        _formatting.SECRET_KEY_RE = re.compile(
            _formatting.SECRET_KEY_RE.pattern + r"|base64_?certificate", re.IGNORECASE
        )


_mask_pkcs12_bundles()


# --- arguments ----------------------------------------------------------------------------------------


class Subject(BaseModel):
    """What goes into the certificate the device requests or makes (FMC's certificate parameters)."""

    model_config = ConfigDict(extra="forbid")

    common_name: str | None = Field(default=None, max_length=64, description="CN")
    organization: str | None = Field(default=None, max_length=64, description="O")
    organizational_unit: str | None = Field(default=None, max_length=64, description="OU")
    locality: str | None = Field(default=None, max_length=64, description="L")
    state: str | None = Field(default=None, max_length=64, description="ST")
    country: str | None = Field(default=None, pattern=r"^[A-Za-z]{2}$", description="C, two letters")
    email: str | None = Field(default=None, max_length=128, description="E")
    fqdn: Literal["device_hostname", "custom", "none", "default"] | None = Field(
        default=None,
        description="FQDN in the certificate: the device's hostname, custom_fqdn, none (the default "
        "here), or FMC's default",
    )
    custom_fqdn: str | None = Field(default=None, max_length=253, description="FQDN for fqdn='custom'")
    alt_fqdn: str | None = Field(
        default=None, max_length=253, description="Alternate FQDN (subject alt name)"
    )
    device_ip: str | None = Field(default=None, description="A device IP address to include")
    device_serial: bool = Field(default=False, description="Include the device's serial number")


def certificate_parameters(s: Subject | None, name: str) -> dict[str, Any]:
    """FMC's certificateParameters. No subject: CN = the enrollment name, no FQDN (the shape the W6N probe
    created on FMC 10.0.1)."""
    s = s or Subject(common_name=name)
    fqdn = s.fqdn or ("custom" if s.custom_fqdn else "none")
    if fqdn == "custom" and not s.custom_fqdn:
        raise InvalidRequest("subject.fqdn='custom' needs subject.custom_fqdn.")
    if s.custom_fqdn and fqdn != "custom":
        raise InvalidRequest("subject.custom_fqdn goes with subject.fqdn='custom'.")
    if s.device_ip:
        try:
            ipaddress.ip_address(s.device_ip.strip())
        except ValueError:
            raise InvalidRequest(f"subject.device_ip {s.device_ip!r} is not an IP address.") from None
    out: dict[str, Any] = {
        "commonName": s.common_name,
        "organization": s.organization,
        "organizationalUnit": s.organizational_unit,
        "locality": s.locality,
        "state": s.state,
        "countryCode": s.country.upper() if s.country else None,
        "email": s.email,
        "includeFQDN": fqdn.upper(),
        "customFqdn": s.custom_fqdn,
        "altFQDN": s.alt_fqdn,
        "includeDeviceIp": s.device_ip.strip() if s.device_ip else None,
        "includeDeviceSerial": s.device_serial,
    }
    return {k: v for k, v in out.items() if v is not None}


def key_block(key_type: str, key_size: int | None, key_name: str | None, name: str) -> dict[str, Any]:
    """FMC's key: the key pair the device generates. Default name: the enrollment's, so two trustpoints never
    share (and re-enrolling one never regenerates) the other's key."""
    size = key_size or DEFAULT_KEY_SIZE[key_type]
    if size not in KEY_SIZES[key_type]:
        sizes = ", ".join(map(str, KEY_SIZES[key_type]))
        raise InvalidRequest(f"key_size {size} is not offered for {key_type}; choose {sizes}.")
    return {"keyType": key_type, "keyName": key_name or name, "keySize": f"CertKey_{size}"}


def usage_block(usage: Sequence[str] | None) -> dict[str, bool] | None:
    if usage is None:
        return None  # FMC's default: IPsec client + SSL client
    return {fmc: key in usage for key, fmc in USAGE_FIELDS.items()}


def revocation_block(mode: str, url: str | None) -> dict[str, Any] | None:
    """FMC's revocation settings. 'none' sends nothing: FMC's default is no CRL/OCSP check (probe)."""
    if mode == "none":
        if url:
            raise InvalidRequest("revocation_url needs revocation='crl' or 'ocsp'.")
        return None
    if url and not re.match(r"^https?://\S+$", url):
        raise InvalidRequest(f"revocation_url {url!r} must be an http(s) URL.")
    crl = mode == "crl"
    crl_part: dict[str, Any] = {
        "enableCertRevocationList": crl,
        "enableCertRevocationListDistributionPoint": crl,
        "enableStaticCertRevocationList": bool(crl and url),
    }
    if crl and url:
        crl_part["certRevocationStaticUrlList"] = [url]
    ocsp_part: dict[str, Any] = {"enableOnlineCertificateStatusProtocol": not crl}
    if not crl and url:
        ocsp_part["onlineCertificateStatusProtocolUrl"] = url
    return {
        "evaluationPriority": mode.upper(),
        # FMC's default ("consider the certificate valid if revocation information can't be reached")
        "ignoreRevocation": True,
        "certRevocationListContent": crl_part,
        "onlineCertificateStatusProtocolContent": ocsp_part,
    }


def ca_fingerprint_value(text: str) -> str:
    v = re.sub(r"[\s:]", "", text).lower()
    if not FINGERPRINT_RE.match(v):
        raise InvalidRequest(
            "ca_fingerprint must be the CA certificate's MD5, SHA-1 or SHA-256 fingerprint in hex."
        )
    return v


# --- certificate files --------------------------------------------------------------------------------


@dataclass
class Blob:
    """A file read from FMC_PKI_DIR as bytes."""

    name: str
    data: bytes
    identity: tuple[int, int, int, int]  # device, inode, size, mtime_ns: a confirm needs the same file
    loose: bool  # readable by group or others


def read_blob(pki_dir: Any, name: str, what: str) -> Blob:
    path, st = pki_path(pki_dir, name, what, PKI_OFF)
    try:
        data = path.read_bytes()
    except OSError as e:
        raise InvalidRequest(f"Can't read {what} {name!r}: {e.strerror}") from None
    return Blob(name, data, (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns), bool(st.st_mode & 0o077))


def pkcs12_der(data: bytes) -> bytes:
    """A PKCS12 file as DER: binary (.p12 / .pfx) or base64 text."""
    if data[:1] == b"\x30":
        return data
    try:
        der = base64.b64decode(re.sub(rb"\s+", b"", data), validate=True)
    except (binascii.Error, ValueError):
        der = b""
    if der[:1] != b"\x30":
        raise InvalidRequest("pkcs12_file is not a PKCS12 file (binary .p12/.pfx or base64 text).")
    return der


def iso(d: datetime) -> str:
    return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def key_label(key: Any) -> str:
    if isinstance(key, rsa.RSAPrivateKey | rsa.RSAPublicKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey):
        return f"ECDSA {key.curve.name}"
    if isinstance(key, ed25519.Ed25519PrivateKey | ed25519.Ed25519PublicKey):
        return "EdDSA Ed25519"
    if isinstance(key, ed448.Ed448PrivateKey | ed448.Ed448PublicKey):
        return "EdDSA Ed448"
    if isinstance(key, dsa.DSAPrivateKey | dsa.DSAPublicKey):
        return f"DSA {key.key_size}"
    return type(key).__name__


def cert_info(cert: x509.Certificate, now: datetime | None = None) -> dict[str, Any]:
    """A certificate's public facts for a preview (never anything secret)."""
    now = now or datetime.now(UTC)
    end = cert.not_valid_after_utc
    try:
        is_ca: bool | None = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = None
    out: dict[str, Any] = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "valid_from": iso(cert.not_valid_before_utc),
        "valid_until": iso(end),
        "days_left": (end - now).days,
        "ca": is_ca,
        "self_signed": cert.subject == cert.issuer or None,
        "sha1_fingerprint": fmc_fingerprint(cert.public_bytes(Encoding.DER)),
        "key": key_label(cert.public_key()),
    }
    return {k: v for k, v in out.items() if v is not None}


@dataclass
class Material:
    """What the kind needs from FMC_PKI_DIR, read and checked: the body parts to send, the same parts for
    the preview with every secret replaced, facts for the preview, and the files a confirm must find
    unchanged."""

    body: dict[str, Any] = field(default_factory=dict)
    shown: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    files: list[tuple[str, tuple[int, int, int, int], str]] = field(default_factory=list)  # name, id, sha256


def _remember(m: Material, b: Blob, digest: bool = True) -> None:
    """Note a file for the confirm check: its identity, and a SHA-256 of its content unless it holds a
    password (a digest of a short secret is guessable, so it stays out of the plan fingerprint)."""
    m.files.append((b.name, b.identity, hashlib.sha256(b.data).hexdigest() if digest else ""))
    if b.loose:
        m.warnings.append(f"{b.name} is readable by group or others on the server host; chmod 600 it.")


def _secret_file(pki_dir: Any, name: str, what: str, m: Material) -> str:
    """A passphrase / password from a file in FMC_PKI_DIR (one line), masked in later logs and errors."""
    f = read_blob(pki_dir, name, what)
    _remember(m, f, digest=False)
    try:
        value = f.data.decode("utf-8").strip("\r\n")
    except UnicodeDecodeError:
        raise InvalidRequest(f"{what} {name!r} is not a UTF-8 text file.") from None
    if not value:
        m.blockers.append(f"{what} {name!r} is empty.")
    register_secret(value)
    return value


def load_pkcs12(settings: Any, pkcs12_file: str, passphrase_file: str | None) -> Material:
    m = Material()
    blob = read_blob(settings.pki_dir, pkcs12_file, "pkcs12_file")
    _remember(m, blob)
    der = pkcs12_der(blob.data)
    if passphrase_file:
        phrase: str | None = _secret_file(settings.pki_dir, passphrase_file, "passphrase_file", m)
        source = f"passphrase file {passphrase_file!r} (FMC_PKI_DIR)"
    elif settings.pki_passphrase is not None:
        phrase = settings.pki_passphrase.get_secret_value().strip("\r\n")
        register_secret(phrase)
        source = "FMC_PKI_PASSPHRASE (server setting)"
    else:
        phrase, source = None, ""
    b64 = base64.b64encode(der).decode()
    register_secret(b64)
    m.body = {"pkcs12Content": {"base64Certificate": b64, "passPhrase": phrase or ""}}
    m.shown = {
        "pkcs12Content": {
            "base64Certificate": f"<{len(der)} bytes from FMC_PKI_DIR/{pkcs12_file}, sent to FMC only>",
            "passPhrase": MASK,
        }
    }
    facts: dict[str, Any] = {"file": pkcs12_file, "bytes": len(der)}
    m.details["pkcs12"] = facts
    if not phrase:
        m.blockers.append(
            "The PKCS12 needs its passphrase (FMC and the FTD import only protected PKCS12 files): put it "
            "in a file in FMC_PKI_DIR and pass passphrase_file, or set FMC_PKI_PASSPHRASE on the server."
        )
        return m
    facts["unlocked_with"] = source
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(der, phrase.encode())
    except UnsupportedAlgorithm:
        m.blockers.append(
            f"{pkcs12_file} uses an encryption this server can't open; export it again with OpenSSL's "
            "defaults (AES-256) or with -legacy."
        )
        return m
    except (ValueError, TypeError):
        m.blockers.append(
            f"Could not open {pkcs12_file} with the passphrase from {source}: wrong passphrase, or not a "
            "PKCS12 file. (A file made with `openssl pkcs12 -export` opens here, also with -legacy.)"
        )
        return m
    if cert is None:
        m.blockers.append(
            f"{pkcs12_file} holds no certificate; FMC needs the identity certificate and its key."
        )
    else:
        info = cert_info(cert)
        facts["identity_certificate"] = info
        if info["days_left"] < 0:
            m.blockers.append(f"The identity certificate expired on {info['valid_until']}.")
        elif info["days_left"] < 30:
            m.warnings.append(f"The identity certificate expires in {info['days_left']} days.")
    if key is None:
        m.blockers.append(f"{pkcs12_file} holds no private key; FMC needs the identity certificate's key.")
    else:
        facts["key"] = key_label(key)  # the type and size only; the key itself is never shown
        if cert is not None and key.public_key() != cert.public_key():
            m.blockers.append(f"The private key in {pkcs12_file} doesn't belong to its certificate.")
    facts["ca_certificates"] = [cert_info(c) for c in extra]
    if not extra:
        m.warnings.append(
            f"{pkcs12_file} has no CA certificate: the trustpoint gets the identity certificate only, so "
            "FMC may show the CA as not available. Export the PKCS12 with its chain (openssl pkcs12 "
            "-export -certfile)."
        )
    return m


def load_ca(settings: Any, ca_cert: str | None, ca_cert_file: str | None) -> Material:
    m = Material()
    if ca_cert_file:
        blob = read_blob(settings.pki_dir, ca_cert_file, "ca_cert_file")
        _remember(m, blob)
        text = blob.data.decode("ascii", "replace")
    else:
        text = ca_cert or ""
    if "PRIVATE KEY" in text:
        raise InvalidRequest("The CA certificate text contains a private key; give only the CA certificate.")
    pem, der = pem_body(text)
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        raise InvalidRequest("The CA certificate is not a valid X.509 certificate.") from None
    info = cert_info(cert)
    m.details["ca_certificate"] = info
    if info.get("ca") is False:
        m.warnings.append(
            "That certificate is not a CA (basicConstraints CA:FALSE); FMC checks the CA flag unless "
            "skip_ca_flag_check=true."
        )
    if info["days_left"] < 0:
        m.blockers.append(f"The CA certificate expired on {info['valid_until']}.")
    body64 = "".join(pem.splitlines()[1:-1])
    lines = "\n".join(body64[i : i + 64] for i in range(0, len(body64), 64))
    m.body = {"caCertificate": {"caOnly": True, "base64Content": lines}}
    m.shown = {
        "caCertificate": {"caOnly": True, "base64Content": f"<CA certificate {info['sha1_fingerprint']}>"}
    }
    return m


# --- results ------------------------------------------------------------------------------------------


def _ca_summary(content: Any) -> dict[str, Any] | None:
    text = str(content or "").strip()
    if not text:
        return None
    try:
        pem = "BEGIN CERTIFICATE" in text
        der = pem_body(text)[1] if pem else base64.b64decode(re.sub(r"\s+", "", text))
        info = cert_info(x509.load_der_x509_certificate(der))
    except (InvalidRequest, ValueError, binascii.Error):
        return None
    return {k: info[k] for k in ("subject", "valid_until", "days_left", "sha1_fingerprint") if k in info}


def enrollment_row(e: dict[str, Any]) -> dict[str, Any]:
    """One enrollment object for a result or preview: what it is, never the PKCS12 bundle or a password."""
    t = str(e.get("enrollmentType") or "")
    params = e.get("certificateParameters") or {}
    key = e.get("key") or {}
    usage = e.get("validationUsage") or {}
    rev = e.get("revocation") or {}
    url = (e.get("scepContent") or {}).get("enrollmentUrl") or (e.get("estContent") or {}).get(
        "enrollmentUrl"
    )
    size = str(key.get("keySize") or "").replace("CertKey_", "")
    row: dict[str, Any] = {
        "name": e.get("name"),
        "kind": KIND_OF.get(t, t.lower() or None),
        "enrollment_type": t or None,
        "description": e.get("description") or None,
        "subject": {k: v for k, v in params.items() if v not in (None, "", False)} or None,
        "key": " ".join(
            x for x in (key.get("keyType"), size, f"({key['keyName']})" if key.get("keyName") else "") if x
        )
        or None,
        "usage": [k for k, f in USAGE_FIELDS.items() if usage.get(f)] or None,
        "revocation": rev.get("evaluationPriority") or None,
        "skip_ca_flag_check": True if e.get("skipCaFlagCheck") else None,
        "ca_certificate": _ca_summary((e.get("caCertificate") or {}).get("base64Content")),
        "pkcs12": "stored on FMC (the bundle and passphrase are never shown)"
        if e.get("pkcs12Content")
        else None,
        "enrollment_url": url or None,
        "domain": ((e.get("metadata") or {}).get("domain") or {}).get("name") or None,
        "id": e.get("id"),
    }
    return {k: v for k, v in row.items() if v is not None}


# --- lookups ------------------------------------------------------------------------------------------


async def resolve_enrollment(app: FmcApp, ref: str, domain: str | None) -> dict[str, Any]:
    """One enrollment object by name or UUID, fully read."""
    ref = ref.strip()
    if not ref:
        raise InvalidRequest("Empty enrollment name.")
    path = await app.config_path(ENROLLMENTS, domain)
    if not is_uuid(ref):
        page = await app.all(path, expanded=False)
        ref = str(pick_by_name(page.items, ref, "certificate enrollment", partial=not page.complete)["id"])
    obj: dict[str, Any] = await app.api.get(f"{path}/{ref}")
    return obj


def ref_paths(node: Any, ids: set[str], path: str = "") -> list[str]:
    """Where inside `node` a reference {id: one of ids} sits, as dotted paths ('a.b[].c')."""
    out: list[str] = []
    if isinstance(node, dict):
        if path and str(node.get("id", "")).lower() in ids:
            out.append(path)
        for k, v in node.items():
            if k not in ("metadata", "links"):
                out += ref_paths(v, ids, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for v in node:
            out += ref_paths(v, ids, f"{path}[]")
    return out


async def enrollment_users(
    app: FmcApp, enrollment_id: str, domain: str | None
) -> tuple[list[str], list[str], list[str]]:
    """(references, notes, unread): the RA VPN policies, S2S topologies and decryption policies that
    reference the enrollment, each with where (FMC 10.0.1: RA VPN access interface identity certificates,
    S2S IKE certificate authentication; decryption rules reference internal CAs and certificates, but are
    walked by id all the same), what could not be checked (notes), and which of those FMC refused to
    read (unread: then nobody can say the enrollment is unused)."""
    ids = {enrollment_id.lower()}
    found: list[str] = []
    notes: list[str] = []
    unread: list[str] = []

    async def scan(what: str, path: str, children: str | None, full_item: str | None) -> None:
        try:
            page = await app.all(path, cap=POLICY_CAP)
        except UpstreamError as e:
            notes.append(f"{what}: not checked ({e})")
            unread.append(f"the {what} list")
            return
        if not page.complete:
            notes.append(f"{what}: only the first {len(page.items)} checked")
        for p in page.items[:POLICY_CAP]:
            try:
                top: Any = p
                if full_item and full_item not in p:
                    top = await app.api.get(f"{path}/{p['id']}")
                hits = [REF_LABELS.get(h, h) for h in ref_paths(top, ids)]
                if children:
                    for c in (await app.all(f"{path}/{p['id']}/{children}", cap=1000)).items:
                        where = [REF_LABELS.get(h, h) for h in ref_paths(c, ids)]
                        rule = f"rule {c['name']}: " if c.get("name") and children.endswith("rules") else ""
                        hits += [f"{rule}{w}" for w in where]
            except UpstreamError as e:
                notes.append(f"{what} {p.get('name')}: not checked ({e})")
                unread.append(f"{what} {p.get('name')}")
                continue
            found.extend(f"{what} {p.get('name')} ({h})" for h in hits)

    await scan("RA VPN", await app.config_path(RAVPN, domain), None, "accessInterfaceSettings")
    await scan("S2S VPN", await app.config_path(S2S, domain), "ikesettings", None)
    await scan("decryption policy", await app.config_path(DECRYPTION, domain), "decryptionpolicyrules", None)
    return sorted(set(found)), notes, unread


async def device_enrolments(
    app: FmcApp, domain: str | None, names: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    """Every device enrolment row (F71's rows: device, name, status, expiry; `id` = the enrollment)."""
    page = await app.all(await app.config_path(DEVICE_CERTS, domain))
    known = dict(names or {})
    if page.items and any(str(i.get("id", "")).lower() not in known for i in page.items):
        devs = await app.all(await app.config_path(DEVICES, domain), expanded=False)
        known |= {str(d.get("id", "")).lower(): str(d.get("name")) for d in devs.items if d.get("id")}
    now = datetime.now(UTC)
    return [r for i in page.items for r in device_rows(i, known, now)]


def _same(a: Any, b: Any) -> bool:
    return str(a or "").lower() == str(b or "").lower()


def find_row(rows: list[dict[str, Any]], device_id: str, enrollment_id: str) -> dict[str, Any] | None:
    return next(
        (r for r in rows if _same(r.get("device_id"), device_id) and _same(r.get("id"), enrollment_id)), None
    )


# --- tools --------------------------------------------------------------------------------------------


def register(reg: ToolRegistrar) -> None:
    @reg.write(title="Create certificate enrollment object")
    async def fmc_create_cert_enrollment(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
                description="Enrollment object name (becomes the trustpoint name on the device)",
            ),
        ],
        kind: Annotated[
            EnrollmentKind,
            Field(
                description="self_signed: the device generates the key and a self-signed certificate; "
                "pkcs12: an existing identity certificate + key + CA chain from pkcs12_file; "
                "manual_ca_only: a CA certificate only (a trustpoint to validate peers); scep / est: the "
                "device requests its "
                "certificate from enrollment_url"
            ),
        ],
        subject: Annotated[
            Subject | None,
            Field(
                description="self_signed / scep / est: the certificate's subject; default CN=<name>, no FQDN"
            ),
        ] = None,
        key_type: Annotated[
            Literal["RSA", "ECDSA", "EdDSA"], Field(description="self_signed / scep / est: key pair type")
        ] = "RSA",
        key_size: Annotated[
            int | None,
            Field(description="RSA 2048 (default) / 3072 / 4096; ECDSA 256 (default) / 384 / 521; EdDSA 256"),
        ] = None,
        key_name: Annotated[
            str | None,
            Field(
                pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
                description="Name of the key pair on the device (default: the enrollment name, a key of its "
                "own)",
            ),
        ] = None,
        pkcs12_file: Annotated[
            str | None,
            Field(description="pkcs12: PKCS12 file name inside FMC_PKI_DIR (.p12/.pfx, binary or base64)"),
        ] = None,
        passphrase_file: Annotated[
            str | None,
            Field(
                description="pkcs12: file in FMC_PKI_DIR holding the PKCS12 passphrase (default: the "
                "server's FMC_PKI_PASSPHRASE)"
            ),
        ] = None,
        ca_cert: Annotated[
            str | None,
            Field(description="manual_ca_only: the CA certificate in PEM (public; never a private key)"),
        ] = None,
        ca_cert_file: Annotated[
            str | None, Field(description="manual_ca_only: the CA certificate's PEM file inside FMC_PKI_DIR")
        ] = None,
        enrollment_url: Annotated[
            str | None, Field(description="scep / est: the CA server's enrolment URL (http:// or https://)")
        ] = None,
        username: Annotated[str | None, Field(max_length=128, description="est: the EST user name")] = None,
        password_file: Annotated[
            str | None,
            Field(
                description="scep: file in FMC_PKI_DIR with the challenge password (optional); est: file "
                "with the EST password"
            ),
        ] = None,
        ca_fingerprint: Annotated[
            str | None,
            Field(description="scep / est: the CA certificate's fingerprint in hex, to authenticate the CA"),
        ] = None,
        usage: Annotated[
            list[Literal["ipsec_client", "ssl_client", "ssl_server"]] | None,
            Field(
                description="What the trustpoint's CA may validate (FMC's validation usage); default "
                "ipsec_client + ssl_client"
            ),
        ] = None,
        revocation: Annotated[
            Literal["none", "crl", "ocsp"],
            Field(
                description="Revocation check of certificates this CA validates (none = FMC's default; "
                "unreachable revocation information counts as valid)"
            ),
        ] = "none",
        revocation_url: Annotated[
            str | None, Field(description="Static CRL URL (crl) or OCSP responder URL (ocsp)")
        ] = None,
        skip_ca_flag_check: Annotated[
            bool, Field(description="Accept a CA certificate without the CA flag (basicConstraints)")
        ] = False,
        description: Annotated[str | None, Field(max_length=256, description="Object description")] = None,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Create a certificate enrollment object: what a device's trustpoint holds and how the device gets
        its identity certificate (the first step before RA VPN, certificate-authenticated S2S or any other
        use of a device certificate). Nothing reaches a device until fmc_enroll_certificate. Secrets never
        pass through MCP: a PKCS12 is read from FMC_PKI_DIR on the server host with its passphrase from a
        file there (or FMC_PKI_PASSPHRASE), SCEP/EST passwords from a file there; the preview shows the
        certificate's subject, expiry, fingerprint and key type, never the key or a password. A CSR-based
        manual enrolment is not in FMC's REST API (manual_ca_only installs a CA certificate only)."""
        app: FmcApp = get_client(ctx)
        settings = app.settings
        given = {
            "subject": subject,
            "key_type": key_type if key_type != "RSA" else None,
            "key_size": key_size,
            "key_name": key_name,
            "pkcs12_file": pkcs12_file,
            "passphrase_file": passphrase_file,
            "ca_cert": ca_cert,
            "ca_cert_file": ca_cert_file,
            "enrollment_url": enrollment_url,
            "username": username,
            "password_file": password_file,
            "ca_fingerprint": ca_fingerprint,
        }
        allowed = {
            "self_signed": {"subject", "key_type", "key_size", "key_name"},
            "pkcs12": {"pkcs12_file", "passphrase_file"},
            "manual_ca_only": {"ca_cert", "ca_cert_file"},
            "scep": {
                "subject",
                "key_type",
                "key_size",
                "key_name",
                "enrollment_url",
                "password_file",
                "ca_fingerprint",
            },
            "est": {
                "subject",
                "key_type",
                "key_size",
                "key_name",
                "enrollment_url",
                "username",
                "password_file",
                "ca_fingerprint",
            },
        }[kind]
        extra = [k for k, v in given.items() if v is not None and k not in allowed]
        if extra:
            raise InvalidRequest(f"kind={kind!r} doesn't take {', '.join(extra)}.")

        def load() -> Material:
            """Reads and checks the kind's inputs (again on confirm, so a changed file is noticed)."""
            if kind == "pkcs12":
                if not pkcs12_file:
                    raise InvalidRequest("kind='pkcs12' needs pkcs12_file (a file inside FMC_PKI_DIR).")
                return load_pkcs12(settings, pkcs12_file, passphrase_file)
            if kind == "manual_ca_only":
                if bool(ca_cert) == bool(ca_cert_file):
                    raise InvalidRequest(
                        "kind='manual_ca_only' needs ca_cert (PEM) or ca_cert_file, one of them."
                    )
                return load_ca(settings, ca_cert, ca_cert_file)
            m = Material()
            m.body = {
                "certificateParameters": certificate_parameters(subject, name),
                "key": key_block(key_type, key_size, key_name, name),
            }
            if kind in ("scep", "est"):
                if not enrollment_url or not re.match(r"^https?://\S+$", enrollment_url):
                    raise InvalidRequest(f"kind={kind!r} needs enrollment_url, an http:// or https:// URL.")
                if kind == "est" and not (username and password_file):
                    raise InvalidRequest("kind='est' needs username and password_file (the EST credentials).")
                secret = (
                    _secret_file(settings.pki_dir, password_file, "password_file", m)
                    if password_file
                    else None
                )
                content: dict[str, Any] = {"enrollmentUrl": enrollment_url}
                if ca_fingerprint:
                    content["fingerprint"] = ca_fingerprint_value(ca_fingerprint)
                if kind == "scep":
                    content |= {"retryPeriodInMins": "1", "retryCount": "10"}  # FMC's UI defaults
                    if secret is not None:
                        content["challengePassword"] = secret
                    m.body["scepContent"] = content
                else:
                    content |= {"username": username, "password": secret}
                    m.body["estContent"] = content
                shown = copy.deepcopy(m.body)
                for part, key in (("scepContent", "challengePassword"), ("estContent", "password")):
                    if key in shown.get(part, {}):
                        shown[part][key] = MASK
                m.shown = shown
            else:
                m.shown = copy.deepcopy(m.body)
            return m

        material = load()
        body: dict[str, Any] = {
            "type": "CertEnrollment",
            "name": name,
            "enrollmentType": FMC_KIND[kind],
            **({"description": description} if description else {}),
            **material.body,
            "overridable": False,
        }
        options: dict[str, Any] = {}
        if (u := usage_block(usage)) is not None:
            options["validationUsage"] = u
        if (r := revocation_block(revocation, revocation_url)) is not None:
            options["revocation"] = r
        if skip_ca_flag_check:
            options["skipCaFlagCheck"] = True
        body |= options
        shown = {k: v for k, v in body.items() if k not in material.body} | material.shown
        path = await app.config_path(ENROLLMENTS, domain)
        page = await app.all(path, expanded=False)
        clash = [e for e in page.items if str(e.get("name", "")).lower() == name.lower()]
        blockers = list(material.blockers)
        if clash:
            blockers.append(f"A certificate enrollment named {clash[0].get('name')!r} already exists.")

        async def apply() -> Any:
            again = load()
            if again.files != material.files:
                raise InvalidRequest("A file changed since the preview; nothing was created. Preview again.")
            if again.blockers:
                raise InvalidRequest(f"Nothing was created: {again.blockers[0]}")
            res = await app.api.post(path, {**body, **again.body})
            full = await app.api.get(f"{path}/{res['id']}")
            out = enrollment_row(full)
            out["next"] = (
                f"Enrol it on a device: fmc_enroll_certificate(device=<name>, enrollment={name!r}, "
                "action='enroll'); then fmc_list_certificates(device=<name>) shows its status and expiry."
            )
            return out

        side_effects = [
            "Creates the enrollment object only; nothing reaches a device until fmc_enroll_certificate."
        ]
        if kind == "pkcs12":
            side_effects.append(
                "The PKCS12 (identity certificate and its encrypted private key) and its passphrase are sent "
                "to FMC only; FMC returns the bundle on reads, and this server never shows it."
            )
        if kind in ("scep", "est"):
            side_effects.append(
                f"On enrolment the device itself contacts {enrollment_url}; it must reach that URL."
            )
        details: dict[str, Any] = {"enrollment": shown, **material.details}
        if material.warnings:
            details["warnings"] = material.warnings
        return await fmc_preview(
            ctx,
            tool=TOOL_CREATE,
            args={
                "name": name,
                "kind": kind,
                "subject": subject.model_dump(exclude_none=True) if subject else None,
                **{k: v for k, v in given.items() if k != "subject"},
                "key_type": key_type,
                "usage": usage,
                "revocation": revocation,
                "revocation_url": revocation_url,
                "skip_ca_flag_check": skip_ca_flag_check,
                "description": description,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"Create {kind} certificate enrollment {name!r}",
                details=details,
                fingerprint={"files": material.files, "existing": [e.get("id") for e in clash]},
                blockers=blockers,
                side_effects=side_effects,
            ),
            apply=lambda: applied(app, apply),
        )

    @reg.dangerous(title="Enrol, re-enrol, refresh or delete a device certificate")
    async def fmc_enroll_certificate(
        ctx: Context,
        device: DeviceRef,
        enrollment: Annotated[
            str, Field(description="Certificate enrollment object name or UUID (fmc_create_cert_enrollment)")
        ],
        action: Annotated[
            EnrolAction,
            Field(
                description="enroll: install it on the device; re_enroll: replace the device's certificate "
                "(also clears a failed enrolment); refresh: re-read its status from the device (changes "
                "nothing there); delete: remove the certificate from the device (the object stays)"
            ),
        ] = "enroll",
        wait: Wait = True,
        domain: Domain = None,
        confirm: Confirm = None,
    ) -> dict[str, Any]:
        """Enrol a certificate enrollment on a device, or re-enrol, refresh or delete it there. FMC acts on
        the device at once (no deployment). The preview shows the device's current enrolment (status,
        expiry), the other devices that use the same enrollment, and the RA VPN, S2S VPN and decryption
        policies that reference it: re-enrolling or deleting a certificate they use drops their sessions,
        and delete is blocked while anything references it. With wait, polls FMC's task and returns the
        enrolment row after it (fmc_list_certificates shows the same). Standalone devices only: an HA pair
        or cluster is enrolled as a whole in the FMC UI."""
        app: FmcApp = get_client(ctx)
        dev = await resolve_in(app, DEVICES, device, "device", domain)
        dev_id, dev_name = str(dev["id"]), str(dev.get("name"))
        enr = await resolve_enrollment(app, enrollment, domain)
        enr_id, enr_name = str(enr["id"]), str(enr.get("name"))
        enr_type = str(enr.get("enrollmentType") or "")
        rows = await device_enrolments(app, domain, {dev_id.lower(): dev_name})
        current = find_row(rows, dev_id, enr_id)
        others = sorted({str(r.get("device")) for r in rows if _same(r.get("id"), enr_id)} - {dev_name})
        users: list[str] = []
        notes: list[str] = []
        unread: list[str] = []
        if action != "refresh":  # a refresh changes nothing on the device: no need to know who uses it
            users, notes, unread = await enrollment_users(app, enr_id, domain)

        blockers: list[str] = []
        member = membership_of(dev)
        if member is not None:
            what = "HA pair" if member.kind == "ha" else "cluster"
            blockers.append(
                f"{dev_name} is a unit of {what} {member.container}: FMC enrols an HA pair's or cluster's "
                "certificates on the whole container, which this tool doesn't do (not proven on FMC 10.0.1); "
                "use the FMC UI (Devices > Certificates)."
            )
        state = str((current or {}).get("deployment") or "").upper()
        status = (
            f"{state or '?'}, identity {current.get('identity_status') or '?'}"
            + (f", expires {current['expires']}" if current.get("expires") else "")
            if current
            else None
        )
        if action == "enroll" and current:
            if state in FAILED_STATES:
                blockers.append(
                    f"An earlier enrolment of {enr_name} on {dev_name} {state}: use action='re_enroll', "
                    "which clears the failed one."
                )
            else:
                blockers.append(
                    f"{enr_name} is already enrolled on {dev_name} ({status}): re_enroll replaces the "
                    "certificate, refresh re-reads its status."
                )
        if action != "enroll" and not current:
            blockers.append(
                f"{enr_name} is not enrolled on {dev_name}"
                + (": use action='enroll'." if action == "re_enroll" else ".")
            )
        if action != "refresh" and state in BUSY_STATES:
            blockers.append(
                f"An enrolment of {enr_name} on {dev_name} is still in progress; refresh it first."
            )
        if action == "delete" and users:
            blockers.append(
                f"Still referenced by: {', '.join(users)}. Point those at another certificate first."
            )
        if action == "delete" and unread:
            # Fail closed: a delete is only offered once every policy that may use the certificate was read.
            blockers.append(
                f"FMC didn't let this server read {', '.join(unread)} (see warnings), so it can't show that "
                f"nothing references {enr_name}; fix that read (the account's role, FMC) and preview again, "
                "or delete it in the FMC UI (Devices > Certificates)."
            )
        window, window_blockers = deploy_window_blockers(get_settings(ctx), TOOL_ENROLL)
        blockers += window_blockers
        warnings: list[str] = []
        if dev.get("isConnected") is False:
            warnings.append(
                f"FMC reports {dev_name} as not connected: the device can't be reached, so this will fail."
            )
        warnings += notes

        key = enr.get("key") or {}
        key_text = (
            f"{key.get('keyType', 'RSA')} {str(key.get('keySize') or '').replace('CertKey_', '')}".strip()
        )
        url = (enr.get("scepContent") or {}).get("enrollmentUrl") or (enr.get("estContent") or {}).get(
            "enrollmentUrl"
        )
        key_name = key.get("keyName") or "?"
        pair = f"the device generates key pair {key_name} ({key_text})"
        how = {
            "SELF_SIGNED_CERTFICATE": f"{pair} and a self-signed identity certificate",
            "PKCS12": "the identity certificate, its private key and CA chain from the PKCS12 go to the "
            "device",
            "MANUAL": "the CA certificate is installed as a trustpoint (no identity certificate)",
            "SCEP": f"{pair} and requests a certificate from {url} (the device must reach it)",
            "EST": f"{pair} and requests a certificate from {url} (the device must reach it)",
        }.get(enr_type, f"FMC enrols the {enr_type or 'certificate'} enrollment")
        # RE_ENROLL re-issues the certificate, not the key (recorded on FMC 10.0.1: a self-signed enrollment
        # got a new serial and validity, the SHA1 public key hash stayed the same). SCEP/EST: not recorded.
        # After a failed earlier enrolment the device may hold no key pair yet: no claim about the key then.
        named_pair = f"key pair {key_name} ({key_text})"
        self_again = (
            f"a self-signed identity certificate on {named_pair}: the earlier enrolment {state}, so the "
            "device may not hold that key pair yet and then generates it (when it does, FMC 10.0.1 "
            "re-issues the certificate on the existing key)"
            if state in FAILED_STATES
            else "a new self-signed identity certificate (new serial and validity) on "
            f"the {named_pair} the device already holds: the key is not regenerated"
        )
        how_again = {
            "SELF_SIGNED_CERTFICATE": self_again,
            "PKCS12": "the identity certificate, its private key and CA chain from the PKCS12 go to the "
            "device again",
            "MANUAL": "the CA certificate is installed again as a trustpoint (no identity certificate)",
            "SCEP": f"the device requests a new certificate for {named_pair} from {url} (it must reach it)",
            "EST": f"the device requests a new certificate for {named_pair} from {url} (it must reach it)",
        }.get(enr_type, f"FMC enrols the {enr_type or 'certificate'} enrollment again")
        effects = {
            "enroll": [f"Installs {enr_name} on {dev_name} now, without a deployment: {how}."],
            "re_enroll": [
                f"Enrols {enr_name} on {dev_name} again, replacing the device's certificate for it: "
                f"{how_again}.",
            ],
            "refresh": [f"Re-reads the status of {enr_name} from {dev_name}; nothing changes on the device."],
            "delete": [
                f"Removes {enr_name}'s certificate and trustpoint from {dev_name}; FMC forgets the "
                "enrolment. The enrollment object stays (the FMC UI or fmc_api_call DELETE "
                "object/certenrollments/<id> removes it)."
            ],
        }[action]
        if users and action == "re_enroll":
            effects.append(
                f"Used by {', '.join(users)}: VPN sessions on {dev_name} that use this certificate may drop."
            )
        body = {
            "action": ACTIONS[action],
            "deviceCertificates": [
                {
                    "deviceId": dev_id,
                    "certificates": [{"certificate": {"id": enr_id, "type": "CertEnrollment"}}],
                }
            ],
        }
        manage = await app.config_path(MANAGE, domain)

        async def row_now() -> dict[str, Any] | None:
            return find_row(await device_enrolments(app, domain, {dev_id.lower(): dev_name}), dev_id, enr_id)

        async def apply() -> Any:
            check_deploy_window(get_settings(ctx), TOOL_ENROLL)
            resp = await app.api.post(manage, body)
            app.invalidate_cache()
            tid = task_id_of(resp)
            out: dict[str, Any] = {"action": action, "device": dev_name, "enrollment": enr_name}
            if tid:
                out["task_id"] = tid
            if not wait:
                out["note"] = (
                    f"Started; follow it with fmc_get_task{f'({tid!r})' if tid else ''} and "
                    f"fmc_list_certificates(device={dev_name!r})."
                )
                return out
            try:
                if tid:
                    out["task"] = await _wait_enrol_task(ctx, app, tid, domain, f"{action} of {enr_name}")
                else:
                    await _wait_row(ctx, row_now, action)
            except TaskFailed as e:
                row = await _quiet(row_now)
                said = "; ".join((row or {}).get("problems") or [])
                raise TaskFailed(
                    f"{e}{f' (device enrolment: {said})' if said else ''}. The request was submitted"
                    f"{f' as task {tid}' if tid else ''}; check fmc_list_certificates(device={dev_name!r})."
                ) from e
            except UpstreamTimeout as e:
                out["status"] = "still running"
                out["note"] = f"{e} Check fmc_list_certificates(device={dev_name!r}) later."
            row = await row_now()
            out["on_device"] = row or "not enrolled"
            out["outcome"] = _outcome(action, row)
            if (
                action in ("enroll", "re_enroll")
                and row
                and str(row.get("deployment", "")).upper() in FAILED_STATES
            ):
                out["next"] = "Fix the cause in problems, then action='re_enroll'."
            return out

        return await fmc_preview(
            ctx,
            tool=TOOL_ENROLL,
            args={
                "device": device,
                "enrollment": enrollment,
                "action": action,
                "wait": wait,
                "domain": domain,
            },
            confirm=confirm,
            plan=Plan(
                f"{action.replace('_', '-').capitalize()} certificate {enr_name} on {dev_name}",
                details={
                    "device": {
                        "name": dev_name,
                        "id": dev_id,
                        "connected": dev.get("isConnected"),
                        "version": dev.get("sw_version"),
                    },
                    "enrollment": enrollment_row(enr),
                    "on_device": current or "not enrolled",
                    **({"also_enrolled_on": others} if others else {}),
                    **({"used_by": users} if action != "refresh" else {}),
                    **({"warnings": warnings} if warnings else {}),
                    **({"deploy_window": window} if window else {}),
                    # what is POSTed to devices/operational/managecertificates (ids only, nothing secret)
                    "body": body,
                },
                fingerprint={
                    "device": dev_id,
                    "enrollment": enr_id,
                    "changed": (enr.get("metadata") or {}).get("timestamp"),
                    "on_device": {
                        k: (current or {}).get(k) for k in ("deployment", "identity_status", "expires")
                    },
                    "used_by": users,
                },
                blockers=blockers,
                blast_radius=1,
                side_effects=effects,
            ),
            apply=apply,
        )


def _outcome(action: str, row: dict[str, Any] | None) -> str:
    if action == "delete":
        return "removed from the device" if row is None else f"still listed ({row.get('deployment')})"
    if row is None:
        return "not listed on the device"
    state = str(row.get("deployment") or "").upper()
    if state in FAILED_STATES:
        return f"failed: {'; '.join(row.get('problems') or [state])}"
    if action == "refresh":
        return f"status refreshed ({state or '?'})"
    return (
        "enrolled" if state == "SUCCESS" else f"{state or 'unknown'} (check again with fmc_list_certificates)"
    )


async def _quiet(fn: Any) -> Any:
    try:
        return await fn()
    except UpstreamError:
        return None


def _enrol_task_done(task: dict[str, Any]) -> bool:
    finished, _ = task_state(task)
    return finished or str(task.get("status") or "").strip().lower() in EXTRA_DONE


async def _wait_enrol_task(
    ctx: Context, app: FmcApp, task_id: str, domain: str | None, what: str
) -> dict[str, Any]:
    path = await app.config_path(f"job/taskstatuses/{task_id}", domain)

    async def fetch() -> dict[str, Any]:
        data: dict[str, Any] = await app.api.get(path)
        return data

    task = await poll_until(
        fetch,
        done=_enrol_task_done,
        failed=lambda t: task_state(t)[1],
        describe=lambda t: f"{t.get('status')}: {t.get('message') or ''}",
        timeout=float(get_settings(ctx).mcp_task_timeout),
        interval=5.0,
        max_interval=20.0,  # FMC allows ~120 requests/minute; poll gently
        ctx=ctx,
        what=what,
    )
    return {k: task.get(k) for k in ("status", "message", "description") if task.get(k)}


async def _wait_row(ctx: Context, row_now: Any, action: str) -> None:
    """No task id in FMC's answer: follow the device enrolment row until it leaves IN_PROGRESS."""

    def done(row: dict[str, Any] | None) -> bool:
        if action == "delete":
            return row is None
        return row is not None and str(row.get("deployment") or "").upper() not in BUSY_STATES

    await poll_until(
        row_now,
        done=done,
        describe=lambda r: str((r or {}).get("deployment") or "not listed"),
        timeout=float(get_settings(ctx).mcp_task_timeout),
        interval=5.0,
        max_interval=20.0,
        ctx=ctx,
        what=f"certificate {action}",
    )

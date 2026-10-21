"""Subject and issuer names of a certificate object, read from its PEM (#273).

FMC 10.0.1's own name fields are unreliable for some of its bundled root CAs (recorded 2026-10-21):
UTF-8 names come back as mojibake ('NetLock Arany (Class Gold) FÅ\\x91tanÃºsÃ\\xadtvÃ¡ny' for
'... Főtanúsítvány'), and a value with a comma is cut there ('SECOM Trust Systems CO.' for
'SECOM Trust Systems CO.,LTD.'). Objects carry the certificate itself in `cert` (GET by id and the expanded
list), so the names are read from it; FMC's fields are the fallback when there is no PEM or it won't parse."""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class CertNames:
    subject_cn: str | None
    subject_o: str | None
    issuer_cn: str | None
    issuer_o: str | None
    from_pem: bool


def _attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    for a in name.get_attributes_for_oid(oid):
        v = a.value
        text = v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)
        if text.strip():
            return text.strip()
    return None


@lru_cache(maxsize=1024)
def _from_pem(pem: str) -> CertNames | None:
    try:
        with warnings.catch_warnings():
            # some bundled roots have serial number 0 (SECOM RootCA2): cryptography warns, later refuses
            warnings.simplefilter("ignore")
            cert = x509.load_pem_x509_certificate(pem.encode("ascii", "ignore"))
    except (ValueError, TypeError):
        return None
    return CertNames(
        subject_cn=_attr(cert.subject, NameOID.COMMON_NAME),
        subject_o=_attr(cert.subject, NameOID.ORGANIZATION_NAME),
        issuer_cn=_attr(cert.issuer, NameOID.COMMON_NAME),
        issuer_o=_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        from_pem=True,
    )


def cert_names(c: dict[str, Any]) -> CertNames:
    """The object's subject/issuer common name and organisation: from its PEM when FMC returned one that
    parses, else FMC's subjectCommonName / subjectOrganization / issuer* fields (empty = None)."""
    pem = str(c.get("cert") or "").strip()
    if pem.startswith("-----BEGIN CERTIFICATE-----"):
        names = _from_pem(pem)
        if names is not None:
            return names
    return CertNames(
        subject_cn=c.get("subjectCommonName") or None,
        subject_o=c.get("subjectOrganization") or None,
        issuer_cn=c.get("issuerCommonName") or None,
        issuer_o=c.get("issuerOrganization") or None,
        from_pem=False,
    )

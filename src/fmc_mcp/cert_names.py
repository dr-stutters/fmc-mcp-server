"""Subject and issuer names of a certificate object, read from its PEM (#273).

FMC 10.0.1's own name fields are unreliable for some of its bundled root CAs (recorded 2026-10-21):
UTF-8 names come back as mojibake ('NetLock Arany (Class Gold) FÅ\\x91tanÃºsÃ\\xadtvÃ¡ny' for
'... Főtanúsítvány'), and a value with a comma is cut there ('SECOM Trust Systems CO.' for
'SECOM Trust Systems CO.,LTD.'). Objects carry the certificate itself in `cert` (GET by id and the expanded
list), so the names are read from it; FMC's fields are the fallback when there is no PEM or it won't parse.

A certificate need not have a CN: SECOM's bundled 'Security Communication RootCA2' is C=JP, O=SECOM Trust
Systems CO.,LTD., OU=Security Communication RootCA2 (issuer = subject). `subject` / `issuer` name it by its
CN, else its OU, else its O, and `self_signed` comes from the PEM's DNs and signature (W6N live-B: the CN-only
reading gave that root no subject, issuer or self_signed)."""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class CertNames:
    subject_cn: str | None
    subject_o: str | None
    issuer_cn: str | None
    issuer_o: str | None
    from_pem: bool
    subject_ou: str | None = None
    issuer_ou: str | None = None
    self_signed: bool | None = None  # from the PEM; None when the names came from FMC's fields

    @property
    def subject(self) -> str | None:
        """The subject's name: its CN, else its OU, else its O (CN-less roots are named by their OU)."""
        return self.subject_cn or self.subject_ou or self.subject_o

    @property
    def issuer(self) -> str | None:
        return self.issuer_cn or self.issuer_ou or self.issuer_o


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
        subject_ou=_attr(cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        issuer_ou=_attr(cert.issuer, NameOID.ORGANIZATIONAL_UNIT_NAME),
        self_signed=_self_signed(cert),
    )


def _self_signed(cert: x509.Certificate) -> bool:
    """Issued by itself: the same subject and issuer DN, and its own key verifies the signature (a CA's
    link certificate can repeat the DN with another key). After the DN check a ValueError means its own key
    can't have made the signature (an RSA certificate signed with an EC key: "Signature algorithm does not
    match issuer key type"), so it isn't self-signed. A signature algorithm or key type this library can't
    check counts by the DNs alone."""
    if cert.subject != cert.issuer:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except (InvalidSignature, ValueError):
        return False
    except (TypeError, UnsupportedAlgorithm):
        return True
    return True


def cert_names(c: dict[str, Any]) -> CertNames:
    """The object's subject/issuer common name, organisation and organisational unit: from its PEM when FMC
    returned one that parses, else FMC's subjectCommonName / subjectOrganization /
    subjectOrganizationUnit / issuer* fields (empty = None)."""
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
        subject_ou=c.get("subjectOrganizationUnit") or None,
        issuer_ou=c.get("issuerOrganizationUnit") or None,
    )

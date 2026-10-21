"""#273 (F71): certificate subject and issuer names come from the object's PEM.

FMC 10.0.1's own name fields are garbled for some bundled roots (tests/fixtures/certificates_pem_fmc10.json,
read live 2026-10-21): NetLock's names are mojibake, SECOM's organisation is cut at its comma and it has no
CN. Both objects carry the certificate (`cert`) in the GET and the expanded list, so fmc_list_certificates
and fmc_get_certificate read the names from it.

A CN-less certificate is named by its OU (W6N live-B: fmc_get_certificate gave SECOM RootCA2, DN C=JP,
O=SECOM Trust Systems CO.,LTD., OU=Security Communication RootCA2, no subject, issuer or self_signed), and
self_signed comes from the PEM's DNs and signature."""

import copy
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastmcp import Client

from fmc_mcp.cert_names import cert_names
from fmc_mcp.server import create_server

from .conftest import CFG, empty, fixture, items, make_settings

FX = fixture("certificates_pem_fmc10")
NETLOCK, SECOM = FX["items"]
NETLOCK_CN = "NetLock Arany (Class Gold) Főtanúsítvány"
SECOM_O = "SECOM Trust Systems CO.,LTD."
SECOM_OU = "Security Communication RootCA2"
EXT = f"{CFG}/object/externalcacertificates"


def server() -> Any:
    return create_server(make_settings())


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, {"response_format": "json", **args})
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def test_names_from_the_recorded_pems() -> None:
    assert NETLOCK["subjectCommonName"] != NETLOCK_CN  # FMC's field: mojibake
    assert SECOM["subjectOrganization"] == "SECOM Trust Systems CO."  # FMC's field: cut at the comma
    n = cert_names(NETLOCK)
    assert (n.subject_cn, n.subject_o, n.issuer_cn, n.from_pem) == (
        NETLOCK_CN,
        "NetLock Kft.",
        NETLOCK_CN,
        True,
    )
    assert (n.subject, n.issuer, n.self_signed) == (NETLOCK_CN, NETLOCK_CN, True)
    s = cert_names(SECOM)
    assert (s.subject_cn, s.subject_o, s.issuer_o) == (None, SECOM_O, SECOM_O)
    assert (s.subject_ou, s.subject, s.issuer, s.self_signed) == (SECOM_OU, SECOM_OU, SECOM_OU, True)


def test_without_a_usable_pem_fmcs_fields_are_kept() -> None:
    bare = {k: v for k, v in NETLOCK.items() if k != "cert"}
    assert cert_names(bare).subject_cn == NETLOCK["subjectCommonName"] and not cert_names(bare).from_pem
    broken = {**NETLOCK, "cert": "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"}
    assert cert_names(broken).subject_cn == NETLOCK["subjectCommonName"]
    assert cert_names({**SECOM, "cert": "not a pem"}).subject_o == "SECOM Trust Systems CO."
    assert cert_names({"subjectCommonName": ""}).subject_cn is None
    # FMC's own fields: SECOM's OU is intact there, and nothing says self-signed without the PEM
    bare_secom = cert_names({k: v for k, v in SECOM.items() if k != "cert"})
    assert (bare_secom.subject, bare_secom.issuer, bare_secom.self_signed) == (SECOM_OU, SECOM_OU, None)
    assert cert_names({"subjectOrganization": "Only O"}).subject == "Only O"


def _pem(subject: x509.Name, issuer: x509.Name, key: Any, signer: Any) -> str:
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(signer, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_self_signed_needs_its_own_signature() -> None:
    """The same DN as issuer and subject is not enough (a CA's link certificate repeats it with another key);
    a certificate issued by another CA is not self-signed. Keys are made in memory for the test only."""
    one, two = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    dn = x509.Name([x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "mcp-test root")])
    other = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mcp-test leaf")])
    assert cert_names({"cert": _pem(dn, dn, one, one)}).self_signed is True
    link = cert_names({"cert": _pem(dn, dn, one, two)})  # same DN, signed by the other key
    assert (link.subject, link.self_signed) == ("mcp-test root", False)
    leaf = cert_names({"cert": _pem(other, dn, two, one)})
    assert (leaf.subject, leaf.issuer, leaf.self_signed) == ("mcp-test leaf", "mcp-test root", False)


async def test_list_certificates_shows_the_pem_names(fmc: respx.MockRouter) -> None:
    fmc.get(EXT).mock(return_value=httpx.Response(200, json=copy.deepcopy(FX)))
    async with Client(server()) as c:
        out = await run(c, "fmc_list_certificates", {"kind": "trusted_ca", "include_bundled": True})
    rows = {r["name"]: r for r in out["results"]}
    assert rows[NETLOCK["name"]]["subject"] == NETLOCK_CN and rows[NETLOCK["name"]]["issuer"] == NETLOCK_CN
    assert rows[SECOM["name"]]["subject"] == SECOM_OU and rows[SECOM["name"]]["issuer"] == SECOM_OU


async def test_get_certificate_shows_the_pem_names(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/object/internalcas").mock(return_value=empty())
    fmc.get(f"{CFG}/object/internalcertificates").mock(return_value=empty())
    fmc.get(EXT).mock(return_value=items(copy.deepcopy(FX["items"])))
    async with Client(server()) as c:
        out = await run(c, "fmc_get_certificate", {"kind": "trusted_ca", "include_system": True})
    rows = {r["name"]: r for r in out["results"]}
    nl, sc = rows[NETLOCK["name"]], rows[SECOM["name"]]
    assert nl["subject"] == NETLOCK_CN and nl["organization"] == "NetLock Kft." and nl["self_signed"] is True
    # live-B's call (#293): the CN-less root now has its subject, issuer and self_signed
    assert sc["organization"] == SECOM_O and sc["subject"] == SECOM_OU and sc["issuer"] == SECOM_OU
    assert sc["self_signed"] is True

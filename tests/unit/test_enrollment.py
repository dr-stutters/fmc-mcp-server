"""F75: certificate enrollment objects (fmc_create_cert_enrollment) and device enrolment
(fmc_enroll_certificate). FMC shapes: tests/fixtures/cert_enrollments.json (the W6N probe's recorded
self-signed enrollment; PKCS12 and managecertificates from FMC 10.0.1's spec and schema). The PKI material is
made here with throwaway keys, so no key or passphrase lives in the repo."""

import base64
import json
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from cryptography.x509.oid import NameOID
from fastmcp import Client
from fastmcp.exceptions import ToolError

import fmc_mcp._core.policy
from fmc_mcp._core.formatting import is_secret_key
from fmc_mcp.server import create_server
from fmc_mcp.tools.enrollment import (
    certificate_parameters,
    enrollment_row,
    key_block,
    ref_paths,
    revocation_block,
)

from .conftest import CFG, fixture, items, make_settings

FX = fixture("cert_enrollments")
ENR = f"{CFG}/object/certenrollments"
DEV_CERTS = f"{CFG}/devices/certificates"
MANAGE = f"{CFG}/devices/operational/managecertificates"
DEVICES = f"{CFG}/devices/devicerecords"
RAVPN = f"{CFG}/policy/ravpns"
S2S = f"{CFG}/policy/ftds2svpns"
DEC = f"{CFG}/policy/decryptionpolicies"
SELF = FX["self_signed_get"]
P12 = FX["pkcs12_get"]
DEVICE = FX["device"]
TASK = FX["manage_response"]["metadata"]["task"]["id"]
PHRASE = "unit-test-only-phrase"  # throwaway: protects a PKCS12 made in tmp_path
CA_PEM = (Path(__file__).resolve().parent.parent / "fixtures" / "test-ca-cert.txt").read_text()


def server(**kw: Any) -> Any:
    kw.setdefault("rate_limit", 100000)  # an enrolment preview reads ~8 collections
    return create_server(make_settings(mcp_enable_writes=True, mcp_enable_dangerous=True, **kw))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


# --- throwaway PKI ------------------------------------------------------------------------------------


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_pki(days: int = 365) -> tuple[bytes, rsa.RSAPrivateKey, x509.Certificate, x509.Certificate]:
    """(PKCS12 protected with PHRASE, identity key, identity cert, CA cert)."""
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("mcp-w6-throwaway-ca"))
        .issuer_name(_name("mcp-w6-throwaway-ca"))
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("ftd1.example.com"))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(2)
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=days))
        .sign(ca_key, hashes.SHA256())
    )
    blob = pkcs12.serialize_key_and_certificates(
        b"mcp-w6-enr-p12", key, cert, [ca], BestAvailableEncryption(PHRASE.encode())
    )
    return blob, key, cert, ca


def pki_dir(tmp_path: Path, blob: bytes | None = None) -> Path:
    d = tmp_path / "pki"
    d.mkdir()
    (d / "ftd1.p12").write_bytes(blob if blob is not None else make_pki()[0])
    (d / "ftd1.pass").write_text(PHRASE + "\n")
    for f in ("ftd1.p12", "ftd1.pass"):
        os.chmod(d / f, 0o600)
    return d


def no_users(fmc: respx.MockRouter) -> None:
    fmc.get(RAVPN).mock(return_value=items([]))
    fmc.get(S2S).mock(return_value=items([]))
    fmc.get(DEC).mock(return_value=items([]))


# --- helpers ------------------------------------------------------------------------------------------


def test_shapes() -> None:
    assert certificate_parameters(None, "mcp-w6-enr-self") == {
        "commonName": "mcp-w6-enr-self",
        "includeFQDN": "NONE",
        "includeDeviceSerial": False,
    }
    from fmc_mcp.tools.enrollment import Subject

    custom = certificate_parameters(Subject(custom_fqdn="ftd1.example.com", country="au"), "x")
    assert custom["includeFQDN"] == "CUSTOM" and custom["countryCode"] == "AU"
    with pytest.raises(ToolError, match="custom_fqdn"):
        certificate_parameters(Subject(fqdn="custom"), "x")
    with pytest.raises(ToolError, match="not an IP"):
        certificate_parameters(Subject(device_ip="ftd1"), "x")
    assert key_block("RSA", None, None, "n") == {"keyType": "RSA", "keyName": "n", "keySize": "CertKey_2048"}
    assert key_block("ECDSA", 384, "k", "n")["keySize"] == "CertKey_384"
    with pytest.raises(ToolError, match="not offered"):
        key_block("RSA", 1024, None, "n")
    assert revocation_block("none", None) is None
    crl = revocation_block("crl", "http://crl.example.com/ca.crl")
    assert crl is not None and crl["evaluationPriority"] == "CRL"
    assert crl["certRevocationListContent"]["certRevocationStaticUrlList"] == [
        "http://crl.example.com/ca.crl"
    ]
    assert ref_paths({"a": {"id": "X"}, "b": [{"c": {"id": "x"}}], "metadata": {"id": "x"}}, {"x"}) == [
        "a",
        "b[].c",
    ]


def test_pkcs12_bundle_is_a_secret_key() -> None:
    """FMC returns the PKCS12 bundle on every read; fmc_api_call and the audit log mask it."""
    assert is_secret_key("base64Certificate") and is_secret_key("passPhrase")
    assert not is_secret_key("base64Content")  # a manual enrollment's CA certificate is public


def test_enrollment_row_never_shows_the_bundle() -> None:
    row = enrollment_row(P12)
    text = json.dumps(row)
    assert row["kind"] == "pkcs12" and "stored on FMC" in row["pkcs12"]
    assert P12["pkcs12Content"]["base64Certificate"][:20] not in text and "*****" not in text
    self_row = enrollment_row(SELF)
    assert self_row["kind"] == "self_signed" and self_row["key"] == "RSA 2048 (mcp-w6-enr-probe-key)"
    assert self_row["usage"] == ["ipsec_client", "ssl_client"] and self_row["revocation"] == "NONE"


# --- fmc_create_cert_enrollment -----------------------------------------------------------------------


async def test_self_signed_matches_the_recorded_request(fmc: respx.MockRouter) -> None:
    fmc.get(ENR).mock(return_value=httpx.Response(200, json=FX["enrollments_empty"]))
    post = fmc.post(ENR).mock(return_value=httpx.Response(201, json=FX["self_signed_post"]))
    fmc.get(f"{ENR}/{SELF['id']}").mock(return_value=httpx.Response(200, json=SELF))
    args = {
        "name": "mcp-w6-enr-probe",
        "kind": "self_signed",
        "subject": {"common_name": "mcp-w6-enr-probe", "organization": "mcp-w6"},
        "key_name": "mcp-w6-enr-probe-key",
        "description": FX["self_signed_request"]["description"],
        "domain": None,
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_create_cert_enrollment", args)
        assert p["status"] == "preview" and not post.called
        assert p["preview"]["enrollment"]["enrollmentType"] == "SELF_SIGNED_CERTFICATE"
        assert any("fmc_enroll_certificate" in s for s in p["side_effects"])
        out = await run(c, "fmc_create_cert_enrollment", {**args, "confirm": p["confirm"]})
    assert json.loads(post.calls.last.request.content) == FX["self_signed_request"]
    result = out["result"]
    assert result["id"] == SELF["id"] and result["kind"] == "self_signed"
    assert "fmc_enroll_certificate" in result["next"]


async def test_name_clash_and_wrong_kind_arguments(fmc: respx.MockRouter) -> None:
    fmc.get(ENR).mock(return_value=items([{"id": SELF["id"], "name": "mcp-w6-enr-probe"}]))
    async with Client(server()) as c:
        dup = await run(c, "fmc_create_cert_enrollment", {"name": "MCP-W6-ENR-PROBE", "kind": "self_signed"})
        assert dup["status"] == "blocked" and "already exists" in dup["blockers"][0]
        with pytest.raises(ToolError, match="doesn't take subject"):
            await run(
                c,
                "fmc_create_cert_enrollment",
                {"name": "x", "kind": "pkcs12", "pkcs12_file": "a.p12", "subject": {"common_name": "x"}},
            )
        with pytest.raises(ToolError, match="needs pkcs12_file"):
            await run(c, "fmc_create_cert_enrollment", {"name": "x", "kind": "pkcs12"})
        with pytest.raises(ToolError, match="FMC_PKI_DIR"):
            await run(
                c, "fmc_create_cert_enrollment", {"name": "x", "kind": "pkcs12", "pkcs12_file": "a.p12"}
            )


async def test_pkcs12_from_files_never_shows_key_bundle_or_passphrase(
    fmc: respx.MockRouter, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    blob, _, cert, ca = make_pki()
    d = pki_dir(tmp_path, blob)
    b64 = base64.b64encode(blob).decode()
    fmc.get(ENR).mock(return_value=items([]))
    post = fmc.post(ENR).mock(return_value=httpx.Response(201, json={"id": P12["id"]}))
    fmc.get(f"{ENR}/{P12['id']}").mock(return_value=httpx.Response(200, json=P12))
    args = {
        "name": "mcp-w6-enr-p12",
        "kind": "pkcs12",
        "pkcs12_file": "ftd1.p12",
        "passphrase_file": "ftd1.pass",
        "usage": ["ipsec_client", "ssl_client", "ssl_server"],
    }
    caplog.set_level(logging.DEBUG)
    async with Client(server(pki_dir=d)) as c:
        p = await run(c, "fmc_create_cert_enrollment", args)
        assert p["status"] == "preview", p
        facts = p["preview"]["pkcs12"]
        assert facts["identity_certificate"]["subject"] == "CN=ftd1.example.com"
        assert facts["identity_certificate"]["issuer"] == "CN=mcp-w6-throwaway-ca"
        assert facts["key"] == "RSA 2048" and len(facts["ca_certificates"]) == 1
        assert facts["ca_certificates"][0]["ca"] is True
        assert "passphrase file 'ftd1.pass'" in facts["unlocked_with"]
        shown = p["preview"]["enrollment"]["pkcs12Content"]
        assert shown["passPhrase"] == "********" and "sent to FMC only" in shown["base64Certificate"]
        out = await run(c, "fmc_create_cert_enrollment", {**args, "confirm": p["confirm"]})
    sent = json.loads(post.calls.last.request.content)
    assert sent["enrollmentType"] == "PKCS12" and sent["pkcs12Content"] == {
        "base64Certificate": b64,
        "passPhrase": PHRASE,
    }
    assert sent["validationUsage"] == {"ipsecClient": True, "sslClient": True, "sslServer": True}
    everything = json.dumps(p) + json.dumps(out) + "\n".join(r.getMessage() for r in caplog.records)
    for secret in (PHRASE, b64[:40], P12["pkcs12Content"]["base64Certificate"][:20]):
        assert secret not in everything
    assert out["result"]["pkcs12"].startswith("stored on FMC")


async def test_pkcs12_passphrase_problems(fmc: respx.MockRouter, tmp_path: Path) -> None:
    d = pki_dir(tmp_path)
    (d / "wrong.pass").write_text("not-the-phrase\n")
    fmc.get(ENR).mock(return_value=items([]))
    base = {"name": "p", "kind": "pkcs12", "pkcs12_file": "ftd1.p12"}
    async with Client(server(pki_dir=d)) as c:
        none = await run(c, "fmc_create_cert_enrollment", base)
        assert none["status"] == "blocked" and "passphrase" in none["blockers"][0]
        wrong = await run(c, "fmc_create_cert_enrollment", {**base, "passphrase_file": "wrong.pass"})
        assert wrong["status"] == "blocked" and "wrong passphrase" in wrong["blockers"][0]
        assert "not-the-phrase" not in json.dumps(wrong)
        with pytest.raises(ToolError, match="outside FMC_PKI_DIR"):
            await run(c, "fmc_create_cert_enrollment", {**base, "pkcs12_file": "../ftd1.p12"})
    async with Client(server(pki_dir=d, pki_passphrase=PHRASE)) as c:
        ok = await run(c, "fmc_create_cert_enrollment", base)
    assert ok["status"] == "preview" and ok["preview"]["pkcs12"]["unlocked_with"].startswith(
        "FMC_PKI_PASSPHRASE"
    )


async def test_pkcs12_base64_file_expiry_chain_and_changed_file(
    fmc: respx.MockRouter, tmp_path: Path
) -> None:
    blob, key, cert, _ = make_pki(days=10)
    bare = pkcs12.serialize_key_and_certificates(
        b"x", key, cert, None, BestAvailableEncryption(PHRASE.encode())
    )
    d = pki_dir(tmp_path, base64.encodebytes(bare))  # base64 text, no CA chain, expiring soon
    fmc.get(ENR).mock(return_value=items([]))
    post = fmc.post(ENR).mock(return_value=httpx.Response(201, json={"id": P12["id"]}))
    args = {"name": "p", "kind": "pkcs12", "pkcs12_file": "ftd1.p12", "passphrase_file": "ftd1.pass"}
    async with Client(server(pki_dir=d)) as c:
        p = await run(c, "fmc_create_cert_enrollment", args)
        warnings = " ".join(p["preview"]["warnings"])
        assert p["status"] == "preview" and "no CA certificate" in warnings and "expires in" in warnings
        (d / "ftd1.p12").write_bytes(blob)  # replaced after the preview
        with pytest.raises(ToolError, match="changed since the preview"):
            await run(c, "fmc_create_cert_enrollment", {**args, "confirm": p["confirm"]})
    assert not post.called
    old = make_pki(days=-1)[0]
    (d / "ftd1.p12").write_bytes(old)
    async with Client(server(pki_dir=d)) as c:
        expired = await run(c, "fmc_create_cert_enrollment", args)
    assert expired["status"] == "blocked" and "expired" in expired["blockers"][0]


async def test_manual_ca_only(fmc: respx.MockRouter) -> None:
    fmc.get(ENR).mock(return_value=items([]))
    new = {"id": "00000000-0000-0ed3-0000-073014444119"}
    post = fmc.post(ENR).mock(return_value=httpx.Response(201, json=new))
    from fmc_mcp.tools.identity import pem_body

    _, der = pem_body(CA_PEM)
    got = {
        **new,
        "name": "mcp-w6-enr-ca",
        "enrollmentType": "MANUAL",
        "caCertificate": {"caOnly": True, "base64Content": base64.b64encode(der).decode()},
    }
    fmc.get(f"{ENR}/{new['id']}").mock(return_value=httpx.Response(200, json=got))
    args = {"name": "mcp-w6-enr-ca", "kind": "manual_ca_only", "ca_cert": CA_PEM}
    async with Client(server()) as c:
        p = await run(c, "fmc_create_cert_enrollment", args)
        assert p["status"] == "preview" and p["preview"]["ca_certificate"]["sha1_fingerprint"]
        assert "BEGIN CERTIFICATE" not in json.dumps(p["preview"]["enrollment"])
        out = await run(c, "fmc_create_cert_enrollment", {**args, "confirm": p["confirm"]})
        with pytest.raises(ToolError, match="private key"):
            await run(c, "fmc_create_cert_enrollment", {**args, "ca_cert": CA_PEM + "PRIVATE KEY"})
        with pytest.raises(ToolError, match="one of them"):
            await run(c, "fmc_create_cert_enrollment", {"name": "x", "kind": "manual_ca_only"})
    sent = json.loads(post.calls.last.request.content)["caCertificate"]
    assert sent["caOnly"] is True and "BEGIN" not in sent["base64Content"]
    assert base64.b64decode(sent["base64Content"]) == der
    assert (
        out["result"]["ca_certificate"]["sha1_fingerprint"]
        == p["preview"]["ca_certificate"]["sha1_fingerprint"]
    )


async def test_scep_and_est_passwords_come_from_files(fmc: respx.MockRouter, tmp_path: Path) -> None:
    d = tmp_path / "pki"
    d.mkdir()
    (d / "scep.pass").write_text("scep-challenge-test\n")
    os.chmod(d / "scep.pass", 0o644)
    fmc.get(ENR).mock(return_value=items([]))
    post = fmc.post(ENR).mock(return_value=httpx.Response(201, json={"id": SELF["id"]}))
    fmc.get(f"{ENR}/{SELF['id']}").mock(return_value=httpx.Response(200, json=SELF))
    args = {
        "name": "mcp-w6-enr-scep",
        "kind": "scep",
        "enrollment_url": "http://198.51.100.20/certsrv/mscep/mscep.dll",
        "password_file": "scep.pass",
        "ca_fingerprint": "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01",
        "subject": {"fqdn": "device_hostname"},
    }
    async with Client(server(pki_dir=d)) as c:
        p = await run(c, "fmc_create_cert_enrollment", args)
        assert p["preview"]["enrollment"]["scepContent"]["challengePassword"] == "********"
        assert "scep-challenge-test" not in json.dumps(p) and "chmod 600" in p["preview"]["warnings"][0]
        await run(c, "fmc_create_cert_enrollment", {**args, "confirm": p["confirm"]})
        with pytest.raises(ToolError, match="username and password_file"):
            await run(
                c,
                "fmc_create_cert_enrollment",
                {"name": "e", "kind": "est", "enrollment_url": "https://198.51.100.21/.well-known/est"},
            )
        with pytest.raises(ToolError, match="http"):
            await run(c, "fmc_create_cert_enrollment", {**args, "enrollment_url": "ftp://x"})
    scep = json.loads(post.calls.last.request.content)["scepContent"]
    assert scep["challengePassword"] == "scep-challenge-test"
    assert scep["fingerprint"] == "abcdef0123456789abcdef0123456789abcdef01"
    assert (
        json.loads(post.calls.last.request.content)["certificateParameters"]["includeFQDN"]
        == "DEVICE_HOSTNAME"
    )


async def test_api_call_masks_the_pkcs12_bundle(fmc: respx.MockRouter) -> None:
    fmc.get(f"{ENR}/{P12['id']}").mock(return_value=httpx.Response(200, json=P12))
    async with Client(server()) as c:
        out = await run(c, "fmc_api_call", {"method": "GET", "path": f"{ENR}/{P12['id']}"})
    assert out["name"] == "mcp-w6-enr-p12" and out["enrollmentType"] == "PKCS12"
    assert out["pkcs12Content"] == {"base64Certificate": "********", "passPhrase": "********"}
    assert P12["pkcs12Content"]["base64Certificate"][:20] not in json.dumps(out)


# --- fmc_enroll_certificate ---------------------------------------------------------------------------


def device_and_enrollment(fmc: respx.MockRouter, device: dict[str, Any] | None = None) -> None:
    dev = device or DEVICE
    fmc.get(DEVICES).mock(return_value=items([dev]))
    fmc.get(f"{DEVICES}/{dev['id']}").mock(return_value=httpx.Response(200, json=dev))
    fmc.get(ENR).mock(
        return_value=items([{"id": SELF["id"], "name": SELF["name"], "type": "CertEnrollment"}])
    )
    fmc.get(f"{ENR}/{SELF['id']}").mock(return_value=httpx.Response(200, json=SELF))


ENROL = {"device": "mcp-ftd1", "enrollment": "mcp-w6-enr-probe"}


async def test_enroll_self_signed_waits_for_the_task(fmc: respx.MockRouter) -> None:
    device_and_enrollment(fmc)
    no_users(fmc)
    certs = fmc.get(DEV_CERTS).mock(
        side_effect=[
            httpx.Response(200, json=FX["device_certificates_empty"]),
            httpx.Response(200, json=FX["device_certificates_empty"]),
            httpx.Response(200, json=FX["device_enrolled"]),
        ]
    )
    post = fmc.post(MANAGE).mock(return_value=httpx.Response(202, json=FX["manage_response"]))
    task = fmc.get(f"{CFG}/job/taskstatuses/{TASK}").mock(
        return_value=httpx.Response(200, json=FX["task_success"])
    )
    async with Client(server()) as c:
        p = await run(c, "fmc_enroll_certificate", ENROL)
        assert p["status"] == "preview", p
        assert p["preview"]["on_device"] == "not enrolled" and p["preview"]["used_by"] == []
        assert (
            "mcp-w6-enr-probe-key (RSA 2048)" in p["side_effects"][0]
            and "without a deployment" in p["side_effects"][0]
        )
        assert p["blast_radius"] == 1 and not post.called
        out = await run(c, "fmc_enroll_certificate", {**ENROL, "confirm": p["confirm"]})
    assert json.loads(post.calls.last.request.content) == {
        "action": "ENROLL",
        "deviceCertificates": [
            {
                "deviceId": DEVICE["id"],
                "certificates": [{"certificate": {"id": SELF["id"], "type": "CertEnrollment"}}],
            }
        ],
    }
    result = out["result"]
    assert task.called and result["task_id"] == TASK and result["task"]["status"] == "SUCCESS"
    assert result["outcome"] == "enrolled" and result["on_device"]["identity_status"] == "AVAILABLE"
    assert result["on_device"]["identity_expires"].startswith("2034-") and certs.call_count == 3


async def test_enroll_blockers(fmc: respx.MockRouter) -> None:
    device_and_enrollment(fmc)
    no_users(fmc)
    fmc.get(DEV_CERTS).mock(return_value=httpx.Response(200, json=FX["device_enrolled"]))
    async with Client(server()) as c:
        again = await run(c, "fmc_enroll_certificate", ENROL)
        assert again["status"] == "blocked" and "already enrolled" in again["blockers"][0]
        assert "re_enroll" in again["blockers"][0]
        fmc.get(DEV_CERTS).mock(return_value=httpx.Response(200, json=FX["device_certificates_empty"]))
        for action in ("re_enroll", "refresh", "delete"):
            out = await run(c, "fmc_enroll_certificate", {**ENROL, "action": action})
            assert out["status"] == "blocked" and "not enrolled on mcp-ftd1" in out["blockers"][0], action
        failed = json.loads(json.dumps(FX["device_enrolled"]))
        failed["items"][0]["enrolledCertificates"][0] |= {
            "deploymentStatus": "FAILED",
            "errorMessage": "boom",
        }
        fmc.get(DEV_CERTS).mock(return_value=httpx.Response(200, json=failed))
        retry = await run(c, "fmc_enroll_certificate", ENROL)
        assert "use action='re_enroll'" in retry["blockers"][0]


async def test_delete_blocked_while_ra_vpn_uses_it_and_refresh_skips_the_scan(fmc: respx.MockRouter) -> None:
    device_and_enrollment(fmc)
    fmc.get(DEV_CERTS).mock(return_value=httpx.Response(200, json=FX["device_enrolled"]))
    ref = {"id": SELF["id"], "type": "CertEnrollment", "name": SELF["name"]}
    rav = fmc.get(RAVPN).mock(
        return_value=items(
            [{"id": "rav1", "name": "mcp-w6-ravpn", "accessInterfaceSettings": {"sslIdCertificate": ref}}]
        )
    )
    fmc.get(S2S).mock(return_value=items([{"id": "s2s1", "name": "mcp-w6-s2s"}]))
    fmc.get(f"{S2S}/s2s1/ikesettings").mock(
        return_value=items(
            [
                {
                    "id": "ike1",
                    "type": "IkeSettings",
                    "ikeV2Settings": {"authenticationType": "CERTIFICATE", "certificateAuth": ref},
                }
            ]
        )
    )
    fmc.get(DEC).mock(return_value=items([]))
    async with Client(server()) as c:
        gone = await run(c, "fmc_enroll_certificate", {**ENROL, "action": "delete"})
        assert gone["status"] == "blocked"
        assert gone["preview"]["used_by"] == [
            "RA VPN mcp-w6-ravpn (SSL identity certificate)",
            "S2S VPN mcp-w6-s2s (IKEv2 certificate authentication)",
        ]
        assert "Still referenced by" in gone["blockers"][-1]
        redo = await run(c, "fmc_enroll_certificate", {**ENROL, "action": "re_enroll"})
        assert redo["status"] == "preview" and any("may drop" in s for s in redo["side_effects"])
        calls = rav.call_count
        fresh = await run(c, "fmc_enroll_certificate", {**ENROL, "action": "refresh"})
        assert fresh["status"] == "preview" and "used_by" not in fresh["preview"] and rav.call_count == calls


async def test_failed_task_names_the_device_error(fmc: respx.MockRouter) -> None:
    device_and_enrollment(fmc)
    no_users(fmc)
    failed = json.loads(json.dumps(FX["device_enrolled"]))
    failed["items"][0]["enrolledCertificates"][0] |= {
        "deploymentStatus": "FAILED",
        "errorMessage": "no route to CA",
    }
    fmc.get(DEV_CERTS).mock(
        side_effect=[
            httpx.Response(200, json=FX["device_enrolled"]),
            httpx.Response(200, json=FX["device_enrolled"]),
            httpx.Response(200, json=failed),
        ]
    )
    fmc.post(MANAGE).mock(return_value=httpx.Response(202, json=FX["manage_response"]))
    fmc.get(f"{CFG}/job/taskstatuses/{TASK}").mock(return_value=httpx.Response(200, json=FX["task_failed"]))
    args = {**ENROL, "action": "re_enroll"}
    async with Client(server()) as c:
        p = await run(c, "fmc_enroll_certificate", args)
        with pytest.raises(ToolError, match="no route to CA") as e:
            await run(c, "fmc_enroll_certificate", {**args, "confirm": p["confirm"]})
    assert TASK in str(e.value)


async def test_no_task_id_follows_the_row_and_no_wait(fmc: respx.MockRouter) -> None:
    device_and_enrollment(fmc)
    no_users(fmc)
    fmc.get(DEV_CERTS).mock(
        side_effect=[
            httpx.Response(200, json=FX["device_enrolled"]),
            httpx.Response(200, json=FX["device_enrolled"]),
            httpx.Response(200, json=FX["device_certificates_empty"]),
            httpx.Response(200, json=FX["device_certificates_empty"]),
        ]
    )
    fmc.post(MANAGE).mock(return_value=httpx.Response(200, json={"action": "DELETE"}))
    args = {**ENROL, "action": "delete"}
    async with Client(server()) as c:
        p = await run(c, "fmc_enroll_certificate", args)
        assert "The enrollment object stays" in p["side_effects"][0]
        out = await run(c, "fmc_enroll_certificate", {**args, "confirm": p["confirm"]})
    assert (
        out["result"]["outcome"] == "removed from the device" and out["result"]["on_device"] == "not enrolled"
    )
    fmc.get(DEV_CERTS).mock(return_value=httpx.Response(200, json=FX["device_certificates_empty"]))
    fmc.post(MANAGE).mock(return_value=httpx.Response(202, json=FX["manage_response"]))
    args = {**ENROL, "wait": False}
    async with Client(server()) as c:
        p = await run(c, "fmc_enroll_certificate", args)
        out = await run(c, "fmc_enroll_certificate", {**args, "confirm": p["confirm"]})
    assert out["result"]["task_id"] == TASK and "fmc_get_task" in out["result"]["note"]


async def test_ha_member_disconnected_and_deploy_window(
    fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    unit = {
        **DEVICE,
        "isConnected": False,
        "metadata": {
            "containerDetails": {
                "id": "ha1",
                "name": "mcp-w6-ha",
                "type": "DeviceHAPair",
                "role": "PRIMARY",
                "status": "Active",
            }
        },
    }
    device_and_enrollment(fmc, unit)
    no_users(fmc)
    fmc.get(DEV_CERTS).mock(return_value=httpx.Response(200, json=FX["device_certificates_empty"]))
    monkeypatch.setattr(fmc_mcp._core.policy, "_now", lambda: datetime(2026, 10, 14, 12, 0, tzinfo=UTC))
    async with Client(server(deploy_window="Sat 22:00-04:00 UTC")) as c:
        out = await run(c, "fmc_enroll_certificate", ENROL)
    text = json.dumps(out)
    assert out["status"] == "blocked" and "HA pair mcp-w6-ha" in out["blockers"][0]
    assert "FMC_DEPLOY_WINDOW" in text and "not connected" in text


async def test_running_task_is_polled_and_a_slow_one_is_reported(
    fmc: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    device_and_enrollment(fmc)
    no_users(fmc)
    fmc.get(DEV_CERTS).mock(return_value=httpx.Response(200, json=FX["device_enrolled"]))
    fmc.post(MANAGE).mock(return_value=httpx.Response(202, json=FX["manage_response"]))
    task = fmc.get(f"{CFG}/job/taskstatuses/{TASK}").mock(
        side_effect=[
            httpx.Response(200, json=FX["task_running"]),
            httpx.Response(200, json=FX["task_success"]),
        ]
    )
    args = {**ENROL, "action": "refresh"}
    async with Client(server()) as c:
        p = await run(c, "fmc_enroll_certificate", args)
        out = await run(c, "fmc_enroll_certificate", {**args, "confirm": p["confirm"]})
    assert task.call_count == 2 and out["result"]["outcome"] == "status refreshed (SUCCESS)"
    task.mock(return_value=httpx.Response(200, json=FX["task_running"]))
    async with Client(server(mcp_task_timeout=0.01)) as c:
        p = await run(c, "fmc_enroll_certificate", args)
        out = await run(c, "fmc_enroll_certificate", {**args, "confirm": p["confirm"]})
    assert out["result"]["status"] == "still running" and "fmc_list_certificates" in out["result"]["note"]


async def test_est_body(fmc: respx.MockRouter, tmp_path: Path) -> None:
    d = tmp_path / "pki"
    d.mkdir()
    (d / "est.pass").write_text("est-password-test\n")
    os.chmod(d / "est.pass", 0o600)
    fmc.get(ENR).mock(return_value=items([]))
    post = fmc.post(ENR).mock(return_value=httpx.Response(201, json={"id": SELF["id"]}))
    fmc.get(f"{ENR}/{SELF['id']}").mock(return_value=httpx.Response(200, json=SELF))
    args = {
        "name": "mcp-w6-enr-est",
        "kind": "est",
        "enrollment_url": "https://198.51.100.21/.well-known/est",
        "username": "ftd-est",
        "password_file": "est.pass",
        "key_type": "ECDSA",
        "revocation": "ocsp",
        "revocation_url": "http://198.51.100.21/ocsp",
    }
    async with Client(server(pki_dir=d)) as c:
        p = await run(c, "fmc_create_cert_enrollment", args)
        assert p["preview"]["enrollment"]["estContent"]["password"] == "********"
        assert "est-password-test" not in json.dumps(p) and "warnings" not in p["preview"]
        await run(c, "fmc_create_cert_enrollment", {**args, "confirm": p["confirm"]})
    sent = json.loads(post.calls.last.request.content)
    assert sent["enrollmentType"] == "EST" and sent["estContent"] == {
        "enrollmentUrl": "https://198.51.100.21/.well-known/est",
        "username": "ftd-est",
        "password": "est-password-test",
    }
    assert sent["key"] == {"keyType": "ECDSA", "keyName": "mcp-w6-enr-est", "keySize": "CertKey_256"}
    assert sent["revocation"]["evaluationPriority"] == "OCSP"
    assert sent["revocation"]["onlineCertificateStatusProtocolContent"] == {
        "enableOnlineCertificateStatusProtocol": True,
        "onlineCertificateStatusProtocolUrl": "http://198.51.100.21/ocsp",
    }

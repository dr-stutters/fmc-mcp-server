"""F64: certificate objects for TLS decryption (internal CAs, internal certificates, trusted CAs)."""

import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server
from fmc_mcp.tools.pki import ca_problems, cert_row, parse_date

from .conftest import CFG, fixture, items, make_settings

FX = fixture("decryption_pki")
CA = FX["internal_ca"]
CSR_CA = FX["internal_ca_csr"]
WEB = FX["internal_cert"]
TRUSTED = FX["trusted_cas"]
POLICY = FX["decryption_policy"]
RULES = FX["decryption_rules"]
CAS = f"{CFG}/object/internalcas"
CERTS = f"{CFG}/object/internalcertificates"
EXT = f"{CFG}/object/externalcacertificates"
DEC = f"{CFG}/policy/decryptionpolicies"
CA_PEM = (Path(__file__).resolve().parent.parent / "fixtures" / "test-ca-cert.txt").read_text()
# A stand-in key file: the PEM label is all the server looks at; FMC (mocked here) checks the key.
DASH = "-" * 5
KEY_BODY = "FAKE0KEY0BODY0FOR0TESTS0ONLY"  # not key material
KEY = f"{DASH}BEGIN PRIVATE KEY{DASH}\n{KEY_BODY}\n{DASH}END PRIVATE KEY{DASH}\n"
ENC_KEY = KEY.replace("BEGIN PRIVATE", "BEGIN ENCRYPTED PRIVATE").replace(
    "END PRIVATE", "END ENCRYPTED PRIVATE"
)


def server(**kw: Any) -> Any:
    return create_server(make_settings(mcp_enable_writes=True, **kw))


async def run(c: Client[Any], name: str, args: dict[str, Any]) -> Any:
    r = await c.call_tool(name, args)
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def mock_catalog(fmc: respx.MockRouter, *, rules: list[dict[str, Any]] | None = None) -> None:
    fmc.get(CAS).mock(return_value=items([CA, CSR_CA]))
    fmc.get(f"{CAS}/{CA['id']}").mock(return_value=httpx.Response(200, json=CA))
    fmc.get(f"{CAS}/{CSR_CA['id']}").mock(return_value=httpx.Response(200, json=CSR_CA))
    fmc.get(CERTS).mock(return_value=items([WEB]))
    fmc.get(f"{CERTS}/{WEB['id']}").mock(return_value=httpx.Response(200, json=WEB))
    fmc.get(EXT).mock(return_value=items(TRUSTED))
    for t in TRUSTED:
        fmc.get(f"{EXT}/{t['id']}").mock(return_value=httpx.Response(200, json=t))
    fmc.get(DEC).mock(return_value=items([POLICY]))
    fmc.get(f"{DEC}/{POLICY['id']}/decryptionpolicyrules").mock(
        return_value=items(RULES if rules is None else rules)
    )
    fmc.get(f"{CFG}/object/realms").mock(return_value=items([]))


def test_dates_rows_and_problems() -> None:
    assert parse_date("Jul  9 21:46:56 2034 GMT") == parse_date("2034-07-09T21:46:56Z")
    assert parse_date("not a date") is None and parse_date(None) is None
    row = cert_row(TRUSTED[0], __import__("fmc_mcp.tools.pki", fromlist=["KINDS"]).KINDS["trusted_ca"])
    assert row["system"] is True and row["self_signed"] is True and row["valid_until"].endswith("2038 GMT")
    assert ca_problems(CA) == []
    assert "fmc_install_internal_ca_cert" in ca_problems(CSR_CA)[0]
    assert "expired" in ca_problems({**CA, "validityEndDate": "2020-01-01T00:00:00Z"})[0]
    assert "expires in" in ca_problems({**CA, "validityEndDate": parse_date_soon()})[0]


def parse_date_soon() -> str:
    from datetime import UTC, datetime, timedelta

    return (datetime.now(UTC) + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")


async def test_list_hides_system_trusted_cas(fmc: respx.MockRouter) -> None:
    mock_catalog(fmc)
    async with Client(server()) as c:
        out = await run(c, "fmc_get_certificate", {"response_format": "json"})
        names = {r["name"]: r for r in out["results"]}
        assert set(names) == {
            "mcp-test-resign-ca",
            "mcp-test-csr-ca",
            "mcp-test-web-cert",
            "mcp-test-server-ca",
        }
        assert names["mcp-test-csr-ca"]["csr_pending"] is True
        assert "privateKey" not in json.dumps(out) and "********" not in json.dumps(out)
        both = await run(
            c,
            "fmc_get_certificate",
            {"kind": "trusted_ca", "include_system": True, "response_format": "json"},
        )
        assert {r["name"] for r in both["results"]} == {"Cisco-Licensing-Root-CA", "mcp-test-server-ca"}


async def test_global_certificates_in_a_child_domain_are_not_system(fmc: respx.MockRouter) -> None:
    """live-B2: in Global/mcp-test-leaf fmc_get_certificate said `system: true` for a certificate somebody
    imported in Global, because FMC 10.0.1 marks an ancestor's objects read-only with no reason there. The
    recorded leaf answers (certificates.json): the internal certificate and the custom CA are not system
    (they name their domain instead) and the custom CA stays listed; the bundled root is system and hidden."""
    live = fixture("certificates")
    internal = live["internal_certificates"]["items"][0]
    cas = live["trusted_cas"]["items"]  # COMODO (bundled root), the lab's own CA, FNMT (bundled root)
    fmc.get(CAS).mock(return_value=items([]))
    fmc.get(CERTS).mock(return_value=items([internal]))
    fmc.get(f"{CERTS}/{internal['id']}").mock(return_value=httpx.Response(200, json=internal))
    fmc.get(EXT).mock(return_value=items(cas))
    for t in cas:
        fmc.get(f"{EXT}/{t['id']}").mock(return_value=httpx.Response(200, json=t))
    fmc.get(DEC).mock(return_value=items([]))
    fmc.get(f"{CFG}/object/realms").mock(return_value=items([]))
    async with Client(server()) as c:
        one = await run(
            c, "fmc_get_certificate", {"certificate": internal["name"], "response_format": "json"}
        )
        assert "system" not in one and one["domain"] == "Global" and one["kind"] == "internal_cert"
        listed = await run(c, "fmc_get_certificate", {"kind": "trusted_ca", "response_format": "json"})
        assert [r["name"] for r in listed["results"]] == ["mcp-test-lab-CA"]
        every = await run(
            c,
            "fmc_get_certificate",
            {"kind": "trusted_ca", "include_system": True, "response_format": "json"},
        )
        assert {r["name"]: r.get("system") for r in every["results"]} == {
            "COMODO-ECC-Certification-Authority": True,
            "mcp-test-lab-CA": None,
            "C_ES-O_FNMT-RCM-OU_AC-RAIZ-FNMT-RCM": True,
        }
        gone = await run(c, "fmc_delete_certificate", {"certificate": internal["name"]})
    # not refused as a system certificate (in a child domain fmc_preview's owner-domain blocker names Global)
    assert "Read-only system certificate." not in gone.get("blockers", [])


async def test_show_internal_ca_with_pem_and_usage(fmc: respx.MockRouter) -> None:
    mock_catalog(fmc)
    async with Client(server()) as c:
        out = await run(
            c, "fmc_get_certificate", {"certificate": "mcp-test-resign-ca", "response_format": "json"}
        )
    assert out["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert out["used_by"] == ["decryption rule mcp-test-tls/resign-outbound (resign CA)"]
    assert any("trusted root" in n for n in out["notes"])
    assert "privateKey" not in json.dumps(out) and "passPhrase" not in json.dumps(out)


async def test_show_trusted_ca_used_by_policy(fmc: respx.MockRouter) -> None:
    mock_catalog(fmc)
    pol = {**POLICY, "trustedCAs": {"objects": [{"id": TRUSTED[1]["id"], "name": TRUSTED[1]["name"]}]}}
    fmc.get(DEC).mock(return_value=items([pol]))
    async with Client(server()) as c:
        out = await run(
            c, "fmc_get_certificate", {"certificate": "mcp-test-server-ca", "response_format": "json"}
        )
    assert out["used_by"] == ["decryption policy mcp-test-tls (trusted CA)"]


async def test_create_self_signed_internal_ca(fmc: respx.MockRouter) -> None:
    fmc.get(CAS).mock(return_value=items([CSR_CA]))
    new = {**CA, "name": "mcp-fw-resign-ca"}
    post = fmc.post(CAS).mock(
        return_value=httpx.Response(201, json={"id": CA["id"], "name": "mcp-fw-resign-ca"})
    )
    fmc.get(f"{CAS}/{CA['id']}").mock(return_value=httpx.Response(200, json=new))
    args = {
        "name": "mcp-fw-resign-ca",
        "common_name": "MCP FW Resign CA",
        "organization": "Example",
        "country": "us",
    }
    async with Client(server()) as c:
        p = await run(c, "fmc_create_internal_ca", args)
        assert p["status"] == "preview" and p["preview"]["method"] == "self_signed"
        assert p["preview"]["subject"]["subjectCountry"] == "US"
        assert not post.called
        out = await run(c, "fmc_create_internal_ca", {**args, "confirm": p["confirm"]})
    req = post.calls.last.request
    assert req.url.params["isCSR"] == "false"
    body = json.loads(req.content)
    assert body == {
        "name": "mcp-fw-resign-ca",
        "type": "InternalCA",
        "subjectCommonName": "MCP FW Resign CA",
        "subjectOrganization": "Example",
        "subjectCountry": "US",
    }
    result = out["result"]
    assert result["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "DECRYPT_RESIGN" in result["next"] and "********" not in json.dumps(out)


async def test_create_csr_internal_ca_and_duplicate(fmc: respx.MockRouter) -> None:
    fmc.get(CAS).mock(return_value=items([CA]))
    post = fmc.post(CAS).mock(return_value=httpx.Response(201, json={"id": CSR_CA["id"]}))
    fmc.get(f"{CAS}/{CSR_CA['id']}").mock(return_value=httpx.Response(200, json=CSR_CA))
    args = {"name": "mcp-test-csr-ca", "common_name": "Example TLS Inspection CA", "csr": True}
    async with Client(server()) as c:
        dup = await run(c, "fmc_create_internal_ca", {**args, "name": "MCP-TEST-RESIGN-CA"})
        assert dup["status"] == "blocked" and "already exists" in dup["blockers"][0]
        p = await run(c, "fmc_create_internal_ca", args)
        out = await run(c, "fmc_create_internal_ca", {**args, "confirm": p["confirm"]})
    assert post.calls.last.request.url.params["isCSR"] == "true"
    assert out["result"]["csr_pem"].startswith("-----BEGIN CERTIFICATE REQUEST-----")
    assert "fmc_install_internal_ca_cert" in out["result"]["next"]


async def test_install_signed_certificate(fmc: respx.MockRouter) -> None:
    mock_catalog(fmc)
    path = f"{CAS}/{CSR_CA['id']}"
    put = fmc.put(path).mock(return_value=httpx.Response(200, json={**CSR_CA, "cert": CA_PEM}))
    args = {"ca": "mcp-test-csr-ca", "certificate": CA_PEM}
    async with Client(server()) as c:
        p = await run(c, "fmc_install_internal_ca_cert", args)
        assert p["status"] == "preview" and p["preview"]["certificates_in_chain"] == 1
        assert CA_PEM.strip() not in json.dumps(p)  # the preview shows the fingerprint, not the PEM
        await run(c, "fmc_install_internal_ca_cert", {**args, "confirm": p["confirm"]})
        done = await run(c, "fmc_install_internal_ca_cert", {**args, "ca": "mcp-test-resign-ca"})
        assert done["status"] == "blocked" and "already has a certificate" in done["blockers"][0]
        with pytest.raises(ToolError, match="private key"):
            await run(c, "fmc_install_internal_ca_cert", {**args, "certificate": CA_PEM + KEY})
    body = json.loads(put.calls.last.request.content)
    assert body["id"] == CSR_CA["id"] and body["type"] == "InternalCA" and "BEGIN CERTIFICATE" in body["cert"]


def pki_dir(tmp_path: Path, key: str = KEY) -> Path:
    d = tmp_path / "pki"
    d.mkdir()
    (d / "ca.crt").write_text(CA_PEM)
    (d / "ca.key").write_text(key)
    os.chmod(d / "ca.key", 0o600)
    (d / "ca.pass").write_text("not-a-real-passphrase\n")
    return d


async def test_import_files_never_shows_the_key(fmc: respx.MockRouter, tmp_path: Path) -> None:
    d = pki_dir(tmp_path)
    fmc.get(CAS).mock(return_value=items([CSR_CA]))
    post = fmc.post(CAS).mock(return_value=httpx.Response(201, json={"id": CA["id"]}))
    fmc.get(f"{CAS}/{CA['id']}").mock(return_value=httpx.Response(200, json=CA))
    args = {"kind": "internal_ca", "name": "mcp-fw-resign-ca", "cert_file": "ca.crt", "key_file": "ca.key"}
    async with Client(server(pki_dir=d)) as c:
        p = await run(c, "fmc_import_certificate_files", args)
        assert p["status"] == "preview"
        assert (
            p["preview"]["sha1_fingerprint"] == CA["certFingerprint"] and p["preview"]["key"] == "PRIVATE KEY"
        )
        assert KEY_BODY not in json.dumps(p)
        out = await run(c, "fmc_import_certificate_files", {**args, "confirm": p["confirm"]})
    assert KEY_BODY not in json.dumps(out)
    req = post.calls.last.request
    body = json.loads(req.content)
    assert req.url.params["isCSR"] == "false"
    assert body["privateKey"] == KEY and body["type"] == "InternalCA" and "passPhrase" not in body
    assert out["result"]["name"] == "mcp-test-resign-ca"


async def test_import_internal_cert_with_passphrase_and_changed_file(
    fmc: respx.MockRouter, tmp_path: Path
) -> None:
    d = pki_dir(tmp_path, ENC_KEY)
    os.chmod(d / "ca.pass", 0o644)
    fmc.get(CERTS).mock(return_value=items([]))
    post = fmc.post(CERTS).mock(return_value=httpx.Response(201, json={"id": WEB["id"]}))
    fmc.get(f"{CERTS}/{WEB['id']}").mock(return_value=httpx.Response(200, json=WEB))
    args = {"kind": "internal_cert", "name": "web", "cert_file": "ca.crt", "key_file": "ca.key"}
    async with Client(server(pki_dir=d)) as c:
        blocked = await run(c, "fmc_import_certificate_files", args)
        assert blocked["status"] == "blocked" and "passphrase_file" in blocked["blockers"][0]
        args["passphrase_file"] = "ca.pass"
        p = await run(c, "fmc_import_certificate_files", args)
        assert p["preview"]["key"] == "ENCRYPTED PRIVATE KEY (encrypted)"
        assert any("ca.pass" in w for w in p["preview"]["warnings"])
        assert "not-a-real-passphrase" not in json.dumps(p)
        (d / "ca.key").write_text(ENC_KEY + "\n")  # the file changes between preview and confirm
        with pytest.raises(ToolError):
            await run(c, "fmc_import_certificate_files", {**args, "confirm": p["confirm"]})
        assert not post.called
        p = await run(c, "fmc_import_certificate_files", args)
        await run(c, "fmc_import_certificate_files", {**args, "confirm": p["confirm"]})
    body = json.loads(post.calls.last.request.content)
    assert body["passPhrase"] == "not-a-real-passphrase" and body["type"] == "InternalCertificate"
    assert "isCSR" not in post.calls.last.request.url.params


@pytest.mark.parametrize(
    ("kw", "args", "match"),
    [
        ({}, {"cert_file": "ca.crt", "key_file": "ca.key"}, "FMC_PKI_DIR"),
        ({"pki": True}, {"cert_file": "../ca.crt", "key_file": "ca.key"}, "outside FMC_PKI_DIR"),
        ({"pki": True}, {"cert_file": "missing.crt", "key_file": "ca.key"}, "No file"),
        ({"pki": True}, {"cert_file": "ca.key", "key_file": "ca.key"}, "contains a private key"),
        ({"pki": True}, {"cert_file": "ca.crt", "key_file": "ca.crt"}, "exactly one PEM private key"),
    ],
)
async def test_import_refusals(
    fmc: respx.MockRouter, tmp_path: Path, kw: dict[str, Any], args: dict[str, Any], match: str
) -> None:
    d = pki_dir(tmp_path)
    (tmp_path / "ca.crt").write_text(CA_PEM)
    fmc.get(CAS).mock(return_value=items([]))
    settings = {"pki_dir": d} if kw.get("pki") else {}
    async with Client(server(**settings)) as c:
        with pytest.raises(ToolError, match=match):
            await run(c, "fmc_import_certificate_files", {"kind": "internal_ca", "name": "x", **args})


async def test_delete_certificate_blocked_while_used(fmc: respx.MockRouter) -> None:
    mock_catalog(fmc)
    delete = fmc.delete(f"{CAS}/{CSR_CA['id']}").mock(return_value=httpx.Response(200, json=CSR_CA))
    async with Client(server()) as c:
        used = await run(c, "fmc_delete_certificate", {"certificate": "mcp-test-resign-ca"})
        assert used["status"] == "blocked" and "resign-outbound" in used["blockers"][0]
        system = await run(c, "fmc_delete_certificate", {"certificate": "Cisco-Licensing-Root-CA"})
        assert "Read-only system certificate." in system["blockers"]
        p = await run(c, "fmc_delete_certificate", {"certificate": "mcp-test-csr-ca", "kind": "internal_ca"})
        await run(
            c,
            "fmc_delete_certificate",
            {"certificate": "mcp-test-csr-ca", "kind": "internal_ca", "confirm": p["confirm"]},
        )
    assert delete.called

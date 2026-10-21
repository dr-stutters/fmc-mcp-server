"""F71: fmc_list_certificates (device enrolments, internal certificates and CAs, trusted CAs, external
certificates) with days_left, a severity and the three date encodings FMC uses."""

import copy
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from fmc_mcp.server import create_server
from fmc_mcp.tools.certificates import COLLECTIONS, bundled, cert_date, days_until, device_rows, severity

from .conftest import CFG, empty, fixture, items, make_settings

FX = fixture("certificates")
DEV_CERTS = f"{CFG}/devices/certificates"
INTERNAL = f"{CFG}/object/internalcertificates"
INTERNAL_CAS = f"{CFG}/object/internalcas"
TRUSTED = f"{CFG}/object/externalcacertificates"
EXTERNAL = f"{CFG}/object/externalcertificates"
DEVICES = f"{CFG}/devices/devicerecords"
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def server() -> Any:
    return create_server(make_settings())


async def run(c: Client[Any], args: dict[str, Any]) -> Any:
    r = await c.call_tool("fmc_list_certificates", {"response_format": "json", **args})
    return r.structured_content if r.structured_content is not None else json.loads(r.content[0].text)  # type: ignore[union-attr]


def in_days(n: float) -> str:
    return (datetime.now(UTC) + timedelta(days=n)).strftime("%Y-%m-%dT%H:%M:%SZ")


def mock_all(fmc: respx.MockRouter, *, devices: dict[str, Any] | None = None, **over: Any) -> None:
    fmc.get(DEV_CERTS).mock(return_value=httpx.Response(200, json=devices or FX["device_certificates_empty"]))
    fmc.get(INTERNAL).mock(
        return_value=httpx.Response(200, json=over.get("internal", FX["internal_certificates"]))
    )
    fmc.get(INTERNAL_CAS).mock(return_value=over.get("internal_cas", empty()))
    fmc.get(TRUSTED).mock(return_value=httpx.Response(200, json=over.get("trusted", FX["trusted_cas"])))
    fmc.get(EXTERNAL).mock(return_value=httpx.Response(200, json=FX["external_certificates_empty"]))
    fmc.get(DEVICES).mock(return_value=httpx.Response(200, json=FX["devicerecords"]))


# --- dates, severity, bundled -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2034-10-27T09:01Z", datetime(2034, 10, 27, 9, 1, tzinfo=UTC)),  # device enrolment, no seconds
        ("2034-10-27T09:01:09Z", datetime(2034, 10, 27, 9, 1, 9, tzinfo=UTC)),
        ("2028-10-18T02:48:52Z", datetime(2028, 10, 18, 2, 48, 52, tzinfo=UTC)),  # internal certificate
        ("Jan  1 00:00:00 2030 GMT", datetime(2030, 1, 1, tzinfo=UTC)),  # trusted CA, OpenSSL text
        (1730881490, datetime(2024, 11, 6, 8, 24, 50, tzinfo=UTC)),  # device enrolment, epoch seconds
        ("1730881490", datetime(2024, 11, 6, 8, 24, 50, tzinfo=UTC)),
        (1730881490000, datetime(2024, 11, 6, 8, 24, 50, tzinfo=UTC)),  # milliseconds
        (0, None),  # FMC: not applicable
        ("0", None),
        ("", None),
        (None, None),
        (True, None),
        ("soon", None),
    ],
)
def test_cert_date_encodings(value: Any, expected: datetime | None) -> None:
    assert cert_date(value) == expected


def test_severity_thresholds() -> None:
    assert [severity(d) for d in (-5, 0, 30, 31, 90, 91, None)] == [
        "critical",
        "critical",
        "critical",
        "warning",
        "warning",
        "ok",
        "unknown",
    ]
    assert days_until(NOW + timedelta(hours=1), NOW) == 0
    assert days_until(NOW - timedelta(hours=1), NOW) == -1  # expired an hour ago
    assert days_until(None, NOW) is None


def test_bundled_roots_in_a_leaf_domain() -> None:
    comodo, lab_ca, fnmt = FX["trusted_cas"]["items"]
    # FMC 10.0.1 in a child domain: every Global object read-only with no reason; the id decides
    assert bundled(comodo) and bundled(fnmt) and not bundled(lab_ca)
    assert bundled({**lab_ca, "metadata": {"readOnly": {"state": True, "reason": "SYSTEM"}}})
    # DOMAIN (inherited) and RBAC (an API user without write rights) say nothing about the object: the id
    # still decides, so a read-only user's listing keeps the lab CA and still hides the bundled roots.
    for reason in ("DOMAIN", "RBAC"):
        ro = {"metadata": {"readOnly": {"state": True, "reason": reason}}}
        assert bundled({**comodo, **ro}) and bundled({**fnmt, **ro}), reason
        assert not bundled({**lab_ca, **ro}), reason
    assert not bundled({**comodo, "metadata": {}})
    assert not bundled({"id": "not-a-uuid", "metadata": {"readOnly": {"state": True}}})


def test_device_rows_both_spec_shapes() -> None:
    names = {"4ff46228-70ac-11ef-b9e1-9bf082619052": "mcp-test-ftd-a"}
    nested, inline = FX["device_certificates"]["items"]
    rows = device_rows(nested, names, NOW)
    assert [r["name"] for r in rows] == ["test-cert-1", "test-cert-2"]
    assert rows[0]["device"] == "mcp-test-ftd-a" and rows[0]["id"] == "0050568C-F0AE-0ed3-0000-012884901940"
    assert rows[0]["expires"] == "2034-10-27T09:01:00Z" and rows[0]["severity"] == "ok"
    assert rows[0]["enrollment_type"] == "PKCS12" and rows[0]["deployment"] == "SUCCESS"
    rows = device_rows(inline, names, NOW)
    expired, later = rows
    assert expired["device"] == "d9b0ef62-3921-11ef-b2a5-e9c9e2e20bd3"  # no name known: the UUID
    assert expired["identity_expires"] == "2024-11-06T08:24:50Z" and "ca_expires" not in expired
    assert expired["expired"] is True and expired["severity"] == "critical" and expired["days_left"] < 0
    assert later["identity_expires"] == "2034-10-15T08:31:14Z" and later["severity"] == "ok"


def test_device_row_problems_and_earliest_expiry() -> None:
    item = {
        "id": "dev-1",
        "enrolledCertificates": [
            {
                "name": "ravpn-id",
                "enrollmentType": "SCEP",
                "deploymentStatus": "FAILED",
                "errorMessage": "CA unreachable",
                "identityCertificateStatus": "PENDING",
                "caCertificateStatus": "AVAILABLE",
                "isOutdated": True,
                "identityCertExpiryDate": "2034-10-27T09:01Z",
                "caCertExpiryDate": (NOW + timedelta(days=60)).strftime("%Y-%m-%dT%H:%MZ"),
            },
            {"name": "pending", "identityCertificateStatus": "IN_PROGRESS"},
        ],
    }
    failed, pending = device_rows(item, {}, NOW)
    assert failed["expiring"] == "ca" and failed["days_left"] == 60 and failed["severity"] == "warning"
    assert failed["problems"] == [
        "deployment FAILED: CA unreachable",
        "identity certificate PENDING",
        "outdated (the enrolment object changed; re-enrol)",
    ]
    assert pending["severity"] == "unknown" and "problems" not in pending
    ok_but_failed = device_rows(
        {"id": "d", "enrolledCertificates": [{**item["enrolledCertificates"][0], "caCertExpiryDate": 0}]},
        {},
        NOW,
    )[0]
    assert ok_but_failed["days_left"] > 90 and ok_but_failed["severity"] == "warning"  # problems lift ok


# --- the tool -----------------------------------------------------------------------------------------


async def test_lists_every_kind_hides_bundled_roots(fmc: respx.MockRouter) -> None:
    mock_all(fmc)
    async with Client(server()) as c:
        out = await run(c, {})
    names = [r["name"] for r in out["results"]]
    assert names == ["mcp-fw-fmc-pxgrid2", "mcp-test-lab-CA"]  # soonest first; both ok
    pxgrid, lab = out["results"]
    assert pxgrid["kind"] == "internal" and pxgrid["expires"] == "2028-10-18T02:48:52Z"
    assert pxgrid["subject"] == "fmc.example.com" and pxgrid["issuer"] == "example-CA"
    assert pxgrid["domain"] == "Global" and pxgrid["severity"] == "ok"
    assert lab["kind"] == "trusted_ca" and lab["expires"] == "2036-10-17T01:04:19Z" and "bundled" not in lab
    assert out["bundled_roots_hidden"] == 2 and out["severity"] == {"ok": 2}
    assert "unavailable" not in out
    text = json.dumps(out)
    assert "********" not in text and "privateKey" not in text and "BEGIN CERTIFICATE" not in text


async def test_read_only_api_user_still_sees_the_lab_ca(fmc: respx.MockRouter) -> None:
    """An API user without write rights gets every object read-only with reason RBAC: the custom CA
    must stay listed (it is the one LDAPS / ISE trust depends on), the bundled roots stay hidden."""
    trusted = copy.deepcopy(FX["trusted_cas"])
    for c in trusted["items"]:
        c["metadata"]["readOnly"] = {"state": True, "reason": "RBAC"}
    mock_all(fmc, trusted=trusted)
    async with Client(server()) as c:
        out = await run(c, {"kind": "trusted_ca"})
    assert [r["name"] for r in out["results"]] == ["mcp-test-lab-CA"]
    assert out["bundled_roots_hidden"] == 2


async def test_include_bundled_and_kind(fmc: respx.MockRouter) -> None:
    mock_all(fmc)
    async with Client(server()) as c:
        out = await run(c, {"kind": "trusted_ca", "include_bundled": True})
    rows = {r["name"]: r for r in out["results"]}
    assert set(rows) == {
        "COMODO-ECC-Certification-Authority",
        "mcp-test-lab-CA",
        "C_ES-O_FNMT-RCM-OU_AC-RAIZ-FNMT-RCM",
    }
    fnmt = rows["C_ES-O_FNMT-RCM-OU_AC-RAIZ-FNMT-RCM"]
    assert fnmt["bundled"] is True and fnmt["subject"] == "FNMT-RCM"  # no CN: the organisation
    assert fnmt["expires"] == "2030-01-01T00:00:00Z"
    assert out["results"][0]["name"] == "C_ES-O_FNMT-RCM-OU_AC-RAIZ-FNMT-RCM"  # 2030 before 2036 and 2038
    assert "bundled_roots_hidden" not in out
    assert not any("internalcertificates" in str(call.request.url) for call in fmc.calls)


async def test_bundled_root_quirks_recorded_live(fmc: respx.MockRouter) -> None:
    """live-B2's raw reads of two bundled roots (trusted_cas_quirks): the double-space OpenSSL date parses,
    FMC's damaged subject fields pass through as FMC has them (mojibake, cut at a comma) because these rows
    carry no PEM (with one the names come from it: test_cert_names), an empty CN falls back to the
    organisation, and a metadata.domain without an id still names the domain."""
    netlock, secom = FX["trusted_cas_quirks"]["items"]
    assert (
        netlock["validityEndDate"] == "Dec  6 15:08:21 2028 GMT" and "id" not in secom["metadata"]["domain"]
    )
    trusted = copy.deepcopy(FX["trusted_cas"])
    trusted["items"] += [netlock, secom]
    mock_all(fmc, trusted=trusted)
    async with Client(server()) as c:
        hidden = await run(c, {"kind": "trusted_ca"})
        out = await run(c, {"kind": "trusted_ca", "include_bundled": True})
    assert [r["name"] for r in hidden["results"]] == ["mcp-test-lab-CA"] and hidden[
        "bundled_roots_hidden"
    ] == 4
    rows = {r["name"]: r for r in out["results"]}
    nl = rows[netlock["name"]]
    assert nl["expires"] == "2028-12-06T15:08:21Z" and nl["severity"] != "unknown"
    assert (
        nl["subject"] == netlock["subjectCommonName"] and nl["bundled"] is True and nl["domain"] == "Global"
    )
    sc = rows[secom["name"]]
    assert sc["subject"] == "SECOM Trust Systems CO." and sc["issuer"] == "SECOM Trust Systems CO."
    assert sc["expires"] == "2029-05-29T05:00:39Z" and sc["bundled"] is True and sc["domain"] == "Global"


async def test_expiring_within_days_and_severity(fmc: respx.MockRouter) -> None:
    internal = copy.deepcopy(FX["internal_certificates"])
    soon = internal["items"][0]
    internal["items"] = [
        {**soon, "name": "mcp-test-expired", "validityEndDate": in_days(-2.5)},
        {**soon, "name": "mcp-test-20d", "validityEndDate": in_days(20.5)},
        {**soon, "name": "mcp-test-60d", "validityEndDate": in_days(60.5)},
        soon,  # 2028: outside 90 days
    ]
    trusted = copy.deepcopy(FX["trusted_cas"])
    trusted["items"][0]["validityEndDate"] = (datetime.now(UTC) + timedelta(days=10)).strftime(
        "%b %d %H:%M:%S %Y GMT"
    )  # a bundled root due soon: counted, not listed
    mock_all(fmc, internal=internal, trusted=trusted)
    async with Client(server()) as c:
        out = await run(c, {"expiring_within_days": 90})
    got = [(r["name"], r["severity"], r["days_left"]) for r in out["results"]]
    assert got == [
        ("mcp-test-expired", "critical", -3),
        ("mcp-test-20d", "critical", 20),
        ("mcp-test-60d", "warning", 60),
    ]
    assert out["results"][0]["expired"] is True
    assert out["severity"] == {"critical": 2, "warning": 1}
    assert out["bundled_roots_hidden"] == 2 and out["bundled_roots_expiring"] == 1


async def test_nothing_due(fmc: respx.MockRouter) -> None:
    mock_all(fmc)
    async with Client(server()) as c:
        out = await run(c, {"expiring_within_days": 30})
    assert out["results"] == [] and out["severity"] == "none"
    assert out["note"] == "No certificate expires within 30 days."


async def test_device_certificates_named_and_filtered(fmc: respx.MockRouter) -> None:
    mock_all(fmc, devices=FX["device_certificates"])
    async with Client(server()) as c:
        out = await run(c, {"kind": "device"})
        rows = out["results"]
        assert [r["name"] for r in rows] == [
            "selfsigned3renamed",
            "selfsigned2",
            "test-cert-1",
            "test-cert-2",
        ]
        assert rows[0]["device"] == "mcp-test-ftd-b" and rows[0]["severity"] == "critical"
        assert {r["device"] for r in rows} == {"mcp-test-ftd-a", "mcp-test-ftd-b"}
        one = await run(c, {"device": "mcp-test-ftd-a"})
        assert {r["device"] for r in one["results"]} == {"mcp-test-ftd-a"} and len(one["results"]) == 2
        by_id = await run(c, {"device": "D9B0EF62-3921-11ef-b2a5-e9c9e2e20bd3"})
        assert [r["name"] for r in by_id["results"]] == ["selfsigned3renamed", "selfsigned2"]
    # device certificates are filtered here: FMC's own filter is never sent
    assert all(
        "filter" not in str(call.request.url) for call in fmc.calls if "certificates" in str(call.request.url)
    )
    assert not any("internalcertificates" in str(call.request.url) for call in fmc.calls)


async def test_device_with_other_kind_refused_and_unknown_device(fmc: respx.MockRouter) -> None:
    mock_all(fmc, devices=FX["device_certificates"])
    async with Client(server()) as c:
        with pytest.raises(ToolError, match="device certificates only"):
            await run(c, {"device": "mcp-test-ftd-a", "kind": "trusted_ca"})
        with pytest.raises(ToolError, match="No device named"):
            await run(c, {"device": "mcp-test-nope"})


async def test_a_missing_collection_is_reported_not_fatal(fmc: respx.MockRouter) -> None:
    mock_all(fmc)
    fmc.get(EXTERNAL).mock(
        return_value=httpx.Response(404, json={"error": {"messages": [{"description": "nope"}]}})
    )
    async with Client(server()) as c:
        out = await run(c, {})
    assert len(out["results"]) == 2
    assert len(out["unavailable"]) == 1 and out["unavailable"][0].startswith("external certificates:")


async def test_internal_cas_listed_with_csr_pending(fmc: respx.MockRouter) -> None:
    pki = fixture("decryption_pki")
    mock_all(fmc, internal_cas=items([pki["internal_ca"], pki["internal_ca_csr"]]))
    async with Client(server()) as c:
        out = await run(c, {"kind": "internal_ca"})
    rows = {r["name"]: r for r in out["results"]}
    assert rows["mcp-test-resign-ca"]["expires"] == "2036-10-13T01:31:15Z"
    assert rows["mcp-test-csr-ca"]["csr_pending"] is True and rows["mcp-test-csr-ca"]["severity"] == "unknown"


async def test_markdown_header_has_counts(fmc: respx.MockRouter) -> None:
    mock_all(fmc)
    async with Client(server()) as c:
        r = await c.call_tool("fmc_list_certificates", {})
    text = r.content[0].text  # type: ignore[union-attr]
    assert "bundled_roots_hidden: 2" in text and "mcp-test-lab-CA" in text


def test_collections_cover_the_scope() -> None:
    assert {c.path for c in COLLECTIONS.values()} == {
        "devices/certificates",
        "object/internalcertificates",
        "object/internalcas",
        "object/externalcacertificates",
        "object/externalcertificates",
    }

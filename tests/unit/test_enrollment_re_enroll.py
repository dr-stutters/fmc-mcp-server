"""fmc_enroll_certificate(action='re_enroll') preview wording (F75 #170, W6N live-A finding).

Recorded live on FMC 10.0.1 / mcp-ftd1 (notes/w6n-fixtures/f75-live-enrollment.json): RE_ENROLL of a
self-signed enrollment re-issued the certificate on the same key (serial 6ad8b2ab -> 6ad8b2ac, new validity,
SHA1 public key hash unchanged). The preview said "the device generates key pair ...".
"""

import copy

import httpx
import respx
from fastmcp import Client

from .test_enrollment import DEV_CERTS, ENR, ENROL, FX, SELF, device_and_enrollment, no_users, run, server


async def preview(fmc: respx.MockRouter, action: str) -> list[str]:
    no_users(fmc)
    fmc.get(DEV_CERTS).mock(return_value=httpx.Response(200, json=FX["device_enrolled"]))
    async with Client(server()) as c:
        out = await run(c, "fmc_enroll_certificate", {**ENROL, "action": action})
    assert out["status"] == "preview", out
    effects: list[str] = out["side_effects"]
    return effects


async def test_re_enroll_self_signed_keeps_the_key(fmc: respx.MockRouter) -> None:
    device_and_enrollment(fmc)
    first = (await preview(fmc, "re_enroll"))[0]
    assert first.startswith("Enrols mcp-w6-enr-probe on mcp-ftd1 again, replacing the device's certificate")
    assert "a new self-signed identity certificate (new serial and validity)" in first
    assert (
        "key pair mcp-w6-enr-probe-key (RSA 2048) the device already holds: the key is not regenerated"
        in first
    )
    assert "generates" not in first


async def test_enroll_still_says_the_device_generates_the_key(fmc: respx.MockRouter) -> None:
    device_and_enrollment(fmc)
    no_users(fmc)
    fmc.get(DEV_CERTS).mock(return_value=httpx.Response(200, json=FX["device_certificates_empty"]))
    async with Client(server()) as c:
        out = await run(c, "fmc_enroll_certificate", ENROL)
    assert "the device generates key pair mcp-w6-enr-probe-key (RSA 2048)" in out["side_effects"][0]


async def test_re_enroll_scep_makes_no_claim_about_the_key(fmc: respx.MockRouter) -> None:
    scep = copy.deepcopy(SELF)
    scep["enrollmentType"] = "SCEP"
    scep["scepContent"] = {"enrollmentUrl": "http://198.51.100.20/certsrv/mscep/mscep.dll"}
    device_and_enrollment(fmc)
    fmc.get(f"{ENR}/{SELF['id']}").mock(return_value=httpx.Response(200, json=scep))
    first = (await preview(fmc, "re_enroll"))[0]
    assert (
        "the device requests a new certificate for key pair mcp-w6-enr-probe-key (RSA 2048) from "
        "http://198.51.100.20/certsrv/mscep/mscep.dll" in first
    )
    assert "generates" not in first and "not regenerated" not in first

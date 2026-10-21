"""Show-command redaction keeps public key data (W6N live-A, found in the F75 #170 proof).

`fmc_run_show_command('show crypto ca certificates')` on mcp-ftd1 (FTD 10.0) answered
'Public Key ******** RSA (2048 bits)' and "redacted: 2 secret value(s)": the secret pattern took the word
after 'Key' in 'Public Key Type:' for a secret. The output below is the FTD's format with the values live-A
recorded (the certificate serial replaced).
"""

import httpx
import respx
from fastmcp import Client

from fmc_mcp.server import create_server
from fmc_mcp.tools.troubleshoot import redact

from .conftest import CFG, fixture, items, make_settings

DEV = fixture("ftd_device")
DEVPATH = f"{CFG}/devices/devicerecords/{DEV['id']}"

CA_CERTIFICATES = """Certificate
  Status: Available
  Certificate Serial Number: 1a2b3c4d
  Certificate Usage: General Purpose
  Public Key Type: RSA (2048 bits)
  Signature Algorithm: SHA256 with RSA Encryption
  Issuer Name:
    cn=mcp-ftd1.example.com
    o=mcp-w6
  Subject Name:
    cn=mcp-ftd1.example.com
    o=mcp-w6
  Validity Date:
    start date: 17:33:48 UTC Oct 21 2026
    end   date: 17:33:48 UTC Oct 18 2036
  Storage: config
  Associated Trustpoints: mcp-w6-enr-self
"""

MYPUBKEY = """Key pair was generated at: 17:32:25 UTC Oct 21 2026
Key name: mcp-w6-enr-self
 Usage: General Purpose Key
 Modulus Size (bits): 2048
 Storage: config
 Key Data:

  30820122 300d0609 2a864886 f70d0101 01050003 82010f00 3082010a 02820101
"""


def test_certificate_and_public_key_lines_are_not_secrets() -> None:
    for text in (CA_CERTIFICATES, MYPUBKEY):
        out, n = redact(text)
        assert n == 0 and out == text, out


def test_secrets_next_to_key_labels_are_still_masked() -> None:
    text = (
        "Public Key Type: RSA (2048 bits)\n"
        " ospf message-digest-key 1 md5 k3y0spf\n"
        "failover key hex 0a1b2c3d\n"
        "Usage: General Purpose Key\n"
        "snmp-server host inside 192.0.2.9 community s3cr3t version 2c\n"
        " Key Data:\n"
    )
    out, n = redact(text)
    assert n == 3
    for secret in ("k3y0spf", "0a1b2c3d", "s3cr3t"):
        assert secret not in out
    assert "Public Key Type: RSA (2048 bits)" in out and "General Purpose Key\n" in out
    assert "failover key hex ********" in out and " Key Data:" in out


async def test_show_crypto_ca_certificates_through_the_tool(fmc: respx.MockRouter) -> None:
    fmc.get(f"{CFG}/devices/devicerecords").mock(return_value=items([DEV]))
    fmc.get(DEVPATH).mock(return_value=httpx.Response(200, json=DEV))
    fmc.get(f"{DEVPATH}/operational/commands").mock(
        return_value=items([{"commandOutput": CA_CERTIFICATES, "type": "command"}])
    )
    async with Client(create_server(make_settings())) as c:
        r = await c.call_tool(
            "fmc_run_show_command", {"device": "mcp-ftd1", "command": "show crypto ca certificates"}
        )
    out = r.structured_content
    assert out is not None
    assert "Public Key Type: RSA (2048 bits)" in out["output"] and "redacted" not in out

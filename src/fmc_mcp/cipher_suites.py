"""TLS cipher suites as FMC's cipher suite list objects take them (F82).

FMC stores a cipher suite list (object/ciphersuitelists) as literals {"name": <IANA name>, "value":
<decimal code>} picked from its own predefined set. A literal it doesn't know fails the whole POST with
400 "Not saved. The SHA is incorrect.", which names nothing, so the tools check literals against this
table first and name the bad ones.

`fmc` records what FMC 10.0.1 did with the literal on a live POST (the ftd-tls-cipher-policy lab,
2026-10-21): "accepted", "refused", or None (not tried yet: the tools warn, and name these suites if FMC
refuses the list)."""

from dataclasses import dataclass
from typing import Literal

FmcStatus = Literal["accepted", "refused"] | None


@dataclass(frozen=True)
class Suite:
    code: int  # IANA value, e.g. 47 (0x002F)
    name: str  # IANA name, e.g. TLS_RSA_WITH_AES_128_CBC_SHA
    weak: str | None  # why it is weak; None = forward secrecy with an AEAD cipher
    fmc: FmcStatus = None

    def literal(self) -> dict[str, str]:
        return {"name": self.name, "value": str(self.code)}


RSA_KX = "RSA key exchange (no forward secrecy)"
CBC_SHA1 = "CBC with SHA-1"
SUITES: tuple[Suite, ...] = (
    # NULL, EXPORT, DES, RC4: broken
    Suite(1, "TLS_RSA_WITH_NULL_MD5", "NULL (no encryption)"),
    Suite(2, "TLS_RSA_WITH_NULL_SHA", "NULL (no encryption)", "accepted"),
    Suite(59, "TLS_RSA_WITH_NULL_SHA256", "NULL (no encryption)", "accepted"),
    Suite(3, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "EXPORT (40-bit)", "accepted"),
    Suite(8, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXPORT (40-bit)", "accepted"),
    Suite(9, "TLS_RSA_WITH_DES_CBC_SHA", "DES (56-bit)", "accepted"),
    Suite(4, "TLS_RSA_WITH_RC4_128_MD5", "RC4", "accepted"),
    Suite(5, "TLS_RSA_WITH_RC4_128_SHA", "RC4", "accepted"),
    Suite(49169, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "RC4", "accepted"),
    Suite(49159, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "RC4"),
    # 3DES (Sweet32)
    Suite(10, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "3DES", "accepted"),
    Suite(22, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "3DES", "accepted"),
    Suite(49170, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "3DES", "accepted"),
    Suite(49160, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "3DES"),
    # anonymous (no server authentication): not among FMC 10.0.1's suites (refused as TLS_DH_anon_ and
    # TLS_DH_ANON_ alike)
    Suite(52, "TLS_DH_anon_WITH_AES_128_CBC_SHA", "anonymous (no server authentication)", "refused"),
    Suite(58, "TLS_DH_anon_WITH_AES_256_CBC_SHA", "anonymous (no server authentication)", "refused"),
    # RSA key exchange
    Suite(47, "TLS_RSA_WITH_AES_128_CBC_SHA", RSA_KX, "accepted"),
    Suite(53, "TLS_RSA_WITH_AES_256_CBC_SHA", RSA_KX, "accepted"),
    Suite(60, "TLS_RSA_WITH_AES_128_CBC_SHA256", RSA_KX, "accepted"),
    Suite(61, "TLS_RSA_WITH_AES_256_CBC_SHA256", RSA_KX, "accepted"),
    Suite(156, "TLS_RSA_WITH_AES_128_GCM_SHA256", RSA_KX, "accepted"),
    Suite(157, "TLS_RSA_WITH_AES_256_GCM_SHA384", RSA_KX, "accepted"),
    # forward secrecy, but CBC with SHA-1
    Suite(51, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", CBC_SHA1, "accepted"),
    Suite(57, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", CBC_SHA1, "accepted"),
    Suite(49161, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", CBC_SHA1, "accepted"),
    Suite(49162, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", CBC_SHA1, "accepted"),
    Suite(49171, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", CBC_SHA1, "accepted"),
    Suite(49172, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", CBC_SHA1, "accepted"),
    # forward secrecy, CBC with SHA-2 (legacy, not in the weak preset)
    Suite(103, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "CBC (legacy)"),
    Suite(107, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "CBC (legacy)"),
    Suite(49187, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "CBC (legacy)"),
    Suite(49188, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "CBC (legacy)"),
    Suite(49191, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "CBC (legacy)"),
    Suite(49192, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "CBC (legacy)"),
    # strong: forward secrecy with AES-GCM or ChaCha20-Poly1305
    Suite(158, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", None),
    Suite(159, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", None),
    Suite(49195, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", None),
    Suite(49196, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", None),
    Suite(49199, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", None),
    Suite(49200, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", None),
    Suite(52392, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", None),
    Suite(52393, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", None),
    Suite(52394, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", None),
    # TLS 1.3
    Suite(4865, "TLS_AES_128_GCM_SHA256", None),
    Suite(4866, "TLS_AES_256_GCM_SHA384", None),
    Suite(4867, "TLS_CHACHA20_POLY1305_SHA256", None),
)
BY_NAME = {s.name.upper(): s for s in SUITES}
BY_CODE = {s.code: s for s in SUITES}
# The weak preset: the 17 suites (RSA key exchange, CBC with SHA-1, 3DES, RC4) FMC 10.0.1 accepted in the
# ftd-tls-cipher-policy lab's tls-weak-ciphers list, in that order, then the NULL, EXPORT, DES and RC4-MD5
# suites a later probe showed it accepts. The anonymous suites are left out: FMC refuses them.
WEAK_CODES = (
    *(5, 10, 47, 53, 60, 61, 156, 157, 22, 51, 57, 49161, 49162, 49169, 49170, 49171, 49172),
    *(2, 59, 3, 8, 9, 4),
)
PRESETS: dict[str, tuple[Suite, ...]] = {"weak": tuple(BY_CODE[c] for c in WEAK_CODES)}


def find_suite(ref: str) -> Suite | None:
    """A suite by IANA name (case-insensitive; an OpenSSL-era 'SSL_' prefix is read as 'TLS_'), decimal
    code ('47') or hex code ('0x002F', '0x00,0x2F')."""
    v = ref.strip()
    if not v:
        return None
    up = v.upper()
    if up.startswith("SSL_"):
        up = "TLS_" + up[4:]
    if up in BY_NAME:
        return BY_NAME[up]
    try:
        code = int(up.replace(",0X", "").replace(",", ""), 16) if up.startswith("0X") else int(up)
    except ValueError:
        return None
    return BY_CODE.get(code)


def suite_of_literal(lit: dict[str, object]) -> Suite | None:
    """The table's suite for a literal FMC returned, by code (FMC's `value`) or name."""
    try:
        return BY_CODE.get(int(str(lit.get("value"))))
    except ValueError:
        return find_suite(str(lit.get("name") or ""))

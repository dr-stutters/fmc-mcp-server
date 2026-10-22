"""TLS cipher suites as FMC's cipher suite list objects take them (F82).

FMC stores a cipher suite list (object/ciphersuitelists) as literals {"name": <IANA name>, "value":
<decimal code>} picked from its own predefined set. A literal it doesn't know fails the whole POST with
400 "Not saved. The SHA is incorrect.", which names nothing, so the tools check literals against this
table first and name the bad ones.

`fmc` records what FMC 10.0.1 did with the literal on a live POST (the ftd-tls-cipher-policy lab,
2026-10-21): "accepted", "refused", or None (not tried yet: the tools warn, and name these suites if FMC
refuses the list).

`resign` records what FTD 10.0 did to the suite under a Decrypt - Resign rule in the same lab's step-up
experiments (FTDv 10.0.0, 2026-10-22; Cookbook recipe README, "Step-up experiments"): "decrypted" (forwarded
in the ClientHello and decrypted unchanged), "stripped" (removed from the ClientHello FTD forwards to the
server, so the server falls back to another suite the client offered), or None (not tried). Stripping a weak
suite looks like a step-up; stripping a strong one (TLS 1.2 ChaCha20, AES-CCM, ARIA) is a downgrade."""

import re
from dataclasses import dataclass
from typing import Literal

FmcStatus = Literal["accepted", "refused"] | None
ResignStatus = Literal["decrypted", "stripped"] | None


@dataclass(frozen=True)
class Suite:
    code: int  # IANA value, e.g. 47 (0x002F)
    name: str  # IANA name, e.g. TLS_RSA_WITH_AES_128_CBC_SHA
    weak: str | None  # why it is weak; None = forward secrecy with an AEAD cipher
    fmc: FmcStatus = None
    resign: ResignStatus = None

    def literal(self) -> dict[str, str]:
        return {"name": self.name, "value": str(self.code)}


RSA_KX = "RSA key exchange (no forward secrecy)"
CBC_SHA1 = "CBC with SHA-1"
SUITES: tuple[Suite, ...] = (
    # NULL, EXPORT, DES, RC4: broken
    Suite(1, "TLS_RSA_WITH_NULL_MD5", "NULL (no encryption)"),
    Suite(2, "TLS_RSA_WITH_NULL_SHA", "NULL (no encryption)", "accepted", "stripped"),
    Suite(59, "TLS_RSA_WITH_NULL_SHA256", "NULL (no encryption)", "accepted"),
    Suite(3, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "EXPORT (40-bit)", "accepted"),
    Suite(8, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "EXPORT (40-bit)", "accepted"),
    Suite(9, "TLS_RSA_WITH_DES_CBC_SHA", "DES (56-bit)", "accepted"),
    Suite(4, "TLS_RSA_WITH_RC4_128_MD5", "RC4", "accepted", "stripped"),
    Suite(5, "TLS_RSA_WITH_RC4_128_SHA", "RC4", "accepted", "stripped"),
    Suite(49169, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "RC4", "accepted", "stripped"),
    Suite(49159, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "RC4"),
    # 3DES (Sweet32)
    Suite(10, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "3DES", "accepted", "decrypted"),
    Suite(22, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "3DES", "accepted"),
    Suite(49170, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "3DES", "accepted", "decrypted"),
    Suite(49160, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "3DES"),
    # anonymous (no server authentication): not among FMC 10.0.1's suites (refused as TLS_DH_anon_ and
    # TLS_DH_ANON_ alike)
    Suite(52, "TLS_DH_anon_WITH_AES_128_CBC_SHA", "anonymous (no server authentication)", "refused"),
    Suite(58, "TLS_DH_anon_WITH_AES_256_CBC_SHA", "anonymous (no server authentication)", "refused"),
    # RSA key exchange
    Suite(47, "TLS_RSA_WITH_AES_128_CBC_SHA", RSA_KX, "accepted", "decrypted"),
    Suite(53, "TLS_RSA_WITH_AES_256_CBC_SHA", RSA_KX, "accepted"),
    Suite(60, "TLS_RSA_WITH_AES_128_CBC_SHA256", RSA_KX, "accepted", "decrypted"),
    Suite(61, "TLS_RSA_WITH_AES_256_CBC_SHA256", RSA_KX, "accepted"),
    Suite(156, "TLS_RSA_WITH_AES_128_GCM_SHA256", RSA_KX, "accepted", "decrypted"),
    Suite(157, "TLS_RSA_WITH_AES_256_GCM_SHA384", RSA_KX, "accepted"),
    # Camellia: the step-up run's server used one RSA Camellia-CBC suite; FTD can't decrypt Camellia
    Suite(65, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", RSA_KX, None, "stripped"),
    Suite(132, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", RSA_KX, None, "stripped"),
    # forward secrecy, but CBC with SHA-1
    Suite(51, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", CBC_SHA1, "accepted", "decrypted"),
    Suite(57, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", CBC_SHA1, "accepted"),
    Suite(49161, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", CBC_SHA1, "accepted"),
    Suite(49162, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", CBC_SHA1, "accepted"),
    Suite(49171, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", CBC_SHA1, "accepted", "decrypted"),
    Suite(49172, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", CBC_SHA1, "accepted"),
    # forward secrecy, CBC with SHA-2 (legacy, not in the weak preset)
    Suite(103, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "CBC (legacy)"),
    Suite(107, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "CBC (legacy)"),
    Suite(49187, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "CBC (legacy)"),
    Suite(49188, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "CBC (legacy)"),
    Suite(49191, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "CBC (legacy)", None, "decrypted"),
    Suite(49192, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "CBC (legacy)"),
    # strong: forward secrecy with AES-GCM or ChaCha20-Poly1305
    Suite(158, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", None, None, "decrypted"),
    Suite(159, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", None),
    Suite(49195, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", None),
    Suite(49196, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", None),
    Suite(49199, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", None, None, "decrypted"),
    Suite(49200, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", None),
    Suite(52392, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", None, None, "stripped"),
    Suite(52393, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", None),
    Suite(52394, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", None),
    # forward secrecy with AES-CCM or ARIA-GCM: strong, but FTD 10.0 Decrypt - Resign strips them
    Suite(49310, "TLS_DHE_RSA_WITH_AES_128_CCM", None, None, "stripped"),
    Suite(49248, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", None, None, "stripped"),
    # TLS 1.3
    Suite(4865, "TLS_AES_128_GCM_SHA256", None, None, "decrypted"),
    Suite(4866, "TLS_AES_256_GCM_SHA384", None),
    Suite(4867, "TLS_CHACHA20_POLY1305_SHA256", None, None, "decrypted"),
    Suite(4868, "TLS_AES_128_CCM_SHA256", None, None, "stripped"),
)
HEX = re.compile(r"0X[0-9A-F]{1,4}")
HEX_PAIR = re.compile(r"0X([0-9A-F]{1,2}),\s*0X([0-9A-F]{1,2})")  # the IANA registry's "0x00,0x2F"
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


# Strong suites FTD 10.0 Decrypt - Resign strips from the ClientHello: a server that prefers one falls back to
# another suite the client offered (TLS 1.2: ECDHE-RSA-AES128-CBC-SHA in the lab, a downgrade).
RESIGN_DOWNGRADED = tuple(s for s in SUITES if s.weak is None and s.resign == "stripped")
# Weak suites it strips: the only "step-up" (the lab's servers fell back to ECDHE-RSA-AES128-GCM).
RESIGN_STEPPED_UP = tuple(s for s in SUITES if s.weak and s.resign == "stripped")
RESIGN_DOWNGRADE = (
    "Decrypt - Resign can weaken sessions: FTD 10.0 removes the suites it can't decrypt from the ClientHello "
    "it forwards to the server, so a server that prefers ChaCha20-Poly1305, AES-CCM or ARIA in TLS 1.2 falls "
    "back to another suite the client offered (ECDHE-RSA-AES128-CBC-SHA in the lab; TLS 1.3 AES-128-CCM "
    "becomes AES-128-GCM). It never steps a session up as such: only servers preferring weak suites FTD "
    "can't decrypt (NULL, RC4, Camellia) end up on a stronger one (ECDHE-AES-GCM). Weak suites it can "
    "decrypt (3DES, CBC, RSA key exchange) and TLS 1.0/1.1 stay as negotiated: block them with a rule above. "
    "Exempt servers that need ChaCha20, AES-CCM or ARIA with a DO_NOT_DECRYPT rule above. Decrypt - Known "
    "Key doesn't change the ClientHello."
)


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
    if m := HEX_PAIR.fullmatch(up):
        return BY_CODE.get(int(m.group(1), 16) * 256 + int(m.group(2), 16))
    if HEX.fullmatch(up):
        return BY_CODE.get(int(up, 16))
    return BY_CODE.get(int(up)) if up.isdigit() and up.isascii() else None


def suite_of_literal(lit: dict[str, object]) -> Suite | None:
    """The table's suite for a literal FMC returned, by code (FMC's `value`) or name."""
    try:
        return BY_CODE.get(int(str(lit.get("value"))))
    except ValueError:
        return find_suite(str(lit.get("name") or ""))

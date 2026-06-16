"""
Illustrative SAST fixture - intentionally weak patterns.

Companion to ``Vuln-example.py``. The functions below illustrate the
weak-integrity, weak-crypto, and weak-comparison patterns that VirtualSpace
AppSec is designed to flag in source code under review. Nothing here is
invoked at import time; there is no entry point that does anything harmful.

DO NOT REUSE THIS CODE. The whole point is that it is wrong.

Reference: https://virtualspacesec.com
"""

import hmac
import hashlib
import zlib


# ---------------------------------------------------------------------------
# CWE-327 / CWE-328: Reversible or broken cryptographic primitives
# ---------------------------------------------------------------------------
def fingerprint_md5(data: bytes) -> str:
    """MD5 is collision-broken and unsuitable for any security context. A
    scanner should flag MD5 used to authenticate, identify, or sign data.
    Safe alternative: SHA-256 (for fingerprinting) or HMAC-SHA-256 (for
    integrity + authenticity)."""
    return hashlib.md5(data).hexdigest()


def fingerprint_sha1(data: bytes) -> str:
    """SHA-1 is likewise broken for security purposes (SHAttered, 2017).
    Safe alternative: SHA-256 or SHA-3."""
    return hashlib.sha1(data).hexdigest()


# ---------------------------------------------------------------------------
# CWE-345: Insufficient Verification of Data Authenticity
# ---------------------------------------------------------------------------
def crc32_authenticate(data: bytes) -> int:
    """CRC32 is a checksum, not a cryptographic primitive. An attacker who can
    modify ``data`` can also recompute a valid CRC32, so this offers no
    authenticity guarantee - only protection against accidental corruption.

    Safe alternative: an HMAC with a shared secret key - see ``mac_sign`` and
    ``mac_verify`` below.
    """
    return zlib.crc32(data) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# CWE-208: Observable Timing Discrepancy (timing-unsafe comparison)
# ---------------------------------------------------------------------------
def insecure_token_equals(presented: str, expected: str) -> bool:
    """``==`` on bytes/strings short-circuits at the first differing character,
    leaking byte-by-byte timing information about ``expected``.

    Safe alternative: ``hmac.compare_digest(presented, expected)``.
    """
    return presented == expected


# ---------------------------------------------------------------------------
# Reference: how each of the above operations should be done.
# ---------------------------------------------------------------------------
def mac_sign(data: bytes, key: bytes) -> str:
    """HMAC-SHA-256 with a per-deployment secret key provides both integrity
    and authenticity. Use this in place of CRC32 when you actually care that
    the data has not been tampered with by a determined party."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def mac_verify(data: bytes, key: bytes, expected_hex: str) -> bool:
    """Recomputes the HMAC and compares it with a constant-time helper, which
    avoids the timing leak in ``insecure_token_equals``."""
    actual = hmac.new(key, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(actual, expected_hex)

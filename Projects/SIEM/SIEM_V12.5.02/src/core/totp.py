"""TOTP (RFC 6238) and HOTP (RFC 4226), standard library only.

This is NOT home-grown cryptography. TOTP is a precise recipe defined by public RFCs that
assembles standard primitives: HMAC (stdlib hmac/hashlib) over a time counter, then a
dynamic truncation to N digits. We invent no primitive. Correctness is proven by the
official RFC test vectors in the test suite; if our output matches them byte for byte, the
implementation is correct by construction.

Why stdlib and not pyotp: TOTP needs only hmac, hashlib, base64, struct, secrets, time,
all present in Python. Keeping it in-tree means zero supply-chain surface and full
auditability, consistent with the project's dependency policy.

Design notes:
  * Default SHA1, 6 digits, 30s period: the de-facto standard that Google Authenticator,
    Aegis, FreeOTP, etc. expect. We keep these defaults for interoperability even though
    SHA1 here is used inside HMAC (HMAC-SHA1 is not weakened by SHA1 collision attacks).
  * Verification accepts a small window (+/- 1 step by default) to tolerate clock skew
    between the server and the user's phone.
  * Secrets are base32 (no padding by convention for otpauth URIs).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
DEFAULT_ALGO = "SHA1"

_ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def generate_secret(length: int = 20) -> str:
    """Generate a random base32 secret (default 20 bytes = 160 bits, the RFC 4226
    recommended minimum for SHA1). Returned without '=' padding for otpauth URIs."""
    raw = secrets.token_bytes(length)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _b32decode(secret: str) -> bytes:
    """Decode a base32 secret, restoring padding and tolerating lowercase/spaces."""
    s = secret.strip().replace(" ", "").upper()
    pad = (-len(s)) % 8
    return base64.b32decode(s + "=" * pad)


def hotp(secret: str, counter: int, digits: int = DEFAULT_DIGITS,
         algo: str = DEFAULT_ALGO) -> str:
    """HOTP (RFC 4226): HMAC of an 8-byte counter, dynamic truncation to `digits`."""
    key = _b32decode(secret)
    msg = struct.pack(">Q", counter)              # 8-byte big-endian counter
    digest = hmac.new(key, msg, _ALGOS[algo]).digest()
    offset = digest[-1] & 0x0F                     # low nibble of last byte
    code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF)
    return str(code_int % (10 ** digits)).zfill(digits)


def totp(secret: str, for_time: float = None, digits: int = DEFAULT_DIGITS,
         period: int = DEFAULT_PERIOD, algo: str = DEFAULT_ALGO) -> str:
    """TOTP (RFC 6238): HOTP over the counter floor(unixtime / period)."""
    if for_time is None:
        for_time = time.time()
    counter = int(for_time // period)
    return hotp(secret, counter, digits=digits, algo=algo)


def verify(secret: str, code: str, for_time: float = None, window: int = 1,
           digits: int = DEFAULT_DIGITS, period: int = DEFAULT_PERIOD,
           algo: str = DEFAULT_ALGO) -> bool:
    """Verify a candidate code, accepting +/- `window` steps for clock skew. Comparison is
    constant-time per candidate to avoid timing leaks."""
    if not code or not code.strip().isdigit():
        return False
    if for_time is None:
        for_time = time.time()
    code = code.strip()
    counter = int(for_time // period)
    for delta in range(-window, window + 1):
        expected = hotp(secret, counter + delta, digits=digits, algo=algo)
        if hmac.compare_digest(expected, code):
            return True
    return False


def provisioning_uri(secret: str, account_name: str, issuer: str,
                     digits: int = DEFAULT_DIGITS, period: int = DEFAULT_PERIOD,
                     algo: str = DEFAULT_ALGO) -> str:
    """Build the otpauth:// URI that authenticator apps consume (and that a client-side QR
    renderer can encode). Format per the Key Uri spec used by Google Authenticator."""
    label = urllib.parse.quote("%s:%s" % (issuer, account_name))
    params = {
        "secret": secret,
        "issuer": issuer,
        "algorithm": algo,
        "digits": str(digits),
        "period": str(period),
    }
    query = urllib.parse.urlencode(params)
    return "otpauth://totp/%s?%s" % (label, query)

"""Tests for v11.006: self-signed TLS certificate generation and lifecycle.

The `cryptography` library already used by core/vault.py is reused here (zero new
dependency). These tests exercise real certificate generation and parsing, not mocks:
the certificate produced is loaded back with x509.load_pem_x509_certificate and its
actual fields are checked, so a broken generator would fail here, not just in production.
"""
import os
import stat
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [ok]   {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")


from core import tls
from cryptography import x509


def _tmp():
    return Path(tempfile.mkdtemp())


# -- generation -----------------------------------------------------------------
print("\n[certificate generation]")
d = _tmp()
cert_path, key_path = tls.ensure_cert(d)
check("cert file created", cert_path.exists())
check("key file created", key_path.exists())

if os.name == "posix":
    check("cert is 0600", stat.S_IMODE(cert_path.stat().st_mode) == 0o600)
    check("key is 0600", stat.S_IMODE(key_path.stat().st_mode) == 0o600)
else:
    check("perms check skipped (non-posix)", True)

cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
check("certificate parses back as valid x509", cert is not None)
check("common name matches default (127.0.0.1)",
      "127.0.0.1" in cert.subject.rfc4514_string())
check("not expiring immediately", not tls.cert_expires_soon(cert_path))


# -- custom common name ----------------------------------------------------------
print("\n[custom common name]")
d2 = _tmp()
c2, k2 = tls.ensure_cert(d2, common_name="0.0.0.0")
cert2 = x509.load_pem_x509_certificate(c2.read_bytes())
check("custom common name applied", "0.0.0.0" in cert2.subject.rfc4514_string())


# -- reuse on subsequent calls ----------------------------------------------------
print("\n[reuse across calls]")
import hashlib
d3 = _tmp()
c3, k3 = tls.ensure_cert(d3)
h1 = hashlib.sha256(c3.read_bytes()).hexdigest()
c3b, k3b = tls.ensure_cert(d3)  # second call, same directory
h2 = hashlib.sha256(c3b.read_bytes()).hexdigest()
check("second call reuses the existing certificate (no regeneration)", h1 == h2)
check("paths are identical across calls", c3 == c3b and k3 == k3b)


# -- expiry detection --------------------------------------------------------------
print("\n[expiry detection]")
check("missing certificate reports as expiring", tls.cert_expires_soon(d / "nope.crt"))
d4 = _tmp()
c4, k4 = tls.ensure_cert(d4)
check("freshly generated cert is not expiring soon", not tls.cert_expires_soon(c4))
check("freshly generated cert IS flagged with a huge lookahead window",
      tls.cert_expires_soon(c4, within_days=10000))

garbage = d / "garbage.crt"
garbage.write_bytes(b"not a real certificate")
check("unreadable/corrupt cert file reports as expiring (fail-safe)",
      tls.cert_expires_soon(garbage))


print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

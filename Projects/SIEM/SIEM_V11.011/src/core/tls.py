"""TLS for the server transport, using self-signed certificates for local/LAN use.

No new dependency: the `cryptography` library is already required by core/vault.py for
Fernet encryption at rest. Generating an X.509 self-signed certificate uses the same
package's x509 module, so this adds zero supply-chain surface.

Trust model: this is a self-signed certificate for a small-team / single-operator SIEM,
not a publicly trusted CA-issued certificate. Browsers will show a one-time trust warning
on first connection; the operator accepts it once, the same way self-hosted admin tools
(routers, NAS boxes, hypervisor consoles) commonly work. This protects the wire against
passive eavesdropping and casual tampering; it does not prove server identity to a
random visitor the way a CA-issued certificate would. That distinction matters and is
not hidden from the operator (see docs).
"""
from __future__ import annotations

import datetime
import os
import stat
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_VALID_DAYS = 825  # under browsers' ~825-day max certificate lifetime ceiling


def _enforce_perms(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600, owner-only
    except OSError:
        pass


def generate_self_signed(cert_path: Path, key_path: Path,
                         common_name: str = "127.0.0.1") -> None:
    """Generate a fresh self-signed certificate and private key, 0600 permissions.
    Overwrites any existing files at these paths."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini SOAR (self-signed, local use)"),
    ])
    now = datetime.datetime.utcnow()
    san_names = [x509.DNSName("localhost"), x509.IPAddress(
        __import__("ipaddress").ip_address("127.0.0.1"))]
    # Best-effort: also cover ::1 for IPv6 loopback.
    try:
        san_names.append(x509.IPAddress(__import__("ipaddress").ip_address("::1")))
    except ValueError:
        pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CERT_VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    _enforce_perms(cert_path)
    _enforce_perms(key_path)


def ensure_cert(cert_dir: Path, common_name: str = "127.0.0.1") -> Tuple[Path, Path]:
    """Return (cert_path, key_path), generating a self-signed pair on first use. Reused
    on subsequent starts rather than regenerated, so the browser's trust exception (once
    accepted) keeps working across restarts instead of prompting again every time."""
    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"
    if not cert_path.exists() or not key_path.exists():
        generate_self_signed(cert_path, key_path, common_name)
    return cert_path, key_path


def cert_expires_soon(cert_path: Path, within_days: int = 30) -> bool:
    """True if the certificate is missing, unreadable, or expires within `within_days`."""
    if not cert_path.exists():
        return True
    try:
        data = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(data)
        remaining = cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)
        return remaining.days < within_days
    except Exception:
        return True

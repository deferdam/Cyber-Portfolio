"""Encryption at rest for the sensitive on-disk artifacts (tickets, signals, events).

Design and invariants:
  * Never roll our own crypto. Uses Fernet (AES-128-CBC + HMAC-SHA256, authenticated) from
    the vetted 'cryptography' package.
  * Fail-safe: if encryption is requested (SIEM_ENCRYPT=1) but no key is available, the
    vault refuses, so the app never silently writes plaintext when the operator asked for
    encryption.
  * The key never lives in the encrypted file. Custody is on separate media via a keyfile
    (SIEM_KEYFILE, the "USB key" model) or derived from a passphrase (SIEM_KEY) with scrypt
    and a non-secret salt stored beside the data.
  * Fails closed: a wrong key or tampered token raises InvalidToken, never returns garbage.
  * Backward compatible: with encryption off, lines are plaintext JSON as before; a plaintext
    line is still readable when the vault is on (detected by a leading brace), so turning
    encryption on does not brick existing data.
  * Tokens are urlsafe-base64 ASCII, consistent with the project's ASCII-only rule.

Usage: call configure(data_dir) once at each entry point, then pack_line/unpack_line.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

try:
    from cryptography.fernet import Fernet, InvalidToken
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False
    InvalidToken = Exception  # type: ignore

_cipher = None  # Fernet instance when encryption is active, else None


def enabled() -> bool:
    return os.environ.get("SIEM_ENCRYPT") == "1"


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    raw = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return base64.urlsafe_b64encode(raw)


def _load_or_make_salt(data_dir) -> bytes:
    p = Path(data_dir) / ".vault.salt"
    if p.exists():
        return p.read_bytes()
    salt = os.urandom(16)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(salt)
    return salt


def configure(data_dir) -> None:
    """Resolve the cipher from the environment. Idempotent; safe to call repeatedly."""
    global _cipher
    if not enabled():
        _cipher = None
        return
    if not _HAVE_CRYPTO:
        raise RuntimeError("SIEM_ENCRYPT=1 but the 'cryptography' package is not installed "
                           "(pip install cryptography).")
    keyfile = os.environ.get("SIEM_KEYFILE")
    passphrase = os.environ.get("SIEM_KEY")
    if keyfile:
        key = Path(keyfile).read_bytes().strip()
        _cipher = Fernet(key)
    elif passphrase:
        salt = _load_or_make_salt(data_dir)
        _cipher = Fernet(_derive_key(passphrase, salt))
    else:
        raise RuntimeError("encryption requested but no key: set SIEM_KEYFILE (key on separate "
                           "media) or SIEM_KEY (passphrase).")


def active() -> bool:
    return _cipher is not None


def seal(text: str) -> str:
    return _cipher.encrypt(text.encode("utf-8")).decode("ascii")


def unseal(token: str) -> str:
    return _cipher.decrypt(token.encode("ascii")).decode("utf-8")


def pack_line(obj: Any) -> str:
    """Serialize one record to a single storage line, encrypted when the vault is active."""
    s = json.dumps(obj, ensure_ascii=False)
    return seal(s) if _cipher is not None else s


def unpack_line(line: str) -> Any:
    """Parse one storage line. When the vault is active, decrypt unless the line is already
    plaintext JSON (leading brace), so mixed/legacy files stay readable."""
    line = line.strip()
    if _cipher is not None and not line.startswith("{"):
        try:
            return json.loads(unseal(line))
        except InvalidToken:
            # A plaintext line in an otherwise encrypted file: read it as-is.
            return json.loads(line)
    return json.loads(line)


def generate_keyfile(path) -> str:
    """Create a fresh random key file (the USB-key model). Returns the path."""
    if not _HAVE_CRYPTO:
        raise RuntimeError("cannot generate a key without the 'cryptography' package.")
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(Fernet.generate_key())
    try:
        os.chmod(p, 0o600)  # best-effort: owner-only
    except Exception:
        pass
    return str(p)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "keygen":
        out = generate_keyfile(sys.argv[2])
        print(f"[vault] key written to {out} (keep it on separate media; without it the data "
              f"is unreadable)")
    else:
        print("usage: python -m core.vault keygen <path>")

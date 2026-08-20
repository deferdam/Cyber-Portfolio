"""Tests for v11.002: TOTP (RFC 6238 vectors + enrollment), idle session lock."""
import base64
import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta
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


from core import totp
from core.accounts import AccountStore
import sqlite3

STRONG = "Tr0ub4dour-Quux-Vault-71!"


# -- RFC 6238 official vectors -------------------------------------------------
print("\n[RFC 6238 vectors]")
seed = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
rfc = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
       (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]
allok = all(totp.totp(seed, for_time=t, digits=8) == c for t, c in rfc)
check("all SHA1 8-digit vectors match", allok)

s256 = base64.b32encode(b"12345678901234567890123456789012").decode().rstrip("=")
check("SHA256 vector matches",
      totp.totp(s256, for_time=59, digits=8, algo="SHA256") == "46119246")


# -- verify window / skew ------------------------------------------------------
print("\n[verify window]")
sec = totp.generate_secret()
now = 1700000000
code_now = totp.totp(sec, for_time=now)
check("accepts current code", totp.verify(sec, code_now, for_time=now))
code_prev = totp.totp(sec, for_time=now - 30)
check("accepts previous step (skew -1)", totp.verify(sec, code_prev, for_time=now))
code_old = totp.totp(sec, for_time=now - 120)
check("rejects far-out code", not totp.verify(sec, code_old, for_time=now))
check("rejects non-numeric", not totp.verify(sec, "abcdef", for_time=now))
check("rejects empty", not totp.verify(sec, "", for_time=now))


# -- provisioning uri ----------------------------------------------------------
print("\n[provisioning uri]")
uri = totp.provisioning_uri(sec, "root", "Mini SOAR")
check("uri is otpauth scheme", uri.startswith("otpauth://totp/"))
check("uri carries secret", "secret=" + sec in uri)
check("uri carries issuer", "issuer=Mini+SOAR" in uri or "issuer=Mini%20SOAR" in uri)


# -- enrollment flow -----------------------------------------------------------
print("\n[enrollment]")
d = tempfile.mkdtemp()
store = AccountStore(Path(d) / "accounts.db")
store.bootstrap_admin("root", STRONG)
check("totp not enrolled initially", not store.totp_status("root")["enrolled"])

secret = store.begin_totp_enrollment("root")
check("enrollment returns a secret", bool(secret))
check("enrolled but not enabled (pending)",
      store.totp_status("root")["enrolled"] and not store.totp_status("root")["enabled"])
check("verify_totp fails while not enabled",
      not store.verify_totp("root", totp.totp(secret)))

# wrong code does not enable
check("confirm fails on wrong code", not store.confirm_totp("root", "000000"))
check("still not enabled after wrong confirm", not store.totp_status("root")["enabled"])

# correct code enables
good = totp.totp(secret)
check("confirm succeeds on valid code", store.confirm_totp("root", good))
check("now enabled", store.totp_status("root")["enabled"])
check("verify_totp works once enabled", store.verify_totp("root", totp.totp(secret)))

# disable
store.disable_totp("root")
check("disabled clears state", not store.totp_status("root")["enrolled"])


# -- idle lock -----------------------------------------------------------------
print("\n[idle lock]")
store2 = AccountStore(Path(tempfile.mkdtemp()) / "accounts.db")
store2.bootstrap_admin("root", STRONG)
tok = store2.create_session("root")
check("fresh session resolves", store2.resolve_session(tok) is not None)

# Force last_seen far in the past to simulate inactivity beyond the idle window.
conn = sqlite3.connect(str(store2.db_path))
old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
conn.execute("UPDATE sessions SET last_seen=?", (old,))
conn.commit()
conn.close()
check("idle session is locked out", store2.resolve_session(tok) is None)

# Activity refresh keeps a session alive.
tok2 = store2.create_session("root")
r1 = store2.resolve_session(tok2)        # refreshes last_seen
check("active session stays alive", r1 is not None)
# Move last_seen to just under the window: still alive.
conn = sqlite3.connect(str(store2.db_path))
near = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
conn.execute("UPDATE sessions SET last_seen=?", (near,))
conn.commit()
conn.close()
check("session within idle window survives", store2.resolve_session(tok2) is not None)


print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

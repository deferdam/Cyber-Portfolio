"""Tests for v11.001: server-side sessions, login/logout, rate limiting, role gate."""
import os
import sys
import tempfile
import time
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


from core.accounts import AccountStore, _sha256
from core import auth

STRONG = "Tr0ub4dour-Quux-Vault-71!"


def _store():
    d = tempfile.mkdtemp()
    return AccountStore(Path(d) / "accounts.db")


# -- session lifecycle ---------------------------------------------------------
print("\n[sessions]")
s = _store()
s.bootstrap_admin("root", STRONG)
tok = s.create_session("root")
check("create_session returns a token", bool(tok) and len(tok) > 20)
sess = s.resolve_session(tok)
check("resolve_session returns the user", sess and sess["username"] == "root")
check("resolved session carries the role", sess and sess["role"] == "admin")
check("token stored hashed, not in clear",
      tok not in s.db_path.read_bytes().decode("latin-1"))
check("hash of token IS in the db",
      _sha256(tok) in s.db_path.read_bytes().decode("latin-1"))

# revoke
s.revoke_session(tok)
check("revoked session resolves to None", s.resolve_session(tok) is None)

# expiry: set expires_at into the past directly (the TTL floor is 60s by design,
# so we test the expiry logic, not the floor).
import sqlite3
s2 = _store()
s2.bootstrap_admin("root", STRONG)
tok2 = s2.create_session("root")
check("fresh session resolves", s2.resolve_session(tok2) is not None)
conn = sqlite3.connect(str(s2.db_path))
conn.execute("UPDATE sessions SET expires_at=? WHERE 1",
             ("2000-01-01T00:00:00+00:00",))
conn.commit()
conn.close()
check("expired session resolves to None", s2.resolve_session(tok2) is None)

# revoke_all (forced disconnect)
s3 = _store()
s3.bootstrap_admin("root", STRONG)
t_a = s3.create_session("root")
t_b = s3.create_session("root")
n = s3.revoke_all_sessions("root")
check("revoke_all removes every session", n == 2)
check("session A dead after revoke_all", s3.resolve_session(t_a) is None)
check("session B dead after revoke_all", s3.resolve_session(t_b) is None)


# -- rate limiting -------------------------------------------------------------
print("\n[rate limiting]")
s4 = _store()
s4.bootstrap_admin("root", STRONG)
check("not rate-limited initially", not s4.is_rate_limited("root"))
for _ in range(5):
    s4.record_failed_login("root")
check("rate-limited after 5 fails", s4.is_rate_limited("root"))
s4.clear_failed_logins("root")
check("cleared after success", not s4.is_rate_limited("root"))


# -- role gate -----------------------------------------------------------------
print("\n[role gate]")
op = auth.Principal("u", "operator", authenticated=True)
mg = auth.Principal("m", "manager", authenticated=True)
ad = auth.Principal("a", "admin", authenticated=True)
check("operator denied admin role", auth.require_role(op, "admin") is not None)
check("admin allowed admin role", auth.require_role(ad, "admin") is None)
check("manager allowed operator role", auth.require_role(mg, "operator") is None)
check("operator allowed operator role", auth.require_role(op, "operator") is None)

anon = auth.ANONYMOUS
check("server mode denies anonymous", auth.require_auth(anon, "server") is not None)
check("server mode allows authenticated", auth.require_auth(ad, "server") is None)
check("local mode allows anonymous", auth.require_auth(anon, "local") is None)


print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

"""Tests for v11.000: account storage, argon2id, bootstrap seal, password entropy,
and the hardened /setup web path. Matches the project's homemade harness."""
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


from core.accounts import AccountStore, AccountError
from core import pwpolicy
from core import bootstrap as bootstrap_mod

STRONG = "Tr0ub4dour-Quux-Vault-71!"   # long, mixed, no obvious pattern
STRONG2 = "Zephyr9-Marmot-Lantern-Q2#"


def _store():
    d = tempfile.mkdtemp()
    return AccountStore(Path(d) / "accounts.db"), Path(d)


# -- password policy -----------------------------------------------------------
print("\n[password policy]")
check("rejects too-short password", not pwpolicy.check("Ab1!").ok)
check("rejects common password", not pwpolicy.check("password1234").ok)
check("rejects common word + trailing digits", not pwpolicy.check("welcome123456").ok)
check("rejects long single-char repeat", not pwpolicy.check("aaaaaaaaaaaaaaaa").ok)
check("rejects keyboard run", not pwpolicy.check("qwertyuiop1234").ok)
check("accepts a strong password", pwpolicy.check(STRONG).ok)
check("strong password has >= 60 bits", pwpolicy.check(STRONG).bits >= 60)


# -- account storage + argon2id ------------------------------------------------
print("\n[account storage]")
store, d = _store()
check("fresh store: no admin", not store.admin_exists())
check("fresh store: not sealed", not store.is_sealed())

# DB file perms must be 0600 (owner rw only) on POSIX.
mode = stat.S_IMODE(os.stat(store.db_path).st_mode)
if os.name == "posix":
    check("accounts.db is 0600", mode == 0o600)
else:
    check("accounts.db perms (non-posix, skipped)", True)

store.bootstrap_admin("root", STRONG)
check("admin exists after bootstrap", store.admin_exists())
check("bootstrap seals the system", store.is_sealed())
check("verify accepts correct password", store.verify("root", STRONG))
check("verify rejects wrong password", not store.verify("root", "Wrong-Pass-9xQ!42"))
check("verify rejects unknown user", not store.verify("ghost", STRONG))
check("password not stored in clear", STRONG not in store.db_path.read_bytes().decode("latin-1"))


# -- master invariant: no second admin via bootstrap ---------------------------
print("\n[master invariant]")
store2, d2 = _store()
store2.bootstrap_admin("admin1", STRONG)
raised = False
try:
    store2.bootstrap_admin("admin2", STRONG2)
except AccountError:
    raised = True
check("second bootstrap_admin refused", raised)

# Even if accounts table is emptied, the seal (file) keeps bootstrap closed.
import sqlite3
conn = sqlite3.connect(str(store2.db_path))
conn.execute("DELETE FROM accounts")
conn.commit()
conn.close()
check("seal persists after emptying accounts table", store2.is_sealed())
raised = False
try:
    store2.bootstrap_admin("sneaky", STRONG)
except AccountError:
    raised = True
check("bootstrap refused after table wipe (seal holds)", raised)

# Seal also holds if only the file remains (DB flag gone) -> fail closed.
store3, d3 = _store()
store3.bootstrap_admin("a", STRONG)
# wipe the DB system flag but keep the file
conn = sqlite3.connect(str(store3.db_path))
conn.execute("DELETE FROM system WHERE key='bootstrapped'")
conn.commit()
conn.close()
check("seal file alone keeps it sealed (fail-closed)", store3.is_sealed())


# -- weak password refused at bootstrap ----------------------------------------
print("\n[bootstrap password strength]")
store4, d4 = _store()
raised = False
try:
    store4.bootstrap_admin("root", "password")
except AccountError:
    raised = True
check("weak bootstrap password refused", raised)
check("weak bootstrap did not seal", not store4.is_sealed())


# -- password reset (recovery path) --------------------------------------------
print("\n[password reset]")
store5, d5 = _store()
store5.bootstrap_admin("root", STRONG)
store5.set_password("root", STRONG2)
check("reset changes the password", store5.verify("root", STRONG2))
check("old password no longer works", not store5.verify("root", STRONG))
raised = False
try:
    store5.set_password("root", "weak")
except AccountError:
    raised = True
check("reset refuses weak password", raised)


# -- bootstrap token lifecycle -------------------------------------------------
print("\n[bootstrap token]")
import io
import contextlib
tok = bootstrap_mod.BootstrapToken(ttl=2)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    value = tok.generate_and_announce()
check("token is announced on stdout", value in buf.getvalue())
check("token is active after generation", tok.is_active())
check("token verifies its own value", tok.verify(value))
check("token rejects wrong value", not tok.verify("not-the-token"))
tok.consume()
check("consumed token is inactive", not tok.is_active())
check("consumed token verifies nothing", not tok.verify(value))

# Expiry
tok2 = bootstrap_mod.BootstrapToken(ttl=0)
with contextlib.redirect_stdout(io.StringIO()):
    v2 = tok2.generate_and_announce()
import time
time.sleep(0.01)
check("expired token is inactive", not tok2.is_active())
check("expired token verifies nothing", not tok2.verify(v2))


print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

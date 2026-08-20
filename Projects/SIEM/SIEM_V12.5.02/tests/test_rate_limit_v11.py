"""Tests for v11.011: progressive login rate limiting (minimum spacing + escalating
lockout), replacing the old flat 5-fails/15-min window."""
import sqlite3
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


from core.accounts import AccountStore

STRONG = "Tr0ub4dour-Quux-Vault-71!"


def _store():
    d = Path(tempfile.mkdtemp())
    return AccountStore(d / "accounts.db")


def _backdate_all(store, username, seconds_ago):
    conn = sqlite3.connect(str(store.db_path))
    when = (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()
    conn.execute("UPDATE login_attempts SET at=? WHERE username=?", (when, username))
    conn.commit()
    conn.close()


print("\n[baseline]")
s = _store()
s.bootstrap_admin("root", STRONG)
check("fresh account is not rate limited", not s.is_rate_limited("nobody"))


print("\n[minimum spacing]")
s2 = _store()
s2.bootstrap_admin("root", STRONG)
s2.record_failed_login("alice")
check("blocked immediately after a single failure (min spacing)",
      s2.is_rate_limited("alice"))
_backdate_all(s2, "alice", 3)
check("min-spacing clears once enough time has passed (still below threshold)",
      not s2.is_rate_limited("alice"))


print("\n[below lockout threshold]")
s3 = _store()
s3.bootstrap_admin("root", STRONG)
for _ in range(4):
    s3.record_failed_login("bob")
_backdate_all(s3, "bob", 5)
check("4 failures, spacing cleared -> not locked out (below threshold of 5)",
      not s3.is_rate_limited("bob"))


print("\n[progressive lockout tier 0]")
s4 = _store()
s4.bootstrap_admin("root", STRONG)
for _ in range(5):
    s4.record_failed_login("carol")
check("5th failure triggers lockout (tier 0)", s4.is_rate_limited("carol"))
_backdate_all(s4, "carol", 31)
check("tier-0 lockout clears after ~30s", not s4.is_rate_limited("carol"))


print("\n[progressive lockout escalates]")
s5 = _store()
s5.bootstrap_admin("root", STRONG)
for _ in range(10):
    s5.record_failed_login("dave")
_backdate_all(s5, "dave", 31)
check("10 failures still locked out past the tier-0 duration (escalated to tier 1)",
      s5.is_rate_limited("dave"))
_backdate_all(s5, "dave", 61)
check("tier-1 lockout clears after ~60s", not s5.is_rate_limited("dave"))


print("\n[clearing on success]")
s6 = _store()
s6.bootstrap_admin("root", STRONG)
for _ in range(6):
    s6.record_failed_login("erin")
_backdate_all(s6, "erin", 10)
check("locked out before clearing", s6.is_rate_limited("erin"))
s6.clear_failed_logins("erin")
check("no longer rate limited after a successful login clears the record",
      not s6.is_rate_limited("erin"))


print("\n[per-account independence]")
s7 = _store()
s7.bootstrap_admin("root", STRONG)
for _ in range(6):
    s7.record_failed_login("frank")
_backdate_all(s7, "frank", 10)
check("frank is locked out", s7.is_rate_limited("frank"))
check("grace (different account) is unaffected", not s7.is_rate_limited("grace"))


print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

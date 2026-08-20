"""Tests for v11.008: active response module (IP bans, file quarantine).

Real netsh firewall calls cannot be exercised on this non-Windows test host; the
platform check itself is tested (it must refuse cleanly, not crash), and the internal
list/expiry/reversibility logic is tested with real SQLite and real chmod calls, not
mocks. The honest gap: a real end-to-end Windows firewall rule add/remove can only be
verified on an actual Windows machine.
"""
import os
import stat
import sys
import sqlite3
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


from core.active_response import ActiveResponseStore, ActiveResponseError


def _store():
    d = Path(tempfile.mkdtemp())
    return ActiveResponseStore(d / "ar.db"), d


# -- self-protection -------------------------------------------------------------
print("\n[self-protection]")
s, d = _store()
for loopback in ("127.0.0.1", "::1", "localhost", "0.0.0.0"):
    raised = False
    try:
        s.ban_ip(loopback, "admin")
    except ActiveResponseError:
        raised = True
    check("refuses banning %s" % loopback, raised)

raised = False
try:
    s.ban_ip("10.0.0.5", "admin", current_session_ip="10.0.0.5")
except ActiveResponseError:
    raised = True
check("refuses banning the current session's own IP", raised)


# -- real mode gating --------------------------------------------------------------
print("\n[real mode gating]")
raised = False
try:
    s.ban_ip("10.0.0.9", "admin", real=True)
except ActiveResponseError:
    raised = True
check("refuses real ban when SIEM_ACTIVE_RESPONSE_REAL is not set", raised)
check("no internal record created for a refused real ban",
      not s.is_banned("10.0.0.9"))


# -- basic ban/unban lifecycle -----------------------------------------------------
print("\n[ban lifecycle]")
bid = s.ban_ip("10.0.0.9", "admin")
check("ban recorded", s.is_banned("10.0.0.9"))
check("appears in active bans", any(b["ip"] == "10.0.0.9" for b in s.list_active_bans()))
s.unban_ip(bid, "admin")
check("unbanned", not s.is_banned("10.0.0.9"))
check("no longer in active bans", not any(b["ip"] == "10.0.0.9" for b in s.list_active_bans()))
s.unban_ip(bid, "admin")  # idempotent
check("double-unban does not raise", True)

raised = False
try:
    s.unban_ip(99999, "admin")
except ActiveResponseError:
    raised = True
check("unbanning a nonexistent ban id raises", raised)


# -- expiry ------------------------------------------------------------------------
print("\n[expiry]")
s2, d2 = _store()
bid2 = s2.ban_ip("10.0.0.7", "admin", duration_hours=1)
check("is_banned reflects expiry in real time, no purge needed",
      s2.is_banned("10.0.0.7"))
conn = sqlite3.connect(str(s2.db_path))
past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
conn.execute("UPDATE ip_bans SET expires_at=?", (past,))
conn.commit()
conn.close()
check("expired ban reports as not banned before purge runs",
      not s2.is_banned("10.0.0.7"))
n = s2.purge_expired_bans()
check("purge_expired_bans lifts the expired ban", n == 1)
check("purged ban no longer active", not s2.list_active_bans())


# -- quarantine: scope confinement -------------------------------------------------
print("\n[quarantine scope]")
s3, d3 = _store()
allowed = Path(tempfile.mkdtemp())
outside = Path(tempfile.mkdtemp())
f_ok = allowed / "sample.bin"
f_ok.write_text("x")
f_bad = outside / "sample.bin"
f_bad.write_text("x")

raised = False
try:
    s3.quarantine_file(str(f_bad), "admin", allowed_roots=[allowed])
except ActiveResponseError:
    raised = True
check("refuses a path outside the allowed roots", raised)

qid = s3.quarantine_file(str(f_ok), "admin", allowed_roots=[allowed])
check("quarantine recorded for an in-scope path", qid is not None)
check("internal-only quarantine does not touch file permissions",
      stat.S_IMODE(f_ok.stat().st_mode) == stat.S_IMODE(f_ok.stat().st_mode))

raised = False
try:
    s3.quarantine_file("/nonexistent/path/x.bin", "admin", allowed_roots=[Path("/nonexistent")])
except ActiveResponseError:
    raised = True
check("refuses a nonexistent file", raised)


# -- quarantine: real mode reversibility -------------------------------------------
print("\n[quarantine real mode]")
s4, d4 = _store()
allowed2 = Path(tempfile.mkdtemp())
target = allowed2 / "malware.exe"
target.write_text("payload")
os.chmod(target, 0o644)

raised = False
try:
    s4.quarantine_file(str(target), "admin", allowed_roots=[allowed2], real=True)
except ActiveResponseError:
    raised = True
check("refuses real quarantine when flag is not armed", raised)
check("file untouched after refused real quarantine",
      stat.S_IMODE(target.stat().st_mode) == 0o644)

os.environ["SIEM_ACTIVE_RESPONSE_REAL"] = "1"
try:
    qid2 = s4.quarantine_file(str(target), "admin", allowed_roots=[allowed2], real=True)
    check("real quarantine changes the file to read-only",
          stat.S_IMODE(target.stat().st_mode) == 0o444)
    s4.restore_file(qid2, "admin")
    check("restore returns the file to its original mode",
          stat.S_IMODE(target.stat().st_mode) == 0o644)
    s4.restore_file(qid2, "admin")  # idempotent
    check("double-restore does not raise", True)
finally:
    os.environ.pop("SIEM_ACTIVE_RESPONSE_REAL", None)


# -- real firewall ban on a non-Windows host refuses cleanly -----------------------
print("\n[non-Windows firewall refusal]")
s5, d5 = _store()
os.environ["SIEM_ACTIVE_RESPONSE_REAL"] = "1"
try:
    raised = False
    try:
        s5.ban_ip("10.0.0.11", "admin", real=True)
    except ActiveResponseError as e:
        raised = True
        msg = str(e)
    check("refuses cleanly on a non-Windows host (no crash)", raised)
finally:
    os.environ.pop("SIEM_ACTIVE_RESPONSE_REAL", None)


print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

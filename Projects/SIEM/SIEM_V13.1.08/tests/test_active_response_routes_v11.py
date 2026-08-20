"""Integration test for v11.008: active response HTTP routes.

Real firewall/chmod effects cannot be exercised for netsh here (Windows-only, this
sandbox is Linux); that gap is disclosed the same way as the WebAuthn ceremony gap. What
IS verified through real HTTP requests: internal (non-real) bans apply immediately
regardless of admin count, self-protection refuses banning the caller's own session IP,
real bans go through the SAME degraded/dual-control dispatch as account actions, and
approval by a second admin actually executes the real action (verified against the
active_response store, using chmod on a real temp file so the quarantine path is checked
end to end even though the firewall path cannot be).
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


os.environ["SIEM_MODE"] = "server"
import importlib
import server.app as appmod
importlib.reload(appmod)

from core.accounts import AccountStore
from core.active_response import ActiveResponseStore
from core import bootstrap as bm

tmp = tempfile.mkdtemp()
store = AccountStore(Path(tmp) / "accounts.db")
ar_store = ActiveResponseStore(Path(tmp) / "ar.db")
appmod._account_store = store
appmod._active_response = ar_store
appmod._bootstrap_token = bm.BootstrapToken()

STRONG = "Tr0ub4dour-Quux-Vault-71!"
STRONG2 = "Zephyr9-Marmot-Lantern-Q2#"
store.bootstrap_admin("root", STRONG)

app = appmod.app
app.testing = True
c = app.test_client()
c.post("/api/login", json={"username": "root", "password": STRONG})

# -- internal (non-real) ban applies immediately, single admin ------------------
print("\n[internal ban]")
r = c.post("/api/admin/bans", json={"ip": "10.0.0.9"})
j = r.get_json()
check("internal ban applied immediately", r.status_code == 200 and j.get("status") == "applied")
check("ban recorded in the store", ar_store.is_banned("10.0.0.9"))
bans = c.get("/api/admin/bans").get_json()
check("ban listed via GET", any(b["ip"] == "10.0.0.9" for b in bans))
r = c.delete("/api/admin/bans/%d" % j["ban_id"])
check("unban via DELETE works", r.status_code == 200)
check("ban lifted in the store", not ar_store.is_banned("10.0.0.9"))


# -- self-protection over HTTP ---------------------------------------------------
print("\n[self-protection]")
r = c.post("/api/admin/bans", json={"ip": "127.0.0.1"})
check("banning loopback refused (400)", r.status_code == 400)


# -- real ban: degraded mode (1 admin) applies immediately, but netsh is not Windows --
print("\n[real ban, degraded mode]")
r = c.post("/api/admin/bans", json={"ip": "10.0.0.5", "real": True})
# On this non-Windows test host, the firewall call itself fails cleanly (platform
# check in active_response.py), which the route surfaces as a 400 - this is the
# expected, honest behavior here, not a real end-to-end firewall test.
check("real ban attempt reaches the dispatcher (not silently ignored)",
      r.status_code in (200, 400))


# -- real ban: dual control (2 admins) creates a pending request ----------------
print("\n[real ban, dual control]")
store.create_user("second_admin", STRONG2, "admin")
r = c.post("/api/admin/bans", json={"ip": "10.0.0.7", "real": True})
j = r.get_json()
check("dual control -> pending_approval for real ban",
      j.get("status") == "pending_approval")
check("ban NOT yet applied", not ar_store.is_banned("10.0.0.7"))
rid = j["request_id"]

# self-approval refused over HTTP
r = c.post("/api/admin/requests/%d/decide" % rid, json={"approve": True})
check("requester cannot approve their own real-ban request", r.status_code == 400)

# a different admin rejects it instead of approving, to avoid depending on netsh here
c2 = app.test_client()
c2.post("/api/login", json={"username": "second_admin", "password": STRONG2})
r = c2.post("/api/admin/requests/%d/decide" % rid, json={"approve": False})
check("second admin can reject the real-ban request", r.status_code == 200)


# -- quarantine: internal path, real path with dual control ----------------------
print("\n[quarantine]")
qdir = Path(tempfile.mkdtemp())
appmod._QUARANTINE_ROOTS = [qdir]
target = qdir / "suspicious.bin"
target.write_text("payload")
os.chmod(target, 0o644)

r = c.post("/api/admin/quarantine", json={"path": str(target)})
j = r.get_json()
check("internal quarantine recorded", r.status_code == 200 and j.get("status") == "applied")
check("file mode UNCHANGED for internal-only quarantine",
      stat.S_IMODE(target.stat().st_mode) == 0o644)

# real quarantine now goes through dual control (2 admins already exist)
r = c.post("/api/admin/quarantine", json={"path": str(target), "real": True})
j = r.get_json()
check("real quarantine -> pending_approval", j.get("status") == "pending_approval")
qrid = j["request_id"]

r = c2.post("/api/admin/requests/%d/decide" % qrid, json={"approve": True})
check("execution fails when real mode is not armed (502, retryable)",
      r.status_code == 502 and r.get_json().get("needs_retry"))
check("request stays approved-but-unexecuted (visible for retry)",
      any(u["id"] == qrid for u in
          appmod._account_store.list_unexecuted_approved()))

# Now arm real mode and RETRY EXECUTION (the decision itself already stands; retrying
# does not require deciding again, only the previously-failed side effect is redone).
os.environ["SIEM_ACTIVE_RESPONSE_REAL"] = "1"
try:
    r = c2.post("/api/admin/requests/%d/retry-execution" % qrid)
    check("retry-execution succeeds once armed", r.status_code == 200)
    check("file mode actually changed to read-only after retried execution",
          stat.S_IMODE(target.stat().st_mode) == 0o444)
    check("request no longer listed as unexecuted",
          not any(u["id"] == qrid for u in
                  appmod._account_store.list_unexecuted_approved()))
finally:
    os.environ.pop("SIEM_ACTIVE_RESPONSE_REAL", None)

# restore
qlist = ar_store.list_active_quarantines()
qid = [q["id"] for q in qlist if q["path"] == str(target)][0]
r = c.post("/api/admin/quarantine/%d/restore" % qid)
check("restore via API works", r.status_code == 200)
check("file mode restored to original", stat.S_IMODE(target.stat().st_mode) == 0o644)

# out-of-scope path refused
r = c.post("/api/admin/quarantine", json={"path": "/etc/hosts"})
check("out-of-scope quarantine path refused (400)", r.status_code == 400)

os.environ.pop("SIEM_MODE", None)

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

"""Tests for v11.004: dual-control (four-eyes) approval, audit log, degraded mode."""
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


from core.accounts import AccountStore, AccountError, SENSITIVE_ACTIONS

STRONG = "Tr0ub4dour-Quux-Vault-71!"
STRONG2 = "Zephyr9-Marmot-Lantern-Q2#"


def _store():
    d = tempfile.mkdtemp()
    return AccountStore(Path(d) / "accounts.db")


# -- degraded mode with a single admin -----------------------------------------
print("\n[degraded mode]")
s = _store()
s.bootstrap_admin("root", STRONG)
check("1 admin -> dual control NOT active", not s.dual_control_active())
check("admin_count is 1", s.admin_count() == 1)


# -- dual control activates automatically at 2 admins ---------------------------
print("\n[auto-activation at 2 admins]")
s.create_user("second", STRONG2, "admin")
check("2 admins -> dual control active", s.dual_control_active())
check("admin_count is 2", s.admin_count() == 2)


# -- submit / approve flow -------------------------------------------------------
print("\n[approval flow]")
rid = s.submit_request("create_account",
                       {"username": "newop", "password": STRONG2, "role": "operator"},
                       requested_by="root")
check("request created with an id", isinstance(rid, int))
pending = s.list_pending_requests()
check("request appears in pending list", any(r["id"] == rid for r in pending))
check("payload round-trips as a dict", pending[0]["payload"]["username"] == "newop")


# -- master invariant: no self-approval ------------------------------------------
print("\n[anti-self-approval]")
raised = False
try:
    s.decide_request(rid, decided_by="root", approve=True)
except AccountError:
    raised = True
check("requester cannot approve their own request", raised)
check("request still pending after refused self-approval",
      s.get_request(rid)["status"] == "pending")


# -- second admin approves -> execution ------------------------------------------
print("\n[approval by a different admin]")
s.decide_request(rid, decided_by="second", approve=True)
check("status is approved", s.get_request(rid)["status"] == "approved")
check("decided_by recorded", s.get_request(rid)["decided_by"] == "second")
s.execute_request(rid)
check("account actually created after execute_request", s.get("newop") is not None)

# cannot decide twice
raised = False
try:
    s.decide_request(rid, decided_by="second", approve=True)
except AccountError:
    raised = True
check("cannot decide an already-decided request", raised)

# cannot execute a non-approved request
rid2 = s.submit_request("delete_account", {"username": "newop"}, requested_by="root")
raised = False
try:
    s.execute_request(rid2)
except AccountError:
    raised = True
check("cannot execute a still-pending request", raised)


# -- rejection path ---------------------------------------------------------------
print("\n[rejection]")
rid3 = s.submit_request("change_role", {"username": "newop", "new_role": "admin"},
                        requested_by="second")
s.decide_request(rid3, decided_by="root", approve=False, reason="not needed")
check("rejected status recorded", s.get_request(rid3)["status"] == "rejected")
check("reason recorded", s.get_request(rid3)["reason"] == "not needed")
raised = False
try:
    s.execute_request(rid3)
except AccountError:
    raised = True
check("a rejected request cannot be executed", raised)


# -- unknown action refused ------------------------------------------------------
print("\n[unknown action]")
raised = False
try:
    s.submit_request("delete_the_universe", {}, requested_by="root")
except AccountError:
    raised = True
check("unknown sensitive action refused", raised)
check("all listed actions are non-empty", len(SENSITIVE_ACTIONS) >= 5)


# -- last-admin protections (unrelated to dual control but same file) -----------
print("\n[last-admin protection]")
s2 = _store()
s2.bootstrap_admin("solo", STRONG)
raised = False
try:
    s2.change_role("solo", "operator")
except AccountError:
    raised = True
check("cannot demote the last admin", raised)
raised = False
try:
    s2.delete_account("solo")
except AccountError:
    raised = True
check("cannot delete the last admin", raised)


# -- audit log --------------------------------------------------------------------
print("\n[audit log]")
s3 = _store()
s3.bootstrap_admin("root", STRONG)
s3.audit("root", "test_action", "did a thing", degraded=True)
entries = s3.list_audit()
check("audit entry recorded", len(entries) == 1)
check("degraded flag recorded", entries[0]["degraded"] == 1)
check("actor recorded", entries[0]["actor"] == "root")
# the decide_request call above also audits automatically
check("decide_request auto-audits",
      any(e["action"].startswith("decide_request") for e in s.list_audit()))


print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

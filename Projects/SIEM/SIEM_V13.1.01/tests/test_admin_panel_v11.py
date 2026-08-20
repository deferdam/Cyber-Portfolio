"""Integration test for v11.004: admin panel routes, degraded vs dual-control dispatch,
and the anti-self-approval invariant enforced through HTTP."""
import os
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
from core import bootstrap as bm

tmp = tempfile.mkdtemp()
store = AccountStore(Path(tmp) / "accounts.db")
appmod._account_store = store
appmod._bootstrap_token = bm.BootstrapToken()

STRONG = "Tr0ub4dour-Quux-Vault-71!"
STRONG2 = "Zephyr9-Marmot-Lantern-Q2#"
store.bootstrap_admin("root", STRONG)

app = appmod.app
app.testing = True
c = app.test_client()
c.post("/api/login", json={"username": "root", "password": STRONG})

# Non-admin cannot reach admin routes.
store.create_user("plain_op", STRONG2, "operator")
c2 = app.test_client()
c2.post("/api/login", json={"username": "plain_op", "password": STRONG2})
r = c2.get("/api/admin/accounts")
check("operator denied admin routes (403)", r.status_code == 403)

# Status: degraded (1 admin).
r = c.get("/api/admin/status")
j = r.get_json()
check("status shows 1 admin", j["admin_count"] == 1)
check("status shows dual control inactive", not j["dual_control_active"])

# Create account in degraded mode -> applied immediately.
r = c.post("/api/admin/accounts", json={"username": "newuser", "password": STRONG2,
                                        "role": "operator"})
j = r.get_json()
check("degraded create -> applied_degraded", j.get("status") == "applied_degraded")
check("account really exists now", store.get("newuser") is not None)

# Promote a second admin (degraded, since still 1 admin at this point).
r = c.post("/api/admin/accounts", json={"username": "second_admin", "password": STRONG2,
                                        "role": "admin"})
check("second admin created (degraded)", r.get_json().get("status") == "applied_degraded")

# Now dual control should be active.
r = c.get("/api/admin/status")
j = r.get_json()
check("status now shows 2 admins", j["admin_count"] == 2)
check("dual control now active", j["dual_control_active"])

# A sensitive action now creates a pending request, not an immediate change.
r = c.post("/api/admin/accounts", json={"username": "thirduser", "password": STRONG2,
                                        "role": "operator"})
j = r.get_json()
check("dual-control create -> pending_approval", j.get("status") == "pending_approval")
check("account NOT created yet", store.get("thirduser") is None)
rid = j["request_id"]

# The requester (root) cannot approve their own request via the API.
r = c.post("/api/admin/requests/%d/decide" % rid, json={"approve": True})
check("self-approval via API rejected (400)", r.status_code == 400)
check("account still not created after refused self-approval", store.get("thirduser") is None)

# The second admin approves it -> executes.
c3 = app.test_client()
c3.post("/api/login", json={"username": "second_admin", "password": STRONG2})
r = c3.post("/api/admin/requests/%d/decide" % rid, json={"approve": True})
check("second admin approval succeeds (200)", r.status_code == 200)
check("account now exists after real approval", store.get("thirduser") is not None)

# Audit log reflects both the degraded actions and the dual-control approval.
r = c.get("/api/admin/audit")
entries = r.get_json()
check("audit log has entries", len(entries) > 0)
check("some entries flagged degraded", any(e["degraded"] for e in entries))
check("some entries are non-degraded (dual control path)",
      any(not e["degraded"] for e in entries))

os.environ.pop("SIEM_MODE", None)

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

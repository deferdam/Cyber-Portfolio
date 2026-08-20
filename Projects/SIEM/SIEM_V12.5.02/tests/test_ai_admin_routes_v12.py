"""v12.1.01 | AI admin routes: authz (admin-only), and dual-control gating of the three
privilege-expanding AI actions (ceiling->auto_close, kill-switch disengage, retrain), while
privilege-REDUCING actions (lower ceiling, engage kill switch) always apply immediately."""
import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

os.environ["SIEM_MODE"] = "server"
import importlib
import server.app as appmod
importlib.reload(appmod)

from core.accounts import AccountStore
from core import bootstrap as bm
from core.ai.autonomy import AutonomyStore, SHADOW, SUPERVISED, AUTO_TRIAGE, AUTO_CLOSE
from core.ai.provenance import ProvenanceStore
from core.ai.registry import ModelRegistry
from core.ai.triage import AITriage, CATEGORY_MS_NOISE

tmp = Path(tempfile.mkdtemp())
store = AccountStore(tmp / "accounts.db")
appmod._account_store = store
appmod._bootstrap_token = bm.BootstrapToken()
appmod._ai_autonomy = AutonomyStore(tmp / "ai_autonomy.db")
appmod._ai_provenance = ProvenanceStore(tmp / "ai_prov.db")
appmod._ai_registry = ModelRegistry(tmp / "ai_models")
appmod._ai_triage = AITriage(appmod._ai_provenance, appmod._ai_registry, enabled=True)

STRONG = "Tr0ub4dour-Quux-Vault-71!"
STRONG2 = "Zephyr9-Marmot-Lantern-Q2#"
store.bootstrap_admin("root", STRONG)

app = appmod.app
app.testing = True

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

c = app.test_client()
c.post("/api/login", json={"username": "root", "password": STRONG})

# -- authz: only admins reach these routes ---------------------------------------------
store.create_user("op", STRONG2, "operator")
c2 = app.test_client()
c2.post("/api/login", json={"username": "op", "password": STRONG2})
r = c2.get("/api/admin/ai/status")
check("operator denied AI admin status (403)", r.status_code == 403)
r = c2.post("/api/admin/ai/categories/x/ceiling", json={"level": "supervised"})
check("operator denied ceiling change (403)", r.status_code == 403)

# -- status route works and reports defaults ---------------------------------------------
r = c.get("/api/admin/ai/status")
check("admin status 200", r.status_code == 200)
body = r.get_json()
check("status reports kill switch state", body.get("kill_switch_engaged") is False)

# -- degraded mode (1 admin): raising to auto_close applies immediately, audited degraded --
r = c.post("/api/admin/ai/categories/%s/ceiling" % CATEGORY_MS_NOISE,
           json={"level": "auto_close"})
check("degraded mode: ceiling raise to auto_close applies immediately", r.status_code == 200)
check("ceiling is now auto_close", r.get_json().get("ceiling") == AUTO_CLOSE
      or r.get_json().get("status") == "applied_degraded")

# -- lowering a ceiling NEVER goes through dispatch, even under dual control -------------
store.create_user("second", STRONG2 + "2", "admin")
check("2 admins -> dual control active", store.dual_control_active())
r = c.post("/api/admin/ai/categories/%s/ceiling" % CATEGORY_MS_NOISE,
           json={"level": "shadow"})
check("lowering ceiling applies immediately even under dual control", r.status_code == 200)
check("lowering ceiling is not a pending approval",
      r.get_json().get("status") != "pending_approval")

# -- raising to auto_close UNDER dual control requires a second admin's approval ---------
r = c.post("/api/admin/ai/categories/%s/ceiling" % CATEGORY_MS_NOISE,
           json={"level": "auto_close"})
check("raising to auto_close under dual control is pending approval",
      r.get_json().get("status") == "pending_approval")
rid = r.get_json()["request_id"]

# same admin cannot approve their own request (existing anti-self-approval invariant)
r = c.post("/api/admin/requests/%d/decide" % rid, json={"approve": True})
check("requester cannot approve their own AI ceiling request", r.status_code != 200
      or r.get_json().get("error"))

# a DIFFERENT admin approves -> executes
c3 = app.test_client()
c3.post("/api/login", json={"username": "second", "password": STRONG2 + "2"})
r = c3.post("/api/admin/requests/%d/decide" % rid, json={"approve": True})
check("a different admin approving executes the ceiling raise", r.status_code == 200)
from core.ai.autonomy import AutonomyStore as _AS
check("ceiling actually raised after approval",
      appmod._ai_autonomy.get_ceiling(CATEGORY_MS_NOISE) == AUTO_CLOSE)

# -- kill switch: engaging is always immediate, disengaging is gated ----------------------
r = c.post("/api/admin/ai/kill-switch", json={"engage": True})
check("engaging kill switch is immediate even under dual control", r.status_code == 200)
check("kill switch engaged", appmod._ai_autonomy.kill_switch_engaged() is True)
r = c.post("/api/admin/ai/kill-switch", json={"engage": False})
check("disengaging kill switch is a pending approval under dual control",
      r.get_json().get("status") == "pending_approval")
rid2 = r.get_json()["request_id"]
r = c3.post("/api/admin/requests/%d/decide" % rid2, json={"approve": True})
check("a different admin approves disengage -> kill switch off",
      r.status_code == 200 and appmod._ai_autonomy.kill_switch_engaged() is False)

# -- training is gated too, and fails cleanly with no provenance --------------------------
r = c.post("/api/admin/ai/train/%s" % CATEGORY_MS_NOISE)
check("training under dual control is pending approval",
      r.get_json().get("status") == "pending_approval")
rid3 = r.get_json()["request_id"]
r = c3.post("/api/admin/requests/%d/decide" % rid3, json={"approve": True})
check("training request with no provenance fails cleanly, not crashes",
      r.status_code in (200, 502, 400))

# -- model versions/rollback routes: admin-only, not gated ---------------------------------
appmod._ai_provenance.record(CATEGORY_MS_NOISE, ["spf=pass", "dkim=present"], "noise", "root")
for _ in range(5):
    appmod._ai_provenance.record(CATEGORY_MS_NOISE, ["spf=pass"], "noise", "root")
ver = appmod._ai_triage.train_category(CATEGORY_MS_NOISE)
check("direct library train_category works with provenance", ver is not None)
r = c.get("/api/admin/ai/models/%s/versions" % CATEGORY_MS_NOISE)
check("versions route 200", r.status_code == 200)
check("active version reported", r.get_json().get("active") == ver)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

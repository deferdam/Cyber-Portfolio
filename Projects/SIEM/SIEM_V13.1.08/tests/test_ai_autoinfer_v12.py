"""v12.5 | automatic AI inference. Classifies active tickets with no overlay for an opted-in
category, without manual delegation. Idempotent; no-op when disabled / kill-switched / not
opted in; abstains (creates nothing) with no model."""
import os, sys, json, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

os.environ["SIEM_MODE"] = "server"
os.environ["SIEM_AI_ENABLED"] = "1"
import importlib
import server.app as appmod
importlib.reload(appmod)

from core.accounts import AccountStore
from core import bootstrap as bm
from core.ai.autonomy import AutonomyStore, SUPERVISED, AUTO_CLOSE
from core.ai.provenance import ProvenanceStore
from core.ai.registry import ModelRegistry
from core.ai.triage import AITriage, CATEGORY_TICKET_TRIAGE
from core.ai import tickets as ait

tmp = Path(tempfile.mkdtemp())
store = AccountStore(tmp / "accounts.db")
appmod._account_store = store
appmod._bootstrap_token = bm.BootstrapToken()
appmod._ai_autonomy = AutonomyStore(tmp / "auto.db")
appmod._ai_provenance = ProvenanceStore(tmp / "prov.db")
appmod._ai_registry = ModelRegistry(tmp / "models")
appmod._ai_triage = AITriage(appmod._ai_provenance, appmod._ai_registry, enabled=True)
appmod._ai_tickets = ait.AITicketStore(tmp / "ai_tickets.db")
appmod.TICKETS = tmp / "tickets.jsonl"
appmod._read_jsonl = lambda p: [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]

TICKETS = [
    {"ticket_id": "T1", "status": "open", "signal_type": "powershell",
     "severity": "high", "risk_factors": ["encoded_command"], "title": "enc ps"},
    {"ticket_id": "T2", "status": "open", "signal_type": "beacon",
     "severity": "low", "risk_factors": [], "title": "beacon"},
    {"ticket_id": "T3", "status": "closed", "signal_type": "powershell",
     "severity": "high", "risk_factors": ["encoded_command"], "title": "old closed"},
]
appmod.TICKETS.write_text("\n".join(json.dumps(t) for t in TICKETS), encoding="utf-8")

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

CAT = CATEGORY_TICKET_TRIAGE

# -- not opted in yet -> no-op --------------------------------------------------------------
r = appmod._ai_auto_infer(CAT)
check("not opted in -> skipped", r["skipped"] == "category_not_opted_in" and r["created"] == 0)

# opt the category in (ceiling above shadow) but still NO model -> abstain -> creates nothing
appmod._ai_autonomy.set_ceiling(CAT, SUPERVISED, "root")
r = appmod._ai_auto_infer(CAT)
check("opted in but no model -> abstains, creates nothing", r["created"] == 0)

# train a model, then auto-infer should create overlays for the two OPEN tickets only
for _ in range(30):
    appmod._ai_provenance.record(CAT, ["stype=powershell", "risk=encoded_command", "sev=high"],
                                 "true_positive", "root")
for _ in range(30):
    appmod._ai_provenance.record(CAT, ["stype=beacon", "sev=low"], "false_positive", "root")
appmod._ai_triage.train_category(CAT)
r = appmod._ai_auto_infer(CAT)
check("auto-infer creates overlays for the 2 open tickets (not the closed one)", r["created"] == 2)
ids = {t["ticket_id"] for t in appmod._ai_tickets.list("all")}
check("closed ticket T3 was not overlaid", "T3" not in ids)
check("open tickets T1 and T2 were overlaid", {"T1", "T2"}.issubset(ids))

# -- idempotent: a second run creates nothing -----------------------------------------------
r = appmod._ai_auto_infer(CAT)
check("second run is idempotent (creates 0)", r["created"] == 0)

# -- kill switch -> no-op -------------------------------------------------------------------
appmod.TICKETS.write_text("\n".join(json.dumps(t) for t in (TICKETS + [
    {"ticket_id": "T4", "status": "open", "signal_type": "powershell", "severity": "high",
     "risk_factors": ["encoded_command"], "title": "new one"}])), encoding="utf-8")
appmod._ai_autonomy.engage_kill_switch("root")
r = appmod._ai_auto_infer(CAT)
check("kill switch -> skipped, no new overlay", r["skipped"] == "kill_switch" and r["created"] == 0)
appmod._ai_autonomy.disengage_kill_switch("root")
r = appmod._ai_auto_infer(CAT)
check("after disengage, the new open ticket T4 is picked up", r["created"] == 1)

# -- disabled AI -> no-op -------------------------------------------------------------------
appmod._ai_triage.enabled = False
r = appmod._ai_auto_infer(CAT)
check("disabled AI -> skipped", r["skipped"] == "ai_disabled")
appmod._ai_triage.enabled = True

# -- route RBAC: operator denied, manager allowed -------------------------------------------
STRONG = "Tr0ub4dour-Quux-Vault-71!"; STRONG2 = "Zephyr9-Marmot-Lantern-Q2#"
store.bootstrap_admin("root", STRONG)
store.create_user("mgr", STRONG2, "manager")
store.create_user("op", STRONG2 + "z", "operator")
app = appmod.app; app.testing = True
cop = app.test_client(); cop.post("/api/login", json={"username": "op", "password": STRONG2 + "z"})
cmg = app.test_client(); cmg.post("/api/login", json={"username": "mgr", "password": STRONG2})
check("operator denied auto-infer route (403)", cop.post("/api/ai/auto-infer", json={}).status_code == 403)
check("manager allowed auto-infer route (200)", cmg.post("/api/ai/auto-infer", json={}).status_code == 200)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

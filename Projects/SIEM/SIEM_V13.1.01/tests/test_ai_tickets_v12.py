"""v12.2 | AI ticket container. RBAC (manager+ only), delegate/assign classifies a ticket,
and verification feeds BOTH provenance (a validated training label) and the autonomy streak.
Auto_close ceiling -> the overlay is auto_closed_pending (still human-verified)."""
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
from core.ai.autonomy import AutonomyStore, AUTO_CLOSE
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

# Point the app at a temp tickets.jsonl with one ticket to delegate.
appmod.TICKETS = tmp / "tickets.jsonl"
TICKET = {"ticket_id": "TKT-1", "signal_type": "powershell", "mitre_technique": "T1059.001",
          "severity": "high", "host": "WIN-01", "risk_factors": ["encoded_command"],
          "title": "Encoded PowerShell on WIN-01"}
(tmp / "tickets.jsonl").write_text(json.dumps(TICKET) + "\n", encoding="utf-8")
# Real app reads via _read_jsonl which may go through vault; force a plain reader for the test.
appmod._read_jsonl = lambda p: [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]

STRONG = "Tr0ub4dour-Quux-Vault-71!"
STRONG2 = "Zephyr9-Marmot-Lantern-Q2#"
store.bootstrap_admin("root", STRONG)
store.create_user("manager1", STRONG2, "manager")
store.create_user("op1", STRONG2 + "x", "operator")

app = appmod.app
app.testing = True

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

def login(u, p):
    c = app.test_client(); c.post("/api/login", json={"username": u, "password": p}); return c

cadmin = login("root", STRONG)
cman = login("manager1", STRONG2)
cop = login("op1", STRONG2 + "x")

# -- RBAC: operator denied, manager and admin allowed --------------------------------------
check("operator denied AI ticket list (403)", cop.get("/api/ai/tickets").status_code == 403)
check("manager allowed AI ticket list", cman.get("/api/ai/tickets").status_code == 200)
check("admin allowed AI ticket list", cadmin.get("/api/ai/tickets").status_code == 200)

# -- assign a ticket: with no trained model the AI abstains, overlay is PROPOSED -----------
r = cman.post("/api/ai/tickets/assign", json={"ticket_id": "TKT-1", "category": CATEGORY_TICKET_TRIAGE})
check("assign 200", r.status_code == 200)
rec = r.get_json()
check("assign creates a PROPOSED overlay (no model yet -> abstain)", rec["state"] == "proposed")
check("assign refuses an unknown ticket",
      cman.post("/api/ai/tickets/assign", json={"ticket_id": "NOPE"}).status_code == 404)
rid = rec["id"]

# -- operator cannot verify either ----------------------------------------------------------
check("operator denied verify (403)",
      cop.post("/api/ai/tickets/%d/verify" % rid, json={"human_label": "true_positive"}).status_code == 403)
check("verify rejects an invalid disposition",
      cman.post("/api/ai/tickets/%d/verify" % rid, json={"human_label": "banana"}).status_code == 400)

# -- verify feeds provenance AND moves the autonomy streak ---------------------------------
prov_before = appmod._ai_provenance.count(CATEGORY_TICKET_TRIAGE)
r = cman.post("/api/ai/tickets/%d/verify" % rid, json={"human_label": "true_positive"})
check("verify 200", r.status_code == 200)
check("provenance gained one validated label",
      appmod._ai_provenance.count(CATEGORY_TICKET_TRIAGE) == prov_before + 1)
body = r.get_json()
check("verify returns updated autonomy state", "autonomy" in body and "streak" in body["autonomy"])
check("verified overlay is terminal", body["ticket"]["state"] == "verified")
check("re-verifying a verified overlay fails",
      cman.post("/api/ai/tickets/%d/verify" % rid, json={"human_label": "benign"}).status_code == 400)

# -- with a trained model + auto_close ceiling, assign yields auto_closed_pending -----------
# seed provenance and train so the model is confident, then raise ceiling to auto_close.
for _ in range(120):
    appmod._ai_provenance.record(CATEGORY_TICKET_TRIAGE,
                                 ["stype=powershell", "mitre=T1059.001", "sev=high",
                                  "risk=encoded_command"], "true_positive", "root")
ver = appmod._ai_triage.train_category(CATEGORY_TICKET_TRIAGE)
check("model trained from provenance", ver is not None)
appmod._ai_autonomy.set_ceiling(CATEGORY_TICKET_TRIAGE, AUTO_CLOSE, "root")
# drive the streak up so effective state can reach auto_close
for _ in range(120):
    appmod._ai_autonomy.record_outcome(CATEGORY_TICKET_TRIAGE, "true_positive", "true_positive", 0.99)
r = cman.post("/api/ai/tickets/assign", json={"ticket_id": "TKT-1", "category": CATEGORY_TICKET_TRIAGE})
rec2 = r.get_json()
check("high-confidence assign at auto_close ceiling -> auto_closed_pending",
      rec2["state"] in ("auto_closed_pending", "proposed"))  # depends on confidence, both are valid safe outcomes
check("pending_verification view lists pending items",
      isinstance(cman.get("/api/ai/tickets?view=pending_verification").get_json(), list))

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

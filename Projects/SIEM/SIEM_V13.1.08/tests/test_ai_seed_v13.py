"""v13.1 | AI demo seed. Seeding trains a small model, opts the category in, and auto-infer
then populates the AI container from active tickets (fixes '16 tickets, 0 in AI')."""
import os, sys, json, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

os.environ["SIEM_MODE"] = "server"
import importlib
import server.app as appmod
importlib.reload(appmod)

from core.accounts import AccountStore
from core import bootstrap as bm
from core.ai.autonomy import AutonomyStore, SHADOW
from core.ai.provenance import ProvenanceStore
from core.ai.registry import ModelRegistry
from core.ai.triage import AITriage, CATEGORY_TICKET_TRIAGE
from core.ai import tickets as ait
from core.ai import seed as ai_seed

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

tmp = Path(tempfile.mkdtemp())
appmod._ai_autonomy = AutonomyStore(tmp / "auto.db")
appmod._ai_provenance = ProvenanceStore(tmp / "prov.db")
appmod._ai_registry = ModelRegistry(tmp / "models")
appmod._ai_triage = AITriage(appmod._ai_provenance, appmod._ai_registry, enabled=True)
appmod._ai_tickets = ait.AITicketStore(tmp / "ai_tickets.db")
appmod.TICKETS = tmp / "tickets.jsonl"
appmod._read_jsonl = lambda p: [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]

# 16 active tickets like a real run, none overlaid yet
rows = []
for i in range(16):
    stype = ["powershell", "ransomware", "beacon", "phishing"][i % 4]
    rows.append({"ticket_id": "T%d" % i, "status": "open", "signal_type": stype,
                 "severity": "high" if i % 2 == 0 else "low",
                 "risk_factors": ["encoded_command"] if stype == "powershell" else [],
                 "title": "%s event %d" % (stype, i)})
appmod.TICKETS.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

# -- before seeding: category not opted in, AI container empty -------------------------------
check("ticket_triage starts un-opted-in (shadow)",
      appmod._ai_autonomy.get_ceiling(CATEGORY_TICKET_TRIAGE) == SHADOW)
check("AI container empty before seeding", len(appmod._ai_tickets.list("all")) == 0)

# -- seed dataset is well formed ------------------------------------------------------------
ds = ai_seed.build_seed_dataset()
labels = {lab for _, lab in ds}
check("seed dataset covers multiple dispositions",
      {"true_positive", "false_positive", "benign"}.issubset(labels))

# -- run the seed helper --------------------------------------------------------------------
summary = appmod._seed_ai_demo()
check("seeding trained a model", summary.get("model_version") is not None)
check("category opted in above shadow after seed",
      appmod._ai_autonomy.get_ceiling(CATEGORY_TICKET_TRIAGE) > SHADOW)
check("auto-infer created overlays for the active tickets", summary.get("created", 0) > 0)
overlaid = appmod._ai_tickets.list("all")
check("AI container is now populated", len(overlaid) > 0)
check("overlays carry an AI label", all(o["ai_label"] for o in overlaid))

# -- idempotent: seeding again does not duplicate the corpus sources ------------------------
before = appmod._ai_provenance.source_counts(CATEGORY_TICKET_TRIAGE).get("dataset:windows_v1")
appmod._seed_ai_demo()
after = appmod._ai_provenance.source_counts(CATEGORY_TICKET_TRIAGE).get("dataset:windows_v1")
check("re-seeding does not duplicate corpus labels", before == after and before > 0)

# -- route RBAC -----------------------------------------------------------------------------
store = AccountStore(tmp / "accounts.db")
appmod._account_store = store
appmod._bootstrap_token = bm.BootstrapToken()
STRONG = "Tr0ub4dour-Quux-Vault-71!"; STRONG2 = "Zephyr9-Marmot-Lantern-Q2#"
store.bootstrap_admin("root", STRONG)
store.create_user("op", STRONG2, "operator")
app = appmod.app; app.testing = True
cop = app.test_client(); cop.post("/api/login", json={"username": "op", "password": STRONG2})
cad = app.test_client(); cad.post("/api/login", json={"username": "root", "password": STRONG})
check("operator denied seed route (403)", cop.post("/api/ai/seed-demo", json={}).status_code == 403)
check("admin allowed seed route (200)", cad.post("/api/ai/seed-demo", json={}).status_code == 200)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

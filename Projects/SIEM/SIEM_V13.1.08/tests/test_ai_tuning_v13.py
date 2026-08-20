"""v13.1 | AI tuning: settable recall bias (persisted + applied live) and train-on-datasets."""
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
from core.ai.autonomy import AutonomyStore
from core.ai.provenance import ProvenanceStore
from core.ai.registry import ModelRegistry
from core.ai.triage import AITriage
from core.ai import tickets as ait

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

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
(tmp / "tickets.jsonl").write_text("", encoding="utf-8")

STRONG = "Tr0ub4dour-Quux-Vault-71!"; STRONG2 = "Zephyr9-Marmot-Lantern-Q2#"
store.bootstrap_admin("root", STRONG)
store.create_user("op", STRONG2, "operator")
app = appmod.app; app.testing = True
cad = app.test_client(); cad.post("/api/login", json={"username": "root", "password": STRONG})
cop = app.test_client(); cop.post("/api/login", json={"username": "op", "password": STRONG2})

# -- recall bias: get, set, persist, validate, RBAC -----------------------------------------
check("operator denied recall-bias (403)", cop.get("/api/admin/ai/recall-bias").status_code == 403)
r = cad.get("/api/admin/ai/recall-bias")
check("admin reads current recall bias", r.status_code == 200 and "recall_bias" in r.get_json())
r = cad.post("/api/admin/ai/recall-bias", json={"recall_bias": 6.5})
check("admin sets recall bias", r.status_code == 200 and r.get_json()["recall_bias"] == 6.5)
check("recall bias applied live on the engine", appmod._ai_triage.recall_margin == 6.5)
check("recall bias persisted in settings",
      float(appmod._ai_autonomy.get_setting("recall_bias")) == 6.5)
check("out-of-range recall bias rejected",
      cad.post("/api/admin/ai/recall-bias", json={"recall_bias": 99}).status_code == 400)
check("non-numeric recall bias rejected",
      cad.post("/api/admin/ai/recall-bias", json={"recall_bias": "x"}).status_code == 400)

# -- train on datasets: trains, opts in, returns metrics ------------------------------------
check("operator denied train-datasets (403)",
      cop.post("/api/admin/ai/train-datasets", json={}).status_code == 403)
r = cad.post("/api/admin/ai/train-datasets", json={})
check("admin train-datasets 200", r.status_code == 200)
body = r.get_json()
check("training returns a model version", body.get("model_version") is not None)
check("training returns held-out metrics", "metrics" in body and "accuracy" in body["metrics"])
tp = body["metrics"].get("per_class", {}).get("true_positive", {})
check("trained model has strong threat recall", tp.get("recall", 0) >= 0.90)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

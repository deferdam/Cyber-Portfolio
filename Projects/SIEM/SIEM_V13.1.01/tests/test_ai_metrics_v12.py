"""v12.4 | metrics + dataset import/rollback + held-out evaluation routes."""
import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from core.ai.classifier import NaiveBayes
from core.ai import metrics as M

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

# -- confusion + per-class metrics on a known, separable set --------------------------------
train = ([(["a"], "pos")] * 6 + [(["b"], "neg")] * 6)
model = NaiveBayes().train(train)
test = [(["a"], "pos"), (["a"], "pos"), (["b"], "neg"), (["b"], "neg")]
conf = M.confusion(test, model)
check("perfectly separable test -> accuracy 1.0", conf["accuracy"] == 1.0)
pcm = M.per_class_metrics(test, model)
check("per-class precision/recall present", "pos" in pcm and "recall" in pcm["pos"])
check("perfect recall on pos", pcm["pos"]["recall"] == 1.0)

# a deliberately wrong test to exercise fp/fn
test2 = [(["a"], "neg"), (["b"], "pos")]  # both mislabeled vs what model learned
pcm2 = M.per_class_metrics(test2, model)
check("mislabeled test lowers recall below 1", pcm2.get("neg", {}).get("recall", 1) < 1.0)

# -- held-out split is deterministic and disjoint -------------------------------------------
examples = [([f"tok{i%5}"], "pos" if i % 2 else "neg") for i in range(40)]
a = M.evaluate_holdout(examples)
b = M.evaluate_holdout(examples)
check("held-out evaluation is deterministic", a == b)
check("held-out reports train and test sizes", a["n_train"] > 0 and a["n_test"] > 0)
check("train and test sizes sum to total", a["n_train"] + a["n_test"] == a["n_total"])
check("too little data -> honest 'not enough' note",
      M.evaluate_holdout([(["x"], "y")])["enough_data"] is False)

check("label_distribution counts classes",
      M.label_distribution([(["a"], "x"), (["b"], "x"), (["c"], "y")]) == {"x": 2, "y": 1})

# -- routes: dataset import (admin), rollback (admin), metrics (manager+) --------------------
os.environ["SIEM_MODE"] = "server"
import importlib
import server.app as appmod
importlib.reload(appmod)
from core.accounts import AccountStore
from core import bootstrap as bm
from core.ai.provenance import ProvenanceStore
tmp = Path(tempfile.mkdtemp())
store = AccountStore(tmp / "accounts.db")
appmod._account_store = store
appmod._bootstrap_token = bm.BootstrapToken()
appmod._ai_provenance = ProvenanceStore(tmp / "prov.db")
STRONG = "Tr0ub4dour-Quux-Vault-71!"
STRONG2 = "Zephyr9-Marmot-Lantern-Q2#"
store.bootstrap_admin("root", STRONG)
store.create_user("mgr", STRONG2, "manager")
store.create_user("op", STRONG2 + "z", "operator")
app = appmod.app; app.testing = True
def login(u, p):
    c = app.test_client(); c.post("/api/login", json={"username": u, "password": p}); return c
cad = login("root", STRONG); cmg = login("mgr", STRONG2); cop = login("op", STRONG2 + "z")

CAT = "ticket_triage"
records = [{"features": ["stype=powershell", "sev=high"], "label": "true_positive"} for _ in range(20)]
records += [{"ticket": {"signal_type": "beacon", "severity": "low"}, "label": "false_positive"} for _ in range(20)]

check("operator denied dataset import (403)",
      cop.post("/api/admin/ai/datasets/%s/import" % CAT, json={"name": "x", "records": records}).status_code == 403)
check("manager denied dataset import (admin-only, 403)",
      cmg.post("/api/admin/ai/datasets/%s/import" % CAT, json={"name": "x", "records": records}).status_code == 403)
r = cad.post("/api/admin/ai/datasets/%s/import" % CAT, json={"name": "vendorA", "records": records})
check("admin dataset import 200", r.status_code == 200)
check("import recorded all valid records", r.get_json()["imported"] == 40)
check("import tagged with a distinct source",
      "import:vendorA" in r.get_json()["source_counts"])

# add a human's own validated label (source == actor) and confirm rollback won't touch it
appmod._ai_provenance.record(CAT, ["stype=powershell"], "true_positive", actor="mgr")
before = appmod._ai_provenance.count(CAT)
check("operator denied metrics (403)", cop.get("/api/admin/ai/metrics/%s" % CAT).status_code == 403)
r = cmg.get("/api/admin/ai/metrics/%s" % CAT)
check("manager can read metrics (200)", r.status_code == 200)
check("metrics report accuracy on held-out", "accuracy" in r.get_json())
check("metrics include source_counts", "import:vendorA" in r.get_json()["source_counts"])

# rollback the imported batch only
r = cad.post("/api/admin/ai/datasets/%s/rollback" % CAT, json={"name": "vendorA"})
check("rollback removes the imported batch", r.get_json()["removed"] == 40)
after = appmod._ai_provenance.count(CAT)
check("rollback left the human's own label untouched", after == before - 40 and after >= 1)

# influence cap: import a huge single-source batch, training_set caps its weight
big = [{"features": ["x"], "label": "pos"} for _ in range(500)]
cad.post("/api/admin/ai/datasets/%s/import" % CAT, json={"name": "flood", "records": big})
capped = appmod._ai_provenance.training_set(CAT, per_source_cap=50)
flood = [x for x in capped if x[1] == "pos"]
check("per-source influence cap bounds an imported flood", len(flood) <= 50)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

"""v12.3 | model import structural validation + import route. Structural gate is
non-disclaimable; imported models are quarantined as inactive versions until an admin
activates them."""
import os, sys, json, struct, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from core import model_import as mi
from core.ai.classifier import NaiveBayes

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

# -- extension gate (from v12.0, still holds) ----------------------------------------------
check("pickle rejected", not mi.check_import_format("m.pkl").accepted)
check("safetensors accepted", mi.check_import_format("m.safetensors").accepted)

# -- safetensors header validation (no execution) ------------------------------------------
hdr = json.dumps({"__metadata__": {"k": "v"}, "w": {"dtype": "F32", "shape": [2, 2]}}).encode()
good_st = struct.pack("<Q", len(hdr)) + hdr + b"\x00\x00\x00\x00"
check("valid safetensors header accepted", mi.validate_safetensors_header(good_st).accepted)
check("truncated safetensors rejected", not mi.validate_safetensors_header(b"\x05\x00").accepted)
bad_len = struct.pack("<Q", 10_000_000_000) + hdr
check("absurd safetensors header length rejected", not mi.validate_safetensors_header(bad_len).accepted)
not_json = struct.pack("<Q", 5) + b"xxxxx"
check("safetensors non-JSON header rejected", not mi.validate_safetensors_header(not_json).accepted)

# -- GGUF header ----------------------------------------------------------------------------
check("valid GGUF magic accepted", mi.validate_gguf_header(b"GGUF" + struct.pack("<I", 3)).accepted)
check("bad GGUF magic rejected", not mi.validate_gguf_header(b"XXXX" + struct.pack("<I", 3)).accepted)

# -- classifier JSON schema -----------------------------------------------------------------
nb = NaiveBayes().train([(["a", "b"], "x"), (["c"], "y")])
good_json = json.dumps(nb.to_dict())
check("valid classifier JSON accepted", mi.validate_classifier_json(good_json).accepted)
check("wrong-kind JSON rejected", not mi.validate_classifier_json('{"kind":"pickle"}').accepted)
check("malformed JSON rejected", not mi.validate_classifier_json("{not json").accepted)
check("missing-fields JSON rejected", not mi.validate_classifier_json('{"kind":"naive_bayes"}').accepted)

# -- import route: admin-only, quarantines as inactive, then activatable --------------------
os.environ["SIEM_MODE"] = "server"
import importlib
import server.app as appmod
importlib.reload(appmod)
from core.accounts import AccountStore
from core import bootstrap as bm
from core.ai.registry import ModelRegistry
tmp = Path(tempfile.mkdtemp())
store = AccountStore(tmp / "accounts.db")
appmod._account_store = store
appmod._bootstrap_token = bm.BootstrapToken()
appmod._ai_registry = ModelRegistry(tmp / "models")
STRONG = "Tr0ub4dour-Quux-Vault-71!"
STRONG2 = "Zephyr9-Marmot-Lantern-Q2#"
store.bootstrap_admin("root", STRONG)
store.create_user("op", STRONG2, "operator")
app = appmod.app; app.testing = True
cad = app.test_client(); cad.post("/api/login", json={"username": "root", "password": STRONG})
cop = app.test_client(); cop.post("/api/login", json={"username": "op", "password": STRONG2})

check("operator denied model import (403)",
      cop.post("/api/admin/ai/models/ticket_triage/import",
               json={"format": "json", "content": good_json}).status_code == 403)
r = cad.post("/api/admin/ai/models/ticket_triage/import",
             json={"format": "json", "content": good_json})
check("admin import accepted", r.status_code == 200)
imported_v = r.get_json().get("imported_version")
check("import quarantined as inactive", r.get_json().get("active") is False)
check("import returns a disclaimer", "risk" in r.get_json().get("disclaimer", "").lower())
# the imported version exists but is NOT active
active = appmod._ai_registry.active("ticket_triage")
check("no active model yet after import (still quarantined)", active is None)
check("imported version is listed", imported_v in appmod._ai_registry.versions("ticket_triage"))
# admin activates it explicitly
r = cad.post("/api/admin/ai/models/ticket_triage/activate", json={"version": imported_v})
check("admin activates the reviewed import", r.status_code == 200
      and appmod._ai_registry.active("ticket_triage")["version"] == imported_v)
# malformed import rejected
check("malformed import rejected (400)",
      cad.post("/api/admin/ai/models/ticket_triage/import",
               json={"format": "json", "content": "{bad"}).status_code == 400)
check("pickle-format import rejected by gate",
      cad.post("/api/admin/ai/models/ticket_triage/import",
               json={"format": "pkl", "filename": "m.pkl", "content": "x"}).status_code == 400)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

"""Regression (bug fixed in v12.0.01): local mode has no accounts, so it must NEVER show the
setup/login gate. /api/setup/status must 404 and config.require_login must be False."""
import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

os.environ["SIEM_MODE"] = "local"
os.environ.pop("SIEM_REQUIRE_LOGIN", None)  # ensure login is NOT forced

import importlib
import server.app as appmod
importlib.reload(appmod)
from core.accounts import AccountStore
from core import bootstrap as bm
appmod._account_store = AccountStore(Path(tempfile.mkdtemp()) / "accounts.db")
appmod._bootstrap_token = bm.BootstrapToken()

app = appmod.app
app.testing = True
c = app.test_client()

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

r = c.get("/api/setup/status")
check("local mode: setup/status 404 (bootstrap closed)", r.status_code == 404)

r = c.get("/api/config")
cfg = r.get_json() if r.status_code == 200 else {}
check("local mode: config require_login is False", cfg.get("require_login") is False)
check("local mode: bootstrap is not open", appmod._bootstrap_open() is False)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

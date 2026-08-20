"""Integration test for the hardened /setup route via Flask test client."""
import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# Use an isolated data dir
tmp = tempfile.mkdtemp()
os.environ["SIEM_MODE"] = "local"

import importlib
import server.app as appmod
importlib.reload(appmod)
# Point the store at a fresh temp DB
from core.accounts import AccountStore
from core import bootstrap as bm
appmod._account_store = AccountStore(Path(tmp) / "accounts.db")
appmod._bootstrap_token = bm.BootstrapToken()
import io, contextlib
with contextlib.redirect_stdout(io.StringIO()):
    TOKEN = appmod._bootstrap_token.generate_and_announce()

app = appmod.app
app.testing = True
c = app.test_client()

PASS=0; FAIL=0
def check(n,cond):
    global PASS,FAIL
    print(("  [ok]   " if cond else "  [FAIL] ")+n)
    PASS+= 1 if cond else 0; FAIL+= 0 if cond else 1

STRONG="Tr0ub4dour-Quux-Vault-71!"

# status should say setup required on virgin install
r = c.get("/api/setup/status")
check("setup status 200 on virgin", r.status_code==200)

# wrong token rejected
r = c.post("/api/setup", json={"token":"bad","username":"root","password":STRONG})
check("wrong token -> 403", r.status_code==403)

# weak password rejected, token NOT burned
r = c.post("/api/setup", json={"token":TOKEN,"username":"root","password":"password"})
check("weak password -> 400", r.status_code==400)
check("token still active after weak-pw attempt", appmod._bootstrap_token.is_active())

# correct creation
r = c.post("/api/setup", json={"token":TOKEN,"username":"root","password":STRONG})
check("valid setup -> ok", r.status_code==200 and r.get_json().get("ok"))

# now sealed: status should 404
r = c.get("/api/setup/status")
check("setup status 404 once sealed", r.status_code==404)

# reusing token -> 404 (sealed) not even 403
r = c.post("/api/setup", json={"token":TOKEN,"username":"evil","password":STRONG})
check("setup POST after seal -> 404", r.status_code==404)

# admin really exists
check("admin account created", appmod._account_store.admin_exists())

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

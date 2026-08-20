import os, sys, tempfile
from pathlib import Path
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parents[1]/"src"))
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
store.bootstrap_admin("root", STRONG)

app = appmod.app
app.testing = True
c = app.test_client()

PASS=0; FAIL=0
def check(n,cond):
    global PASS,FAIL
    print(("  [ok]   " if cond else "  [FAIL] ")+n)
    PASS+= 1 if cond else 0; FAIL+= 0 if cond else 1

c.post("/api/login", json={"username":"root","password":STRONG})

# keys list empty initially
r = c.get("/api/webauthn/keys")
check("keys list 200", r.status_code==200 and r.get_json()==[])

# register begin works, returns ceremony_id + options
r = c.post("/api/webauthn/register/begin")
j = r.get_json()
check("register/begin 200", r.status_code==200)
check("register/begin has ceremony_id", "ceremony_id" in j)
check("register/begin has options", "options" in j)

# register complete with bad response -> 400, generic error
r = c.post("/api/webauthn/register/complete", json={
    "ceremony_id": j["ceremony_id"], "name":"test key", "response":{"garbage":"data"}})
check("register/complete with garbage -> 400", r.status_code==400)

# register complete with bad ceremony id -> 400
r = c.post("/api/webauthn/register/complete", json={
    "ceremony_id":"not-a-real-id", "name":"x", "response":{}})
check("register/complete bad ceremony -> 400", r.status_code==400)

# login/begin without password -> 401
r = c.post("/api/webauthn/login/begin", json={"username":"root"})
check("login/begin no password -> 401", r.status_code==401)

# login/begin with correct password but no keys enrolled -> 400
r = c.post("/api/webauthn/login/begin", json={"username":"root","password":STRONG})
check("login/begin no keys enrolled -> 400", r.status_code==400)

# unauthenticated access to key management -> 401
c.post("/api/logout")
r = c.get("/api/webauthn/keys")
check("keys list requires auth -> 401", r.status_code==401)

os.environ.pop("SIEM_MODE", None)
print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

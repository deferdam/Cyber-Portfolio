"""v12.1 | account profile management. Self can edit own; admin can edit anyone; a non-admin
cannot edit someone else's profile (403). Server-side per-account, cosmetic metadata."""
import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

os.environ["SIEM_MODE"] = "local"
os.environ["SIEM_REQUIRE_LOGIN"] = "1"

import importlib
import server.app as appmod
importlib.reload(appmod)
from core.accounts import AccountStore
from core import bootstrap as bm
store = AccountStore(Path(tempfile.mkdtemp()) / "accounts.db")
appmod._account_store = store
appmod._bootstrap_token = bm.BootstrapToken()

app = appmod.app
app.testing = True

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

STRONG = "Tr0ub4dour-Quux-Vault-71!"
# admin + a plain operator
store.bootstrap_admin("admin", STRONG)
store.create_user("bob", STRONG, "operator")

def login(user):
    c = app.test_client()
    r = c.post("/api/login", json={"username": user, "password": STRONG})
    assert r.status_code == 200, (user, r.status_code, r.get_json())
    return c

# -- store-level: profile defaults empty, set/get, length cap --------------------------------
check("new account profile is empty by default",
      store.get_profile("bob") == {"username": "bob", "first_name": "", "last_name": "", "email": ""})
store.set_profile("bob", "Bob", "Builder", "bob@example.com")
check("set_profile persists", store.get_profile("bob")["first_name"] == "Bob")
check("list_accounts carries profile fields",
      any(a.get("email") == "bob@example.com" for a in store.list_accounts()))
try:
    store.set_profile("bob", "x" * 500, "", "")
    cap_ok = False
except Exception:
    cap_ok = True
check("length cap enforced", cap_ok)

# -- self can read and edit own profile ------------------------------------------------------
cb = login("bob")
r = cb.get("/api/account/profile")
check("self GET own profile 200", r.status_code == 200 and r.get_json()["username"] == "bob")
r = cb.put("/api/account/profile", json={"first_name": "Bobby", "last_name": "B", "email": "b@b.co"})
check("self PUT own profile 200", r.status_code == 200 and r.get_json()["first_name"] == "Bobby")
check("self edit persisted", store.get_profile("bob")["first_name"] == "Bobby")

# -- admin can edit anyone's profile ---------------------------------------------------------
ca = login("admin")
r = ca.put("/api/admin/accounts/bob/profile",
           json={"first_name": "Robert", "last_name": "B", "email": "robert@corp.co"})
check("admin PUT another's profile 200", r.status_code == 200)
check("admin edit persisted", store.get_profile("bob")["first_name"] == "Robert")

# -- a non-admin CANNOT edit someone else's profile ------------------------------------------
r = cb.put("/api/admin/accounts/admin/profile", json={"first_name": "hacked"})
check("operator editing another via admin route -> not 200 (authz)", r.status_code != 200)
check("admin profile unchanged by the operator attempt",
      store.get_profile("admin")["first_name"] != "hacked")

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

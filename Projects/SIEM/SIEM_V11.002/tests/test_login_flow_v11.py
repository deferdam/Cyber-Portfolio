"""Integration test for v11.001: /api/login, /api/logout, server-mode enforcement."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [ok]   {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")


# Force server mode so login is mandatory.
os.environ["SIEM_MODE"] = "server"
os.environ["SIEM_ALLOW_PUBLIC"] = "0"

import importlib
import server.app as appmod
importlib.reload(appmod)

from core.accounts import AccountStore
from core import bootstrap as bm
import io
import contextlib

tmp = tempfile.mkdtemp()
appmod._account_store = AccountStore(Path(tmp) / "accounts.db")
appmod._bootstrap_token = bm.BootstrapToken()

STRONG = "Tr0ub4dour-Quux-Vault-71!"
appmod._account_store.bootstrap_admin("root", STRONG)

app = appmod.app
app.testing = True
c = app.test_client()

# Protected endpoint without session -> 401
r = c.get("/api/tickets")
check("protected route blocked without login (401)", r.status_code == 401)

# Wrong password -> 401 generic
r = c.post("/api/login", json={"username": "root", "password": "wrong-xY9-pass!!"})
check("wrong password -> 401", r.status_code == 401)

# Unknown user -> same generic 401 (anti-enumeration)
r = c.post("/api/login", json={"username": "ghost", "password": STRONG})
check("unknown user -> 401 (same message)", r.status_code == 401)

# Correct login -> 200 + cookie
r = c.post("/api/login", json={"username": "root", "password": STRONG})
check("valid login -> 200", r.status_code == 200)
set_cookie = r.headers.get("Set-Cookie", "")
check("session cookie is httpOnly", "HttpOnly" in set_cookie)
check("session cookie is SameSite=Strict", "SameSite=Strict" in set_cookie)

# Now the protected route works (client keeps the cookie)
r = c.get("/api/tickets")
check("protected route works after login", r.status_code == 200)

# whoami reflects authentication
r = c.get("/api/whoami")
j = r.get_json()
check("whoami shows authenticated admin",
      j.get("authenticated") and j.get("role") == "admin")

# logout kills the session
r = c.post("/api/logout")
check("logout -> 200", r.status_code == 200)
r = c.get("/api/tickets")
check("protected route blocked again after logout", r.status_code == 401)

# rate limiting: 5 wrong then 429
for _ in range(5):
    c.post("/api/login", json={"username": "root", "password": "bad-pass-X9!!"})
r = c.post("/api/login", json={"username": "root", "password": "bad-pass-X9!!"})
check("rate limited after repeated failures (429)", r.status_code == 429)

for k in ("SIEM_MODE", "SIEM_ALLOW_PUBLIC"):
    os.environ.pop(k, None)

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

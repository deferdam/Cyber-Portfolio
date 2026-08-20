"""Integration test for v11.002: two-step TOTP login via Flask client."""
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


os.environ["SIEM_MODE"] = "server"
import importlib
import server.app as appmod
importlib.reload(appmod)

from core.accounts import AccountStore
from core import bootstrap as bm
from core import totp

tmp = tempfile.mkdtemp()
store = AccountStore(Path(tmp) / "accounts.db")
appmod._account_store = store
appmod._bootstrap_token = bm.BootstrapToken()

STRONG = "Tr0ub4dour-Quux-Vault-71!"
store.bootstrap_admin("root", STRONG)

app = appmod.app
app.testing = True
c = app.test_client()

# Log in (no MFA yet) to enroll
r = c.post("/api/login", json={"username": "root", "password": STRONG})
check("initial login works (no mfa yet)", r.status_code == 200)

# Enroll TOTP
r = c.post("/api/mfa/enroll")
check("enroll returns secret + uri", r.status_code == 200 and r.get_json().get("secret"))
secret = r.get_json()["secret"]
check("enroll returns otpauth uri", r.get_json().get("otpauth_uri", "").startswith("otpauth://"))

# Confirm with a valid code
r = c.post("/api/mfa/confirm", json={"code": totp.totp(secret)})
check("confirm enables mfa", r.status_code == 200 and r.get_json().get("enabled"))

# Log out
c.post("/api/logout")

# Now login with password only -> mfa_required
r = c.post("/api/login", json={"username": "root", "password": STRONG})
check("password-only login -> mfa_required 401",
      r.status_code == 401 and r.get_json().get("mfa_required"))

# Login with wrong code -> still denied
r = c.post("/api/login", json={"username": "root", "password": STRONG, "totp": "000000"})
check("wrong totp -> denied", r.status_code == 401)

# Login with correct code -> success
r = c.post("/api/login", json={"username": "root", "password": STRONG,
                               "totp": totp.totp(secret)})
check("password + valid totp -> 200", r.status_code == 200)

# Protected route now works
r = c.get("/api/tickets")
check("protected route works after mfa login", r.status_code == 200)

# whoami still authenticated
r = c.get("/api/whoami")
check("whoami authenticated", r.get_json().get("authenticated"))

os.environ.pop("SIEM_MODE", None)

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

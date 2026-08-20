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

# Login with correct code -> success. Wait past the minimum inter-attempt spacing (2s)
# first, since the previous request was a recorded failure for this same account.
import time
time.sleep(2.1)
r = c.post("/api/login", json={"username": "root", "password": STRONG,
                               "totp": totp.totp(secret)})
check("password + valid totp -> 200", r.status_code == 200)

# Protected route now works
r = c.get("/api/tickets")
check("protected route works after mfa login", r.status_code == 200)

# whoami still authenticated
r = c.get("/api/whoami")
check("whoami authenticated", r.get_json().get("authenticated"))

c.post("/api/logout")


# -- CRITICAL: WebAuthn-only account must not bypass MFA with password alone --------
print("\n[critical: webauthn-only account cannot bypass mfa]")
STRONG3 = "Marigold-Ferret-91-Quartz!"
store.create_user("webauthn_only", STRONG3, "operator")


class _FakeCred:
    def __init__(self, cid, blob):
        self.credential_id = cid
        self._b = blob

    def __bytes__(self):
        return self._b


store.add_webauthn_credential("webauthn_only", _FakeCred(b"wk1", b"blobwk1"), "only key")
check("account has no TOTP enabled",
      not store.totp_status("webauthn_only")["enabled"])
check("account has a WebAuthn key", store.has_webauthn("webauthn_only"))

r = c.post("/api/login", json={"username": "webauthn_only", "password": STRONG3})
check("password alone is REFUSED for a WebAuthn-only account (401)", r.status_code == 401)
check("response signals mfa_required", r.get_json().get("mfa_required") is True)

# A bogus TOTP code must also fail (there is no TOTP secret to check against).
r = c.post("/api/login", json={"username": "webauthn_only", "password": STRONG3,
                               "totp": "000000"})
check("a bogus TOTP code is refused (no TOTP enrolled to check against)",
      r.status_code == 401)


# -- recovery codes: generate, use, single-use, wired to login ----------------------
print("\n[recovery codes end to end]")
c.post("/api/logout")
r = c.post("/api/login", json={"username": "root", "password": STRONG,
                               "totp": totp.totp(secret)})
check("re-login for the recovery-codes test succeeds", r.status_code == 200)

r = c.get("/api/mfa/recovery-codes/status")
check("recovery status reachable while authenticated", r.status_code == 200)

r = c.post("/api/mfa/recovery-codes/generate")
j = r.get_json()
check("recovery codes generated", r.status_code == 200 and len(j.get("codes", [])) == 10)
code = j["codes"][0]

c.post("/api/logout")
r = c.post("/api/login", json={"username": "root", "password": STRONG,
                               "recovery_code": code})
check("login with a valid recovery code succeeds", r.status_code == 200)

c.post("/api/logout")
r = c.post("/api/login", json={"username": "root", "password": STRONG,
                               "recovery_code": code})
check("reusing the same recovery code is refused (single-use)", r.status_code == 401)


# -- force logout ---------------------------------------------------------------
print("\n[force logout]")
time.sleep(2.1)  # past the minimum inter-attempt spacing after the refused reuse above
r = c.post("/api/login", json={"username": "root", "password": STRONG,
                               "totp": totp.totp(secret)})
check("re-authenticate as admin before force-logout test", r.status_code == 200)
r = c.post("/api/admin/accounts/webauthn_only/force-logout")
check("force-logout route reachable by an admin", r.status_code == 200)
check("response reports how many sessions were revoked",
      "sessions_revoked" in r.get_json())

os.environ.pop("SIEM_MODE", None)

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

"""Tests for v11.003: WebAuthn/FIDO2 credential storage, multi-key management, and the
last-key deletion guard. Full register/authenticate cryptographic ceremonies require a
real or simulated authenticator (a physical YubiKey, in practice); those are exercised by
the person testing in an actual browser, not here. What IS tested here is everything the
storage and policy layer owns: it must behave correctly regardless of what a real
ceremony produces.
"""
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


from core.accounts import AccountStore, AccountError
from core import webauthn

STRONG = "Tr0ub4dour-Quux-Vault-71!"


class _FakeCredential:
    """Stand-in for fido2's AttestedCredentialData: anything with a credential_id and a
    bytes representation works for the storage layer, which never inspects the payload."""
    def __init__(self, cred_id: bytes, blob: bytes):
        self.credential_id = cred_id
        self._blob = blob

    def __bytes__(self):
        return self._blob


def _store():
    d = tempfile.mkdtemp()
    return AccountStore(Path(d) / "accounts.db")


# -- module sanity ---------------------------------------------------------------
print("\n[module basics]")
check("RP_ID matches the loopback origin launch.py opens", webauthn.RP_ID == "127.0.0.1")
opts, state = webauthn.registration_begin("someone", [])
check("registration_begin returns options + state", opts is not None and state is not None)
check("state carries a challenge", "challenge" in state)


# -- credential storage ------------------------------------------------------------
print("\n[credential storage]")
s = _store()
s.bootstrap_admin("root", STRONG)
check("no keys initially", s.list_webauthn_credentials("root") == [])
check("has_webauthn false initially", not s.has_webauthn("root"))

cred1 = _FakeCredential(b"credential-one-id", b"credential-one-full-blob")
s.add_webauthn_credential("root", cred1, "office key")
keys = s.list_webauthn_credentials("root")
check("one key stored", len(keys) == 1)
check("key name stored correctly", keys[0]["name"] == "office key")
check("key defaults to not backup", keys[0]["is_backup"] == 0)
check("has_webauthn true after enrollment", s.has_webauthn("root"))

# duplicate credential id refused
dup = _FakeCredential(b"credential-one-id", b"different-blob-same-id")
raised = False
try:
    s.add_webauthn_credential("root", dup, "duplicate attempt")
except AccountError:
    raised = True
check("duplicate credential id refused", raised)

# second key, marked backup
cred2 = _FakeCredential(b"credential-two-id", b"credential-two-full-blob")
s.add_webauthn_credential("root", cred2, "vault key", is_backup=True)
keys = s.list_webauthn_credentials("root")
check("two keys stored", len(keys) == 2)
backup_row = [k for k in keys if k["name"] == "vault key"][0]
check("backup flag stored correctly", backup_row["is_backup"] == 1)


# -- deletion protection ------------------------------------------------------------
print("\n[deletion protection]")
s2 = _store()
s2.bootstrap_admin("root", STRONG)
c1 = _FakeCredential(b"only-key-id", b"only-key-blob")
s2.add_webauthn_credential("root", c1, "only key")
raised = False
try:
    s2.remove_webauthn_credential("root", s2.list_webauthn_credentials("root")[0]["id"])
except AccountError:
    raised = True
check("cannot remove the last key with no TOTP fallback", raised)
check("key still present after refused removal", len(s2.list_webauthn_credentials("root")) == 1)

# with TOTP enabled as a fallback, removing the last key IS allowed
secret = s2.begin_totp_enrollment("root")
from core import totp as totp_mod
s2.confirm_totp("root", totp_mod.totp(secret))
row_id = s2.list_webauthn_credentials("root")[0]["id"]
s2.remove_webauthn_credential("root", row_id)
check("last key removable once TOTP fallback exists", s2.list_webauthn_credentials("root") == [])

# with two keys, removing one is always fine (one remains)
s3 = _store()
s3.bootstrap_admin("root", STRONG)
s3.add_webauthn_credential("root", _FakeCredential(b"k1", b"blob1"), "key one")
s3.add_webauthn_credential("root", _FakeCredential(b"k2", b"blob2"), "key two")
first_id = s3.list_webauthn_credentials("root")[0]["id"]
s3.remove_webauthn_credential("root", first_id)  # should not raise
check("removing one of two keys succeeds", len(s3.list_webauthn_credentials("root")) == 1)


# -- backup toggle -------------------------------------------------------------
print("\n[backup toggle]")
s4 = _store()
s4.bootstrap_admin("root", STRONG)
s4.add_webauthn_credential("root", _FakeCredential(b"k1", b"blob1"), "key one")
row_id = s4.list_webauthn_credentials("root")[0]["id"]
s4.set_webauthn_backup("root", row_id, True)
check("backup flag can be toggled on", s4.list_webauthn_credentials("root")[0]["is_backup"] == 1)
s4.set_webauthn_backup("root", row_id, False)
check("backup flag can be toggled off", s4.list_webauthn_credentials("root")[0]["is_backup"] == 0)


# -- name required --------------------------------------------------------------
print("\n[naming]")
s5 = _store()
s5.bootstrap_admin("root", STRONG)
raised = False
try:
    s5.add_webauthn_credential("root", _FakeCredential(b"k", b"b"), "")
except AccountError:
    raised = True
check("empty key name refused", raised)


print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

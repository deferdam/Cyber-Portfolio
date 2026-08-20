"""Tests for v11.005: recovery codes and the WebAuthn-gated CLI password reset.

The native WebAuthn ceremony itself (cli_verify_key talking to a real USB device) cannot
be exercised here without physical hardware; that gap is the same honest limitation noted
for the browser ceremony in v11.003. What IS tested: the storage layer for recovery codes
(hashing, single use), and that admin_cli.cmd_reset_admin_password correctly branches to
the WebAuthn path when a key is enrolled (verified via a monkey-patched cli_verify_key,
since no real key is present in this environment) versus the confirmation-phrase fallback
when none is enrolled.
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
from core import admin_cli

STRONG = "Tr0ub4dour-Quux-Vault-71!"
STRONG2 = "Zephyr9-Marmot-Lantern-Q2#"


def _store():
    d = tempfile.mkdtemp()
    return AccountStore(Path(d) / "accounts.db")


class _FakeCredential:
    def __init__(self, cred_id: bytes, blob: bytes):
        self.credential_id = cred_id
        self._blob = blob

    def __bytes__(self):
        return self._blob


# -- recovery codes: generation and hashing ------------------------------------
print("\n[recovery codes: generation]")
s = _store()
s.bootstrap_admin("root", STRONG)
codes = s.generate_recovery_codes("root", count=10)
check("returns the requested count", len(codes) == 10)
check("codes are unique", len(set(codes)) == 10)
check("remaining count matches", s.recovery_codes_remaining("root") == 10)
check("codes not stored in clear in the db file",
      all(c not in s.db_path.read_bytes().decode("latin-1") for c in codes))


# -- recovery codes: single use -------------------------------------------------
print("\n[recovery codes: single use]")
first = codes[0]
check("valid code verifies", s.verify_recovery_code("root", first))
check("remaining count decreases", s.recovery_codes_remaining("root") == 9)
check("reusing the same code fails", not s.verify_recovery_code("root", first))
check("wrong code fails", not s.verify_recovery_code("root", "not-a-real-code"))
check("empty code fails", not s.verify_recovery_code("root", ""))


# -- recovery codes: regeneration invalidates old ones --------------------------
print("\n[recovery codes: regeneration]")
old_codes = codes[1:]
new_codes = s.generate_recovery_codes("root", count=5)
check("regenerating gives a fresh set", len(new_codes) == 5)
check("old codes no longer verify", not s.verify_recovery_code("root", old_codes[0]))
check("new codes verify", s.verify_recovery_code("root", new_codes[0]))


# -- unknown account refused -----------------------------------------------------
print("\n[recovery codes: unknown account]")
raised = False
try:
    s.generate_recovery_codes("ghost")
except AccountError:
    raised = True
check("cannot generate codes for a nonexistent account", raised)


# -- CLI reset: confirmation-phrase fallback (no key enrolled) -------------------
print("\n[CLI reset: no key enrolled -> confirmation fallback]")
s2 = _store()
s2.bootstrap_admin("root", STRONG)
prompts = iter(["root", admin_cli.CONFIRM_PHRASE])
secrets_ = iter([STRONG2, STRONG2])
out = []
rc = admin_cli.cmd_reset_admin_password(
    s2.db_path, prompt=lambda p: next(prompts), secret=lambda p: next(secrets_),
    out=out.append)
check("reset succeeds via confirmation phrase", rc == 0)
check("password actually changed", s2.verify("root", STRONG2))

# wrong phrase refused
s3 = _store()
s3.bootstrap_admin("root", STRONG)
prompts = iter(["root", "wrong phrase"])
out2 = []
rc2 = admin_cli.cmd_reset_admin_password(
    s3.db_path, prompt=lambda p: next(prompts), secret=lambda p: "unused", out=out2.append)
check("wrong confirmation phrase refused", rc2 == 1)
check("password unchanged after refused reset", s3.verify("root", STRONG))


# -- CLI reset: WebAuthn path attempted when a key IS enrolled -------------------
print("\n[CLI reset: key enrolled -> WebAuthn path attempted]")
s4 = _store()
s4.bootstrap_admin("root", STRONG)
s4.add_webauthn_credential("root", _FakeCredential(b"k1", b"blob1"), "office key")

# Monkey-patch cli_verify_key to simulate a successful touch, since no real USB device
# is present in this environment. This tests the BRANCHING logic in admin_cli, not the
# real cryptographic ceremony (which needs physical hardware, see module docstring).
import core.webauthn as webauthn_mod
import core.accounts as accounts_mod
_orig_verify = webauthn_mod.cli_verify_key
_orig_load = accounts_mod.AccountStore.load_webauthn_credential_objects
# The fake credential blobs above are not valid CBOR AttestedCredentialData, so real
# parsing would fail before even reaching cli_verify_key. This test targets the
# BRANCHING logic in admin_cli (does it try WebAuthn when a key is enrolled?), not binary
# parsing, so we bypass real parsing here the same way we bypass the real ceremony.
accounts_mod.AccountStore.load_webauthn_credential_objects = lambda self, u: ["placeholder"]
webauthn_mod.cli_verify_key = lambda creds, prompt=print: True
try:
    prompts = iter(["root"])
    secrets_ = iter([STRONG2, STRONG2])
    out3 = []
    rc3 = admin_cli.cmd_reset_admin_password(
        s4.db_path, prompt=lambda p: next(prompts), secret=lambda p: next(secrets_),
        out=out3.append)
    check("reset succeeds when the (simulated) key verifies", rc3 == 0)
    check("no confirmation phrase was needed (key path taken)",
          not any(admin_cli.CONFIRM_PHRASE in o for o in out3))
    check("password actually changed via key path", s4.verify("root", STRONG2))
finally:
    webauthn_mod.cli_verify_key = _orig_verify
    accounts_mod.AccountStore.load_webauthn_credential_objects = _orig_load

# Simulate a failed key verification -> reset must be refused.
s5 = _store()
s5.bootstrap_admin("root", STRONG)
s5.add_webauthn_credential("root", _FakeCredential(b"k1", b"blob1"), "office key")
accounts_mod.AccountStore.load_webauthn_credential_objects = lambda self, u: ["placeholder"]
webauthn_mod.cli_verify_key = lambda creds, prompt=print: False
try:
    prompts = iter(["root"])
    out4 = []
    rc4 = admin_cli.cmd_reset_admin_password(
        s5.db_path, prompt=lambda p: next(prompts), secret=lambda p: "unused",
        out=out4.append)
    check("reset refused when key verification fails", rc4 == 1)
    check("password unchanged after failed key verification", s5.verify("root", STRONG))
finally:
    webauthn_mod.cli_verify_key = _orig_verify
    accounts_mod.AccountStore.load_webauthn_credential_objects = _orig_load

# No physical device plugged in -> WebauthnUnavailable is handled gracefully.
s6 = _store()
s6.bootstrap_admin("root", STRONG)
s6.add_webauthn_credential("root", _FakeCredential(b"k1", b"blob1"), "office key")
def _raise_unavailable(creds, prompt=print):
    raise webauthn_mod.WebauthnUnavailable("No USB security key detected.")
accounts_mod.AccountStore.load_webauthn_credential_objects = lambda self, u: ["placeholder"]
webauthn_mod.cli_verify_key = _raise_unavailable
try:
    prompts = iter(["root"])
    out5 = []
    rc5 = admin_cli.cmd_reset_admin_password(
        s6.db_path, prompt=lambda p: next(prompts), secret=lambda p: "unused",
        out=out5.append)
    check("reset refused (not crashed) when no USB device is present", rc5 == 1)
finally:
    webauthn_mod.cli_verify_key = _orig_verify
    accounts_mod.AccountStore.load_webauthn_credential_objects = _orig_load


print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

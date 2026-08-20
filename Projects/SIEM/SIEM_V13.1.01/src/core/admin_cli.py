"""CLI bootstrap and recovery commands.

Two commands, both network-free (no HTTP surface):

  create-admin          Create the first admin on a virgin install. Refuses if bootstrap
                        is already sealed (master invariant). Password typed twice, masked.

  reset-admin-password  Recovery path for a forgotten admin password. Gated by a native
                        WebAuthn (USB security key) check when a key is enrolled on the
                        account: machine access alone is not enough, the physical key
                        must be presented and touched. Falls back to a typed STRONG
                        CONFIRMATION phrase if no key is enrolled, so an admin who never
                        set up WebAuthn is not locked out of recovery.

The functions take injectable input/output/getpass callables so they are unit-testable
without a real terminal.
"""
from __future__ import annotations

import getpass as _getpass
from pathlib import Path
from typing import Callable

from .accounts import AccountStore, AccountError

CONFIRM_PHRASE = "RESET ADMIN PASSWORD"


def cmd_create_admin(db_path: Path,
                     prompt: Callable[[str], str] = input,
                     secret: Callable[[str], str] = _getpass.getpass,
                     out: Callable[[str], None] = print) -> int:
    store = AccountStore(db_path)

    if store.is_sealed():
        out("Bootstrap is already sealed: an admin exists. "
            "Use reset-admin-password for recovery.")
        return 1

    username = prompt("Choose the admin username: ").strip()
    if not username:
        out("Username must not be empty.")
        return 1

    pw1 = secret("Choose a password: ")
    pw2 = secret("Repeat the password: ")
    if pw1 != pw2:
        out("Passwords do not match.")
        return 1

    try:
        store.bootstrap_admin(username, pw1)
    except AccountError as e:
        out("Refused: %s" % e)
        return 1

    out("Admin '%s' created. Bootstrap is now sealed permanently." % username)
    return 0


def cmd_reset_admin_password(db_path: Path,
                             prompt: Callable[[str], str] = input,
                             secret: Callable[[str], str] = _getpass.getpass,
                             out: Callable[[str], None] = print) -> int:
    store = AccountStore(db_path)

    username = prompt("Admin username to reset: ").strip()
    acct = store.get(username)
    if not acct or acct["role"] != "admin":
        out("No such admin account.")
        return 1

    out("WARNING: this resets the password for admin '%s'." % username)

    if store.has_webauthn(username):
        # Machine access alone is no longer enough: the physical key must be presented
        # and touched. This closes the gap the plain confirmation phrase left open (a
        # compromised host could otherwise reset the password with no further proof).
        from . import webauthn as webauthn_mod
        out("A security key is enrolled on this account. Verifying it now is required.")
        creds = store.load_webauthn_credential_objects(username)
        try:
            ok = webauthn_mod.cli_verify_key(creds, prompt=out)
        except webauthn_mod.WebauthnUnavailable as e:
            out(str(e))
            return 1
        if not ok:
            out("Security key verification failed. Aborted.")
            return 1
        out("Security key verified.")
    else:
        # No key enrolled: fall back to the typed confirmation phrase, so an admin who
        # never set up WebAuthn is not locked out of their own recovery path.
        out("This recovery path is currently protected by confirmation only. "
            "Enroll a security key to require it for future resets.")
        typed = prompt('Type exactly "%s" to proceed: ' % CONFIRM_PHRASE)
        if typed != CONFIRM_PHRASE:
            out("Confirmation phrase did not match. Aborted.")
            return 1

    pw1 = secret("New password: ")
    pw2 = secret("Repeat new password: ")
    if pw1 != pw2:
        out("Passwords do not match.")
        return 1

    try:
        store.set_password(username, pw1)
    except AccountError as e:
        out("Refused: %s" % e)
        return 1

    out("Password for admin '%s' has been reset." % username)
    return 0

"""Authentication seam.

This is the SINGLE place where authentication plugs in. In v10 it does not enforce
anything: the app is single-user/local, so every request resolves to one local operator.
Establishing the seam now means v11 can add real login, sessions and MFA by filling in
these functions, without scattering auth checks across the codebase.

v11 design (recorded here so it is not lost):
  * Primary factor: a password, stored only as a salted hash (argon2id or bcrypt), never
    in clear, never logged.
  * Second factor (MFA), two supported paths:
      - TOTP (RFC 6238): works with any authenticator app, and with the YubiKey via the
        Yubico Authenticator (OATH-TOTP). Simple, no special browser support needed.
      - FIDO2 / WebAuthn: hardware security keys such as the YubiKey 5C register and
        authenticate directly in the browser. This is the strongest option and supports
        passwordless / phishing-resistant login. Caveat: WebAuthn requires a secure
        context (HTTPS) and a fixed origin, which is why it is tied to the v11 server
        transport (TLS), not the current loopback dev server.
  * Roles: operator / manager / admin, checked server-side via require_role().
  * Sessions: signed, httpOnly cookie or bearer token; idle timeout re-locks (the 30 min
    idle lock idea), full re-auth on expiry.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    name: str
    role: str = "operator"        # operator | manager | admin
    authenticated: bool = False   # True only after a real login (v11)
    mfa: bool = False             # True only after a verified second factor (v11)


# v10 single-user identity. No login happened; this is a placeholder operator so that
# endpoints can already read a principal and v11 can swap in real resolution.
LOCAL_OPERATOR = Principal(name="local-operator", role="operator",
                           authenticated=False, mfa=False)


def current_principal(request=None, mode="local") -> Principal:
    """Resolve who is making this request. v10: always the local operator. v11 will read a
    verified session here and return the authenticated principal."""
    return LOCAL_OPERATOR


def require_auth(principal: Principal, mode: str):
    """Auth gate. v10: no-op (returns None = allowed). v11 will return a challenge/denial
    when the principal is not authenticated (and not MFA-verified for sensitive actions)."""
    return None


def require_role(principal: Principal, role: str):
    """Role gate. v10: no-op. v11 will enforce operator < manager < admin server-side."""
    return None

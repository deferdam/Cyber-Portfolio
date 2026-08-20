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

# Anonymous principal for an unauthenticated request once login exists (v11.001).
ANONYMOUS = Principal(name="anonymous", role="operator",
                      authenticated=False, mfa=False)


def principal_from_session(session: dict) -> "Principal":
    """Build an authenticated Principal from a resolved server session dict
    {username, role}. mfa stays False until a second factor is verified (later v11)."""
    return Principal(name=session["username"], role=session.get("role", "operator"),
                     authenticated=True, mfa=False)


def require_auth(principal: Principal, mode: str):
    """Auth gate. In server mode an unauthenticated principal is denied. In local mode it
    is allowed unless login was explicitly enabled (handled in app.py)."""
    if mode == "server" and not principal.authenticated:
        return "authentication required"
    return None


def require_role(principal: Principal, role: str):
    """Role gate: operator < manager < admin, enforced server-side."""
    order = {"operator": 0, "manager": 1, "admin": 2}
    if order.get(principal.role, 0) < order.get(role, 99):
        return "insufficient role"
    return None

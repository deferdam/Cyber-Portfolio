"""app.py - Mini SOAR web server (v8).

Run:
    cd SIEM_V8
    $env:PYTHONPATH = "src"     (PowerShell)
    py src/server/app.py
    open http://localhost:5000

Mode is chosen at launch via SIEM_MODE (local|server), default local.
In local mode the file browser is unrestricted (single operator on their own
machine). In server mode (v10) it is confined to SIEM_SCAN_ROOT.
"""
from __future__ import annotations

import json
import os
import hmac
import secrets
import string
import subprocess
import sys
import threading
import time
import webbrowser
from collections import Counter
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, Response, jsonify, request, stream_with_context, g, send_from_directory

BASE    = Path(__file__).parent.parent.parent
SRC_DIR = BASE / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
from core import vault
from core import auth
from core import accounts as accounts_mod
from core import bootstrap as bootstrap_mod
from core import webauthn as webauthn_mod
from core import tls as tls_mod
from core import update_check as update_mod
from core import active_response as ar_mod
from core.ai import autonomy as ai_autonomy_mod
from core.ai import features as ai_features_mod
from core.ai import metrics as ai_metrics_mod
from core.ai.triage import AITriage
from core.ai import triage as ai_triage_mod
from core.ai.triage import CATEGORY_TICKET_TRIAGE
from core.ai import tickets as ai_tickets_mod
from core.ai import llm as ai_llm_mod
from core import model_import as model_import_mod
from core.ai.provenance import ProvenanceStore
from core.ai.registry import ModelRegistry
MODE      = os.environ.get("SIEM_MODE", "local").lower()
IS_SHOWCASE = MODE == "showcase"
IS_SERVER = MODE == "server"
# The mode is a TRUSTED signal taken only from the environment set by the
# operator/launcher, never from client input, so it cannot be spoofed by a request.
# Server mode requires real accounts and login (v11); binding beyond loopback still
# needs an explicit operator opt-in below, since it increases attack surface
# regardless of authentication (TLS also becomes mandatory at that point, see v11.006).
READONLY_HOST = True


def _safe_bind_host(requested, allow_public):
    """Fail-safe binding. Loopback is always allowed; a public bind requires an explicit
    operator opt-in (SIEM_ALLOW_PUBLIC=1), since exposing the app beyond loopback is a
    deliberate decision even with accounts, MFA and TLS in place. Returns
    (host, warning) or raises."""
    if requested in ("127.0.0.1", "localhost", "::1"):
        return requested, None
    if not allow_public:
        raise RuntimeError(
            "refusing to bind " + requested + ": exposing beyond loopback requires an "
            "explicit operator opt-in. Use 127.0.0.1, or set SIEM_ALLOW_PUBLIC=1 to "
            "override deliberately (TLS becomes mandatory at that point).")
    return requested, ("WARNING: bound to a public interface. Confirm accounts are "
                       "created, TLS is active, and this network is trusted.")
# Showcase is a sealed demo sandbox: fake data only, read from a SEPARATE output
# directory so it can never read or corrupt real local data. File access, the run
# pipeline and the profile are disabled in this mode (see the guards below).
OUT_DIR = BASE / "out" / ("showcase" if IS_SHOWCASE else "large")
TICKETS = OUT_DIR / "tickets.jsonl"
SIGNALS = OUT_DIR / "signals.jsonl"
vault.configure(OUT_DIR)

SCAN_ROOT = Path(os.environ.get("SIEM_SCAN_ROOT", str(BASE)))
ALLOWED_FORMATS = ("json", "syslog", "auto", "csv", "elastic", "snort", "evtx", "pcap", "auditd")

# Identity store on its own trust path, outside out/. Never vault-encrypted.
DATA_DIR = BASE / "data"
ACCOUNTS_DB = DATA_DIR / "accounts.db"
_account_store = accounts_mod.AccountStore(ACCOUNTS_DB)
# Web bootstrap token: only armed if login is required (server mode), no admin exists yet AND
# bootstrap is not sealed. Local/showcase modes have no auth, so they never bootstrap an admin.
_bootstrap_token = bootstrap_mod.BootstrapToken()
_LOGIN_REQUIRED_ENV = IS_SERVER or os.environ.get("SIEM_REQUIRE_LOGIN") == "1"
if _LOGIN_REQUIRED_ENV and not _account_store.is_sealed() and not _account_store.admin_exists():
    # Arm the one-time setup token and announce it on the terminal only.
    _bootstrap_token.generate_and_announce()

# WebAuthn ceremony state (the "state" object from register_begin/authenticate_begin)
# lives server-side only, in memory, keyed by a short-lived ceremony id. It is NEVER sent
# to the client and NEVER persisted; a ceremony not completed within a few minutes is
# simply garbage (process restart or key eviction clears it).
_webauthn_ceremonies = {}

# Single source of truth for the app version lives in frontend.py's VERSION constant;
# extracted here instead of duplicating the string, so bumping one file cannot silently
# desync from the other.
def _current_version() -> str:
    from server import frontend as frontend_mod
    m = __import__("re").search(r"const VERSION='([^']+)'", frontend_mod.FRONTEND_HTML)
    return m.group(1) if m else "unknown"

UPDATE_REPO = "deferdam/Cyber-Portfolio"
_update_checker = update_mod.WeeklyUpdateChecker(UPDATE_REPO, _current_version())
_active_response = ar_mod.ActiveResponseStore(DATA_DIR / "active_response.db")
# Quarantine is confined to the app's own output/data directories, never an arbitrary
# system path, consistent with the read-only-host posture established in v10.
_QUARANTINE_ROOTS = [OUT_DIR, DATA_DIR]

# AI subsystem (v12). Autonomy policy, provenance and the model registry are always
# instantiated (an admin can configure policy ahead of time); the classifier itself stays
# OFF by default via SIEM_AI_ENABLED, per the v12.0 seam invariant. Nothing here is wired to
# ticket handling yet (that lands with the v12.2 AI ticket category); this is the panel's
# control surface only.
_ai_autonomy = ai_autonomy_mod.AutonomyStore(DATA_DIR / "ai_autonomy.db")
_ai_provenance = ProvenanceStore(DATA_DIR / "ai_provenance.db")
_ai_registry = ModelRegistry(DATA_DIR / "ai_models")
_ai_triage = AITriage(_ai_provenance, _ai_registry)
# Apply the persisted recall bias (set from the app) if one was saved.
try:
    _ai_triage.recall_margin = float(_ai_autonomy.get_setting(
        "recall_bias", _ai_triage.recall_margin))
except (TypeError, ValueError):
    pass
_ai_tickets = ai_tickets_mod.AITicketStore(DATA_DIR / "ai_tickets.db")
# Optional LLM explainer. Off by default; loopback-only; explanation-only; never the verdict.
_ai_llm = ai_llm_mod.LocalLLMExplainer()

app = Flask(__name__, static_folder=None)


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(vault.unpack_line(line))
            except Exception:
                pass
    return rows


def _write_tickets(tickets: List[Dict]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(TICKETS, "w", encoding="utf-8") as f:
        for t in tickets:
            f.write(vault.pack_line(t) + "\n")


def _base_label(signal_type: str) -> str:
    return "merged" if signal_type.startswith("merged[") else signal_type


def _human(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def _within_scan_root(target: Path) -> bool:
    root = SCAN_ROOT.resolve()
    return target == root or root in target.parents


# -- Config --------------------------------------------------------------------

SESSION_COOKIE = "siem_session"
# Set to True once the __main__ startup block actually enables TLS. Cookies use this to
# decide the Secure flag: mark it Secure whenever the connection really is HTTPS, plain
# otherwise (Secure on plain HTTP would just make the cookie unusable, not safer).
TLS_ACTIVE = False
# Login is mandatory in server mode; in local mode it is OFF unless explicitly enabled.
REQUIRE_LOGIN = IS_SERVER or os.environ.get("SIEM_REQUIRE_LOGIN") == "1"
# Endpoints reachable without a session even when login is required.
_AUTH_EXEMPT = {"/api/login", "/api/logout", "/api/setup", "/api/setup/status",
                "/api/whoami", "/api/config", "/"}


@app.before_request
def _resolve_principal():
    # Authentication seam. Resolve a real server session from the cookie if present;
    # otherwise the principal is anonymous. In server mode (or when login is enabled in
    # local mode) protected routes require an authenticated principal.
    token = request.cookies.get(SESSION_COOKIE, "")
    principal = auth.ANONYMOUS
    if token:
        sess = _account_store.resolve_session(token)
        if sess:
            principal = auth.principal_from_session(sess)
    if not principal.authenticated and not REQUIRE_LOGIN:
        # Local convenience: single operator, no login configured.
        principal = auth.LOCAL_OPERATOR
    g.principal = principal

    if REQUIRE_LOGIN:
        path = request.path.rstrip("/") or "/"
        exempt = path in _AUTH_EXEMPT or path == ""
        if not exempt and not g.principal.authenticated:
            return jsonify({"error": "authentication required"}), 401


# Content-Security-Policy: self-contained app (no CDN). connect-src 'self' means a page
# cannot exfiltrate to an external origin even if some script slipped through (anti-C2,
# defense in depth behind output escaping); object/base/frame-ancestors are locked down.
_CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


@app.after_request
def _security_headers(resp):
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return resp


@app.route("/api/whoami")
def api_whoami():
    p = g.principal
    return jsonify({"name": p.name, "role": p.role,
                    "authenticated": p.authenticated, "mfa": p.mfa})


def _is_loopback_request() -> bool:
    """True only if the request originates from the local machine. Defense for /setup."""
    addr = request.remote_addr or ""
    return addr in ("127.0.0.1", "::1", "localhost")


def _bootstrap_open() -> bool:
    """Bootstrap is open only on a virgin install of a mode that actually requires login
    (server mode). Local and showcase modes have no accounts, so setup never applies there."""
    return (REQUIRE_LOGIN and (not _account_store.is_sealed())
            and (not _account_store.admin_exists()))


@app.route("/api/setup/status", methods=["GET"])
def api_setup_status():
    """Tells the UI whether to show the first-run setup form. 404 once sealed so the
    route looks non-existent to anyone probing after bootstrap."""
    if not _bootstrap_open():
        return jsonify({"error": "not found"}), 404
    if not _is_loopback_request():
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"setup_required": True})


@app.route("/api/setup", methods=["POST"])
def api_setup():
    """Create the FIRST admin via the one-time web token. Hardened with six layers:
    (1) 404 if sealed/admin-exists, (2) loopback-only, (3) constant-time token check,
    (4) single-use token, (5) short TTL window, (6) can only create the first admin,
    never mutate a role. The master invariant lives in AccountStore.bootstrap_admin."""
    # Layer 1: existence/seal check. 404, not 403, so the route appears non-existent.
    if not _bootstrap_open():
        return jsonify({"error": "not found"}), 404
    # Layer 2: loopback only.
    if not _is_loopback_request():
        return jsonify({"error": "forbidden"}), 403

    body = request.get_json(silent=True) or {}
    token = body.get("token", "")
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    # Layers 3-5: token must be live (TTL), unconsumed, and match in constant time.
    if not _bootstrap_token.verify(token):
        return jsonify({"error": "invalid or expired setup token"}), 403

    # The one-time token is printed in clear on the terminal stdout: it is designed to leak
    # and is single-use/short-TTL for that reason. A password is a durable secret that must
    # never have appeared in clear anywhere, so reusing the token as the password is refused
    # (constant-time). The token is NOT burned here, so the operator can retry with a real
    # password within the same TTL window.
    if password and hmac.compare_digest(password, token):
        return jsonify({"error": "the setup token cannot be reused as your password"}), 400

    # Layer 6 + master invariant: bootstrap_admin refuses if sealed or an admin exists,
    # and can ONLY create an admin on a virgin base.
    try:
        _account_store.bootstrap_admin(username, password)
    except accounts_mod.AccountError as e:
        # Do not burn the token on a policy error (e.g. weak password): let the operator
        # retry with a stronger password within the TTL.
        return jsonify({"error": str(e)}), 400

    # Success: burn the token. Bootstrap is now sealed by bootstrap_admin().
    _bootstrap_token.consume()
    return jsonify({"ok": True, "username": username})


def _complete_login(username: str):
    """Shared final step for every successful login path (password+TOTP, WebAuthn):
    clear the failure counter, record the login, open a session, and opportunistically
    purge any expired sessions system-wide. Purging here (a naturally low-frequency,
    already-authenticated event) avoids running that query on every single request,
    while keeping the sessions table from growing unbounded."""
    _account_store.clear_failed_logins(username)
    _account_store.touch_login(username)
    _account_store.purge_expired_sessions()
    token = _account_store.create_session(username)
    resp = jsonify({"ok": True, "username": username})
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="Strict",
                    secure=TLS_ACTIVE, path="/")
    return resp


@app.route("/api/login", methods=["POST"])
def api_login():
    """Authenticate and open a server-side session. Two steps when TOTP is enabled:
    password first, then the 6-digit code (or a one-time recovery code as a fallback).
    Generic failure message and a per-account rate limit defend against enumeration and
    brute force."""
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    totp_code = (body.get("totp") or "").strip()
    recovery_code = (body.get("recovery_code") or "").strip()

    GENERIC = (jsonify({"error": "invalid username or password"}), 401)

    if not username or not password:
        return GENERIC
    if _account_store.is_rate_limited(username):
        return jsonify({"error": "too many attempts, try again later"}), 429

    if not _account_store.verify(username, password):
        _account_store.record_failed_login(username)
        return GENERIC

    # Password is correct. If TOTP OR a security key is enrolled, require the second
    # factor before issuing a session. Checking TOTP alone here was a real bug: an
    # account with ONLY a WebAuthn key enrolled (no TOTP) would otherwise log in with
    # just a password, silently bypassing its second factor entirely. We do NOT clear
    # the failed-login counter until full success, so brute force against the password
    # stays throttled regardless of which second factor path is taken.
    status = _account_store.totp_status(username)
    mfa_enrolled = status["enabled"] or _account_store.has_webauthn(username)
    if mfa_enrolled:
        if recovery_code:
            # Recovery code path: consumed atomically, single-use, bypasses whichever
            # second factor is enrolled (TOTP and/or WebAuthn) for this one login.
            if not _account_store.verify_recovery_code(username, recovery_code):
                _account_store.record_failed_login(username)
                return jsonify({"error": "invalid or already-used recovery code",
                               "mfa_required": True}), 401
        elif not totp_code:
            # No code supplied: tell the client a second factor is needed. The frontend
            # offers both a TOTP input and a "use a security key instead" button, which
            # routes to /api/webauthn/login/begin+complete (a separate ceremony that
            # re-verifies the password independently before checking enrolled keys).
            return jsonify({"mfa_required": True}), 401
        elif not status["enabled"]:
            # A code was supplied but this account has no TOTP enrolled at all (only a
            # security key): a TOTP code can never be valid here, so fail without
            # bothering to hash-compare against nothing.
            _account_store.record_failed_login(username)
            return jsonify({"error": "invalid code", "mfa_required": True}), 401
        elif not _account_store.verify_totp(username, totp_code):
            _account_store.record_failed_login(username)
            return jsonify({"error": "invalid code", "mfa_required": True}), 401

    return _complete_login(username)


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Destroy the current server session (revocable by design)."""
    token = request.cookies.get(SESSION_COOKIE, "")
    _account_store.revoke_session(token)
    resp = jsonify({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


def require_login(view):
    """Route decorator: reject with 401 unless the request carries an authenticated
    principal. Factors out the repeated check across the MFA management routes."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.principal.authenticated:
            return jsonify({"error": "authentication required"}), 401
        return view(*args, **kwargs)
    return wrapped


def require_admin(view):
    """Route decorator: reject with 403 unless the principal holds the admin role.
    Implies require_login (401 first if not authenticated at all)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.principal.authenticated:
            return jsonify({"error": "authentication required"}), 401
        err = auth.require_role(g.principal, "admin")
        if err:
            return jsonify({"error": err}), 403
        return view(*args, **kwargs)
    return wrapped


def require_manager(view):
    """Route decorator: reject unless the principal is manager OR admin. Used for the AI
    ticket container: only responsible/senior analysts (manager) and admins may see and
    correct the AI's dispositions; operators are denied server-side."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.principal.authenticated:
            return jsonify({"error": "authentication required"}), 401
        err = auth.require_role(g.principal, "manager")
        if err:
            return jsonify({"error": err}), 403
        return view(*args, **kwargs)
    return wrapped


@app.route("/api/mfa/status", methods=["GET"])
@require_login
def api_mfa_status():
    """Report the current user's TOTP state."""
    return jsonify(_account_store.totp_status(g.principal.name))


@app.route("/api/mfa/enroll", methods=["POST"])
@require_login
def api_mfa_enroll():
    """Begin TOTP enrollment: generate a pending secret and return it plus the otpauth URI
    so the client can render a QR and offer the text fallback. Not active until confirmed."""
    try:
        secret = _account_store.begin_totp_enrollment(g.principal.name)
        uri = _account_store.totp_provisioning_uri(g.principal.name)
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"secret": secret, "otpauth_uri": uri})


@app.route("/api/mfa/confirm", methods=["POST"])
@require_login
def api_mfa_confirm():
    """Enable TOTP only after the user proves a valid current code (phone is synced)."""
    body = request.get_json(silent=True) or {}
    code = (body.get("code") or "").strip()
    if _account_store.confirm_totp(g.principal.name, code):
        return jsonify({"ok": True, "enabled": True})
    return jsonify({"error": "invalid code"}), 400


@app.route("/api/mfa/disable", methods=["POST"])
@require_login
def api_mfa_disable():
    """Disable TOTP. Requires a valid current code, so an attacker on a hijacked session
    cannot strip the second factor without also having the physical/app second factor."""
    body = request.get_json(silent=True) or {}
    code = (body.get("code") or "").strip()
    if not _account_store.verify_totp(g.principal.name, code):
        return jsonify({"error": "invalid code"}), 400
    _account_store.disable_totp(g.principal.name)
    return jsonify({"ok": True, "enabled": False})


def _has_any_mfa(username: str) -> bool:
    return _account_store.totp_status(username)["enabled"] or \
        _account_store.has_webauthn(username)


@app.route("/api/mfa/recovery-codes/status", methods=["GET"])
@require_login
def api_recovery_codes_status():
    return jsonify({"remaining": _account_store.recovery_codes_remaining(g.principal.name)})


@app.route("/api/mfa/recovery-codes/generate", methods=["POST"])
@require_login
def api_recovery_codes_generate():
    """Generate a fresh set of one-time recovery codes, shown to the user ONCE. Requires
    at least one MFA method already enabled: recovery codes are a fallback for when TOTP
    or a security key is unavailable, not a replacement for having a second factor at
    all. Regenerating invalidates any previously issued codes (see
    AccountStore.generate_recovery_codes)."""
    if not _has_any_mfa(g.principal.name):
        return jsonify({"error": "enable an authenticator app or a security key "
                                 "before generating recovery codes"}), 400
    try:
        codes = _account_store.generate_recovery_codes(g.principal.name)
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"codes": codes})


_CEREMONY_TTL = 300  # 5 minutes to complete a WebAuthn ceremony


def _stash_ceremony(state) -> str:
    cid = secrets.token_urlsafe(24)
    _webauthn_ceremonies[cid] = (state, time.monotonic())
    # Opportunistic cleanup of stale ceremonies.
    stale = [k for k, (_, t) in _webauthn_ceremonies.items()
             if time.monotonic() - t > _CEREMONY_TTL]
    for k in stale:
        _webauthn_ceremonies.pop(k, None)
    return cid


def _pop_ceremony(cid: str):
    entry = _webauthn_ceremonies.pop(cid, None)
    if not entry:
        return None
    state, t = entry
    if time.monotonic() - t > _CEREMONY_TTL:
        return None
    return state


@app.route("/api/webauthn/keys", methods=["GET"])
@require_login
def api_webauthn_keys():
    """List the current user's enrolled keys (name, backup flag, dates)."""
    return jsonify(_account_store.list_webauthn_credentials(g.principal.name))


@app.route("/api/webauthn/register/begin", methods=["POST"])
@require_login
def api_webauthn_register_begin():
    """Start enrollment of a new key for the current user."""
    existing = _account_store.load_webauthn_credential_objects(g.principal.name)
    options, state = webauthn_mod.registration_begin(g.principal.name, existing)
    cid = _stash_ceremony(state)
    return jsonify({"ceremony_id": cid, "options": options})


@app.route("/api/webauthn/register/complete", methods=["POST"])
@require_login
def api_webauthn_register_complete():
    """Finish enrollment: verify the browser's response and store the new credential."""
    body = request.get_json(silent=True) or {}
    cid = body.get("ceremony_id", "")
    name = (body.get("name") or "").strip()
    is_backup = bool(body.get("is_backup"))
    state = _pop_ceremony(cid)
    if not state:
        return jsonify({"error": "ceremony expired or invalid, try again"}), 400
    if not name:
        return jsonify({"error": "key name is required"}), 400
    try:
        credential = webauthn_mod.registration_complete(state, body.get("response") or {})
        _account_store.add_webauthn_credential(g.principal.name, credential, name, is_backup)
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        # Any WebAuthn verification failure (bad signature, wrong origin, replay) lands
        # here; never leak the exact reason, it is not actionable for the client and
        # could aid an attacker probing the ceremony.
        return jsonify({"error": "key verification failed"}), 400
    return jsonify({"ok": True})


@app.route("/api/webauthn/keys/<int:row_id>", methods=["DELETE"])
@require_login
def api_webauthn_delete_key(row_id):
    """Remove a key. Refuses to remove the last remaining second factor (see
    remove_webauthn_credential); the account must always keep a way in."""
    try:
        _account_store.remove_webauthn_credential(g.principal.name, row_id)
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"ok": True})


@app.route("/api/webauthn/keys/<int:row_id>/backup", methods=["POST"])
@require_login
def api_webauthn_set_backup(row_id):
    body = request.get_json(silent=True) or {}
    _account_store.set_webauthn_backup(g.principal.name, row_id, bool(body.get("is_backup")))
    return jsonify({"ok": True})


@app.route("/api/webauthn/login/begin", methods=["POST"])
def api_webauthn_login_begin():
    """Start a WebAuthn verification at LOGIN time, before a session exists. The caller
    must already have passed the password step (mfa_required). We re-verify the password
    here so this route cannot be used to enumerate who has keys without a valid password."""
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password or not _account_store.verify(username, password):
        return jsonify({"error": "invalid username or password"}), 401
    creds = _account_store.load_webauthn_credential_objects(username)
    if not creds:
        return jsonify({"error": "no security key enrolled"}), 400
    options, state = webauthn_mod.authentication_begin(creds)
    cid = _stash_ceremony((state, username))
    return jsonify({"ceremony_id": cid, "options": options})


@app.route("/api/webauthn/login/complete", methods=["POST"])
def api_webauthn_login_complete():
    """Finish the WebAuthn login: verify the signature, then open a session exactly like
    a normal password+TOTP login would."""
    body = request.get_json(silent=True) or {}
    cid = body.get("ceremony_id", "")
    entry = _pop_ceremony(cid)
    if not entry:
        return jsonify({"error": "ceremony expired or invalid, try again"}), 400
    state, username = entry
    if _account_store.is_rate_limited(username):
        return jsonify({"error": "too many attempts, try again later"}), 429
    creds = _account_store.load_webauthn_credential_objects(username)
    try:
        used = webauthn_mod.authentication_complete(state, creds, body.get("response") or {})
    except Exception:
        _account_store.record_failed_login(username)
        return jsonify({"error": "key verification failed"}), 401

    _account_store.touch_webauthn_credential(bytes(used.credential_id).hex()
                                             if hasattr(used, "credential_id") else "")
    return _complete_login(username)


def _dispatch_sensitive_action(action: str, payload: dict, actor: str) -> dict:
    """Route a sensitive action through degraded mode (fewer than 2 admins: execute
    immediately, audited as degraded) or dual control (2+ admins: create a pending
    approval request instead of executing). This is the single place that decides which
    path applies, so no route can accidentally bypass it."""
    if _account_store.dual_control_active():
        rid = _account_store.submit_request(action, payload, actor)
        _account_store.audit(actor, "submit_request:%s" % action,
                             "request #%d awaiting a second admin's approval" % rid)
        return {"status": "pending_approval", "request_id": rid}
    # Degraded mode (fewer than 2 admins): no second admin exists to approve anything, so
    # we apply directly rather than create a request that could never be decided. The
    # anti-self-approval invariant in decide_request is untouched; this path never calls
    # it. The gap is made visible via the audit trail's degraded flag.
    if action == "create_account":
        _account_store.create_user(payload["username"], payload["password"],
                                   payload.get("role", "operator"))
    elif action == "change_role":
        _account_store.change_role(payload["username"], payload["new_role"])
    elif action == "delete_account":
        _account_store.delete_account(payload["username"])
    elif action == "delete_other_webauthn_key":
        _account_store.remove_webauthn_credential(payload["username"],
                                                   payload["credential_row_id"])
    elif action == "reset_other_password":
        _account_store.set_password(payload["username"], payload["new_password"])
    elif action == "ban_ip_real":
        _active_response.ban_ip(payload["ip"], actor,
                               current_session_ip=payload.get("current_session_ip"),
                               duration_hours=payload.get("duration_hours"), real=True)
    elif action == "quarantine_file_real":
        _active_response.quarantine_file(payload["path"], actor,
                                        allowed_roots=_QUARANTINE_ROOTS, real=True)
    elif action == "set_ai_ceiling_auto_close":
        _ai_autonomy.set_ceiling(payload["category"], ai_autonomy_mod.AUTO_CLOSE, actor)
    elif action == "disengage_ai_kill_switch":
        _ai_autonomy.disengage_kill_switch(actor)
    elif action == "train_ai_model":
        version = _ai_triage.train_category(payload["category"])
        if version is None:
            raise accounts_mod.AccountError(
                "no human-validated labels yet for category %r" % payload["category"])
    else:
        raise accounts_mod.AccountError("Unknown sensitive action: %s" % action)
    _account_store.audit(actor, "%s:degraded" % action, str(payload), degraded=True)
    return {"status": "applied_degraded"}


@app.route("/api/admin/status", methods=["GET"])
@require_admin
def api_admin_status():
    return jsonify({
        "admin_count": _account_store.admin_count(),
        "dual_control_active": _account_store.dual_control_active(),
    })


@app.route("/api/admin/accounts", methods=["GET"])
@require_admin
def api_admin_list_accounts():
    return jsonify(_account_store.list_accounts())


@app.route("/api/admin/accounts", methods=["POST"])
@require_admin
def api_admin_create_account():
    body = request.get_json(silent=True) or {}
    payload = {"username": (body.get("username") or "").strip(),
              "password": body.get("password") or "",
              "role": body.get("role") or "operator"}
    if not payload["username"]:
        return jsonify({"error": "username is required"}), 400
    try:
        result = _dispatch_sensitive_action("create_account", payload, g.principal.name)
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


@app.route("/api/admin/accounts/<username>/role", methods=["POST"])
@require_admin
def api_admin_change_role(username):
    body = request.get_json(silent=True) or {}
    payload = {"username": username, "new_role": body.get("new_role") or ""}
    try:
        result = _dispatch_sensitive_action("change_role", payload, g.principal.name)
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


@app.route("/api/admin/accounts/<username>", methods=["DELETE"])
@require_admin
def api_admin_delete_account(username):
    payload = {"username": username}
    try:
        result = _dispatch_sensitive_action("delete_account", payload, g.principal.name)
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


@app.route("/api/admin/accounts/<username>/reset-password", methods=["POST"])
@require_admin
def api_admin_reset_password(username):
    body = request.get_json(silent=True) or {}
    payload = {"username": username, "new_password": body.get("new_password") or ""}
    try:
        result = _dispatch_sensitive_action("reset_other_password", payload, g.principal.name)
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


@app.route("/api/admin/accounts/<username>/force-logout", methods=["POST"])
@require_admin
def api_admin_force_logout(username):
    """Kill every active session for a user immediately. Deliberately NOT gated by dual
    control: this is a protective/defensive action (suspected compromise, urgent
    incident response), not a destructive one, and it is fully reversible (the user
    simply logs back in). Requiring a second admin's approval here would defeat the
    point: the whole value of a forced logout is that it happens NOW."""
    n = _account_store.revoke_all_sessions(username)
    _account_store.audit(g.principal.name, "force_logout",
                         "revoked %d session(s) for %s" % (n, username))
    return jsonify({"ok": True, "sessions_revoked": n})


@app.route("/api/account/profile", methods=["GET"])
@require_login
def api_account_profile_get():
    """Read the caller's own cosmetic profile (display name, email)."""
    return jsonify(_account_store.get_profile(g.principal.name))


@app.route("/api/account/profile", methods=["PUT"])
@require_login
def api_account_profile_set():
    """Set the caller's OWN profile. Self-service, no admin needed."""
    body = request.get_json(silent=True) or {}
    try:
        _account_store.set_profile(g.principal.name,
                                   body.get("first_name", ""), body.get("last_name", ""),
                                   body.get("email", ""))
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    _account_store.audit(g.principal.name, "set_profile", "self")
    return jsonify(_account_store.get_profile(g.principal.name))


@app.route("/api/admin/accounts/<username>/profile", methods=["PUT"])
@require_admin
def api_admin_set_profile(username):
    """Admin edits ANY account's cosmetic profile. Authz: admin (decorator). Deliberately
    NOT dual-control gated: display name and email are low-risk cosmetic metadata, not role
    or password. Audited. (If email ever drives an auth flow, this must become sensitive.)"""
    body = request.get_json(silent=True) or {}
    try:
        _account_store.set_profile(username,
                                   body.get("first_name", ""), body.get("last_name", ""),
                                   body.get("email", ""))
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    _account_store.audit(g.principal.name, "set_profile", "for %s" % username)
    return jsonify(_account_store.get_profile(username))


@app.route("/api/admin/ai/status", methods=["GET"])
@require_admin
def api_admin_ai_status():
    return jsonify({
        "ai_enabled": _ai_triage.enabled,
        "recall_bias": _ai_triage.recall_margin,
        "kill_switch_engaged": _ai_autonomy.kill_switch_engaged(),
        "categories": _ai_autonomy.list_categories(),
        "levels": ai_autonomy_mod.LEVEL_NAMES,
    })


@app.route("/api/admin/ai/categories/<category>/ceiling", methods=["POST"])
@require_admin
def api_admin_ai_set_ceiling(category):
    """Set a category's autonomy ceiling. Lowering it (or keeping it equal) always applies
    immediately: it can only remove authority, so there is nothing to gate. Raising it to
    AUTO_CLOSE expands what the AI may do to real tickets on its own, so it is routed
    through dual control like any other sensitive action."""
    body = request.get_json(silent=True) or {}
    level_name = (body.get("level") or "").strip().lower()
    if level_name not in ai_autonomy_mod.NAME_TO_LEVEL:
        return jsonify({"error": "unknown level %r" % level_name}), 400
    level = ai_autonomy_mod.NAME_TO_LEVEL[level_name]
    current = _ai_autonomy.get_ceiling(category)
    if level > current and level == ai_autonomy_mod.AUTO_CLOSE:
        payload = {"category": category}
        try:
            result = _dispatch_sensitive_action(
                "set_ai_ceiling_auto_close", payload, g.principal.name)
        except accounts_mod.AccountError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify(result)
    _ai_autonomy.set_ceiling(category, level, g.principal.name)
    _account_store.audit(g.principal.name, "set_ai_ceiling",
                         "%s -> %s" % (category, level_name))
    return jsonify(_ai_autonomy.get_state(category))


@app.route("/api/admin/ai/kill-switch", methods=["POST"])
@require_admin
def api_admin_ai_kill_switch():
    """Engaging the kill switch is a safety action: always immediate, never gated, exactly
    like force_logout. Disengaging it restores autonomy and is routed through dual control,
    exactly like raising a ceiling to AUTO_CLOSE."""
    body = request.get_json(silent=True) or {}
    engage = bool(body.get("engage", True))
    if engage:
        _ai_autonomy.engage_kill_switch(g.principal.name)
        _account_store.audit(g.principal.name, "ai_kill_switch_engaged", "immediate")
        return jsonify({"ok": True, "kill_switch_engaged": True})
    try:
        result = _dispatch_sensitive_action("disengage_ai_kill_switch", {}, g.principal.name)
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


@app.route("/api/admin/ai/train/<category>", methods=["POST"])
@require_admin
def api_admin_ai_train(category):
    """Retraining changes what the AI will do next: sensitive action under dual control."""
    payload = {"category": category}
    try:
        result = _dispatch_sensitive_action("train_ai_model", payload, g.principal.name)
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


@app.route("/api/admin/ai/models/<category>/versions", methods=["GET"])
@require_admin
def api_admin_ai_model_versions(category):
    entry = _ai_registry.active(category)
    return jsonify({"active": entry["version"] if entry else None,
                    "versions": _ai_registry.versions(category)})


@app.route("/api/admin/ai/models/<category>/rollback", methods=["POST"])
@require_admin
def api_admin_ai_model_rollback(category):
    """Corrective/defensive action (a bad label batch degraded precision): admin-only,
    audited, not dual-control gated, same reasoning as force_logout."""
    new_version = _ai_registry.rollback(category)
    if new_version is None:
        return jsonify({"error": "nothing to roll back to"}), 400
    _account_store.audit(g.principal.name, "ai_model_rollback",
                         "%s -> version %d" % (category, new_version))
    return jsonify({"ok": True, "active_version": new_version})


@app.route("/api/admin/ai/models/<category>/activate", methods=["POST"])
@require_admin
def api_admin_ai_model_activate(category):
    body = request.get_json(silent=True) or {}
    try:
        version = int(body.get("version"))
        _ai_registry.activate(category, version)
    except (TypeError, ValueError) as e:
        return jsonify({"error": "invalid version"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    _account_store.audit(g.principal.name, "ai_model_activate",
                         "%s -> version %d" % (category, version))
    return jsonify({"ok": True, "active_version": version})


_AI_DISPOSITIONS = {"true_positive", "false_positive", "benign", "duplicate"}


def _ai_auto_infer(category=CATEGORY_TICKET_TRIAGE):
    """Automatically classify active tickets that have no overlay yet for `category`, creating
    AI proposals without a human delegating each one. This is the ingestion hook. It is a
    no-op unless the AI is enabled, the kill switch is off, and an admin has opted the category
    in (ceiling above shadow). It never mutates the real ticket and never triggers an active
    response; at most it marks a high-confidence item auto_closed_pending for a human check.
    Idempotent: a ticket already overlaid for the category is skipped. Abstentions (no model)
    create nothing, so there is no noise before a model exists."""
    if not _ai_triage.enabled:
        return {"created": 0, "skipped": "ai_disabled"}
    if _ai_autonomy.kill_switch_engaged():
        return {"created": 0, "skipped": "kill_switch"}
    st = _ai_autonomy.get_state(category)
    if st["ceiling"] <= ai_autonomy_mod.SHADOW:
        return {"created": 0, "skipped": "category_not_opted_in"}
    existing = _ai_tickets.overlaid_ticket_ids(category)
    created = 0
    for t in _read_jsonl(TICKETS):
        if t.get("status") not in ("open", "investigating"):
            continue
        tid = t.get("ticket_id")
        if not tid or tid in existing:
            continue
        prediction, feats = _ai_triage.classify_ticket(t, category)
        if prediction.abstained:
            continue
        state = ai_tickets_mod.PROPOSED
        if (st["effective_state"] == ai_autonomy_mod.AUTO_CLOSE
                and prediction.confidence >= st["close_confidence"]):
            state = ai_tickets_mod.AUTO_CLOSED_PENDING
        _ai_tickets.assign(tid, category, prediction.label, prediction.confidence,
                           feats, prediction.top_features, state, "ai-auto")
        existing.add(tid)
        created += 1
    return {"created": created, "category": category}


@app.route("/api/ai/auto-infer", methods=["POST"])
@require_manager
def api_ai_auto_infer():
    """Manually run auto-inference over current tickets (also runs automatically after each
    ingestion). Manager+ like the rest of the AI ticket container."""
    body = request.get_json(silent=True) or {}
    category = (body.get("category") or CATEGORY_TICKET_TRIAGE).strip()
    return jsonify(_ai_auto_infer(category))


def _seed_ai_demo():
    """Seed a small ticket-triage model, opt the category in, then auto-infer over current
    tickets so the AI container is populated. Safe and idempotent."""
    from core.ai import seed as ai_seed
    version = ai_seed.seed_triage_model(_ai_triage, _ai_autonomy)
    result = _ai_auto_infer()
    result["model_version"] = version
    return result


@app.route("/api/ai/seed-demo", methods=["POST"])
@require_manager
def api_ai_seed_demo():
    """One-click: train a small demo model, opt ticket_triage in, and auto-triage current
    tickets. Gives a populated AI container without hand-labeling first."""
    return jsonify(_seed_ai_demo())


@app.route("/api/admin/ai/recall-bias", methods=["GET", "POST"])
@require_admin
def api_admin_ai_recall_bias():
    """Get or set the cost-sensitive recall bias (how hard the AI leans toward calling a
    borderline ticket a threat). Persisted and applied live. Admin-only."""
    if request.method == "GET":
        return jsonify({"recall_bias": _ai_triage.recall_margin})
    body = request.get_json(silent=True) or {}
    try:
        value = float(body.get("recall_bias"))
    except (TypeError, ValueError):
        return jsonify({"error": "recall_bias must be a number"}), 400
    if value < 0 or value > 20:
        return jsonify({"error": "recall_bias out of range (0..20)"}), 400
    _ai_triage.recall_margin = value
    _ai_autonomy.set_setting("recall_bias", value)
    _account_store.audit(g.principal.name, "set_ai_recall_bias", "%.2f" % value)
    return jsonify({"recall_bias": value})


@app.route("/api/admin/ai/train-datasets", methods=["POST"])
@require_admin
def api_admin_ai_train_datasets():
    """Train the ticket_triage model on the current training data (the bundled SOC corpus is
    recorded if absent, then training runs over all provenance labels for the category) and
    opt the category in. Returns the new model version and a held-out quality estimate."""
    result = _seed_ai_demo()
    examples = _ai_provenance.training_set(CATEGORY_TICKET_TRIAGE)
    metrics = ai_metrics_mod.evaluate_holdout(
        examples, priority_label=ai_triage_mod.THREAT_LABEL,
        priority_margin=_ai_triage.recall_margin)
    result["metrics"] = metrics
    _account_store.audit(g.principal.name, "train_ai_datasets",
                         "model v%s" % result.get("model_version"))
    return jsonify(result)


@app.route("/api/ai/tickets", methods=["GET"])
@require_manager
def api_ai_tickets_list():
    view = request.args.get("view", "open")
    return jsonify(_ai_tickets.list(view))


@app.route("/api/ai/tickets/<int:record_id>", methods=["GET"])
@require_manager
def api_ai_ticket_detail(record_id):
    rec = _ai_tickets.get(record_id)
    if not rec:
        return jsonify({"error": "not found"}), 404
    return jsonify(rec)


@app.route("/api/ai/tickets/assign", methods=["POST"])
@require_manager
def api_ai_ticket_assign():
    """Delegate a real ticket to the AI. The AI classifies it (deterministically) and an
    overlay record is created. The AI never mutates the real ticket here: at auto_close the
    record is only marked auto_closed_pending, still queued for human verification."""
    body = request.get_json(silent=True) or {}
    ticket_id = (body.get("ticket_id") or "").strip()
    category = (body.get("category") or CATEGORY_TICKET_TRIAGE).strip()
    if not ticket_id:
        return jsonify({"error": "ticket_id required"}), 400
    ticket = None
    for t in _read_jsonl(TICKETS):
        if t.get("ticket_id") == ticket_id:
            ticket = t
            break
    if ticket is None:
        return jsonify({"error": "no such ticket: %s" % ticket_id}), 404

    prediction, feats = _ai_triage.classify_ticket(ticket, category)
    autonomy = _ai_autonomy.get_state(category)
    state = ai_tickets_mod.PROPOSED
    if (autonomy["effective_state"] == ai_autonomy_mod.AUTO_CLOSE
            and not prediction.abstained
            and prediction.confidence >= autonomy["close_confidence"]):
        state = ai_tickets_mod.AUTO_CLOSED_PENDING
    rid = _ai_tickets.assign(ticket_id, category, prediction.label, prediction.confidence,
                             feats, prediction.top_features, state, g.principal.name)
    _account_store.audit(g.principal.name, "ai_assign_ticket",
                         "%s -> %s (%s)" % (ticket_id, prediction.label, state))
    return jsonify(_ai_tickets.get(rid))


@app.route("/api/ai/tickets/<int:record_id>/verify", methods=["POST"])
@require_manager
def api_ai_ticket_verify(record_id):
    """Human verification: the core human-in-the-loop step. Records the human-validated
    label into provenance (the ONLY thing the model ever learns from) and moves the autonomy
    streak (agree raises it, a single disagreement resets it and demotes the category)."""
    body = request.get_json(silent=True) or {}
    human_label = (body.get("human_label") or "").strip()
    if human_label not in _AI_DISPOSITIONS:
        return jsonify({"error": "human_label must be one of %s"
                        % sorted(_AI_DISPOSITIONS)}), 400
    rec = _ai_tickets.get(record_id)
    if not rec:
        return jsonify({"error": "not found"}), 404
    try:
        updated = _ai_tickets.verify(record_id, human_label, g.principal.name)
    except ai_tickets_mod.AITicketError as e:
        return jsonify({"error": str(e)}), 400
    # Feed the validated label into provenance (training source) and the autonomy ladder.
    _ai_provenance.record(rec["category"], rec["features_list"], human_label,
                          actor=g.principal.name)
    autonomy = _ai_autonomy.record_outcome(rec["category"], rec["ai_label"],
                                           human_label, rec["confidence"])
    _account_store.audit(g.principal.name, "ai_verify_ticket",
                         "%s: ai=%s human=%s" % (rec["ticket_id"], rec["ai_label"], human_label))
    return jsonify({"ticket": updated, "autonomy": autonomy})


@app.route("/api/ai/tickets/<int:record_id>/explain", methods=["GET"])
@require_manager
def api_ai_ticket_explain(record_id):
    """Optional plain-language explanation of the AI's disposition, from the local LLM if it
    is enabled and reachable. The verdict is NOT produced here; this only phrases the
    deterministic classifier's existing decision. Returns explanation:null gracefully when
    the LLM is off or unreachable."""
    rec = _ai_tickets.get(record_id)
    if not rec:
        return jsonify({"error": "not found"}), 404
    if not _ai_llm.available():
        return jsonify({"explanation": None,
                        "reason": _ai_llm.reason or "LLM explainer is disabled"})
    text = _ai_llm.explain(rec["ai_label"], rec["confidence"], rec["features_list"])
    if text is None:
        return jsonify({"explanation": None, "reason": "local LLM runtime unreachable"})
    return jsonify({"explanation": text})


@app.route("/api/admin/ai/models/<category>/import", methods=["POST"])
@require_admin
def api_admin_ai_model_import(category):
    """Import a classifier model (our JSON params). Structurally validated (no execution),
    then stored as an INACTIVE version (quarantine): an admin must activate it after review.
    Semantic quality is the importer's risk and is disclaimed; the structural gate is not."""
    body = request.get_json(silent=True) or {}
    fmt = (body.get("format") or "json").strip().lower()
    filename = (body.get("filename") or ("model.%s" % fmt)).strip()
    content = body.get("content")
    gate = model_import_mod.check_import_format(filename)
    if not gate.accepted:
        return jsonify({"error": gate.reason}), 400
    if fmt != "json" or not isinstance(content, str):
        # Only our JSON classifier params can be imported as an active classifier. GGUF /
        # safetensors are LLM weight containers validated structurally elsewhere but not run
        # as classifiers here.
        return jsonify({"error": "only json classifier params can be imported as a model"}), 400
    verdict = model_import_mod.validate_classifier_json(content)
    if not verdict.accepted:
        return jsonify({"error": verdict.reason}), 400
    try:
        model = json.loads(content)
    except ValueError:
        return jsonify({"error": "not valid JSON"}), 400
    version = _ai_registry.save(category, model, metrics={"imported": True}, activate=False)
    _account_store.audit(g.principal.name, "ai_model_import",
                         "%s -> inactive version %d (%s)" % (category, version, verdict.reason))
    return jsonify({"ok": True, "imported_version": version, "active": False,
                    "disclaimer": "Imported model stored inactive. Review and activate "
                                  "explicitly. Semantic quality is not vetted; this is at "
                                  "your own risk."})


@app.route("/api/admin/ai/datasets/<category>/import", methods=["POST"])
@require_admin
def api_admin_ai_dataset_import(category):
    """Import a labeled training dataset (e.g. true/false-positive sets exported from another
    tool) so a team can switch tools and keep its labels. Each label is recorded in provenance
    tagged with a DISTINCT source 'import:<name>', so the per-source influence cap bounds its
    weight and it can be rolled back as a batch. Admin-only + audited (the admin is the human
    review). It does not retrain by itself; the retrain that uses it stays dual-control gated."""
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    records = body.get("records")
    if not name or not isinstance(records, list):
        return jsonify({"error": "name and a records array are required"}), 400
    if len(records) > 50000:
        return jsonify({"error": "dataset too large (max 50000 records)"}), 400
    source = "import:%s" % name
    imported = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        label = str(rec.get("label", "")).strip()
        if not label:
            continue
        if isinstance(rec.get("features"), list):
            feats = [str(x) for x in rec["features"]]
        elif isinstance(rec.get("ticket"), dict):
            feats = ai_features_mod.extract_ticket_features(rec["ticket"])
        elif isinstance(rec.get("mail"), dict):
            feats = ai_features_mod.extract_mail_features(rec["mail"])
        else:
            continue
        _ai_provenance.record(category, feats, label, actor=g.principal.name, source=source)
        imported += 1
    _account_store.audit(g.principal.name, "ai_dataset_import",
                         "%s: +%d labels from %s" % (category, imported, source))
    return jsonify({"ok": True, "imported": imported, "source": source,
                    "source_counts": _ai_provenance.source_counts(category),
                    "disclaimer": "Imported labels are provenance-tagged, influence-capped and "
                                  "rollback-able. Semantic quality is not vetted; at your own risk."})


@app.route("/api/admin/ai/datasets/<category>/rollback", methods=["POST"])
@require_admin
def api_admin_ai_dataset_rollback(category):
    """Undo an imported dataset batch by name. Purges only that 'import:<name>' source; human
    analysts' own validated labels (source == their username) are never touched."""
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    removed = _ai_provenance.purge_source(category, "import:%s" % name)
    _account_store.audit(g.principal.name, "ai_dataset_rollback",
                         "%s: removed %d labels from import:%s" % (category, removed, name))
    return jsonify({"ok": True, "removed": removed})


@app.route("/api/admin/ai/metrics/<category>", methods=["GET"])
@require_manager
def api_admin_ai_metrics(category):
    """Held-out precision/recall/F1 and accuracy for a category, plus the label distribution
    (drift). Manager+ so responsible analysts can drive autonomy decisions by data. The
    estimate is honest: the model is scored on a disjoint split it was not trained on."""
    examples = _ai_provenance.training_set(category)
    metrics = ai_metrics_mod.evaluate_holdout(
        examples, priority_label=ai_triage_mod.THREAT_LABEL,
        priority_margin=_ai_triage.recall_margin)
    metrics["recall_bias"] = _ai_triage.recall_margin
    metrics["label_distribution"] = ai_metrics_mod.label_distribution(examples)
    metrics["source_counts"] = _ai_provenance.source_counts(category)
    return jsonify(metrics)


@app.route("/api/admin/requests", methods=["GET"])
@require_admin
def api_admin_list_requests():
    return jsonify(_account_store.list_pending_requests())


@app.route("/api/admin/requests/<int:request_id>/decide", methods=["POST"])
@require_admin
def api_admin_decide_request(request_id):
    body = request.get_json(silent=True) or {}
    approve = bool(body.get("approve"))
    reason = body.get("reason") or ""
    try:
        req = _account_store.decide_request(request_id, g.principal.name, approve, reason)
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    if approve:
        # Decision is now recorded regardless of what happens next. Execution is a
        # separate, retryable step: if it fails here, the request stays 'approved' but
        # unexecuted (visible via list_unexecuted_approved), not silently stuck. The
        # admin can retry via /retry-execution instead of the action being lost.
        err = _execute_approved_request(request_id, req)
        if err:
            return jsonify({"error": err, "request": req, "needs_retry": True}), 502
    return jsonify(req)


def _execute_approved_request(request_id: int, req: dict) -> Optional[str]:
    """Run the real side effect for an approved request. Returns None on success, or an
    error message on failure (the request itself stays 'approved'/unexecuted so a retry
    is possible, see mark_executed/list_unexecuted_approved)."""
    try:
        if req["action"] == "ban_ip_real":
            p = req["payload"]
            _active_response.ban_ip(p["ip"], req["requested_by"],
                                   current_session_ip=p.get("current_session_ip"),
                                   duration_hours=p.get("duration_hours"), real=True)
        elif req["action"] == "quarantine_file_real":
            p = req["payload"]
            _active_response.quarantine_file(p["path"], req["requested_by"],
                                            allowed_roots=_QUARANTINE_ROOTS, real=True)
        elif req["action"] == "set_ai_ceiling_auto_close":
            _ai_autonomy.set_ceiling(req["payload"]["category"],
                                    ai_autonomy_mod.AUTO_CLOSE, req["requested_by"])
        elif req["action"] == "disengage_ai_kill_switch":
            _ai_autonomy.disengage_kill_switch(req["requested_by"])
        elif req["action"] == "train_ai_model":
            version = _ai_triage.train_category(req["payload"]["category"])
            if version is None:
                return ("no human-validated labels yet for category %r"
                       % req["payload"]["category"])
        else:
            _account_store.execute_request(request_id)
    except (accounts_mod.AccountError, ar_mod.ActiveResponseError) as e:
        return str(e)
    if req["action"] in ("ban_ip_real", "quarantine_file_real", "set_ai_ceiling_auto_close",
                         "disengage_ai_kill_switch", "train_ai_model"):
        _account_store.mark_executed(request_id)
    return None


@app.route("/api/admin/requests/unexecuted", methods=["GET"])
@require_admin
def api_admin_list_unexecuted():
    """Approved requests whose action has not actually run yet (a previous execution
    attempt failed). Should normally be empty."""
    return jsonify(_account_store.list_unexecuted_approved())


@app.route("/api/admin/requests/<int:request_id>/retry-execution", methods=["POST"])
@require_admin
def api_admin_retry_execution(request_id):
    """Retry execution of an approved-but-not-yet-executed request, without requiring a
    fresh approval decision (the human decision already happened and stands)."""
    req = _account_store.get_request(request_id)
    if not req or req["status"] != "approved":
        return jsonify({"error": "Request is not in an approved, retryable state."}), 400
    if req.get("executed_at"):
        return jsonify({"ok": True, "already_executed": True})
    err = _execute_approved_request(request_id, req)
    if err:
        return jsonify({"error": err, "needs_retry": True}), 502
    return jsonify({"ok": True})


@app.route("/api/admin/audit", methods=["GET"])
@require_admin
def api_admin_audit():
    return jsonify(_account_store.list_audit())


@app.route("/api/admin/bans", methods=["GET"])
@require_admin
def api_admin_list_bans():
    _active_response.purge_expired_bans()
    return jsonify(_active_response.list_active_bans())


@app.route("/api/admin/bans", methods=["POST"])
@require_admin
def api_admin_ban_ip():
    """Ban an IP. Internal-only bans (real=False, default) apply immediately regardless
    of dual control: they never touch the OS and are trivially reversible. Real firewall
    bans go through the same degraded/dual-control dispatch as account actions."""
    body = request.get_json(silent=True) or {}
    ip = (body.get("ip") or "").strip()
    real = bool(body.get("real"))
    duration = body.get("duration_hours")
    session_token = request.cookies.get(SESSION_COOKIE, "")
    session_ip = request.remote_addr if session_token else None

    try:
        if real:
            payload = {"ip": ip, "duration_hours": duration,
                      "current_session_ip": session_ip}
            result = _dispatch_sensitive_action("ban_ip_real", payload, g.principal.name)
            return jsonify(result)
        bid = _active_response.ban_ip(ip, g.principal.name, current_session_ip=session_ip,
                                     duration_hours=duration, real=False)
        return jsonify({"status": "applied", "ban_id": bid})
    except (ar_mod.ActiveResponseError, accounts_mod.AccountError) as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/admin/bans/<int:ban_id>", methods=["DELETE"])
@require_admin
def api_admin_unban_ip(ban_id):
    try:
        _active_response.unban_ip(ban_id, g.principal.name)
    except ar_mod.ActiveResponseError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"ok": True})


@app.route("/api/admin/quarantine", methods=["GET"])
@require_admin
def api_admin_list_quarantines():
    return jsonify(_active_response.list_active_quarantines())


@app.route("/api/admin/quarantine", methods=["POST"])
@require_admin
def api_admin_quarantine_file():
    """Quarantine a file. Internal-only (default) records the intent without touching
    filesystem permissions. Real quarantine (actual chmod) goes through dual control."""
    body = request.get_json(silent=True) or {}
    path = body.get("path") or ""
    real = bool(body.get("real"))
    try:
        if real:
            result = _dispatch_sensitive_action(
                "quarantine_file_real", {"path": path}, g.principal.name)
            return jsonify(result)
        qid = _active_response.quarantine_file(
            path, g.principal.name, allowed_roots=_QUARANTINE_ROOTS, real=False)
        return jsonify({"status": "applied", "quarantine_id": qid})
    except (ar_mod.ActiveResponseError, accounts_mod.AccountError) as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/admin/quarantine/<int:qid>/restore", methods=["POST"])
@require_admin
def api_admin_restore_file(qid):
    try:
        _active_response.restore_file(qid, g.principal.name)
    except ar_mod.ActiveResponseError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"ok": True})



FONTS_DIR = BASE / "assets" / "fonts"
# Allowlist, not a path-traversal-prone open directory listing: only these exact
# filenames can ever be served, regardless of what the URL asks for.
_FONT_FILES = {
    "JetBrainsMono-Regular.woff2", "JetBrainsMono-Medium.woff2", "JetBrainsMono-Bold.woff2",
    "SpaceGrotesk-Regular.woff2", "SpaceGrotesk-Medium.woff2", "SpaceGrotesk-Bold.woff2",
}


@app.route("/assets/fonts/<path:filename>")
def serve_font(filename):
    """Serve the two self-hosted typefaces. Same-origin, so the existing CSP
    (default-src 'self') covers font loading with no policy change needed; this is
    exactly why the fonts are bundled locally instead of pulled from a CDN. The
    allowlist means the :filename part of the URL can never be used to read an
    arbitrary file off disk, no matter what is requested."""
    if filename not in _FONT_FILES:
        return "", 404
    resp = send_from_directory(str(FONTS_DIR), filename)
    resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return resp


@app.route("/api/config")
def api_config():
    return jsonify({
        "mode": MODE,
        "scan_root": str(SCAN_ROOT.resolve()) if MODE == "server" else None,
        "encrypted": vault.active(),
        "require_login": REQUIRE_LOGIN,
        "authenticated": g.principal.authenticated,
        "user": g.principal.name if g.principal.authenticated else None,
        "role": g.principal.role if g.principal.authenticated else None,
    })


@app.route("/api/update-status", methods=["GET"])
def api_update_status():
    """Last weekly check result (never triggers a new check on request; the checker runs
    on its own Monday-17:00 schedule). Never downloads or executes anything: the frontend
    only ever gets a link to the repo's own Releases page for the operator to visit."""
    r = _update_checker.last_result
    if r is None:
        return jsonify({"checked": False})
    return jsonify(dict(r, checked=True))


# -- Dashboard stats -----------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    tickets = _read_jsonl(TICKETS)
    signals = _read_jsonl(SIGNALS)
    sev    = Counter(t.get("severity") for t in tickets)
    status = Counter(t.get("status") for t in tickets)
    mitre  = Counter(t.get("mitre_technique") for t in tickets if t.get("mitre_technique"))
    hosts  = Counter(t.get("host") for t in tickets)
    types  = Counter(_base_label(t.get("signal_type", "")) for t in tickets)
    return jsonify({
        "total_tickets": len(tickets),
        "total_signals": len(signals),
        "severity": dict(sev),
        "status":   dict(status),
        "mitre":    dict(mitre.most_common(10)),
        "hosts":    dict(hosts.most_common(10)),
        "types":    dict(types.most_common(10)),
    })


# -- Tickets -------------------------------------------------------------------

@app.route("/api/tickets")
def api_tickets():
    tickets = _read_jsonl(TICKETS)
    sev    = request.args.get("severity")
    status = request.args.get("status")
    host   = request.args.get("host")
    mitre  = request.args.get("mitre")
    stype  = request.args.get("type")
    if sev:    tickets = [t for t in tickets if t.get("severity") == sev]
    if status: tickets = [t for t in tickets if t.get("status") == status]
    if host:   tickets = [t for t in tickets if t.get("host") == host]
    if mitre:  tickets = [t for t in tickets if t.get("mitre_technique") == mitre]
    if stype:  tickets = [t for t in tickets if _base_label(t.get("signal_type", "")) == stype]
    tickets.sort(key=lambda t: t.get("score", 0), reverse=True)
    return jsonify(tickets)


@app.route("/api/tickets/<tid>", methods=["GET"])
def api_ticket(tid):
    for t in _read_jsonl(TICKETS):
        if t.get("ticket_id") == tid:
            return jsonify(t)
    return jsonify({"error": "not found"}), 404


_ALLOWED_STATUS = {"open", "investigating", "resolved", "closed"}
_ALLOWED_DISPOSITION = {"", "true_positive", "false_positive", "benign", "duplicate"}
_MAX_NOTES = 5000
_MAX_ASSIGNEE = 120


@app.route("/api/tickets/<tid>", methods=["PATCH"])
def api_ticket_update(tid):
    tickets = _read_jsonl(TICKETS)
    body    = request.get_json(silent=True) or {}

    # Validate before touching the store. Only known fields, with checked values; this
    # keeps unvalidated or oversized data out of the ticket store (defense in depth; XSS
    # is independently neutralized at render time).
    if "status" in body and body["status"] not in _ALLOWED_STATUS:
        return jsonify({"error": "invalid status"}), 400
    if "disposition" in body and body["disposition"] not in _ALLOWED_DISPOSITION:
        return jsonify({"error": "invalid disposition"}), 400
    clean = {}
    if "status" in body:
        clean["status"] = body["status"]
    if "disposition" in body:
        clean["disposition"] = body["disposition"]
    if "assignee" in body:
        clean["assignee"] = str(body["assignee"])[:_MAX_ASSIGNEE]
    if "notes" in body:
        clean["notes"] = str(body["notes"])[:_MAX_NOTES]

    updated = False
    for t in tickets:
        if t.get("ticket_id") == tid:
            t.update(clean)
            t["updated_at"] = datetime.now(timezone.utc).isoformat()
            updated = True
            break
    if not updated:
        return jsonify({"error": "not found"}), 404
    _write_tickets(tickets)
    return jsonify({"ok": True})


# -- Signals -------------------------------------------------------------------

@app.route("/api/signals")
def api_signals():
    signals = _read_jsonl(SIGNALS)
    signals.sort(key=lambda s: s.get("score", 0), reverse=True)
    return jsonify(signals)


# -- File browser --------------------------------------------------------------

def _drive_roots() -> List[Dict[str, Any]]:
    out = []
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        if os.path.exists(root):
            out.append({"name": root, "is_dir": True, "size": "", "path": root})
    return out


def _crumbs(target: Path) -> List[Dict[str, str]]:
    crumbs, acc = [], None
    for part in target.parts:
        acc = Path(part) if acc is None else acc / part
        label = part[:-1] if part.endswith("\\") else part
        crumbs.append({"name": label, "path": str(acc)})
    return crumbs


def _parent_of(target: Path) -> Optional[str]:
    parent = target.parent
    if parent == target:                       # filesystem root
        return "" if os.name == "nt" else None  # nt: back to drive list
    return str(parent)


@app.route("/api/browse")
def api_browse():
    if IS_SHOWCASE:
        return jsonify({"error": "file access is disabled in showcase mode"}), 403
    raw = request.args.get("path", "")
    try:
        if raw == "":
            if os.name == "nt":
                return jsonify({"path": "", "parent": None, "crumbs": [], "entries": _drive_roots()})
            raw = "/"

        target = Path(raw).resolve()

        if MODE == "server" and not _within_scan_root(target):
            return jsonify({"error": "path outside allowed root"}), 403
        if not target.exists():
            return jsonify({"error": "path not found"}), 404
        if target.is_file():
            return jsonify({"error": "not a directory"}), 400

        entries = []
        for child in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            try:
                is_dir = child.is_dir()
                size = "" if is_dir else _human(child.stat().st_size)
            except (PermissionError, OSError):
                continue
            entries.append({"name": child.name, "is_dir": is_dir, "size": size, "path": str(child)})

        return jsonify({
            "path":    str(target),
            "parent":  _parent_of(target),
            "crumbs":  _crumbs(target),
            "entries": entries,
        })
    except PermissionError:
        return jsonify({"error": "permission denied"}), 403
    except Exception as exc:
        # Do not leak server filesystem structure or stack traces to an untrusted client.
        msg = str(exc) if MODE != "server" else "could not read path"
        return jsonify({"error": msg}), 500


# -- Run pipeline (SSE) --------------------------------------------------------

def _sse(text: str) -> str:
    return "data: " + json.dumps(text) + "\n\n"


@app.route("/api/run-stream")
def api_run_stream():
    if IS_SHOWCASE:
        return jsonify({"error": "the run pipeline is disabled in showcase mode"}), 403
    raw = request.args.get("input", "")
    fmt = request.args.get("format", "auto")
    if fmt not in ALLOWED_FORMATS:
        fmt = "auto"

    target = Path(raw).resolve()
    error = None
    if not raw:
        error = "no input file"
    elif MODE == "server" and not _within_scan_root(target):
        error = "input outside allowed root"
    elif not target.exists():
        error = "input not found" if MODE == "server" else "input not found: " + str(target)

    if error:
        return Response(_sse("[!] " + error) + _sse("__DONE__"),
                        mimetype="text/event-stream")

    def generate():
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SRC_DIR)
        cmd = [sys.executable, "-m", "ingest.replay",
               "--input", str(target),
               "--out-dir", str(OUT_DIR),
               "--format", fmt]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, env=env, cwd=str(BASE))
        for line in proc.stdout:
            yield _sse(line.rstrip())
        proc.wait()
        # Ingestion just wrote/updated tickets: run AI auto-inference so proposals appear in
        # the AI container without a human delegating each ticket. Best-effort; a failure here
        # never breaks the pipeline result.
        try:
            summary = _ai_auto_infer()
            if summary.get("created"):
                yield _sse("[ai] auto-triaged %d new ticket(s)" % summary["created"])
            elif summary.get("skipped"):
                yield _sse("[ai] auto-triage skipped (%s)" % summary["skipped"])
        except Exception as exc:
            yield _sse("[ai] auto-triage error: %s" % exc)
        yield _sse("__DONE__")

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# -- Index ---------------------------------------------------------------------

@app.route("/api/shutdown", methods=["POST"])
def api_shutdown():
    # Full stop of this app from the UI, in any mode. Loopback-only by construction
    # (the app binds 127.0.0.1 unless explicitly opted out). v11 note: once auth exists,
    # this must be restricted to an authenticated operator/admin.
    import signal
    import threading as _th
    _th.Timer(0.4, lambda: os.kill(os.getpid(), signal.SIGINT)).start()
    return jsonify({"stopping": True})


@app.route("/")
def index():
    from server.frontend import FRONTEND_HTML
    return FRONTEND_HTML


if __name__ == "__main__":
    # Local mode binds to loopback only. No auth exists yet, so never expose to
    # the network by default. v10 server mode may set SIEM_HOST explicitly.
    if IS_SHOWCASE:
        from ingest.showcase_data import ensure_showcase, replay_showcase
        ensure_showcase(OUT_DIR)
        # Showcase is the demo mode: seed a small AI model, opt the category in, and
        # auto-triage the demo tickets so the AI container is populated out of the box.
        # Best-effort; a failure here must never stop the server from starting.
        try:
            summary = _seed_ai_demo()
            print("[soar-server] AI demo seeded: %s" % summary)
        except Exception as exc:
            print("[soar-server] AI demo seed skipped: %s" % exc)
        # Streaming runs only in showcase, and starts automatically with it: a daemon
        # thread reveals the demo tickets progressively.
        threading.Thread(target=replay_showcase, args=(OUT_DIR, 5.0), daemon=True).start()
    host = os.environ.get("SIEM_HOST", "127.0.0.1")
    allow_public = os.environ.get("SIEM_ALLOW_PUBLIC") == "1"
    try:
        host, warn = _safe_bind_host(host, allow_public)
    except RuntimeError as exc:
        print("[soar-server] " + str(exc))
        raise SystemExit(2)
    if warn:
        print("[soar-server] " + warn)

    # TLS: mandatory once exposed beyond loopback (sending session cookies and
    # passwords over plain HTTP on a real network is not acceptable); optional but
    # available on loopback via SIEM_TLS=1, mainly so WebAuthn/browser behavior can be
    # exercised the same way it would be over a real network.
    want_tls = os.environ.get("SIEM_TLS") == "1"
    ssl_context = None
    if allow_public and os.environ.get("SIEM_TLS") == "0":
        print("[soar-server] Refusing to start: public exposure without TLS "
              "(SIEM_ALLOW_PUBLIC=1 with SIEM_TLS=0). Remove SIEM_TLS=0 or keep the "
              "server on loopback.")
        raise SystemExit(2)
    if allow_public or want_tls:
        data_dir = BASE / "data"
        cert_path, key_path = tls_mod.ensure_cert(data_dir, common_name=host)
        if tls_mod.cert_expires_soon(cert_path):
            print("[soar-server] TLS certificate is missing or expiring soon; "
                  "a fresh self-signed certificate has been generated.")
        ssl_context = (str(cert_path), str(key_path))
        scheme = "https"
        TLS_ACTIVE = True
    else:
        scheme = "http"

    print("[soar-server] mode=" + MODE + " at " + scheme + "://" + host + ":5000")
    _update_checker.start()  # weekly Monday-17:00 background check, check-only
    threading.Timer(1.2, lambda: webbrowser.open(
        scheme + "://127.0.0.1:5000")).start()
    app.run(host=host, port=5000, debug=False, ssl_context=ssl_context)

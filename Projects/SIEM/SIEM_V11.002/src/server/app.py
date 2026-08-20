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
import string
import subprocess
import sys
import threading
import webbrowser
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, Response, jsonify, request, stream_with_context, g

BASE    = Path(__file__).parent.parent.parent
SRC_DIR = BASE / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
from core import vault
from core import auth
from core import accounts as accounts_mod
from core import bootstrap as bootstrap_mod
MODE      = os.environ.get("SIEM_MODE", "local").lower()
IS_SHOWCASE = MODE == "showcase"
IS_SERVER = MODE == "server"
# v10 security foundation: the mode is a TRUSTED signal taken only from the environment
# set by the operator/launcher, never from client input, so it cannot be spoofed by a
# request. Server mode is a locked-down skeleton: no accounts yet (auth lands in v11) and
# a read-only posture toward the host (the app only reads, it never mutates the host).
READONLY_HOST = True


def _safe_bind_host(requested, allow_public):
    """Fail-safe binding. The app has no authentication yet, so it must never be exposed
    on a public interface by accident. Loopback is always allowed; a public bind requires
    an explicit operator opt-in (SIEM_ALLOW_PUBLIC=1). Returns (host, warning) or raises."""
    if requested in ("127.0.0.1", "localhost", "::1"):
        return requested, None
    if not allow_public:
        raise RuntimeError(
            "refusing to bind " + requested + ": no authentication exists yet (auth lands in "
            "v11). Use 127.0.0.1, or set SIEM_ALLOW_PUBLIC=1 to override deliberately.")
    return requested, ("WARNING: bound to a public interface with no auth. This is a v10 "
                       "skeleton; do not use on an untrusted network until v11 adds accounts.")
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
# Web bootstrap token: only armed if no admin exists yet AND bootstrap is not sealed.
_bootstrap_token = bootstrap_mod.BootstrapToken()
if not _account_store.is_sealed() and not _account_store.admin_exists():
    # Arm the one-time setup token and announce it on the terminal only.
    _bootstrap_token.generate_and_announce()

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
    """Bootstrap is open only on a virgin install: not sealed AND no admin yet."""
    return (not _account_store.is_sealed()) and (not _account_store.admin_exists())


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


@app.route("/api/login", methods=["POST"])
def api_login():
    """Authenticate and open a server-side session. Two steps when TOTP is enabled:
    password first, then the 6-digit code. Generic failure message and a per-account rate
    limit defend against enumeration and brute force."""
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    totp_code = (body.get("totp") or "").strip()

    GENERIC = (jsonify({"error": "invalid username or password"}), 401)

    if not username or not password:
        return GENERIC
    if _account_store.is_rate_limited(username):
        return jsonify({"error": "too many attempts, try again later"}), 429

    if not _account_store.verify(username, password):
        _account_store.record_failed_login(username)
        return GENERIC

    # Password is correct. If TOTP is enabled, require the second factor before issuing a
    # session. We do NOT clear the failed-login counter until full success, so brute force
    # against the password is still throttled.
    status = _account_store.totp_status(username)
    if status["enabled"]:
        if not totp_code:
            # Tell the client a second factor is needed (password was accepted).
            return jsonify({"mfa_required": True}), 401
        if not _account_store.verify_totp(username, totp_code):
            _account_store.record_failed_login(username)
            return jsonify({"error": "invalid code", "mfa_required": True}), 401

    _account_store.clear_failed_logins(username)
    _account_store.touch_login(username)
    token = _account_store.create_session(username)

    resp = jsonify({"ok": True, "username": username})
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="Strict",
                    secure=False, path="/")
    return resp


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """Destroy the current server session (revocable by design)."""
    token = request.cookies.get(SESSION_COOKIE, "")
    _account_store.revoke_session(token)
    resp = jsonify({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.route("/api/mfa/status", methods=["GET"])
def api_mfa_status():
    """Report the current user's TOTP state. Requires authentication."""
    if not g.principal.authenticated:
        return jsonify({"error": "authentication required"}), 401
    return jsonify(_account_store.totp_status(g.principal.name))


@app.route("/api/mfa/enroll", methods=["POST"])
def api_mfa_enroll():
    """Begin TOTP enrollment for the current user: generate a pending secret and return it
    plus the otpauth URI so the client can render a QR and offer the text fallback. The
    secret is NOT active until confirmed with a valid code."""
    if not g.principal.authenticated:
        return jsonify({"error": "authentication required"}), 401
    try:
        secret = _account_store.begin_totp_enrollment(g.principal.name)
        uri = _account_store.totp_provisioning_uri(g.principal.name)
    except accounts_mod.AccountError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"secret": secret, "otpauth_uri": uri})


@app.route("/api/mfa/confirm", methods=["POST"])
def api_mfa_confirm():
    """Enable TOTP only after the user proves a valid current code (phone is synced)."""
    if not g.principal.authenticated:
        return jsonify({"error": "authentication required"}), 401
    body = request.get_json(silent=True) or {}
    code = (body.get("code") or "").strip()
    if _account_store.confirm_totp(g.principal.name, code):
        return jsonify({"ok": True, "enabled": True})
    return jsonify({"error": "invalid code"}), 400


@app.route("/api/mfa/disable", methods=["POST"])
def api_mfa_disable():
    """Disable TOTP for the current user. Requires a valid current code to prove it is the
    legitimate owner turning it off (not an attacker on a hijacked session)."""
    if not g.principal.authenticated:
        return jsonify({"error": "authentication required"}), 401
    body = request.get_json(silent=True) or {}
    code = (body.get("code") or "").strip()
    if not _account_store.verify_totp(g.principal.name, code):
        return jsonify({"error": "invalid code"}), 400
    _account_store.disable_totp(g.principal.name)
    return jsonify({"ok": True, "enabled": False})


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
    print("[soar-server] mode=" + MODE + " at http://" + host + ":5000")
    threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    app.run(host=host, port=5000, debug=False)

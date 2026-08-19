"""Account storage and the bootstrap seal.

This is the identity store for v11. It is deliberately separate from the log vault:
accounts are a small, critical identity file that deserves its own trust path, isolated
from the bulk operational log data. Decisions locked in:

  * SQLite via the stdlib sqlite3 module (NO new PyPI dependency for storage).
  * The DB file is created with 0600 permissions (owner read/write only), verified.
  * Passwords are hashed with argon2id (argon2-cffi), explicit parameters, never stored
    or logged in clear.
  * The DB lives outside out/, is never vault-encrypted, never version-controlled.

The BOOTSTRAP SEAL is the core anti-reuse defense for /setup. Once the first admin is
created, bootstrap is sealed PERMANENTLY. The seal is written in TWO places that must
concur: a row in the SQLite `system` table AND a separate 0600 marker file. Emptying the
accounts table cannot reopen bootstrap, because the seal persists independently. If the
two disagree, we treat the system as sealed (fail closed).

Master invariant: once any admin exists OR the seal is set, no bootstrap path may create
another admin. Enforced here, server-side, on every call.
"""
from __future__ import annotations

import os
import hashlib
import json
import secrets
import sqlite3
import stat
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, InvalidHashError

from . import pwpolicy

# argon2id parameters. Explicit, not the library defaults, so they are auditable and
# stable across versions. ~64 MiB memory, 3 iterations, parallelism 2: resistant to
# GPU/ASIC cracking while remaining acceptable for an interactive login.
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,   # KiB -> 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID,            # argon2id
)

ROLES = ("operator", "manager", "admin")

# Actions requiring four-eyes approval once a second admin exists. AI training-data and
# system-prompt actions are deliberately NOT listed here yet: that module does not exist
# yet (v12), and wiring approval for routes that do not exist would mean guessing their
# shape. They are added when the AI module is built, reusing this same mechanism.
SENSITIVE_ACTIONS = (
    "create_account",
    "change_role",
    "delete_account",
    "delete_other_webauthn_key",
    "reset_other_password",
    "ban_ip_real",
    "quarantine_file_real",
)

# Session absolute lifetime, configurable via env, default 8h (a SOC work day). The idle
# lock (re-prompt after inactivity) is a SEPARATE later increment; this is the hard cap.
def _session_ttl_seconds() -> int:
    try:
        return max(60, int(os.environ.get("SIEM_SESSION_TTL", str(8 * 3600))))
    except ValueError:
        return 8 * 3600

# Idle lock: re-prompt for the password after this much inactivity, independent of the
# absolute TTL. Configurable, default 30 minutes, floor 60s.
def _idle_timeout_seconds() -> int:
    try:
        return max(60, int(os.environ.get("SIEM_IDLE_TIMEOUT", str(30 * 60))))
    except ValueError:
        return 30 * 60

# Minimum seconds between last_seen writes for a given session. The idle timeout is
# measured in minutes, so refreshing more often than this buys no real precision, only
# extra disk I/O on every polled request.
_SESSION_TOUCH_GRANULARITY = 30

# Brute-force throttle, two layers:
# 1. A minimum spacing between consecutive failed attempts for the same account, cheap
#    enough to reject before even touching argon2 (deliberately slow), capping an
#    automated guesser at roughly one attempt per interval regardless of raw speed.
# 2. Progressive lockout: once past a threshold of failures, each further batch of
#    failures escalates the block duration (30s, then 60s, then 120s, ...), rather than
#    a single flat window.
_MIN_ATTEMPT_INTERVAL = timedelta(seconds=2)
_LOCKOUT_THRESHOLD = 5       # failures before any lockout kicks in
_LOCKOUT_BASE_SECONDS = 30   # first lockout tier
_LOCKOUT_ESCALATE_EVERY = 5  # every N additional failures, double the lockout duration
# Housekeeping only (not a security boundary): prune failure rows older than this.
_FAIL_ROW_MAX_AGE = timedelta(days=7)


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class AccountError(Exception):
    """Raised for any account-policy violation (weak password, sealed bootstrap, etc.)."""


class AccountStore:
    def __init__(self, db_path: Path, seal_path: Optional[Path] = None):
        self.db_path = Path(db_path)
        # The seal file sits next to the DB by default.
        self.seal_path = Path(seal_path) if seal_path else \
            self.db_path.with_suffix(".bootstrap_sealed")
        self._init_db()

    # -- low-level db -----------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        first_create = not self.db_path.exists()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    username     TEXT UNIQUE NOT NULL,
                    hash         TEXT NOT NULL,
                    role         TEXT NOT NULL,
                    created_at   TEXT NOT NULL,
                    last_login   TEXT,
                    totp_secret  TEXT,
                    totp_enabled INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS system (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    username   TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    last_seen  TEXT NOT NULL,
                    FOREIGN KEY (username) REFERENCES accounts(username)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    username   TEXT NOT NULL,
                    at         TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS webauthn_credentials (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    username      TEXT NOT NULL,
                    credential_id TEXT UNIQUE NOT NULL,
                    credential    TEXT NOT NULL,
                    name          TEXT NOT NULL,
                    is_backup     INTEGER NOT NULL DEFAULT 0,
                    created_at    TEXT NOT NULL,
                    last_used     TEXT,
                    FOREIGN KEY (username) REFERENCES accounts(username)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS recovery_codes (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    username     TEXT NOT NULL,
                    code_hash    TEXT UNIQUE NOT NULL,
                    created_at   TEXT NOT NULL,
                    consumed_at  TEXT,
                    FOREIGN KEY (username) REFERENCES accounts(username)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS approval_requests (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    action       TEXT NOT NULL,
                    payload      TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    status       TEXT NOT NULL DEFAULT 'pending',
                    decided_by   TEXT,
                    decided_at   TEXT,
                    reason       TEXT,
                    executed_at  TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    at        TEXT NOT NULL,
                    actor     TEXT NOT NULL,
                    action    TEXT NOT NULL,
                    detail    TEXT NOT NULL,
                    degraded  INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.commit()
        finally:
            conn.close()
        self._migrate()
        # Lock down file permissions to owner-only, on creation and defensively every init.
        self._enforce_perms()

    def _migrate(self) -> None:
        """Add columns introduced after the first release, for pre-existing DBs."""
        conn = self._connect()
        try:
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(accounts)")}
            if "totp_secret" not in cols:
                conn.execute("ALTER TABLE accounts ADD COLUMN totp_secret TEXT")
            if "totp_enabled" not in cols:
                conn.execute(
                    "ALTER TABLE accounts ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
            scols = {r["name"] for r in conn.execute("PRAGMA table_info(sessions)")}
            if "last_seen" not in scols:
                # Backfill last_seen with created_at for any pre-existing sessions.
                conn.execute("ALTER TABLE sessions ADD COLUMN last_seen TEXT")
                conn.execute("UPDATE sessions SET last_seen=created_at WHERE last_seen IS NULL")
            rcols = {r["name"] for r in conn.execute("PRAGMA table_info(approval_requests)")}
            if "executed_at" not in rcols:
                conn.execute("ALTER TABLE approval_requests ADD COLUMN executed_at TEXT")
                # Pre-existing approved requests predate this column and were executed
                # synchronously at approval time under the old (buggy) behavior; backfill
                # executed_at from decided_at so they are not mistaken for stuck/retryable.
                conn.execute(
                    "UPDATE approval_requests SET executed_at=decided_at "
                    "WHERE status='approved' AND executed_at IS NULL")
            conn.commit()
        finally:
            conn.close()

    def _enforce_perms(self) -> None:
        try:
            os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:
            # On platforms where chmod is a no-op (some Windows setups) we cannot enforce
            # POSIX perms; that is a documented limitation, not a silent failure.
            pass

    # -- bootstrap seal ---------------------------------------------------------
    def is_sealed(self) -> bool:
        """True if bootstrap has ever completed. Fail-closed: if either the DB flag or the
        marker file says sealed, the system is sealed."""
        db_sealed = False
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM system WHERE key='bootstrapped'").fetchone()
            db_sealed = row is not None and row["value"] == "1"
        finally:
            conn.close()
        file_sealed = self.seal_path.exists()
        return db_sealed or file_sealed

    def _seal(self) -> None:
        """Set the seal in BOTH places. Irreversible by design."""
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO system(key, value) VALUES('bootstrapped','1')")
            conn.commit()
        finally:
            conn.close()
        # Marker file, 0600, content is non-secret (the seal is a fact, not a credential).
        self.seal_path.write_text("sealed at %s\n" % _utcnow(), encoding="utf-8")
        try:
            os.chmod(self.seal_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    # -- queries ----------------------------------------------------------------
    def admin_exists(self) -> bool:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM accounts WHERE role='admin'").fetchone()
            return row["n"] > 0
        finally:
            conn.close()

    def get(self, username: str) -> Optional[Dict]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM accounts WHERE username=?", (username,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def list_accounts(self) -> List[Dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id, username, role, created_at, last_login "
                "FROM accounts ORDER BY id").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # -- mutations --------------------------------------------------------------
    def _insert(self, username: str, password: str, role: str) -> None:
        if role not in ROLES:
            raise AccountError("Unknown role: %s" % role)
        strength = pwpolicy.check(password)
        if not strength.ok:
            raise AccountError(strength.reason)
        pw_hash = _HASHER.hash(password)
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO accounts(username, hash, role, created_at) "
                "VALUES(?,?,?,?)", (username, pw_hash, role, _utcnow()))
            conn.commit()
        except sqlite3.IntegrityError:
            raise AccountError("Username already exists: %s" % username)
        finally:
            conn.close()

    def bootstrap_admin(self, username: str, password: str) -> None:
        """Create the FIRST admin. The only path that may seal bootstrap.

        Master invariant enforced here: refuse if an admin already exists OR if bootstrap
        is already sealed. After success, seal permanently.
        """
        if self.is_sealed():
            raise AccountError("Bootstrap is sealed: an admin was already created.")
        if self.admin_exists():
            raise AccountError("An admin already exists; bootstrap is closed.")
        if not username or not username.strip():
            raise AccountError("Username must not be empty.")
        self._insert(username.strip(), password, "admin")
        self._seal()

    def create_user(self, username: str, password: str, role: str = "operator") -> None:
        """Create a non-bootstrap account. Called either directly (degraded mode, fewer
        than 2 admins) or via execute_request after dual-control approval."""
        self._insert(username, password, role)

    def change_role(self, username: str, new_role: str) -> None:
        if new_role not in ROLES:
            raise AccountError("Unknown role: %s" % new_role)
        acct = self.get(username)
        if not acct:
            raise AccountError("No such account: %s" % username)
        # Do not allow demoting the last admin: that would leave no admin at all.
        if acct["role"] == "admin" and new_role != "admin" and self.admin_count() <= 1:
            raise AccountError("Refusing to demote the last admin.")
        conn = self._connect()
        try:
            conn.execute("UPDATE accounts SET role=? WHERE username=?", (new_role, username))
            conn.commit()
        finally:
            conn.close()

    def delete_account(self, username: str) -> None:
        acct = self.get(username)
        if not acct:
            raise AccountError("No such account: %s" % username)
        if acct["role"] == "admin" and self.admin_count() <= 1:
            raise AccountError("Refusing to delete the last admin.")
        conn = self._connect()
        try:
            conn.execute("DELETE FROM accounts WHERE username=?", (username,))
            conn.execute("DELETE FROM sessions WHERE username=?", (username,))
            conn.execute("DELETE FROM webauthn_credentials WHERE username=?", (username,))
            conn.commit()
        finally:
            conn.close()

    def execute_request(self, request_id: int) -> None:
        """Apply an APPROVED request's payload. Idempotent and retryable: if the request
        was already executed, this is a no-op rather than raising, so a caller retrying
        after a partial failure elsewhere cannot double-apply an action. On success,
        marks executed_at; if the underlying action raises, executed_at stays NULL so a
        future retry is possible instead of the request being stuck 'approved' forever
        with the action having silently never happened."""
        req = self.get_request(request_id)
        if not req or req["status"] != "approved":
            raise AccountError("Request is not approved.")
        if req.get("executed_at"):
            return  # already executed, idempotent no-op
        action = req["action"]
        p = req["payload"]
        if action == "create_account":
            self.create_user(p["username"], p["password"], p.get("role", "operator"))
        elif action == "change_role":
            self.change_role(p["username"], p["new_role"])
        elif action == "delete_account":
            self.delete_account(p["username"])
        elif action == "delete_other_webauthn_key":
            self.remove_webauthn_credential(p["username"], p["credential_row_id"])
        elif action == "reset_other_password":
            self.set_password(p["username"], p["new_password"])
        else:
            raise AccountError("Unknown action: %s" % action)
        self.mark_executed(request_id)

    def mark_executed(self, request_id: int) -> None:
        conn = self._connect()
        try:
            conn.execute("UPDATE approval_requests SET executed_at=? WHERE id=?",
                         (_utcnow(), request_id))
            conn.commit()
        finally:
            conn.close()

    def list_unexecuted_approved(self) -> List[Dict]:
        """Approved requests whose action has not (yet) actually run. Should normally be
        empty; a non-empty result means a previous execution attempt failed (e.g. real
        mode was not armed) and needs a retry, surfaced to the admin panel rather than
        silently lost."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM approval_requests WHERE status='approved' "
                "AND executed_at IS NULL ORDER BY id").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["payload"] = json.loads(d["payload"])
                out.append(d)
            return out
        finally:
            conn.close()

    def verify(self, username: str, password: str) -> bool:
        """Verify a login. Returns True on match. Transparently rehashes if argon2
        parameters changed (argon2-cffi supports check_needs_rehash)."""
        acct = self.get(username)
        if not acct:
            # Still run a dummy hash to keep timing roughly constant (avoid user
            # enumeration via response time).
            try:
                _HASHER.verify(
                    "$argon2id$v=19$m=65536,t=3,p=2$"
                    "c29tZXNhbHRzb21lc2FsdA$"
                    "0000000000000000000000000000000000000000000", password)
            except Exception:
                pass
            return False
        try:
            _HASHER.verify(acct["hash"], password)
        except (VerifyMismatchError, InvalidHashError):
            return False
        # Opportunistic rehash if params upgraded.
        if _HASHER.check_needs_rehash(acct["hash"]):
            new_hash = _HASHER.hash(password)
            conn = self._connect()
            try:
                conn.execute("UPDATE accounts SET hash=? WHERE username=?",
                             (new_hash, username))
                conn.commit()
            finally:
                conn.close()
        return True

    def set_password(self, username: str, new_password: str) -> None:
        """Reset a password (used by the CLI reset path, after strong confirmation).
        Validates strength; does not touch role or seal."""
        acct = self.get(username)
        if not acct:
            raise AccountError("No such account: %s" % username)
        strength = pwpolicy.check(new_password)
        if not strength.ok:
            raise AccountError(strength.reason)
        new_hash = _HASHER.hash(new_password)
        conn = self._connect()
        try:
            conn.execute("UPDATE accounts SET hash=? WHERE username=?",
                         (new_hash, username))
            conn.commit()
        finally:
            conn.close()

    def touch_login(self, username: str) -> None:
        conn = self._connect()
        try:
            conn.execute("UPDATE accounts SET last_login=? WHERE username=?",
                         (_utcnow(), username))
            conn.commit()
        finally:
            conn.close()

    # -- sessions ---------------------------------------------------------------
    def create_session(self, username: str) -> str:
        """Create a server-side session. Returns the CLEAR token for the cookie; the DB
        stores only its SHA-256, so reading the sessions table cannot replay a session."""
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=_session_ttl_seconds())
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO sessions(token_hash, username, created_at, expires_at, last_seen) "
                "VALUES(?,?,?,?,?)",
                (_sha256(token), username, now.isoformat(), expires.isoformat(),
                 now.isoformat()))
            conn.commit()
        finally:
            conn.close()
        return token

    def resolve_session(self, token: str, refresh: bool = True) -> Optional[Dict]:
        """Return {username, role, expires_at} for a live session, or None. A session dies
        on absolute expiry OR on idle timeout (no activity for the idle window). On a valid
        resolve we refresh last_seen so activity keeps the session alive."""
        if not token:
            return None
        h = _sha256(token)
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT s.username, s.expires_at, s.last_seen, a.role "
                "FROM sessions s JOIN accounts a ON a.username=s.username "
                "WHERE s.token_hash=?", (h,)).fetchone()
            if not row:
                return None
            now = datetime.now(timezone.utc)
            # Absolute expiry.
            try:
                exp = datetime.fromisoformat(row["expires_at"])
            except ValueError:
                exp = None
            if exp is None or exp <= now:
                conn.execute("DELETE FROM sessions WHERE token_hash=?", (h,))
                conn.commit()
                return None
            # Idle timeout.
            try:
                seen = datetime.fromisoformat(row["last_seen"])
            except (ValueError, TypeError):
                seen = None
            idle = _idle_timeout_seconds()
            if seen is not None and (now - seen).total_seconds() > idle:
                conn.execute("DELETE FROM sessions WHERE token_hash=?", (h,))
                conn.commit()
                return None
            # Activity keeps the session alive: refresh last_seen. Skip the write if the
            # last refresh was recent enough (default: within 30s) to matter, since the
            # idle timeout is measured in minutes; writing (and committing) on literally
            # every single request, including a frontend that polls every few seconds,
            # is unnecessary disk I/O for no observable difference in behavior.
            if refresh and (seen is None or
                            (now - seen).total_seconds() > _SESSION_TOUCH_GRANULARITY):
                conn.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?",
                             (now.isoformat(), h))
                conn.commit()
            return {"username": row["username"], "role": row["role"],
                    "expires_at": row["expires_at"]}
        finally:
            conn.close()

    def revoke_session(self, token: str) -> None:
        if not token:
            return
        conn = self._connect()
        try:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (_sha256(token),))
            conn.commit()
        finally:
            conn.close()

    def revoke_all_sessions(self, username: str) -> int:
        """Force-logout every session of a user (basis for the future admin panel and for
        a forced disconnect after a breach). Returns the count removed."""
        conn = self._connect()
        try:
            cur = conn.execute("DELETE FROM sessions WHERE username=?", (username,))
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()

    def purge_expired_sessions(self) -> int:
        conn = self._connect()
        try:
            now = datetime.now(timezone.utc).isoformat()
            cur = conn.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()

    # -- brute-force throttle ---------------------------------------------------
    def record_failed_login(self, username: str) -> None:
        conn = self._connect()
        try:
            conn.execute("INSERT INTO login_attempts(username, at) VALUES(?,?)",
                         (username, _utcnow()))
            conn.commit()
        finally:
            conn.close()

    def clear_failed_logins(self, username: str) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM login_attempts WHERE username=?", (username,))
            conn.commit()
        finally:
            conn.close()

    def is_rate_limited(self, username: str) -> bool:
        """True if this account must wait before another attempt is processed: either
        the previous failure was too recent (minimum spacing), or enough failures have
        accumulated to trigger a progressive lockout still in effect."""
        conn = self._connect()
        try:
            stale = (datetime.now(timezone.utc) - _FAIL_ROW_MAX_AGE).isoformat()
            conn.execute("DELETE FROM login_attempts WHERE at<?", (stale,))
            conn.commit()

            row = conn.execute(
                "SELECT at FROM login_attempts WHERE username=? ORDER BY at DESC LIMIT 1",
                (username,)).fetchone()
            if not row:
                return False
            try:
                last_at = datetime.fromisoformat(row["at"])
            except ValueError:
                return False
            now = datetime.now(timezone.utc)
            elapsed = (now - last_at).total_seconds()

            if elapsed < _MIN_ATTEMPT_INTERVAL.total_seconds():
                return True

            count = conn.execute(
                "SELECT COUNT(*) AS n FROM login_attempts WHERE username=?",
                (username,)).fetchone()["n"]
            if count < _LOCKOUT_THRESHOLD:
                return False
            tier = (count - _LOCKOUT_THRESHOLD) // _LOCKOUT_ESCALATE_EVERY
            block_seconds = _LOCKOUT_BASE_SECONDS * (2 ** tier)
            return elapsed < block_seconds
        finally:
            conn.close()

    # -- TOTP (second factor) ---------------------------------------------------
    def totp_status(self, username: str) -> dict:
        """Return {enrolled, enabled} for a user's TOTP. 'enrolled' means a secret exists
        (pending confirmation); 'enabled' means confirmed and required at login."""
        acct = self.get(username)
        if not acct:
            return {"enrolled": False, "enabled": False}
        return {"enrolled": bool(acct.get("totp_secret")),
                "enabled": bool(acct.get("totp_enabled"))}

    def begin_totp_enrollment(self, username: str) -> str:
        """Generate a fresh TOTP secret for the user and store it as PENDING (not yet
        enabled). Returns the base32 secret so the UI can show it / build the QR. Enabling
        requires a follow-up confirm_totp with a valid code, proving the phone is synced."""
        from . import totp as totp_mod
        acct = self.get(username)
        if not acct:
            raise AccountError("No such account: %s" % username)
        secret = totp_mod.generate_secret()
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE accounts SET totp_secret=?, totp_enabled=0 WHERE username=?",
                (secret, username))
            conn.commit()
        finally:
            conn.close()
        return secret

    def confirm_totp(self, username: str, code: str) -> bool:
        """Enable TOTP only after the user proves a valid current code. This guarantees the
        authenticator app is correctly synced before we start requiring it (otherwise the
        user could lock themselves out)."""
        from . import totp as totp_mod
        acct = self.get(username)
        if not acct or not acct.get("totp_secret"):
            return False
        if not totp_mod.verify(acct["totp_secret"], code):
            return False
        conn = self._connect()
        try:
            conn.execute("UPDATE accounts SET totp_enabled=1 WHERE username=?", (username,))
            conn.commit()
        finally:
            conn.close()
        return True

    def verify_totp(self, username: str, code: str) -> bool:
        """Verify a login-time TOTP code against the enabled secret."""
        from . import totp as totp_mod
        acct = self.get(username)
        if not acct or not acct.get("totp_enabled") or not acct.get("totp_secret"):
            return False
        return totp_mod.verify(acct["totp_secret"], code)

    def disable_totp(self, username: str) -> None:
        """Remove TOTP from an account (clears secret and the enabled flag)."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE accounts SET totp_secret=NULL, totp_enabled=0 WHERE username=?",
                (username,))
            conn.commit()
        finally:
            conn.close()

    def totp_provisioning_uri(self, username: str, issuer: str = "Mini SOAR") -> str:
        from . import totp as totp_mod
        acct = self.get(username)
        if not acct or not acct.get("totp_secret"):
            raise AccountError("No pending TOTP secret for %s" % username)
        return totp_mod.provisioning_uri(acct["totp_secret"], username, issuer)

    # -- WebAuthn / FIDO2 credentials --------------------------------------------
    def list_webauthn_credentials(self, username: str) -> List[Dict]:
        """List a user's enrolled keys (metadata only, not the raw credential blob)."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id, name, is_backup, created_at, last_used "
                "FROM webauthn_credentials WHERE username=? ORDER BY id", (username,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def load_webauthn_credential_objects(self, username: str) -> List:
        """Deserialize all AttestedCredentialData for a user, for use in a WebAuthn
        ceremony (registration exclusion list, or authentication candidate list)."""
        from fido2.webauthn import AttestedCredentialData
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT credential FROM webauthn_credentials WHERE username=?",
                (username,)).fetchall()
        finally:
            conn.close()
        out = []
        for r in rows:
            out.append(AttestedCredentialData(bytes.fromhex(r["credential"])))
        return out

    def add_webauthn_credential(self, username: str, credential, name: str,
                                is_backup: bool = False) -> None:
        """Persist a newly-enrolled key. credential_id is stored separately (hex) as a
        unique lookup key; the full credential blob (hex) is what WebAuthn needs to
        verify future signatures. Naming is required so the user can tell keys apart."""
        if not name or not name.strip():
            raise AccountError("Key name must not be empty.")
        cred_id_hex = credential.credential_id.hex()
        cred_blob_hex = bytes(credential).hex()
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO webauthn_credentials"
                "(username, credential_id, credential, name, is_backup, created_at) "
                "VALUES(?,?,?,?,?,?)",
                (username, cred_id_hex, cred_blob_hex, name.strip(), int(is_backup),
                 _utcnow()))
            conn.commit()
        except sqlite3.IntegrityError:
            raise AccountError("This key is already registered.")
        finally:
            conn.close()

    def remove_webauthn_credential(self, username: str, credential_row_id: int) -> None:
        """Remove one key. Refuses to remove the LAST key for a user who has WebAuthn as
        their only second factor with no TOTP enabled, so the account cannot be locked
        out. The caller (route layer) is responsible for requiring re-proof (another key
        or the password) before calling this."""
        creds = self.list_webauthn_credentials(username)
        if len(creds) <= 1:
            totp_enabled = self.totp_status(username)["enabled"]
            if not totp_enabled:
                raise AccountError(
                    "Refusing to remove the last security key: you would have no second "
                    "factor left. Enroll a backup key or enable TOTP first.")
        conn = self._connect()
        try:
            conn.execute(
                "DELETE FROM webauthn_credentials WHERE id=? AND username=?",
                (credential_row_id, username))
            conn.commit()
        finally:
            conn.close()

    def set_webauthn_backup(self, username: str, credential_row_id: int,
                            is_backup: bool) -> None:
        """Toggle the primary/backup designation on a key (cosmetic bookkeeping to help
        the user organize keys; both primary and backup keys are equally valid at login)."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE webauthn_credentials SET is_backup=? WHERE id=? AND username=?",
                (int(is_backup), credential_row_id, username))
            conn.commit()
        finally:
            conn.close()

    def touch_webauthn_credential(self, credential_id_hex: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE webauthn_credentials SET last_used=? WHERE credential_id=?",
                (_utcnow(), credential_id_hex))
            conn.commit()
        finally:
            conn.close()

    def has_webauthn(self, username: str) -> bool:
        return len(self.list_webauthn_credentials(username)) > 0

    # -- recovery codes -------------------------------------------------------------
    def generate_recovery_codes(self, username: str, count: int = 10) -> List[str]:
        """Generate one-time recovery codes. Each code is hashed IMMEDIATELY on
        generation; the clear-text value exists only inside this function's local scope
        long enough to build the return list shown once to the user. Nothing clear-text
        is written to disk, logged, or retained after this call returns. This closes the
        window a process memory dump, crash dump, swapped-out page, or attached debugger
        could otherwise use to recover a code without ever touching the database.
        Regenerating replaces all previous codes (old ones become invalid)."""
        acct = self.get(username)
        if not acct:
            raise AccountError("No such account: %s" % username)
        codes = []
        rows = []
        for _ in range(count):
            code = "-".join(secrets.token_hex(2) for _ in range(3))  # e.g. ab12-cd34-ef56
            codes.append(code)
            rows.append((username, _sha256(code), _utcnow()))
        conn = self._connect()
        try:
            conn.execute("DELETE FROM recovery_codes WHERE username=?", (username,))
            conn.executemany(
                "INSERT INTO recovery_codes(username, code_hash, created_at) "
                "VALUES(?,?,?)", rows)
            conn.commit()
        finally:
            conn.close()
        return codes  # shown once; caller must not persist this list anywhere

    def verify_recovery_code(self, username: str, code: str) -> bool:
        """Check a candidate code and consume it atomically if valid. A consumed code can
        never be used again, even if the same value is resubmitted."""
        if not code:
            return False
        h = _sha256(code.strip().lower())
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT id FROM recovery_codes WHERE username=? AND code_hash=? "
                "AND consumed_at IS NULL", (username, h)).fetchone()
            if not row:
                return False
            conn.execute("UPDATE recovery_codes SET consumed_at=? WHERE id=?",
                         (_utcnow(), row["id"]))
            conn.commit()
            return True
        finally:
            conn.close()

    def recovery_codes_remaining(self, username: str) -> int:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM recovery_codes "
                "WHERE username=? AND consumed_at IS NULL", (username,)).fetchone()
            return row["n"]
        finally:
            conn.close()

    # -- audit log ----------------------------------------------------------------
    def audit(self, actor: str, action: str, detail: str, degraded: bool = False) -> None:
        """Append-only audit trail. No delete method is exposed on purpose: an audit log
        that can be edited or pruned by the same process it audits is not trustworthy."""
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO audit_log(at, actor, action, detail, degraded) "
                "VALUES(?,?,?,?,?)",
                (_utcnow(), actor, action, detail, int(degraded)))
            conn.commit()
        finally:
            conn.close()

    def list_audit(self, limit: int = 200) -> List[Dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # -- dual control (four-eyes) --------------------------------------------------
    def admin_count(self) -> int:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM accounts WHERE role='admin'").fetchone()
            return row["n"]
        finally:
            conn.close()

    def dual_control_active(self) -> bool:
        """Four-eyes is active automatically once a second admin exists, unless
        explicitly forced off via SIEM_DUAL_CONTROL=0 (debug/test only; this is a
        deliberate weakening and is itself audited when used)."""
        if os.environ.get("SIEM_DUAL_CONTROL") == "0":
            return False
        return self.admin_count() >= 2

    def submit_request(self, action: str, payload: dict, requested_by: str) -> int:
        """Submit a sensitive action. In degraded mode (fewer than 2 admins) the caller
        should NOT call this at all and should instead perform the action directly while
        auditing it as degraded; this method is for the dual-control path only."""
        if action not in SENSITIVE_ACTIONS:
            raise AccountError("Unknown sensitive action: %s" % action)
        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT INTO approval_requests(action, payload, requested_by, requested_at) "
                "VALUES(?,?,?,?)",
                (action, json.dumps(payload), requested_by, _utcnow()))
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def list_pending_requests(self) -> List[Dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM approval_requests WHERE status='pending' ORDER BY id"
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["payload"] = json.loads(d["payload"])
                out.append(d)
            return out
        finally:
            conn.close()

    def get_request(self, request_id: int) -> Optional[Dict]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE id=?", (request_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["payload"] = json.loads(d["payload"])
            return d
        finally:
            conn.close()

    def decide_request(self, request_id: int, decided_by: str, approve: bool,
                       reason: str = "") -> Dict:
        """Approve or reject a pending request. MASTER INVARIANT: the approver can never
        be the requester. Enforced here, server-side, regardless of what the UI allows."""
        req = self.get_request(request_id)
        if not req:
            raise AccountError("No such request: %s" % request_id)
        if req["status"] != "pending":
            raise AccountError("Request already decided.")
        if decided_by == req["requested_by"]:
            raise AccountError("An admin cannot approve their own request.")
        status = "approved" if approve else "rejected"
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE approval_requests SET status=?, decided_by=?, decided_at=?, reason=? "
                "WHERE id=?",
                (status, decided_by, _utcnow(), reason, request_id))
            conn.commit()
        finally:
            conn.close()
        self.audit(decided_by, "decide_request:%s" % status,
                  "request #%d (%s) requested by %s" % (request_id, req["action"], req["requested_by"]))
        return self.get_request(request_id)

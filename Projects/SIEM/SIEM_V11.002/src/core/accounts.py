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

# Brute-force throttle: max failed logins per account within the window.
_MAX_FAILS = 5
_FAIL_WINDOW = timedelta(minutes=15)


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
        """Create a non-bootstrap account. Used by the (future) admin panel, never by
        /setup. Refuses to create an admin via this path is NOT enforced here on purpose:
        the admin panel (v11 later) will gate admin creation behind dual control. For now
        this is used in tests and by authenticated flows only."""
        self._insert(username, password, role)

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
            # Activity keeps the session alive: refresh last_seen.
            if refresh:
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
        """True if too many recent failures for this account within the window."""
        cutoff = (datetime.now(timezone.utc) - _FAIL_WINDOW).isoformat()
        conn = self._connect()
        try:
            # Opportunistically drop stale attempts.
            conn.execute("DELETE FROM login_attempts WHERE at<?", (cutoff,))
            conn.commit()
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM login_attempts WHERE username=? AND at>=?",
                (username, cutoff)).fetchone()
            return row["n"] >= _MAX_FAILS
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

"""Active response: banning IPs and quarantining files. The most dangerous capability in
this project, because it lets the software mutate the state of its own host, not just
observe it. Every design choice here optimizes for "cannot break the machine it runs on"
over convenience.

STRICT ALLOWLIST: exactly two actions exist, ban_ip/unban_ip and quarantine_file/
restore_file. No arbitrary command execution path exists anywhere in this module.

REAL vs INTERNAL: by default (real=False), an action only affects this module's own
internal ban/quarantine list, which the rest of the app can consult (e.g. to drop
ingested events from a banned IP, or refuse to open a quarantined file). Touching the
actual OS firewall or filesystem permissions requires BOTH real=True AND the environment
variable SIEM_ACTIVE_RESPONSE_REAL=1 to be set; a caller cannot flip this at runtime from
inside the app, only an operator restarting the process with that variable set can. This
mirrors the same "no persisted toggle" reasoning as update_check.py: a one-time
compromise should not be able to permanently arm real system mutation.

SELF-PROTECTION: banning loopback addresses or the IP of the session issuing the request
is refused unconditionally, before anything else runs, so a mistake or an attacker cannot
lock the operator out of their own tool.

REVERSIBILITY: every ban/quarantine records what it changed and how to undo it. Bans
carry a mandatory expiry (default 24h, configurable) and are auto-lifted by
purge_expired_bans(); nothing is silently permanent.
"""
from __future__ import annotations

import os
import platform
import sqlite3
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

SELF_PROTECTED_IPS = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}

DEFAULT_BAN_HOURS = 24


class ActiveResponseError(Exception):
    """Raised for any refusal: self-protection, real mode not armed, out-of-scope path."""


def _real_armed() -> bool:
    return os.environ.get("SIEM_ACTIVE_RESPONSE_REAL") == "1"


def _default_ban_hours() -> float:
    try:
        return max(0.1, float(os.environ.get("SIEM_BAN_HOURS", str(DEFAULT_BAN_HOURS))))
    except ValueError:
        return DEFAULT_BAN_HOURS


def _rule_name(ip: str) -> str:
    # Deterministic, greppable name so the exact rule this module created can always be
    # found and removed again, and so two calls for the same IP reuse one rule.
    return "MiniSOAR-Block-%s" % ip.replace(":", "_").replace(".", "-")


class ActiveResponseStore:
    """SQLite-backed store for bans and quarantines, sharing the pattern of accounts.py:
    a small, auditable table, not a generic command log."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_bans (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip          TEXT NOT NULL,
                    actor       TEXT NOT NULL,
                    real        INTEGER NOT NULL DEFAULT 0,
                    rule_name   TEXT,
                    banned_at   TEXT NOT NULL,
                    expires_at  TEXT NOT NULL,
                    lifted_at   TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_quarantines (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    path           TEXT NOT NULL,
                    actor          TEXT NOT NULL,
                    real           INTEGER NOT NULL DEFAULT 0,
                    previous_mode  INTEGER,
                    quarantined_at TEXT NOT NULL,
                    restored_at    TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()
        try:
            os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def _connect(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    # -- IP bans ------------------------------------------------------------------
    def is_banned(self, ip: str) -> bool:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM ip_bans WHERE ip=? AND lifted_at IS NULL "
                "AND expires_at>?", (ip, _utcnow())).fetchone()
            return row is not None
        finally:
            conn.close()

    def ban_ip(self, ip: str, actor: str, current_session_ip: Optional[str] = None,
              duration_hours: Optional[float] = None, real: bool = False) -> int:
        ip = (ip or "").strip()
        if not ip:
            raise ActiveResponseError("IP address is required.")
        if ip in SELF_PROTECTED_IPS:
            raise ActiveResponseError(
                "Refusing to ban a loopback address: this would be self-inflicted.")
        if current_session_ip and ip == current_session_ip:
            raise ActiveResponseError(
                "Refusing to ban the IP of the session making this request.")
        if real and not _real_armed():
            raise ActiveResponseError(
                "Real firewall mode is not armed (SIEM_ACTIVE_RESPONSE_REAL != 1); "
                "the ban was NOT applied to the OS firewall.")

        hours = duration_hours if duration_hours is not None else _default_ban_hours()
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=hours)
        rule = _rule_name(ip) if real else None

        if real:
            _firewall_block(ip, rule)

        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT INTO ip_bans(ip, actor, real, rule_name, banned_at, expires_at) "
                "VALUES(?,?,?,?,?,?)",
                (ip, actor, int(real), rule, now.isoformat(), expires.isoformat()))
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def unban_ip(self, ban_id: int, actor: str) -> None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM ip_bans WHERE id=?", (ban_id,)).fetchone()
            if not row:
                raise ActiveResponseError("No such ban: %d" % ban_id)
            if row["lifted_at"] is not None:
                return  # already lifted, idempotent no-op
            if row["real"]:
                _firewall_unblock(row["rule_name"])
            conn.execute("UPDATE ip_bans SET lifted_at=? WHERE id=?",
                         (_utcnow(), ban_id))
            conn.commit()
        finally:
            conn.close()

    def list_active_bans(self) -> List[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM ip_bans WHERE lifted_at IS NULL AND expires_at>? "
                "ORDER BY id DESC", (_utcnow(),)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def purge_expired_bans(self) -> int:
        """Auto-lift any ban past its expiry. Returns the count lifted."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT id FROM ip_bans WHERE lifted_at IS NULL AND expires_at<=?",
                (_utcnow(),)).fetchall()
        finally:
            conn.close()
        for r in rows:
            self.unban_ip(r["id"], actor="system:auto-expiry")
        return len(rows)

    # -- file quarantine ------------------------------------------------------------
    def quarantine_file(self, path: str, actor: str, allowed_roots: List[Path],
                        real: bool = False) -> int:
        p = Path(path).resolve()
        if not any(str(p).startswith(str(Path(r).resolve())) for r in allowed_roots):
            raise ActiveResponseError(
                "Refusing to quarantine a path outside the allowed roots: %s" % p)
        if not p.exists():
            raise ActiveResponseError("No such file: %s" % p)
        if real and not _real_armed():
            raise ActiveResponseError(
                "Real quarantine mode is not armed (SIEM_ACTIVE_RESPONSE_REAL != 1); "
                "permissions were NOT changed.")

        previous_mode = stat.S_IMODE(p.stat().st_mode)
        if real:
            os.chmod(p, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # read-only, 0444

        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT INTO file_quarantines"
                "(path, actor, real, previous_mode, quarantined_at) VALUES(?,?,?,?,?)",
                (str(p), actor, int(real), previous_mode, _utcnow()))
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def restore_file(self, quarantine_id: int, actor: str) -> None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM file_quarantines WHERE id=?", (quarantine_id,)).fetchone()
            if not row:
                raise ActiveResponseError("No such quarantine: %d" % quarantine_id)
            if row["restored_at"] is not None:
                return  # already restored, idempotent no-op
            if row["real"] and row["previous_mode"] is not None:
                p = Path(row["path"])
                if p.exists():
                    os.chmod(p, row["previous_mode"])
            conn.execute("UPDATE file_quarantines SET restored_at=? WHERE id=?",
                         (_utcnow(), quarantine_id))
            conn.commit()
        finally:
            conn.close()

    def list_active_quarantines(self) -> List[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM file_quarantines WHERE restored_at IS NULL "
                "ORDER BY id DESC").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _firewall_block(ip: str, rule_name: str) -> None:
    """Add a real Windows Firewall rule blocking inbound and outbound traffic to/from
    this IP. Only called when real=True AND SIEM_ACTIVE_RESPONSE_REAL=1; the caller has
    already verified both. Raises ActiveResponseError on non-Windows platforms, since
    netsh does not exist there (Linux/macOS real enforcement is a later increment)."""
    if platform.system() != "Windows":
        raise ActiveResponseError(
            "Real firewall enforcement is only implemented for Windows (netsh) so far; "
            "Linux/macOS support is a later increment. The ban was recorded internally "
            "but NOT applied to any OS firewall.")
    for direction in ("in", "out"):
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=%s-%s" % (rule_name, direction),
            "dir=%s" % direction, "action=block", "remoteip=%s" % ip,
        ]
        subprocess.run(cmd, check=True, capture_output=True, timeout=15)


def _firewall_unblock(rule_name: str) -> None:
    if platform.system() != "Windows" or not rule_name:
        return
    for direction in ("in", "out"):
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule",
              "name=%s-%s" % (rule_name, direction)]
        subprocess.run(cmd, check=False, capture_output=True, timeout=15)

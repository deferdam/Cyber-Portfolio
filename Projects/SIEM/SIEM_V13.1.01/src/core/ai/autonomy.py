"""Graduated autonomy for AI-assisted triage, per category.

The ladder, from least to most authority:
    SHADOW       | the AI predicts, a human decides, the system only measures agreement.
    SUPERVISED   | the AI's prediction is shown as a suggestion; a human still decides.
    AUTO_TRIAGE  | the AI may set severity/category on its own (low risk, reversible).
    AUTO_CLOSE   | the AI may close a ticket outright (high risk, final disposition).

Two safety mechanisms enforced here, matching the v12 invariants (see ROADMAP.md):
  * The CEILING is set by an admin and is the authority allowlist: the AI never operates
    above it, no matter how good its streak is. Raising a ceiling to AUTO_CLOSE is a
    privilege escalation and is handled as a sensitive action by the caller (app.py),
    exactly like ban_ip_real. Lowering a ceiling is a safety action and always applies
    immediately here; it is never gated.
  * The STREAK is per-category, counts consecutive human-agreed outcomes, and resets to
    zero on a SINGLE human override. On any override the operating state also drops back to
    SUPERVISED immediately, even if the ceiling still allows more, so a fresh mistake cannot
    be followed by more autonomous action before a human looks again.

A global KILL SWITCH can force every category back to SUPERVISED instantly, regardless of
ceiling or streak. Engaging it is a safety action (never gated); disengaging it restores
autonomy and is treated as a privilege change (gated like a ceiling raise) by the caller.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

from core.time import utcnow

SHADOW, SUPERVISED, AUTO_TRIAGE, AUTO_CLOSE = 0, 1, 2, 3
LEVEL_NAMES = {SHADOW: "shadow", SUPERVISED: "supervised",
              AUTO_TRIAGE: "auto_triage", AUTO_CLOSE: "auto_close"}
NAME_TO_LEVEL = {v: k for k, v in LEVEL_NAMES.items()}

# A brand new category starts with ceiling=SHADOW: until an admin explicitly reviews and
# opts it in, the AI cannot even surface a suggestion to a human (SUPERVISED), let alone
# act. This matches the allowlist invariant: the AI never extends its own authority, and a
# category an admin has not looked at yet should not silently start influencing anyone.

DEFAULT_TRIAGE_THRESHOLD = 50    # consecutive human-agreed outcomes to unlock auto-triage
DEFAULT_CLOSE_THRESHOLD = 50     # additional consecutive agreements (on top of triage) for close
DEFAULT_TRIAGE_CONFIDENCE = 0.85
DEFAULT_CLOSE_CONFIDENCE = 0.95  # auto-close needs a strictly higher confidence floor


class AutonomyError(Exception):
    pass


_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_autonomy (
    category            TEXT PRIMARY KEY,
    ceiling             INTEGER NOT NULL DEFAULT 0,
    state               INTEGER NOT NULL DEFAULT 0,
    streak              INTEGER NOT NULL DEFAULT 0,
    triage_threshold    INTEGER NOT NULL DEFAULT %d,
    close_threshold     INTEGER NOT NULL DEFAULT %d,
    triage_confidence   REAL NOT NULL DEFAULT %f,
    close_confidence    REAL NOT NULL DEFAULT %f,
    updated_at          TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_kill_switch (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    engaged INTEGER NOT NULL DEFAULT 0,
    engaged_by TEXT,
    engaged_at TEXT
);
""" % (DEFAULT_TRIAGE_THRESHOLD, DEFAULT_CLOSE_THRESHOLD,
      DEFAULT_TRIAGE_CONFIDENCE, DEFAULT_CLOSE_CONFIDENCE)


class AutonomyStore:
    def __init__(self, db_path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            conn.execute("INSERT OR IGNORE INTO ai_kill_switch(id, engaged) VALUES(1, 0)")
            conn.commit()
        finally:
            conn.close()
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _row_or_default(self, conn: sqlite3.Connection, category: str) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM ai_autonomy WHERE category=?", (category,)).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO ai_autonomy(category, updated_at) VALUES(?,?)",
                (category, utcnow().isoformat()))
            conn.commit()
            row = conn.execute(
                "SELECT * FROM ai_autonomy WHERE category=?", (category,)).fetchone()
        return row

    # -- kill switch --------------------------------------------------------------------
    def kill_switch_engaged(self) -> bool:
        conn = self._connect()
        try:
            row = conn.execute("SELECT engaged FROM ai_kill_switch WHERE id=1").fetchone()
            return bool(row["engaged"]) if row else False
        finally:
            conn.close()

    def engage_kill_switch(self, actor: str) -> None:
        """Safety action: always applies immediately, never gated."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE ai_kill_switch SET engaged=1, engaged_by=?, engaged_at=? WHERE id=1",
                (actor, utcnow().isoformat()))
            conn.commit()
        finally:
            conn.close()

    def disengage_kill_switch(self, actor: str) -> None:
        """Restores autonomy: the CALLER is responsible for gating this as a privilege
        change (see app.py), exactly like raising a ceiling to AUTO_CLOSE."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE ai_kill_switch SET engaged=0, engaged_by=?, engaged_at=? WHERE id=1",
                (actor, utcnow().isoformat()))
            conn.commit()
        finally:
            conn.close()

    # -- ceiling (the admin-approved authority allowlist) --------------------------------
    def get_ceiling(self, category: str) -> int:
        conn = self._connect()
        try:
            return self._row_or_default(conn, category)["ceiling"]
        finally:
            conn.close()

    def set_ceiling(self, category: str, level: int, actor: str) -> int:
        """Lowering a ceiling (or keeping it equal) always applies immediately: it can only
        remove authority. Raising it to AUTO_CLOSE must be routed through dual control by
        the caller BEFORE calling this; this method itself does not gate anything, so it
        must only be invoked once approval (or degraded-mode authorization) is settled."""
        if level not in LEVEL_NAMES:
            raise AutonomyError("Unknown autonomy level: %r" % level)
        conn = self._connect()
        try:
            row = self._row_or_default(conn, category)
            new_state = min(row["state"], level)
            conn.execute(
                "UPDATE ai_autonomy SET ceiling=?, state=?, updated_at=? WHERE category=?",
                (level, new_state, utcnow().isoformat(), category))
            conn.commit()
        finally:
            conn.close()
        return level

    # -- outcome recording: the promotion/demotion engine ---------------------------------
    def record_outcome(self, category: str, ai_label: str, human_label: str,
                       confidence: float) -> Dict:
        """A human just confirmed or overrode the AI's prediction for one item in this
        category. Updates streak and operating state. Returns the new row as a dict."""
        agree = (ai_label == human_label)
        conn = self._connect()
        try:
            row = self._row_or_default(conn, category)
            ceiling = row["ceiling"]
            if agree:
                streak = row["streak"] + 1
                eligible = SUPERVISED
                if (streak >= row["triage_threshold"]
                        and confidence >= row["triage_confidence"]):
                    eligible = AUTO_TRIAGE
                if (streak >= row["triage_threshold"] + row["close_threshold"]
                        and confidence >= row["close_confidence"]):
                    eligible = AUTO_CLOSE
                new_state = min(ceiling, eligible)
            else:
                # A single override resets the streak AND drops the operating state back to
                # SUPERVISED immediately, even if the ceiling still allows more.
                streak = 0
                new_state = min(row["state"], SUPERVISED)
            conn.execute(
                "UPDATE ai_autonomy SET streak=?, state=?, updated_at=? WHERE category=?",
                (streak, new_state, utcnow().isoformat(), category))
            conn.commit()
        finally:
            conn.close()
        return self.get_state(category)

    # -- effective state, accounting for the global kill switch --------------------------
    def get_state(self, category: str) -> Dict:
        conn = self._connect()
        try:
            row = dict(self._row_or_default(conn, category))
        finally:
            conn.close()
        effective = min(row["state"], SUPERVISED) if self.kill_switch_engaged() else row["state"]
        row["effective_state"] = effective
        row["effective_state_name"] = LEVEL_NAMES[effective]
        row["ceiling_name"] = LEVEL_NAMES[row["ceiling"]]
        row["state_name"] = LEVEL_NAMES[row["state"]]
        return row

    def list_categories(self) -> List[Dict]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT category FROM ai_autonomy ORDER BY category").fetchall()
        finally:
            conn.close()
        return [self.get_state(r["category"]) for r in rows]

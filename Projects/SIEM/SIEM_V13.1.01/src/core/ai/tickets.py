"""AI ticket overlay store (v12.2, the container).

An "AI ticket" is NOT a second copy of a SOC ticket. It is an overlay record that links a
real ticket to an AI disposition and its human verification. This keeps the AI's opinion and
the human's confirmation auditable without the AI mutating the real TicketStore on its own
(the hard rail: the AI proposes, a human/dual-control disposes).

States:
    PROPOSED             | the AI suggested a disposition; a human should confirm or correct.
    AUTO_CLOSED_PENDING  | the category was at auto_close and the AI acted; still queued for a
                           human spot-check verification (auto-close is never blind here).
    VERIFIED             | a human confirmed or corrected it. Terminal. The verification is
                           what feeds provenance (a validated training label) and moves the
                           autonomy streak.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

from core.time import utcnow

PROPOSED = "proposed"
AUTO_CLOSED_PENDING = "auto_closed_pending"
VERIFIED = "verified"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ai_tickets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id     TEXT NOT NULL,
    category      TEXT NOT NULL,
    ai_label      TEXT NOT NULL,
    confidence    REAL NOT NULL DEFAULT 0,
    features      TEXT NOT NULL DEFAULT '',
    top_features  TEXT NOT NULL DEFAULT '[]',
    state         TEXT NOT NULL,
    human_label   TEXT,
    assigned_by   TEXT NOT NULL,
    verified_by   TEXT,
    created_at    TEXT NOT NULL,
    verified_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_ai_tickets_state ON ai_tickets(state);
"""


class AITicketError(Exception):
    pass


class AITicketStore:
    def __init__(self, db_path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
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

    def assign(self, ticket_id: str, category: str, ai_label: str, confidence: float,
               features: List[str], top_features: List, state: str, actor: str) -> int:
        if state not in (PROPOSED, AUTO_CLOSED_PENDING):
            raise AITicketError("invalid initial state: %r" % state)
        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT INTO ai_tickets(ticket_id, category, ai_label, confidence, features, "
                "top_features, state, assigned_by, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (ticket_id, category, ai_label, float(confidence),
                 " ".join(features), json.dumps(top_features), state, actor,
                 utcnow().isoformat()))
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def get(self, record_id: int) -> Optional[Dict]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM ai_tickets WHERE id=?", (record_id,)).fetchone()
            return self._to_dict(row) if row else None
        finally:
            conn.close()

    def overlaid_ticket_ids(self, category: str) -> set:
        """Ticket ids that already have an overlay in this category (any state). Used to keep
        auto-inference idempotent: a ticket is never overlaid twice for the same category."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT DISTINCT ticket_id FROM ai_tickets WHERE category=?",
                (category,)).fetchall()
            return {r[0] for r in rows}
        finally:
            conn.close()

    def list(self, view: str = "open") -> List[Dict]:
        q = "SELECT * FROM ai_tickets"
        args = ()
        if view == "proposed":
            q += " WHERE state=?"; args = (PROPOSED,)
        elif view == "pending_verification":
            q += " WHERE state=?"; args = (AUTO_CLOSED_PENDING,)
        elif view == "open":
            q += " WHERE state IN (?,?)"; args = (PROPOSED, AUTO_CLOSED_PENDING)
        elif view == "verified":
            q += " WHERE state=?"; args = (VERIFIED,)
        # "all" -> no filter
        q += " ORDER BY id DESC"
        conn = self._connect()
        try:
            rows = conn.execute(q, args).fetchall()
            return [self._to_dict(r) for r in rows]
        finally:
            conn.close()

    def verify(self, record_id: int, human_label: str, verifier: str) -> Dict:
        rec = self.get(record_id)
        if not rec:
            raise AITicketError("no such AI ticket: %r" % record_id)
        if rec["state"] == VERIFIED:
            raise AITicketError("already verified")
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE ai_tickets SET state=?, human_label=?, verified_by=?, verified_at=? "
                "WHERE id=?",
                (VERIFIED, human_label, verifier, utcnow().isoformat(), record_id))
            conn.commit()
        finally:
            conn.close()
        return self.get(record_id)

    @staticmethod
    def _to_dict(row: sqlite3.Row) -> Dict:
        d = dict(row)
        d["features_list"] = d.get("features", "").split() if d.get("features") else []
        try:
            d["top_features"] = json.loads(d.get("top_features") or "[]")
        except ValueError:
            d["top_features"] = []
        d["agreed"] = (d.get("human_label") == d.get("ai_label")) if d.get("human_label") else None
        return d

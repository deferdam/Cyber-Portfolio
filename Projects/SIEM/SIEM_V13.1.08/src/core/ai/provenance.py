"""Label provenance registry.

This is what makes anti-poisoning demonstrable rather than merely claimed. Every training
label is a HUMAN-VALIDATED verdict (an analyst's ticket disposition), recorded here with who
validated it, from what source, and when. The classifier trains ONLY from this store, so it
can never learn from raw ingested content.

Two poisoning defenses live here:
  * provenance | each label is attributable, so a bad batch can be traced and rolled back,
  * influence cap | when assembling a training set, one source can contribute at most N of
    the most recent labels, so no single actor or import can dominate what the model learns.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import List, Optional, Tuple

from core.time import utcnow

_SCHEMA = """
CREATE TABLE IF NOT EXISTS label_provenance (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    category   TEXT NOT NULL,
    features   TEXT NOT NULL,      -- space-joined sorted feature tokens
    label      TEXT NOT NULL,
    actor      TEXT NOT NULL,      -- the human (or 'import:<name>') who validated it
    source     TEXT NOT NULL,      -- influence bucket (usually == actor)
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_prov_cat ON label_provenance(category);
"""


class ProvenanceStore:
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
        return sqlite3.connect(str(self.db_path))

    def record(self, category: str, features: List[str], label: str,
               actor: str, source: Optional[str] = None) -> None:
        if not category or not label or not actor:
            raise ValueError("category, label and actor are required for a provenance record")
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO label_provenance(category, features, label, actor, source, created_at) "
                "VALUES(?,?,?,?,?,?)",
                (category, " ".join(sorted(set(features))), label, actor,
                 source or actor, utcnow().isoformat()))
            conn.commit()
        finally:
            conn.close()

    def count(self, category: str) -> int:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM label_provenance WHERE category=?", (category,)).fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    def source_counts(self, category: str) -> dict:
        """Labels grouped by source, so an imported batch's weight is visible before and
        after the per-source influence cap is applied."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT source, COUNT(*) FROM label_provenance WHERE category=? "
                "GROUP BY source ORDER BY source", (category,)).fetchall()
            return {r[0]: int(r[1]) for r in rows}
        finally:
            conn.close()

    def purge_source(self, category: str, source: str) -> int:
        """Remove every label from one source in a category (dataset rollback). Human-entered
        labels use source == actor, so purging an 'import:<name>' source can never delete a
        human's own validated labels."""
        conn = self._connect()
        try:
            cur = conn.execute(
                "DELETE FROM label_provenance WHERE category=? AND source=?",
                (category, source))
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()

    def training_set(self, category: str,
                     per_source_cap: Optional[int] = None) -> List[Tuple[List[str], str]]:
        """Return [(feature_tokens, label)] for a category. If per_source_cap is set, each
        source contributes at most that many of its MOST RECENT labels, so no single source
        dominates the model."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT features, label, source, created_at FROM label_provenance "
                "WHERE category=? ORDER BY id DESC", (category,)).fetchall()
        finally:
            conn.close()
        out: List[Tuple[List[str], str]] = []
        per_source = {}
        for features, label, source, _ in rows:   # newest first
            if per_source_cap is not None:
                used = per_source.get(source, 0)
                if used >= per_source_cap:
                    continue
                per_source[source] = used + 1
            out.append((features.split() if features else [], label))
        return out

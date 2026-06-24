"""ticket.py - Ticket dataclass and persistent store.

Each Signal that passes the score threshold becomes a Ticket.
Tickets are written to a JSONL file and kept in memory for the session.

Severity mapping:
  CRITICAL  score >= 0.90
  HIGH      score >= 0.75
  MEDIUM    score >= 0.55
  LOW       score >= 0.35
  INFO      score <  0.35
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from core import vault
from typing import Any, Dict, List, Optional


def _severity(score: float) -> str:
    if score >= 0.90: return "CRITICAL"
    if score >= 0.75: return "HIGH"
    if score >= 0.55: return "MEDIUM"
    if score >= 0.35: return "LOW"
    return "INFO"


def _ticket_id(signal_id: str, ts: str) -> str:
    date = ts[:10].replace("-", "")
    short = hashlib.sha256(signal_id.encode()).hexdigest()[:6].upper()
    return f"TKT-{date}-{short}"


@dataclass
class Ticket:
    ticket_id:        str
    created_at:       str
    updated_at:       str
    status:           str            # open | investigating | resolved | closed
    severity:         str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title:            str
    host:             str
    signal_id:        str
    signal_type:      str
    score:            float
    mitre_tactic:     str
    mitre_technique:  str
    risk_factors:     List[str]
    file_hashes:      Dict[str, str]
    evidence_ids:     List[str]
    explanation:      str
    playbook:         str
    actions_taken:    List[Dict[str, Any]] = field(default_factory=list)
    notes:            str = ""
    assignee:         Optional[str] = None
    process_ancestors: List[Dict[str, Any]] = field(default_factory=list)
    process_children:  List[Dict[str, Any]] = field(default_factory=list)
    process_self:      Optional[Dict[str, Any]] = None
    disposition:       str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ticket_id":       self.ticket_id,
            "created_at":      self.created_at,
            "updated_at":      self.updated_at,
            "status":          self.status,
            "severity":        self.severity,
            "title":           self.title,
            "host":            self.host,
            "signal_id":       self.signal_id,
            "signal_type":     self.signal_type,
            "score":           round(self.score, 4),
            "mitre_tactic":    self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "risk_factors":    self.risk_factors,
            "file_hashes":     self.file_hashes,
            "evidence_ids":    self.evidence_ids,
            "explanation":     self.explanation,
            "playbook":        self.playbook,
            "actions_taken":   self.actions_taken,
            "notes":           self.notes,
            "assignee":        self.assignee,
            "process_ancestors": self.process_ancestors,
            "process_children":  self.process_children,
            "process_self":      self.process_self,
            "disposition":       self.disposition,
        }

    @classmethod
    def from_signal(cls, sig, playbook: str) -> "Ticket":
        now = datetime.now(timezone.utc).isoformat()
        host = sig.host.hostname if sig.host else "unknown"
        sev  = _severity(sig.score)
        tid  = _ticket_id(sig.signal_id, now)
        return cls(
            ticket_id       = tid,
            created_at      = now,
            updated_at      = now,
            status          = "open",
            severity        = sev,
            title           = f"[{sev}] {sig.signal_type} on {host}",
            host            = host,
            signal_id       = sig.signal_id,
            signal_type     = sig.signal_type,
            score           = sig.score,
            mitre_tactic    = sig.mitre_tactic or "",
            mitre_technique = sig.mitre_technique or "",
            risk_factors    = list(sig.risk_factors or []),
            file_hashes     = dict(sig.file_hashes or {}),
            evidence_ids    = list(sig.evidence_event_ids or []),
            explanation     = sig.explanation or "",
            playbook        = playbook,
            process_ancestors = list(getattr(sig, "process_ancestors", []) or []),
            process_children  = list(getattr(sig, "process_children", []) or []),
            process_self      = getattr(sig, "process_self", None),
        )


class TicketStore:
    def __init__(self, path: str = "tickets.jsonl"):
        self._path   = Path(path)
        self._tickets: Dict[str, Ticket] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        for line in self._path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = vault.unpack_line(line)
                t = Ticket(**d)
                self._tickets[t.ticket_id] = t
            except Exception:
                pass

    def add(self, ticket: Ticket) -> None:
        self._tickets[ticket.ticket_id] = ticket
        with open(self._path, "a") as f:
            f.write(vault.pack_line(ticket.to_dict()) + "\n")

    def get(self, ticket_id: str) -> Optional[Ticket]:
        return self._tickets.get(ticket_id)

    def all(self) -> List[Ticket]:
        return list(self._tickets.values())

    def by_severity(self, severity: str) -> List[Ticket]:
        return [t for t in self._tickets.values() if t.severity == severity]

    def open_tickets(self) -> List[Ticket]:
        return [t for t in self._tickets.values() if t.status == "open"]

    def update_status(self, ticket_id: str, status: str, note: str = "") -> bool:
        t = self._tickets.get(ticket_id)
        if not t:
            return False
        t.status     = status
        t.updated_at = datetime.now(timezone.utc).isoformat()
        if note:
            t.notes += f"\n{note}" if t.notes else note
        # Rewrite the whole file on update (simple approach for lab scale)
        with open(self._path, "w") as f:
            for ticket in self._tickets.values():
                f.write(json.dumps(ticket.to_dict()) + "\n")
        return True

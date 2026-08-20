"""orchestrator.py - SOAR orchestrator (v8).

Entry point: SoarOrchestrator.process(signals) -> List[Ticket]

For each Signal:
  1. Score threshold filter  (default >= 0.30)
  2. Match playbook
  3. Create Ticket
  4. Execute playbook steps
  5. Persist Ticket

Also callable from EmailPoller via email_poller.py (signals go
through the same orchestrator regardless of source).

Usage:
    from soar.orchestrator import SoarOrchestrator
    soar = SoarOrchestrator()
    tickets = soar.process(signals)
"""
from __future__ import annotations

import sys
from typing import List, Optional

from core.schemas import Signal
from soar.ticket import Ticket, TicketStore
from soar.playbook import match, execute

_DEFAULT_THRESHOLD = 0.30


class SoarOrchestrator:
    def __init__(self,
                 ticket_path: str = "tickets.jsonl",
                 min_score:   float = _DEFAULT_THRESHOLD):
        self.store     = TicketStore(ticket_path)
        self.min_score = min_score

    def process(self, signals: List[Signal]) -> List[Ticket]:
        tickets: List[Ticket] = []
        for sig in signals:
            if (sig.score or 0.0) < self.min_score:
                continue
            try:
                ticket = self._handle(sig)
                tickets.append(ticket)
            except Exception as exc:
                print(f"[soar] ERROR processing {sig.signal_id}: {exc}", file=sys.stderr)
        return tickets

    def _handle(self, sig: Signal) -> Ticket:
        playbook_name, steps = match(Ticket.from_signal(sig, ""))
        ticket = Ticket.from_signal(sig, playbook_name)
        execute(ticket, steps)
        ticket.status = "open"
        self.store.add(ticket)
        print(
            f"[soar] {ticket.severity:8s} | {ticket.ticket_id} | "
            f"{ticket.signal_type[:40]:40s} | score={ticket.score:.2f} | "
            f"playbook={ticket.playbook}",
            file=sys.stderr,
        )
        return ticket

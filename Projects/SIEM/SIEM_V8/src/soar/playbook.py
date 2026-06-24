"""playbook.py - Playbook definitions and executor.

A playbook is a list of steps. Each step is a callable that receives
the ticket and returns an action result dict.

Matching priority: first playbook whose condition returns True wins.
The last entry (playbook_generic) is the unconditional fallback.
"""
from __future__ import annotations

import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

from soar.actions import (alert_analyst, block_ip, check_hash,
                           disable_ai_service, escalate,
                           isolate_host, quarantine_file)
from soar.ticket import Ticket


# -- Playbook type -------------------------------------------------------------
# A step is a function(ticket) -> dict
Step     = Callable[["Ticket"], Dict[str, Any]]
Playbook = List[Step]


# -- Step factories ------------------------------------------------------------

def _alert(msg_template: str, use_severity: bool = True) -> Step:
    def step(t: Ticket) -> Dict[str, Any]:
        msg = msg_template.format(host=t.host, type=t.signal_type,
                                  score=round(t.score, 2))
        return alert_analyst(msg, t.ticket_id, t.severity if use_severity else "")
    return step

def _isolate() -> Step:
    def step(t: Ticket) -> Dict[str, Any]:
        return isolate_host(t.host, t.ticket_id, f"Signal: {t.signal_type}")
    return step

def _block_source() -> Step:
    def step(t: Ticket) -> Dict[str, Any]:
        src = next((f.split(":", 1)[1] for f in t.risk_factors
                    if f.startswith("brute_force:") or f.startswith("dest:")), "unknown")
        return block_ip(src, t.ticket_id, f"Triggered by {t.signal_type}")
    return step

def _quarantine() -> Step:
    def step(t: Ticket) -> Dict[str, Any]:
        path = next((f.split(":", 1)[1] for f in t.risk_factors
                     if "model_path" in f or "filename" in f), t.host)
        return quarantine_file(path, t.ticket_id, t.file_hashes)
    return step

def _check_hashes() -> Step:
    def step(t: Ticket) -> Dict[str, Any]:
        return check_hash(t.file_hashes, t.ticket_id)
    return step

def _escalate_step() -> Step:
    def step(t: Ticket) -> Dict[str, Any]:
        return escalate(t.ticket_id, f"Score {t.score:.2f} requires Tier 2 review")
    return step

def _disable_ai() -> Step:
    def step(t: Ticket) -> Dict[str, Any]:
        svc = next((f.split(":", 1)[1] for f in t.risk_factors
                    if f.startswith("port:")), "local-ai-service")
        return disable_ai_service(svc, t.ticket_id)
    return step


# -- Playbook registry ---------------------------------------------------------
#
# Format: (condition_fn, playbook_name, steps_list)
# First matching condition wins.

def _sig(t: Ticket, *keywords: str) -> bool:
    return any(k in t.signal_type for k in keywords)

_REGISTRY: List[Tuple[Callable[[Ticket], bool], str, Playbook]] = [

    (lambda t: _sig(t, "ransomware"),
     "playbook_ransomware",
     [
         _alert("Ransomware behavior on {host} - score {score}"),
         _isolate(),
         _escalate_step(),
     ]),

    (lambda t: _sig(t, "reverse_shell", "/dev/tcp", "bash_sigma", "execve_suspicious") and t.score >= 0.78,
     "playbook_reverse_shell",
     [
         _alert("Reverse shell or suspicious execution on {host}"),
         _block_source(),
         _isolate(),
     ]),

    (lambda t: _sig(t, "brute_force"),
     "playbook_brute_force",
     [
         _alert("SSH brute force detected on {host}"),
         _block_source(),
     ]),

    (lambda t: _sig(t, "email."),
     "playbook_email_threat",
     [
         _alert("Email threat on {host} - {type}"),
         _check_hashes(),
         _quarantine(),
     ]),

    (lambda t: _sig(t, "ai."),
     "playbook_ai_tamper",
     [
         _alert("Local AI service tamper on {host} - {type}"),
         _disable_ai(),
         _escalate_step(),
     ]),

    (lambda t: t.score >= 0.80,
     "playbook_high_score",
     [
         _alert("High-confidence signal on {host} - {type} score {score}"),
         _escalate_step(),
     ]),

    (lambda t: True,
     "playbook_generic",
     [
         _alert("Signal detected on {host} - {type} score {score}", use_severity=False),
     ]),
]


def match(ticket: Ticket) -> Tuple[str, Playbook]:
    for condition, name, steps in _REGISTRY:
        try:
            if condition(ticket):
                return name, steps
        except Exception:
            pass
    return "playbook_generic", _REGISTRY[-1][2]


def execute(ticket: Ticket, steps: Playbook) -> None:
    for step in steps:
        try:
            result = step(ticket)
            ticket.actions_taken.append(result)
        except Exception as exc:
            ticket.actions_taken.append({
                "action": "ERROR", "detail": str(exc), "status": "failed"
            })
            print(f"[playbook] ERROR step on {ticket.ticket_id}: {exc}", file=sys.stderr)

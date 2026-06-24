"""ai_network.py — Detect local AI service port/process anomalies.

Three detectors:
  1. Port swap        — unexpected process bound to a known AI port
  2. Process mismatch  — known AI port, but process_name not in baseline
  3. Client redirect   — client process connecting to a non-baseline AI port

MITRE ATLAS:
  AML.T0012 — Valid Accounts (pivot via local AI service)
  AML.T0040 — Network Traffic Capture (local proxy)
"""
from __future__ import annotations

import hashlib
import sys
from typing import List

from core.schemas import CanonicalEvent, Signal
from detect.modules.ai_baseline import load_default, match_framework, is_known_ai_port, observe


def _sig_id(stype: str, eid: str) -> str:
    return "sig-" + hashlib.sha256(f"{stype}|{eid}".encode()).hexdigest()[:16]


def _is_bind(ev: CanonicalEvent) -> bool:
    raw = ev.raw or {}
    return str(raw.get("syscall") or "") == "49" or "bind" in (ev.process.command_line or "").lower()


def _is_connect(ev: CanonicalEvent) -> bool:
    raw = ev.raw or {}
    return str(raw.get("syscall") or "") == "42"


def run(events: List[CanonicalEvent]) -> List[Signal]:
    defaults = load_default()
    signals: List[Signal] = []

    for ev in events:
        raw = ev.raw or {}
        port = raw.get("port") or ev.network.dest_port
        if not port:
            continue
        port = int(port)
        proc = ev.process.name or ""

        if not is_known_ai_port(port, defaults):
            continue

        fw = match_framework(proc, port, defaults)

        # ── bind() on known AI port ────────────────────────────────────────
        if _is_bind(ev):
            if fw is None:
                signals.append(Signal(
                    signal_id=_sig_id("ai.port_swap", ev.event_id),
                    signal_type="ai.unexpected_process_on_ai_port",
                    host=ev.host,
                    process_key=f"{proc}|{ev.process.pid or 0}",
                    score=0.90, confidence=0.85,
                    risk_factors=[f"port:{port}", f"unexpected_process:{proc}"],
                    evidence_event_ids=[ev.event_id],
                    explanation=f"Process '{proc}' bound to known AI port {port} but does not match any baseline framework. Possible local AI service replacement or proxy.",
                    recommended_actions=["Verifier le binaire du processus.", "Comparer le hash avec le binaire legitime.", "Isoler le service IA."],
                    mitre_tactic="Initial Access",
                    mitre_technique="AML.T0012",
                ))
            else:
                observe(fw, proc, port)

        # ── connect() to known AI port from unexpected client ──────────────
        if _is_connect(ev):
            if fw is None:
                signals.append(Signal(
                    signal_id=_sig_id("ai.client_redirect", ev.event_id),
                    signal_type="ai.client_connect_unexpected_process",
                    host=ev.host,
                    process_key=f"{proc}|{ev.process.pid or 0}",
                    score=0.70, confidence=0.65,
                    risk_factors=[f"port:{port}", f"client_process:{proc}"],
                    evidence_event_ids=[ev.event_id],
                    explanation=f"Process '{proc}' connected to AI port {port} from a process not in baseline. Possible MITM proxy or redirected client.",
                    recommended_actions=["Verifier la configuration client (endpoint, port).", "Verifier l'absence de proxy local non-autorise."],
                    mitre_tactic="Collection",
                    mitre_technique="AML.T0040",
                ))

    return signals

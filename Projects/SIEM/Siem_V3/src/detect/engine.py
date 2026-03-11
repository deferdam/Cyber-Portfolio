"""engine.py — Detection engine orchestrator.

Three-layer architecture:
  1. Signature    — fast IOC/pattern matching (ransomware hashes, PowerShell patterns)
  2. Behavioral   — action patterns (mass writes, extension rename, VSS deletion, LOTL)
  3. Correlation  — temporal event chains (recon → exec sequences)

The process tree is built once and passed to behavioral/correlation detectors
that need parent-child context.
"""
from __future__ import annotations

import sys
from typing import List

from core.schemas import CanonicalEvent, Signal
from detect.modules import ransomware_v4, powershell_sigma, lotl_sigma
from normalize.process_tree import build_tree


def run_all(events: List[CanonicalEvent]) -> List[Signal]:
    """Run all detection layers and return aggregated signals.

    Order matters:
      1. Build process tree (used by behavioral + correlation layers)
      2. Layer 1 — Signature: ransomware hashes
      3. Layer 2 — Behavioral: PowerShell patterns, LOTL patterns, spawn suspects
      4. Layer 3 — Correlation: temporal recon sequences
    """
    signals: List[Signal] = []

    # ── Pre-computation: process tree ─────────────────────────────────────────
    try:
        tree = build_tree(events)
    except Exception as exc:  # noqa: BLE001
        print(f"[engine] WARN process tree build failed: {exc}", file=sys.stderr)
        tree = None

    # ── Layer 1: Signature ────────────────────────────────────────────────────
    try:
        signals.extend(ransomware_v4.run(events))
    except Exception as exc:
        print(f"[engine] ERROR ransomware_v4: {exc}", file=sys.stderr)

    # ── Layer 2: Behavioral ───────────────────────────────────────────────────
    try:
        ps_signals = powershell_sigma.run(events, rule_path="powershell_suspicious.yaml")
        signals.extend(ps_signals)
    except Exception as exc:
        print(f"[engine] ERROR powershell_sigma: {exc}", file=sys.stderr)
        ps_signals = []

    try:
        signals.extend(lotl_sigma.run(events, tree=tree))
    except Exception as exc:
        print(f"[engine] ERROR lotl_sigma: {exc}", file=sys.stderr)

    # ── Layer 3: Correlation ──────────────────────────────────────────────────
    try:
        correlated = powershell_sigma.correlate_recon_sequence(events, ps_signals)
        signals.extend(correlated)
    except Exception as exc:
        print(f"[engine] ERROR powershell_sigma.correlate: {exc}", file=sys.stderr)

    return signals
"""engine.py — Detection engine orchestrator (v5.5 — dual OS + deduplication).

Three-layer architecture:
  1. Signature    — fast IOC/pattern matching
  2. Behavioral   — action patterns (PowerShell, LOTL, bash, auditd, auth)
  3. Correlation  — temporal event chains

v5.5 addition: deduplicator.merge() runs after all detection layers and
before the correlator. Signals sharing the same event evidence are merged
into one consolidated Signal with an aggregated score.
"""
from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import List

from core.schemas import CanonicalEvent, Signal
from normalize.process_tree import build_tree
from detect.deduplicator import merge as dedup_merge, stats as dedup_stats

OS = platform.system()
_MODULES_DIR = Path(__file__).parent / "modules"

if OS == "Windows":
    from detect.modules import powershell_sigma, lotl_sigma, ransomware_v4
    _PS_RULE_FILES = [
        str(_MODULES_DIR / "ps_scriptblock.yaml"),
        str(_MODULES_DIR / "ps_persistence.yaml"),
        str(_MODULES_DIR / "ps_privilege_escalation.yaml"),
        str(_MODULES_DIR / "powershell_suspicious.yaml"),
    ]
else:
    if OS not in ("Linux",):
        print(f"[engine] WARN OS={OS!r}, using Linux pipeline.", file=sys.stderr)
    from detect.modules import bash_sigma, linux_auditd, linux_auth, ransomware_linux
    _LINUX_RULE_FILES = [
        str(_MODULES_DIR / "linux_suspicious.yaml"),
        str(_MODULES_DIR / "linux_auditd.yaml"),
        str(_MODULES_DIR / "linux_auth.yaml"),
    ]


def _run_windows(events: List[CanonicalEvent], tree) -> List[Signal]:
    signals: List[Signal] = []

    try:
        signals.extend(ransomware_v4.run(events))
    except Exception as exc:
        print(f"[engine] ERROR ransomware_v4: {exc}", file=sys.stderr)

    ps_signals: List[Signal] = []
    try:
        ps_signals = powershell_sigma.run(events, rule_paths=_PS_RULE_FILES)
        signals.extend(ps_signals)
    except Exception as exc:
        print(f"[engine] ERROR powershell_sigma: {exc}", file=sys.stderr)

    try:
        signals.extend(lotl_sigma.run(events, tree=tree))
    except Exception as exc:
        print(f"[engine] ERROR lotl_sigma: {exc}", file=sys.stderr)

    try:
        signals.extend(
            powershell_sigma.correlate_recon_sequence(events, ps_signals)
        )
    except Exception as exc:
        print(f"[engine] ERROR ps_correlate: {exc}", file=sys.stderr)

    return signals


def _run_linux(events: List[CanonicalEvent], tree) -> List[Signal]:
    signals: List[Signal] = []

    try:
        signals.extend(ransomware_linux.run(events))
    except Exception as exc:
        print(f"[engine] ERROR ransomware_linux: {exc}", file=sys.stderr)

    try:
        signals.extend(bash_sigma.run(events, rule_paths=_LINUX_RULE_FILES))
    except Exception as exc:
        print(f"[engine] ERROR bash_sigma: {exc}", file=sys.stderr)

    try:
        signals.extend(linux_auditd.run(events))
    except Exception as exc:
        print(f"[engine] ERROR linux_auditd: {exc}", file=sys.stderr)

    try:
        signals.extend(linux_auth.run(events))
    except Exception as exc:
        print(f"[engine] ERROR linux_auth: {exc}", file=sys.stderr)

    return signals


def run_all(events: List[CanonicalEvent]) -> List[Signal]:
    """Run all detection layers, deduplicate, and return consolidated signals.

    Pipeline (v5.5):
      1. Build process tree
      2. Run OS-appropriate detection pipeline → raw signals
      3. Deduplicate + aggregate scores          ← NEW in v5.5
      4. Return merged signals to correlator
    """
    try:
        tree = build_tree(events)
    except Exception as exc:
        print(f"[engine] WARN process tree: {exc}", file=sys.stderr)
        tree = None

    raw_signals = (
        _run_windows(events, tree) if OS == "Windows"
        else _run_linux(events, tree)
    )

    # ── v5.5: deduplication ───────────────────────────────────────────────────
    merged_signals = dedup_merge(raw_signals)
    print(
        f"[engine] {dedup_stats(len(raw_signals), len(merged_signals))}",
        file=sys.stderr,
    )

    return merged_signals

"""engine.py — Detection engine orchestrator (v7 — dual OS + AI + email + dedup).

v7 changes:
  - Module imports updated for new subdirectory structure
  - Email detection added (email_attachments + email_phishing)
  - Hash propagation via extract_hashes() in all modules
"""
from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import List

from core.schemas import CanonicalEvent, Signal
from normalize.process_tree import build_tree
from detect.deduplicator import merge as dedup_merge, stats as dedup_stats
from detect.modules.ai import ai_network, ai_integrity
from detect.modules.email import email_attachments, email_phishing

OS = platform.system()
_WIN_DIR   = Path(__file__).parent / "modules" / "windows"
_LIN_DIR   = Path(__file__).parent / "modules" / "linux"

if OS == "Windows":
    from detect.modules.windows import powershell_sigma, lotl_sigma, ransomware_v4
    _PS_RULE_FILES = [
        str(_WIN_DIR / "ps_scriptblock.yaml"),
        str(_WIN_DIR / "ps_persistence.yaml"),
        str(_WIN_DIR / "ps_privilege_escalation.yaml"),
        str(_WIN_DIR / "powershell_suspicious.yaml"),
    ]
else:
    if OS not in ("Linux",):
        print(f"[engine] WARN OS={OS!r}, using Linux pipeline.", file=sys.stderr)
    from detect.modules.linux import bash_sigma, linux_auditd, linux_auth, ransomware_linux
    _LINUX_RULE_FILES = [
        str(_LIN_DIR / "linux_suspicious.yaml"),
        str(_LIN_DIR / "linux_auditd.yaml"),
        str(_LIN_DIR / "linux_auth.yaml"),
    ]


def _run_ai(events):
    signals = []
    for fn, label in [(ai_network.run, "ai_network"), (ai_integrity.run, "ai_integrity")]:
        try: signals.extend(fn(events))
        except Exception as e: print(f"[engine] ERROR {label}: {e}", file=sys.stderr)
    return signals


def _run_email(events):
    signals = []
    email_evs = [e for e in events if e.source == "email"]
    if not email_evs:
        return signals
    for fn, label in [(email_attachments.run, "email_attach"), (email_phishing.run, "email_phish")]:
        try: signals.extend(fn(email_evs))
        except Exception as e: print(f"[engine] ERROR {label}: {e}", file=sys.stderr)
    return signals


def _run_windows(events, tree):
    signals = []
    try: signals.extend(ransomware_v4.run(events))
    except Exception as e: print(f"[engine] ERROR ransomware_v4: {e}", file=sys.stderr)
    ps_signals = []
    try:
        ps_signals = powershell_sigma.run(events, rule_paths=_PS_RULE_FILES)
        signals.extend(ps_signals)
    except Exception as e: print(f"[engine] ERROR powershell_sigma: {e}", file=sys.stderr)
    try: signals.extend(lotl_sigma.run(events, tree=tree))
    except Exception as e: print(f"[engine] ERROR lotl_sigma: {e}", file=sys.stderr)
    try: signals.extend(powershell_sigma.correlate_recon_sequence(events, ps_signals))
    except Exception as e: print(f"[engine] ERROR ps_correlate: {e}", file=sys.stderr)
    signals.extend(_run_ai(events))
    signals.extend(_run_email(events))
    return signals


def _run_linux(events, tree):
    signals = []
    try: signals.extend(ransomware_linux.run(events))
    except Exception as e: print(f"[engine] ERROR ransomware_linux: {e}", file=sys.stderr)
    try: signals.extend(bash_sigma.run(events, rule_paths=_LINUX_RULE_FILES))
    except Exception as e: print(f"[engine] ERROR bash_sigma: {e}", file=sys.stderr)
    try: signals.extend(linux_auditd.run(events))
    except Exception as e: print(f"[engine] ERROR linux_auditd: {e}", file=sys.stderr)
    try: signals.extend(linux_auth.run(events))
    except Exception as e: print(f"[engine] ERROR linux_auth: {e}", file=sys.stderr)
    signals.extend(_run_ai(events))
    signals.extend(_run_email(events))
    return signals


def run_all(events: List[CanonicalEvent]) -> List[Signal]:
    try: tree = build_tree(events)
    except Exception as e:
        print(f"[engine] WARN process tree: {e}", file=sys.stderr); tree = None
    raw = _run_windows(events, tree) if OS == "Windows" else _run_linux(events, tree)
    merged = dedup_merge(raw)
    print(f"[engine] {dedup_stats(len(raw), len(merged))}", file=sys.stderr)
    return merged

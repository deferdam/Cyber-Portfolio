"""engine.py - Detection engine orchestrator (v7 - dual OS + AI + email + dedup).

v7 changes:
  - Module imports updated for new subdirectory structure
  - Email detection added (email_attachments + email_phishing)
  - Hash propagation via extract_hashes() in all modules
"""
from __future__ import annotations

import platform
import sys
from dataclasses import replace
from pathlib import Path
from typing import List

from core.schemas import CanonicalEvent, Signal
from normalize.process_tree import build_tree
from detect.deduplicator import merge as dedup_merge, stats as dedup_stats
from detect.modules.ai import ai_network, ai_integrity
from detect.modules.email import email_attachments, email_phishing
from detect.modules.imported import snort_alert, net_suspect

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


def _run_imported(events):
    """Pre-detected alerts from external sensors (Snort, ...) -> signals.
    OS-independent; runs in both pipelines."""
    signals = []
    try: signals.extend(snort_alert.run(events))
    except Exception as e: print(f"[engine] ERROR snort_alert: {e}", file=sys.stderr)
    try: signals.extend(net_suspect.run(events))
    except Exception as e: print(f"[engine] ERROR net_suspect: {e}", file=sys.stderr)
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
    signals.extend(_run_imported(events))
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
    signals.extend(_run_imported(events))
    return signals


def _attach_process_context(signals, events, tree):
    """Return signals enriched with process ancestry from the tree.

    Signal is a frozen dataclass, so we rebuild each enriched signal with
    dataclasses.replace rather than mutating in place. Read-only on the tree.
    If the tree is missing or the triggering event has no PID, the signal is
    returned unchanged (empty context lists).
    """
    if not tree:
        return signals
    idx = {ev.event_id: ev for ev in events}
    out = []
    for sig in signals:
        ev = None
        for eid in sig.evidence_event_ids:
            if eid in idx:
                ev = idx[eid]
                break
        if ev is None or not ev.process or not ev.process.pid:
            out.append(sig)
            continue
        host = ev.host.hostname
        pid = ev.process.pid
        anc = tree.ancestor_nodes(host, pid)
        chi = tree.child_nodes(host, pid)
        img = ev.process.name or (ev.process.image_path or "").split("/")[-1].split("\\")[-1]
        self_node = {
            "image": img or "process",
            "pid": pid,
            "ppid": ev.process.ppid,
            "command_line": ev.process.command_line,
            "event_id": ev.event_id,
            "host": host,
        }
        out.append(replace(sig, process_ancestors=anc, process_children=chi, process_self=self_node))
    return out


def run_all(events: List[CanonicalEvent]) -> List[Signal]:
    try: tree = build_tree(events)
    except Exception as e:
        print(f"[engine] WARN process tree: {e}", file=sys.stderr); tree = None
    raw = _run_windows(events, tree) if OS == "Windows" else _run_linux(events, tree)
    merged = dedup_merge(raw)
    merged = _attach_process_context(merged, events, tree)
    print(f"[engine] {dedup_stats(len(raw), len(merged))}", file=sys.stderr)
    return merged

from __future__ import annotations
import platform, sys
from pathlib import Path
from typing import List
from core.schemas import CanonicalEvent, Signal
from normalize.process_tree import build_tree

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
        print(f"[engine] WARN OS={OS}, using Linux pipeline.", file=sys.stderr)
    from detect.modules import bash_sigma, linux_auditd, linux_auth, ransomware_linux
    _LINUX_RULE_FILES = [
        str(_MODULES_DIR / "linux_suspicious.yaml"),
        str(_MODULES_DIR / "linux_auditd.yaml"),
        str(_MODULES_DIR / "linux_auth.yaml"),
    ]

def _run_windows(events, tree):
    sigs = []
    try: sigs.extend(ransomware_v4.run(events))
    except Exception as e: print(f"[engine] ERROR ransomware_v4: {e}", file=sys.stderr)
    ps_sigs = []
    try:
        ps_sigs = powershell_sigma.run(events, rule_paths=_PS_RULE_FILES)
        sigs.extend(ps_sigs)
    except Exception as e: print(f"[engine] ERROR powershell_sigma: {e}", file=sys.stderr)
    try: sigs.extend(lotl_sigma.run(events, tree=tree))
    except Exception as e: print(f"[engine] ERROR lotl_sigma: {e}", file=sys.stderr)
    try: sigs.extend(powershell_sigma.correlate_recon_sequence(events, ps_sigs))
    except Exception as e: print(f"[engine] ERROR ps_correlate: {e}", file=sys.stderr)
    return sigs

def _run_linux(events, tree):
    sigs = []
    try: sigs.extend(ransomware_linux.run(events))
    except Exception as e: print(f"[engine] ERROR ransomware_linux: {e}", file=sys.stderr)
    try: sigs.extend(bash_sigma.run(events, rule_paths=_LINUX_RULE_FILES))
    except Exception as e: print(f"[engine] ERROR bash_sigma: {e}", file=sys.stderr)
    try: sigs.extend(linux_auditd.run(events))
    except Exception as e: print(f"[engine] ERROR linux_auditd: {e}", file=sys.stderr)
    try: sigs.extend(linux_auth.run(events))
    except Exception as e: print(f"[engine] ERROR linux_auth: {e}", file=sys.stderr)
    return sigs

def run_all(events: List[CanonicalEvent]) -> List[Signal]:
    try: tree = build_tree(events)
    except Exception as e:
        print(f"[engine] WARN process tree: {e}", file=sys.stderr); tree = None
    return _run_windows(events, tree) if OS == "Windows" else _run_linux(events, tree)

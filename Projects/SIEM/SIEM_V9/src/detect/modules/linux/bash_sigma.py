from __future__ import annotations
from core.hashes import extract_hashes
import warnings
from pathlib import Path
from typing import List, Optional
from core.ids import process_key
from core.schemas import CanonicalEvent, Signal
from detect.modules.windows.powershell_sigma import _parse_simple_sigma_yaml, _read_text

try:
    from core.ids import stable_event_id as _sid
except Exception:
    _sid = None

_LINUX_SOURCES = {"syslog","auditd","bash","linux","auth","journald"}

def _is_linux_event(ev):
    src = (ev.source or "").lower()
    if src in _LINUX_SOURCES: return True
    if (ev.raw or {}).get("type") in ("EXECVE","SYSCALL","PROCTITLE","PATH"): return True
    raw = ev.raw or {}
    has_eid = any(raw.get(k) for k in ("EventID","event_id","eventid"))
    if not has_eid and ev.event_type in ("process","other","auth"): return True
    return False

def _get_field(ev, field):
    raw = ev.raw or {}
    f = field.lower()
    if f == "commandline":
        cmd = getattr(ev.process,"command_line",None)
        if cmd: return str(cmd)
        return str(raw.get("args") or raw.get("cmdline") or raw.get("command_line") or "")
    v = raw.get(field)
    return "" if v is None else str(v)

def _make_signal_id(ev, rule_title, matched):
    payload = {"kind":"signal","type":"bash_sigma","rule":rule_title,
               "event_id":ev.event_id,"matched":",".join(sorted(matched)),"host":ev.host.hostname}
    return _sid(payload) if _sid else f"sig|bash_sigma|{ev.event_id}|{','.join(sorted(matched))}"

def run(events, rule_paths=None):
    if rule_paths is None: rule_paths = ["linux_suspicious.yaml"]
    signals = []
    for rule_path in rule_paths:
        path = Path(rule_path)
        if not path.exists():
            warnings.warn(f"[bash_sigma] Rule file not found: {rule_path}", RuntimeWarning, stacklevel=2)
            continue
        rule = _parse_simple_sigma_yaml(_read_text(path))
        for ev in events:
            if not _is_linux_event(ev): continue
            matched = [sel for sel,(field,needles) in rule.selections.items()
                       if (t := _get_field(ev,field)) and any(n in t for n in needles)]
            if not matched: continue
            pk = process_key(getattr(ev.process,"name",None), getattr(ev.process,"pid",None),
                             getattr(ev.process,"image_path",None))
            conf = min(1.0, 0.6 + 0.1*len(matched))
            signals.append(Signal(
                signal_id=_make_signal_id(ev,rule.title,matched),
                signal_type="bash_sigma", host=ev.host, process_key=pk,
                score=conf, confidence=conf,
                risk_factors=[f"Matched {m}" for m in matched],
                evidence_event_ids=[ev.event_id],
                file_hashes=extract_hashes(ev),
                explanation=f"Linux event matched '{rule.title}' via {', '.join(matched)}",
                recommended_actions=["Verify the parent process."],
                mitre_tactic="Execution", mitre_technique="T1059.004",
            ))
    return signals

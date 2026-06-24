from __future__ import annotations
from core.hashes import extract_hashes
from typing import Any, Dict, List
from core.ids import process_key as make_pk
from core.schemas import CanonicalEvent, Signal
from detect.modules.common.ransomware_core import detect_ransomware

_ABNORMAL_LINUX = ("/tmp/","/dev/shm/","/var/tmp/")
_SYSTEM_LINUX   = ("/usr/bin/","/usr/sbin/","/bin/","/sbin/","/usr/lib/","/usr/local/bin/","/opt/")
_ENC_TOOLS = ("openssl enc","openssl aes","gpg --symmetric","gpg -c ","age -e","ccrypt","bcrypt","mcrypt")
_RANSOM_NOTES = ("readme_how_to","decrypt_files","how_to_decrypt","recovery_instructions","_encrypted",".locked",".crypt",".enc")

def _is_abnormal(path):
    if not path: return False
    p = path.lower()
    if any(p.startswith(a) for a in _ABNORMAL_LINUX): return True
    if p.startswith("/home/") and "/.local/bin/" not in p and "/.cargo/bin/" not in p: return True
    return False

def _is_root(uid):
    try: return int(uid) == 0
    except: return False

def _enc_tools(events):
    found = []
    for ev in events:
        cl = (ev.process.command_line or "").lower()
        for t in _ENC_TOOLS:
            if t in cl: found.append(f"enc:{t.split()[0]}"); break
    return found

def _ransom_notes(events):
    count = 0
    for ev in events:
        if ev.event_type != "file": continue
        fp = (ev.file.path or "").lower()
        op = (ev.file.operation or "").lower()
        if op in ("write","create","rename") and any(p in fp for p in _RANSOM_NOTES): count += 1
    return count

def run(events):
    evs, evidence_by_proc = [], {}
    for e in events:
        raw = {"timestamp":e.event_time_utc,"event_type":e.event_type if e.event_type in ("file","network") else "file",
               "process_name":e.process.name,"pid":e.process.pid,"operation":e.file.operation,"file_path":e.file.path,
               "direction":e.network.direction,"dest_ip":e.network.dest_ip,"dest_port":e.network.dest_port,
               "protocol":e.network.protocol,"process_path":e.process.image_path,"integrity_level":None,
               "uid":(e.raw or {}).get("uid") or e.user.sid}
        evs.append(raw)
        pk = make_pk(e.process.name, e.process.pid, e.process.image_path)
        evidence_by_proc.setdefault(pk, []).append(e.event_id)

    report = detect_ransomware(evs)
    enc_tools_found = _enc_tools(events)
    notes = _ransom_notes(events)
    sigs = []
    if not events: return sigs
    host = events[0].host

    for proc in report.get("suspicious_processes", []):
        pk = make_pk(proc.get("process_name"), proc.get("pid"), proc.get("process_path"))
        factors = list(proc.get("risk_factors", []))
        score = float(proc.get("risk_score", 0.0))
        ppath = proc.get("process_path") or ""
        uid = proc.get("uid")

        if _is_abnormal(ppath) and proc.get("total_unique_files",0) >= 30:
            factors.append("abnormal_linux_proc_location"); score = min(1.0, score+0.10)
        if _is_root(uid) and ppath and not any(ppath.lower().startswith(s) for s in _SYSTEM_LINUX):
            factors.append("root_non_system_path"); score = min(1.0, score+0.12)
        if enc_tools_found:
            factors.extend(enc_tools_found[:2]); score = min(1.0, score+0.08*len(enc_tools_found))
        if notes:
            factors.append(f"ransom_notes:{notes}"); score = min(1.0, score+0.15)
        if score <= 0.0: continue

        bits = [f"burst={proc.get('max_burst_unique_files')}",
                f"long={proc.get('long_window_unique_files')}",
                f"spread={proc.get('directory_spread')}"]
        explanation = " ; ".join(bits + [f"factors={','.join(factors)}"])
        actions = (["kill_process","isolate_host","block_network","alert_human"] if score >= 0.85
                   else ["alert_human","increase_monitoring"] if score >= 0.60
                   else ["log_suspicious"])

        sigs.append(Signal(
            signal_id=f"rw_linux_{pk}", signal_type="ransomware_behavior_linux",
            host=host, process_key=pk, score=score, confidence=score,
            risk_factors=factors, evidence_event_ids=evidence_by_proc.get(pk,[]),
            explanation=explanation, recommended_actions=actions,
            mitre_tactic="Impact", mitre_technique="T1486",
        ))
    return sigs

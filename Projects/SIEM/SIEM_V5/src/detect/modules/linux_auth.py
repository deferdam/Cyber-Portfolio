from __future__ import annotations
import hashlib, re, sys
from collections import defaultdict
from typing import Dict, List
from core.schemas import CanonicalEvent, Signal

def _sig_id(stype, eid, extra=""):
    blob = f"{stype}|{eid}|{extra}".encode()
    return "sig-" + hashlib.sha256(blob).hexdigest()[:16]

def _is_auth(ev):
    src = (ev.source or "").lower()
    if src in ("auth","syslog","journald","linux"): return True
    if ev.event_type == "auth": return True
    msg = str((ev.raw or {}).get("message") or "").lower()
    return any(k in msg for k in ("sshd","sudo","pam_unix","session opened","failed password"))

def _msg(ev): return str((ev.raw or {}).get("message") or (ev.raw or {}).get("msg") or "")

def _make(stype, ev, score, conf, factors, expl, actions, tactic, tech):
    return Signal(signal_id=_sig_id(stype,ev.event_id), signal_type=stype, host=ev.host,
        process_key=f"{ev.process.name or 'sshd'}|{ev.process.pid or 0}", user_key=ev.user.username,
        score=score, confidence=conf, risk_factors=factors, evidence_event_ids=[ev.event_id],
        explanation=expl, recommended_actions=actions, mitre_tactic=tactic, mitre_technique=tech)

_SSH_FAIL_RE = re.compile(r"Failed (password|publickey) for (?:invalid user )?(\S+) from ([\d.a-fA-F:]+)", re.I)
_BRUTE_THRESHOLD = 5
_BRUTE_WINDOW_S  = 120

def _brute_force(events):
    failures: Dict[str, List[CanonicalEvent]] = defaultdict(list)
    for ev in events:
        if not _is_auth(ev): continue
        m = _SSH_FAIL_RE.search(_msg(ev))
        if m: failures[m.group(3)].append(ev)
    sigs, emitted = [], set()
    for src_ip, evs in failures.items():
        if len(evs) < _BRUTE_THRESHOLD: continue
        evs.sort(key=lambda e: e.event_time_utc)
        for i in range(len(evs) - _BRUTE_THRESHOLD + 1):
            w = evs[i:i+_BRUTE_THRESHOLD]
            delta = (w[-1].event_time_utc - w[0].event_time_utc).total_seconds()
            if delta <= _BRUTE_WINDOW_S:
                k = f"{src_ip}|{w[0].event_id}"
                if k in emitted: continue
                emitted.add(k)
                anchor = w[-1]
                sigs.append(Signal(
                    signal_id=_sig_id("auth.ssh_brute_force", anchor.event_id, src_ip),
                    signal_type="auth.ssh_brute_force", host=anchor.host,
                    process_key=f"sshd|{anchor.process.pid or 0}", user_key=anchor.user.username,
                    score=min(1.0, 0.70+0.05*(len(w)-_BRUTE_THRESHOLD)), confidence=0.85,
                    risk_factors=[f"brute_force:{src_ip}", f"failures:{len(w)}", f"window:{int(delta)}s"],
                    evidence_event_ids=[e.event_id for e in w],
                    explanation=f"SSH brute force: {len(w)} failures from {src_ip} in {int(delta)}s",
                    recommended_actions=[f"Bloquer {src_ip} via fail2ban."],
                    mitre_tactic="Credential Access", mitre_technique="T1110.001"))
                break
    return sigs

_ROOT_RE = re.compile(r"(session opened for user root|Accepted .* for root from|su:.*to root)", re.I)
_LEGIT_ROOT = {"cron","systemd","init","(systemd)"}
def _root_login(events):
    sigs = []
    for ev in events:
        if not _is_auth(ev): continue
        msg = _msg(ev)
        if not _ROOT_RE.search(msg): continue
        if (ev.process.name or "").lower() in _LEGIT_ROOT: continue
        is_remote = "from" in msg.lower() and re.search(r"\d{1,3}\.\d{1,3}", msg)
        score = 0.85 if is_remote else 0.65
        sigs.append(_make("auth.root_login", ev, score, score-0.05,
            ["root_session", "remote" if is_remote else "local"],
            f"Root login | {msg[:100]}",
            ["Desactiver PermitRootLogin."], "Initial Access", "T1078.003"))
    return sigs

_SUDO_RE = re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.+)", re.I)
_DANGER_SUDO = ("/bin/bash","/bin/sh","python","perl","ruby","vim","nano","awk","find","dd","nc ","useradd","usermod","sudo -s","sudo -i","sudo su")
def _sudo_escalation(events):
    sigs = []
    for ev in events:
        if not _is_auth(ev): continue
        m = _SUDO_RE.search(_msg(ev))
        if not m: continue
        user, cmd = m.group(1), m.group(2).strip()
        is_danger = any(d in cmd.lower() for d in _DANGER_SUDO)
        score = 0.80 if is_danger else 0.45
        if score < 0.50: continue
        sigs.append(_make("auth.sudo_escalation", ev, score, score-0.05,
            [f"sudo:{user}", f"dangerous:{is_danger}", f"cmd:{cmd[:50]}"],
            f"Sudo: {user} ran {cmd[:60]}",
            ["Restreindre sudoers."], "Privilege Escalation", "T1548.003"))
    return sigs

def _ssh_key_added(events):
    sigs = []
    for ev in events:
        fpath = ev.file.path or ""
        msg = _msg(ev)
        op = (ev.file.operation or "").lower()
        if "authorized_keys" not in fpath and "authorized_keys" not in msg: continue
        if op and op not in ("write","modify","create","rename"): continue
        sigs.append(_make("auth.ssh_key_added", ev, 0.78, 0.72,
            ["authorized_keys_modified", f"op:{op}"],
            f"authorized_keys modified | {fpath or 'N/A'}",
            ["Verifier la cle ajoutee."], "Persistence", "T1098.004"))
    return sigs

def run(events):
    sigs = []
    for fn, label in [(_brute_force,"brute"),(_root_login,"root"),(_sudo_escalation,"sudo"),(_ssh_key_added,"sshkey")]:
        try: sigs.extend(fn(events))
        except Exception as e: print(f"[linux_auth] ERROR {label}: {e}", file=sys.stderr)
    return sigs

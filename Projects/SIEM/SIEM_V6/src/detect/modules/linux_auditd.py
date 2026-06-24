from __future__ import annotations
import hashlib, re, sys
from typing import Any, Dict, List, Tuple
from core.schemas import CanonicalEvent, Signal

def _sig_id(stype, eid, extra=""):
    blob = f"{stype}|{eid}|{extra}".encode()
    return "sig-" + hashlib.sha256(blob).hexdigest()[:16]

def _cl(ev): return (ev.process.command_line or "").lower()
def _raw_args(ev):
    raw = ev.raw or {}
    if raw.get("args"): return str(raw["args"]).lower()
    parts = [str(raw[f"a{i}"]) for i in range(20) if raw.get(f"a{i}") is not None]
    return " ".join(parts).lower()

def _is_auditd(ev):
    src = (ev.source or "").lower()
    if src == "auditd": return True
    return str((ev.raw or {}).get("type") or "").upper() in ("EXECVE","SYSCALL","PATH","PROCTITLE","AUDIT")

def _make(stype, ev, score, conf, factors, expl, actions, tactic, tech):
    return Signal(signal_id=_sig_id(stype,ev.event_id), signal_type=stype, host=ev.host,
        process_key=f"{ev.process.name or 'unknown'}|{ev.process.pid or 0}", user_key=ev.user.username,
        score=score, confidence=conf, risk_factors=factors, evidence_event_ids=[ev.event_id],
        explanation=expl, recommended_actions=actions, mitre_tactic=tactic, mitre_technique=tech)

_SENSITIVE = ("/etc/shadow","/etc/passwd","/etc/sudoers","/root/.ssh","authorized_keys")
def _sensitive_file(events):
    sigs = []
    for ev in events:
        if not _is_auditd(ev): continue
        raw = ev.raw or {}
        paths = [p for p in [ev.file.path, raw.get("name"), raw.get("path")] if p]
        for fpath in paths:
            matched = next((s for s in _SENSITIVE if s in fpath), None)
            if matched:
                sigs.append(_make("auditd.sensitive_file_access", ev, 0.80, 0.78,
                    [f"sensitive_file:{matched}", f"proc:{ev.process.name or 'unk'}"],
                    f"Sensitive file: {fpath} | Proc: {ev.process.name} | User: {ev.user.username}",
                    ["Verifier le processus accedant au fichier."],
                    "Credential Access", "T1003.008"))
                break
    return sigs

_CHMOD_PATS = [re.compile(r"chmod.*[+]s"), re.compile(r"chmod\s+4[0-9]{3}"), re.compile(r"chmod\s+6[0-9]{3}")]
_CHMOD_SYSCALLS = {"90","91","268"}
def _setuid_chmod(events):
    sigs = []
    for ev in events:
        if not _is_auditd(ev): continue
        raw = ev.raw or {}
        syscall = str(raw.get("syscall") or "")
        cl = _cl(ev) or _raw_args(ev)
        triggered, reason = False, ""
        if syscall in _CHMOD_SYSCALLS:
            mode = str(raw.get("a1") or "")
            if mode.startswith("4") or mode.startswith("6"):
                triggered, reason = True, f"syscall {syscall} mode {mode}"
        if not triggered and cl:
            for pat in _CHMOD_PATS:
                if pat.search(cl):
                    triggered, reason = True, f"cmdline:{pat.pattern}"; break
        if triggered:
            sigs.append(_make("auditd.setuid_chmod", ev, 0.85, 0.82,
                ["setuid_chmod", reason], f"setuid chmod | {reason} | {ev.file.path or 'N/A'}",
                ["Identifier le binaire affecte."], "Privilege Escalation", "T1548.001"))
    return sigs

_USERADD = [re.compile(r"\buseradd\b"), re.compile(r"\badduser\b"), re.compile(r"\busermod\b")]
def _user_creation(events):
    sigs = []
    for ev in events:
        if not _is_auditd(ev): continue
        cl = _cl(ev) or _raw_args(ev)
        if not cl: continue
        for pat in _USERADD:
            if pat.search(cl):
                is_root = "-o" in cl or "-u 0" in cl or "uid=0" in cl
                score = 0.90 if is_root else 0.70
                sigs.append(_make("auditd.user_creation", ev, score, score-0.05,
                    ["user_creation", "uid_0_clone" if is_root else "new_user"],
                    f"User creation | CMD:{cl[:80]} | uid0:{is_root}",
                    ["Verifier si autorise."], "Persistence", "T1136.001"))
                break
    return sigs

_NON_NET = {"bash","sh","dash","zsh","python","python3","perl","ruby","awk","sed","grep","find","cat"}
def _suspicious_connect(events):
    sigs = []
    for ev in events:
        if not _is_auditd(ev): continue
        raw = ev.raw or {}
        if str(raw.get("syscall") or "") != "42": continue
        proc = (ev.process.name or "").lower().split("/")[-1]
        if proc not in _NON_NET: continue
        dest = ev.network.dest_ip or raw.get("addr") or "unknown"
        sigs.append(_make("auditd.suspicious_connect", ev, 0.88, 0.80,
            [f"non_network_proc:{proc}", f"dest:{dest}"],
            f"connect() from {proc} -> {dest} — likely reverse shell",
            ["Bloquer IP destination."], "Command and Control", "T1071.001"))
    return sigs

_EXECVE_PATS: List[Tuple] = [
    (re.compile(r"bash\s+-[ic]\s+.*(\||>|curl|wget|nc)"), 0.90, "bash_inline_pipe", "Execution", "T1059.004"),
    (re.compile(r"/dev/tcp/"), 0.95, "bash_tcp_redirect", "Execution", "T1059.004"),
    (re.compile(r"nc\s+(-e|-c)\s+/bin/(bash|sh)"), 0.95, "nc_reverse_shell", "Execution", "T1059.004"),
    (re.compile(r"socat.*EXEC:"), 0.90, "socat_reverse_shell", "Execution", "T1059.004"),
    (re.compile(r"python.*-c.*socket.*connect"), 0.88, "python_socket_shell", "Execution", "T1059.004"),
    (re.compile(r"LD_PRELOAD="), 0.85, "ld_preload_inject", "Defense Evasion", "T1574.006"),
    (re.compile(r"(curl|wget).*\|\s*(bash|sh|python|perl)"), 0.88, "download_exec", "Execution", "T1059.004"),
    (re.compile(r"(echo|printf).*>>.*/etc/(passwd|shadow|cron)"), 0.92, "cred_write", "Credential Access", "T1098"),
]
def _execve_patterns(events):
    sigs = []
    for ev in events:
        if not _is_auditd(ev): continue
        cl = _cl(ev) or _raw_args(ev)
        if not cl: continue
        for pat, score, label, tactic, tech in _EXECVE_PATS:
            if pat.search(cl):
                sigs.append(_make("auditd.execve_suspicious", ev, score, score-0.05,
                    [label], f"Suspicious EXECVE: {label} | CMD:{ev.process.command_line or cl[:80]}",
                    ["Verifier le contexte."], tactic, tech))
                break
    return sigs

def run(events):
    sigs = []
    for fn, label in [(_sensitive_file,"sensitive"),(_setuid_chmod,"chmod"),
                      (_user_creation,"useradd"),(_suspicious_connect,"connect"),(_execve_patterns,"execve")]:
        try: sigs.extend(fn(events))
        except Exception as e: print(f"[linux_auditd] ERROR {label}: {e}", file=sys.stderr)
    return sigs

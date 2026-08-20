"""test_v8.py — SOAR tests: ticket, playbook, actions, orchestrator.

Run:
    cd SIEM_V8
    export PYTHONPATH=src
    python tests/test_v8.py
"""
from __future__ import annotations

import sys, os, json, tempfile
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC  = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path: sys.path.insert(0, _SRC)

from core.schemas import HostRef, Signal

PASS = 0; FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}" + (f" - {detail}" if detail else ""))


def _sig(sid="s1", stype="bash_sigma", hostname="h1", score=0.80,
         risk_factors=None, file_hashes=None, ev_ids=None, mitre_tech="T1059.004"):
    return Signal(
        signal_id=sid, signal_type=stype,
        host=HostRef(hostname=hostname),
        score=score, confidence=score,
        risk_factors=risk_factors or [f"factor:{stype}"],
        file_hashes=file_hashes or {},
        evidence_event_ids=ev_ids or ["ev1"],
        explanation=f"Test signal {stype}",
        recommended_actions=["Check it"],
        mitre_tactic="Execution", mitre_technique=mitre_tech,
    )


print("\n-- 1. Severity mapping --")
from soar.ticket import _severity, Ticket

check("score 0.95 -> CRITICAL", _severity(0.95) == "CRITICAL")
check("score 0.80 -> HIGH",     _severity(0.80) == "HIGH")
check("score 0.60 -> MEDIUM",   _severity(0.60) == "MEDIUM")
check("score 0.40 -> LOW",      _severity(0.40) == "LOW")
check("score 0.20 -> INFO",     _severity(0.20) == "INFO")
check("boundary 0.90 -> CRITICAL", _severity(0.90) == "CRITICAL")
check("boundary 0.75 -> HIGH",     _severity(0.75) == "HIGH")


print("\n-- 2. Ticket creation from Signal --")
sig = _sig(score=0.88, file_hashes={"sha256": "abc123", "md5": "def456"},
           risk_factors=["brute_force:192.168.1.1", "failures:5"])
t = Ticket.from_signal(sig, "playbook_test")
check("ticket_id starts with TKT-",    t.ticket_id.startswith("TKT-"))
check("severity HIGH",                 t.severity == "HIGH")
check("status open",                   t.status == "open")
check("file_hashes propagated",        t.file_hashes == {"sha256": "abc123", "md5": "def456"})
check("risk_factors propagated",       "brute_force:192.168.1.1" in t.risk_factors)
check("playbook assigned",             t.playbook == "playbook_test")
check("host correct",                  t.host == "h1")
check("to_dict is serializable",       json.dumps(t.to_dict()) is not None)


print("\n-- 3. Playbook matching --")
from soar.playbook import match

t_rw   = Ticket.from_signal(_sig(stype="ransomware_behavior_linux", score=0.90), "")
t_ssh  = Ticket.from_signal(_sig(stype="auth.ssh_brute_force", score=0.75), "")
t_rev  = Ticket.from_signal(_sig(stype="bash_sigma", score=0.82), "")
t_mail = Ticket.from_signal(_sig(stype="email.risky_attachment", score=0.75), "")
t_ai   = Ticket.from_signal(_sig(stype="ai.model_file_modified", score=0.92), "")
t_low  = Ticket.from_signal(_sig(stype="something_else", score=0.40), "")
t_crit = Ticket.from_signal(_sig(stype="unknown_high", score=0.85), "")

check("ransomware -> playbook_ransomware",      match(t_rw)[0]   == "playbook_ransomware")
check("brute_force -> playbook_brute_force",    match(t_ssh)[0]  == "playbook_brute_force")
check("bash_sigma >= 0.78 -> reverse_shell",    match(t_rev)[0]  == "playbook_reverse_shell")
check("email.* -> playbook_email_threat",       match(t_mail)[0] == "playbook_email_threat")
check("ai.* -> playbook_ai_tamper",             match(t_ai)[0]   == "playbook_ai_tamper")
check("high score unknown -> playbook_high",    match(t_crit)[0] == "playbook_high_score")
check("low score fallback -> playbook_generic", match(t_low)[0]  == "playbook_generic")


print("\n-- 4. Actions --")
from soar.actions import (block_ip, isolate_host, alert_analyst,
                           check_hash, escalate, quarantine_file,
                           disable_ai_service)

with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as f:
    log_path = f.name

import soar.actions as _act
_act._LOG_PATH = log_path

check("block_ip returns dict",     block_ip("1.2.3.4", "TKT-001").get("action") == "BLOCK_IP")
check("isolate_host target",       isolate_host("srv01", "TKT-001").get("target") == "srv01")
check("alert_analyst status",      alert_analyst("test", "TKT-001").get("status") == "logged")
check("escalate action",           escalate("TKT-001").get("action") == "ESCALATE")
check("check_hash with hashes",    "SUBMIT" in check_hash({"sha256":"abc"}, "TKT-001").get("detail","").upper() or
                                   "VirusTotal" in check_hash({"sha256":"abc"}, "TKT-001").get("detail",""))
check("check_hash empty",          check_hash({}, "TKT-001").get("action") == "CHECK_HASH")
check("disable_ai_service action", disable_ai_service("ollama", "TKT-001").get("action") == "DISABLE_AI_SERVICE")

lines = open(log_path).readlines()
check("actions written to log",    len(lines) >= 5)
os.unlink(log_path)
_act._LOG_PATH = "response_log.jsonl"


print("\n-- 5. Playbook execute --")
from soar.playbook import match, execute

with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as f:
    _act._LOG_PATH = f.name
    exec_log = f.name

t_exec = Ticket.from_signal(_sig(stype="ransomware_behavior_linux", score=0.92), "")
pb_name, steps = match(t_exec)
execute(t_exec, steps)
check("actions_taken populated",       len(t_exec.actions_taken) >= 2)
check("alert action present",          any(a.get("action")=="ALERT_ANALYST" for a in t_exec.actions_taken))
check("isolate action present",        any(a.get("action")=="ISOLATE_HOST" for a in t_exec.actions_taken))
check("escalate action present",       any(a.get("action")=="ESCALATE" for a in t_exec.actions_taken))

t_email = Ticket.from_signal(_sig(stype="email.risky_attachment", score=0.75,
                                   file_hashes={"sha256":"deadbeef"},
                                   risk_factors=["filename:invoice.exe"]), "")
_, steps_e = match(t_email)
execute(t_email, steps_e)
check("email: check_hash action",      any(a.get("action")=="CHECK_HASH" for a in t_email.actions_taken))
check("email: file_hashes in ticket",  t_email.file_hashes.get("sha256") == "deadbeef")

os.unlink(exec_log)
_act._LOG_PATH = "response_log.jsonl"


print("\n-- 6. TicketStore --")
from soar.ticket import TicketStore

with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as f:
    store_path = f.name

store = TicketStore(store_path)
t1 = Ticket.from_signal(_sig("s1", "ransomware_behavior_linux", score=0.90), "playbook_ransomware")
t2 = Ticket.from_signal(_sig("s2", "auth.ssh_brute_force", hostname="h2", score=0.70), "playbook_brute_force")
store.add(t1)
store.add(t2)

check("store has 2 tickets",           len(store.all()) == 2)
check("by_severity CRITICAL",          len(store.by_severity("CRITICAL")) >= 1)
check("open_tickets",                  len(store.open_tickets()) == 2)
check("get by id",                     store.get(t1.ticket_id) is not None)

store.update_status(t1.ticket_id, "resolved", "False positive confirmed")
check("status updated to resolved",    store.get(t1.ticket_id).status == "resolved")

store2 = TicketStore(store_path)
check("tickets reload from JSONL",     len(store2.all()) == 2)
os.unlink(store_path)


print("\n-- 7. Orchestrator end-to-end --")
from soar.orchestrator import SoarOrchestrator

with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as f:
    orch_path = f.name
with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w") as f:
    _act._LOG_PATH = f.name
    orch_log = f.name

signals = [
    _sig("sig-rw",  "ransomware_behavior_linux", score=0.92),
    _sig("sig-ssh", "auth.ssh_brute_force",       score=0.75),
    _sig("sig-low", "bash_sigma",                 score=0.20),  # below threshold
    _sig("sig-em",  "email.risky_attachment",     score=0.75,
         file_hashes={"sha256":"cafebabe"}),
]

soar = SoarOrchestrator(ticket_path=orch_path, min_score=0.30)
tickets = soar.process(signals)

check("3 tickets created (1 filtered by score)", len(tickets) == 3)
check("low-score signal filtered out",
      not any(t.signal_id == "sig-low" for t in tickets))
check("ransomware ticket CRITICAL",
      any(t.severity == "CRITICAL" for t in tickets))
check("email ticket has file_hashes",
      any(t.file_hashes.get("sha256") == "cafebabe" for t in tickets))
check("all tickets have actions",
      all(len(t.actions_taken) > 0 for t in tickets))
check("tickets persisted to file",
      os.path.exists(orch_path) and os.path.getsize(orch_path) > 0)

# Reload and verify persistence
soar2 = SoarOrchestrator(ticket_path=orch_path)
check("tickets reload correctly", len(soar2.store.all()) == 3)

os.unlink(orch_path)
os.unlink(orch_log)
_act._LOG_PATH = "response_log.jsonl"


print(f"\n{'='*60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL: sys.exit(1)

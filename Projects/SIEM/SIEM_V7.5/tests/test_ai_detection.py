"""test_ai_detection.py — Tests for local AI service detection.

Run:
    cd SIEM_AI
    export PYTHONPATH=src
    python tests/test_ai_detection.py
"""
from __future__ import annotations

import sys, os
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC  = os.path.join(os.path.dirname(_HERE), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from core.schemas import CanonicalEvent, HostRef, UserRef, ProcessRef, FileRef, NetworkRef
from detect.modules.ai.ai_baseline import load_default, match_framework, is_known_ai_port, observe, load_learned, _LEARNED_PATH

PASS = 0; FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: PASS += 1; print(f"  PASS  {name}")
    else:    FAIL += 1; print(f"  FAIL  {name}" + (f" - {detail}" if detail else ""))

# cleanup learned baseline before tests
if _LEARNED_PATH.exists():
    _LEARNED_PATH.unlink()

def _ev(source="auditd", proc="ollama", pid=100, cmd="", fp="", op="", port=0,
        raw_extra=None, off=0):
    ts = datetime(2026,3,17,12,0,off%60,tzinfo=timezone.utc)
    raw = {"timestamp": ts.isoformat(), "source": source, "host": "test",
           "port": port or None, **(raw_extra or {})}
    return CanonicalEvent(
        event_id=f"t{pid}-{off}", event_time_utc=ts, ingest_time_utc=ts,
        source=source, event_type="other", host=HostRef(hostname="test"),
        user=UserRef(username="user"),
        process=ProcessRef(name=proc, pid=pid, command_line=cmd),
        file=FileRef(path=fp or None, operation=op or None),
        network=NetworkRef(dest_port=port or None), raw=raw)


print("\n-- 1. ai_baseline --")
defaults = load_default()
check("ollama in defaults", "ollama" in defaults)
check("ollama port 11434",  defaults["ollama"]["port"] == 11434)
check("match ollama process+port", match_framework("ollama", 11434, defaults) == "ollama")
check("no match wrong port",       match_framework("ollama", 9999, defaults) is None)
check("is_known_ai_port 11434",    is_known_ai_port(11434, defaults))
check("is_known_ai_port 9999 false", not is_known_ai_port(9999, defaults))

observe("ollama", "ollama", 11434, "hash123")
learned = load_learned()
check("observe stores hash", "hash123" in learned["ollama"]["model_hashes"])


print("\n-- 2. ai_network: port swap --")
from detect.modules.ai.ai_network import run as net_run

ev_legit = _ev(proc="ollama", port=11434, raw_extra={"syscall": "49"})
sigs = net_run([ev_legit])
check("legit ollama bind: no signal", sigs == [])

ev_evil = _ev(proc="python3", port=11434, raw_extra={"syscall": "49"})
sigs = net_run([ev_evil])
check("unexpected process on AI port -> signal",
      any(s.signal_type == "ai.unexpected_process_on_ai_port" for s in sigs))
check("score 0.90", sigs[0].score == 0.90 if sigs else False)
check("MITRE ATLAS AML.T0012", sigs[0].mitre_technique == "AML.T0012" if sigs else False)

ev_unknown_port = _ev(proc="weird", port=9999, raw_extra={"syscall": "49"})
sigs = net_run([ev_unknown_port])
check("non-AI port: no signal", sigs == [])


print("\n-- 3. ai_network: client redirect --")
ev_client_legit = _ev(proc="curl", port=11434, raw_extra={"syscall": "42"})
sigs = net_run([ev_client_legit])
check("client connect unknown process -> signal",
      any(s.signal_type == "ai.client_connect_unexpected_process" for s in sigs))
check("score 0.70", sigs[0].score == 0.70 if sigs else False)
check("MITRE ATLAS AML.T0040", sigs[0].mitre_technique == "AML.T0040" if sigs else False)


print("\n-- 4. ai_integrity: model tamper --")
from detect.modules.ai.ai_integrity import run as integ_run

if _LEARNED_PATH.exists():
    _LEARNED_PATH.unlink()

# First observation: builds baseline
ev_first = _ev(fp="/root/.ollama/models/llama3.gguf", op="write",
               raw_extra={"file_hash": "abc111"})
sigs = integ_run([ev_first])
check("first write: no signal (baseline build)", sigs == [])

# Same hash again: no signal
ev_same = _ev(fp="/root/.ollama/models/llama3.gguf", op="write",
              raw_extra={"file_hash": "abc111"})
sigs = integ_run([ev_same])
check("same hash: no signal", sigs == [])

# Different hash: signal
ev_tampered = _ev(fp="/root/.ollama/models/llama3.gguf", op="write",
                  raw_extra={"file_hash": "evil999"})
sigs = integ_run([ev_tampered])
check("hash mismatch -> signal", any(s.signal_type == "ai.model_file_modified" for s in sigs))
check("score 0.92", sigs[0].score == 0.92 if sigs else False)
check("MITRE ATLAS AML.T0018", sigs[0].mitre_technique == "AML.T0018" if sigs else False)


print("\n-- 5. ai_integrity: non-model files ignored --")
ev_other = _ev(fp="/etc/passwd", op="write", raw_extra={"file_hash": "xxx"})
sigs = integ_run([ev_other])
check("non-model file: no signal", sigs == [])


# cleanup
if _LEARNED_PATH.exists():
    _LEARNED_PATH.unlink()

print(f"\n{'='*60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL: sys.exit(1)

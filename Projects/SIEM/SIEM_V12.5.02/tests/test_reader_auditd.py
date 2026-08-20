"""Tests for the native auditd ingestion reader."""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ingest.auditd_reader import read as auditd_read
from normalize.normalizer import normalize
from detect.engine import run_all

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [ok]   {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")


SAMPLE = ROOT / "samples" / "demo_auditd.log"
raw = list(auditd_read(str(SAMPLE)))

check("merges multi-line events into 4 records", len(raw) == 4)
check("every record tagged source=auditd", all(r["source"] == "auditd" for r in raw))
check("SYSCALL pid/ppid merged with EXECVE", raw[0]["pid"] == 7000 and raw[0]["ppid"] == 6999)
check("pid coerced to int", isinstance(raw[0]["pid"], int))
check("execve args kept for command reconstruction", raw[0].get("a0") == "bash")
check("exe captured", raw[0].get("exe") == "/usr/bin/bash")
check("PATH name captured on the sensitive-file event",
      any(r.get("name") == "/etc/shadow" for r in raw))

events = [normalize(r) for r in raw]
check("normalizer produces 4 events", len(events) == 4)
check("execve events typed as process", any(e.event_type == "process" for e in events))
check("command line reconstructed from a0..aN",
      "/dev/tcp" in (events[0].process.command_line or ""))
check("process tree chain present (ppid links)",
      any(e.process.ppid == 7000 for e in events))

signals = run_all(events)
types = {s.signal_type for s in signals}
check("reverse shell raises a detection", any("bash" in t or "execve" in t for t in types))
check("sensitive file access detected", "auditd.sensitive_file_access" in types)
check("user creation detected", "auditd.user_creation" in types)

# Robustness: a malformed file yields nothing, no crash.
with tempfile.TemporaryDirectory() as d:
    bad = Path(d) / "bad.log"
    bad.write_text("not an audit line at all\nanother junk line\n")
    check("malformed file yields no events, no crash", list(auditd_read(str(bad))) == [])

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

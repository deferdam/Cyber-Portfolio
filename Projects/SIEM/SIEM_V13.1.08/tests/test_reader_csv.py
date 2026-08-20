"""Tests for the CSV ingestion reader."""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ingest.csv_reader import read as csv_read
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


SAMPLE = ROOT / "samples" / "demo.csv"
raw = list(csv_read(str(SAMPLE)))

check("parses 4 data rows", len(raw) == 4)
check("every record tagged source=csv", all(r["source"] == "csv" for r in raw))
check("no raw event_id key (avoids Windows EventID heuristic)", all("event_id" not in r for r in raw))
check("pid coerced to int", isinstance(raw[0]["pid"], int))
check("ppid coerced to int", isinstance(raw[1]["ppid"], int))
check("event_type is process", all(r["event_type"] == "process" for r in raw))

events = [normalize(r) for r in raw]
check("normalizer produces 4 events", len(events) == 4)
check("event ids are unique", len({e.event_id for e in events}) == 4)
check("command_line mapped to ProcessRef", any("/dev/tcp" in (e.process.command_line or "") for e in events))
check("host mapped", all(e.host.hostname == "csv-host-01" for e in events))

signals = run_all(events)
check("detection fires on the reverse shell", len(signals) >= 1)
check("process tree is populated (self + children)",
      any(s.process_self and s.process_children for s in signals))

# Robustness: a row with a non-integer pid must not crash; pid becomes None.
with tempfile.TemporaryDirectory() as d:
    bad = Path(d) / "bad.csv"
    bad.write_text("timestamp,host,pid,command_line\n2026-01-01T00:00:00+00:00,h,NOT_A_PID,echo hi\n")
    rows = list(csv_read(str(bad)))
    check("non-integer pid handled (set to None, no crash)", len(rows) == 1 and rows[0].get("pid") is None)

# Robustness: empty file yields nothing, no crash.
with tempfile.TemporaryDirectory() as d:
    empty = Path(d) / "empty.csv"
    empty.write_text("")
    check("empty file yields no rows", list(csv_read(str(empty))) == [])

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

"""Tests for the Snort ingestion reader and the imported-alert detection module."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ingest.snort_reader import read as snort_read
from normalize.normalizer import normalize
from detect.engine import run_all
from detect.modules.imported import snort_alert

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


SAMPLE = ROOT / "samples" / "demo_snort.log"
raw = list(snort_read(str(SAMPLE)))

check("parses 3 alerts (4th line is garbage and skipped)", len(raw) == 3)
check("every record tagged source=snort", all(r["source"] == "snort" for r in raw))
check("event_type is network", all(r["event_type"] == "network" for r in raw))
check("signature (message) extracted", any("reverse shell" in (r.get("signature") or "") for r in raw))
check("priority parsed as int", {r.get("priority") for r in raw} == {1, 2, 3})
check("destination ip and port parsed", any(r.get("dest_ip") == "10.10.10.9" and r.get("dest_port") == 4444 for r in raw))
check("classification captured", any("Trojan" in (r.get("classification") or "") for r in raw))
check("sid in gid:sid:rev form", all(r.get("sid", "").count(":") == 2 for r in raw))

events = [normalize(r) for r in raw]
check("normalizer produces 3 events", len(events) == 3)

# Direct module test: priority drives score.
mod_sigs = snort_alert.run(events)
check("module emits one signal per alert", len(mod_sigs) == 3)
check("all signals are snort.alert", all(s.signal_type == "snort.alert" for s in mod_sigs))
by_score = sorted(s.score for s in mod_sigs)
check("priority 1 yields the highest score (0.90)", max(by_score) == 0.90)
check("priority 3 yields the lowest score (0.50)", min(by_score) == 0.50)

# End-to-end through the engine.
signals = run_all(events)
check("engine routes snort events to snort.alert signals",
      len([s for s in signals if s.signal_type == "snort.alert"]) == 3)

# Robustness: a non-snort event produces no snort signal.
fake = normalize({"source": "csv", "event_type": "process", "pid": 1,
                  "command_line": "ls", "timestamp": "2026-01-01T00:00:00+00:00"})
check("module ignores non-snort events", snort_alert.run([fake]) == [])

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

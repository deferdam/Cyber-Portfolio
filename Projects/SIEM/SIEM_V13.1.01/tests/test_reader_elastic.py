"""Tests for the Elastic / ECS ingestion reader."""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ingest.elastic_reader import read as ecs_read
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


SAMPLE = ROOT / "samples" / "demo_ecs.ndjson"
raw = list(ecs_read(str(SAMPLE)))

check("parses 3 documents", len(raw) == 3)
check("every record tagged source=elastic", all(r["source"] == "elastic" for r in raw))
check("handles _source-wrapped hit and raw doc alike",
      {r["pid"] for r in raw} == {5100, 5200, 5300})
check("event.category process maps to event_type process", all(r["event_type"] == "process" for r in raw))
check("process.parent.pid maps to ppid", any(r.get("ppid") == 5100 for r in raw))
check("process.args list joined into command_line",
      any("/dev/tcp" in (r.get("command_line") or "") for r in raw))
check("host.name mapped", all(r["host"] == "ecs-host-02" for r in raw))

events = [normalize(r) for r in raw]
check("normalizer produces 3 events", len(events) == 3)
check("event ids are unique", len({e.event_id for e in events}) == 3)

signals = run_all(events)
check("detection fires on the reverse shell", len(signals) >= 1)
check("process tree is populated", any(s.process_self for s in signals))

# Robustness: a malformed JSON line is skipped, valid lines still parsed.
with tempfile.TemporaryDirectory() as d:
    mixed = Path(d) / "mixed.ndjson"
    mixed.write_text(
        '{"@timestamp":"2026-01-01T00:00:00Z","host":{"name":"h"},'
        '"event":{"category":"process"},"process":{"pid":1,"name":"sh"}}\n'
        'THIS IS NOT JSON\n'
        '{"@timestamp":"2026-01-01T00:00:01Z","host":{"name":"h"},'
        '"event":{"category":"process"},"process":{"pid":2,"name":"sh"}}\n'
    )
    rows = list(ecs_read(str(mixed)))
    check("malformed JSON line skipped, valid kept", len(rows) == 2)

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

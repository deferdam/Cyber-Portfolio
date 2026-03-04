from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Any, List

from normalize.normalizer import normalize
from detect.engine import run_all
from correlate.correlator import correlate
from output.reporter import export


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def main() -> None:
    p = argparse.ArgumentParser(description="Replay JSONL logs through the mini-SIEM pipeline.")
    p.add_argument("--input", required=True, help="Path to raw events.jsonl")
    p.add_argument("--out-dir", required=True, help="Output directory for artifacts")
    p.add_argument("--default-host", default="lab-host", help="Default host if not present in raw events")
    args = p.parse_args()

    raw_events = _read_jsonl(Path(args.input))
    events = [normalize(re, default_host=args.default_host) for re in raw_events]
    # Ensure stable ordering for timelines
    events.sort(key=lambda e: e.event_time_utc)

    signals = run_all(events)
    alerts = correlate(signals)

    export(Path(args.out_dir), events, signals, alerts)

    print(f"Normalized events: {len(events)}")
    print(f"Signals: {len(signals)}")
    print(f"Alerts: {len(alerts)}")
    if alerts:
        print("Alert IDs:")
        for a in alerts:
            print(f" - {a.alert_id} ({a.severity}, conf={a.confidence:.2f})")


if __name__ == "__main__":
    main()

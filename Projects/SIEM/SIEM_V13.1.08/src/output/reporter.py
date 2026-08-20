from __future__ import annotations

import json
from pathlib import Path
from typing import List

from core.schemas import Alert, Signal, CanonicalEvent
from core import vault


def write_jsonl(path: Path, rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(vault.pack_line(r) + "\n")


def export(out_dir: Path, events: List[CanonicalEvent], signals: List[Signal], alerts: List[Alert]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    write_jsonl(out_dir / "normalized_events.jsonl", [e.to_dict() for e in events])
    write_jsonl(out_dir / "signals.jsonl", [s.to_dict() for s in signals])
    write_jsonl(out_dir / "alerts.jsonl", [a.to_dict() for a in alerts])

    # Per-alert timeline files (event_id + minimal event view)
    by_id = {e.event_id: e for e in events}

    for a in alerts:
        timeline = []
        for eid in a.timeline_event_ids:
            e = by_id.get(eid)
            if not e:
                continue
            timeline.append(
                {
                    "event_id": e.event_id,
                    "event_time_utc": e.event_time_utc.isoformat(),
                    "event_type": e.event_type,
                    "process_name": e.process.name,
                    "pid": e.process.pid,
                    "operation": e.file.operation,
                    "file_path": e.file.path,
                    "dest_ip": e.network.dest_ip,
                    "dest_port": e.network.dest_port,
                }
            )
        # Sort by time
        timeline.sort(key=lambda x: x["event_time_utc"])
        write_jsonl(out_dir / f"timeline_{a.alert_id}.jsonl", timeline)

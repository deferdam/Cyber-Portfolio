"""Showcase data builder (fake data only).

Builds a sealed demo dataset from the bundled sample files so a visitor can try the app
without supplying any of their own files, while still seeing how each log type flows
through the pipeline: auditd process trees, CSV, Elastic/ECS, Snort alerts and PCAP.

The dataset is generated once and written to out/showcase, a directory the showcase app
reads but never writes from user input. Shipping a pre-generated copy means the demo also
works on Windows, where the Linux detection modules would not re-fire: the app only reads
the baked-in tickets.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

# Sample files to fold into the showcase, one per log type.
_SAMPLES = [
    ("json",    "demo_linux_attack.jsonl"),   # auditd, rich process trees
    ("csv",     "demo.csv"),
    ("elastic", "demo_ecs.ndjson"),
    ("snort",   "demo_snort.log"),
    ("pcap",    "demo_capture.pcap"),
    ("auditd",  "demo_auditd.log"),
]


def build_showcase(out_dir) -> int:
    from ingest.replay import _READERS
    from normalize.normalizer import normalize
    from detect.engine import run_all
    from correlate.correlator import correlate
    from output.reporter import export
    from soar.orchestrator import SoarOrchestrator
    from output.html_report import generate_report

    samples = ROOT / "samples"
    raws = []
    for fmt, fname in _SAMPLES:
        p = samples / fname
        if not p.exists():
            continue
        try:
            raws.extend(_READERS[fmt](str(p)))
        except Exception as exc:
            print(f"[showcase] skip {fmt} ({fname}): {exc}", file=sys.stderr)

    events = [normalize(r) for r in raws]
    events.sort(key=lambda e: e.event_time_utc)
    signals = run_all(events)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    export(out, events, signals, correlate(signals))
    (out / "tickets.jsonl").unlink(missing_ok=True)
    soar = SoarOrchestrator(ticket_path=str(out / "tickets.jsonl"), min_score=0.30)
    tickets = soar.process(signals)
    try:
        generate_report(events, signals, tickets, str(out / "dashboard.html"))
    except Exception:
        pass
    return len(tickets)


def ensure_showcase(out_dir) -> None:
    """Build the showcase only if it is missing or empty (fallback). The shipped copy
    normally satisfies this without regenerating."""
    tickets = Path(out_dir) / "tickets.jsonl"
    if not tickets.exists() or tickets.stat().st_size == 0:
        n = build_showcase(out_dir)
        print(f"[showcase] generated {n} demo tickets in {out_dir}", file=sys.stderr)


def replay_showcase(out_dir, interval: float = 1.0) -> None:
    """Reveal the baked showcase tickets one at a time, so the demo "streams": tickets
    appear progressively in the UI. This replays pre-detected tickets rather than
    re-running detection, so it behaves identically on Linux and Windows. It runs once,
    then leaves the full set in place for the visitor to interact with.
    """
    import time
    tickets_path = Path(out_dir) / "tickets.jsonl"
    ensure_showcase(out_dir)
    full = [ln for ln in tickets_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if len(full) <= 1:
        return
    for i in range(1, len(full) + 1):
        tickets_path.write_text("\n".join(full[:i]) + "\n", encoding="utf-8")
        time.sleep(interval)
    tickets_path.write_text("\n".join(full) + "\n", encoding="utf-8")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "out" / "showcase")
    print(f"[showcase] building demo dataset in {target}")
    count = build_showcase(target)
    print(f"[showcase] done: {count} tickets")

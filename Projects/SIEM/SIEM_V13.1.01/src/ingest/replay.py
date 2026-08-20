"""replay.py - Ingest layer entry point.

Supports three input formats (--format flag):
  json    Raw events.jsonl (V1 format, one JSON object per line)
  syslog  RFC 3164, RFC 5424, CEF, or JSON-in-syslog (NXLog, Winlogbeat)
  auto    (default) Tries JSON first, falls back to syslog parser per line

Input source:
  --input <path>   Read from file
  --input -        Read from stdin
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List

from normalize.normalizer import normalize
from detect.engine import run_all
from correlate.correlator import correlate
from output.reporter import export
from soar.orchestrator import SoarOrchestrator
from output.html_report import generate_report


def _read_jsonl(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    lines = sys.stdin if path_or_stdin == "-" else Path(path_or_stdin).open("r", encoding="utf-8")
    for lineno, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                yield obj
        except json.JSONDecodeError as exc:
            print(f"[replay] WARN jsonl line {lineno}: {exc}", file=sys.stderr)


def _read_syslog(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    from ingest.syslog_parser import read_syslog_file
    source = sys.stdin if path_or_stdin == "-" else path_or_stdin
    yield from read_syslog_file(source)


def _read_auto(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    from ingest.syslog_parser import parse_line as syslog_parse
    lines = sys.stdin if path_or_stdin == "-" else Path(path_or_stdin).open("r", encoding="utf-8", errors="replace")
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    yield obj
                    continue
            except json.JSONDecodeError:
                pass
        try:
            result = syslog_parse(stripped)
            if result is not None:
                yield result
        except Exception as exc:
            print(f"[replay] WARN auto line {lineno}: {exc}", file=sys.stderr)


def _read_csv(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    from ingest.csv_reader import read as _r
    yield from _r(path_or_stdin)


def _read_elastic(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    from ingest.elastic_reader import read as _r
    yield from _r(path_or_stdin)


def _read_snort(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    from ingest.snort_reader import read as _r
    yield from _r(path_or_stdin)


def _read_evtx(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    from ingest.evtx_reader import read as _r
    yield from _r(path_or_stdin)


def _read_pcap(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    from ingest.pcap_reader import read as _r
    yield from _r(path_or_stdin)


def _read_auditd(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    from ingest.auditd_reader import read as _r
    yield from _r(path_or_stdin)


_READERS = {
    "json": _read_jsonl, "syslog": _read_syslog, "auto": _read_auto,
    "csv": _read_csv, "elastic": _read_elastic, "snort": _read_snort,
    "evtx": _read_evtx, "pcap": _read_pcap, "auditd": _read_auditd,
}


def main() -> None:
    p = argparse.ArgumentParser(description="Replay logs through the mini-SIEM pipeline.")
    p.add_argument("--input", required=True, help="Path to input file, or '-' for stdin")
    p.add_argument("--out-dir", required=True, help="Output directory for artifacts")
    p.add_argument("--format", choices=["json", "syslog", "auto", "csv", "elastic", "snort", "evtx", "pcap", "auditd"], default="auto",
                   help="Input format (default: auto)")
    p.add_argument("--default-host", default="lab-host",
                   help="Fallback hostname if not present in raw events")
    args = p.parse_args()

    raw_events: List[Dict[str, Any]] = list(_READERS[args.format](args.input))
    if not raw_events:
        print("[replay] WARN: no events parsed. Check input format.", file=sys.stderr)

    events = [normalize(re, default_host=args.default_host) for re in raw_events]
    events.sort(key=lambda e: e.event_time_utc)

    signals = run_all(events)
    alerts  = correlate(signals)

    out_path = Path(args.out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    from core import vault
    vault.configure(out_path)
    export(out_path, events, signals, alerts)

    # -- SOAR --------------------------------------------------------------
    ticket_path = str(out_path / 'tickets.jsonl')
    soar = SoarOrchestrator(ticket_path=ticket_path, min_score=0.30)
    tickets = soar.process(signals)

    # -- HTML dashboard ----------------------------------------------------
    report_path = str(out_path / 'dashboard.html')
    generate_report(events, signals, tickets, report_path)

    print(f"[replay] Format   : {args.format}")
    print(f"[replay] Ingested : {len(raw_events)} raw lines -> {len(events)} events")
    print(f"[replay] Signals  : {len(signals)}")
    print(f"[replay] Alerts   : {len(alerts)}")
    print(f"[replay] Tickets  : {len(tickets)}")
    print(f"[replay] Report   : {report_path}")
    if tickets:
        for t in sorted(tickets, key=lambda x: x.score, reverse=True)[:5]:
            print(f"  -> {t.ticket_id} [{t.severity:8s}] score={t.score:.2f}  {t.signal_type}")


if __name__ == "__main__":
    main()

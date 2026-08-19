"""Snort alert ingestion reader.

Parses Snort fast/full alert lines into canonical raw dicts. Snort output is already
a detection, so these events are turned into signals by the imported.snort_alert
detection module rather than re-detected. Local-only format. Defensive: a line that
does not match is logged and skipped, never fatal.

Example line:
  01/18-12:00:00.123456  [**] [1:2010935:3] ET TROJAN backdoor [**] \
  [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} \
  10.10.10.5:4444 -> 192.168.1.20:51234
"""
from __future__ import annotations

import datetime as _dt
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterator

_LINE_RE = re.compile(
    r"^(?:(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+)?"
    r"\[\*\*\]\s*\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*"
    r"(?P<msg>.*?)\s*\[\*\*\]\s*"
    r"(?:\[Classification:\s*(?P<cls>[^\]]*)\]\s*)?"
    r"(?:\[Priority:\s*(?P<pri>\d+)\]\s*)?"
    r"(?:\{(?P<proto>[^}]+)\}\s*)?"
    r"(?:(?P<src>[0-9a-fA-F.:]+?)(?::(?P<sport>\d+))?\s*->\s*"
    r"(?P<dst>[0-9a-fA-F.:]+?)(?::(?P<dport>\d+))?)?\s*$"
)


def _int(value: Any):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_iso(snort_ts):
    """Snort fast timestamps omit the year. Best-effort to an ISO string using the
    current year, so the normalizer can parse it. Returns None if absent."""
    if not snort_ts:
        return None
    try:
        mmdd, hms = snort_ts.split("-", 1)
        month, day = mmdd.split("/")
        year = _dt.datetime.now(_dt.timezone.utc).year
        hms = hms.split(".")[0]
        return f"{year:04d}-{int(month):02d}-{int(day):02d}T{hms}+00:00"
    except Exception:
        return None


def read(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    handle = (sys.stdin if path_or_stdin == "-"
              else Path(path_or_stdin).open("r", encoding="utf-8", errors="replace"))
    try:
        for n, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            m = _LINE_RE.match(line)
            if not m:
                print(f"[snort] WARN line {n}: unrecognized format", file=sys.stderr)
                continue
            try:
                g = m.groupdict()
                raw: Dict[str, Any] = {
                    "source":         "snort",
                    "event_type":     "network",
                    "timestamp":      _to_iso(g.get("ts")),
                    "host":           g.get("dst") or "snort-sensor",
                    "signature":      (g.get("msg") or "").strip() or "Snort alert",
                    "sid":            f"{g.get('gid')}:{g.get('sid')}:{g.get('rev')}",
                    "classification": (g.get("cls") or "").strip() or None,
                    "priority":       _int(g.get("pri")),
                    "protocol":       g.get("proto"),
                    "src_ip":         g.get("src"),
                    "src_port":       _int(g.get("sport")),
                    "dest_ip":        g.get("dst"),
                    "dest_port":      _int(g.get("dport")),
                }
                yield {k: v for k, v in raw.items() if v is not None}
            except Exception as exc:
                print(f"[snort] WARN line {n}: {exc}", file=sys.stderr)
    finally:
        if handle is not sys.stdin:
            handle.close()

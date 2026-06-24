"""CSV ingestion reader.

Generic tabular events -> canonical raw dicts that the normalizer understands.
Local-only format. Defensive: a malformed row is logged and skipped, never fatal.
Column names are matched case-insensitively against a table of common aliases, so
exports from different tools map to the same canonical shape.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Any, Dict, Iterator

# canonical key -> accepted column aliases (lowercase)
_ALIASES = {
    "timestamp":    ["timestamp", "time", "@timestamp", "date", "datetime", "ts"],
    "host":         ["host", "hostname", "computer", "machine"],
    "event_type":   ["event_type", "type", "category"],
    "pid":          ["pid", "process_id", "processid"],
    "ppid":         ["ppid", "parent_pid", "parentprocessid", "parent_process_id"],
    "process_name": ["process_name", "image_name", "proc", "process"],
    "process_path": ["process_path", "image", "image_path", "exe", "path"],
    "command_line": ["command_line", "commandline", "cmd", "cmdline"],
    "username":     ["username", "user", "account", "user_name"],
    "dest_ip":      ["dest_ip", "dst_ip", "destination_ip", "remote_ip"],
    "dest_port":    ["dest_port", "dst_port", "destination_port", "remote_port"],
    "protocol":     ["protocol", "proto"],
    "file_path":    ["file_path", "filename", "file", "target_file"],
}

_VALID_TYPES = ("file", "network", "process", "auth", "other")


def _int(value: Any):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _resolve_columns(fieldnames):
    """Map canonical keys to the actual header names present in this file."""
    lower = {(f or "").strip().lower(): f for f in (fieldnames or [])}
    resolved = {}
    for canon, aliases in _ALIASES.items():
        for alias in aliases:
            if alias in lower:
                resolved[canon] = lower[alias]
                break
    return resolved


def read(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    handle = (sys.stdin if path_or_stdin == "-"
              else Path(path_or_stdin).open("r", encoding="utf-8", errors="replace", newline=""))
    try:
        reader = csv.DictReader(handle)
        index = _resolve_columns(reader.fieldnames)
        for n, row in enumerate(reader, start=1):
            try:
                raw: Dict[str, Any] = {"source": "csv"}
                for canon, col in index.items():
                    val = row.get(col)
                    if val is None or val == "":
                        continue
                    raw[canon] = val
                for k in ("pid", "ppid", "dest_port"):
                    if k in raw:
                        raw[k] = _int(raw[k])
                et = str(raw.get("event_type") or "").lower()
                if et not in _VALID_TYPES:
                    raw["event_type"] = "process" if raw.get("pid") else "other"
                else:
                    raw["event_type"] = et
                yield raw
            except Exception as exc:  # one bad row never kills the batch
                print(f"[csv] WARN row {n}: {exc}", file=sys.stderr)
    finally:
        if handle is not sys.stdin:
            handle.close()

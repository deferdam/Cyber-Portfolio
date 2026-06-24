"""Elastic / ECS ingestion reader.

Reads ndjson (one JSON document per line). Handles both a raw ECS document and an
Elasticsearch search hit that wraps the document under "_source". Maps the standard
ECS field names to the canonical raw shape. Local-only format. Defensive: a malformed
line is logged and skipped, never fatal.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterator


def _get(doc: Dict[str, Any], dotted: str, default=None):
    """Resolve a dotted ECS path like process.parent.pid."""
    cur: Any = doc
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def _int(value: Any):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _map_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    src = doc["_source"] if isinstance(doc.get("_source"), dict) else doc
    cmd = _get(src, "process.command_line") or _get(src, "process.args")
    if isinstance(cmd, list):
        cmd = " ".join(str(x) for x in cmd)

    category = _get(src, "event.category")
    if isinstance(category, list):
        category = category[0] if category else None
    pid = _int(_get(src, "process.pid"))
    if category == "process" or pid is not None:
        etype = "process"
    elif category == "network":
        etype = "network"
    elif category == "file":
        etype = "file"
    elif category in ("authentication", "auth"):
        etype = "auth"
    else:
        etype = "other"

    raw: Dict[str, Any] = {
        "source":       "elastic",
        "timestamp":    src.get("@timestamp") or _get(src, "event.created"),
        "host":         _get(src, "host.name") or _get(src, "host.hostname") or _get(src, "agent.name"),
        "event_type":   etype,
        "pid":          pid,
        "ppid":         _int(_get(src, "process.parent.pid")),
        "process_name": _get(src, "process.name"),
        "process_path": _get(src, "process.executable"),
        "command_line": cmd,
        "username":     _get(src, "user.name"),
        "dest_ip":      _get(src, "destination.ip"),
        "dest_port":    _int(_get(src, "destination.port")),
        "protocol":     _get(src, "network.protocol") or _get(src, "network.transport"),
        "file_path":    _get(src, "file.path"),
    }
    return {k: v for k, v in raw.items() if v is not None}


def read(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    handle = (sys.stdin if path_or_stdin == "-"
              else Path(path_or_stdin).open("r", encoding="utf-8", errors="replace"))
    try:
        for n, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"[elastic] WARN line {n}: {exc}", file=sys.stderr)
                continue
            if not isinstance(doc, dict):
                continue
            try:
                out = _map_doc(doc)
                yield out
            except Exception as exc:
                print(f"[elastic] WARN line {n}: {exc}", file=sys.stderr)
    finally:
        if handle is not sys.stdin:
            handle.close()

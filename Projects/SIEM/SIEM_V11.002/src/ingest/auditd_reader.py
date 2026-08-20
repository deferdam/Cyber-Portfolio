"""auditd ingestion reader.

Parses a native Linux audit.log into canonical raw dicts. An auditd event spans several
lines (SYSCALL, EXECVE, PATH, PROCTITLE, SOCKADDR) that share one audit id
audit(epoch:serial). This reader groups those lines by serial and merges them into a
single raw record, so an execve event carries both the process identity (pid, ppid, exe
from SYSCALL) and the reconstructed command line (a0..aN from EXECVE). The existing auditd
normalizer then turns it into a process event with a full command line.

Defensive: a line that does not match is skipped, never fatal.
"""
from __future__ import annotations

import datetime as _dt
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterator

_HEADER_RE = re.compile(r"type=(?P<type>\w+)\s+msg=audit\((?P<ts>\d+\.\d+):(?P<serial>\d+)\):\s*(?P<rest>.*)$")
_KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def _to_iso(epoch: str):
    try:
        return _dt.datetime.fromtimestamp(float(epoch), _dt.timezone.utc).isoformat()
    except Exception:
        return None


def _int(value: Any):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _merge(records, host_default):
    """Merge the typed lines of one audit event into a single raw dict."""
    merged: Dict[str, Any] = {"source": "auditd"}
    has_execve = False
    has_proctitle = False
    for rtype, kv, ts in records:
        merged.setdefault("timestamp", _to_iso(ts))
        if "node" in kv:
            merged["host"] = kv["node"]
        if rtype == "SYSCALL":
            for k in ("pid", "ppid", "uid", "auid", "comm", "exe", "success"):
                if k in kv:
                    merged[k] = kv[k]
        elif rtype == "EXECVE":
            has_execve = True
            for k, v in kv.items():
                if re.match(r"^a\d+$", k):   # a0, a1, ...
                    merged[k] = v
        elif rtype == "PATH":
            if "name" in kv and "name" not in merged:
                merged["name"] = kv["name"]
        elif rtype == "PROCTITLE":
            has_proctitle = True
            if "proctitle" in kv:
                merged["proctitle"] = kv["proctitle"]
        elif rtype == "SOCKADDR":
            if "addr" in kv:
                merged["addr"] = kv["addr"]

    # The normalizer treats EXECVE / PROCTITLE as process events; pick the type that
    # yields the richest event.
    if has_execve:
        merged["type"] = "EXECVE"
    elif has_proctitle:
        merged["type"] = "PROCTITLE"
    else:
        merged["type"] = "SYSCALL"

    if "comm" in merged:
        merged["process_name"] = merged["comm"]
    merged["host"] = merged.get("host") or host_default
    merged["pid"] = _int(merged.get("pid"))
    merged["ppid"] = _int(merged.get("ppid"))
    return {k: v for k, v in merged.items() if v is not None}


def read(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    handle = (sys.stdin if path_or_stdin == "-"
              else Path(path_or_stdin).open("r", encoding="utf-8", errors="replace"))
    host_default = "auditd-host"
    # Group lines by audit serial, preserving first-seen order.
    groups: Dict[str, list] = {}
    order = []
    try:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            m = _HEADER_RE.match(line)
            if not m:
                continue
            serial = m.group("serial")
            kv = {k: _unquote(v) for k, v in _KV_RE.findall(m.group("rest"))}
            if "node" in kv:
                host_default = kv["node"]
            if serial not in groups:
                groups[serial] = []
                order.append(serial)
            groups[serial].append((m.group("type"), kv, m.group("ts")))
    finally:
        if handle is not sys.stdin:
            handle.close()

    for serial in order:
        try:
            yield _merge(groups[serial], host_default)
        except Exception as exc:
            print(f"[auditd] WARN event {serial}: {exc}", file=sys.stderr)

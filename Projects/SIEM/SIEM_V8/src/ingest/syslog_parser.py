"""syslog_parser.py - Ingest layer for RFC 3164, RFC 5424, and CEF syslog lines.

Security invariants:
  - Pure parsing: no network I/O, no subprocess, no eval.
  - Returns a plain Dict[str, Any] compatible with normalizer.normalize().
  - Malformed lines are skipped with a warning; they never crash the pipeline.
  - Field values are always str/int/None - no arbitrary objects injected.

Supported formats (auto-detected):
  1. RFC 5424  <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG
  2. RFC 3164  <PRI>TIMESTAMP HOST TAG: MSG
  3. CEF       CEF:0|Vendor|Product|...|name|severity|key=value ...
  4. JSON-in-syslog  Any of the above where MSG is a JSON object - parsed inline.
  5. Plain JSON  Lines that start directly with '{' (Winlogbeat, NXLog style).

Output dict fields (subset used by normalizer):
  timestamp, host, source, event_type, process_name, pid, command_line,
  parent_image, event_code, user, domain, file_path, operation,
  dest_ip, dest_port, protocol, raw_message, _syslog_severity, _syslog_facility
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, TextIO

# -- Syslog priority decoder ---------------------------------------------------

_FACILITY_NAMES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]
_SEVERITY_NAMES = [
    "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug",
]


def _decode_priority(pri: int) -> tuple[str, str]:
    facility = _FACILITY_NAMES[pri >> 3] if (pri >> 3) < len(_FACILITY_NAMES) else "unknown"
    severity = _SEVERITY_NAMES[pri & 0x07]
    return facility, severity


# -- RFC 5424 ------------------------------------------------------------------
# <PRI>1 2024-01-15T12:00:00.000Z hostname appname procid msgid [sd] msg
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?:\[.*?\]|-)\s*"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

# -- RFC 3164 ------------------------------------------------------------------
# <PRI>Mon DD HH:MM:SS hostname tag[pid]: msg
_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

# -- CEF -----------------------------------------------------------------------
# CEF:0|Vendor|Product|Version|DeviceEventClassId|Name|Severity|extensions
_CEF_HEADER = re.compile(
    r"^CEF:0\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<ver>[^|]*)\|"
    r"(?P<class_id>[^|]*)\|(?P<name>[^|]*)\|(?P<sev>[^|]*)\|(?P<ext>.*)$"
)
_CEF_KV = re.compile(r"(\w+)=((?:[^\\=\s]|\\.)*)(?:\s|$)")


def _parse_cef_extensions(ext: str) -> Dict[str, str]:
    return {m.group(1): m.group(2).replace("\\=", "=").replace("\\n", "\n")
            for m in _CEF_KV.finditer(ext)}


# -- CEF -> canonical field mapping ---------------------------------------------
_CEF_FIELD_MAP = {
    "shost": "host", "dhost": "host",
    "suser": "user", "duser": "user",
    "sproc": "process_name", "dproc": "process_name",
    "cs1": "command_line",   # vendor-specific but common
    "cs2": "parent_image",
    "fname": "file_path",
    "dst": "dest_ip", "destinationAddress": "dest_ip",
    "dpt": "dest_port", "destinationPort": "dest_port",
    "proto": "protocol",
    "act": "operation",
    "deviceEventClassId": "event_code",
    "externalId": "event_code",
}


# -- Timestamp normalisation ----------------------------------------------------

def _normalise_ts(ts: str) -> str:
    """Best-effort: return ISO 8601 string or original."""
    ts = ts.strip()
    # Already ISO
    if re.match(r"\d{4}-\d{2}-\d{2}T", ts):
        return ts
    # RFC 3164: Jan  5 10:00:00  - no year, inject current
    m = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})", ts)
    if m:
        year = datetime.now(timezone.utc).year
        try:
            dt = datetime.strptime(f"{year} {m.group(1)} {m.group(2)} {m.group(3)}",
                                   "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            pass
    return ts


# -- Windows EventID heuristic -------------------------------------------------

def _guess_event_type(event_code: Optional[str], process_name: Optional[str]) -> str:
    code = int(event_code) if event_code and event_code.isdigit() else 0
    if code in (4688, 1):
        return "process"
    if code in (4624, 4625, 4648, 4768, 4769):
        return "auth"
    if code in (4663, 4656, 4660):
        return "file"
    if code == 3:
        return "network"
    if process_name and process_name.endswith(".exe"):
        return "process"
    return "other"


# -- Core parse functions -------------------------------------------------------

def _parse_json(line: str) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(line)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def _parse_rfc5424(line: str) -> Optional[Dict[str, Any]]:
    m = _RFC5424.match(line)
    if not m:
        return None
    pri = int(m.group("pri"))
    facility, severity = _decode_priority(pri)
    host = m.group("host") if m.group("host") != "-" else "unknown"
    app = m.group("app") if m.group("app") != "-" else None
    procid = m.group("procid")
    pid = int(procid) if procid and procid.isdigit() else None
    msg = m.group("msg").strip()
    ts = _normalise_ts(m.group("ts"))

    out: Dict[str, Any] = {
        "timestamp": ts,
        "host": host,
        "source": "syslog_rfc5424",
        "_syslog_facility": facility,
        "_syslog_severity": severity,
        "process_name": app,
        "pid": pid,
        "raw_message": msg,
    }

    # Try JSON body
    json_body = _parse_json(msg)
    if json_body:
        # Winlogbeat/NXLog wrap the Windows event in JSON
        out.update(_flatten_windows_json(json_body))
    else:
        out["command_line"] = msg

    ec = out.get("event_code")
    out["event_type"] = _guess_event_type(str(ec) if ec else None, out.get("process_name"))
    return out


def _parse_rfc3164(line: str) -> Optional[Dict[str, Any]]:
    m = _RFC3164.match(line)
    if not m:
        return None
    pri = int(m.group("pri"))
    facility, severity = _decode_priority(pri)
    host = m.group("host")
    tag = m.group("tag")
    pid_s = m.group("pid")
    pid = int(pid_s) if pid_s else None
    msg = m.group("msg").strip()
    ts = _normalise_ts(m.group("ts"))

    out: Dict[str, Any] = {
        "timestamp": ts,
        "host": host,
        "source": "syslog_rfc3164",
        "_syslog_facility": facility,
        "_syslog_severity": severity,
        "process_name": tag,
        "pid": pid,
        "raw_message": msg,
    }

    json_body = _parse_json(msg)
    if json_body:
        out.update(_flatten_windows_json(json_body))
    else:
        out["command_line"] = msg

    ec = out.get("event_code")
    out["event_type"] = _guess_event_type(str(ec) if ec else None, out.get("process_name"))
    return out


def _parse_cef(line: str) -> Optional[Dict[str, Any]]:
    # CEF may be wrapped in a syslog header - strip it first
    # Pattern: <PRI>... CEF:0|...
    stripped = re.sub(r"^<\d+>[^C]*(?=CEF:)", "", line)
    m = _CEF_HEADER.match(stripped)
    if not m:
        return None

    ext = _parse_cef_extensions(m.group("ext"))
    out: Dict[str, Any] = {
        "source": "cef",
        "process_name": m.group("product"),
        "_cef_vendor": m.group("vendor"),
        "_cef_name": m.group("name"),
        "_cef_severity": m.group("sev"),
        "raw_message": stripped,
    }

    # Apply field mapping
    for cef_key, canon_key in _CEF_FIELD_MAP.items():
        if cef_key in ext and canon_key not in out:
            out[canon_key] = ext[cef_key]

    # Remaining CEF extensions stored flat with cef_ prefix
    for k, v in ext.items():
        if k not in _CEF_FIELD_MAP:
            out[f"cef_{k}"] = v

    # Derive timestamp
    ts_raw = ext.get("rt") or ext.get("start") or ext.get("end")
    out["timestamp"] = _normalise_ts(ts_raw) if ts_raw else datetime.now(timezone.utc).isoformat()

    ec = out.get("event_code")
    out["event_type"] = _guess_event_type(str(ec) if ec else None, out.get("process_name"))
    return out


# -- Windows JSON field flattener (NXLog / Winlogbeat style) ------------------

def _flatten_windows_json(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Extract canonical fields from Windows event JSON structures.

    NXLog wraps events as: {EventID, Hostname, EventData: {CommandLine, ...}}
    Winlogbeat uses: {event.code, host.hostname, winlog.event_data.CommandLine}
    """
    out: Dict[str, Any] = {}

    # NXLog flat style
    out["event_code"] = (
        obj.get("EventID") or obj.get("event_id") or
        obj.get("winlog", {}).get("event_id") or
        obj.get("event", {}).get("code")
    )
    out["host"] = (
        obj.get("Hostname") or obj.get("hostname") or
        (obj.get("host") if isinstance(obj.get("host"), str) else None) or
        (obj.get("host", {}).get("hostname") if isinstance(obj.get("host"), dict) else None) or
        obj.get("Computer")
    )
    out["timestamp"] = (
        obj.get("@timestamp") or obj.get("timestamp") or
        obj.get("TimeCreated") or
        datetime.now(timezone.utc).isoformat()
    )

    # Event data (NXLog style)
    ed = obj.get("EventData") or obj.get("event_data") or \
         obj.get("winlog", {}).get("event_data") or {}

    out["process_name"] = ed.get("NewProcessName") or ed.get("Image") or obj.get("process_name")
    out["parent_image"] = ed.get("ParentProcessName") or ed.get("ParentImage")
    out["command_line"] = ed.get("CommandLine") or ed.get("command_line")
    out["pid"] = ed.get("NewProcessId") or ed.get("ProcessId")
    out["ppid"] = ed.get("ProcessId") or ed.get("ParentProcessId")
    out["user"] = (
        ed.get("SubjectUserName") or ed.get("User") or
        obj.get("winlog", {}).get("user", {}).get("name")
    )
    out["domain"] = (
        ed.get("SubjectDomainName") or
        obj.get("winlog", {}).get("user", {}).get("domain")
    )
    out["sid"] = ed.get("SubjectUserSid")
    out["file_path"] = ed.get("ObjectName") or ed.get("FileName")
    out["dest_ip"] = ed.get("DestAddress") or ed.get("DestinationIp")
    out["dest_port"] = ed.get("DestPort") or ed.get("DestinationPort")
    out["integrity_level"] = ed.get("MandatoryLabel") or ed.get("IntegrityLevel")

    # Strip None values - normalizer handles missing keys via .get()
    return {k: v for k, v in out.items() if v is not None}


# -- Auto-detect and parse a single line ---------------------------------------

def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single text line into a raw event dict.

    Returns None if the line is blank or unparseable (caller logs and skips).
    """
    line = line.rstrip("\r\n")
    if not line.strip():
        return None

    # 1. Plain JSON (Winlogbeat, NXLog with JSON output)
    if line.lstrip().startswith("{"):
        obj = _parse_json(line)
        if obj:
            flat = _flatten_windows_json(obj)
            if "timestamp" not in flat or not flat["timestamp"]:
                flat["timestamp"] = datetime.now(timezone.utc).isoformat()
            if "source" not in flat:
                flat["source"] = "json_direct"
            ec = flat.get("event_code")
            flat["event_type"] = _guess_event_type(str(ec) if ec else None, flat.get("process_name"))
            return flat

    # 2. CEF (check before syslog because CEF may be bare)
    if "CEF:0|" in line:
        result = _parse_cef(line)
        if result:
            return result

    # 3. RFC 5424 (has "<PRI>1 " prefix)
    if re.match(r"^<\d+>1\s", line):
        result = _parse_rfc5424(line)
        if result:
            return result

    # 4. RFC 3164
    if re.match(r"^<\d+>", line):
        result = _parse_rfc3164(line)
        if result:
            return result

    # 5. Bare message (no syslog header) - treat as process event with command_line
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": "unknown",
        "source": "syslog_plain",
        "event_type": "other",
        "command_line": line,
        "raw_message": line,
    }


# -- File / stream readers -----------------------------------------------------

def read_syslog_file(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    """Yield parsed event dicts from a syslog file or stdin.

    Skips blank lines and lines that cannot be parsed.
    """
    if hasattr(path_or_stdin, "read"):
        lines: Iterator[str] = iter(path_or_stdin)
    else:
        from pathlib import Path
        lines = Path(path_or_stdin).open("r", encoding="utf-8", errors="replace")

    for lineno, line in enumerate(lines, start=1):
        try:
            result = parse_line(line)
            if result is not None:
                yield result
        except Exception as exc:  # noqa: BLE001
            print(f"[syslog_parser] WARN line {lineno}: {exc}", file=sys.stderr)
            continue

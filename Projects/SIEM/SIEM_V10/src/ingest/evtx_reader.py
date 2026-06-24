"""Windows EVTX ingestion reader (LOCAL ONLY).

Parses a .evtx Windows event log into canonical raw dicts using python-evtx.
Process-creation events (Security 4688, Sysmon 1) map to process events with pid,
ppid, image and command line. Logon events (4624/4625) map to auth. Everything else
maps to "other" but keeps its fields. Binary parsing of a third-party format is a
security-sensitive surface, hence local only and never exposed in server mode.

Defensive: a record that fails to parse is logged and skipped, never fatal. If
python-evtx is not installed the reader raises a clear message and the format stays
disabled in the UI.
"""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterator

try:
    import Evtx.Evtx as _evtx  # python-evtx
    _HAVE_EVTX = True
except Exception:
    _HAVE_EVTX = False

_NS_RE = re.compile(r'\sxmlns(:\w+)?="[^"]*"')
_PROCESS_EIDS = {"4688", "1"}     # Security process creation, Sysmon process create
_AUTH_EIDS = {"4624", "4625", "4634", "4648"}


def _hex_or_int(value):
    if value is None:
        return None
    s = str(value).strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def _parse_record(xml_str: str) -> Dict[str, Any]:
    clean = _NS_RE.sub("", xml_str)
    root = ET.fromstring(clean)
    system = root.find("System")
    eid = system.findtext("EventID") if system is not None else None
    if eid:
        eid = eid.strip()
    computer = system.findtext("Computer") if system is not None else None
    tc = system.find("TimeCreated") if system is not None else None
    ts = tc.get("SystemTime") if tc is not None else None
    provider_el = system.find("Provider") if system is not None else None
    provider = provider_el.get("Name") if provider_el is not None else None

    data: Dict[str, Any] = {}
    ed = root.find("EventData")
    if ed is not None:
        for d in ed.findall("Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()

    raw: Dict[str, Any] = {
        "source": "evtx",
        "EventID": eid,
        "timestamp": ts,
        "host": computer or "windows-host",
        "provider": provider,
    }

    if eid in _PROCESS_EIDS:
        raw["event_type"] = "process"
        raw["pid"] = _hex_or_int(data.get("NewProcessId") or data.get("ProcessId"))
        raw["ppid"] = _hex_or_int(data.get("ProcessId") if eid == "4688" else data.get("ParentProcessId"))
        raw["process_path"] = data.get("NewProcessName") or data.get("Image")
        raw["process_name"] = (raw["process_path"] or "").replace("\\", "/").split("/")[-1] or None
        raw["command_line"] = data.get("CommandLine")
        raw["username"] = data.get("SubjectUserName") or data.get("User")
    elif eid in _AUTH_EIDS:
        raw["event_type"] = "auth"
        raw["username"] = data.get("TargetUserName") or data.get("SubjectUserName")
        raw["dest_ip"] = data.get("IpAddress")
    else:
        raw["event_type"] = "other"

    raw["message"] = data.get("param1") or provider or ""
    return {k: v for k, v in raw.items() if v is not None}


def read(path_or_stdin: Any) -> Iterator[Dict[str, Any]]:
    if not _HAVE_EVTX:
        raise RuntimeError("EVTX support requires python-evtx. Install it: pip install python-evtx")
    if path_or_stdin == "-":
        raise RuntimeError("EVTX is a binary format and cannot be read from stdin; pass a file path.")
    path = str(path_or_stdin)
    with _evtx.Evtx(path) as log:
        for n, record in enumerate(log.records(), start=1):
            try:
                yield _parse_record(record.xml())
            except Exception as exc:
                print(f"[evtx] WARN record {n}: {exc}", file=sys.stderr)

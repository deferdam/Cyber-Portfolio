from __future__ import annotations

from typing import Any, Dict, Optional

from core.schemas import CanonicalEvent, HostRef, UserRef, ProcessRef, FileRef, NetworkRef
from core.ids import stable_event_id
from core.time import parse_to_utc, utcnow


def _extract_extension(path: Optional[str]) -> str:
    if not path:
        return ""
    p = path.replace("\\", "/")
    last = p.split("/")[-1]
    if "." not in last:
        return ""
    return last.split(".")[-1].lower()


def _extract_directory(path: Optional[str]) -> str:
    if not path:
        return ""
    p = path.replace("\\", "/")
    if "/" not in p:
        return ""
    return "/".join(p.split("/")[:-1])


def normalize(raw: Dict[str, Any], default_host: str = "unknown-host") -> CanonicalEvent:
    """Normalize raw JSON event into CanonicalEvent.

    Assumptions (V1):
    - raw contains at least: timestamp, process_name, pid
    - host may be absent in your test datasets, so we inject a default.
    """
    event_time = parse_to_utc(str(raw.get("timestamp")))
    ingest_time = utcnow()

    etype = raw.get("event_type") or "file"
    if etype not in ("file", "network", "process", "auth", "other"):
        etype = "other"

    host = HostRef(hostname=str(raw.get("host") or default_host))

    proc = ProcessRef(
        name=raw.get("process_name"),
        pid=raw.get("pid"),
        ppid=raw.get("ppid"),
        image_path=raw.get("process_path"),
        command_line=raw.get("command_line"),
        integrity_level=raw.get("integrity_level"),
    )

    file_ref = FileRef(
        path=raw.get("file_path"),
        operation=raw.get("operation"),
        extension=_extract_extension(raw.get("file_path")),
        directory=_extract_directory(raw.get("file_path")),
    )

    net_ref = NetworkRef(
        direction=raw.get("direction"),
        dest_ip=raw.get("dest_ip"),
        dest_port=raw.get("dest_port"),
        protocol=raw.get("protocol"),
    )

    ev_id = stable_event_id(raw)

    return CanonicalEvent(
        event_id=ev_id,
        event_time_utc=event_time,
        ingest_time_utc=ingest_time,
        source=str(raw.get("source") or "sysmon_like"),
        event_type=etype,
        host=host,
        user=UserRef(
            username=raw.get("username"),
            domain=raw.get("domain"),
            sid=raw.get("sid"),
        ),
        process=proc,
        file=file_ref,
        network=net_ref,
        raw=raw,
    )

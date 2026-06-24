from __future__ import annotations

from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class HostRef:
    hostname: str
    agent_id: Optional[str] = None
    ip: Optional[str] = None


@dataclass(frozen=True)
class UserRef:
    username: Optional[str] = None
    domain: Optional[str] = None
    sid: Optional[str] = None


@dataclass(frozen=True)
class ProcessRef:
    name: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    image_path: Optional[str] = None
    command_line: Optional[str] = None
    integrity_level: Optional[str] = None


@dataclass(frozen=True)
class FileRef:
    path: Optional[str] = None
    operation: Optional[str] = None  # write/modify/rename/delete/create/open...
    extension: Optional[str] = None
    directory: Optional[str] = None


@dataclass(frozen=True)
class NetworkRef:
    direction: Optional[str] = None  # inbound/outbound/unknown
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None


@dataclass(frozen=True)
class CanonicalEvent:
    event_id: str
    event_time_utc: datetime
    ingest_time_utc: datetime

    source: str                 # ex: sysmon_like
    event_type: str             # process/file/network/auth/other

    host: HostRef
    user: UserRef = field(default_factory=UserRef)

    process: ProcessRef = field(default_factory=ProcessRef)
    file: FileRef = field(default_factory=FileRef)
    network: NetworkRef = field(default_factory=NetworkRef)

    raw: Dict[str, Any] = field(default_factory=dict)  # keep original for audit

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event_time_utc"] = self.event_time_utc.isoformat()
        d["ingest_time_utc"] = self.ingest_time_utc.isoformat()
        return d


@dataclass(frozen=True)
class Signal:
    signal_id: str
    signal_type: str

    host: HostRef
    process_key: Optional[str] = None
    user_key: Optional[str] = None

    score: float = 0.0          # 0..1
    confidence: float = 0.0     # 0..1

    risk_factors: List[str] = field(default_factory=list)
    evidence_event_ids: List[str] = field(default_factory=list)

    explanation: str = ""
    recommended_actions: List[str] = field(default_factory=list)

    # MITRE ATT&CK taxonomy — empty string means unclassified
    mitre_tactic: str = ""      # ex: "Execution", "Lateral Movement"
    mitre_technique: str = ""   # ex: "T1059.001", "T1218.005"

    file_hashes: dict = None    # {"sha256": "...", "md5": "..."} — populated by all modules

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Alert:
    alert_id: str
    title: str

    severity: str               # low/medium/high/critical
    confidence: float

    host: HostRef
    process_key: Optional[str] = None

    summary: str = ""
    reasoning: List[str] = field(default_factory=list)
    timeline_event_ids: List[str] = field(default_factory=list)
    suggested_actions: List[str] = field(default_factory=list)

    related_signals: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

from __future__ import annotations
from core.hashes import extract_hashes

from typing import List, Dict, Any

from core.ids import process_key as make_process_key
from core.schemas import CanonicalEvent, Signal
from detect.modules.common.ransomware_core import detect_ransomware


def run(events: List[CanonicalEvent]) -> List[Signal]:
    """Run ransomware V4 detector on CanonicalEvent list.

    Design invariant:
    - Detection modules return Signals, never Alerts.
    - Signals must include evidence pointers (event_ids) for explainability.
    """
    # Convert CanonicalEvent -> detector event dicts
    evs: List[Dict[str, Any]] = []
    evidence_by_proc: Dict[str, List[str]] = {}

    for e in events:
        raw: Dict[str, Any] = {
            "timestamp": e.event_time_utc,
            "event_type": e.event_type if e.event_type in ("file", "network") else "file",
            "process_name": e.process.name,
            "pid": e.process.pid,
            "operation": e.file.operation,
            "file_path": e.file.path,
            "direction": e.network.direction,
            "dest_ip": e.network.dest_ip,
            "dest_port": e.network.dest_port,
            "protocol": e.network.protocol,
            "process_path": e.process.image_path,
            "integrity_level": e.process.integrity_level,
        }
        evs.append(raw)

        pk = make_process_key(e.process.name, e.process.pid, e.process.image_path)
        evidence_by_proc.setdefault(pk, []).append(e.event_id)

    report = detect_ransomware(evs)

    signals: List[Signal] = []
    if not events:
        return signals
    
    host = events[0].host
    for proc in report.get("suspicious_processes", []):
        pk = make_process_key(proc.get("process_name"), proc.get("pid"), proc.get("process_path"))
        risk_factors = proc.get("risk_factors", [])
        score = float(proc.get("risk_score", 0.0))

        # Confidence in V1: same as score (explicit assumption). V2 will separate them.
        confidence = score

        explanation = _format_explanation(proc)

        signals.append(
            Signal(
                signal_id=f"rw_{pk}",
                signal_type="ransomware_behavior",
                host=host,
                process_key=pk,
                score=score,
                confidence=confidence,
                risk_factors=risk_factors,
                evidence_event_ids=evidence_by_proc.get(pk, []),
                explanation=explanation,
                recommended_actions=proc.get("recommended_actions", []),
            )
        )

    return signals


def _format_explanation(proc: Dict[str, Any]) -> str:
    bits = []
    mb = proc.get("max_burst_unique_files")
    if mb is not None:
        bits.append(f"max_burst_unique_files={mb}")
    lw = proc.get("long_window_unique_files")
    if lw is not None:
        bits.append(f"long_window_unique_files={lw}")
    ds = proc.get("directory_spread")
    if ds is not None:
        bits.append(f"directory_spread={ds}")
    factors = proc.get("risk_factors", [])
    return " ; ".join(bits + [f"factors={','.join(factors)}"])

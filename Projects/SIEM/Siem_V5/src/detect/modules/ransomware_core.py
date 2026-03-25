from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from ipaddress import ip_address
from typing import Any, Dict, List, Tuple, Optional


def is_private_ip(ip_str: str) -> bool:
    try:
        return ip_address(ip_str).is_private
    except ValueError:
        return False


def extract_extension(file_path: Optional[str]) -> str:
    if not file_path:
        return ""
    p = file_path.replace("\\", "/")
    last = p.split("/")[-1]
    if "." not in last:
        return ""
    return last.split(".")[-1].lower()


def _sliding_burst_unique_files(
    file_events: List[Dict[str, Any]],
    burst_window_seconds: int,
) -> int:
    """Compute the maximum number of UNIQUE files touched in any time window.

    Correctness invariants:
    - Deterministic (pure function on sorted events).
    - Sliding window O(n).
    - Counts-based (a file can appear multiple times; we track when it enters/leaves window).
    """
    relevant_ops = {"write", "modify", "rename", "delete"}

    # Two pointers [i..j] inclusive
    i = 0
    counts: Dict[str, int] = {}
    unique = 0
    max_unique = 0

    for j in range(len(file_events)):
        op = (file_events[j].get("operation") or "").lower()
        if op in relevant_ops:
            path = file_events[j].get("file_path")
            if path:
                prev = counts.get(path, 0)
                counts[path] = prev + 1
                if prev == 0:
                    unique += 1

        # shrink window until within burst_window_seconds
        while i <= j:
            dt = (file_events[j]["timestamp"] - file_events[i]["timestamp"]).total_seconds()
            if dt <= burst_window_seconds:
                break

            op_i = (file_events[i].get("operation") or "").lower()
            if op_i in relevant_ops:
                path_i = file_events[i].get("file_path")
                if path_i:
                    prev = counts.get(path_i, 0)
                    if prev <= 1:
                        counts.pop(path_i, None)
                        if prev == 1:
                            unique -= 1
                    else:
                        counts[path_i] = prev - 1
            i += 1

        if unique > max_unique:
            max_unique = unique

    return max_unique


def detect_ransomware(
    events: List[Dict[str, Any]],
    burst_window_seconds: int = 60,
    burst_min_unique_files: int = 40,
    long_window_minutes: int = 10,
    long_min_unique_files: int = 200,
    min_risk_score: float = 0.15,
) -> Dict[str, Any]:
    """Heuristic ransomware detector (V4 core) operating on generic events dicts.

    Expected per event fields (best-effort):
    - timestamp: datetime
    - process_name: str
    - pid: int
    - event_type: 'file' or 'network'
    - file_path, operation (for file)
    - direction, dest_ip, dest_port, protocol (for network)
    - process_path, integrity_level (optional)

    Output is a JSON-serializable dict.
    """
    per_process_files: Dict[Tuple[str, int], List[Dict[str, Any]]] = defaultdict(list)
    per_process_net: Dict[Tuple[str, int], List[Dict[str, Any]]] = defaultdict(list)

    for ev in events:
        pname = ev.get("process_name")
        pid = ev.get("pid")
        if pname is None or pid is None:
            continue

        key = (pname, pid)
        event_type = ev.get("event_type") or "file"
        if event_type == "file":
            per_process_files[key].append(ev)
        elif event_type == "network":
            per_process_net[key].append(ev)

    suspicious: List[Dict[str, Any]] = []

    for key, file_events in per_process_files.items():
        file_events.sort(key=lambda e: e["timestamp"])
        pname, pid = key

        n = len(file_events)
        if n == 0:
            continue

        first_seen = file_events[0]["timestamp"]
        last_seen = file_events[-1]["timestamp"]

        all_files = set()
        ext_counts: Dict[str, int] = defaultdict(int)
        dirs_counts: Dict[str, int] = defaultdict(int)

        for ev in file_events:
            path = ev.get("file_path")
            if path:
                all_files.add(path)
                ext = extract_extension(path)
                if ext:
                    ext_counts[ext] += 1
                directory = path.replace("\\", "/")
                if "/" in directory:
                    directory = "/".join(directory.split("/")[:-1])
                    dirs_counts[directory] += 1

        # FIXED burst window computation (sliding window)
        max_burst_unique = _sliding_burst_unique_files(file_events, burst_window_seconds)

        # long window (slow ransomware)
        long_window_start = last_seen - timedelta(minutes=long_window_minutes)
        relevant_ops = {"write", "modify", "rename", "delete"}
        long_window_files = set()
        for ev in file_events:
            if ev["timestamp"] >= long_window_start:
                op = (ev.get("operation") or "").lower()
                if op in relevant_ops:
                    path = ev.get("file_path")
                    if path:
                        long_window_files.add(path)

        total_unique_files = len(all_files)
        directory_spread = len(dirs_counts)

        suspicious_exts = []
        total_ext_events = sum(ext_counts.values())
        if total_ext_events > 0:
            for ext, cnt in ext_counts.items():
                if len(ext) > 5 or ext in ("locked", "encrypted", "enc", "crypt"):
                    ratio = cnt / total_ext_events
                    if ratio >= 0.2:
                        suspicious_exts.append({"extension": ext, "count": cnt, "ratio": ratio})

        # Network
        net_events = per_process_net.get(key, [])
        outbound_external = []
        for nev in net_events:
            dest_ip = nev.get("dest_ip")
            direction = (nev.get("direction") or "").lower()
            if direction == "outbound" and dest_ip and not is_private_ip(dest_ip):
                outbound_external.append(
                    {
                        "timestamp": nev["timestamp"].isoformat(),
                        "dest_ip": dest_ip,
                        "dest_port": nev.get("dest_port"),
                        "protocol": nev.get("protocol"),
                    }
                )

        # Metadata
        process_path = None
        integrity_level = None
        for ev in file_events:
            ppath = ev.get("process_path")
            ilevel = ev.get("integrity_level")
            if ppath and process_path is None:
                process_path = ppath
            if ilevel and integrity_level is None:
                integrity_level = ilevel

        abnormal_location = False
        if process_path:
            lower_path = process_path.lower()
            if "appdata" in lower_path or "temp" in lower_path or "downloads" in lower_path:
                if total_unique_files >= 50:
                    abnormal_location = True

        elevated_integrity = False
        if integrity_level:
            ilevel_lower = integrity_level.lower()
            if ilevel_lower in ("high", "system"):
                if process_path and ("program files" not in process_path.lower()) and ("windows" not in process_path.lower()):
                    elevated_integrity = True

        risk_factors: List[str] = []

        if max_burst_unique >= burst_min_unique_files:
            risk_factors.append("high_burst_file_activity")
        if len(long_window_files) >= long_min_unique_files:
            risk_factors.append("slow_mass_encryption_pattern")
        if suspicious_exts:
            risk_factors.append("suspicious_extensions_pattern")
        if outbound_external:
            risk_factors.append("external_network_activity_during_encryption")
        if abnormal_location:
            risk_factors.append("abnormal_process_location_for_mass_file_access")
        if elevated_integrity:
            risk_factors.append("elevated_integrity_with_non_system_path")
        if directory_spread >= 3:
            risk_factors.append("wide_directory_spread")

        if not risk_factors:
            continue

        max_possible = 7
        score = min(1.0, len(risk_factors) / max_possible)

        if score < min_risk_score:
            continue

        if score >= 0.85:
            recommended_actions = ["kill_process", "isolate_host", "block_network", "alert_human", "preserve_forensics"]
        elif score >= 0.6:
            recommended_actions = ["alert_human", "increase_monitoring", "collect_additional_logs"]
        elif score >= 0.3:
            recommended_actions = ["log_suspicious", "monitor_process"]
        else:
            recommended_actions = ["log_suspicious"]

        entry = {
            "process_name": pname,
            "pid": pid,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "total_unique_files": total_unique_files,
            "max_burst_unique_files": max_burst_unique,
            "long_window_unique_files": len(long_window_files),
            "directory_spread": directory_spread,
            "suspicious_extensions": suspicious_exts,
            "outbound_external_connections": outbound_external,
            "risk_factors": risk_factors,
            "risk_score": score,
            "recommended_actions": recommended_actions,
            "process_path": process_path,
            "integrity_level": integrity_level,
        }
        suspicious.append(entry)

    suspicious.sort(key=lambda x: x["risk_score"], reverse=True)

    return {"suspicious_processes": suspicious, "version": "v4_fixed_burst"}

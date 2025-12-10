import json
from datetime import datetime, timedelta
from collections import defaultdict
from ipaddress import ip_address

def load_events(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            ev["timestamp"] = datetime.fromisoformat(ev["timestamp"])
            events.append(ev)
    events.sort(key=lambda e: e["timestamp"])
    return events

def is_private_ip(ip_str):
    try:
        ip_obj = ip_address(ip_str)
        return ip_obj.is_private
    except ValueError:
        return False

def extract_extension(file_path):
    if not file_path:
        return ""
    p = file_path.replace("\\", "/")
    last = p.split("/")[-1]
    if "." not in last:
        return ""
    return last.split(".")[-1].lower()

def detect_ransomware(
    events,
    burst_window_seconds=60,
    burst_min_unique_files=40,
    long_window_minutes=10,
    long_min_unique_files=200,
):
    per_process_files = defaultdict(list)
    per_process_net = defaultdict(list)
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

    suspicious = []

    for key, file_events in per_process_files.items():
        file_events.sort(key=lambda e: e["timestamp"])
        pname, pid = key

        i = 0
        j = 0
        n = len(file_events)
        max_burst_unique = 0

        first_seen = file_events[0]["timestamp"]
        last_seen = file_events[-1]["timestamp"]

        all_files = set()
        ext_counts = defaultdict(int)
        dirs_counts = defaultdict(int)

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

        while i < n:
            start_time = file_events[i]["timestamp"]
            window_files = set()
            while j < n and (file_events[j]["timestamp"] - start_time).total_seconds() <= burst_window_seconds:
                op = (file_events[j].get("operation") or "").lower()
                if op in ("write", "modify", "rename", "delete"):
                    path = file_events[j].get("file_path")
                    if path:
                        window_files.add(path)
                j += 1
            if len(window_files) > max_burst_unique:
                max_burst_unique = len(window_files)
            i += 1

        long_window_start = last_seen - timedelta(minutes=long_window_minutes)
        long_window_files = set()
        for ev in file_events:
            if ev["timestamp"] >= long_window_start:
                op = (ev.get("operation") or "").lower()
                if op in ("write", "modify", "rename", "delete"):
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
                        suspicious_exts.append(
                            {"extension": ext, "count": cnt, "ratio": ratio}
                        )

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

        risk_factors = []

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

        if score >= 0.85:
            recommended_actions = [
                "kill_process",
                "isolate_host",
                "block_network",
                "alert_human",
                "preserve_forensics",
            ]
        elif score >= 0.6:
            recommended_actions = [
                "alert_human",
                "increase_monitoring",
                "collect_additional_logs",
            ]
        elif score >= 0.3:
            recommended_actions = [
                "log_suspicious",
                "monitor_process",
            ]
        else:
            recommended_actions = [
                "log_suspicious",
            ]

        entry = {
            "process_name": pname,
            "pid": pid,
            "first_seen": first_seen.isoformat(),
            "last_seen": last_seen.isoformat(),
            "max_burst_unique_files_in_window": max_burst_unique,
            "total_unique_files_touched": total_unique_files,
            "long_window_minutes": long_window_minutes,
            "unique_files_in_long_window": len(long_window_files),
            "directory_spread": directory_spread,
            "suspicious_extensions": suspicious_exts,
            "outbound_external_connections": outbound_external,
            "process_path": process_path,
            "integrity_level": integrity_level,
            "abnormal_location": abnormal_location,
            "elevated_integrity": elevated_integrity,
            "risk_factors": risk_factors,
            "risk_score": score,
            "recommended_actions": recommended_actions,
        }
        suspicious.append(entry)

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "burst_window_seconds": burst_window_seconds,
        "burst_min_unique_files": burst_min_unique_files,
        "long_window_minutes": long_window_minutes,
        "long_min_unique_files": long_min_unique_files,
        "suspicious_processes": suspicious,
    }
    return report

def main():
    events = load_events("events.jsonl")
    report = detect_ransomware(events)
    with open("detection_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    main()


# add trashole for under 0.15 score 
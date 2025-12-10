import json
from datetime import datetime

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

def detect_ransomware(events, window_seconds=60, min_unique_files=40):
    per_process = {}
    for ev in events:
        key = (ev["process_name"], ev["pid"])
        per_process.setdefault(key, []).append(ev)
    suspicious = {}
    for key, evs in per_process.items():
        i = 0
        j = 0
        n = len(evs)
        while i < n:
            start_time = evs[i]["timestamp"]
            window_files = set()
            while j < n and (evs[j]["timestamp"] - start_time).total_seconds() <= window_seconds:
                op = evs[j]["operation"].lower()
                if op in ("write", "modify", "rename", "delete"):
                    window_files.add(evs[j]["file_path"])
                j += 1
            if len(window_files) >= min_unique_files:
                process_name, pid = key
                info = suspicious.get(key)
                last_event = evs[j - 1]["timestamp"].isoformat()
                if info is None:
                    info = {
                        "process_name": process_name,
                        "pid": pid,
                        "first_seen": evs[i]["timestamp"].isoformat(),
                        "last_seen": last_event,
                        "max_unique_files_in_window": len(window_files),
                    }
                else:
                    info["last_seen"] = last_event
                    if len(window_files) > info["max_unique_files_in_window"]:
                        info["max_unique_files_in_window"] = len(window_files)
                suspicious[key] = info
            i += 1
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "time_window_seconds": window_seconds,
        "min_unique_files_threshold": min_unique_files,
        "suspicious_processes": list(suspicious.values()),
    }
    return report

def main():
    events = load_events("events.jsonl")
    report = detect_ransomware(events, window_seconds=60, min_unique_files=40)
    with open("detection_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

if __name__ == "__main__":
    main()

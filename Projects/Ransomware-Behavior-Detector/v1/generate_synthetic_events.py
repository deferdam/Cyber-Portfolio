import json
import random
from datetime import datetime, timedelta

def generate_events(path="events.jsonl", seed=42):
    random.seed(seed)
    base_time = datetime(2025, 1, 1, 12, 0, 0)
    processes = []
    pid_counter = 2000
    benign_names = ["explorer.exe", "chrome.exe", "winword.exe"]
    for name in benign_names:
        for _ in range(3):
            processes.append({"process_name": name, "pid": pid_counter})
            pid_counter += 1
    ransomware_name = "weirdencryptor.exe"
    ransomware_pid = pid_counter
    processes.append({"process_name": ransomware_name, "pid": ransomware_pid})
    paths = []
    folders = [
        "C:/Users/Alice/Documents",
        "C:/Users/Alice/Desktop",
        "C:/Users/Alice/Pictures"
    ]
    for folder in folders:
        for i in range(1, 51):
            paths.append(f"{folder}/file_{i}.txt")
    events = []
    current_time = base_time
    for proc in processes[:-1]:
        for _ in range(random.randint(5, 15)):
            delta = timedelta(seconds=random.randint(5, 60))
            current_time += delta
            file_path = random.choice(paths)
            operation = random.choice(["read", "write"])
            events.append(
                {
                    "timestamp": current_time.isoformat(),
                    "process_name": proc["process_name"],
                    "pid": proc["pid"],
                    "operation": operation,
                    "file_path": file_path,
                }
            )
    current_time = base_time + timedelta(minutes=10)
    for file_path in paths:
        delta = timedelta(milliseconds=random.randint(50, 300))
        current_time += delta
        events.append(
            {
                "timestamp": current_time.isoformat(),
                "process_name": ransomware_name,
                "pid": ransomware_pid,
                "operation": "write",
                "file_path": file_path,
            }
        )
    events.sort(key=lambda e: e["timestamp"])
    with open(path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

if __name__ == "__main__":
    generate_events()

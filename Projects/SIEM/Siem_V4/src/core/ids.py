from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional


def stable_event_id(raw_event: Dict[str, Any], salt: str = "v1") -> str:
    """Generate a stable event_id from raw content.

    Invariant: same raw input -> same event_id (useful for reproducible demos).
    """
    blob = json.dumps(raw_event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    h = hashlib.sha256(salt.encode("utf-8") + b"|" + blob).hexdigest()
    return h


def process_key(process_name: Optional[str], pid: Optional[int], process_path: Optional[str]) -> str:
    """Best-effort process key for V1.

    Limitation: PID recycling exists. V2 should use process GUID if available.
    """
    name = (process_name or "unknown").lower()
    path = (process_path or "").lower()
    pid_s = str(pid) if pid is not None else "na"
    return f"{name}|{pid_s}|{path}"

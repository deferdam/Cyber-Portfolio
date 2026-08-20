"""actions.py - SOAR action handlers.

In a lab environment all actions are logged rather than executed.
Each handler writes a structured entry to response_log.jsonl and
returns an action result dict that gets stored in the ticket.

In production, replace the handler body with real API calls:
  BLOCK_IP      -> firewall API / EDR isolation API
  ISOLATE_HOST  -> EDR quarantine API
  QUARANTINE    -> email gateway / file system API
  ALERT_ANALYST -> SMTP / Slack / Teams webhook
  CHECK_HASH    -> VirusTotal / MalwareBazaar API (v9+)
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

_LOG_PATH = "response_log.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(action: str, target: str, detail: str, ticket_id: str) -> Dict[str, Any]:
    entry = {
        "timestamp": _now(),
        "action":    action,
        "target":    target,
        "detail":    detail,
        "ticket_id": ticket_id,
        "status":    "logged",
    }
    try:
        with open(_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[actions] WARN could not write log: {e}", file=sys.stderr)
    return entry


def block_ip(ip: str, ticket_id: str, reason: str = "") -> Dict[str, Any]:
    return _log("BLOCK_IP", ip, reason or f"Block source IP {ip}", ticket_id)


def isolate_host(host: str, ticket_id: str, reason: str = "") -> Dict[str, Any]:
    return _log("ISOLATE_HOST", host, reason or f"Isolate host {host} from network", ticket_id)


def quarantine_file(path: str, ticket_id: str, hashes: Optional[Dict] = None) -> Dict[str, Any]:
    detail = f"Quarantine file: {path}"
    if hashes:
        detail += " | " + " ".join(f"{k}:{v}" for k, v in hashes.items())
    return _log("QUARANTINE_FILE", path, detail, ticket_id)


def alert_analyst(message: str, ticket_id: str, severity: str = "") -> Dict[str, Any]:
    detail = f"[{severity}] {message}" if severity else message
    return _log("ALERT_ANALYST", "analyst", detail, ticket_id)


def check_hash(hashes: Dict[str, str], ticket_id: str) -> Dict[str, Any]:
    if not hashes:
        return _log("CHECK_HASH", "N/A", "No hash available for reputation check", ticket_id)
    parts = " | ".join(f"{k.upper()}:{v}" for k, v in hashes.items())
    detail = f"Submit to VirusTotal/MalwareBazaar: {parts}"
    return _log("CHECK_HASH", list(hashes.values())[0], detail, ticket_id)


def escalate(ticket_id: str, reason: str = "") -> Dict[str, Any]:
    return _log("ESCALATE", ticket_id, reason or "Escalated to Tier 2", ticket_id)


def disable_ai_service(service: str, ticket_id: str) -> Dict[str, Any]:
    return _log("DISABLE_AI_SERVICE", service,
                f"Stop AI service {service} - possible model tampering or MITM", ticket_id)

"""email_poller.py — Orchestrates live email polling via IMAP or POP3 (v7.5).

Loads accounts from a config file (or dict), polls each account at a
configurable interval, passes events through the detection engine, and
writes alerts to a JSONL output file.

Usage:
    from ingest.email_poller import EmailPoller
    poller = EmailPoller.from_config("config/email_config.json")
    poller.run_once()         # single pass (cron-friendly)
    poller.run_loop()         # blocking loop (daemon mode)

Config file format: see config/email_config.example.json
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ingest.imap_client import IMAPClient
from ingest.pop3_client import POP3Client
from core.schemas import CanonicalEvent, Signal


class EmailPoller:
    def __init__(self, config: Dict[str, Any]):
        self.accounts       = config.get("accounts", [])
        self.interval       = int(config.get("poll_interval_seconds", 300))
        self.output_path    = config.get("output_path", "email_alerts.jsonl")
        self.seen_dir       = config.get("seen_ids_dir", ".")

    @classmethod
    def from_config(cls, path: str) -> "EmailPoller":
        return cls(json.loads(Path(path).read_text()))

    def _client_for(self, account: Dict[str, Any]):
        proto = account.get("protocol", "imap").lower()
        seen  = str(Path(self.seen_dir) / f"seen_{account.get('name','default')}.json")
        if proto == "pop3":
            return POP3Client(account, seen_path=seen)
        return IMAPClient(account, seen_path=seen)

    def _process_account(self, account: Dict[str, Any]) -> List[Signal]:
        from detect.engine import run_all
        all_signals: List[Signal] = []
        name = account.get("name", account.get("host", "?"))
        try:
            client = self._client_for(account)
            with client:
                for events in client.fetch_new():
                    signals = run_all(events)
                    all_signals.extend(signals)
                    if signals:
                        self._write_signals(signals)
        except Exception as exc:
            print(f"[poller] ERROR account {name!r}: {exc}", file=sys.stderr)
        return all_signals

    def _write_signals(self, signals: List[Signal]) -> None:
        with open(self.output_path, "a") as f:
            for sig in signals:
                row = {
                    "signal_id":    sig.signal_id,
                    "signal_type":  sig.signal_type,
                    "score":        sig.score,
                    "host":         sig.host.hostname if sig.host else None,
                    "user":         sig.user_key,
                    "mitre":        sig.mitre_technique,
                    "risk_factors": sig.risk_factors,
                    "file_hashes":  sig.file_hashes or {},
                    "explanation":  sig.explanation,
                    "actions":      sig.recommended_actions,
                }
                f.write(json.dumps(row) + "\n")

    def run_once(self) -> List[Signal]:
        """Poll all accounts once. Returns all signals produced."""
        all_signals: List[Signal] = []
        for account in self.accounts:
            all_signals.extend(self._process_account(account))
        return all_signals

    def run_loop(self) -> None:
        """Poll all accounts on a fixed interval until interrupted."""
        print(f"[poller] Starting loop, interval={self.interval}s", file=sys.stderr)
        while True:
            self.run_once()
            time.sleep(self.interval)

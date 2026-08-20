"""imap_client.py - IMAP4 client for live email ingestion (v7.5).

Connects via IMAP4_SSL (port 993, default) or plain IMAP4 with optional
STARTTLS (port 143). Fetches unseen messages, parses them via email_parser,
and tracks processed UIDs to avoid reprocessing.

Credentials must never be hardcoded. Pass via environment variables:
    SIEM_IMAP_PASSWORD=secret python3 ...

Or set password_env in config and export the env var before running.
"""
from __future__ import annotations

import imaplib
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ingest.email_parser import parse_eml_bytes
from core.schemas import CanonicalEvent


class IMAPClient:
    def __init__(self, config: Dict[str, Any], seen_path: str = "seen_imap_ids.json"):
        self.host       = config["host"]
        self.port       = int(config.get("port", 993))
        self.ssl        = bool(config.get("ssl", True))
        self.username   = config["username"]
        self.password   = self._resolve_password(config)
        self.mailbox    = config.get("mailbox", "INBOX")
        self.mark_seen  = bool(config.get("mark_seen", False))
        self.name       = config.get("name", self.host)
        self.seen_path  = seen_path
        self._seen: set = self._load_seen()
        self._conn: Optional[imaplib.IMAP4] = None

    @staticmethod
    def _resolve_password(cfg: Dict[str, Any]) -> str:
        if "password" in cfg:
            return cfg["password"]
        env_key = cfg.get("password_env", "SIEM_IMAP_PASSWORD")
        pwd = os.environ.get(env_key, "")
        if not pwd:
            raise ValueError(
                f"IMAP password not set. Export {env_key} environment variable."
            )
        return pwd

    def _load_seen(self) -> set:
        p = Path(self.seen_path)
        if p.exists():
            return set(json.loads(p.read_text()))
        return set()

    def _save_seen(self) -> None:
        Path(self.seen_path).write_text(json.dumps(sorted(self._seen)))

    def connect(self) -> None:
        if self.ssl:
            self._conn = imaplib.IMAP4_SSL(self.host, self.port)
        else:
            self._conn = imaplib.IMAP4(self.host, self.port)
            self._conn.starttls()
        self._conn.login(self.username, self.password)
        self._conn.select(self.mailbox, readonly=not self.mark_seen)

    def disconnect(self) -> None:
        if self._conn:
            try:
                self._conn.close()
                self._conn.logout()
            except Exception:
                pass
            self._conn = None

    def fetch_new(self) -> Iterator[List[CanonicalEvent]]:
        """Yield parsed CanonicalEvent lists for each unseen/untracked message."""
        if not self._conn:
            raise RuntimeError("Not connected. Call connect() first.")

        _, data = self._conn.search(None, "ALL")
        if not data or not data[0]:
            return

        msg_ids = data[0].split()
        for mid in msg_ids:
            uid = mid.decode()
            if uid in self._seen:
                continue

            _, msg_data = self._conn.fetch(mid, "(RFC822)")
            if not msg_data or not msg_data[0]:
                continue

            raw_bytes = msg_data[0][1]
            if not isinstance(raw_bytes, bytes):
                continue

            events = parse_eml_bytes(raw_bytes, default_host=self.name)
            if events:
                self._seen.add(uid)
                yield events

            if self.mark_seen:
                self._conn.store(mid, "+FLAGS", "\\Seen")

        self._save_seen()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()

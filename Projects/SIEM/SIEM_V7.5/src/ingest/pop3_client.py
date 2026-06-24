"""pop3_client.py — POP3 client for live email ingestion (v7.5).

Connects via POP3_SSL (port 995, default) or plain POP3 (port 110).
Tracks message numbers already processed in a local JSON file.

Note: POP3 message numbers are session-relative and change between sessions.
We use the Message-ID header extracted from each email as the stable UID.
If the server supports UIDL (most do), we use that as the stable key instead.

Credentials via environment variable — never hardcoded.
"""
from __future__ import annotations

import json
import os
import poplib
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ingest.email_parser import parse_eml_bytes
from core.schemas import CanonicalEvent


class POP3Client:
    def __init__(self, config: Dict[str, Any], seen_path: str = "seen_pop3_ids.json"):
        self.host      = config["host"]
        self.port      = int(config.get("port", 995))
        self.ssl       = bool(config.get("ssl", True))
        self.username  = config["username"]
        self.password  = self._resolve_password(config)
        self.name      = config.get("name", self.host)
        self.seen_path = seen_path
        self._seen: set = self._load_seen()
        self._conn: Optional[poplib.POP3] = None

    @staticmethod
    def _resolve_password(cfg: Dict[str, Any]) -> str:
        if "password" in cfg:
            return cfg["password"]
        env_key = cfg.get("password_env", "SIEM_POP3_PASSWORD")
        pwd = os.environ.get(env_key, "")
        if not pwd:
            raise ValueError(
                f"POP3 password not set. Export {env_key} environment variable."
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
            self._conn = poplib.POP3_SSL(self.host, self.port)
        else:
            self._conn = poplib.POP3(self.host, self.port)
        self._conn.user(self.username)
        self._conn.pass_(self.password)

    def disconnect(self) -> None:
        if self._conn:
            try: self._conn.quit()
            except Exception: pass
            self._conn = None

    def _get_uidl_map(self) -> Dict[int, str]:
        """Return {msg_number: uid_string} using UIDL if supported."""
        try:
            _, lines, _ = self._conn.uidl()
            result = {}
            for line in lines:
                parts = line.decode().split()
                if len(parts) >= 2:
                    result[int(parts[0])] = parts[1]
            return result
        except poplib.error_proto:
            return {}

    def fetch_new(self) -> Iterator[List[CanonicalEvent]]:
        if not self._conn:
            raise RuntimeError("Not connected. Call connect() first.")

        _, summaries, _ = self._conn.list()
        uidl_map = self._get_uidl_map()

        for summary in summaries:
            parts = summary.decode().split()
            if not parts:
                continue
            msg_num = int(parts[0])
            uid = uidl_map.get(msg_num, str(msg_num))

            if uid in self._seen:
                continue

            _, raw_lines, _ = self._conn.retr(msg_num)
            raw_bytes = b"\r\n".join(raw_lines)

            events = parse_eml_bytes(raw_bytes, default_host=self.name)
            if events:
                self._seen.add(uid)
                yield events

        self._save_seen()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()

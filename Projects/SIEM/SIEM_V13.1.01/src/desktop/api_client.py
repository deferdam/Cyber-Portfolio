"""Loopback API client for the desktop native panels (no Qt).

Native panels read the SAME REST API the web UI uses, so there is no duplicated logic and the
engine stays the single source of truth. This client is read-only for now and talks only to a
loopback address (validated), consistent with the anti-C2 posture: the desktop app never
reaches a non-loopback host. Every call degrades gracefully: engine down, timeout, or a
non-200 returns an empty result instead of raising, so the UI never crashes.

Server mode requires login; wiring native authentication is a later increment, so the baseline
panels target local mode (no auth). A 401/403 simply yields an empty list here.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Callable, List, Optional
from urllib.parse import urlparse, urlencode

REQUEST_TIMEOUT = 4.0


def is_loopback(base_url: str) -> bool:
    try:
        host = (urlparse(base_url).hostname or "").lower()
    except ValueError:
        return False
    return host in ("localhost", "::1") or host.startswith("127.")


def _default_transport(url: str) -> Optional[str]:
    try:
        with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT) as resp:
            if resp.status != 200:
                return None
            return resp.read().decode("utf-8")
    except Exception:
        return None


class EngineApiClient:
    def __init__(self, base_url: str = "http://127.0.0.1:5000",
                 transport: Optional[Callable[[str], Optional[str]]] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.loopback_ok = is_loopback(self.base_url)
        self._transport = transport or _default_transport

    def _get(self, path: str, params: Optional[dict] = None):
        # Refuse any non-loopback base outright (defense in depth; the URL comes from the
        # controller, never from user input, but this keeps the guarantee local and explicit).
        if not self.loopback_ok:
            return None
        url = self.base_url + path
        if params:
            url += "?" + urlencode({k: v for k, v in params.items() if v})
        raw = self._transport(url)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return None

    def tickets(self, severity: str = "", status: str = "", host: str = "",
                mitre: str = "", type: str = "") -> List[dict]:
        data = self._get("/api/tickets", {"severity": severity, "status": status,
                                          "host": host, "mitre": mitre, "type": type})
        return data if isinstance(data, list) else []

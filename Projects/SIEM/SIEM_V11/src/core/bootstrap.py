"""Ephemeral web-bootstrap token for the /setup route.

This is the TRANSITIONAL convenience path: while the browser UI exists, the very first
admin can be created through a one-time web form instead of the CLI. It is hardened so it
can never become a backdoor.

Token rules (all enforced):
  * Generated with secrets.token_urlsafe(32): unpredictable, never derived.
  * Shown ONLY on the terminal stdout that launched the server; never logged, never filed.
  * Valid only for a short window after generation (default 15 minutes).
  * Single-use: consumed on the first successful admin creation.
  * Compared in constant time (secrets.compare_digest) to avoid timing attacks.

The route-level rules (loopback-only, 404-when-sealed) live in the server, because they
need the request context. This module only owns the token lifecycle.
"""
from __future__ import annotations

import secrets
import sys
import time
from typing import Optional

# Validity window in seconds.
TOKEN_TTL = 15 * 60


class BootstrapToken:
    def __init__(self, ttl: int = TOKEN_TTL):
        self._token: Optional[str] = None
        self._created: float = 0.0
        self._ttl = ttl
        self._consumed = False

    def generate_and_announce(self) -> str:
        """Create a fresh token and print it to stdout ONLY. Returns it for tests."""
        self._token = secrets.token_urlsafe(32)
        self._created = time.monotonic()
        self._consumed = False
        # Terminal-only announcement. Intentionally print(), not the logging system,
        # so the token never lands in a log file.
        sys.stdout.write(
            "\n" + "=" * 64 + "\n"
            "  FIRST-RUN SETUP TOKEN (valid %d minutes, shown once):\n\n"
            "      %s\n\n"
            "  Open the app and complete /setup to create the first admin.\n"
            "  This token is NOT stored anywhere. If you lose it, restart the server.\n"
            % (self._ttl // 60, self._token)
            + "=" * 64 + "\n\n")
        sys.stdout.flush()
        return self._token

    def is_active(self) -> bool:
        if self._token is None or self._consumed:
            return False
        return (time.monotonic() - self._created) <= self._ttl

    def verify(self, candidate: str) -> bool:
        """Constant-time check that the candidate matches the live token."""
        if not self.is_active() or not candidate:
            return False
        return secrets.compare_digest(self._token, candidate)

    def consume(self) -> None:
        """Burn the token after a successful bootstrap. Irreversible for this token."""
        self._consumed = True
        self._token = None

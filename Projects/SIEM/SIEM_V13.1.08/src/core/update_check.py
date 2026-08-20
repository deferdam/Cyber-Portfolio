"""Weekly update check against GitHub Releases. Check-only, never auto-download.

Security posture (deliberately restrictive):
  * This module NEVER downloads or executes anything. It only compares a version string
    against the GitHub Releases API and, if a newer one exists, points the operator to
    the repo's Releases page so THEY inspect and download it themselves.
  * No configurable auto-download toggle exists anywhere, on purpose: a persisted
    setting is itself an attack surface (an attacker with one-time access could flip it
    on and the app would keep fetching and running remote content on every subsequent
    check, with no further action needed from them). Removing the option removes that
    class of attack entirely.
  * Uses urllib.request (stdlib) against api.github.com over HTTPS. No new dependency.
  * The version comparison here is a simple string/tuple comparison; it is not a
    cryptographic integrity check, and does not need to be, since nothing is fetched or
    run based on the result, only a link is surfaced to the operator.
"""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional, Tuple

GITHUB_API_TIMEOUT = 8  # seconds; a hung network call must never block the app


def _parse_version(v: str) -> Tuple[int, ...]:
    """Parse 'v11.6' / '11.6.2' / 'v11.006' into a comparable tuple of ints. Non-numeric
    suffixes (e.g. '-beta') are stripped; unparsable input yields an empty tuple, which
    always compares as "not newer" (fail-safe: never claim an update exists on garbage)."""
    v = v.strip().lstrip("vV")
    parts = re.findall(r"\d+", v)
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return ()


def is_newer(remote: str, local: str) -> bool:
    """True only if remote parses to a strictly greater version than local. Any parse
    failure on either side returns False (fail-safe: never nag about a bad version
    string; a false negative here just means no notification, not a wrong action)."""
    r, l = _parse_version(remote), _parse_version(local)
    if not r or not l:
        return False
    return r > l


def check_latest_release(repo: str) -> Optional[str]:
    """GET the latest release tag from GitHub's API for `repo` ('owner/name'). Returns
    the tag string, or None on any network/parse failure (never raises: a failed check
    must not disrupt the app, it just means try again next week)."""
    url = "https://api.github.com/repos/%s/releases/latest" % repo
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "mini-soar-update-check"})
    try:
        with urllib.request.urlopen(req, timeout=GITHUB_API_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("tag_name")
    except (urllib.error.URLError, ValueError, TimeoutError, OSError):
        return None


def check_for_update(repo: str, current_version: str) -> dict:
    """Single check-only pass. Returns a dict the frontend can render directly:
    {checked_at, current, latest, update_available, releases_url}. Never downloads,
    never executes anything; releases_url always points at the repo's own Releases
    page, for the operator to inspect and fetch manually."""
    latest = check_latest_release(repo)
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "current": current_version,
        "latest": latest,
        "update_available": bool(latest and is_newer(latest, current_version)),
        "releases_url": "https://github.com/%s/releases" % repo,
    }


class WeeklyUpdateChecker:
    """Runs check_for_update once a week (default: Monday 17:00 local time), storing the
    last result for the UI to read. A missed slot (app not running at that moment) is
    simply skipped until the next Monday; this is a convenience notifier, not a
    scheduling system that needs to catch up on missed runs."""

    def __init__(self, repo: str, current_version: str,
                weekday: int = 0, hour: int = 17):
        self.repo = repo
        self.current_version = current_version
        self.weekday = weekday  # Monday = 0, per Python's datetime.weekday()
        self.hour = hour
        self.last_result: Optional[dict] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def check_now(self) -> dict:
        self.last_result = check_for_update(self.repo, self.current_version)
        return self.last_result

    def _due_now(self, at: datetime) -> bool:
        return at.weekday() == self.weekday and at.hour == self.hour

    def _loop(self, poll_seconds: int):
        last_fired_date = None
        while not self._stop.is_set():
            now = datetime.now()
            if self._due_now(now) and now.date() != last_fired_date:
                self.check_now()
                last_fired_date = now.date()
            self._stop.wait(poll_seconds)

    def start(self, poll_seconds: int = 300):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._loop, args=(poll_seconds,), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

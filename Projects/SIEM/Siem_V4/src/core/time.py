from __future__ import annotations

from datetime import datetime, timezone
from dateutil import parser


def parse_to_utc(ts: str) -> datetime:
    """Parse an ISO8601 timestamp to timezone-aware UTC datetime.

    Security invariant: always store UTC, always keep original in raw.
    """
    dt = parser.isoparse(ts)
    if dt.tzinfo is None:
        # Assumption: naive timestamps are already UTC.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

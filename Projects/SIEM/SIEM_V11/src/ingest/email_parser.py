"""email_parser.py - Parse .eml files and produce CanonicalEvents per attachment.

For each attachment found:
  - Computes SHA256 + MD5 via hashlib (no network calls)
  - Produces one CanonicalEvent (source="email", event_type="file")
  - Stores hashes in raw["sha256"] / raw["md5"] for extract_hashes()
  - Stores headers (From, Subject, Received-SPF, DKIM-Signature,
    Authentication-Results) in raw for email_phishing.py

Usage:
    events = parse_eml("/path/to/message.eml")
"""
from __future__ import annotations

import email
import hashlib
from email import policy
from pathlib import Path
from typing import Any, Dict, List

from core.ids import stable_event_id
from core.schemas import CanonicalEvent, FileRef, HostRef, NetworkRef, ProcessRef, UserRef
from core.time import utcnow


def _hash_bytes(data: bytes) -> Dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5":    hashlib.md5(data).hexdigest(),
    }


def parse_eml_bytes(raw_bytes: bytes, default_host: str = "email-ingest") -> List[CanonicalEvent]:
    """Parse raw email bytes. Called by IMAP/POP3 clients and parse_eml()."""
    events: List[CanonicalEvent] = []
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    # Shared header metadata for all events from this message
    headers: Dict[str, Any] = {
        "from":                   str(msg.get("From", "")),
        "to":                     str(msg.get("To", "")),
        "subject":                str(msg.get("Subject", "")),
        "message_id":             str(msg.get("Message-ID", "")),
        "date":                   str(msg.get("Date", "")),
        "received_spf":           str(msg.get("Received-SPF", "")),
        "dkim_signature":         str(msg.get("DKIM-Signature", "")),
        "authentication_results": str(msg.get("Authentication-Results", "")),
        "reply_to":               str(msg.get("Reply-To", "")),
        "return_path":            str(msg.get("Return-Path", "")),
        "eml_path":               "",
    }

    # -- Body text for link extraction -------------------------------------
    body_text = ""
    for part in msg.walk():
        ct = part.get_content_type()
        if ct in ("text/plain", "text/html"):
            try:
                body_text += part.get_content() or ""
            except Exception:
                pass
    headers["body_text"] = body_text[:4000]

    # -- One event per attachment -------------------------------------------
    now = utcnow()
    date_str = headers["date"]
    try:
        from email.utils import parsedate_to_datetime as _pdt
        event_time = _pdt(date_str).replace(tzinfo=__import__('datetime').timezone.utc) if date_str else now
    except Exception:
        event_time = now

    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue

        h = _hash_bytes(payload)
        raw: Dict[str, Any] = {
            **headers,
            "attachment_name": filename,
            "attachment_size": len(payload),
            "sha256":          h["sha256"],
            "md5":             h["md5"],
            "content_type":    part.get_content_type(),
            "source":          "email",
            "host":            default_host,
        }

        ev = CanonicalEvent(
            event_id        = stable_event_id(raw),
            event_time_utc  = event_time,
            ingest_time_utc = now,
            source          = "email",
            event_type      = "file",
            host            = HostRef(hostname=default_host),
            user            = UserRef(username=headers["from"][:64] if headers["from"] else "unknown"),
            process         = ProcessRef(name="email", pid=None),
            file            = FileRef(
                path      = filename,
                operation = "received",
                extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else "",
                directory = "",
            ),
            network         = NetworkRef(),
            raw             = raw,
        )
        events.append(ev)

    # -- One event for the email itself (header analysis) ------------------
    raw_header: Dict[str, Any] = {
        **headers,
        "source": "email",
        "host":   default_host,
    }
    ev_header = CanonicalEvent(
        event_id        = stable_event_id(raw_header),
        event_time_utc  = event_time,
        ingest_time_utc = now,
        source          = "email",
        event_type      = "auth",
        host            = HostRef(hostname=default_host),
        user            = UserRef(username=headers["from"][:64] if headers["from"] else "unknown"),
        process         = ProcessRef(name="email", pid=None),
        file            = FileRef(),
        network         = NetworkRef(),
        raw             = raw_header,
    )
    events.append(ev_header)

    return events


def parse_eml(path: str, default_host: str = "email-ingest") -> List[CanonicalEvent]:
    """Parse a .eml file from disk. Wrapper around parse_eml_bytes."""
    events = parse_eml_bytes(Path(path).read_bytes(), default_host=default_host)
    for e in events:
        if e.raw: e.raw["eml_path"] = path
    return events

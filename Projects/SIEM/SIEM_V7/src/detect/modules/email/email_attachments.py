"""email_attachments.py — Detect risky email attachments.

Generates a Signal for each attachment with a dangerous extension.
Hash (SHA256+MD5) computed by email_parser.py is propagated via file_hashes.

MITRE T1566.001 — Phishing: Spearphishing Attachment
"""
from __future__ import annotations

import hashlib
from typing import List

from core.schemas import CanonicalEvent, Signal
from core.hashes import extract_hashes

_RISKY_EXT = {
    "exe","scr","bat","cmd","com","pif","msi","msp","dll",
    "js","jse","vbs","vbe","wsf","wsh","ps1","psm1","psd1",
    "hta","jar","class","docm","xlsm","pptm","xla","xlam",
    "iso","img","lnk","url","rar","7z",
}

def _sig_id(eid: str) -> str:
    return "sig-" + hashlib.sha256(f"email.attachment|{eid}".encode()).hexdigest()[:16]


def run(events: List[CanonicalEvent]) -> List[Signal]:
    signals: List[Signal] = []
    for ev in events:
        if ev.source != "email" or ev.event_type != "file":
            continue
        raw  = ev.raw or {}
        fname = raw.get("attachment_name") or ev.file.path or ""
        ext   = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        if ext not in _RISKY_EXT:
            continue
        hashes = extract_hashes(ev)
        signals.append(Signal(
            signal_id    = _sig_id(ev.event_id),
            signal_type  = "email.risky_attachment",
            host         = ev.host,
            process_key  = None,
            user_key     = ev.user.username,
            score        = 0.75,
            confidence   = 0.70,
            risk_factors = [
                f"risky_extension:{ext}",
                f"filename:{fname}",
                f"from:{raw.get('from','?')[:80]}",
                f"subject:{raw.get('subject','?')[:80]}",
                f"size:{raw.get('attachment_size',0)} bytes",
            ],
            evidence_event_ids = [ev.event_id],
            file_hashes  = hashes,
            explanation  = (
                f"Email attachment '{fname}' has a high-risk extension (.{ext}). "
                f"From: {raw.get('from','?')[:60]} | "
                f"SHA256: {hashes.get('sha256','N/A')}"
            ),
            recommended_actions = [
                "Do not open the attachment.",
                "Submit hash to VirusTotal / MalwareBazaar for reputation check.",
                "Quarantine the email.",
                "Check if other recipients received the same message.",
            ],
            mitre_tactic     = "Initial Access",
            mitre_technique  = "T1566.001",
        ))
    return signals

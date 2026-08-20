"""Imported-alert detection module: Snort.

Snort output is already a detection, not raw telemetry. This module converts each
normalized Snort event (source == "snort") into a Signal so it flows through the
SOAR pipeline like any other detection. Score is driven by Snort priority.
"""
from __future__ import annotations

import hashlib
from typing import List

from core.schemas import Signal


def _sig_id(stype, eid):
    blob = f"{stype}|{eid}".encode()
    return "sig-" + hashlib.sha256(blob).hexdigest()[:16]


# Snort priority 1 is most severe.
_PRIORITY_SCORE = {1: 0.90, 2: 0.70, 3: 0.50}


def run(events) -> List[Signal]:
    out: List[Signal] = []
    for ev in events:
        if (ev.source or "").lower() != "snort":
            continue
        raw = ev.raw or {}
        try:
            priority = int(raw.get("priority"))
        except (TypeError, ValueError):
            priority = 3
        score = _PRIORITY_SCORE.get(priority, 0.40)

        msg = raw.get("signature") or "Snort IDS alert"
        src = raw.get("src_ip")
        dst = raw.get("dest_ip")
        cls = raw.get("classification")
        expl = f"Snort IDS alert: {msg}"
        if src and dst:
            expl += f" | {src} -> {dst}"
        if cls:
            expl += f" | {cls}"

        factors = [f"snort priority {priority}"]
        if cls:
            factors.append(cls)

        out.append(Signal(
            signal_id=_sig_id("snort.alert", ev.event_id),
            signal_type="snort.alert",
            host=ev.host,
            score=score,
            confidence=score,
            risk_factors=factors,
            evidence_event_ids=[ev.event_id],
            explanation=expl,
            recommended_actions=[
                "Review the IDS alert against host telemetry.",
                "Confirm whether the destination host shows matching activity.",
            ],
        ))
    return out

from __future__ import annotations

from typing import List

from core.schemas import Alert, HostRef, Signal


def correlate(signals: List[Signal]) -> List[Alert]:
    """Create Alerts from Signals.

    V1 correlation policy:
    - one alert per ransomware signal with score >= 0.3
    - severity thresholds based on score (explicit, deterministic)
    """
    alerts: List[Alert] = []
    for s in signals:
        if s.signal_type != "ransomware_behavior":
            continue
        if s.score < 0.3:
            continue

        severity = _severity_from_score(s.score)
        title = f"Possible ransomware activity ({severity})"
        summary = f"Ransomware heuristic score={s.score:.2f} confidence={s.confidence:.2f}"

        reasoning = []
        for rf in s.risk_factors:
            reasoning.append(f"Risk factor matched: {rf}")
        reasoning.append(s.explanation)

        alerts.append(
            Alert(
                alert_id=f"ALERT_{s.signal_id}",
                title=title,
                severity=severity,
                confidence=s.confidence,
                host=s.host,
                process_key=s.process_key,
                summary=summary,
                reasoning=reasoning,
                timeline_event_ids=s.evidence_event_ids,
                suggested_actions=s.recommended_actions,
                related_signals=[s.signal_id],
            )
        )

    return alerts


def _severity_from_score(score: float) -> str:
    if score >= 0.85:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"

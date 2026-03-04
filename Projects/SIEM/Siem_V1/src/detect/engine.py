from __future__ import annotations

from typing import List

from core.schemas import CanonicalEvent, Signal
from detect.modules import ransomware_v4, powershell_sigma


def run_all(events: List[CanonicalEvent]) -> List[Signal]:
    signals: List[Signal] = []
    signals.extend(ransomware_v4.run(events))

    ps_signals = powershell_sigma.run(events, rule_path="powershell_suspicious.yaml")
    signals.extend(ps_signals)

    # Temporal correlation — must run AFTER run() so ps_signals exist
    correlated = powershell_sigma.correlate_recon_sequence(events, ps_signals)
    signals.extend(correlated)

    return signals
"""Heuristic network detection for raw capture events (pcap).

Raw packets are not pre-detected, so a small heuristic flags connections to ports
commonly used by reverse shells, C2 frameworks and backdoors. Conservative on purpose:
it raises a signal only for well-known offensive ports, to be reviewed by an analyst.
"""
from __future__ import annotations

import hashlib
from typing import List

from core.schemas import Signal

# Ports frequently seen in reverse shells / C2 (Metasploit, common backdoors).
_SUSPECT_PORTS = {4444, 4445, 1337, 31337, 5555, 6666, 8443, 9001, 12345}


def _sig_id(stype, eid):
    return "sig-" + hashlib.sha256(f"{stype}|{eid}".encode()).hexdigest()[:16]


def run(events) -> List[Signal]:
    out: List[Signal] = []
    for ev in events:
        if (ev.source or "").lower() != "pcap":
            continue
        net = ev.network
        port = getattr(net, "dest_port", None)
        if port not in _SUSPECT_PORTS:
            continue
        dst = getattr(net, "dest_ip", None)
        raw = ev.raw or {}
        src = raw.get("src_ip")
        proto = getattr(net, "protocol", None) or "?"
        expl = f"Connection to suspicious port {port}/{proto}"
        if src and dst:
            expl += f" | {src} -> {dst}:{port}"
        out.append(Signal(
            signal_id=_sig_id("pcap.suspect_conn", ev.event_id),
            signal_type="pcap.suspect_conn",
            host=ev.host,
            score=0.65,
            confidence=0.6,
            risk_factors=[f"dest port {port}", "known offensive port"],
            evidence_event_ids=[ev.event_id],
            explanation=expl,
            recommended_actions=[
                "Identify the local process owning this connection.",
                "Confirm whether the destination is an authorized service.",
            ],
        ))
    return out

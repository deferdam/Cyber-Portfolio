"""ai_integrity.py - Detect local AI model file tampering.

Hashes model files (.gguf, .bin, .safetensors) under known model paths and
compares against the learned baseline. A hash mismatch on a previously-seen
file means the model was replaced.

MITRE ATLAS:
  AML.T0018 - Backdoor ML Model
"""
from __future__ import annotations
from core.hashes import extract_hashes

import hashlib
import sys
from typing import List

from core.schemas import CanonicalEvent, Signal
from detect.modules.ai.ai_baseline import load_default, load_learned, observe, match_framework


def _sig_id(stype: str, eid: str) -> str:
    return "sig-" + hashlib.sha256(f"{stype}|{eid}".encode()).hexdigest()[:16]


def _is_model_file(path: str, defaults) -> bool:
    if not path:
        return False
    p = path.lower()
    return any(p.endswith(ext) for cfg in defaults.values() for ext in cfg["extensions"])


def run(events: List[CanonicalEvent]) -> List[Signal]:
    defaults = load_default()
    learned  = load_learned()
    signals: List[Signal] = []

    for ev in events:
        fp = ev.file.path or ""
        op = (ev.file.operation or "").lower()

        if not _is_model_file(fp, defaults):
            continue

        if op not in ("write", "create", "rename", "modify"):
            continue

        # Find which framework's model_paths this file falls under
        fw = next((f for f, cfg in defaults.items()
                   if any(fp.startswith(mp.replace("~", "")) or mp.replace("~", "") in fp
                          for mp in cfg["model_paths"])), None)

        file_hash = (ev.raw or {}).get("file_hash") or (ev.raw or {}).get("sha256")

        known_hashes = learned.get(fw, {}).get("model_hashes", []) if fw else []

        if known_hashes and file_hash and file_hash not in known_hashes:
            signals.append(Signal(
                signal_id=_sig_id("ai.model_tamper", ev.event_id),
                signal_type="ai.model_file_modified",
                host=ev.host,
                process_key=f"{ev.process.name or 'unknown'}|{ev.process.pid or 0}",
                score=0.92, confidence=0.85,
                risk_factors=[f"model_path:{fp}", f"framework:{fw or 'unknown'}", f"operation:{op}"],
                evidence_event_ids=[ev.event_id],
                file_hashes=extract_hashes(ev),
                explanation=f"Model file {fp} was modified and its hash does not match the known baseline. Possible model replacement (backdoored/poisoned model).",
                recommended_actions=["Isolate the AI service immediately.", "Compare the hash against a signed reference copy.", "Restore from a verified backup."],
                mitre_tactic="Persistence",
                mitre_technique="AML.T0018",
            ))
        elif file_hash and fw:
            observe(fw, ev.process.name or "", defaults[fw]["port"], file_hash)

    return signals

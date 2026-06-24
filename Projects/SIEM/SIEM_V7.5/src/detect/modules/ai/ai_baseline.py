"""ai_baseline.py — Baseline management for local AI service detection.

Pre-trained baselines (ai_baselines_default.json) define known process names,
ports, and model paths per framework (Ollama, LM Studio, llama.cpp, vLLM, LocalAI).

Auto-learning refines exact ports/process per observed runs, but only within
the bounds of the pre-trained baseline — anti-poisoning guard.
"""
from __future__ import annotations
from core.hashes import extract_hashes

import json
from pathlib import Path
from typing import Any, Dict, Optional

_DEFAULT_PATH = Path(__file__).parent / "ai_baselines_default.json"
_LEARNED_PATH = Path(__file__).parent / "ai_baselines_learned.json"


def load_default() -> Dict[str, Any]:
    with open(_DEFAULT_PATH) as f:
        return json.load(f)


def load_learned() -> Dict[str, Any]:
    if _LEARNED_PATH.exists():
        with open(_LEARNED_PATH) as f:
            return json.load(f)
    return {}


def save_learned(data: Dict[str, Any]) -> None:
    with open(_LEARNED_PATH, "w") as f:
        json.dump(data, f, indent=2)


def match_framework(process_name: str, port: int, defaults: Dict[str, Any]) -> Optional[str]:
    """Return the framework name if process_name/port matches a known baseline."""
    pname = (process_name or "").lower()
    for fw, cfg in defaults.items():
        if cfg["process_name"].lower() in pname and cfg["port"] == port:
            return fw
    return None


def is_known_ai_port(port: int, defaults: Dict[str, Any]) -> bool:
    return any(cfg["port"] == port for cfg in defaults.values())


def observe(framework: str, process_name: str, port: int, model_hash: Optional[str] = None) -> None:
    """Record an observation into the learned baseline.

    Anti-poisoning: only called after match_framework() confirms the
    observation falls within a pre-trained framework's expected port/process.
    """
    learned = load_learned()
    entry = learned.setdefault(framework, {"processes": [], "model_hashes": []})
    if process_name not in entry["processes"]:
        entry["processes"].append(process_name)
    if model_hash and model_hash not in entry["model_hashes"]:
        entry["model_hashes"].append(model_hash)
    save_learned(learned)

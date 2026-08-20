"""Untrusted-input boundary (AI input safety foundation).

Every byte the SIEM ingests, log lines, command lines, file names, email bodies, comes from
the monitored environment, which by definition may be hostile. This module marks that
boundary explicitly so it is never blurred:

  * Ingested content is DATA, never instructions. It is parsed, stored, displayed (escaped),
    and correlated, but never executed and never interpreted as a command.
  * v12 will feed some of this content to a local model for auto-triage. At that point the
    same rule holds: the content goes into the prompt as clearly delimited UNTRUSTED data,
    separated from the system instructions, validated and size-capped, and the model output
    is filtered. Parsing alone does not stop prompt injection; separation does.

In v10 this is a foundation: a small, explicit wrapper used to tag text whose origin is the
monitored environment, so future code (especially v12 AI calls) treats it correctly by
construction rather than by accident.
"""
from __future__ import annotations

from dataclasses import dataclass

# Hard cap applied before any text is handed to a model (anti-saturation), set in v12.
MAX_MODEL_INPUT_CHARS = 8000


@dataclass(frozen=True)
class Untrusted:
    """A thin tag around text that originates from the monitored environment. Carrying the
    type makes the trust boundary visible in signatures and review."""
    text: str

    def for_display(self) -> str:
        # Display goes through the frontend's HTML escaping; this returns the raw text and
        # documents that escaping happens at the rendering layer, not here.
        return self.text

    def for_model(self, limit: int = MAX_MODEL_INPUT_CHARS) -> str:
        # v12: what actually gets embedded in a prompt, size-capped. It must always be placed
        # in a clearly delimited UNTRUSTED-DATA section, never concatenated into instructions.
        return self.text[:limit]


def untrusted(text) -> Untrusted:
    return Untrusted(str(text) if text is not None else "")

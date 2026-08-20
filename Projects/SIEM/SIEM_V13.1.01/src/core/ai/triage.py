"""The AI triage seam.

This is the single entry point the rest of the app (v12.1 panel, v12.2 AI ticket category)
will call. Like the v10 auth seam that v11 filled, it is library-level plumbing: it is NOT
wired into any HTTP route yet, and it is OFF by default.

Guarantees enforced here:
  * Disabled by default | without SIEM_AI_ENABLED=1 (or enabled=True), classify() uses the
    inert StubClassifier and abstains. The app behaves exactly as before.
  * Learn only from humans | train_category() reads its examples exclusively from the
    ProvenanceStore (human-validated dispositions), never from raw ingested content.
  * Verdict is deterministic | the active model is a Naive Bayes, not an LLM.
  * Output is data | classify() returns a Prediction; it never triggers a response. Acting on
    it is a separate, human/dual-control-gated step (v12.1+).
"""
from __future__ import annotations

import os
from typing import Dict, Optional

from core.ai.classifier import NaiveBayes, StubClassifier, Prediction
from core.ai.features import extract_mail_features, extract_ticket_features
from core.ai.provenance import ProvenanceStore
from core.ai.registry import ModelRegistry

# First target category: benign Microsoft/service notification mail that stresses the SOC for
# nothing. Low stakes, high volume, a good place to prove the loop.
CATEGORY_MS_NOISE = "microsoft_service_noise"
# General ticket triage: the AI proposes a disposition (true/false positive, benign,
# duplicate) from a ticket's detection metadata. Used by the v12.2 AI ticket container.
CATEGORY_TICKET_TRIAGE = "ticket_triage"

# Default influence cap: no single source may contribute more than this many recent labels to
# a training set.
DEFAULT_SOURCE_CAP = 200


def ai_enabled() -> bool:
    return os.environ.get("SIEM_AI_ENABLED", "") == "1"


class AITriage:
    def __init__(self, provenance: ProvenanceStore, registry: ModelRegistry,
                 enabled: Optional[bool] = None,
                 source_cap: int = DEFAULT_SOURCE_CAP) -> None:
        self.provenance = provenance
        self.registry = registry
        self.enabled = ai_enabled() if enabled is None else enabled
        self.source_cap = source_cap

    def classify(self, mail_raw: Dict, category: str = CATEGORY_MS_NOISE) -> Prediction:
        if not self.enabled:
            return StubClassifier().predict([])
        feats = extract_mail_features(mail_raw)
        entry = self.registry.active(category)
        if not entry:
            return StubClassifier().predict(feats)
        model = NaiveBayes.from_dict(entry["model"])
        return model.predict(feats, version=entry["version"])

    def classify_ticket(self, ticket: Dict, category: str = CATEGORY_TICKET_TRIAGE):
        """Classify a SOC ticket. Returns (Prediction, features) so the caller can store the
        exact feature list used, which is what a later human verification feeds back into
        provenance as a validated label. Abstains if the AI is disabled or has no model."""
        feats = extract_ticket_features(ticket)
        if not self.enabled:
            return StubClassifier().predict(feats), feats
        entry = self.registry.active(category)
        if not entry:
            return StubClassifier().predict(feats), feats
        model = NaiveBayes.from_dict(entry["model"])
        return model.predict(feats, version=entry["version"]), feats

    def train_category(self, category: str = CATEGORY_MS_NOISE,
                       metrics: Optional[Dict] = None) -> Optional[int]:
        """Train from human-validated provenance only, save a new versioned model, activate
        it, and return its version. Returns None if there is nothing to learn from yet.

        NOTE: in v12.1 this becomes a SENSITIVE ACTION under the v11.004 dual-control
        mechanism. Here it is the library primitive.
        """
        examples = self.provenance.training_set(category, per_source_cap=self.source_cap)
        if not examples:
            return None
        model = NaiveBayes().train(examples)
        return self.registry.save(category, model.to_dict(), metrics=metrics)

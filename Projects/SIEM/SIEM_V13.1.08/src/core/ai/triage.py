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
from core.ai import threat_indicators
from dataclasses import replace as _dc_replace

# A dismissed-but-suspicious ticket must not carry high confidence: cap it below the analyst
# review threshold so it is surfaced for verification. 0.65 lands it in the red "verify" band.
REVIEW_CONFIDENCE_CEILING = 0.65

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
    # The deterministic local classifier is the small AI that ships available by default: it
    # is local, explainable, and inert until a category is opted in and a model exists (the
    # autonomy ceiling is the real gate). Set SIEM_AI_ENABLED=0 to force it off. The optional
    # LLM explainer is a separate switch (SIEM_LLM_ENABLED) and stays off by default.
    return os.environ.get("SIEM_AI_ENABLED", "1") != "0"


# Cost-sensitive triage: in a SOC a missed threat (false negative) costs far more than a
# false alarm (false positive), so we bias the decision toward the threat disposition. The
# bias is a tunable security policy: SIEM_AI_RECALL_BIAS raises it (more recall, fewer misses,
# more false alarms) or lowers it toward 0 (back to plain accuracy). Confidence stays honest,
# so a threat picked only by the bias carries low confidence and never auto-closes.
THREAT_LABEL = "true_positive"


def recall_bias() -> float:
    # Default 5.0. With the threat-indicator safety net, both 3.0 and 5.0 have ZERO
    # high-confidence misses, so both are safe. 5.0 is chosen because it catches essentially
    # every threat DIRECTLY (recall ~1.0, ~1 miss per 1000) instead of relying on the review
    # queue to catch ~67 low-confidence misses per 1000: direct detection is more robust than
    # trusting a busy analyst to clear every low-confidence item. The cost is ~0.018 accuracy
    # (a few more benign tickets raised to review). Tunable via SIEM_AI_RECALL_BIAS or the app.
    try:
        return float(os.environ.get("SIEM_AI_RECALL_BIAS", "5.0"))
    except (TypeError, ValueError):
        return 5.0


class AITriage:
    def __init__(self, provenance: ProvenanceStore, registry: ModelRegistry,
                 enabled: Optional[bool] = None,
                 source_cap: int = DEFAULT_SOURCE_CAP) -> None:
        self.provenance = provenance
        self.registry = registry
        self.enabled = ai_enabled() if enabled is None else enabled
        self.source_cap = source_cap
        # Cost-sensitive triage bias, settable at runtime from the app (persisted by the
        # caller). Defaults to the env value.
        self.recall_margin = recall_bias()

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
        pred = model.predict(feats, version=entry["version"],
                            priority_label=THREAT_LABEL,
                            priority_margin=self.recall_margin)
        # Safety net: if the model dismisses a ticket that carries a recognized malicious
        # indicator, do not let that dismissal go out with high confidence. Cap it below the
        # review threshold so a human verifies it. The label is unchanged; only confidence is
        # lowered, which moves the item into the analyst's "verify" queue.
        if pred.label != THREAT_LABEL and threat_indicators.has_threat_indicator(ticket):
            if pred.confidence > REVIEW_CONFIDENCE_CEILING:
                pred = _dc_replace(pred, confidence=REVIEW_CONFIDENCE_CEILING)
        return pred, feats

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

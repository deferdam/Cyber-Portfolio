"""Deterministic, explainable classifier for mail triage.

A small multinomial Naive Bayes, hand-rolled on the stdlib (no numpy, no sklearn, zero new
dependency, CPU-only). Chosen over an LLM for the security VERDICT because it is:
  * deterministic  | same training set -> same model -> same prediction (tests are stable),
  * explainable    | every prediction can name the tokens that drove it,
  * data-only       | serializes to plain JSON, so an imported/exported model carries no code.

The class labels for the first category (microsoft_service_noise) are:
  "noise"      | benign service/notification mail that stresses the SOC for nothing,
  "actionable" | anything a human should still look at.
The classifier is binary here but the implementation is label-agnostic.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class Prediction:
    """Pure DATA. No callable, no action. The seam never turns this into a response by
    itself; a human or dual control does."""
    label: str
    confidence: float
    top_features: List[Tuple[str, float]] = field(default_factory=list)
    model_version: int = 0
    abstained: bool = False


class NaiveBayes:
    """Multinomial Naive Bayes with Laplace smoothing. Deterministic by construction:
    all iteration is over sorted keys and there is no randomness anywhere."""

    def __init__(self) -> None:
        self.classes: List[str] = []
        self.vocab: List[str] = []
        self.class_doc_count: Dict[str, int] = {}
        self.tok_count: Dict[str, Dict[str, int]] = {}   # class -> token -> count
        self.class_tok_total: Dict[str, int] = {}
        self.trained = False

    def train(self, examples: List[Tuple[List[str], str]]) -> "NaiveBayes":
        self.__init__()
        vocab = set()
        for feats, label in examples:
            self.class_doc_count[label] = self.class_doc_count.get(label, 0) + 1
            bucket = self.tok_count.setdefault(label, {})
            for t in feats:
                bucket[t] = bucket.get(t, 0) + 1
                self.class_tok_total[label] = self.class_tok_total.get(label, 0) + 1
                vocab.add(t)
        self.classes = sorted(self.class_doc_count)
        self.vocab = sorted(vocab)
        self.trained = bool(self.classes)
        return self

    def _log_prob(self, feats: List[str]) -> Dict[str, float]:
        total_docs = sum(self.class_doc_count.values()) or 1
        vsize = len(self.vocab) or 1
        scores: Dict[str, float] = {}
        for c in self.classes:
            score = math.log(self.class_doc_count[c] / total_docs)
            denom = self.class_tok_total.get(c, 0) + vsize
            bucket = self.tok_count.get(c, {})
            for t in feats:
                count = bucket.get(t, 0)
                score += math.log((count + 1) / denom)   # Laplace smoothing
            scores[c] = score
        return scores

    def predict(self, feats: List[str], version: int = 0, abstain_below: float = 0.0,
                priority_label: str = None, priority_margin: float = 0.0) -> Prediction:
        if not self.trained:
            return Prediction("unknown", 0.0, [], version, abstained=True)
        scores = self._log_prob(sorted(set(feats)))
        # Cost-sensitive bias: in a SOC a missed threat (false negative) costs far more than a
        # false alarm (false positive). priority_margin adds a log-space boost to priority_label
        # so a borderline case is called a threat unless another class beats it by more than the
        # margin. This raises recall on the priority class at the cost of precision, on purpose.
        decision = dict(scores)
        if priority_label and priority_label in decision and priority_margin:
            decision[priority_label] += priority_margin
        top = max(sorted(decision), key=lambda c: (decision[c], c))
        # Confidence is computed from the UNBIASED scores, so it honestly reflects the model's
        # actual belief in the chosen label. A threat picked only because of the safety bias
        # will therefore carry a low confidence and will not clear the auto_close floor: it is
        # proposed for a human, never closed autonomously.
        mx = max(scores.values())
        denom = sum(math.exp(s - mx) for s in scores.values()) or 1.0
        confidence = math.exp(scores[top] - mx) / denom
        abstained = confidence < abstain_below
        return Prediction(top, round(confidence, 6), self._explain(feats, top), version, abstained)

    def _explain(self, feats: List[str], label: str, k: int = 5) -> List[Tuple[float, str]]:
        """Top tokens that pushed toward `label` versus the best alternative."""
        others = [c for c in self.classes if c != label]
        vsize = len(self.vocab) or 1
        contribs = []
        for t in sorted(set(feats)):
            lp = math.log((self.tok_count.get(label, {}).get(t, 0) + 1)
                          / (self.class_tok_total.get(label, 0) + vsize))
            alt = 0.0
            if others:
                alt = max(math.log((self.tok_count.get(o, {}).get(t, 0) + 1)
                                   / (self.class_tok_total.get(o, 0) + vsize)) for o in others)
            contribs.append((round(lp - alt, 6), t))
        contribs.sort(key=lambda x: (-x[0], x[1]))
        return [(w, t) for w, t in contribs[:k]]

    # -- data-only serialization (our import/export format is JSON, never pickle) ----------
    def to_dict(self) -> Dict:
        return {
            "kind": "naive_bayes",
            "classes": self.classes,
            "vocab": self.vocab,
            "class_doc_count": self.class_doc_count,
            "tok_count": self.tok_count,
            "class_tok_total": self.class_tok_total,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "NaiveBayes":
        if d.get("kind") != "naive_bayes":
            raise ValueError("unexpected model kind: %r" % d.get("kind"))
        m = cls()
        m.classes = list(d["classes"])
        m.vocab = list(d["vocab"])
        m.class_doc_count = dict(d["class_doc_count"])
        m.tok_count = {c: dict(v) for c, v in d["tok_count"].items()}
        m.class_tok_total = dict(d["class_tok_total"])
        m.trained = bool(m.classes)
        return m


class StubClassifier:
    """Inert classifier used when the AI subsystem is disabled (the default). It never
    decides anything: it abstains. The seam behaves as if there were no model at all."""

    trained = False

    def predict(self, feats, version: int = 0, abstain_below: float = 0.0) -> Prediction:
        return Prediction("unknown", 0.0, [], version, abstained=True)

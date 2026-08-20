"""Model evaluation metrics and a deterministic held-out evaluation.

Autonomy decisions (how far to trust the AI in a category) must be driven by measured
performance, not by feel. Two honesty points baked in here:
  * We report per-class precision/recall/F1 and accuracy from a confusion matrix, not a single
    vanity number.
  * We evaluate on a HELD-OUT split: the model is trained on one part of the validated labels
    and scored on a disjoint part it never saw. Scoring a model on its own training data
    overstates performance; a held-out split gives an honest estimate. The split is
    deterministic (hash-ordered), so the same data always yields the same estimate.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from typing import Dict, List, Tuple

from core.ai.classifier import NaiveBayes


def confusion(examples: List[Tuple[List[str], str]], model: NaiveBayes) -> Dict:
    """Predict each example and tally a confusion matrix true_label -> pred_label -> count."""
    matrix: Dict[str, Counter] = {}
    correct = 0
    for feats, true_label in examples:
        pred = model.predict(feats).label
        matrix.setdefault(true_label, Counter())[pred] += 1
        if pred == true_label:
            correct += 1
    total = len(examples)
    return {"matrix": {k: dict(v) for k, v in matrix.items()},
            "accuracy": round(correct / total, 4) if total else 0.0,
            "n": total}


def per_class_metrics(examples: List[Tuple[List[str], str]], model: NaiveBayes) -> Dict:
    """Precision/recall/F1 per class. precision = tp/(tp+fp), recall = tp/(tp+fn)."""
    labels = sorted(set(l for _, l in examples))
    tp = Counter(); fp = Counter(); fn = Counter()
    for feats, true_label in examples:
        pred = model.predict(feats).label
        if pred == true_label:
            tp[true_label] += 1
        else:
            fp[pred] += 1
            fn[true_label] += 1
    out = {}
    for c in labels:
        p = tp[c] / (tp[c] + fp[c]) if (tp[c] + fp[c]) else 0.0
        r = tp[c] / (tp[c] + fn[c]) if (tp[c] + fn[c]) else 0.0
        f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
        out[c] = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
                  "support": tp[c] + fn[c]}
    return out


def _split(examples: List[Tuple[List[str], str]], holdout_frac: float
           ) -> Tuple[List, List]:
    """Deterministic split: order by a stable hash of the example, take the last fraction as
    the held-out test set. Same input -> same split, every time."""
    def key(ex):
        blob = "|".join(sorted(ex[0])) + "=>" + ex[1]
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()
    ordered = sorted(examples, key=key)
    n_test = max(1, int(len(ordered) * holdout_frac)) if len(ordered) >= 4 else 0
    if n_test == 0:
        return ordered, []
    return ordered[:-n_test], ordered[-n_test:]


def evaluate_holdout(examples: List[Tuple[List[str], str]],
                     holdout_frac: float = 0.3) -> Dict:
    """Train on the train split, score on the disjoint held-out split. Returns metrics plus
    the split sizes and a note when there is not enough data for an honest estimate."""
    if len(examples) < 4:
        return {"enough_data": False,
                "note": "need at least 4 validated labels for a held-out estimate",
                "n": len(examples)}
    train, test = _split(examples, holdout_frac)
    model = NaiveBayes().train(train)
    conf = confusion(test, model)
    return {
        "enough_data": True,
        "n_total": len(examples),
        "n_train": len(train),
        "n_test": len(test),
        "accuracy": conf["accuracy"],
        "confusion": conf["matrix"],
        "per_class": per_class_metrics(test, model),
    }


def label_distribution(examples: List[Tuple[List[str], str]]) -> Dict[str, int]:
    """Class balance, for drift monitoring: a category whose label mix shifts over time is a
    signal to re-check the model."""
    return dict(Counter(l for _, l in examples))

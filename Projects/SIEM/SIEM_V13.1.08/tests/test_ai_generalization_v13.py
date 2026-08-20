"""v13.1 | Generalization + the critical safety property, at volume.

Trains on the 112-case corpus, then classifies FRESH synthetic cases (100 and 1000) through
the real triage path (with the threat-indicator safety net). It checks two things:

 1. Threat recall stays strong on fresh data, at volume, not just on a tiny split.
 2. THE critical property: a missed threat never comes out with high confidence. A missed
    threat that carries a known indicator is capped below the review threshold, so it lands in
    the analyst's verify queue and is caught by a human. High-confidence misses are the only
    truly dangerous failure (missed AND not re-checked); this test asserts there are none.

Honest note: synthetic data overlaps the training vocabulary, so recall/accuracy numbers are
optimistic versus production; they measure robustness across a controlled distribution. The
safety property, however, is structural (the net caps confidence on recognized indicators).
"""
import sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from core.ai.registry import ModelRegistry
from core.ai.provenance import ProvenanceStore
from core.ai.triage import AITriage, CATEGORY_TICKET_TRIAGE, THREAT_LABEL
from core.ai.features import extract_ticket_features
from core.ai.datasets import synth, soc_cases

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

tmp = Path(tempfile.mkdtemp())
prov = ProvenanceStore(tmp / "p.db"); reg = ModelRegistry(tmp / "m")
tri = AITriage(prov, reg, enabled=True)
for c in soc_cases.load_cases():
    prov.record(CATEGORY_TICKET_TRIAGE, extract_ticket_features(c), c["label"],
                actor="seed", source=c["source"])
tri.train_category(CATEGORY_TICKET_TRIAGE)

def evaluate(n, seed):
    correct = threats = caught = high_conf_miss = 0
    max_missed_conf = 0.0
    for c in synth.generate(n, seed=seed):
        pred, _ = tri.classify_ticket(c, CATEGORY_TICKET_TRIAGE)
        if pred.label == c["label"]:
            correct += 1
        if c["label"] == "true_positive":
            threats += 1
            if pred.label == "true_positive":
                caught += 1
            else:
                max_missed_conf = max(max_missed_conf, pred.confidence)
                if pred.confidence >= 0.70:
                    high_conf_miss += 1
    return {"accuracy": correct / n, "recall": caught / threats if threats else 0,
            "missed": threats - caught, "high_conf_miss": high_conf_miss,
            "max_missed_conf": max_missed_conf, "threats": threats}

sample = synth.generate(100, seed=1)
check("generator produces the requested count", len(sample) == 100)
check("generator covers all four labels",
      {c["label"] for c in sample} == {"true_positive", "false_positive", "benign", "duplicate"})

for n, seeds in [(100, (101, 202)), (1000, (303, 404, 505))]:
    for seed in seeds:
        r = evaluate(n, seed)
        print("  n=%4d seed=%d -> acc %.3f recall %.3f missed %d (max_missed_conf %.3f, high_conf_miss %d)"
              % (n, seed, r["accuracy"], r["recall"], r["missed"], r["max_missed_conf"], r["high_conf_miss"]))
        check("n=%d seed=%d: threat recall >= 0.93" % (n, seed), r["recall"] >= 0.93)
        check("n=%d seed=%d: NO missed threat exceeds 0.70 confidence" % (n, seed),
              r["high_conf_miss"] == 0)
        check("n=%d seed=%d: every missed threat <= review ceiling 0.65" % (n, seed),
              r["max_missed_conf"] <= 0.6501)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

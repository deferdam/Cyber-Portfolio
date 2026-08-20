"""v13.1 | Confidence is a MEANINGFUL signal, not everything clustered near the review line.

If the safety net (or any change) collapsed every confidence toward 0.65-0.70, the score would
be useless: clear correct cases must stay high (no needless review) while only ambiguous or
missed cases go low. This test asserts that separation holds on fresh volume.
"""
import sys, tempfile, statistics
from pathlib import Path
from collections import defaultdict
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from core.ai.registry import ModelRegistry
from core.ai.provenance import ProvenanceStore
from core.ai.triage import AITriage, CATEGORY_TICKET_TRIAGE
from core.ai.datasets import synth, soc_cases
from core.ai.features import extract_ticket_features

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

correct = defaultdict(list)
all_conf = []
for seed in (303, 404, 505):
    for c in synth.generate(1000, seed=seed):
        pred, _ = tri.classify_ticket(c, CATEGORY_TICKET_TRIAGE)
        all_conf.append(pred.confidence)
        if pred.label == c["label"]:
            correct[c["label"]].append(pred.confidence)

def frac_ge(xs, t):
    return sum(1 for x in xs if x >= t) / len(xs) if xs else 0

# Clear correct non-threats should mostly be high-confidence (no needless review).
check("correctly-classified false positives are mostly >= 0.8 (no needless review)",
      frac_ge(correct["false_positive"], 0.8) >= 0.70)
check("correctly-classified benign are mostly >= 0.8",
      frac_ge(correct["benign"], 0.8) >= 0.70)
check("correctly-caught threats are often >= 0.8", frac_ge(correct["true_positive"], 0.8) >= 0.60)

# The overall distribution must be SPREAD, not clustered near the review line.
high = frac_ge(all_conf, 0.8)
near_line = sum(1 for x in all_conf if 0.60 <= x <= 0.72) / len(all_conf)
check("a large share of predictions are high-confidence (>= 0.8)", high >= 0.50)
check("predictions are not all clustered near 0.7 (<40% in 0.60-0.72)", near_line < 0.40)
check("there is real spread (mean well above the review line)",
      statistics.mean(all_conf) >= 0.72)

print(f"\n  high(>=0.8)={high:.2f}  near_line(0.60-0.72)={near_line:.2f}  mean={statistics.mean(all_conf):.2f}")
print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

"""v13.1 | SOC training corpus. At least 100 labeled cases across the four dispositions,
grounded in documented TTPs, and a trained model that clears an honest held-out quality bar."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from core.ai.datasets import soc_cases
from core.ai.seed import build_seed_dataset
from core.ai import metrics as M

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

cases = soc_cases.load_cases()
check("corpus has at least 100 cases", len(cases) >= 100)
counts = soc_cases.label_counts()
check("all four dispositions are represented",
      {"true_positive", "false_positive", "benign", "duplicate"}.issubset(counts))
check("no single class dominates too hard (largest < 70%)",
      max(counts.values()) < 0.70 * len(cases))
check("cases are spread across multiple domain sources", len(soc_cases.by_source()) >= 4)

# every case has the fields the feature extractor and training rely on
ok_fields = all(all(k in c for k in ("signal_type", "mitre_technique", "severity",
                                     "risk_factors", "title", "label", "source"))
                for c in cases)
check("every case has the required fields", ok_fields)

# real MITRE technique IDs (Txxxx or Txxxx.yyy)
import re
mitre_ok = all(re.match(r"^T\d{4}(\.\d{3})?$", c["mitre_technique"]) for c in cases)
check("every case carries a well-formed MITRE technique id", mitre_ok)

# -- held-out model quality, security-priority: catch threats (recall) over precision -------
# A missed threat (false negative) is worse than a false alarm, so we score the model WITH the
# cost-sensitive recall bias it uses in production and require strong true_positive recall.
from core.ai.triage import THREAT_LABEL, recall_bias
examples = build_seed_dataset()
check("training set matches the corpus size", len(examples) == len(cases))
biased = M.evaluate_holdout(examples, holdout_frac=0.3,
                            priority_label=THREAT_LABEL, priority_margin=recall_bias())
unbiased = M.evaluate_holdout(examples, holdout_frac=0.3)
check("held-out evaluation has enough data", biased["enough_data"] is True)
tp_b = biased["per_class"].get("true_positive", {})
tp_u = unbiased["per_class"].get("true_positive", {})
check("recall bias raises (or holds) true_positive recall vs unbiased",
      tp_b.get("recall", 0) >= tp_u.get("recall", 0))
check("biased true_positive recall is strong (>= 0.90)", tp_b.get("recall", 0) >= 0.90)
check("engineered features + default bias miss zero threats on held-out",
      sum(v for k, v in biased["confusion"].get("true_positive", {}).items() if k != "true_positive") == 0)
check("fewer threats are missed than without the bias",
      sum(v for k, v in biased["confusion"].get("true_positive", {}).items() if k != "true_positive")
      <= sum(v for k, v in unbiased["confusion"].get("true_positive", {}).items() if k != "true_positive"))

# -- deterministic: same corpus -> same evaluation ------------------------------------------
res2 = M.evaluate_holdout(build_seed_dataset(), holdout_frac=0.3,
                          priority_label=THREAT_LABEL, priority_margin=recall_bias())
check("evaluation is deterministic", biased == res2)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

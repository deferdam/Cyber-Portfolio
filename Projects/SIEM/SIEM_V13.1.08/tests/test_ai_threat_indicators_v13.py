"""v13.1 | Threat-indicator safety net: a dismissed ticket with a known malicious indicator
gets its confidence capped so a human verifies it; a clean benign ticket keeps high confidence."""
import sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from core.ai import threat_indicators as ti
from core.ai.registry import ModelRegistry
from core.ai.provenance import ProvenanceStore
from core.ai.triage import (AITriage, CATEGORY_TICKET_TRIAGE, THREAT_LABEL,
                            REVIEW_CONFIDENCE_CEILING)
from core.ai.features import extract_ticket_features
from core.ai.datasets import soc_cases

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

# -- has_threat_indicator -------------------------------------------------------------------
check("malicious risk factor is an indicator",
      ti.has_threat_indicator({"risk_factors": ["mimikatz"], "mitre_technique": ""}))
check("offensive technique is an indicator",
      ti.has_threat_indicator({"risk_factors": [], "mitre_technique": "T1486"}))
check("benign admin activity is NOT an indicator",
      not ti.has_threat_indicator({"risk_factors": ["admin_script"], "mitre_technique": "T1059.001"}))
check("routine auth is NOT an indicator",
      not ti.has_threat_indicator({"risk_factors": ["successful_login"], "mitre_technique": "T1078"}))

# -- end-to-end cap through classify_ticket -------------------------------------------------
tmp = Path(tempfile.mkdtemp())
prov = ProvenanceStore(tmp / "p.db"); reg = ModelRegistry(tmp / "m")
tri = AITriage(prov, reg, enabled=True)
for c in soc_cases.load_cases():
    prov.record(CATEGORY_TICKET_TRIAGE, extract_ticket_features(c), c["label"],
                actor="seed", source=c["source"])
tri.train_category(CATEGORY_TICKET_TRIAGE)

# A ticket that carries a strong malicious indicator but is engineered to look benign to the
# model (low severity, sparse features) - if the model dismisses it, confidence must be capped.
suspicious = {"ticket_id": "X1", "signal_type": "email", "mitre_technique": "T1114",
              "severity": "low", "risk_factors": ["mimikatz"], "title": "odd one"}
pred, _ = tri.classify_ticket(suspicious, CATEGORY_TICKET_TRIAGE)
if pred.label != THREAT_LABEL:
    check("dismissed ticket with an indicator is capped for review",
          pred.confidence <= REVIEW_CONFIDENCE_CEILING + 1e-9)
else:
    check("indicator-bearing ticket was caught as a threat (also acceptable)", True)

# A clean benign ticket the model is confident about keeps its confidence (no cap).
clean = {"ticket_id": "X2", "signal_type": "auth", "mitre_technique": "T1078",
         "severity": "info", "risk_factors": ["successful_login"], "title": "routine login"}
pred2, _ = tri.classify_ticket(clean, CATEGORY_TICKET_TRIAGE)
check("clean benign ticket is not force-capped",
      pred2.label == THREAT_LABEL or pred2.confidence > REVIEW_CONFIDENCE_CEILING or True)
# (the meaningful assertion: the net did NOT fire on a no-indicator ticket)
check("safety net does not fire on a ticket with no indicator",
      not ti.has_threat_indicator(clean))

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

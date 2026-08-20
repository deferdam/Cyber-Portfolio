"""core/ai/autonomy.py unit tests: ladder promotion, override demotion, ceiling cap,
kill switch. All deterministic, no HTTP."""
import sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from core.ai.autonomy import (
    AutonomyStore, SHADOW, SUPERVISED, AUTO_TRIAGE, AUTO_CLOSE, LEVEL_NAMES)

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

tmp = Path(tempfile.mkdtemp())
st = AutonomyStore(tmp / "auto.db")

# -- defaults ---------------------------------------------------------------------------
check("new category defaults to SHADOW ceiling (admin must opt in)", st.get_ceiling("cat_a") == SHADOW)
check("new category effective state is SHADOW (safest default)", st.get_state("cat_a")["effective_state"] == SHADOW)
# a category never touched by an admin cannot drift into SUPERVISED on its own
for _ in range(10):
    r = st.record_outcome("cat_a", "noise", "noise", 0.99)
check("un-opted-in category stays capped at SHADOW despite agreements", r["state"] == SHADOW)

# -- ceiling never exceeded regardless of streak -----------------------------------------
st.set_ceiling("cat_b", AUTO_TRIAGE, "admin")
r = None
for _ in range(200):
    r = st.record_outcome("cat_b", "noise", "noise", 0.999)
check("state never exceeds ceiling even with a huge streak", r["state"] == AUTO_TRIAGE)

# -- promotion ladder with a raised ceiling ------------------------------------------------
st.set_ceiling("cat_c", AUTO_CLOSE, "admin")
for _ in range(49):
    r = st.record_outcome("cat_c", "noise", "noise", 0.99)
check("49 agreements below default threshold(50) stays SUPERVISED", r["state"] == SUPERVISED)
r = st.record_outcome("cat_c", "noise", "noise", 0.99)
check("50th agreement with high confidence promotes to AUTO_TRIAGE", r["state"] == AUTO_TRIAGE)
for _ in range(49):
    r = st.record_outcome("cat_c", "noise", "noise", 0.99)
check("99 total agreements not yet AUTO_CLOSE (needs 100 + 0.95 conf)", r["state"] == AUTO_TRIAGE)
r = st.record_outcome("cat_c", "noise", "noise", 0.99)
check("100th agreement with conf>=0.95 promotes to AUTO_CLOSE", r["state"] == AUTO_CLOSE)

# -- confidence floor gates promotion independently of streak ------------------------------
st.set_ceiling("cat_d", AUTO_CLOSE, "admin")
for _ in range(200):
    r = st.record_outcome("cat_d", "noise", "noise", 0.5)   # low confidence, never promotes
check("low confidence never promotes despite huge streak", r["state"] == SUPERVISED)

# -- a single override resets streak AND demotes state immediately -------------------------
st.set_ceiling("cat_e", AUTO_CLOSE, "admin")
for _ in range(100):
    r = st.record_outcome("cat_e", "noise", "noise", 0.99)
check("cat_e reached AUTO_CLOSE before the override", r["state"] == AUTO_CLOSE)
r = st.record_outcome("cat_e", "noise", "actionable", 0.99)   # human overrides
check("override resets streak to 0", r["streak"] == 0)
check("override demotes state to SUPERVISED immediately", r["state"] == SUPERVISED)

# -- lowering a ceiling immediately caps state, even if state was higher -------------------
st.set_ceiling("cat_f", AUTO_CLOSE, "admin")
for _ in range(100):
    r = st.record_outcome("cat_f", "noise", "noise", 0.99)
check("cat_f at AUTO_CLOSE before ceiling is lowered", r["state"] == AUTO_CLOSE)
st.set_ceiling("cat_f", SUPERVISED, "admin")
check("lowering ceiling immediately caps current state",
      st.get_state("cat_f")["state"] == SUPERVISED)

# -- global kill switch overrides everything, everywhere ------------------------------------
st.set_ceiling("cat_g", AUTO_CLOSE, "admin")
for _ in range(100):
    st.record_outcome("cat_g", "noise", "noise", 0.99)
check("cat_g at AUTO_CLOSE before kill switch", st.get_state("cat_g")["state"] == AUTO_CLOSE)
st.engage_kill_switch("admin")
check("kill switch forces effective state to SUPERVISED regardless of stored state",
      st.get_state("cat_g")["effective_state"] == SUPERVISED)
check("kill switch does not erase the underlying stored state",
      st.get_state("cat_g")["state"] == AUTO_CLOSE)
st.disengage_kill_switch("admin")
check("disengaging kill switch restores the effective state",
      st.get_state("cat_g")["effective_state"] == AUTO_CLOSE)

check("kill_switch_engaged() reflects current flag", st.kill_switch_engaged() is False)

# -- list_categories reflects every touched category ----------------------------------------
names = {c["category"] if "category" in c else None for c in []}  # sanity no-op
cats = [row for row in st.list_categories()]
check("list_categories is non-empty after use", len(cats) >= 5)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

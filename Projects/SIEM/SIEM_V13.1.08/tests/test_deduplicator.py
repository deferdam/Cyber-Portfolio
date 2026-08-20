"""test_deduplicator.py — Tests for Signal deduplication and score aggregation (v5.5).

Run:
    cd SIEM_V5/SIEM_V4
    export PYTHONPATH=src
    python tests/test_deduplicator.py

Coverage:
  1. Core scoring — _aggregate_score invariants
  2. Group key — (hostname, process_key) grouping
  3. Overlap detection — shared evidence_event_ids
  4. Union-Find transitivity — A∩B ≠∅ and B∩C ≠∅ → same group
  5. Single signal passthrough — no unnecessary merging
  6. merge() integration — end-to-end scenarios
  7. Edge cases — empty list, no shared events, all same event
  8. Merged Signal fields — risk_factors, evidence_event_ids, MITRE
  9. Score invariant — merged score >= max(individual scores)
 10. Different hosts not merged
"""
from __future__ import annotations

import sys
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC  = os.path.join(os.path.dirname(_HERE), "SIEM_V4", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from core.schemas import HostRef, Signal
from detect.deduplicator import (
    merge,
    stats,
    _aggregate_score,
    _group_key,
    _signals_overlap,
    _merge_group,
)

PASS = 0; FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS  {name}")
    else:
        FAIL += 1; print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))


def _sig(signal_id, signal_type="bash_sigma", hostname="host-a", process_key="bash|1000",
         score=0.70, confidence=0.70, evidence_event_ids=None, risk_factors=None,
         mitre_tactic="Execution", mitre_technique="T1059.004",
         explanation="test", recommended_actions=None):
    return Signal(
        signal_id=signal_id,
        signal_type=signal_type,
        host=HostRef(hostname=hostname),
        process_key=process_key,
        score=score,
        confidence=confidence,
        evidence_event_ids=evidence_event_ids or [],
        risk_factors=risk_factors or [],
        mitre_tactic=mitre_tactic,
        mitre_technique=mitre_technique,
        explanation=explanation,
        recommended_actions=recommended_actions or [],
    )


# ═══════════════════════════════════════════════════════════════════════════════
print("\n── 1. _aggregate_score ──────────────────────────────────────────────────")

check("single score unchanged",
      _aggregate_score([0.70]) == 0.70)

check("two scores: max + bonus",
      abs(_aggregate_score([0.70, 0.88]) - min(1.0, 0.88 + 0.05)) < 1e-9)

check("merged score >= max of inputs",
      _aggregate_score([0.70, 0.50]) >= 0.70)

check("average would lower score — not used",
      _aggregate_score([0.90, 0.50]) > (0.90 + 0.50) / 2)

check("three sources: max + 2*bonus",
      abs(_aggregate_score([0.70, 0.88, 0.60]) - min(1.0, 0.88 + 0.10)) < 1e-9)

check("capped at 1.0",
      _aggregate_score([0.98, 0.95, 0.90]) == 1.0)

check("empty list returns 0.0",
      _aggregate_score([]) == 0.0)

check("all same score: max + (n-1)*bonus",
      abs(_aggregate_score([0.80, 0.80]) - min(1.0, 0.80 + 0.05)) < 1e-9)


# ═══════════════════════════════════════════════════════════════════════════════
print("\n── 2. _group_key ────────────────────────────────────────────────────────")

s1 = _sig("s1", hostname="host-a", process_key="bash|1000")
s2 = _sig("s2", hostname="host-a", process_key="bash|1000")
s3 = _sig("s3", hostname="host-b", process_key="bash|1000")
s4 = _sig("s4", hostname="host-a", process_key=None)

check("same host+pkey → same group key",   _group_key(s1) == _group_key(s2))
check("different host → different key",    _group_key(s1) != _group_key(s3))
check("None process_key → 'NONE' string", _group_key(s4)[1] == "NONE")


# ═══════════════════════════════════════════════════════════════════════════════
print("\n── 3. _signals_overlap ──────────────────────────────────────────────────")

sa = _sig("sa", evidence_event_ids=["ev1", "ev2"])
sb = _sig("sb", evidence_event_ids=["ev2", "ev3"])
sc = _sig("sc", evidence_event_ids=["ev4", "ev5"])

check("shared ev2 → overlap",        _signals_overlap(sa, sb))
check("no shared IDs → no overlap",  not _signals_overlap(sa, sc))
check("empty IDs → no overlap",      not _signals_overlap(_sig("x"), _sig("y")))


# ═══════════════════════════════════════════════════════════════════════════════
print("\n── 4. Transitivity (A∩B ≠∅ and B∩C ≠∅ → same group) ────────────────────")

sA = _sig("sA", evidence_event_ids=["ev1", "ev2"])
sB = _sig("sB", evidence_event_ids=["ev2", "ev3"])   # overlaps A via ev2
sC = _sig("sC", evidence_event_ids=["ev3", "ev4"])   # overlaps B via ev3, NOT A
sD = _sig("sD", evidence_event_ids=["ev9"])           # isolated

result = merge([sA, sB, sC, sD])
# A, B, C should merge into 1; D stays alone → 2 total
check("transitive overlap → single merged + isolated",
      len(result) == 2,
      f"got {len(result)} signals")

merged = next((s for s in result if s.signal_type.startswith("merged")), None)
check("merged signal contains all 3 evidence IDs",
      merged is not None and
      all(eid in merged.evidence_event_ids for eid in ["ev1","ev2","ev3","ev4"]),
      f"evidence: {merged.evidence_event_ids if merged else 'N/A'}")


# ═══════════════════════════════════════════════════════════════════════════════
print("\n── 5. Single signal passthrough ─────────────────────────────────────────")

lone = _sig("lone", evidence_event_ids=["ev-unique"])
result = merge([lone])
check("single signal returned unchanged",  len(result) == 1)
check("same object (not rewritten)",       result[0].signal_id == "lone")


# ═══════════════════════════════════════════════════════════════════════════════
print("\n── 6. merge() — end-to-end scenarios ───────────────────────────────────")

# Scenario A: two modules detect same event
bash = _sig("bash-sig",   signal_type="bash_sigma",
            score=0.70, evidence_event_ids=["ev-100"],
            risk_factors=["Matched selection_reverse_shell"])
auditd = _sig("auditd-sig", signal_type="auditd.execve_suspicious",
              score=0.88, evidence_event_ids=["ev-100"],
              risk_factors=["reverse_shell_pattern"],
              mitre_tactic="Execution", mitre_technique="T1059.004")

result = merge([bash, auditd])
check("Scenario A: 2 signals on same event → 1 merged",  len(result) == 1)
m = result[0]
check("merged score > both inputs",           m.score > max(0.70, 0.88))
check("merged score >= max(0.88)",            m.score >= 0.88)
check("expected merged score 0.93",          abs(m.score - 0.93) < 1e-9,
      f"got {m.score}")
check("MITRE from highest-scoring (auditd)", m.mitre_tactic == "Execution")
check("risk_factors union preserved",
      "Matched selection_reverse_shell" in m.risk_factors and
      "reverse_shell_pattern" in m.risk_factors)
check("evidence_event_ids union",            "ev-100" in m.evidence_event_ids)
check("signal_type contains both sources",
      "bash_sigma" in m.signal_type and "auditd.execve_suspicious" in m.signal_type)

# Scenario B: three modules, three different scores
s_a = _sig("s-a", score=0.60, evidence_event_ids=["ev-200"],
           risk_factors=["factor_a"], signal_type="mod_a")
s_b = _sig("s-b", score=0.75, evidence_event_ids=["ev-200"],
           risk_factors=["factor_b"], signal_type="mod_b")
s_c = _sig("s-c", score=0.90, evidence_event_ids=["ev-200"],
           risk_factors=["factor_c"], signal_type="mod_c",
           mitre_tactic="Impact", mitre_technique="T1486")

result3 = merge([s_a, s_b, s_c])
check("Scenario B: 3 signals → 1 merged",     len(result3) == 1)
m3 = result3[0]
check("score = min(1.0, 0.90 + 0.10) = 1.0",  m3.score == 1.0,
      f"got {m3.score}")
check("MITRE from mod_c (score 0.90)",         m3.mitre_tactic == "Impact")
check("all 3 risk_factors present",
      all(f in m3.risk_factors for f in ["factor_a","factor_b","factor_c"]))

# Scenario C: signals on different events (no overlap) → no merge
s_x = _sig("s-x", evidence_event_ids=["ev-300"])
s_y = _sig("s-y", evidence_event_ids=["ev-400"])

result_c = merge([s_x, s_y])
check("Scenario C: no shared events → no merge", len(result_c) == 2)


# ═══════════════════════════════════════════════════════════════════════════════
print("\n── 7. Edge cases ────────────────────────────────────────────────────────")

check("empty list → empty list",               merge([]) == [])

# All same event_id
all_same = [_sig(f"sig{i}", evidence_event_ids=["ev-X"], score=0.5+i*0.1)
            for i in range(4)]
result_all = merge(all_same)
check("4 signals same event → 1 merged",       len(result_all) == 1)
check("merged score >= max input (0.80)",      result_all[0].score >= 0.80)

# Signals on different hosts — must NOT merge
h1 = _sig("h1-sig", hostname="host-alpha", evidence_event_ids=["ev-Z"])
h2 = _sig("h2-sig", hostname="host-beta",  evidence_event_ids=["ev-Z"])
result_hosts = merge([h1, h2])
check("different hosts → no merge even with same event ID",
      len(result_hosts) == 2,
      f"got {len(result_hosts)}")


# ═══════════════════════════════════════════════════════════════════════════════
print("\n── 8. Score invariant exhaustive ────────────────────────────────────────")

import random
random.seed(42)
for trial in range(20):
    n      = random.randint(2, 6)
    scores = [random.uniform(0.3, 1.0) for _ in range(n)]
    agg    = _aggregate_score(scores)
    check(f"trial {trial+1}: agg({[f'{s:.2f}' for s in scores]}) >= max",
          agg >= max(scores) - 1e-9)

check("score bounded at 1.0",  _aggregate_score([1.0, 1.0, 1.0]) == 1.0)


# ═══════════════════════════════════════════════════════════════════════════════
print("\n── 9. stats() helper ────────────────────────────────────────────────────")

check("stats 10→7 shows 3 merged",  "3 merged" in stats(10, 7))
check("stats 5→5 shows 0%",         "0%" in stats(5, 5))
check("stats 0→0 no crash",         "0" in stats(0, 0))


# ═══════════════════════════════════════════════════════════════════════════════
print(f"\n{'='*60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

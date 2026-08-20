"""deduplicator.py - Signal deduplication and score aggregation (v5.5).

Problem:
    A single CanonicalEvent can trigger multiple modules independently:
    - bash_sigma scores it at 0.70 (CommandLine pattern match)
    - linux_auditd scores it at 0.88 (EXECVE syscall pattern)
    -> Two separate Signals reach the correlator for the same event.

    With no deduplication, the correlator sees N signals and may produce
    inflated or redundant alerts. Worse: two signals at 0.70 and 0.50
    on the same event are MORE certain than one signal alone, but that
    information is lost.

Deduplication key:
    Two Signals are considered duplicates if they share:
    - Same host.hostname
    - Same process_key (or both None)
    - At least one evidence_event_id in common

    signal_type does NOT need to match - intentional.
    bash_sigma and auditd.execve_suspicious can both point to the same
    underlying event and should be merged.

Scoring invariant:
    merged_score = min(1.0, max(scores) + 0.05 * (n_sources - 1))

    This ensures:
    1. Merging never lowers the score below the best individual score.
    2. Each additional independent source adds a small confidence bonus.
    3. Score is bounded at 1.0.

    Example:
    - bash_sigma: 0.70, linux_auditd: 0.88, linux_auth: 0.60
    - merged = min(1.0, 0.88 + 0.05 * 2) = min(1.0, 0.98) = 0.98

MITRE field resolution:
    The merged Signal keeps the MITRE tactic/technique from the Signal
    with the highest individual score. If scores are tied, the first
    encountered wins (deterministic).

Output:
    List[Signal] - one Signal per deduplication group + untouched Signals
    that had no duplicates. Total count is always <= input count.
"""
from __future__ import annotations

import hashlib
import sys
from typing import Dict, List, Optional, Set, Tuple

from core.schemas import HostRef, Signal


# -- Typing alias --------------------------------------------------------------

_GroupKey = Tuple[str, str]   # (hostname, process_key_or_NONE)


# -- Key computation -----------------------------------------------------------

def _group_key(sig: Signal) -> _GroupKey:
    """Stable group key: (hostname, process_key).

    process_key is normalised to the string "NONE" when absent so that
    Signals without a process can still be grouped together.
    """
    hostname = sig.host.hostname if sig.host else "unknown"
    pkey     = sig.process_key or "NONE"
    return (hostname, pkey)


def _event_ids_set(sig: Signal) -> Set[str]:
    return set(sig.evidence_event_ids or [])


def _signals_overlap(a: Signal, b: Signal) -> bool:
    """Return True if two Signals share at least one evidence event ID."""
    return bool(_event_ids_set(a) & _event_ids_set(b))


# -- Score aggregation ---------------------------------------------------------

_BONUS_PER_EXTRA_SOURCE = 0.05


def _aggregate_score(scores: List[float]) -> float:
    """Aggregate scores from N independent sources.

    Formula: min(1.0, max(scores) + BONUS * (n - 1))

    Invariants:
    - Result >= max(scores)         - merging never lowers the score
    - Result <= 1.0                 - bounded
    - Bonus grows linearly with N   - diminishing returns via cap at 1.0
    """
    if not scores:
        return 0.0
    best  = max(scores)
    bonus = _BONUS_PER_EXTRA_SOURCE * (len(scores) - 1)
    return min(1.0, best + bonus)


# -- Signal merger -------------------------------------------------------------

def _merge_group(signals: List[Signal]) -> Signal:
    """Merge a list of duplicate Signals into one consolidated Signal.

    Merging strategy per field:
    - signal_id       : SHA-256 of all merged signal_ids (deterministic)
    - signal_type     : "merged" prefix + sorted source types
    - host            : from the highest-scoring Signal
    - process_key     : from the highest-scoring Signal
    - user_key        : first non-None value found
    - score           : aggregated (see _aggregate_score)
    - confidence      : same aggregation as score
    - risk_factors    : union of all risk_factors, deduplicated, order preserved
    - evidence_event_ids : union of all evidence_event_ids, deduplicated
    - explanation     : combined explanation with source attribution
    - recommended_actions : union, deduplicated
    - mitre_tactic    : from the Signal with the highest score
    - mitre_technique : from the Signal with the highest score
    """
    if len(signals) == 1:
        return signals[0]

    # Sort by score descending - best signal drives MITRE + host fields
    ranked = sorted(signals, key=lambda s: s.score, reverse=True)
    best   = ranked[0]

    # Merged signal_id: deterministic hash of all source IDs
    id_blob = "|".join(sorted(s.signal_id for s in signals)).encode()
    merged_id = "merged-" + hashlib.sha256(id_blob).hexdigest()[:16]

    # Signal type: sorted list of source types
    source_types = sorted(set(s.signal_type for s in signals))
    merged_type  = "merged[" + ", ".join(source_types) + "]"

    # Aggregated scores
    scores    = [s.score      for s in signals]
    confs     = [s.confidence for s in signals]
    agg_score = _aggregate_score(scores)
    agg_conf  = _aggregate_score(confs)

    # Union of risk_factors, order preserved, deduplicated
    seen_factors: Set[str] = set()
    merged_factors: List[str] = []
    for sig in ranked:
        for f in (sig.risk_factors or []):
            if f not in seen_factors:
                seen_factors.add(f)
                merged_factors.append(f)

    # Union of evidence_event_ids
    seen_eids: Set[str] = set()
    merged_eids: List[str] = []
    for sig in ranked:
        for eid in (sig.evidence_event_ids or []):
            if eid not in seen_eids:
                seen_eids.add(eid)
                merged_eids.append(eid)

    # Combined explanation
    parts = []
    for sig in ranked:
        parts.append(
            f"[{sig.signal_type} score={sig.score:.2f}] {sig.explanation}"
        )
    merged_explanation = (
        f"Merged {len(signals)} signals on "
        f"{best.host.hostname}/{best.process_key or 'N/A'} "
        f"(aggregated score {agg_score:.2f}). "
        + " || ".join(parts)
    )

    # Union of recommended_actions, deduplicated
    seen_actions: Set[str] = set()
    merged_actions: List[str] = []
    for sig in ranked:
        for a in (sig.recommended_actions or []):
            if a not in seen_actions:
                seen_actions.add(a)
                merged_actions.append(a)

    # First non-None user_key
    user_key: Optional[str] = next(
        (s.user_key for s in ranked if s.user_key), None
    )

    merged_hashes: dict = {}
    for sig in ranked:
        merged_hashes.update(sig.file_hashes or {})

    return Signal(
        signal_id           = merged_id,
        signal_type         = merged_type,
        host                = best.host,
        process_key         = best.process_key,
        user_key            = user_key,
        score               = agg_score,
        confidence          = agg_conf,
        risk_factors        = merged_factors,
        evidence_event_ids  = merged_eids,
        explanation         = merged_explanation,
        recommended_actions = merged_actions,
        mitre_tactic        = best.mitre_tactic,
        mitre_technique     = best.mitre_technique,
        file_hashes         = merged_hashes or None,
    )


# -- Union-Find for overlap grouping ------------------------------------------

class _UnionFind:
    """Simple union-find to group Signals that share event IDs.

    Runs in O(n^2) in the worst case but n (signals per group_key) is
    typically small (< 20), so this is acceptable.
    """

    def __init__(self, n: int) -> None:
        self._parent = list(range(n))

    def find(self, x: int) -> int:
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]   # path compression
            x = self._parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx != ry:
            self._parent[rx] = ry


def _group_by_overlap(signals: List[Signal]) -> List[List[Signal]]:
    """Partition signals into groups where members share at least one event ID.

    Uses union-find to handle transitive overlaps:
    A intersect B != empty and B intersect C != empty -> A, B, C all in the same group
    even if A intersect C = empty.
    """
    n  = len(signals)
    uf = _UnionFind(n)

    for i in range(n):
        for j in range(i + 1, n):
            if _signals_overlap(signals[i], signals[j]):
                uf.union(i, j)

    # Collect groups
    groups: Dict[int, List[Signal]] = {}
    for i, sig in enumerate(signals):
        root = uf.find(i)
        groups.setdefault(root, []).append(sig)

    return list(groups.values())


# -- Main entry point ----------------------------------------------------------

def merge(signals: List[Signal]) -> List[Signal]:
    """Deduplicate and aggregate a list of Signals.

    Steps:
    1. Group Signals by (hostname, process_key) - coarse grouping
    2. Within each coarse group, sub-group by shared evidence_event_ids
       using union-find (handles transitive overlaps)
    3. Merge each sub-group into one Signal
    4. Return the merged list

    Signals with no duplicates pass through unchanged (same object).

    Args:
        signals: Raw signals from all detection modules.

    Returns:
        Deduplicated and aggregated signals. len(result) <= len(signals).
    """
    if not signals:
        return []

    # Step 1: coarse grouping by (host, process_key)
    coarse: Dict[_GroupKey, List[Signal]] = {}
    for sig in signals:
        key = _group_key(sig)
        coarse.setdefault(key, []).append(sig)

    result: List[Signal] = []

    for key, group in coarse.items():
        if len(group) == 1:
            # No possible duplicates in this coarse group
            result.append(group[0])
            continue

        # Step 2: fine grouping by shared event IDs within the coarse group
        fine_groups = _group_by_overlap(group)

        # Step 3: merge each fine group
        for fine_group in fine_groups:
            try:
                result.append(_merge_group(fine_group))
            except Exception as exc:
                print(
                    f"[deduplicator] ERROR merging group ({key}): {exc}",
                    file=sys.stderr,
                )
                # Safety: return originals on merge failure
                result.extend(fine_group)

    return result


# -- Statistics helper (optional, used by engine for logging) ------------------

def stats(before: int, after: int) -> str:
    """Return a human-readable deduplication summary string."""
    if before == 0:
        return "deduplicator: 0 signals in"
    removed = before - after
    pct     = 100.0 * removed / before
    return (
        f"deduplicator: {before} -> {after} signals "
        f"({removed} merged, {pct:.0f}% reduction)"
    )

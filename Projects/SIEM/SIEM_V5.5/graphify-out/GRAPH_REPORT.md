# Graph Report - .  (2026-05-29)

## Corpus Check
- Corpus is ~20,193 words - fits in a single context window. You may not need a graph.

## Summary
- 257 nodes · 581 edges · 15 communities (14 shown, 1 thin omitted)
- Extraction: 73% EXTRACTED · 27% INFERRED · 0% AMBIGUOUS · INFERRED: 154 edges (avg confidence: 0.59)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]

## God Nodes (most connected - your core abstractions)
1. `Signal` - 36 edges
2. `CanonicalEvent` - 34 edges
3. `HostRef` - 26 edges
4. `normalize()` - 18 edges
5. `run()` - 12 edges
6. `detect_ransomware()` - 12 edges
7. `str` - 11 edges
8. `parse_line()` - 11 edges
9. `UserRef` - 10 edges
10. `ProcessRef` - 10 edges

## Surprising Connections (you probably didn't know these)
- `_sig()` --calls--> `HostRef`  [INFERRED]
  src/detect/test_deduplicator.py → src/core/schemas.py
- `_auth()` --calls--> `HostRef`  [INFERRED]
  tests/test_linux_v5.py → src/core/schemas.py
- `_ev()` --calls--> `HostRef`  [INFERRED]
  tests/test_linux_v5.py → src/core/schemas.py
- `_fev()` --calls--> `HostRef`  [INFERRED]
  tests/test_linux_v5.py → src/core/schemas.py
- `_auth()` --calls--> `UserRef`  [INFERRED]
  tests/test_linux_v5.py → src/core/schemas.py

## Communities (15 total, 1 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.00
Nodes (36): process_key(), Best-effort process key for V1.      Limitation: PID recycling exists. V2 should, Generate a stable event_id from raw content.      Invariant: same raw input -> s, stable_event_id(), CanonicalEvent, _get_field(), _is_linux_event(), _make_signal_id() (+28 more)

### Community 1 - "Community 1"
Cohesion: 0.00
Nodes (28): FileRef, HostRef, NetworkRef, ProcessRef, UserRef, parse_to_utc(), Parse an ISO8601 timestamp to timezone-aware UTC datetime.      Security invaria, utcnow() (+20 more)

### Community 2 - "Community 2"
Cohesion: 0.00
Nodes (24): _aggregate_score(), _event_ids_set(), _group_by_overlap(), _group_key(), merge(), _merge_group(), deduplicator.py — Signal deduplication and score aggregation (v5.5).  Problem:, Merge a list of duplicate Signals into one consolidated Signal.      Merging str (+16 more)

### Community 3 - "Community 3"
Cohesion: 0.00
Nodes (23): detect_ransomware(), extract_extension(), is_private_ip(), Compute the maximum number of UNIQUE files touched in any time window.      Corr, Heuristic ransomware detector (V4 core) operating on generic events dicts., _sliding_burst_unique_files(), _enc_tools(), _is_abnormal() (+15 more)

### Community 4 - "Community 4"
Cohesion: 0.00
Nodes (16): build_tree(), ProcessNode, ProcessTree, process_tree.py — Build and query process ancestry from normalized events.  Secu, Populate the tree from a sorted list of CanonicalEvents.          Must be called, Return direct child image basenames for a given parent., Return ancestor chain for the process in this event (root first).          Cycle, Return True if (parent, child) is a known suspicious spawn pair. (+8 more)

### Community 5 - "Community 5"
Cohesion: 0.00
Nodes (18): Alert, Signal, correlate(), Create Alerts from Signals.      V1 correlation policy:     - one alert per rans, _severity_from_score(), main(), export(), write_jsonl() (+10 more)

### Community 6 - "Community 6"
Cohesion: 0.00
Nodes (20): _basename(), _cl(), _image(), _make_signal(), lotl_sigma.py — Living-off-the-Land (LOTL) detection module.  Security invariant, Pattern-match CommandLine for each LOTL rule., Detect scheduled task events by EventID (4698/4699/4702)., Detect suspicious parent→child spawn pairs using the process tree. (+12 more)

### Community 7 - "Community 7"
Cohesion: 0.00
Nodes (19): _decode_priority(), _flatten_windows_json(), _guess_event_type(), _normalise_ts(), _parse_cef(), _parse_cef_extensions(), _parse_json(), parse_line() (+11 more)

### Community 8 - "Community 8"
Cohesion: 0.00
Nodes (10): _cl(), _execve_patterns(), _is_auditd(), _make(), _raw_args(), _sensitive_file(), _setuid_chmod(), _sig_id() (+2 more)

### Community 9 - "Community 9"
Cohesion: 0.00
Nodes (8): _brute_force(), _is_auth(), _make(), _msg(), _root_login(), _sig_id(), _ssh_key_added(), _sudo_escalation()

### Community 10 - "Community 10"
Cohesion: 0.00
Nodes (7): engine.py — Detection engine orchestrator (v5.5 — dual OS + deduplication).  Thr, Run all detection layers, deduplicate, and return consolidated signals.      Pip, run_all(), _run_linux(), _run_windows(), CanonicalEvent, Signal

### Community 11 - "Community 11"
Cohesion: 0.00
Nodes (6): replay.py — Ingest layer entry point.  Supports three input formats (--format fl, _read_auto(), _read_jsonl(), _read_syslog(), Any, str

## Knowledge Gaps
- **6 isolated node(s):** `Any`, `int`, `str`, `bool`, `float` (+1 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.
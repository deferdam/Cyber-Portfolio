# AI context prompt | Mini SIEM/SOAR

Paste this into an AI assistant so it gains full context on the project before
helping. It is not part of the HTML site and is not served anywhere. Keep it
updated as the project advances.

---

You are assisting on a personal cybersecurity portfolio project: a Mini SIEM/SOAR
system. Read this context fully before answering.

## What it is
A defensive, educational Sigma-based detection and SOAR ticketing system, written
in Python (standard library plus Flask) with an embedded single-page web UI. Scope
is defensive and educational, authored by Damien Defer ("SME Security Hardening").
It is meant for a GitHub portfolio and a personal website, with one card per version.

## Author and working style
Damien is an Epitech Paris student (promo 2027) on exchange at Keimyung University,
Daegu. He works on Windows. He wants ruthless, precise mentoring in French, with
verifiable claims and sources, no flattery. For any code or security task the order
is: plan and security invariants, then pseudocode, then a test checklist, then the
code. Conventions in docs and READMEs: pipe characters instead of dashes, "->" instead
of arrows, no em dashes, ASCII only in the embedded frontend.

## Architecture (one-direction pipeline)
raw source -> reader (src/ingest) -> normalizer (raw dict to Event) -> detection
engine (OS-gated Sigma plus heuristics, dedup, process-context attach) -> correlator
(signals to alerts) -> reporter (writes to out/) -> SOAR orchestrator (signal to
playbook to Ticket) -> web UI.

Key modules: src/ingest/replay.py (holds _READERS), src/normalize/normalizer.py (owns
event_type and field mapping), src/normalize/process_tree.py (tree by host and pid),
src/detect/engine.py (run_all; attaches process_ancestors, process_children,
process_self after merge), src/detect/modules/* (per family), src/soar/ticket.py and
src/soar/orchestrator.py (tickets start at status open), src/server/app.py (Flask),
src/server/frontend.py (the whole SPA as one ASCII HTML string).

## Data model
Event: event_id, event_time_utc, event_type (process, file, auth, ...), host.hostname,
process (ProcessRef: name, pid, ppid, image_path, command_line), raw.
Signal: frozen dataclass; signal_type, score, severity, mitre_technique, explanation,
recommended_actions, evidence_event_ids, process_ancestors, process_children,
process_self. Enrich with dataclasses.replace, never assignment.
Ticket: not frozen; from_signal; adds status, assignee, notes, disposition (analyst
verdict feeding future auto-triage), and the process context fields.

## Hard-won lessons (do not regress these)
- Scoring: max(scores) + 0.05 * (n_sources - 1), capped at 1.0. Corroboration raises
  confidence; averaging would wrongly lower it.
- Sigma matching is literal substring, not regex. Use "| bash", not wildcard patterns.
- The process tree stays empty in two distinct ways: a record not typed "process"
  (sysmon-like input defaults missing event_type to "file"), or a process record whose
  binary name is not extracted (auditd EXECVE keeps it in a0), so build_tree drops the
  node on "if not image: continue". A reader must set event_type and provide an image.
- TicketStore appends; delete tickets.jsonl before regenerating sample data.
- Frontend must stay ASCII; the box-drawing char U+2500 keeps sneaking into comment
  separators. Clickable UI uses data- attributes plus one handler, not nested-quote
  inline calls. The modal closes only if a click both starts and ends on the backdrop.

## Current state (v9 in progress)
v8 is complete: full UI refactor with Open and My Tickets tabs, take-a-ticket workflow,
verdict/disposition dropdown, note hot-save drafts in localStorage, a Templates tab with
per-status editable templates and variable substitution plus an Insert template and Clear
button, auto-growing note textarea, two dashboard zones (Open queue and My tickets) with
clickable severity and type chips, and an active process tree showing a bash reverse-shell
chain (pid 7000 with children dirtycow, useradd, python3, chisel). 244 tests pass.

v9 workspace (SIEM_V9), feature-complete. SIX ingestion readers: auditd (native audit.log, merges SYSCALL+EXECVE+PATH by audit id), Snort/Elastic/CSV in stdlib, and EVTX (python-evtx) / PCAP (dpkt) for binary formats, all registered, enabled in the Run dropdown, and tested (suite 313 passing). Snort and PCAP are pre/heuristic-detected via imported modules; CSV, Elastic and auditd process events flow through existing detection and build the tree. THREE app modes via SIEM_MODE: local (out/large, real data), server (v11+, not implemented), and SHOWCASE, a sealed demo reading a separate out/showcase sandbox of fake data covering every log type, with file access, the run pipeline and the profile disabled. Streaming runs ONLY in showcase and auto-starts with it: a daemon thread reveals the baked tickets progressively (replay, not re-detection, so OS-independent). launch.py is a universal launcher: no argument opens a clickable web UI to pick the mode, with single-instance lifecycle (it STOPS the running app before starting another, fixing stale-data-on-mode-switch) and a Stop button. Scripts are split under scripts/sh, scripts/bat, scripts/ps1. EVTX and PCAP are LOCAL ONLY. App binds 127.0.0.1 by default. v9 done: parsing, refactor, comment cleanup (unused imports removed via pyflakes). Roadmap re-phased: v10 = server skeleton + security foundations (secure backbone, no live users yet), v11 = real multi-user (accounts, roles, admin panel/four-eyes, mail OAuth, active response), v12 = AI and AI security (ML auto-triage from false-positive closures + analyst notes, anti-poisoning, prompt-injection safety). dpkt and python-evtx are in requirements.txt.

## Roadmap ahead
v10: multi-user/server mode with accounts, roles, server-side ticket scoping; an admin
panel with two admins max and four-eyes approval for sensitive actions; ML auto-triage
trained on dispositions with anti-poisoning measures; read-only posture; full security
hardening (auth, encryption at rest and in transit, no privilege/mode spoofing, no
injection, AI input treated as untrusted text). v11: active response (ban IPs, set files
read-only to quarantine ransomware), responsive mobile, i18n. Far future and exploratory:
a webhook bridge to a companion app toward Ghidra for reverse engineering.

When you help, respect the planning order, keep claims verifiable, prefer the smallest
correct change, and never regress the lessons above.

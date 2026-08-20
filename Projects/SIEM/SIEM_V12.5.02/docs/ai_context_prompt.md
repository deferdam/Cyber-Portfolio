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

v10 workspace (SIEM_V10), forked from the completed v9. Carries the six ingestion readers (auditd/Snort/Elastic/CSV/EVTX/PCAP), three+ SIEM_MODE values, the sealed showcase with auto-streaming (now 5s reveal cadence), and the universal launcher. NEW in v10.0: a full-stop control everywhere (POST /api/shutdown kills the app via SIGINT, with a Shut down button in the drawer in every mode; the launcher has a Quit-everything button that stops app + launcher). FIRST v10 SERVER-SKELETON STONE: server mode (SIEM_MODE=server) is now a runnable, locked-down skeleton, loopback only, no auth yet (auth is v11), read-only host posture (READONLY_HOST), a red SERVER banner; mode is a trusted env-only signal (IS_SERVER), not client input; _safe_bind_host() is a fail-safe that REFUSES any non-loopback bind unless SIEM_ALLOW_PUBLIC=1 is set explicitly (tested). Launcher Server button enabled. Version shown in the drawer via VERSION const (now v10.0), removed from the title; bump it one notch every new zip. Test suite 332 passing. v10.1 adds ENCRYPTION AT REST: core/vault.py (Fernet, AES+HMAC), opt-in SIEM_ENCRYPT=1 with key from SIEM_KEYFILE (USB-key model) or SIEM_KEY (passphrase+scrypt); fail-safe (refuses encrypted with no key), fails closed on wrong key, backward compatible (plaintext when off). All ticket/signal/event/alert writers (app, TicketStore, reporter) route through vault.pack_line/unpack_line; /api/config exposes an 'encrypted' flag shown in the drawer. cryptography in requirements.txt. Full-stop control (/api/shutdown + drawer button + launcher Quit) in all modes. v10.2 adds INJECTION DEFENSE: stored XSS neutralized by a central esc() that escapes every log-derived field before the DOM (process trees/command lines, explanations, hosts, file names, notes, etc.); ticket PATCH validates server-side (status/disposition whitelists, length caps, unknown fields dropped); run pipeline is argv-list (no shell), whitelisted format, SCAN_ROOT-confined in server mode. AUTH SEAM PREPARED for v11: core/auth.py (Principal, current_principal, require_auth/require_role) + before_request hook + /api/whoami; v10 enforces nothing (single local operator). v11 MFA design recorded: password hash + TOTP and FIDO2/WebAuthn (YubiKey 5C), WebAuthn needs HTTPS so it rides the v11 TLS transport. Secret scan of the repo came back clean (no keys/credentials, only env-read code and fake test fixtures). Test suite 347 passing. v10.3 CLOSES the v10 roadmap: read-only host posture (READONLY_HOST, no active response, writes confined to OUT_DIR), anti-C2 (no outbound calls/SSRF in handlers; CSP connect-src 'self' blocks browser exfil; loopback default), endpoint-exposure hardening (security headers CSP/nosniff/X-Frame-Options DENY/Referrer-Policy/Permissions-Policy on every response; errors don't leak server paths in server mode), credential hygiene (secrets env-only, never echoed), and the AI-input-safety foundation (core/untrusted.py: ingested text is DATA, size-capped for_model()). All v10 security foundations DONE and tested EXCEPT encryption in transit (TLS), deferred to v11 (rides the server transport). Test suite 365 passing. v10 is complete; next is v11: real accounts, sessions, auth enforcement at the prepared seam, MFA (TOTP + FIDO2/WebAuthn YubiKey), admin panel/four-eyes, TLS, active response, idle lock. Roadmap: v10 = server skeleton + security foundations (STARTED), v11 = real multi-user (accounts, roles, admin/four-eyes, mail OAuth, active response, idle-session lock), v12 = AI + AI security. dpkt and python-evtx are in requirements.txt.

## Roadmap ahead
v10: multi-user/server mode with accounts, roles, server-side ticket scoping; an admin
panel with two admins max and four-eyes approval for sensitive actions; ML auto-triage
trained on dispositions with anti-poisoning measures; read-only posture; full security
hardening (auth, encryption at rest and in transit, no privilege/mode spoofing, no
injection, AI input treated as untrusted text). v11: active response (ban IPs, set files
read-only to quarantine ransomware), responsive mobile, i18n. Far future and exploratory:
a webhook bridge to a companion app toward Ghidra for reverse engineering.

VERSIONING CONVENTION. The VERSION const in src/server/frontend.py is shown in the left
drawer (not the title) and bumped on every shipped zip.

Before (v8 to v11): a flat vMAJOR.NNN build counter (v11.000 ... v11.013). NNN just counted
builds, so from the number alone you could not tell WHICH module a build touched, nor tell a
module's maintenance fix apart from a whole new module.

Now (from v12): vMAJOR.MINOR.PATCH, which maps to version / module / update.
  * MAJOR = the version/epoch (v12 = AI).
  * MINOR = the module (a sub-part inside the epoch). v12.1 = AI admin panel,
    v12.2 = AI ticket container.
  * PATCH = a two-digit update of THAT module. Module baseline ships as .00 (v12.1.00), its
    first bugfix is v12.1.01, its second v12.1.02.
  * The major-version work folder follows MAJOR: SIEM_V8 ... SIEM_V11, then SIEM_V12.

Why the change is worth it: the number now tells you at a glance which module a change belongs
to, lets a bugfix on a module (v12.1.01) be read apart from a new module (v12.2.00), and gives
a clean per-module changelog. It is simply easier to navigate between modules and to see where
in the project any given fix lives. First v12 build is v12.0.00.

AI IMPORT FORMAT POLICY (what the app accepts or refuses when a user imports a model or
dataset). Two responsibilities are kept separate. STRUCTURAL safety is ours and is NOT
disclaimable: we hard-refuse formats that execute code at load. SEMANTIC quality (is the
model good or poisoned?) is the user's risk, disclaimed, and handled by human review plus a
behavioral quarantine (shadow-run against our own validated ground truth before any authority
is granted). Accepted, data-only: .safetensors, .gguf, and our own .json classifier params.
Refused (pickle family / can execute or carry pickled code): .pkl .pickle .pt .pth .ckpt
.bin .joblib .dill .npz .h5 .pb .model (.npz is refused because numpy.load with allow_pickle
can run pickled code). Enforced in core/model_import.py (extension allowlist, default-deny);
deeper header validation and the shadow quarantine come with the import feature in v12.3.

When you help, respect the planning order, keep claims verifiable, prefer the smallest
correct change, and never regress the lessons above.

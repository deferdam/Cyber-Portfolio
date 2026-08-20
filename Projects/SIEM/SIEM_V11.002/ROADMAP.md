# Mini SOAR | Roadmap

## v8 (current) | UI tranche A + local/server seam + process context
* Top horizontal section nav | Dashboard, Tickets, Signals, Run
* Animated semi transparent left drawer | profile (name, email, avatar in localStorage), theme toggle, contacts
* Dark theme (locked) + light theme (Kibana style), saved in localStorage
* Animated ticket open/close, signals explanation accordion
* Palette | black/dark grey chrome, green accents, red buttons
  * Severity ramp | CRITICAL red -> HIGH orange -> MEDIUM yellow -> LOW green -> INFO grey
  * Category colors by source domain | windows, linux, ai, mail, web, server
* Click a type, MITRE code, or severity -> filtered Tickets view
* Browser back button works (History API), closed tickets dimmed
* Closed-ticket signals hidden in the Signals view
* File hash click -> copy only. Signal ID click -> copy (search it in Tickets)
* File browser (/api/browse) | free in local mode, confined in server mode
* /api/run-stream | --out-dir + whitelisted format
* MODE seam | SIEM_MODE=local|server fixed at launch (run_local.bat | run_server.bat)
* Process context | each signal now carries process_ancestors and process_children
  (enriched: image, pid, ppid, command_line, event_id, host). Attached post-merge
  from the ProcessTree. Front display of this data is the next front task.

## v9 | multi format ingestion
* pcap/Wireshark, evtx, auditd, elastic/ECS, snort, csv (dropdown stubs already present)
* live local log capture agent

### v9 | DECISION: file analysis is a LOCAL-ONLY capability
* The "analyze a specific file" feature (file browser + run-on-file) is available
  only in the non-connected local build. Rationale: online, an analyst does not
  parse a Wireshark or Snort file through the web app; those artifacts live on the
  analyst workstation. A regular user would neither have nor be able to produce
  them. Confining file analysis to local removes path-traversal and binary-parser
  attack surface from the server.
* PCAP and EVTX are the most security-sensitive (third-party binary parsers).
  They are LOCAL ONLY, never exposed in multi / server mode.
* v10 note: in server mode the file-analysis UI (browser, run-on-file, pcap/evtx)
  is hidden entirely. Server ingestion comes from controlled feeds, not analyst
  file uploads.
* Format availability matrix lives in docs/USAGE.md and must stay in sync.
* Supply chain: more libraries (dpkt, python-evtx) raise CVE exposure. Pin
  versions, keep an SBOM, run a recurring tech-watch (veille). Local-only
  confinement of the risky parsers is itself a mitigation.

## v10 | server skeleton + security foundations
Goal: stand up the server SKELETON first, so every security control is designed and put
in place BEFORE any real user connects. No live multi-user yet; v10 is the secured backbone.
STARTED (v10.0) then COMPLETE (v10.3): all security foundations are in place and tested,
EXCEPT encryption in transit (TLS), deferred to v11 because it rides the server transport.
Server mode is a runnable, locked-down skeleton (loopback only, no auth yet, read-only host
posture, banner); mode is a trusted env-only signal (IS_SERVER); a fail-safe bind refuses any
public interface unless SIEM_ALLOW_PUBLIC=1 is explicitly set; a full-stop control
(/api/shutdown + launcher Quit) stops the app/launcher cleanly.
* Server seam | establish the server process and make the local-vs-server boundary a
  trusted, non-spoofable signal, never a client-controllable input. Prevent a "privilege
  glitch" where a server-side process is tricked into believing it is local. [seam + mode
  integrity STARTED; harden further]
* Read-only posture | the app may only READ. No mutation of the host. DONE (v10.3): READONLY_HOST invariant; no host-mutating/active-response code in v10 (deferred to v11); writes confined to OUT_DIR; verified by test.
* Credential theft | never store, log, or expose credentials in readable form; no secrets
  in tickets, notes, or logs. DONE (v10.3): repo secret-scanned clean; key material read from
  env only; /api/whoami and /api/config never echo secrets; verified by test.
* Anti-C2 | given its accesses, the app must not be usable as a covert channel; no
  command/data exfiltration paths. DONE (v10.3): no request handler makes outbound network
  calls (no SSRF surface); CSP connect-src 'self' blocks browser-side exfiltration to any
  external origin; loopback-only by default. Verified by test.
* Injection | no command, SQL, path, or template injection anywhere input flows.
  DONE (v10.2): stored XSS neutralized by escaping every log-derived field before it enters
  the DOM (central esc()); ticket PATCH validates fields server-side (status/disposition
  whitelists, length caps, unknown fields ignored); the run pipeline uses argv lists (no
  shell), a whitelisted format, and a path confined to SCAN_ROOT in server mode.
* Encryption at rest and in transit | tickets stored or sent to a server are encrypted so
  files are unreadable to anyone with raw disk access. Key custody to evaluate: physical
  USB key or a VeraCrypt-style container. Tension: security vs fast operator access.
  AT REST DONE (v10.1): core/vault.py uses Fernet (AES-CBC + HMAC, authenticated); opt-in via
  SIEM_ENCRYPT=1 with a key from SIEM_KEYFILE (USB-key model) or SIEM_KEY (passphrase + scrypt,
  salt beside data). Fail-safe (refuses to run encrypted with no key), fails closed on wrong
  key/tamper, backward compatible (plaintext when off; legacy lines still readable). All
  ticket/signal/event/alert writers route through the vault. IN TRANSIT: pending (needs the
  server transport, v11) | TLS for the server endpoint.
* Endpoint exposure foundations | sensitive routes not named literally (obscurity is a
  SECONDARY layer only); the PRIMARY control is server-side authn + authz, prepared here.
  DONE (v10.3): security headers on every response (CSP, nosniff, X-Frame-Options DENY,
  Referrer-Policy, Permissions-Policy); error messages no longer leak server paths/stack
  traces in server mode; primary control is the prepared auth seam. Verified by test.
* AI input safety foundation | external text is UNTRUSTED; the boundary is laid now and
  fully exploited in v12. DONE (v10.3): core/untrusted.py marks ingested text as DATA (never
  instructions), with a size cap and a for_model() path that v12 must place in a delimited
  untrusted section. Foundation only; the model itself is v12.

## v11 | multi user (people connected)
Goal: real users connect and collaborate, on top of the v10 secured skeleton.

v11.000 DONE | account foundation and bootstrap. SQLite store (stdlib) at data/accounts.db,
0600 perms; argon2id hashing (argon2-cffi) with explicit params; real password-entropy
gate (zxcvbn-inspired, stdlib only). CLI create-admin (permanent, network-free) and CLI
reset-admin-password (strong typed-confirmation now; YubiKey gate added in a later v11
increment). Hardened web bootstrap: /setup with a one-time secrets token shown only on
terminal stdout, loopback-only, constant-time compare, single-use, ~15 min TTL, 404 once
sealed. PERSISTENT DUAL SEAL (SQLite system flag + 0600 marker file, fail-closed) so
emptying the accounts table cannot reopen bootstrap. Master invariant enforced: once an
admin exists or the seal is set, no path creates a second admin. 45 new tests, all green.
v11.001 DONE | real login and server-side sessions. POST /api/login verifies argon2id and
opens a server session; POST /api/logout revokes it. Sessions live in SQLite, token stored
as SHA-256 (never clear), so reading the table cannot replay a session; cookie is httpOnly +
SameSite=Strict (Secure once TLS lands). Absolute session lifetime configurable via
SIEM_SESSION_TTL, default 8h, floor 60s. Revocable: revoke_session and revoke_all_sessions
(forced disconnect, basis for admin panel + post-breach logout). Anti-enumeration: generic
failure message whether or not the user exists. Brute-force throttle: 5 fails / 15 min per
account -> 429. Auth seam filled: require_auth (server mode denies anonymous), require_role
(operator < manager < admin). Login mandatory in server mode; in local mode OFF unless
SIEM_REQUIRE_LOGIN=1. Frontend login screen + sign-out control. 32 new tests, all green.
v11.002 DONE | TOTP second factor and idle session lock. TOTP is RFC 6238, stdlib only
(hmac/hashlib), proven correct against the official RFC 6238 test vectors (SHA1/256/512).
Enrollment is two-step: a pending secret is generated, the user must confirm a valid code
before it is enabled (so they cannot lock themselves out with an unsynced app). Login
becomes two-step when TOTP is enabled: password first (mfa_required), then the 6-digit code;
the failed-login counter is not cleared until full success, so brute force stays throttled.
QR is rendered client-side (compact public-domain encoder, zero Python dependency) with the
base32 secret shown as a manual-entry fallback; the server emits the otpauth:// URI.
Idle lock: sessions die after SIEM_IDLE_TIMEOUT inactivity (default 30 min, floor 60s),
independent of the absolute TTL; activity refreshes last_seen. Disabling TOTP requires a
valid current code. 33 new tests, all green.
NEXT in v11: FIDO2/WebAuthn (YubiKey), then admin panel with dual control, then active
response, then TLS. Recovery codes and the YubiKey-gated CLI reset ride with WebAuthn.
* accounts, authentication, roles and permissions. SEAM PREPARED (v10.2): core/auth.py is
  the single plug-in point (Principal, current_principal, require_auth/require_role) with a
  before_request hook and /api/whoami; v10 enforces nothing (single local operator), v11
  fills it in. Primary factor: password as a salted hash (argon2id/bcrypt), never in clear.
  MFA, two paths: TOTP (RFC 6238, any authenticator app, or the YubiKey via OATH-TOTP) and
  FIDO2/WebAuthn for hardware keys like the YubiKey 5C (strongest, phishing-resistant, can be
  passwordless). WebAuthn needs HTTPS + a fixed origin, so it rides on the v11 TLS transport.
  MFA optional at first, then enforced.
* BOOTSTRAP of the first admin (v11.000) | two paths. CLI (python launch.py create-admin)
  is the permanent, network-free path, reused in v13 when the browser is gone. Ephemeral web
  token (/setup route) is transitional convenience while the browser UI exists. Master
  invariant: once any admin exists, NO bootstrap path can create a second admin; verified
  server-side on every request. /setup hardening: 404 (not 403) once sealed so the route
  looks non-existent; PERSISTENT SEAL in both SQLite and a 600-perm file that must concur, so
  emptying the accounts table cannot reopen /setup; token via secrets.token_urlsafe(32),
  shown only on terminal stdout, never logged or filed; loopback-only; constant-time compare;
  single-use; short validity window (~15 min after start); /setup can ONLY create the first
  admin on a virgin base, never mutate an existing role.
* PASSWORD recovery | the recovery paradox: every recovery path also helps an attacker, so
  it must be gated by a second independent factor. CLI password reset is gated by a YubiKey
  validation (FIDO2): machine access alone is NOT enough, the physical key is also required,
  so a compromised host cannot reset the password without the key in hand. Always provide at
  least two independent recovery routes (CLI+key, recovery codes, backup key) so losing one
  element never locks the admin out permanently.
* RECOVERY CODES (later v11 increment) | one-time codes generated at MFA enrolment, for the
  case where the admin is not at the machine. Stored offline by the user.
* YUBIKEY management (later v11 increment) | enrol at least TWO keys (primary + backup kept
  elsewhere); this is a requirement, not a convenience, since a single key can be lost or
  broken. In account settings: add, remove, name keys ("office key", "vault key"), designate
  primary vs backup, switch between them. Removing a key is sensitive: block or strongly warn
  on removing the last key; ideally require validation by another still-valid key to remove
  one, so a temporary intruder cannot strip the legitimate keys.
* ticket transfer between operators (assignee field already exists); Kanban board;
  Contacts directory with privilege levels
* Gmail / Outlook OAuth (read only). Mail is professional-only, never personal, even when
  both are connected. A central system aggregating all mailboxes is a large surface; verify
  end-to-end encryption before considering it.
* template editing restricted to roles (manager / CISO)
* ADMIN PANEL and access control | admin tab to create/manage users and view everyone's
  roles and accesses. Two admins maximum. Four-eyes / dual control: sensitive actions
  (create user/admin, change role) need approval by the SECOND admin; approver differs from
  requester (server-enforced); every request and decision audit-logged. RISK: two-admins-max
  is a single point of failure; needs a break-glass path, and dual control only on actions
  that truly need it.
* gate hardening | prefer per-user MFA (TOTP) over a static shared admin code; any static
  code is defense in depth on top of real auth, never instead of it.
* idle session lock | after ~30 min with no key/activity, re-prompt for the password, so an
  unattended open session cannot expose server data or the admin panel to someone without
  access. Belongs here because it needs the auth system to have a password to re-prompt
  against; meaningless before v11.
* ACTIVE RESPONSE (was read-only before) | from the app, ban IPs; change file permissions,
  e.g. read+write -> read-only, notably to quarantine ransomware.
* responsive mobile layout; English / French i18n.

## v12 | AI and AI security
Goal: ML auto-triage, and the security of the AI itself.
* ML auto-triage (false-positive learning) | the model learns from tickets closed as
  false-positive (and the converse) and from analyst notes. Especially valuable for mail
  triage: spam and phishing.
* Confidentiality | model artifact and training data behind admin auth; the model can
  memorize sensitive ticket content, so protect it.
* Anti-poisoning (the hard one) | no auto-retrain on raw labels. Track label provenance per
  user, rate-limit one user's influence, review training data, monitor label drift, keep a
  human in the loop.
* Anti-saturation | rate-limit inference, cap input size.
* AI input safety | mails and ticket content fed to any model are UNTRUSTED. Never
  interpreted or executed. Separate instructions from data in the prompt, validate input,
  filter output. Parsing alone does not stop prompt injection.
* Access | the model and its data are reachable only via an admin-gated, non-literal route.

## Far future (exploratory, not committed)
* "super tool" | fingerprint/hash analysis; possible Ghidra association for reverse
  engineering. Feasibility unknown; explicitly out of scope for now.
* Webhook bridge | the app emits webhooks to a separate companion app; that companion is
  the integration point toward Ghidra and heavier offline analysis. Keeps the SIEM core lean
  and isolates the reverse-engineering surface. Paired with the companion app, later.

## Showcase | DONE in v9
* Implemented as a third SIEM_MODE (showcase), distinct from local and server: a sealed
  sandbox reading out/showcase, fake data only covering every log type, with file access,
  the run pipeline and the profile disabled. Streaming auto-starts with it (progressive
  reveal of the baked tickets, OS-independent). Future: host it read-only as the public
  portfolio demo.

## Open items
* powershell_sigma.py lines 438-440 | three French advisory strings keep accents.
  Decide: keep, strip to ASCII, or translate to English.
* clipboard copy needs a secure context | works on http://localhost, blocked on plain
  http:// over a network IP. Relevant when v10 server mode is served on a LAN.
* current bash sample data has no pid/ppid linkage, so ancestry shows empty there;
  a sysmon-like dataset with real process events populates it.

## v13 | desktop app (PySide6), two modes

Migrate the UI from a browser SPA to an installable desktop application built in
PySide6 (Qt). Not Electron (Chromium + Node would add web vulnerabilities plus a
native code-execution vector, a worse surface than Flask in loopback). The backend
Python pipeline (detection, SOAR, vault, accounts) stays the single source of truth;
Qt is only a presentation layer that calls the same internal API. The Flask web UI is
kept as a lightweight headless/remote fallback, NOT duplicated logic.

Two modes, five variants total:

SIEM mode (3 variants, no network surface, local analysis only):
* SIEM Local | host telemetry: auditd, EVTX, syslog, process trees, auth events.
  Sys admin and endpoint audit workflows.
* SIEM Network | network telemetry: PCAP, Snort alerts, flow analysis, lateral
  movement. Network analyst workflows.
* SIEM Multi | both telemetry types combined on one machine, multi-source
  correlation. Single-workstation, still no network surface.

SOAR mode (2 variants):
* SOAR Local | ticketing on a single machine, no network. The current SOAR workflow
  migrates here as the default.
* SOAR Multi | the ONLY mode that activates the network. Central collector that
  aggregates signals from remote agents. This is where TLS, mutual agent-collector
  authentication, agent identity verification, anti-spoofing of forged signals, and
  connection-loss handling all live. Confined here so that no other mode has any
  inbound network surface: an operator who never runs SOAR Multi has zero network
  exposure.

Communication: Qt talks to the backend via local Unix socket or in-process IPC, never
HTTP, so no TCP port is opened except in SOAR Multi.

Implementation order: SIEM Local first (least new surface, reuses the existing
pipeline directly), then SIEM Network, then SIEM Multi, then SOAR Local. SOAR Multi
(the agent-collector protocol) is the heaviest and riskiest piece; sequence it last in
v13 or split it into its own version (v15), only after the local modes are stable. Do
NOT couple it to the first Qt migration.

## v14 | full dashboard and app customization
Snort-style configurability across the SIEM/SOAR apps. The operator chooses which
widgets appear, their layout, and their data scope; layouts are saved per user. The
dashboard becomes fully composable rather than fixed. Builds on the view-scope toggle
introduced in v10.5 (general vs my tickets) and generalizes it to every panel.

## v14 | compliance evidence (short term) and software certification (long term)

Two distinct goals, deliberately separated so the ambition stays honest.

Short term, achievable and portfolio-relevant | the SIEM produces the artifacts an
auditor asks for, so an organization can use them as evidence during its own audit.
The SIEM does NOT itself hold a certification here; it supplies proof. Concretely:
log-retention reports, timestamped access journals, incident export with how each was
handled, and a mapping of detections onto a chosen framework's controls. This
demonstrates understanding of what an audit requires, which is exactly the skill a PME
hardening or SOC role looks for.

Target frameworks (not yet fixed; pick when the module is designed):
* ISO/IEC 27001 | logging and monitoring controls (A.8.15, A.8.16 in the 2022
  revision), incident management, access control. Closest to the ISO 27001 context of
  the TVH Consulting / Fidens leads.
* NIS2 (EU directive, transposed into French law) | detection, logging, and incident
  notification within 24/72 hours. Relevant to French PMEs in regulated sectors.
* RGPD | access traceability to personal data and breach detection, with the 72-hour
  CNIL notification obligation.
* SOC 2 (US), PCI-DSS (if card payments) | secondary, for international or
  payment-handling clients.
The useful split is not "French vs American" but "which framework for which client".

Long term, exploratory and NOT committed | having the software itself evaluated by an
accredited body. French side: ANSSI qualification (security visa, or PDIS qualification
for incident detection providers). US side: FedRAMP or Common Criteria. Stated plainly:
this is out of reach for a solo portfolio project. It costs tens to hundreds of
thousands of euros, takes one to two years, and requires a legal entity, on-site
audits, and code submitted for evaluation. Listed here only to mark awareness of the
distinction between producing compliance evidence and certifying a product. Do not
present this as a near-term deliverable.

## Deferred ingestion-cadence rules (target v11/v12)
* Email refresh cadence | local poste pulls only the current week's updates on refresh
  to avoid re-analyzing already-triaged mail (weekly analysis). The server (Multi mode)
  runs daily analysis. Belongs with the email_poller temporal dedup work, not UI.
* Machine/person traceability | enrich each ticket so the host maps to a physical
  machine and its owner, to go inspect the affected computer and identify the person
  directly; same for phishing mail. Depends on the v11 contact directory.

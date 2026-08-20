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
v11.003 DONE | FIDO2/WebAuthn (YubiKey). Uses python-fido2 (maintained by Yubico), the
one case in v11 where hand-rolling was rejected as too risky (CBOR/COSE/attestation have
real pitfalls), the mirror image of the TOTP decision. Private key never leaves the
authenticator; the server stores only a public key (AttestedCredentialData) and a
credential id, so a stolen accounts DB cannot be used to impersonate a key (unlike a
stolen TOTP shared secret). Signatures are bound to the origin, resisting phishing that
would fool a human copying a TOTP code. RP_ID is 127.0.0.1 to exactly match the origin
launch.py opens (WebAuthn requires an exact match when the origin host is an IP; using
"localhost" here would have silently broken every ceremony). WebAuthn is offered as an
ALTERNATIVE second factor alongside TOTP (user picks key or code at the mfa_required
step), not passwordless. Multi-key support: named keys, primary/backup designation,
deletion blocked on the last remaining factor unless TOTP is also enabled as a fallback.
Ceremony state (challenge, etc.) lives server-side only, in memory, keyed by a short-lived
ceremony id, never sent to or trusted from the client. QR/manual TOTP enrollment and key
enrollment share one MFA settings panel. 28 new tests (storage, multi-key management,
deletion guard, route error handling); the actual cryptographic register/authenticate
ceremony can only be exercised end-to-end with a real key in a real browser, not in this
environment, and should be verified that way before relying on it.
v11.004 DONE | admin panel with dual control (four-eyes). Mode is automatic, not manually
toggled: fewer than 2 admins runs in DEGRADED mode (sensitive actions apply immediately,
audited with a degraded flag); from the moment a second admin exists, dual control
activates on its own and every sensitive action becomes a pending request needing a
DIFFERENT admin's approval. SIEM_DUAL_CONTROL=0 can force degraded mode off for
debug/test only, itself a deliberate weakening. MASTER INVARIANT: an admin can never
approve their own request, enforced server-side in decide_request regardless of what the
UI allows (tested through the HTTP layer, not just the storage layer). Sensitive actions
covered: create account, change role, delete account, delete another user's WebAuthn key,
reset another user's password. Last-admin protections: cannot demote or delete the sole
remaining admin. Append-only audit log (no delete method exposed on purpose) records
every action, actor, and degraded/approved status. Admin panel UI: account list and
creation, pending-approval queue with approve/reject, audit trail view; hidden from the
nav for non-admins. AI training-data and system-prompt actions were explicitly NOT wired
into SENSITIVE_ACTIONS yet: that module does not exist (v12), and guessing its route
shape now would mean building against a fiction. They will be added, reusing this same
approval mechanism, once the AI module is real. 42 new tests (storage-level invariants
plus an HTTP-level test proving self-approval is rejected through the API, not just in
the function call).
v11.005 DONE | recovery codes and the WebAuthn-gated CLI password reset. Recovery codes:
10 one-time codes generated on demand, HASHED IMMEDIATELY on generation (no clear-text
retention beyond the local scope needed to display them once), so a process memory dump,
crash dump, swapped page, or attached debugger cannot recover them after the fact.
Single-use, regeneration invalidates all previous codes. CLI reset-admin-password now
gates on a NATIVE WebAuthn ceremony (USB security key over CTAP HID, no browser) when a
key is enrolled: machine access alone is no longer enough, the physical key must be
presented and touched. Falls back to the v11.000 typed-confirmation phrase when no key
is enrolled, so an admin who never set up WebAuthn is not locked out of recovery.
Correctness note: python-fido2's own default origin verifier only special-cases the exact
hostname 'localhost' for non-TLS http, NOT 127.0.0.1 (unlike browsers, which treat both as
secure contexts) - a real gap caught while building this, not assumed. A custom verifier
was written for this native, browser-free path specifically. 23 new tests cover the
storage layer and the branching logic (key path vs confirmation-phrase fallback vs no
device present); the actual cryptographic handshake with a physical key can only be
verified with real hardware in a real browser/OS, not in this environment, same honest
limitation as the v11.003 WebAuthn ceremony.
v11.006 DONE | TLS for the server transport. Self-signed certificates via the
`cryptography` library ALREADY required for vault.py (zero new dependency): RSA 2048,
SHA256 signature, SAN covering localhost/127.0.0.1/::1, 0600 permissions on both cert and
key, generated once and reused across restarts (so a browser's one-time trust exception
keeps working instead of re-prompting every start). Verified end to end in this
environment: a real server was started, curl connected over actual HTTPS and got 200 OK,
not just a syntax check. MANDATORY once exposed beyond loopback: SIEM_ALLOW_PUBLIC=1
combined with an explicit SIEM_TLS=0 refuses to start (exit code 2) rather than silently
serving plaintext credentials over a real network; verified by actually launching the
process and reading its exit code. Optional on loopback via SIEM_TLS=1, mainly so
WebAuthn/browser behavior can be exercised the same way it would over a real network.
Session cookies now carry Secure whenever the connection genuinely is HTTPS (TLS_ACTIVE
flag set at startup), plain otherwise; existing tests are unaffected since they import
the Flask app directly and never execute the __main__ startup block, so TLS_ACTIVE stays
False there as before. Trust model documented plainly in the module: self-signed means a
one-time browser warning, not third-party-verified identity; that distinction is not
hidden from the operator. 14 new tests, real certificates generated and parsed back, not
mocked.
v11.007 DONE | four UI elements, translated from 21st.dev prompts into plain HTML/CSS/JS
(no React/Tailwind/Framer Motion/Three.js: zero new frontend dependency, consistent with
the project's supply-chain policy). Nav became a dock-style icon bar with a hover tooltip
that tracks the hovered item (measured via getBoundingClientRect, no animation library),
four distinct button states (default/hover/active/selected). Login screen restyled with a
larger title, a CSS-only ambient gradient background (no WebGL/Three.js: decorative cost
was not justified for a security tool) and a slide-in transition between the
password/MFA steps; the actual auth flow is unchanged, only the presentation is new (the
prompt's email+magic-code flow was NOT ported, since it does not match this app's real
username+password+TOTP/WebAuthn flow). Footer added, reduced to what a purchased desktop
tool needs now: EULA and privacy-notice placeholders (explicitly marked as placeholder
legal text pending real review), with reserved slots for company contact, certifications,
documentation links, and a bug/suggestion/rating slot, added later once that content
exists. Weekly update checker (core/update_check.py): GitHub Releases API only, via
urllib (stdlib, zero new dependency), runs on its own Monday-17:00 schedule, NEVER
downloads or executes anything; no auto-download setting exists anywhere in the codebase,
by design, since a persisted toggle would itself be an attack surface. The footer shows a
link straight to the repo's Releases page when a newer version exists. 27 new tests for
the update checker (version parsing, comparison, fail-safe network handling, schedule
logic); the visual nav/login/footer changes are validated by node --check (syntax) only,
same honest limitation as every other frontend change this session: real rendering needs
a browser.
KNOWN UX TRADE-OFF, flagged not hidden: the nav is now icon-only by default (label shown
only on hover/selection), which trades away at-a-glance clarity for the requested dock
aesthetic. Worth revisiting if labels turn out to matter more than the visual style in
daily use.
v11.008 DONE | active response (IP bans, file quarantine). STRICT ALLOWLIST: exactly
two actions exist, ban/unban an IP and quarantine/restore a file; no arbitrary command
execution path exists anywhere in the module. INTERNAL vs REAL: internal-only mode
(default) never touches the OS, only this module's own list; REAL mode requires BOTH
real=True in the call AND the environment variable SIEM_ACTIVE_RESPONSE_REAL=1, which
cannot be flipped at runtime from inside the app, only by an operator restarting the
process with it set (same "no persisted toggle" reasoning as the update checker).
SELF-PROTECTION verified with real calls: banning 127.0.0.1/::1/localhost/0.0.0.0 or the
IP of the session making the request is refused unconditionally before anything else
runs. Bans carry a mandatory expiry (default 24h, SIEM_BAN_HOURS-configurable);
purge_expired_bans lifts them automatically; is_banned reflects expiry in real time even
before a purge runs. Quarantine is confined to OUT_DIR/DATA_DIR, verified by an actual
refused attempt against a path outside those roots. Real quarantine was verified
end-to-end with a real chmod: 0644 -> 0444 on quarantine, back to 0644 on restore, not
mocked. Windows firewall integration uses netsh advfirewall (named, greppable rules,
add and delete both implemented); this cannot be exercised on this non-Windows test host,
so that specific path is verified only by its clean refusal on non-Windows platforms, not
by an actual rule being added - confirm on a real Windows machine before relying on it.
Real actions (ban_ip_real, quarantine_file_real) are gated by the same automatic
degraded/dual-control mechanism as account actions (v11.004); internal-only actions are
NOT gated, since they cannot touch the OS and are trivially reversible - a deliberate
scoping choice, not an oversight.
REAL BUG FOUND AND FIXED WHILE BUILDING THIS: decide_request marked a request "approved"
in the database BEFORE the underlying action executed. If execution then failed (wrong
real-mode flag, a transient error), the request was stuck "approved" forever with the
action never having actually happened, and no way to retry since decide_request refuses
to re-decide a non-pending request. This affected account actions since v11.004, not just
the new active-response ones. Fixed by separating decision from execution: a new
executed_at column tracks whether the side effect actually ran; execute_request is now
idempotent and retryable (a no-op if already executed, leaves executed_at NULL on
failure); list_unexecuted_approved() surfaces any stuck request; a new
/retry-execution route lets an admin retry the side effect without a fresh approval
decision. Existing v11.004 tests (dual control, admin panel) were re-run and still pass
unchanged, confirming no regression to the normal success path.
ALSO FOUND AND FIXED: /api/config had no @app.route decorator anywhere in the codebase
since it was first added (pre-v11), meaning Flask never registered it as an endpoint.
Every call to it from the frontend (login gate, mode pill, encrypted-at-rest indicator,
update-check footer) would have silently 404'd. Caught only because building active
response prompted a closer read of the surrounding routes; none of the prior v11 test
files had asserted this specific pre-existing route actually worked, since each
increment's tests focused on what that increment newly built. A regression test now
asserts /api/config returns 200, so this exact class of bug (a route function defined
but never wired to Flask) cannot recur silently.
49 new tests total (27 module-level, 22 HTTP integration) plus the 3-test regression
suite for the /api/config bug.
v11 is now considered feature-complete for this pass. Remaining hardening (Linux/macOS
firewall support, more granular quarantine paths, admin UI panels for bans/quarantine
management) can be picked up as later increments without blocking v12.

v11.009 DONE | hygiene pass across the full v11 codebase: cross-file dead-code search (not
just within-file), documentation reconciliation, and a targeted optimization.
CRITICAL SECURITY BUG FOUND AND FIXED: the login MFA gate checked TOTP status only, never
WebAuthn. An account with ONLY a security key enrolled (no TOTP) could be logged in with
password alone, completely bypassing its second factor. This existed since v11.003 and
was found only by this hygiene pass, not by any prior test. Reproduced with a real request
before fixing (200 OK, confirmed exploitable) and after (401 + mfa_required, confirmed
closed); a permanent regression test now guards this exact scenario.
THREE ORPHANED FEATURES FOUND AND WIRED IN (built and unit-tested in earlier increments,
but never reachable through any route, hence functionally inert): recovery codes
(v11.005's generate/verify/remaining-count methods had no HTTP route at all; added
generate/status routes plus a "recovery_code" alternative at the MFA login step, and a
frontend section in the MFA panel to generate and display them); revoke_all_sessions
(v11.001, unused; added a force-logout admin route, deliberately NOT behind dual control
since it is protective and fully reversible, unlike destructive actions); purge_expired_
sessions (unused; wired into the shared post-login step so expired session rows do not
accumulate forever).
REAL DUPLICATION FIXED: password-login and WebAuthn-login success paths repeated the
same 6 lines (clear failures, touch login, create session, set cookie); extracted into
one _complete_login helper, which is also where the session-purge call now lives.
OPTIMIZATION: resolve_session used to write last_seen to disk (with a commit) on every
single authenticated HTTP request, including a frontend that polls every few seconds.
Since the idle timeout is measured in minutes, sub-minute precision on last_seen buys
nothing observable; writes are now skipped unless at least 30s have passed since the
last one, cutting session-table write volume substantially under normal polling without
changing any user-visible behavior (existing idle-lock tests re-run unchanged and pass).
KNOWN GAP, deliberately not closed here: active_response.is_banned exists, is tested, and
is manageable through the admin panel, but nothing in the actual detection/ingestion
pipeline consults it to filter events from a banned IP. Wiring that up touches the core
detection engine (outside this session's identity/security scope) and deserves its own
explicit scoping decision rather than a silent change to engine.py.
13 new/expanded tests (regression coverage for the WebAuthn-only bypass, recovery-code
login end to end, force-logout). Full suite re-run after every fix; zero regressions.

v11.010 DONE | self-hosted typography (first slice of the dashboard UX rework). Design
overhaul (colors/shapes/layout) was explicitly dropped by the person; scope narrowed to
font only, plus a queued set of click-reduction UX features to follow in later
increments (filter chips, multi-select, keyboard nav, context menu, side panel, command
palette, a shortcuts/settings page). Space Grotesk (titles/labels) and JetBrains Mono
(all data: IDs, scores, hosts, MITRE codes) replace the prior system-font/Consolas mix.
Fonts are SELF-HOSTED (real woff2 files fetched from the projects' own GitHub repos,
Space Grotesk converted from ttf via fonttools), not loaded from a CDN: the app's own
CSP (default-src 'self') would not have allowed an external font host, and pulling
fonts from a third party is itself a supply-chain surface this project has avoided
everywhere else. Served via a new /assets/fonts/<filename> route gated by a fixed
allowlist of exact filenames, verified to refuse both a path-traversal attempt and a
filename outside the allowlist (both return 404, tested against the real Flask route,
not asserted). Font loading verified in an actual browser via the document.fonts API
against a live server (not just a syntax check): Regular and Bold weights confirmed
status=loaded for both typefaces. 669 tests still green, zero regressions.

v11.011 DONE | fixes from real-world testing on the person's own Windows machine, plus
progressive login throttling. The person tested an older snapshot and found real gaps:

CRITICAL, previously undiscovered: the /setup web bootstrap had NO frontend screen at
all. init() never checked /api/setup/status, so a server-mode install with a valid
bootstrap token showing on the terminal had no way to actually use it through the
browser: the person would only ever see the normal login form, for an account that did
not exist yet. Backend routes were correct and tested via raw HTTP since v11.000, but no
human-usable UI ever called them. Fixed: init() now checks /api/setup/status before the
login gate and renders a setup screen (token, username, password) that chains into a
real login on success. Verified end-to-end with Playwright against a live server twice:
first run confirmed the setup screen renders and the dashboard becomes visible after
submission; second run confirmed login-host is genuinely removed (not just visually
hidden) and that a second visit correctly shows the normal login form, not setup again,
proving the bootstrap seal holds. An alternative bootstrap mechanism the person proposed
(token becomes a temporary admin password, forcing a first-login setup flow) was
considered and declined: it would persist the token indirectly (as a password hash) and
seal bootstrap automatically at server start regardless of whether a human ever acts,
both weaker than the existing invariant that sealing only happens after a real, explicit
setup action.

Progressive login throttling replaces the old flat 5-fails/15-min window: a minimum 2s
spacing between consecutive failed attempts for the same account (rejected before even
touching argon2), plus an escalating lockout once past 5 failures (roughly 30s, then
60s, then 120s, doubling every 5 further failures) instead of one fixed window. This
introduced a real side effect across several existing tests that immediately retried a
login right after a failure for the same account (now correctly throttled); fixed by
waiting past the spacing window in those tests rather than weakening the throttle
itself. 12 new tests cover minimum spacing, threshold, escalation, clearing on success,
and per-account independence.

Also fixed: stale "v10 skeleton" wording in four places (server-mode banner, contacts
drawer, two app.py comments/warnings) that inaccurately claimed no accounts or
authentication existed, when v11 has built all of it; a quick "Take" button directly on
open ticket rows (status=investigating, assignee=me) without opening the ticket, using
the same PATCH the modal's save button already sent; the "Mini SOAR" brand now navigates
to the dashboard; the packaged zip's internal folder was always literally named
"SIEM_V10" regardless of actual version, renamed to "SIEM_V11" to match the project's own
historical major-version-folder convention; native title tooltips on the dashboard's
Signal Types and MITRE bars replaced with the same styled tooltip bubble used by the nav
dock (a judgment call on an ambiguous request, flagged for confirmation rather than
guessed silently and left unflagged).
681 tests green, zero regressions.
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

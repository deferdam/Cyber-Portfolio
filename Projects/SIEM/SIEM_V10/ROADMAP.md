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
STARTED (v10.0): server mode is a runnable, locked-down skeleton (loopback only, no auth
yet, read-only host posture, banner); mode is a trusted env-only signal (IS_SERVER); a
fail-safe bind refuses any public interface unless SIEM_ALLOW_PUBLIC=1 is explicitly set;
a full-stop control (/api/shutdown + launcher Quit) stops the app/launcher cleanly.
* Server seam | establish the server process and make the local-vs-server boundary a
  trusted, non-spoofable signal, never a client-controllable input. Prevent a "privilege
  glitch" where a server-side process is tricked into believing it is local. [seam + mode
  integrity STARTED; harden further]
* Read-only posture | the app may only READ. No mutation of the host.
* Credential theft | never store, log, or expose credentials in readable form; no secrets
  in tickets, notes, or logs.
* Anti-C2 | given its accesses, the app must not be usable as a covert channel; no
  command/data exfiltration paths.
* Injection | no command, SQL, path, or template injection anywhere input flows.
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
* AI input safety foundation | external text is UNTRUSTED; the boundary is laid now and
  fully exploited in v12.

## v11 | multi user (people connected)
Goal: real users connect and collaborate, on top of the v10 secured skeleton.
* accounts, authentication, roles and permissions
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

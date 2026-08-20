"""Tests for the v10 server-skeleton security foundations."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from server.app import _safe_bind_host

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


# Loopback is always allowed, no opt-in needed.
host, warn = _safe_bind_host("127.0.0.1", allow_public=False)
check("loopback 127.0.0.1 allowed without opt-in", host == "127.0.0.1" and warn is None)
host, warn = _safe_bind_host("localhost", allow_public=False)
check("localhost allowed without opt-in", host == "localhost")

# Public bind refused without explicit opt-in (fail-safe).
refused = False
try:
    _safe_bind_host("0.0.0.0", allow_public=False)
except RuntimeError:
    refused = True
check("public 0.0.0.0 REFUSED without SIEM_ALLOW_PUBLIC", refused)

refused2 = False
try:
    _safe_bind_host("192.168.1.50", allow_public=False)
except RuntimeError:
    refused2 = True
check("public LAN ip refused without opt-in", refused2)

# Public bind allowed only with explicit opt-in, and it warns.
host, warn = _safe_bind_host("0.0.0.0", allow_public=True)
check("public bind allowed with explicit opt-in", host == "0.0.0.0")
check("public bind emits a reminder warning",
      warn is not None and ("tls" in warn.lower() or "accounts" in warn.lower()))

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

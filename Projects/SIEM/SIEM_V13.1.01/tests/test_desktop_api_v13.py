"""v13.1 | EngineApiClient tests. No Qt, no network: transport is injected."""
import sys, json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from desktop.api_client import EngineApiClient, is_loopback

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1

# -- loopback guard -------------------------------------------------------------------------
check("127.0.0.1 loopback", is_loopback("http://127.0.0.1:5000"))
check("localhost loopback", is_loopback("http://localhost:5000"))
check("public host not loopback", not is_loopback("http://example.com:5000"))

# -- non-loopback client never calls transport and returns empty ----------------------------
called = {"n": 0}
def spy(url):
    called["n"] += 1; return "[]"
bad = EngineApiClient("http://evil.example.com:5000", transport=spy)
check("non-loopback client returns [] for tickets", bad.tickets() == [])
check("non-loopback client never called transport", called["n"] == 0)

# -- happy path: parses a JSON ticket list --------------------------------------------------
sample = [{"ticket_id": "T1", "severity": "high", "status": "open", "host": "WIN-01",
           "signal_type": "powershell", "score": 0.9, "title": "enc ps"}]
captured = {}
def ok_transport(url):
    captured["url"] = url; return json.dumps(sample)
c = EngineApiClient("http://127.0.0.1:5000", transport=ok_transport)
got = c.tickets()
check("tickets parsed from JSON", got == sample)
check("request hits /api/tickets", "/api/tickets" in captured["url"])

# -- filters are passed as query params -----------------------------------------------------
c.tickets(severity="high", status="open")
check("filters go into the query string",
      "severity=high" in captured["url"] and "status=open" in captured["url"])

# -- graceful degradation: transport None / bad JSON -> [] ----------------------------------
check("transport None -> empty list", EngineApiClient("http://127.0.0.1", transport=lambda u: None).tickets() == [])
check("bad JSON -> empty list", EngineApiClient("http://127.0.0.1", transport=lambda u: "not json").tickets() == [])

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

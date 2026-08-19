"""Tests for the injection-defense layer (v10 security foundation):
XSS escaping, ticket-PATCH validation, and shell-free subprocess execution."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import server.app as app_mod

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

# --- ticket PATCH validation (defense in depth) ---
with tempfile.TemporaryDirectory() as d:
    tickets = Path(d) / "tickets.jsonl"
    tickets.write_text(json.dumps({"ticket_id": "T1", "status": "open"}) + "\n")
    app_mod.OUT_DIR = Path(d)
    app_mod.TICKETS = tickets

    r = client.patch("/api/tickets/T1", json={"status": "investigating"})
    check("valid status accepted", r.status_code == 200)

    r = client.patch("/api/tickets/T1", json={"status": "pwned; rm -rf /"})
    check("invalid status rejected with 400", r.status_code == 400)

    r = client.patch("/api/tickets/T1", json={"disposition": "totally_made_up"})
    check("invalid disposition rejected with 400", r.status_code == 400)

    r = client.patch("/api/tickets/T1", json={"is_admin": True, "score": 999})
    rows = [json.loads(x) for x in tickets.read_text().splitlines() if x.strip()]
    t1 = next(x for x in rows if x["ticket_id"] == "T1")
    check("unknown fields are ignored (no privilege/field injection)",
          "is_admin" not in t1 and t1.get("score") != 999)

    long_note = "A" * 9000
    client.patch("/api/tickets/T1", json={"notes": long_note})
    rows = [json.loads(x) for x in tickets.read_text().splitlines() if x.strip()]
    t1 = next(x for x in rows if x["ticket_id"] == "T1")
    check("notes are length-capped", len(t1.get("notes", "")) <= app_mod._MAX_NOTES)

    r = client.patch("/api/tickets/NOPE", json={"status": "open"})
    check("patching a missing ticket returns 404", r.status_code == 404)

# --- XSS escaping is wired into the render path (regression guard) ---
fe = (ROOT / "src" / "server" / "frontend.py").read_text()
check("an HTML-escape helper exists", "function esc(" in fe)
check("command lines are escaped in the process tree", "esc(n.command_line" in fe)
check("signal explanation is escaped", "esc(exp)" in fe)
check("host is escaped in tickets", "esc(t.host" in fe and "esc((s.host" in fe)
check("file names are escaped in the browser", "esc(e.name)" in fe)
check("ticket notes are escaped (no textarea breakout)", "esc(getDraft(t.ticket_id)||t.notes" in fe)

# --- command injection: the run pipeline never uses a shell ---
ap = (ROOT / "src" / "server" / "app.py").read_text()
check("run-stream builds an argv list, not a shell string", "cmd = [sys.executable" in ap)
check("no shell=True anywhere in the app", "shell=True" not in ap)
check("ingestion format is whitelisted", "if fmt not in ALLOWED_FORMATS" in ap)

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

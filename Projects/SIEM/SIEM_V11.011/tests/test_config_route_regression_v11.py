"""Regression test: /api/config must actually be registered as a Flask route.

Found while building v11.008 (active response): api_config() existed as a function since
before this session but had NO @app.route decorator above it, so Flask never registered
it as an endpoint. Every /api/config call from the frontend (login gate, mode pill,
encrypted-at-rest indicator, update-check footer) would have silently 404'd. None of the
prior v11 test files caught this because they tested the routes each increment newly
built, never re-verified this pre-existing one. The lesson: existing code is not
automatically correct just because it predates the current change; this test exists so
this specific class of "route defined but never wired to Flask" regression cannot recur
silently.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

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


os.environ["SIEM_MODE"] = "local"
import importlib
import server.app as appmod
importlib.reload(appmod)

app = appmod.app
app.testing = True
c = app.test_client()

r = c.get("/api/config")
check("/api/config is actually registered (not 404)", r.status_code == 200)
j = r.get_json()
check("response has the expected keys",
      {"mode", "encrypted", "require_login", "authenticated", "user", "role"} <= set(j.keys()))
check("local mode reports mode=local", j.get("mode") == "local")

os.environ.pop("SIEM_MODE", None)

print(f"\n{'=' * 60}")
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)

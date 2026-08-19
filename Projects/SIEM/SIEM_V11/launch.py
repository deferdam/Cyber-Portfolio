#!/usr/bin/env python3
"""Universal launcher.

Run with no argument to open a small clickable UI in the browser where you pick the mode
to launch, and where you can STOP the running instance:

  python launch.py                 # open the clickable mode picker (UI)
  python launch.py local           # start the app in local mode (CLI, blocking)
  python launch.py showcase        # start the sealed demo (CLI, blocking)
  python launch.py docs | tests | pipeline <file> | server

Single instance by design. The UI tracks the running app and stops it before starting
another mode, so switching from local to showcase actually restarts the server instead of
leaving stale data on screen. Local reads out/large (real data); showcase reads out/showcase
(a sealed fake-data sandbox) and streams its demo tickets automatically. The two never share
a directory, so a demo can never corrupt local data.

The launcher lets you pick LOCAL vs MULTI (server) mode. Server mode is the multi-user build
(real accounts, sessions, roles, MFA and TLS); it binds to loopback unless explicitly opened.
"""
import atexit
import os
import platform
import subprocess
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.path.dirname(os.path.abspath(__file__))
APP_PY = os.path.join(ROOT, "src", "server", "app.py")
# Identity store lives OUTSIDE out/ on its own trust path: never vault-encrypted, never
# version-controlled, 0600 perms enforced by the AccountStore.
DATA_DIR = os.path.join(ROOT, "data")
ACCOUNTS_DB = os.path.join(DATA_DIR, "accounts.db")
ALIASES = {"tests": "run_tests", "test": "run_tests", "app": "start"}
LAUNCH_PORT = 5050
IS_WINDOWS = platform.system() == "Windows"

# App modes spawn the server directly (so we can stop them); the rest run a script.
APP_MODES = {"local": "local", "showcase": "showcase", "server": "server"}

MENU = [
    ("local",    "Local mode",      "Analyze your own files. Reads out/large.",            "green"),
    ("showcase", "Showcase / Demo", "Sealed demo, fake data, auto-streaming. No files.",   "amber"),
    ("server",   "Server mode",     "Multi-user: login required, TLS, roles, MFA. Loopback by default.", "muted"),
    ("docs",     "Documentation",   "Open the HTML documentation.",                        "muted"),
    ("tests",    "Run tests",       "Run the whole test suite.",                           "muted"),
]

_app_proc = None
_app_mode = None


# ---- App lifecycle (single instance) ----------------------------------------

def _stop_app():
    global _app_proc, _app_mode
    if _app_proc and _app_proc.poll() is None:
        try:
            if IS_WINDOWS:
                subprocess.call(["taskkill", "/T", "/F", "/PID", str(_app_proc.pid)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                _app_proc.terminate()
            _app_proc.wait(timeout=6)
        except Exception:
            try:
                _app_proc.kill()
            except Exception:
                pass
    _app_proc, _app_mode = None, None


def _start_app(mode):
    global _app_proc, _app_mode
    _stop_app()                      # never two instances on port 5000
    import time
    time.sleep(0.6)                  # let the port free up before rebinding
    env = dict(os.environ)
    env["SIEM_MODE"] = mode
    env["SIEM_HOST"] = "127.0.0.1"
    env["PYTHONPATH"] = os.path.join(ROOT, "src")
    _app_proc = subprocess.Popen([sys.executable, APP_PY], env=env)
    _app_mode = mode


atexit.register(_stop_app)


# ---- Script targets (docs, tests, pipeline, server) -------------------------

def _script_for(target):
    target = ALIASES.get(target, target)
    if IS_WINDOWS:
        return os.path.join(ROOT, "scripts", "bat", target + ".bat"), True
    return os.path.join(ROOT, "scripts", "sh", target + ".sh"), False


def run_target(target, extra=None, detached=False):
    extra = extra or []
    if target in APP_MODES:
        # CLI path: run the app in the foreground (blocking) for direct use.
        env = dict(os.environ, SIEM_MODE=APP_MODES[target], SIEM_HOST="127.0.0.1",
                   PYTHONPATH=os.path.join(ROOT, "src"))
        return subprocess.call([sys.executable, APP_PY], env=env)
    script, is_bat = _script_for(target)
    if not os.path.exists(script):
        sys.stderr.write(f"[launch] unknown target '{target}'.\n")
        return 1
    cmd = ([script] if is_bat else ["bash", script]) + extra
    if detached:
        subprocess.Popen(cmd, shell=is_bat)
        return 0
    return subprocess.call(cmd, shell=is_bat)


# ---- Clickable UI -----------------------------------------------------------

def _page():
    rows = []
    for target, label, desc, accent in MENU:
        disabled = "disabled" if accent == "disabled" else ""
        rows.append(
            f'<button class="card {accent}" {disabled} onclick="launch(\'{target}\')">'
            f'<div class="lab">{label}</div><div class="desc">{desc}</div></button>'
        )
    cards = "\n".join(rows)
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Mini SOAR launcher</title>
<style>
 body{{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#15171a;color:#e6e8ea;margin:0;padding:40px;}}
 h1{{font-size:20px;font-weight:700;margin:0 0 4px;}}
 p.sub{{color:#8b9096;margin:0 0 24px;font-size:13px;}}
 .grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px;max-width:680px;}}
 .card{{text-align:left;background:#1d2024;border:1px solid #2a2e33;border-radius:12px;padding:16px 18px;cursor:pointer;color:inherit;transition:border-color .15s,transform .1s;}}
 .card:hover{{transform:translateY(-1px);}}
 .card .lab{{font-weight:700;font-size:15px;margin-bottom:3px;}}
 .card .desc{{font-size:12px;color:#8b9096;}}
 .card.green{{border-color:#3fae74;}} .card.green .lab{{color:#5cc98c;}}
 .card.amber{{border-color:#e0a458;}} .card.amber .lab{{color:#e0a458;}}
 .card.disabled{{opacity:.45;cursor:not-allowed;}}
 .bar{{display:flex;align-items:center;gap:14px;margin-top:24px;max-width:680px;}}
 #status{{flex:1;font-size:13px;color:#8b9096;}}
 #status b{{color:#5cc98c;}}
 .stop{{background:#2a1d1d;border:1px solid #b5524f;color:#e07a78;border-radius:10px;padding:10px 16px;font-weight:700;cursor:pointer;}}
 .stop:hover{{background:#3a2424;}}
</style></head><body>
 <h1>Mini SOAR | universal launcher</h1>
 <p class="sub">Pick one mode. Switching modes stops the running server first, so you never see stale data.</p>
 <div class="grid">{cards}</div>
 <div class="bar">
   <div id="status">Checking...</div>
   <button class="stop" onclick="stopApp()">Stop running app</button>
   <button class="stop" onclick="quitAll()" style="border-color:#8a8f96;color:#c2c7cd">Quit everything</button>
 </div>
<script>
 async function refresh(){{
   try{{
     const r=await fetch('/status'); const s=await r.json();
     const el=document.getElementById('status');
     el.innerHTML = s.running ? ('Running: <b>'+s.mode+'</b> at http://127.0.0.1:5000')
                              : 'Nothing running.';
   }}catch(e){{}}
 }}
 async function launch(t){{
   if(t==='local'||t==='showcase'){{
     document.getElementById('status').textContent='Starting '+t+' (restarting server)...';
   }}
   try{{ await fetch('/launch?target='+t); }}catch(e){{}}
   setTimeout(refresh, 1200);
 }}
 async function stopApp(){{
   try{{ await fetch('/stop'); }}catch(e){{}}
   setTimeout(refresh, 600);
 }}
 async function quitAll(){{
   if(!confirm('Stop the app AND quit the launcher?'))return;
   try{{ await fetch('/quit'); }}catch(e){{}}
   document.body.innerHTML='<div style="padding:40px;color:#8b9096">Everything stopped. You can close this tab.</div>';
 }}
 refresh(); setInterval(refresh, 2500);
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj):
        import json
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/status":
            running = _app_proc is not None and _app_proc.poll() is None
            return self._json({"running": running, "mode": _app_mode})
        if parsed.path == "/stop":
            _stop_app()
            return self._json({"running": False, "mode": None})
        if parsed.path == "/quit":
            _stop_app()
            self._json({"bye": True})
            # Shut the launcher itself down from another thread (cannot block here).
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if parsed.path == "/launch":
            target = parse_qs(parsed.query).get("target", ["?"])[0]
            if target in APP_MODES:
                _start_app(APP_MODES[target])
            else:
                run_target(target, detached=True)
            return self._json({"ok": True})
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(_page().encode("utf-8"))


def serve_ui():
    httpd = HTTPServer(("127.0.0.1", LAUNCH_PORT), _Handler)
    url = f"http://127.0.0.1:{LAUNCH_PORT}"
    print(f"[launch] mode picker at {url} (Ctrl+C to quit; this also stops the app)")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[launch] stopping app and quitting")
        _stop_app()


def _run_admin_cli(cmd):
    """Dispatch the account CLI commands. Imports are local so the launcher has no hard
    dependency on argon2 unless an admin command is actually run."""
    sys.path.insert(0, os.path.join(ROOT, "src"))
    from pathlib import Path
    from core import admin_cli
    db = Path(ACCOUNTS_DB)
    if cmd == "create-admin":
        return admin_cli.cmd_create_admin(db)
    if cmd == "reset-admin-password":
        return admin_cli.cmd_reset_admin_password(db)
    sys.stderr.write("[launch] unknown admin command '%s'.\n" % cmd)
    return 1


def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd in ("create-admin", "reset-admin-password"):
            sys.exit(_run_admin_cli(cmd))
        sys.exit(run_target(cmd, extra=sys.argv[2:]))
    serve_ui()


if __name__ == "__main__":
    main()

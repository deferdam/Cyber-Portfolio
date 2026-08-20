"""v13.0 | EngineController tests. No Qt, no real subprocess: spawn and admin creator are
injected fakes, so this runs in the normal suite on any machine."""
import sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from desktop.controller import EngineController

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1


class FakeProc:
    def __init__(self, cmd, env):
        self.cmd = cmd; self.env = env; self._alive = True; self.terminated = False
    def poll(self):
        return None if self._alive else 0
    def terminate(self):
        self.terminated = True; self._alive = False
    def wait(self, timeout=None):
        self._alive = False; return 0
    def kill(self):
        self._alive = False


spawned = []
def fake_spawn(cmd, env=None, **kw):
    p = FakeProc(cmd, env or {}); spawned.append(p); return p

tmp = Path(tempfile.mkdtemp())
ctrl = EngineController(root=tmp, python_exe="python3", spawn=fake_spawn)

# -- initial state -------------------------------------------------------------------------
check("not running initially", ctrl.is_running() is False)
check("url is loopback", ctrl.url == "http://127.0.0.1:5000")
check("status shape", set(ctrl.status()) == {"running", "mode", "url"})

# -- start builds the right command + env --------------------------------------------------
p = ctrl.start("local")
check("running after start", ctrl.is_running() is True)
check("current mode is local", ctrl.current_mode() == "local")
check("spawn ran app.py", str(p.cmd[-1]).endswith("server/app.py") or p.cmd[-1].endswith("app.py"))
check("env carries SIEM_MODE=local", p.env.get("SIEM_MODE") == "local")
check("env pins loopback host", p.env.get("SIEM_HOST") == "127.0.0.1")

# -- invalid mode rejected -----------------------------------------------------------------
try:
    ctrl.start("hacker")
    bad = False
except ValueError:
    bad = True
check("invalid mode raises ValueError", bad)

# -- single instance: starting another mode stops the previous -----------------------------
first = ctrl.proc
p2 = ctrl.start("showcase")
check("previous engine was terminated (single instance)", first.terminated is True)
check("new mode is showcase", ctrl.current_mode() == "showcase")
check("a new process was spawned", p2 is not first)

# -- stop clears state ---------------------------------------------------------------------
ctrl.stop()
check("not running after stop", ctrl.is_running() is False)
check("no current mode after stop", ctrl.current_mode() is None)

# -- create_admin reuses the CLI bootstrap non-interactively -------------------------------
calls = {}
def fake_creator(db_path, prompt, secret, out):
    calls["user"] = prompt("Choose the admin username: ")
    calls["pw1"] = secret("Choose a password: ")
    calls["pw2"] = secret("Repeat the password: ")
    out("Admin '%s' created." % calls["user"])
    return 0
ctrl2 = EngineController(root=tmp, spawn=fake_spawn, admin_creator=fake_creator)
rc, output = ctrl2.create_admin("root", "Tr0ub4dour-Quux-Vault-71!")
check("create_admin returns rc 0 on success", rc == 0)
check("username was passed through non-interactively", calls["user"] == "root")
check("both password prompts got the same value", calls["pw1"] == calls["pw2"] == "Tr0ub4dour-Quux-Vault-71!")
check("create_admin captures output", "created" in output)

print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

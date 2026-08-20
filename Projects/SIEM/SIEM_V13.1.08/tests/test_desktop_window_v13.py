"""v13.0 | Qt window smoke test, headless (offscreen). Skips (passes) cleanly if PySide6 is
not installed, so the suite still runs on machines without the desktop extras."""
import os, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication
except ImportError:
    print("  [skip] PySide6 not installed; desktop window smoke test skipped")
    print("\n  Results: 0 passed, 0 failed")
    sys.exit(0)

from desktop.controller import EngineController
from desktop.window import MainWindow, AdminDialog

PASS = 0; FAIL = 0
def check(n, cond):
    global PASS, FAIL
    print(("  [ok]   " if cond else "  [FAIL] ") + n)
    PASS += 1 if cond else 0; FAIL += 0 if cond else 1


class FakeProc:
    def __init__(self, *a, **k): self._alive = True; self.stdout = None
    def poll(self): return None if self._alive else 0
    def terminate(self): self._alive = False
    def wait(self, timeout=None): self._alive = False; return 0
    def kill(self): self._alive = False

def fake_spawn(cmd, env=None, **kw): return FakeProc()

app = QApplication.instance() or QApplication([])
ctrl = EngineController(root=Path(tempfile.mkdtemp()), spawn=fake_spawn)
win = MainWindow(ctrl)

check("window constructs offscreen", win is not None)
check("window title is Mini SOAR", win.windowTitle() == "Mini SOAR")
check("three mode buttons present", set(win._mode_buttons) == {"local", "showcase", "server"})
check("admin button disabled when idle", win.admin_btn.isEnabled() is False)

# start server mode via the controller -> admin button becomes enabled
win.start_mode("server")
check("engine running after start_mode", ctrl.is_running() is True)
check("status label reflects running server", "server" in win.status_label.text())
check("admin button enabled in server mode", win.admin_btn.isEnabled() is True)

# stop
win.stop_engine()
check("engine stopped", ctrl.is_running() is False)
check("admin button disabled again after stop", win.admin_btn.isEnabled() is False)

# admin dialog constructs and returns values
dlg = AdminDialog(win)
dlg.user.setText("root"); dlg.pw.setText("pw"); dlg.pw2.setText("pw")
check("admin dialog returns entered values", dlg.values() == ("root", "pw", "pw"))

# tickets panel: populate directly and via a stubbed refresh
from desktop.panels import TicketsPanel
panel = TicketsPanel(lambda: "http://127.0.0.1:5000")
panel.populate([{"ticket_id": "T1", "severity": "high", "status": "open", "host": "H",
                 "signal_type": "powershell", "score": 0.9, "title": "x"}])
check("tickets panel populates one row", panel.table.rowCount() == 1)
check("tickets panel cell shows ticket id", panel.table.item(0, 0).text() == "T1")
check("main window has a tickets panel", hasattr(win, "tickets_panel"))

win.close()
print(f"\n  Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)

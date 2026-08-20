"""Desktop engine controller (no Qt).

This holds ALL the logic of the desktop app so it can be unit-tested without a display. The
Qt window (window.py) is a thin layer that calls into this. The controller does not
reimplement or fork the SIEM/SOAR engine: it launches the exact same server the web launcher
does, as a subprocess, in a chosen mode. Single-instance is enforced (one engine at a time).

Server mode has no browser, so admin bootstrap reuses the exact CLI path
(core.admin_cli.cmd_create_admin) driven non-interactively, which keeps the same one-admin
seal invariant. No new outbound network call is introduced: the controller only spawns the
local engine and hands back a loopback URL to open.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from core import admin_cli


class EngineController:
    MODES = ("local", "showcase", "server")

    def __init__(self, root: Optional[Path] = None, python_exe: Optional[str] = None,
                 host: str = "127.0.0.1", port: int = 5000,
                 spawn: Callable = subprocess.Popen,
                 admin_creator: Callable = admin_cli.cmd_create_admin) -> None:
        # root is the SIEM_Vxx project directory (three parents up from this file:
        # src/desktop/controller.py -> src -> project root).
        self.root = Path(root) if root else Path(__file__).resolve().parents[2]
        self.app_py = self.root / "src" / "server" / "app.py"
        self.data_db = self.root / "data" / "accounts.db"
        self.python_exe = python_exe or sys.executable
        self.host = host
        self.port = port
        self._spawn = spawn
        self._admin_creator = admin_creator
        self._proc = None
        self._mode: Optional[str] = None

    @property
    def url(self) -> str:
        return "http://%s:%d" % (self.host, self.port)

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def current_mode(self) -> Optional[str]:
        return self._mode if self.is_running() else None

    def start(self, mode: str):
        """Start the engine in `mode`. Single instance: any running engine is stopped first."""
        if mode not in self.MODES:
            raise ValueError("unknown mode: %r (expected one of %s)" % (mode, self.MODES))
        if self.is_running():
            self.stop()
        env = dict(os.environ, SIEM_MODE=mode, SIEM_HOST=self.host, SIEM_PORT=str(self.port))
        self._proc = self._spawn([self.python_exe, str(self.app_py)], env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 bufsize=1, universal_newlines=True)
        self._mode = mode
        return self._proc

    def stop(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        self._proc = None
        self._mode = None

    def status(self) -> Dict:
        return {"running": self.is_running(), "mode": self.current_mode(), "url": self.url}

    @property
    def proc(self):
        return self._proc

    # -- admin bootstrap (server mode, no browser) -----------------------------------------
    def admin_exists(self) -> bool:
        try:
            from core.accounts import AccountStore
            return AccountStore(self.data_db).is_sealed()
        except Exception:
            return False

    def create_admin(self, username: str, password: str) -> Tuple[int, str]:
        """Create the first admin by reusing the CLI bootstrap non-interactively. Returns
        (returncode, captured_output). Same seal invariant as the CLI: if an admin already
        exists the underlying command refuses."""
        lines: List[str] = []
        rc = self._admin_creator(self.data_db,
                                 prompt=lambda _p: username,
                                 secret=lambda _p: password,
                                 out=lines.append)
        return rc, "\n".join(lines)

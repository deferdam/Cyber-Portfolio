"""Desktop main window (PySide6).

Thin Qt view over EngineController. All decisions live in the controller; this file only wires
widgets to it and streams the engine's output into a log pane. Kept deliberately small.
"""
from __future__ import annotations

import webbrowser

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QPlainTextEdit, QDialog, QLineEdit, QFormLayout, QDialogButtonBox, QMessageBox,
    QTabWidget,
)

from desktop.controller import EngineController
from desktop.panels import TicketsPanel


class _LogReader(QThread):
    """Reads the engine subprocess stdout line by line and emits each line. Runs only while
    the process is alive; exits cleanly when it ends or is stopped."""
    line = Signal(str)

    def __init__(self, proc):
        super().__init__()
        self._proc = proc
        self._stop = False

    def run(self):
        if not self._proc or not self._proc.stdout:
            return
        for line in self._proc.stdout:
            if self._stop:
                break
            self.line.emit(line.rstrip())

    def stop(self):
        self._stop = True


class AdminDialog(QDialog):
    """Collects a username and password to bootstrap the first admin (server mode, no
    browser). The controller reuses the CLI bootstrap, so the seal invariant is unchanged."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create admin account")
        form = QFormLayout(self)
        self.user = QLineEdit()
        self.pw = QLineEdit(); self.pw.setEchoMode(QLineEdit.Password)
        self.pw2 = QLineEdit(); self.pw2.setEchoMode(QLineEdit.Password)
        form.addRow("Username", self.user)
        form.addRow("Password", self.pw)
        form.addRow("Repeat password", self.pw2)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def values(self):
        return self.user.text().strip(), self.pw.text(), self.pw2.text()


class MainWindow(QMainWindow):
    def __init__(self, controller: EngineController = None):
        super().__init__()
        self.controller = controller or EngineController()
        self._reader = None
        self.setWindowTitle("Mini SOAR")
        self.resize(720, 480)

        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central)

        root.addWidget(QLabel("Mode"))
        modes = QHBoxLayout()
        self._mode_buttons = {}
        for mode, label in (("local", "Local"), ("showcase", "Showcase"), ("server", "Server")):
            b = QPushButton(label)
            b.clicked.connect(lambda _=False, m=mode: self.start_mode(m))
            modes.addWidget(b)
            self._mode_buttons[mode] = b
        root.addLayout(modes)

        actions = QHBoxLayout()
        self.stop_btn = QPushButton("Stop"); self.stop_btn.clicked.connect(self.stop_engine)
        self.open_btn = QPushButton("Open in browser"); self.open_btn.clicked.connect(self.open_browser)
        self.admin_btn = QPushButton("Create admin"); self.admin_btn.clicked.connect(self.create_admin)
        self.quit_btn = QPushButton("Quit"); self.quit_btn.clicked.connect(self.quit_all)
        for b in (self.stop_btn, self.open_btn, self.admin_btn, self.quit_btn):
            actions.addWidget(b)
        root.addLayout(actions)

        self.status_label = QLabel("Idle. Pick a mode to start the engine.")
        root.addWidget(self.status_label)

        tabs = QTabWidget()
        self.log = QPlainTextEdit(); self.log.setReadOnly(True)
        tabs.addTab(self.log, "Log")
        self.tickets_panel = TicketsPanel(lambda: self.controller.url)
        tabs.addTab(self.tickets_panel, "Tickets")
        root.addWidget(tabs, 1)

        self._refresh_status()

    # -- actions ---------------------------------------------------------------------------
    def start_mode(self, mode):
        try:
            proc = self.controller.start(mode)
        except Exception as exc:
            self._append("[error] %s" % exc)
            return
        self._append("[app] started engine in %s mode" % mode)
        self._start_reader(proc)
        self._refresh_status()

    def stop_engine(self):
        self._stop_reader()
        self.controller.stop()
        self._append("[app] engine stopped")
        self._refresh_status()

    def open_browser(self):
        if not self.controller.is_running():
            self._append("[app] nothing running to open")
            return
        webbrowser.open(self.controller.url)

    def create_admin(self):
        dlg = AdminDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return
        user, pw, pw2 = dlg.values()
        if not user or not pw:
            QMessageBox.warning(self, "Create admin", "Username and password are required.")
            return
        if pw != pw2:
            QMessageBox.warning(self, "Create admin", "Passwords do not match.")
            return
        rc, output = self.controller.create_admin(user, pw)
        self._append("[admin] " + output.replace("\n", " "))
        if rc == 0:
            QMessageBox.information(self, "Create admin", "Admin created. Bootstrap is sealed.")
        else:
            QMessageBox.warning(self, "Create admin", output or "Admin creation refused.")

    def quit_all(self):
        self._stop_reader()
        self.controller.stop()
        QApplication.instance().quit()

    # -- helpers ---------------------------------------------------------------------------
    def _start_reader(self, proc):
        self._stop_reader()
        self._reader = _LogReader(proc)
        self._reader.line.connect(self._append)
        self._reader.start()

    def _stop_reader(self):
        if self._reader is not None:
            self._reader.stop()
            self._reader.wait(1000)
            self._reader = None

    def _append(self, text):
        self.log.appendPlainText(text)

    def _refresh_status(self):
        st = self.controller.status()
        if st["running"]:
            self.status_label.setText("Running in %s mode at %s" % (st["mode"], st["url"]))
        else:
            self.status_label.setText("Idle. Pick a mode to start the engine.")
        self.admin_btn.setEnabled(st["mode"] == "server")

    def closeEvent(self, event):
        self._stop_reader()
        self.controller.stop()
        super().closeEvent(event)

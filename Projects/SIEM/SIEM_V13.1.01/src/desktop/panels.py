"""Native tickets panel (PySide6).

A read-only table of the engine's tickets, fetched from the loopback REST API. Thin view: it
owns no logic beyond mapping ticket dicts to rows. It works when the engine runs in a no-auth
mode (local/showcase); in server mode the API needs login and the table simply stays empty
until native auth lands in a later increment.
"""
from __future__ import annotations

from typing import Callable, List

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView,
)

from desktop.api_client import EngineApiClient

_COLUMNS = ["ID", "Severity", "Status", "Host", "Type", "Score", "Title"]
_FIELDS = ["ticket_id", "severity", "status", "host", "signal_type", "score", "title"]


class TicketsPanel(QWidget):
    def __init__(self, base_url_provider: Callable[[], str], parent=None):
        super().__init__(parent)
        self._base_url_provider = base_url_provider

        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        self.count_label = QLabel("No tickets loaded.")
        top.addWidget(self.refresh_btn)
        top.addWidget(self.count_label)
        top.addStretch(1)
        layout.addLayout(top)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table, 1)

    def _client(self) -> EngineApiClient:
        return EngineApiClient(self._base_url_provider())

    def populate(self, tickets: List[dict]) -> None:
        self.table.setRowCount(len(tickets))
        for r, t in enumerate(tickets):
            for c, field in enumerate(_FIELDS):
                val = t.get(field, "")
                self.table.setItem(r, c, QTableWidgetItem(str(val)))
        self.count_label.setText("%d ticket(s)." % len(tickets))

    def refresh(self) -> None:
        tickets = self._client().tickets()
        self.populate(tickets)
        if not tickets:
            self.count_label.setText("No tickets (engine not running, empty, or server mode).")

"""Toolchain Doctor & Setup dialog. All probing/downloading runs off the GUI thread."""
from __future__ import annotations

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QHeaderView, QLabel, QPlainTextEdit,
                               QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout,
                               QWidget)

from ..config import TOOLS_BIN
from ..core import doctor

COLS = ["Plugin / Tool", "Formats", "Status", "Location", "Version", "Action"]


class _Signals(QObject):
    rows = Signal(list)
    log = Signal(str)
    done = Signal(bool)


class _Job(QRunnable):
    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        self.fn()


class DoctorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Toolchain Doctor & Setup")
        self.resize(1100, 520)
        self.sig = _Signals()
        self.sig.rows.connect(self._populate)
        self.sig.log.connect(lambda s: self.log.appendPlainText(s))
        self.sig.done.connect(lambda ok: self.refresh())

        self.status = QLabel(f"Portable tools directory: {TOOLS_BIN}")
        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(140)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)

        lay = QVBoxLayout(self)
        lay.addWidget(self.status)
        lay.addWidget(self.table, 1)
        lay.addWidget(QLabel("Setup log:"))
        lay.addWidget(self.log)
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        bottom.addWidget(refresh)
        bottom.addWidget(close)
        lay.addLayout(bottom)
        self.refresh()

    def refresh(self) -> None:
        self.status.setText(f"Probing tools … (portable dir: {TOOLS_BIN})")
        sig = self.sig
        QThreadPool.globalInstance().start(_Job(lambda: sig.rows.emit(doctor.doctor_rows())))

    @Slot(list)
    def _populate(self, rows: list) -> None:
        self.status.setText(f"Portable tools directory: {TOOLS_BIN}")
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            vals = [r.name, r.formats, "OK" if r.available else "MISSING", r.location, r.version]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if c == 2:
                    item.setForeground(QColor("#27ae60" if r.available else "#eb5757"))
                if c == 3:
                    item.setToolTip(r.hint if not r.available else r.location)
                self.table.setItem(i, c, item)
            self.table.setCellWidget(i, 5, self._actions(r))
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)

    def _actions(self, row) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(2, 0, 2, 0)
        if row.portable:
            dl = QPushButton("Download Portable Tool")
            dl.setEnabled(not row.available)
            dl.clicked.connect(lambda _=False, n=row.name, b=dl: self._download(n, b))
            h.addWidget(dl)
        cp = QPushButton("Copy Install Command")
        cp.clicked.connect(lambda _=False, t=row.hint: self._copy(t))
        h.addWidget(cp)
        return w

    def _copy(self, text: str) -> None:
        QGuiApplication.clipboard().setText(text)
        self.log.appendPlainText(f"Copied to clipboard: {text}")

    def _download(self, name: str, button: QPushButton) -> None:
        button.setEnabled(False)
        button.setText("Downloading…")
        sig = self.sig
        QThreadPool.globalInstance().start(
            _Job(lambda: sig.done.emit(doctor.download_portable(name, sig.log.emit))))

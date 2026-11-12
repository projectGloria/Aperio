"""Inspector & live log drawer for the selected queue row."""
from __future__ import annotations

from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QHeaderView, QLabel, QPlainTextEdit, QTableWidget,
                               QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget)

from .queue_model import MAX_LOG_LINES, Row


def _mono(widget: QPlainTextEdit) -> QPlainTextEdit:
    f = QFont("Consolas")
    f.setStyleHint(QFont.Monospace)
    widget.setFont(f)
    widget.setReadOnly(True)
    widget.setLineWrapMode(QPlainTextEdit.NoWrap)
    return widget


class Inspector(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_id: int | None = None
        self._shown_lines = 0
        self.title = QLabel("Select a row to inspect it.")
        self.title.setWordWrap(True)
        self.title.setStyleSheet("font-weight:600; padding:4px 2px;")

        self.tabs = QTabWidget()
        self.log = _mono(QPlainTextEdit())
        self.log.setMaximumBlockCount(MAX_LOG_LINES)
        self.meta = QTableWidget(0, 2)
        self.meta.setHorizontalHeaderLabels(["Field", "Value"])
        self.meta.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.meta.verticalHeader().setVisible(False)
        self.meta.setEditTriggers(QTableWidget.NoEditTriggers)
        self.cmd = _mono(QPlainTextEdit())
        self.cmd.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.batch = _mono(QPlainTextEdit())
        self.batch.setMaximumBlockCount(MAX_LOG_LINES)
        self.tabs.addTab(self.log, "Live Output (stdout / stderr)")
        self.tabs.addTab(self.meta, "Header Metadata")
        self.tabs.addTab(self.cmd, "Command Line")
        self.tabs.addTab(self.batch, "Batch Log")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.addWidget(self.title)
        lay.addWidget(self.tabs)

    def show_row(self, row: Row | None) -> None:
        if row is None:
            self.current_id = None
            self.title.setText("Select a row to inspect it.")
            for w in (self.log, self.cmd):
                w.clear()
            self.meta.setRowCount(0)
            return
        self.current_id = row.task_id
        self.title.setText(f"{row.rel_path}  —  {row.fmt}  →  {row.plugin}  [{row.status_text}]")
        self.log.setPlainText("\n".join(row.logs))
        self._shown_lines = len(row.logs)
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())
        self.cmd.setPlainText("\n\n".join(row.commands) or "(not executed yet)")
        items = list(row.metadata.items()) + [("output_dir", row.out_dir)]
        if row.output_path:
            items.append(("output_path", row.output_path))
        if row.error:
            items.append(("error", row.error))
        self.meta.setRowCount(len(items))
        for i, (k, v) in enumerate(items):
            self.meta.setItem(i, 0, QTableWidgetItem(str(k)))
            self.meta.setItem(i, 1, QTableWidgetItem(str(v)))
        self.meta.resizeColumnToContents(0)

    def refresh_live(self, row: Row) -> None:
        """Append only lines that arrived since the last refresh."""
        if row.task_id != self.current_id:
            return
        total = len(row.logs)
        if total < self._shown_lines or total == MAX_LOG_LINES:
            self.show_row(row)       # deque wrapped: full redraw
            return
        new = list(row.logs)[self._shown_lines:]
        if new:
            bar = self.log.verticalScrollBar()
            at_bottom = bar.value() >= bar.maximum() - 4
            self.log.appendPlainText("\n".join(new))
            if at_bottom:
                bar.setValue(bar.maximum())
        self._shown_lines = total
        self.title.setText(f"{row.rel_path}  —  {row.fmt}  →  {row.plugin}  [{row.status_text}]")
        if row.commands:
            self.cmd.setPlainText("\n\n".join(row.commands))

    def append_batch(self, lines: list[str]) -> None:
        if lines:
            self.batch.appendPlainText("\n".join(lines))

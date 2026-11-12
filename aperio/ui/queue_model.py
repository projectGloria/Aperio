"""Live file-queue table model + status/format filter proxy."""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor

from ..core.events import TaskCompleted, TaskDiscovered, TaskLog, TaskStarted

COLUMNS = ["File Path (Relative)", "Detected Format", "Tool / Plugin", "Status",
           "Duration", "Quick Action"]
COL_ACTION = 5
STATUS_COLORS = {"Queued": "#8a8f98", "Running": "#2f80ed", "Success": "#27ae60",
                 "Failed": "#eb5757", "Skipped": "#c99a2e"}
MAX_LOG_LINES = 5000


@dataclass
class Row:
    task_id: int
    rel_path: str
    fmt: str
    plugin: str
    status: str            # base status (Queued/Running/...)
    status_text: str
    out_dir: str
    metadata: dict
    output_path: str = ""
    error: str = ""
    duration: float = 0.0
    started_at: float | None = None
    commands: list[str] = field(default_factory=list)
    logs: deque = field(default_factory=lambda: deque(maxlen=MAX_LOG_LINES))


class QueueModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: list[Row] = []
        self.index_of: dict[int, int] = {}
        self.batch_log: deque[str] = deque(maxlen=MAX_LOG_LINES)

    # ----------------------------------------------------------- Qt API
    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return COLUMNS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self.rows[index.row()]
        c = index.column()
        if role == Qt.DisplayRole:
            if c == 0:
                return r.rel_path
            if c == 1:
                return r.fmt
            if c == 2:
                return r.plugin
            if c == 3:
                return r.status_text
            if c == 4:
                d = (time.monotonic() - r.started_at) if r.status == "Running" and r.started_at \
                    else r.duration
                return f"{d:.1f}s" if d else ""
            if c == COL_ACTION:
                return "Open Output Folder" if r.status in ("Success", "Failed") else ""
        if role == Qt.ForegroundRole:
            if c == 3:
                return QColor(STATUS_COLORS.get(r.status, "#888"))
            if c == COL_ACTION:
                return QColor("#2f80ed")
        if role == Qt.ToolTipRole:
            if c == 3 and r.error:
                return r.error[:1000]
            if c == 0:
                return r.rel_path
        if role == Qt.TextAlignmentRole and c == 4:
            return int(Qt.AlignRight | Qt.AlignVCenter)
        if role == Qt.UserRole:
            return r.task_id
        return None

    # -------------------------------------------------------- updates
    def clear(self) -> None:
        self.beginResetModel()
        self.rows.clear()
        self.index_of.clear()
        self.batch_log.clear()
        self.endResetModel()

    def row_for(self, task_id: int) -> Row | None:
        i = self.index_of.get(task_id)
        return self.rows[i] if i is not None else None

    def apply(self, events: list) -> tuple[set[int], list[str]]:
        """Apply a batch of core events. Returns (task ids with new log lines,
        new batch-level log lines)."""
        new_rows = [e for e in events if isinstance(e, TaskDiscovered)]
        if new_rows:
            start = len(self.rows)
            self.beginInsertRows(QModelIndex(), start, start + len(new_rows) - 1)
            for e in new_rows:
                base = e.status.split(" ", 1)[0]
                self.index_of[e.task_id] = len(self.rows)
                self.rows.append(Row(e.task_id, e.rel_path, e.detected_format, e.plugin_name,
                                     base, e.status, e.out_dir, e.metadata))
            self.endInsertRows()
        changed: set[int] = set()
        logged: set[int] = set()
        batch_lines: list[str] = []
        for e in events:
            if isinstance(e, TaskLog):
                if e.task_id is None:
                    self.batch_log.append(e.line)
                    batch_lines.append(e.line)
                    continue
                r = self.row_for(e.task_id)
                if r is None:
                    continue
                if e.stream == "cmd":
                    r.commands.append(e.line)
                r.logs.append(f"[{e.stream}] {e.line}")
                logged.add(e.task_id)
            elif isinstance(e, TaskStarted):
                r = self.row_for(e.task_id)
                if r:
                    r.status = r.status_text = "Running"
                    r.started_at = time.monotonic()
                    changed.add(self.index_of[e.task_id])
            elif isinstance(e, TaskCompleted):
                r = self.row_for(e.task_id)
                if r:
                    r.status, r.status_text = e.status, e.status_text
                    r.duration, r.error = e.duration, e.error
                    r.output_path = e.output_path
                    if e.error:
                        r.logs.append(f"[error] {e.error}")
                        logged.add(e.task_id)
                    changed.add(self.index_of[e.task_id])
        if changed:
            self.dataChanged.emit(self.index(min(changed), 0),
                                  self.index(max(changed), len(COLUMNS) - 1))
        return logged, batch_lines

    def tick_running(self) -> None:
        """Refresh the Duration column of running rows (live timer)."""
        running = [i for i, r in enumerate(self.rows) if r.status == "Running"]
        if running:
            self.dataChanged.emit(self.index(min(running), 4), self.index(max(running), 4))

    def counts(self) -> dict[str, int]:
        out = {k: 0 for k in STATUS_COLORS}
        for r in self.rows:
            out[r.status] = out.get(r.status, 0) + 1
        return out


class QueueFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.status_filter = "All"
        self.format_filter = ""

    def set_filters(self, status: str, fmt: str) -> None:
        if hasattr(self, "beginFilterChange"):  # Qt >= 6.10
            self.beginFilterChange()
            self.status_filter, self.format_filter = status, fmt.strip().lower()
            self.endFilterChange(QSortFilterProxyModel.Direction.Rows)
        else:
            self.status_filter, self.format_filter = status, fmt.strip().lower()
            self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        r = self.sourceModel().rows[source_row]
        if self.status_filter != "All" and r.status != self.status_filter:
            return False
        if self.format_filter and self.format_filter not in (
                f"{r.fmt} {r.plugin} {r.rel_path}".lower()):
            return False
        return True

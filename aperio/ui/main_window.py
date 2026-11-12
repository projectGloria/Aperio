"""Aperio main window: target bar, live queue, inspector drawer, batch controls."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QModelIndex, Qt, QTimer, QUrl, Slot
from PySide6.QtGui import QAction, QDesktopServices
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDockWidget, QHBoxLayout,
                               QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
                               QProgressBar, QPushButton, QTableView, QToolBar, QVBoxLayout,
                               QWidget)

from ..core.events import BatchFinished
from ..core.models import DispatchOptions
from .bridge import BatchController
from .doctor_dialog import DoctorDialog
from .inspector import Inspector
from .queue_model import COL_ACTION, QueueFilterProxy, QueueModel
from .widgets import DropZone, TargetBar


class MainWindow(QMainWindow):
    def __init__(self, notice: str | None = None):
        super().__init__()
        self.setWindowTitle("Aperio — Binary Inspection & Decompiler Dispatcher")
        self.resize(1280, 820)
        self.controller = BatchController(self)
        self.model = QueueModel(self)
        self.proxy = QueueFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.report_path: Path | None = None
        self._doctor: DoctorDialog | None = None
        self._total = 0
        self._completed = 0

        self._build_toolbar()
        central = QWidget()
        lay = QVBoxLayout(central)
        if notice:
            lay.addWidget(self._banner(notice))
        self.drop = DropZone()
        self.targets = TargetBar()
        lay.addWidget(self.drop)
        lay.addWidget(self.targets)
        lay.addLayout(self._filter_bar())
        lay.addWidget(self._build_table(), 1)
        lay.addLayout(self._batch_controls())
        self.setCentralWidget(central)

        self.inspector = Inspector()
        dock = QDockWidget("Inspector & Live Log", self)
        dock.setWidget(self.inspector)
        dock.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable)
        self.addDockWidget(Qt.BottomDockWidgetArea, dock)
        self.resizeDocks([dock], [250], Qt.Vertical)

        self.drop.pathDropped.connect(self.targets.set_target)
        self.targets.targetChanged.connect(lambda p: self.drop.set_text(f"Target: {p}"))
        self.controller.eventsReady.connect(self._on_events)
        self.controller.batchFinished.connect(self._on_finished)
        self.controller.runningChanged.connect(self._on_running)
        self._ticker = QTimer(self)
        self._ticker.setInterval(500)
        self._ticker.timeout.connect(self.model.tick_running)
        self._ticker.start()

    # ------------------------------------------------------------ layout
    def _build_toolbar(self) -> None:
        tb = QToolBar("Main")
        tb.setMovable(False)
        self.addToolBar(tb)
        doctor = QAction("Toolchain Doctor && Setup", self)
        doctor.triggered.connect(self._open_doctor)
        out = QAction("Open Output Folder", self)
        out.triggered.connect(lambda: self._open_path(Path(self.targets.out.text())))
        tb.addAction(doctor)
        tb.addAction(out)

    def _banner(self, text: str) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background:#fff4d6; color:#5c4400; border-radius:6px;")
        h = QHBoxLayout(w)
        label = QLabel(text)
        label.setWordWrap(True)
        close = QPushButton("Dismiss")
        close.clicked.connect(w.hide)
        h.addWidget(label, 1)
        h.addWidget(close)
        return w

    def _filter_bar(self) -> QHBoxLayout:
        h = QHBoxLayout()
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "Queued", "Running", "Success", "Failed", "Skipped"])
        self.format_filter = QLineEdit()
        self.format_filter.setPlaceholderText("Filter by format / plugin / path…")
        self.format_filter.setClearButtonEnabled(True)
        apply = lambda *_: self.proxy.set_filters(self.status_filter.currentText(),  # noqa: E731
                                                  self.format_filter.text())
        self.status_filter.currentTextChanged.connect(apply)
        self.format_filter.textChanged.connect(apply)
        h.addWidget(QLabel("Status:"))
        h.addWidget(self.status_filter)
        h.addWidget(self.format_filter, 1)
        return h

    def _build_table(self) -> QTableView:
        t = QTableView()
        t.setModel(self.proxy)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setSelectionMode(QAbstractItemView.SingleSelection)
        t.setAlternatingRowColors(True)
        t.setSortingEnabled(True)
        t.sortByColumn(0, Qt.AscendingOrder)
        t.verticalHeader().setVisible(False)
        t.verticalHeader().setDefaultSectionSize(22)
        hh = t.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Stretch)
        for c, w in ((1, 220), (2, 110), (3, 240), (4, 70), (5, 140)):
            hh.resizeSection(c, w)
        t.selectionModel().currentRowChanged.connect(self._on_select)
        t.clicked.connect(self._on_click)
        self.table = t
        return t

    def _batch_controls(self) -> QHBoxLayout:
        h = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.cancel_btn = QPushButton("Cancel All")
        self.cancel_btn.setEnabled(False)
        self.report_btn = QPushButton("Open REPORT.md")
        self.report_btn.setEnabled(False)
        self.progress = QProgressBar()
        self.progress.setFormat("%v / %m completed")
        self.progress.setValue(0)
        self.start_btn.clicked.connect(self._start)
        self.cancel_btn.clicked.connect(self._cancel)
        self.report_btn.clicked.connect(lambda: self.report_path and self._open_path(self.report_path))
        for w in (self.start_btn, self.cancel_btn):
            h.addWidget(w)
        h.addWidget(self.progress, 1)
        h.addWidget(self.report_btn)
        return h

    # ----------------------------------------------------------- actions
    def _start(self) -> None:
        text = self.targets.target.text().strip()
        if not text:
            QMessageBox.information(self, "Aperio", "Choose or drop a target first.")
            return
        opts = DispatchOptions(out_dir=Path(self.targets.out.text()).resolve(),
                               jobs=self.targets.jobs.value(),
                               heavy_jobs=self.targets.heavy.value(),
                               timeout=self.targets.timeout.value(),
                               skip_native=self.targets.skip_native.isChecked(),
                               copy_assets=self.targets.copy_assets.isChecked())
        self.model.clear()
        self.inspector.show_row(None)
        self.inspector.batch.clear()
        self._total = self._completed = 0
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.report_btn.setEnabled(False)
        # existence of the target is checked by the dispatcher thread (no GUI-thread I/O)
        self.controller.start(Path(text), opts)

    def _cancel(self) -> None:
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setText("Cancelling…")
        self.controller.cancel()

    def _open_doctor(self) -> None:
        if self._doctor is None:
            self._doctor = DoctorDialog(self)
        else:
            self._doctor.refresh()
        self._doctor.show()
        self._doctor.raise_()

    @staticmethod
    def _open_path(path: Path) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    # ------------------------------------------------------------ events
    @Slot(list)
    def _on_events(self, events: list) -> None:
        from ..core.events import TaskCompleted, TaskDiscovered
        self._total += sum(isinstance(e, TaskDiscovered) for e in events)
        self._completed += sum(isinstance(e, TaskCompleted) for e in events)
        logged, batch_lines = self.model.apply(events)
        self.inspector.append_batch(batch_lines)
        self.progress.setRange(0, max(1, self._total))
        self.progress.setValue(self._completed)
        cur = self.inspector.current_id
        if cur is not None and cur in logged:
            self.inspector.refresh_live(self.model.row_for(cur))
        for e in events:
            if isinstance(e, BatchFinished) and e.report_path:
                self.report_path = Path(e.report_path)

    @Slot(object)
    def _on_finished(self, result) -> None:
        if isinstance(result, Exception):
            QMessageBox.critical(self, "Aperio", f"Batch crashed: {result}")
            return
        if isinstance(result, BatchFinished):
            self.report_path = result.report_path
            self.report_btn.setEnabled(result.report_path is not None)
            self.statusBar().showMessage(
                f"{'Cancelled' if result.cancelled else 'Finished'}: {result.total} files — "
                f"{result.succeeded} succeeded, {result.failed} failed, {result.skipped} skipped")

    @Slot(bool)
    def _on_running(self, running: bool) -> None:
        self.start_btn.setEnabled(not running)
        self.cancel_btn.setEnabled(running)
        self.cancel_btn.setText("Cancel All")
        if running:
            self.statusBar().showMessage("Running…")

    def _source_row(self, proxy_index: QModelIndex):
        if not proxy_index.isValid():
            return None
        src = self.proxy.mapToSource(proxy_index)
        return self.model.rows[src.row()]

    def _on_select(self, current: QModelIndex, _prev: QModelIndex) -> None:
        self.inspector.show_row(self._source_row(current))

    def _on_click(self, index: QModelIndex) -> None:
        row = self._source_row(index)
        if row and index.column() == COL_ACTION and row.status in ("Success", "Failed"):
            target = Path(row.output_path) if row.output_path else Path(row.out_dir)
            self._open_path(target if target.is_dir() else target.parent)

    def closeEvent(self, event) -> None:
        # Kill every running process tree (java.exe children included) before exit.
        self.controller.shutdown()
        super().closeEvent(event)

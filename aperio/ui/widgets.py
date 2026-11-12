"""Drop zone and target bar widgets."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
                               QLabel, QLineEdit, QPushButton, QSpinBox, QWidget)


class DropZone(QFrame):
    pathDropped = Signal(Path)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setObjectName("DropZone")
        self.setMinimumHeight(70)
        self._label = QLabel("Drop a binary or a folder here")
        self._label.setAlignment(Qt.AlignCenter)
        lay = QHBoxLayout(self)
        lay.addWidget(self._label)
        self._style(False)

    def _style(self, hover: bool) -> None:
        color = "#2f80ed" if hover else "#9aa3ad"
        self.setStyleSheet(f"#DropZone {{ border: 2px dashed {color}; border-radius: 8px; }}"
                           f"QLabel {{ color: {color}; font-size: 14px; }}")

    def set_text(self, text: str) -> None:
        self._label.setText(text)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and any(u.isLocalFile() for u in event.mimeData().urls()):
            event.acceptProposedAction()
            self._style(True)

    def dragLeaveEvent(self, event):
        self._style(False)

    def dropEvent(self, event):
        self._style(False)
        for url in event.mimeData().urls():
            if url.isLocalFile():
                self.pathDropped.emit(Path(url.toLocalFile()))
                event.acceptProposedAction()
                return


class TargetBar(QWidget):
    targetChanged = Signal(Path)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.target = QLineEdit()
        self.target.setPlaceholderText("Target file or folder")
        self.out = QLineEdit(str(Path.cwd() / "aperio_out"))
        pick_file = QPushButton("File…")
        pick_dir = QPushButton("Folder…")
        pick_out = QPushButton("Output…")
        self.timeout = QSpinBox()
        self.timeout.setRange(10, 24 * 3600)
        self.timeout.setValue(900)
        self.timeout.setSuffix(" s")
        self.timeout.setToolTip("Per-task timeout; the whole process tree is killed when exceeded")
        self.jobs = QSpinBox()
        self.jobs.setRange(1, 32)
        self.jobs.setValue(4)
        self.jobs.setToolTip("Fast pool size (CFR, jadx, ilspycmd, pycdc, asar)")
        self.heavy = QSpinBox()
        self.heavy.setRange(1, 2)
        self.heavy.setToolTip("Concurrent Ghidra analyzeHeadless instances")
        self.skip_native = QCheckBox("Skip Native (Ghidra)")
        self.copy_assets = QCheckBox("Copy assets")

        g = QGridLayout(self)
        g.setContentsMargins(0, 0, 0, 0)
        g.addWidget(QLabel("Target:"), 0, 0)
        g.addWidget(self.target, 0, 1, 1, 5)
        g.addWidget(pick_file, 0, 6)
        g.addWidget(pick_dir, 0, 7)
        g.addWidget(QLabel("Output:"), 1, 0)
        g.addWidget(self.out, 1, 1, 1, 6)
        g.addWidget(pick_out, 1, 7)
        opts = QHBoxLayout()
        for label, w in (("Timeout:", self.timeout), ("Jobs:", self.jobs), ("Ghidra slots:", self.heavy)):
            opts.addWidget(QLabel(label))
            opts.addWidget(w)
        opts.addSpacing(12)
        opts.addWidget(self.skip_native)
        opts.addWidget(self.copy_assets)
        opts.addStretch(1)
        g.addLayout(opts, 2, 0, 1, 8)

        pick_file.clicked.connect(self._pick_file)
        pick_dir.clicked.connect(self._pick_dir)
        pick_out.clicked.connect(self._pick_out)
        self.target.editingFinished.connect(
            lambda: self.target.text() and self.targetChanged.emit(Path(self.target.text())))

    def set_target(self, path: Path) -> None:
        self.target.setText(str(path))
        self.targetChanged.emit(path)

    def _pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select binary")
        if path:
            self.set_target(Path(path))

    def _pick_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Select folder")
        if path:
            self.set_target(Path(path))

    def _pick_out(self):
        path = QFileDialog.getExistingDirectory(self, "Select output folder", self.out.text())
        if path:
            self.out.setText(path)

"""Bridge between the core dispatcher (worker threads) and the Qt GUI thread.

Core events are appended to a deque from any thread (cheap, never touches Qt
objects). A GUI-thread QTimer drains the deque every 16 ms and emits ONE
batched `eventsReady(list)` signal, keeping the UI at ~60 FPS even when tools
produce thousands of log lines per second.
"""
from __future__ import annotations

from collections import deque
from pathlib import Path

from PySide6.QtCore import QObject, QThread, QTimer, Signal, Slot

from ..core import procutil
from ..core.dispatcher import Dispatcher
from ..core.events import BatchFinished
from ..core.models import DispatchOptions

MAX_EVENTS_PER_TICK = 4000


class DispatchWorker(QObject):
    """Lives in a QThread; runs the blocking Dispatcher.run()."""
    finished = Signal(object)

    def __init__(self, dispatcher: Dispatcher):
        super().__init__()
        self.dispatcher = dispatcher

    @Slot()
    def run(self) -> None:
        result = None
        try:
            result = self.dispatcher.run()
        except Exception as exc:  # surface crashes instead of hanging the UI
            result = exc
        self.finished.emit(result)


class BatchController(QObject):
    eventsReady = Signal(list)
    batchFinished = Signal(object)      # BatchFinished | Exception | None
    runningChanged = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._queue: deque = deque()
        self._thread: QThread | None = None
        self._worker: DispatchWorker | None = None
        self.dispatcher: Dispatcher | None = None
        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._drain)
        self._timer.start()

    # called from ANY thread
    def _push(self, event) -> None:
        self._queue.append(event)

    @Slot()
    def _drain(self) -> None:
        if not self._queue:
            return
        batch = []
        q = self._queue
        while q and len(batch) < MAX_EVENTS_PER_TICK:
            batch.append(q.popleft())
        self.eventsReady.emit(batch)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    def start(self, target: Path, options: DispatchOptions) -> None:
        if self.running:
            return
        self.dispatcher = Dispatcher(target, options)
        self.dispatcher.subscribe(self._push)
        self._thread = QThread()
        self._thread.setObjectName("aperio-dispatcher")
        self._worker = DispatchWorker(self.dispatcher)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_finished)
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.start()
        self.runningChanged.emit(True)

    @Slot(object)
    def _on_finished(self, result) -> None:
        self._drain_all()
        self.batchFinished.emit(result if isinstance(result, (BatchFinished, Exception)) else None)
        self.runningChanged.emit(False)

    def _drain_all(self) -> None:
        while self._queue:
            self._drain()

    def cancel(self) -> None:
        """Cancel All: stop queued work and kill every running process tree."""
        if self.dispatcher:
            self.dispatcher.cancel()   # sets cancel_event + procutil.kill_all()
        else:
            procutil.kill_all()

    def shutdown(self, wait_ms: int = 8000) -> None:
        """Window close: cancel, kill trees, wait briefly for the worker thread."""
        self.cancel()
        procutil.kill_all()
        if self._thread is not None and self._thread.isRunning():
            self._thread.quit()
            self._thread.wait(wait_ms)

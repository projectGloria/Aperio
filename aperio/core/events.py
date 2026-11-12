"""Structured events emitted by the dispatcher and a thread-safe bus."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Union


@dataclass(frozen=True)
class TaskDiscovered:
    task_id: int
    rel_path: str
    detected_format: str
    plugin_name: str
    status: str
    metadata: dict = field(default_factory=dict)
    out_dir: str = ""


@dataclass(frozen=True)
class TaskStarted:
    task_id: int
    plugin_name: str


@dataclass(frozen=True)
class TaskLog:
    task_id: int | None      # None = batch-level message
    stream: str              # "stdout" | "stderr" | "cmd" | "info"
    line: str


@dataclass(frozen=True)
class TaskCompleted:
    task_id: int
    status: str              # TaskStatus value
    status_text: str         # including reason, e.g. "Skipped (Missing Tool: CFR)"
    duration: float
    output_path: str = ""
    error: str = ""


@dataclass(frozen=True)
class BatchFinished:
    total: int
    succeeded: int
    failed: int
    skipped: int
    report_path: Path | None
    cancelled: bool = False


Event = Union[TaskDiscovered, TaskStarted, TaskLog, TaskCompleted, BatchFinished]
Listener = Callable[[Event], None]


class EventBus:
    """Fan-out of events to listeners. Listeners are invoked on the emitting
    thread and must be cheap and thread-safe (e.g. push onto a queue)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._listeners: list[Listener] = []

    def subscribe(self, listener: Listener) -> None:
        with self._lock:
            self._listeners.append(listener)

    def emit(self, event: Event) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(event)
            except Exception:  # a broken listener must never kill a worker
                pass

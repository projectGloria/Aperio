"""Batch dispatcher: scan -> detect -> two-pool execution -> REPORT.md.

`Dispatcher.run()` is blocking and meant to run on a background thread (CLI
main thread or a GUI QThread). It communicates exclusively via EventBus events.
"""
from __future__ import annotations

import shutil
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from pathlib import Path

from . import procutil, report, scanner
from .detector import classify
from .events import (BatchFinished, EventBus, TaskCompleted, TaskDiscovered, TaskLog,
                     TaskStarted)
from .models import DispatchOptions, Task, TaskStatus


class Dispatcher:
    def __init__(self, target: Path, options: DispatchOptions, plugins=None,
                 bus: EventBus | None = None):
        if plugins is None:
            from ..plugins import all_plugins
            plugins = all_plugins()
        self.target = Path(target)
        self.options = options
        self.plugins = sorted(plugins, key=lambda p: p.priority)
        self.bus = bus or EventBus()
        self.cancel_event = threading.Event()
        self.tasks: list[Task] = []
        self._plugin_of: dict[int, object] = {}
        self._availability: dict[str, tuple[bool, str]] = {}
        self._hinted: set[str] = set()
        self._lock = threading.Lock()
        self._heavy_sem = threading.BoundedSemaphore(max(1, min(2, options.heavy_jobs)))

    # ------------------------------------------------------------- control
    def subscribe(self, listener) -> None:
        self.bus.subscribe(listener)

    def cancel(self) -> None:
        """Cancel queued work and kill every running process tree."""
        self.cancel_event.set()
        procutil.kill_all()

    def _log(self, task_id, stream, line) -> None:
        self.bus.emit(TaskLog(task_id, stream, line))

    # ---------------------------------------------------------------- scan
    def _discover(self) -> None:
        out_root = self.options.out_dir.resolve()
        entries = scanner.enumerate_target(self.target, exclude=out_root)
        single = self.target.is_file()
        for i, entry in enumerate(entries):
            if self.cancel_event.is_set():
                break
            task = Task(task_id=i, path=entry.path, rel_path=entry.rel_path,
                        out_dir=scanner.output_dir_for(out_root, entry.rel_path))
            try:
                plugin, info = classify(entry.path, self.plugins)
                task.metadata = info.metadata()
            except OSError as exc:
                plugin, info = None, None
                task.status, task.reason, task.error = TaskStatus.SKIPPED, "Unreadable", str(exc)
            if plugin is not None:
                task.detected_format = plugin.describe(info)
                task.plugin_name = plugin.name
                task.pool = plugin.pool
                self._plugin_of[task.task_id] = plugin
                if not single and scanner.is_electron_stub(entry, info.is_native
                                                           and plugin.pool == "heavy"):
                    task.status, task.reason = TaskStatus.SKIPPED, "Electron Runtime Stub"
                elif plugin.pool == "heavy" and self.options.skip_native:
                    task.status, task.reason = TaskStatus.SKIPPED, "Native Disabled"
            elif info is not None:
                task.detected_format = "Asset"
                task.status, task.reason = TaskStatus.SKIPPED, "Non-executable/Asset"
            self.tasks.append(task)
            self.bus.emit(TaskDiscovered(task.task_id, task.rel_path.as_posix(),
                                         task.detected_format, task.plugin_name,
                                         task.status_text, dict(task.metadata),
                                         str(task.out_dir)))

    def _availability_of(self, plugin) -> tuple[bool, str]:
        with self._lock:
            if plugin.key not in self._availability:
                self._availability[plugin.key] = plugin.is_available()
            ok, where = self._availability[plugin.key]
            if not ok and plugin.key not in self._hinted:
                self._hinted.add(plugin.key)
                self._log(None, "info", f"[missing tool] {plugin.key}: {where}. "
                                        f"Install: {plugin.install_hint()}")
            return ok, where

    # ----------------------------------------------------------------- run
    def _finish(self, task: Task, started: float | None = None) -> None:
        if started is not None:
            task.duration = time.monotonic() - started
        self.bus.emit(TaskCompleted(task.task_id, task.status.value, task.status_text,
                                    task.duration, str(task.output_path or ""), task.error))

    def _execute(self, task: Task) -> None:
        plugin = self._plugin_of[task.task_id]
        if self.cancel_event.is_set():
            task.status, task.reason = TaskStatus.SKIPPED, "Cancelled"
            return self._finish(task)
        ok, _ = self._availability_of(plugin)
        if not ok:
            task.status, task.reason = TaskStatus.SKIPPED, f"Missing Tool: {plugin.key}"
            return self._finish(task)
        sem = self._heavy_sem if plugin.pool == "heavy" else None
        if sem:
            sem.acquire()
        started = time.monotonic()
        try:
            if self.cancel_event.is_set():
                task.status, task.reason = TaskStatus.SKIPPED, "Cancelled"
                return self._finish(task)
            task.status = TaskStatus.RUNNING
            self.bus.emit(TaskStarted(task.task_id, plugin.name))
            log = lambda stream, line, tid=task.task_id: self._log(tid, stream, line)  # noqa: E731
            result = plugin.run(task.path, task.out_dir, self.options.timeout,
                                self.cancel_event, log)
            task.output_path = result.output_path
            if result.success:
                task.status = TaskStatus.SUCCESS
                task.reason = result.notes
            else:
                task.status, task.error = TaskStatus.FAILED, result.error
                task.reason = ("Cancelled" if result.cancelled
                               else "Timeout" if result.timed_out else "")
        except Exception as exc:  # plugin bug must not take the batch down
            task.status, task.error = TaskStatus.FAILED, f"{type(exc).__name__}: {exc}"
            self._log(task.task_id, "stderr", task.error)
        finally:
            if sem:
                sem.release()
        self._finish(task, started)

    def _copy_asset(self, task: Task) -> None:
        dst = self.options.out_dir / task.rel_path
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(task.path, dst)
            task.output_path = dst
        except OSError as exc:
            task.error = f"copy failed: {exc}"

    def run(self) -> BatchFinished:
        self.options.out_dir.mkdir(parents=True, exist_ok=True)
        if self.target.exists():
            self._log(None, "info", f"Scanning {self.target} ...")
            self._discover()
        else:
            self._log(None, "info", f"Target does not exist: {self.target}")
        for t in self.tasks:  # resolve tool availability once per tool, before queueing
            if t.status == TaskStatus.QUEUED:
                plugin = self._plugin_of[t.task_id]
                if not self._availability_of(plugin)[0]:
                    t.status, t.reason = TaskStatus.SKIPPED, f"Missing Tool: {plugin.key}"
        runnable = [t for t in self.tasks if t.status == TaskStatus.QUEUED]
        self._log(None, "info", f"Discovered {len(self.tasks)} files, {len(runnable)} to process")
        for t in self.tasks:
            if t.status == TaskStatus.SKIPPED:
                if t.reason == "Non-executable/Asset" and self.options.copy_assets:
                    self._copy_asset(t)
                self._finish(t)
        fast = ThreadPoolExecutor(max_workers=max(1, self.options.jobs),
                                  thread_name_prefix="aperio-fast")
        heavy = ThreadPoolExecutor(max_workers=max(1, min(2, self.options.heavy_jobs)),
                                   thread_name_prefix="aperio-heavy")
        futures: list[Future] = []
        try:
            for t in runnable:
                pool = heavy if t.pool == "heavy" else fast
                futures.append(pool.submit(self._execute, t))
            pending = set(futures)
            while pending:
                _done, pending = wait(pending, timeout=0.25)
        finally:
            fast.shutdown(wait=True, cancel_futures=self.cancel_event.is_set())
            heavy.shutdown(wait=True, cancel_futures=self.cancel_event.is_set())
        for t in runnable:  # tasks whose futures were cancelled before starting
            if t.status == TaskStatus.QUEUED:
                t.status, t.reason = TaskStatus.SKIPPED, "Cancelled"
                self._finish(t)
        report_path = report.write_report(self.options.out_dir, self.target, self.tasks,
                                          cancelled=self.cancel_event.is_set())
        counts = report.counts(self.tasks)
        done = BatchFinished(len(self.tasks), counts["Success"], counts["Failed"],
                             counts["Skipped"], report_path, self.cancel_event.is_set())
        self.bus.emit(done)
        return done

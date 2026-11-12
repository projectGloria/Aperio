"""DecompilerPlugin contract shared by every format handler."""
from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Sequence

from ..core import procutil
from ..core.detector import FileInfo, analyze
from ..core.models import PluginResult

LogFn = Callable[[str, str], None]  # (stream, line)

__all__ = ["DecompilerPlugin", "PluginResult", "LogFn", "Deadline"]


class Deadline:
    """Shared time budget across the stages of a multi-step pipeline."""

    def __init__(self, seconds: float):
        self.end = time.monotonic() + seconds

    def remaining(self) -> float:
        return max(1.0, self.end - time.monotonic())


class DecompilerPlugin(ABC):
    priority: int = 100
    name: str = "plugin"
    tool_key: str = ""          # missing-tool dedup key (defaults to name)
    pool: str = "fast"          # "fast" or "heavy"
    portable: bool = False      # can be downloaded by --setup into ./tools_bin

    @property
    def key(self) -> str:
        return self.tool_key or self.name

    # ------------------------------------------------------------ contract
    @abstractmethod
    def detect(self, file_path: Path, header_bytes: bytes) -> bool: ...

    @abstractmethod
    def is_available(self) -> tuple[bool, str]: ...

    @abstractmethod
    def install_hint(self) -> str: ...

    @abstractmethod
    def run(self, file_path: Path, out_dir: Path, timeout: int,
            cancel_event: threading.Event, log: LogFn | None = None) -> PluginResult: ...

    def describe(self, info: FileInfo) -> str:
        """Human-readable detected format (shown in UI and report)."""
        return self.name

    def version(self) -> str:
        """Version string for the doctor (may spawn a process; never call on GUI thread)."""
        return ""

    # ------------------------------------------------------------- helpers
    @staticmethod
    def info(file_path: Path) -> FileInfo:
        return analyze(file_path)

    @staticmethod
    def exec(cmd: Sequence[str | Path], timeout: float, cancel_event: threading.Event,
             log: LogFn | None, cwd: Path | None = None) -> procutil.ProcResult:
        return procutil.run(cmd, timeout=timeout, cancel_event=cancel_event,
                            cwd=cwd, on_line=log)

    @staticmethod
    def failure(res: procutil.ProcResult, timeout: float) -> PluginResult:
        if res.cancelled:
            msg = "Cancelled by user (process tree killed)"
        elif res.timed_out:
            msg = f"Timed out after {int(timeout)}s (process tree killed)"
        else:
            tail = [ln for ln in (res.stderr or res.stdout).splitlines() if ln.strip()][-6:]
            msg = f"exit code {res.returncode}: " + " | ".join(tail)
        return PluginResult(False, error=msg[:1500], commands=[res.command],
                            stdout=res.stdout, stderr=res.stderr,
                            cancelled=res.cancelled, timed_out=res.timed_out)

    @staticmethod
    def has_output(path: Path) -> bool:
        return path.exists() and any(p.is_file() for p in path.rglob("*"))

"""Plain data models shared by core, plugins, CLI and UI."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path


class TaskStatus(str, enum.Enum):
    QUEUED = "Queued"
    RUNNING = "Running"
    SUCCESS = "Success"
    FAILED = "Failed"
    SKIPPED = "Skipped"


@dataclass
class PluginResult:
    success: bool
    output_path: Path | None = None
    error: str = ""
    commands: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    notes: str = ""
    cancelled: bool = False
    timed_out: bool = False


@dataclass
class Task:
    task_id: int
    path: Path
    rel_path: Path
    out_dir: Path
    detected_format: str = "Unknown"
    plugin_name: str = "-"
    status: TaskStatus = TaskStatus.QUEUED
    reason: str = ""                       # e.g. "Missing Tool: CFR"
    duration: float = 0.0
    output_path: Path | None = None
    error: str = ""
    metadata: dict = field(default_factory=dict)
    pool: str = "fast"

    @property
    def status_text(self) -> str:
        return f"{self.status.value} ({self.reason})" if self.reason else self.status.value


@dataclass
class DispatchOptions:
    out_dir: Path
    jobs: int = 4
    heavy_jobs: int = 1
    timeout: int = 900
    skip_native: bool = False
    copy_assets: bool = False

"""REPORT.md generation."""
from __future__ import annotations

import datetime as _dt
import os
from collections import Counter
from pathlib import Path

from .models import Task, TaskStatus


def _cell(text: object, limit: int = 220) -> str:
    s = str(text).replace("\r", " ").replace("\n", " ").replace("|", "\\|").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def counts(tasks: list[Task]) -> dict[str, int]:
    c = Counter(t.status.value for t in tasks)
    return {s.value: c.get(s.value, 0) for s in TaskStatus}


def write_report(out_dir: Path, target: Path, tasks: list[Task], cancelled: bool = False) -> Path:
    out_dir = Path(out_dir)
    c = counts(tasks)
    skipped_by_reason = Counter(t.reason or "Unspecified" for t in tasks
                                if t.status == TaskStatus.SKIPPED)
    failed_by_reason = Counter(t.reason or "Tool error" for t in tasks
                               if t.status == TaskStatus.FAILED)
    lines = [
        "# Aperio Report", "",
        f"- **Target:** `{target}`",
        f"- **Generated:** {_dt.datetime.now().isoformat(timespec='seconds')}",
        f"- **Batch state:** {'CANCELLED' if cancelled else 'complete'}", "",
        "## Summary", "",
        "| Metric | Count |", "|---|---:|",
        f"| Total | {len(tasks)} |",
        f"| Succeeded | {c['Success']} |",
        f"| Failed | {c['Failed']} |",
        f"| Skipped | {c['Skipped']} |",
    ]
    for reason, n in sorted(skipped_by_reason.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| &nbsp;&nbsp;Skipped — {_cell(reason, 80)} | {n} |")
    for reason, n in sorted(failed_by_reason.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| &nbsp;&nbsp;Failed — {_cell(reason, 80)} | {n} |")
    by_format = Counter(t.detected_format for t in tasks)
    lines += ["", "## Formats detected", "", "| Format | Files |", "|---|---:|"]
    lines += [f"| {_cell(f, 80)} | {n} |" for f, n in by_format.most_common()]
    lines += ["", "## Files", "",
              "| File | Detected Format | Plugin Used | Duration | Status | Output Path / Error Excerpt |",
              "|---|---|---|---:|---|---|"]
    for t in sorted(tasks, key=lambda t: t.rel_path.as_posix().lower()):
        if t.status == TaskStatus.FAILED:
            detail = t.error or "-"
        elif t.output_path:
            try:
                detail = "`" + Path(os.path.relpath(t.output_path, out_dir)).as_posix() + "`"
            except ValueError:
                detail = f"`{t.output_path}`"
        else:
            detail = t.error or "-"
        dur = f"{t.duration:.1f}s" if t.duration else "-"
        lines.append(f"| `{_cell(t.rel_path.as_posix(), 160)}` | {_cell(t.detected_format, 60)} "
                     f"| {_cell(t.plugin_name, 30)} | {dur} | {_cell(t.status_text, 90)} "
                     f"| {_cell(detail)} |")
    path = out_dir / "REPORT.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path

"""Headless CLI front-end and argument routing."""
from __future__ import annotations

import argparse
import sys
import threading
from pathlib import Path

from . import __version__
from .config import consume_first_run_notice
from .core.events import BatchFinished, TaskCompleted, TaskDiscovered, TaskLog


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aperio", description="Aperio - binary inspection & decompiler dispatcher")
    p.add_argument("target", nargs="?", type=Path, help="file or directory to process (CLI mode)")
    p.add_argument("--ui", action="store_true", help="launch the desktop GUI")
    p.add_argument("--out", type=Path, default=Path("aperio_out"), help="output directory")
    p.add_argument("--jobs", type=int, default=4, help="fast pool size (default 4)")
    p.add_argument("--heavy-jobs", type=int, choices=(1, 2), default=1,
                   help="concurrent Ghidra instances (default 1)")
    p.add_argument("--timeout", type=int, default=900, help="per-task timeout in seconds")
    p.add_argument("--skip-native", action="store_true", help="do not run Ghidra")
    p.add_argument("--copy-assets", action="store_true",
                   help="copy non-executable files into the output tree")
    p.add_argument("-v", "--verbose", action="store_true", help="stream tool stdout/stderr")
    p.add_argument("--doctor", action="store_true", help="print toolchain health table")
    p.add_argument("--setup", action="store_true",
                   help="download portable tools into ./tools_bin and print install commands")
    p.add_argument("--version", action="version", version=f"Aperio {__version__}")
    return p


class _Printer:
    def __init__(self, verbose: bool):
        self.verbose = verbose
        self.lock = threading.Lock()
        self.total = 0
        self.done = 0
        self.rows: dict[int, TaskDiscovered] = {}

    def __call__(self, ev) -> None:
        with self.lock:
            if isinstance(ev, TaskDiscovered):
                self.total += 1
                self.rows[ev.task_id] = ev
            elif isinstance(ev, TaskLog):
                if ev.task_id is None:
                    print(f"[aperio] {ev.line}", flush=True)
                elif self.verbose:
                    print(f"    #{ev.task_id} {ev.stream}: {ev.line}", flush=True)
            elif isinstance(ev, TaskCompleted):
                self.done += 1
                d = self.rows.get(ev.task_id)
                name = d.rel_path if d else ev.task_id
                fmt = f"{d.detected_format} -> {d.plugin_name}" if d else ""
                width = len(str(self.total))
                print(f"[{self.done:>{width}}/{self.total}] {ev.status_text:<38} "
                      f"{ev.duration:6.1f}s  {name}  ({fmt})", flush=True)
                if ev.error:
                    print(f"      error: {ev.error[:300]}", flush=True)
            elif isinstance(ev, BatchFinished):
                print(f"\nTotal {ev.total} | Succeeded {ev.succeeded} | Failed {ev.failed} | "
                      f"Skipped {ev.skipped}{' | CANCELLED' if ev.cancelled else ''}")
                if ev.report_path:
                    print(f"Report: {ev.report_path}")


def run_cli(args: argparse.Namespace) -> int:
    from .core.dispatcher import Dispatcher
    from .core.models import DispatchOptions
    if not args.target.exists():
        print(f"error: {args.target} does not exist", file=sys.stderr)
        return 2
    opts = DispatchOptions(out_dir=args.out.resolve(), jobs=max(1, args.jobs),
                           heavy_jobs=args.heavy_jobs, timeout=max(5, args.timeout),
                           skip_native=args.skip_native, copy_assets=args.copy_assets)
    dispatcher = Dispatcher(args.target, opts)
    dispatcher.subscribe(_Printer(args.verbose))
    result: list[BatchFinished] = []
    worker = threading.Thread(target=lambda: result.append(dispatcher.run()),
                              name="aperio-dispatcher", daemon=True)
    worker.start()
    try:
        while worker.is_alive():
            worker.join(timeout=0.2)
    except KeyboardInterrupt:
        print("\n[aperio] Cancelling - killing running process trees ...", flush=True)
        dispatcher.cancel()
        worker.join(timeout=60)
    if not result:
        return 130
    return 1 if result[0].failed else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.ui or not (args.target or args.doctor or args.setup):
        from .ui.app import run_gui  # imported lazily: CLI never needs PySide6
        return run_gui()
    notice = consume_first_run_notice()
    if notice:
        print(notice + "\n")
    if args.doctor:
        from .core.doctor import doctor_rows, format_doctor_table
        print(format_doctor_table(doctor_rows()))
        return 0
    if args.setup:
        from .core.doctor import run_setup
        return run_setup()
    return run_cli(args)

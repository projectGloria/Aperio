"""Subprocess execution with timeout, cancellation and process-TREE killing.

Launchers such as analyzeHeadless.bat / jadx.bat / npx.cmd spawn a child
java.exe / node.exe. Killing only the launcher would orphan the child, so every
tool runs in its own process group and is torn down with
`taskkill /F /T` (Windows) or `os.killpg` (POSIX).
"""
from __future__ import annotations

import atexit
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

IS_WINDOWS = os.name == "nt"
POLL_INTERVAL = 0.1

_live_lock = threading.Lock()
_live: dict[int, subprocess.Popen] = {}


@dataclass
class ProcResult:
    returncode: int | None
    stdout: str
    stderr: str
    command: str
    timed_out: bool = False
    cancelled: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.cancelled


def format_command(cmd: Sequence[str]) -> str:
    if IS_WINDOWS:
        return subprocess.list2cmdline([str(c) for c in cmd])
    return shlex.join(str(c) for c in cmd)


def _quote_for_cmd(arg: str) -> str:
    """Always double-quote (so & | < > ^ in file names stay literal for cmd.exe)
    using MSVCRT escaping rules for embedded quotes / trailing backslashes."""
    arg = re.sub(r'(\\*)"', r'\1\1\\"', arg)
    arg = re.sub(r"(\\+)$", r"\1\1", arg)
    return f'"{arg}"'


def _wrap_launcher(cmd: list[str]) -> list[str] | str:
    """.bat/.cmd launchers must run through cmd.exe. With /s, cmd strips the
    outermost quote pair, so the whole line is wrapped in one extra pair.
    Known cmd.exe limitation: `%NAME%` inside a path is still expanded."""
    if IS_WINDOWS and cmd and str(cmd[0]).lower().endswith((".bat", ".cmd")):
        inner = " ".join(_quote_for_cmd(c) for c in cmd)
        return f'{os.environ.get("COMSPEC", "cmd.exe")} /d /s /c "{inner}"'
    return cmd


def kill_tree(proc: subprocess.Popen) -> None:
    """Kill a process and all of its descendants."""
    if IS_WINDOWS:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            proc.kill()
        except OSError:
            pass
    else:
        try:
            pgid = os.getpgid(proc.pid)
        except ProcessLookupError:
            return
        for sig, grace in ((signal.SIGTERM, 2.0), (signal.SIGKILL, 0)):
            try:
                os.killpg(pgid, sig)
            except ProcessLookupError:
                return
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline and proc.poll() is None:
                time.sleep(0.05)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def kill_all() -> int:
    """Kill every process tree started by this module. Returns the count."""
    with _live_lock:
        procs = list(_live.values())
    for p in procs:
        kill_tree(p)
    return len(procs)


atexit.register(kill_all)


def _pump(stream, sink: list[str], name: str, on_line) -> None:
    for raw in iter(stream.readline, b""):
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        sink.append(line)
        if on_line:
            on_line(name, line)
    stream.close()


def run(cmd: Sequence[str | Path], *, timeout: float, cancel_event: threading.Event,
        cwd: Path | None = None, on_line: Callable[[str, str], None] | None = None,
        env: dict | None = None) -> ProcResult:
    """Run `cmd`, streaming lines to `on_line(stream, line)`.

    Returns when the process exits, `timeout` elapses or `cancel_event` is set;
    in the latter two cases the whole process tree is killed first.
    """
    argv = _wrap_launcher([str(c) for c in cmd])
    command = format_command([str(c) for c in cmd])
    if on_line:
        on_line("cmd", command)
    kwargs: dict = {"cwd": str(cwd) if cwd else None, "stdin": subprocess.DEVNULL,
                    "stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "env": env}
    if IS_WINDOWS:
        kwargs["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP
                                   | subprocess.CREATE_NO_WINDOW)
    else:
        kwargs["start_new_session"] = True
    if cancel_event.is_set():
        return ProcResult(None, "", "", command, cancelled=True)
    try:
        proc = subprocess.Popen(argv, **kwargs)
    except OSError as exc:
        return ProcResult(None, "", f"failed to start: {exc}", command)
    with _live_lock:
        _live[proc.pid] = proc
    out: list[str] = []
    err: list[str] = []
    pumps = [threading.Thread(target=_pump, args=(proc.stdout, out, "stdout", on_line), daemon=True),
             threading.Thread(target=_pump, args=(proc.stderr, err, "stderr", on_line), daemon=True)]
    for t in pumps:
        t.start()
    deadline = time.monotonic() + timeout
    timed_out = cancelled = False
    try:
        while proc.poll() is None:
            if cancel_event.is_set():
                cancelled = True
                kill_tree(proc)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                kill_tree(proc)
                break
            cancel_event.wait(POLL_INTERVAL)
    finally:
        with _live_lock:
            _live.pop(proc.pid, None)
    for t in pumps:
        t.join(timeout=5)
    return ProcResult(proc.returncode, "\n".join(out), "\n".join(err), command,
                      timed_out=timed_out, cancelled=cancelled)


def python_cmd() -> list[str]:
    """Interpreter for helper scripts (works when frozen or in a venv)."""
    return [sys.executable]

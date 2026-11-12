"""Priorities 7/8: Go and generic native binaries -> Ghidra analyzeHeadless.

analyzeHeadless has no "export C" flag, so the bundled post-script
scripts/ExportDecompiled.java drives DecompInterface and writes a .c file.
Each run gets its own TemporaryDirectory project and -deleteProject, so a
killed or concurrent run never leaves a locked .gpr behind.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import threading
from pathlib import Path

from ..config import SCRIPTS_DIR
from ..core import detector, toolchain
from ..core.procutil import IS_WINDOWS
from .base import DecompilerPlugin, LogFn, PluginResult

POST_SCRIPT = "ExportDecompiled.java"

# Ghidra's launch.bat walks its arguments inside an `IF DEFINED ARG ( ... )`
# block that also contains unquoted `set X=%~1` lines. cmd.exe substitutes
# %~1 into the whole block before running it, so a ")" in any argument (such
# as "C:\Program Files (x86)\...") ends the block early, and cmd fails with
# "... was unexpected at this time". "!" is eaten by delayed expansion and
# "%" / "^" are expanded too. Quoting cannot fix this, so paths that contain
# these characters are copied to a safe temp location instead.
_LAUNCHER_UNSAFE = re.compile(r"[()!%^&<>|\"]")


def _is_launcher_safe(p: Path) -> bool:
    return not (IS_WINDOWS and _LAUNCHER_UNSAFE.search(str(p)))


def _launcher_safe(file_path: Path, stage_dir: Path, log: LogFn | None) -> Path:
    """Return `file_path`, or a hardlink/copy of it under `stage_dir` when the
    path would break analyzeHeadless.bat / launch.bat."""
    if _is_launcher_safe(file_path):
        return file_path
    stage_dir.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", file_path.name) or "input.bin"
    staged = stage_dir / name
    if not _is_launcher_safe(staged):
        raise OSError(f"temp dir {stage_dir} itself is not safe for cmd.exe")
    try:
        os.link(file_path, staged)
    except OSError:
        shutil.copy2(file_path, staged)
    if log:
        log("info", f"staged {file_path} -> {staged} (path unsafe for Ghidra's .bat launcher)")
    return staged


def _stage_dir(src: Path, dst: Path) -> Path:
    shutil.copytree(src, dst)
    if not _is_launcher_safe(dst):
        raise OSError(f"temp dir {dst} itself is not safe for cmd.exe")
    return dst


def ghidra_version() -> str:
    headless = toolchain.ghidra_headless()
    if not headless:
        return ""
    props = headless.parent.parent / "Ghidra" / "application.properties"
    try:
        for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("application.version="):
                return "Ghidra " + line.split("=", 1)[1].strip()
    except OSError:
        pass
    return "Ghidra (version unknown)"


class GhidraPlugin(DecompilerPlugin):
    priority = 80
    name = "Ghidra"
    tool_key = "Ghidra"
    pool = "heavy"
    portable = True

    def detect(self, file_path: Path, header_bytes: bytes) -> bool:
        return self.info(file_path).is_native

    def is_available(self) -> tuple[bool, str]:
        h = toolchain.ghidra_headless()
        if not h:
            return False, "analyzeHeadless not found (set GHIDRA_INSTALL_DIR)"
        if not (SCRIPTS_DIR / POST_SCRIPT).is_file():
            return False, f"missing post-script {SCRIPTS_DIR / POST_SCRIPT}"
        if not toolchain.java():
            return False, f"{h} found but no JDK on PATH / JAVA_HOME"
        return True, str(h)

    def install_hint(self) -> str:
        return ("python aperio.py --setup  (portable Ghidra + JDK 25 into ./tools_bin; "
                "or set GHIDRA_INSTALL_DIR to an existing install)")

    def version(self) -> str:
        return ghidra_version()

    def describe(self, info) -> str:
        n = info.native or {}
        return f"Native ({n.get('format')}, {n.get('arch')})"

    def run(self, file_path: Path, out_dir: Path, timeout: int,
            cancel_event: threading.Event, log: LogFn | None = None) -> PluginResult:
        headless = toolchain.ghidra_headless()
        if not headless:
            return PluginResult(False, error="Ghidra not available")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_c = out_dir / f"{file_path.name}.c"
        with tempfile.TemporaryDirectory(prefix="aperio_ghidra_",
                                         ignore_cleanup_errors=True) as tmp:
            work = Path(tmp)
            proj_dir = work / "proj"
            proj_dir.mkdir()
            try:
                src = _launcher_safe(file_path, work / "in", log)
                scripts = (SCRIPTS_DIR if _is_launcher_safe(SCRIPTS_DIR)
                           else _stage_dir(SCRIPTS_DIR, work / "scripts"))
            except OSError as exc:
                return PluginResult(False, error=f"could not stage input for Ghidra: {exc}")
            # The post-script writes to a safe temp path; it is moved afterwards.
            tmp_c = out_c if _is_launcher_safe(out_c) else work / "out.c"
            cmd = [str(headless), str(proj_dir), f"aperio_{os.getpid()}",
                   "-import", str(src),
                   "-scriptPath", str(scripts),
                   "-postScript", POST_SCRIPT, str(tmp_c),
                   "-analysisTimeoutPerFile", str(max(60, int(timeout * 0.8))),
                   "-deleteProject"]
            res = self.exec(cmd, timeout, cancel_event, log)
            if tmp_c != out_c and tmp_c.is_file():
                shutil.move(str(tmp_c), out_c)
        if res.cancelled or res.timed_out:
            return self.failure(res, timeout)
        if not out_c.is_file() or out_c.stat().st_size == 0:
            fail = self.failure(res, timeout)
            fail.error = "Ghidra produced no C output. " + fail.error
            return fail
        return PluginResult(True, output_path=out_c, commands=[res.command],
                            stdout=res.stdout, stderr=res.stderr)


class GoPlugin(GhidraPlugin):
    """Same Ghidra pipeline, but flagged distinctly as a Go binary."""
    priority = 70
    name = "Ghidra (Go)"

    def detect(self, file_path: Path, header_bytes: bytes) -> bool:
        return detector.is_go(self.info(file_path))

    def describe(self, info) -> str:
        return "Native (Go Binary)"

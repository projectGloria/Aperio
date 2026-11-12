"""Priorities 7/8: Go and generic native binaries -> Ghidra analyzeHeadless.

analyzeHeadless has no "export C" flag, so the bundled post-script
scripts/ExportDecompiled.java drives DecompInterface and writes a .c file.
Each run gets its own TemporaryDirectory project and -deleteProject, so a
killed or concurrent run never leaves a locked .gpr behind.
"""
from __future__ import annotations

import os
import tempfile
import threading
from pathlib import Path

from ..config import SCRIPTS_DIR
from ..core import detector, toolchain
from .base import DecompilerPlugin, LogFn, PluginResult

POST_SCRIPT = "ExportDecompiled.java"


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
                                         ignore_cleanup_errors=True) as proj_dir:
            cmd = [str(headless), proj_dir, f"aperio_{os.getpid()}",
                   "-import", str(file_path),
                   "-scriptPath", str(SCRIPTS_DIR),
                   "-postScript", POST_SCRIPT, str(out_c),
                   "-analysisTimeoutPerFile", str(max(60, int(timeout * 0.8))),
                   "-deleteProject"]
            res = self.exec(cmd, timeout, cancel_event, log)
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

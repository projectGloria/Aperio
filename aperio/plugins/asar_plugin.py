"""Priority 1: Electron ASAR archives -> @electron/asar extract."""
from __future__ import annotations

import threading
from pathlib import Path

from ..config import TOOLS_BIN
from ..core import detector, toolchain
from .base import DecompilerPlugin, LogFn, PluginResult

ASAR_PKG = "@electron/asar"
ASAR_JS = TOOLS_BIN / "asar" / "node_modules" / "@electron" / "asar" / "bin" / "asar.mjs"


def bundled_asar_js() -> Path | None:
    """@electron/asar installed by --setup into ./tools_bin/asar (entry is .mjs or .js)."""
    for cand in (ASAR_JS, ASAR_JS.with_suffix(".js")):
        if cand.is_file():
            return cand
    return None


class AsarPlugin(DecompilerPlugin):
    priority = 10
    name = "asar"

    def detect(self, file_path: Path, header_bytes: bytes) -> bool:
        return detector.asar_header(header_bytes) is not None

    portable = True

    def _base_cmd(self) -> list[str] | None:
        node, js = toolchain.bundled_node() or toolchain.which("node"), bundled_asar_js()
        if node and js:
            return [str(node), str(js)]
        asar = toolchain.which("asar")
        if asar:
            return [str(asar)]
        npx = toolchain.which("npx")
        if npx:
            return [str(npx), "--yes", "@electron/asar"]
        return None

    def is_available(self) -> tuple[bool, str]:
        cmd = self._base_cmd()
        return (True, " ".join(cmd)) if cmd else (False, "asar / npx not found")

    def install_hint(self) -> str:
        return ("python aperio.py --setup  (downloads portable Node.js and installs "
                "@electron/asar into ./tools_bin)")

    def version(self) -> str:
        cmd = self._base_cmd()
        return toolchain.probe_version(cmd + ["--version"], timeout=60) if cmd else ""

    def describe(self, info) -> str:
        n = info.asar_files
        return f"Electron ASAR ({n} entries)" if n is not None else "Electron ASAR"

    def run(self, file_path: Path, out_dir: Path, timeout: int,
            cancel_event: threading.Event, log: LogFn | None = None) -> PluginResult:
        cmd = self._base_cmd()
        if not cmd:
            return PluginResult(False, error="asar not available")
        out_dir.mkdir(parents=True, exist_ok=True)
        res = self.exec(cmd + ["extract", str(file_path), str(out_dir)],
                        timeout, cancel_event, log)
        if not res.ok:
            return self.failure(res, timeout)
        if not self.has_output(out_dir):
            return PluginResult(False, error="asar produced no files", commands=[res.command],
                                stdout=res.stdout, stderr=res.stderr)
        return PluginResult(True, output_path=out_dir, commands=[res.command],
                            stdout=res.stdout, stderr=res.stderr)

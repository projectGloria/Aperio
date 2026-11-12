"""Priority 3: .NET managed assemblies (PE + CLR header) -> ilspycmd."""
from __future__ import annotations

import threading
from pathlib import Path

from ..core import detector, toolchain
from .base import DecompilerPlugin, LogFn, PluginResult


class DotNetPlugin(DecompilerPlugin):
    priority = 30
    name = "ILSpy"

    def detect(self, file_path: Path, header_bytes: bytes) -> bool:
        if header_bytes[:2] != b"MZ":
            return False
        return detector.is_dotnet(self.info(file_path))

    def is_available(self) -> tuple[bool, str]:
        p = toolchain.which("ilspycmd")
        return (True, str(p)) if p else (False, "ilspycmd not found")

    def install_hint(self) -> str:
        return ("winget install Microsoft.DotNet.SDK.8  then  "
                "dotnet tool install -g ilspycmd   (adds %USERPROFILE%\\.dotnet\\tools to PATH)")

    def version(self) -> str:
        p = toolchain.which("ilspycmd")
        return toolchain.probe_version([str(p), "--version"]) if p else ""

    def describe(self, info) -> str:
        n = info.native or {}
        kind = "DLL" if n.get("is_dll") else "EXE"
        return f".NET Assembly ({n.get('format')} {kind}, {n.get('arch')})"

    def run(self, file_path: Path, out_dir: Path, timeout: int,
            cancel_event: threading.Event, log: LogFn | None = None) -> PluginResult:
        ilspy = toolchain.which("ilspycmd")
        if not ilspy:
            return PluginResult(False, error="ilspycmd not available")
        out_dir.mkdir(parents=True, exist_ok=True)
        res = self.exec([str(ilspy), "-p", "-o", str(out_dir), str(file_path)],
                        timeout, cancel_event, log)
        if not res.ok:
            return self.failure(res, timeout)
        if not any(out_dir.rglob("*.cs")):
            return PluginResult(False, error="ilspycmd produced no .cs files",
                                commands=[res.command], stdout=res.stdout, stderr=res.stderr)
        return PluginResult(True, output_path=out_dir, commands=[res.command],
                            stdout=res.stdout, stderr=res.stderr)

"""Priority 4: Android APK / Dalvik DEX -> jadx."""
from __future__ import annotations

import os
import threading
from pathlib import Path

from ..core import detector, toolchain
from .base import DecompilerPlugin, LogFn, PluginResult

JADX_VERSION = "1.5.1"
JADX_URL = (f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/"
            f"jadx-{JADX_VERSION}.zip")


def find_jadx() -> Path | None:
    return toolchain.which("jadx.bat", "jadx") if os.name == "nt" else toolchain.which("jadx")


class AndroidPlugin(DecompilerPlugin):
    priority = 40
    name = "jadx"
    portable = True

    def detect(self, file_path: Path, header_bytes: bytes) -> bool:
        if detector.is_dex(header_bytes):
            return True
        if header_bytes[:4] != b"PK\x03\x04":
            return False
        return detector.is_apk(self.info(file_path))

    def is_available(self) -> tuple[bool, str]:
        p = find_jadx()
        if not p:
            return False, "jadx not found"
        if not toolchain.java():
            return False, f"{p} found but java is missing"
        return True, str(p)

    def install_hint(self) -> str:
        return (f"python aperio.py --setup  (downloads portable jadx {JADX_VERSION} into "
                f"./tools_bin; needs Java 11+: winget install EclipseAdoptium.Temurin.21.JDK)")

    def version(self) -> str:
        p = find_jadx()
        return toolchain.probe_version([str(p), "--version"], timeout=60) if p else ""

    def describe(self, info) -> str:
        return "Dalvik DEX" if info.container == "DEX" else "Android APK"

    def run(self, file_path: Path, out_dir: Path, timeout: int,
            cancel_event: threading.Event, log: LogFn | None = None) -> PluginResult:
        jadx = find_jadx()
        if not jadx:
            return PluginResult(False, error="jadx not available")
        out_dir.mkdir(parents=True, exist_ok=True)
        res = self.exec([str(jadx), "-d", str(out_dir), str(file_path)],
                        timeout, cancel_event, log)
        if res.cancelled or res.timed_out:
            return self.failure(res, timeout)
        produced = self.has_output(out_dir / "sources") or self.has_output(out_dir)
        if res.returncode != 0 and not produced:
            return self.failure(res, timeout)
        notes = "" if res.returncode == 0 else "jadx finished with errors in some classes"
        return PluginResult(True, output_path=out_dir, commands=[res.command],
                            stdout=res.stdout, stderr=res.stderr, notes=notes)

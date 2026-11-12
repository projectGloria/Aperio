"""Priority 6: standalone Python bytecode -> pycdc."""
from __future__ import annotations

import threading
from pathlib import Path

from ..core import detector, toolchain
from .base import DecompilerPlugin, LogFn, PluginResult

PYCDC_HINT = ("pycdc has no official binaries. Build it: git clone https://github.com/zrax/pycdc "
              "&& cmake -S pycdc -B pycdc/build && cmake --build pycdc/build --config Release, "
              "then copy pycdc(.exe) into ./tools_bin (needs: winget install Kitware.CMake "
              "and a C++ compiler, e.g. winget install Microsoft.VisualStudio.2022.BuildTools)")


def find_pycdc() -> Path | None:
    return toolchain.which("pycdc")


def run_pycdc(plugin: DecompilerPlugin, pycdc: Path, src: Path, dst: Path, timeout: float,
              cancel_event: threading.Event, log: LogFn | None) -> PluginResult:
    """Decompile one .pyc; pycdc writes source to stdout which we save to `dst`."""
    res = plugin.exec([str(pycdc), str(src)], timeout, cancel_event, None)
    if log:
        log("cmd", res.command)
        for line in res.stderr.splitlines()[-30:]:
            log("stderr", line)
        log("info", f"pycdc wrote {len(res.stdout.splitlines())} lines -> {dst.name}")
    if res.cancelled or res.timed_out:
        return plugin.failure(res, timeout)
    if res.stdout.strip():
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(res.stdout + "\n", encoding="utf-8")
    if res.returncode != 0 or not res.stdout.strip():
        fail = plugin.failure(res, timeout)
        fail.output_path = dst if dst.exists() else None
        return fail
    incomplete = "Unsupported opcode" in res.stderr or "Decompyle incomplete" in res.stdout
    return PluginResult(True, output_path=dst, commands=[res.command], stdout="",
                        stderr=res.stderr,
                        notes="partial decompilation (unsupported opcodes)" if incomplete else "")


class PycPlugin(DecompilerPlugin):
    priority = 60
    name = "pycdc"

    def detect(self, file_path: Path, header_bytes: bytes) -> bool:
        return detector.pyc_info(header_bytes) is not None

    def is_available(self) -> tuple[bool, str]:
        p = find_pycdc()
        return (True, str(p)) if p else (False, "pycdc not found")

    def install_hint(self) -> str:
        return PYCDC_HINT

    def describe(self, info) -> str:
        return f"Python Bytecode ({info.pyc_version})"

    def version(self) -> str:
        p = find_pycdc()
        return toolchain.probe_version([str(p), "--help"]) if p else ""

    def run(self, file_path: Path, out_dir: Path, timeout: int,
            cancel_event: threading.Event, log: LogFn | None = None) -> PluginResult:
        pycdc = find_pycdc()
        if not pycdc:
            return PluginResult(False, error="pycdc not available")
        return run_pycdc(self, pycdc, file_path, out_dir / f"{file_path.stem}.py",
                         timeout, cancel_event, log)

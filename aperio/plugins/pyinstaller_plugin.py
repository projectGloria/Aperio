"""Priority 2: PyInstaller executables.

Stage 1: pyinstxtractor-ng (or ./tools_bin/pyinstxtractor.py) extracts the
CArchive (+ PYZ). Stage 2: entry-point .pyc files (not stdlib / bootstrap) are
header-repaired if needed and decompiled with pycdc.
"""
from __future__ import annotations

import re
import sys
import threading
from pathlib import Path

from ..core import detector, procutil, toolchain
from .base import Deadline, DecompilerPlugin, LogFn, PluginResult
from .pyc_plugin import PYCDC_HINT, find_pycdc, run_pycdc

PYINSTXTRACTOR_URL = ("https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/"
                      "master/pyinstxtractor.py")
_BOOTSTRAP_PREFIXES = ("pyiboot", "pyimod", "pyi_rth_", "pyi_", "_pyi_")
_ENTRY_RE = re.compile(r"Possible entry point:\s*(.+?)\s*$", re.M)
MAX_ENTRY_POINTS = 50


def _extractor_cmd() -> list[str] | None:
    ng = toolchain.which("pyinstxtractor-ng")
    if ng:
        return [str(ng)]
    script = toolchain.find_file("pyinstxtractor*.py")
    return procutil.python_cmd() + [str(script)] if script else None


def is_stdlib_or_bootstrap(name: str) -> bool:
    base = name.split(".")[0]
    return base.startswith(_BOOTSTRAP_PREFIXES) or base in sys.stdlib_module_names


def repair_pyc_header(pyc: Path, ref_magic: bytes | None) -> bool:
    """Prepend a 16-byte (3.7+) / 12-byte / 8-byte header to a raw marshalled
    code object. Returns True if the file was modified."""
    data = pyc.read_bytes()
    if detector.pyc_info(data[:64]) is not None or not data or data[0] not in (0x63, 0xE3):
        return False
    if not ref_magic:
        return False
    magic = int.from_bytes(ref_magic[:2], "little")
    pad = 12 if magic >= 3392 else 8 if magic >= 3230 else 4
    pyc.write_bytes(ref_magic[:4] + b"\0" * pad + data)
    return True


def find_reference_magic(root: Path) -> bytes | None:
    for pyc in root.rglob("*.pyc"):
        head = pyc.read_bytes()[:64]
        if detector.pyc_info(head):
            return head[:4]
    return None


class PyInstallerPlugin(DecompilerPlugin):
    priority = 20
    name = "PyInstaller"
    portable = True

    def detect(self, file_path: Path, header_bytes: bytes) -> bool:
        if header_bytes[:2] != b"MZ" and header_bytes[:4] != b"\x7fELF" \
                and header_bytes[:4] not in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
            return False
        return detector.is_pyinstaller(self.info(file_path))

    def is_available(self) -> tuple[bool, str]:
        cmd = _extractor_cmd()
        if not cmd:
            return False, "pyinstxtractor-ng / pyinstxtractor.py not found"
        pycdc = find_pycdc()
        return True, " ".join(cmd) + (f" + {pycdc}" if pycdc else " (pycdc missing: extract only)")

    def install_hint(self) -> str:
        return ("pip install pyinstxtractor-ng   (or: python aperio.py --setup to fetch "
                "pyinstxtractor.py)  +  pycdc for stage 2: " + PYCDC_HINT)

    def describe(self, info) -> str:
        n = info.native or {}
        return f"PyInstaller ({n.get('container')} {n.get('arch')})"

    def run(self, file_path: Path, out_dir: Path, timeout: int,
            cancel_event: threading.Event, log: LogFn | None = None) -> PluginResult:
        cmd = _extractor_cmd()
        if not cmd:
            return PluginResult(False, error="pyinstxtractor not available")
        deadline = Deadline(timeout)
        out_dir.mkdir(parents=True, exist_ok=True)
        res = self.exec(cmd + [str(file_path)], deadline.remaining(), cancel_event, log,
                        cwd=out_dir)
        if not res.ok:
            return self.failure(res, timeout)
        extracted = next((d for d in out_dir.iterdir()
                          if d.is_dir() and d.name.endswith("_extracted")), None)
        # pyinstxtractor exits 0 even for an empty/corrupt CArchive ("Found 0 files")
        if not extracted or not any(p.is_file() for p in extracted.rglob("*")):
            m = re.search(r"Found (\d+) files in CArchive", res.stdout)
            detail = f" (extractor reported {m.group(1)} files in CArchive)" if m else ""
            return PluginResult(False, error="extractor produced no files" + detail,
                                commands=[res.command], stdout=res.stdout, stderr=res.stderr)
        commands, notes = [res.command], []
        entries = [extracted / m for m in _ENTRY_RE.findall(res.stdout)]
        if not entries:
            entries = [p for p in extracted.glob("*.pyc")]
        entries = [p for p in entries if p.is_file() and not is_stdlib_or_bootstrap(p.name)]
        entries = entries[:MAX_ENTRY_POINTS]
        ref = find_reference_magic(extracted)
        for e in entries:
            if repair_pyc_header(e, ref) and log:
                log("info", f"repaired missing .pyc header on {e.name}")
        pycdc = find_pycdc()
        if not pycdc:
            notes.append("stage 2 skipped: pycdc not installed")
            if log:
                log("info", "pycdc not found - extraction only. " + PYCDC_HINT)
        else:
            decomp_dir = out_dir / "decompiled"
            ok = 0
            for e in entries:
                if cancel_event.is_set():
                    break
                r = run_pycdc(self, pycdc, e, decomp_dir / (e.stem + ".py"),
                              deadline.remaining(), cancel_event, log)
                commands += r.commands
                if r.cancelled or r.timed_out:
                    r.commands = commands
                    return r
                ok += r.success
            notes.append(f"pycdc decompiled {ok}/{len(entries)} entry point(s)")
        if cancel_event.is_set():
            return PluginResult(False, error="Cancelled by user", cancelled=True, commands=commands)
        return PluginResult(True, output_path=out_dir, commands=commands, stdout=res.stdout,
                            stderr=res.stderr, notes="; ".join(notes))

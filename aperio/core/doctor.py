"""Toolchain health (--doctor) and portable tool installation (--setup)."""
from __future__ import annotations

import shutil
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..config import TOOLS_BIN
from . import toolchain


@dataclass
class DoctorRow:
    name: str
    formats: str
    available: bool
    location: str
    version: str
    hint: str
    portable: bool


FORMATS = {"asar": "Electron ASAR", "PyInstaller": "PyInstaller EXE/ELF",
           "ILSpy": ".NET assemblies", "jadx": "APK / DEX", "CFR": "class / JAR / WAR",
           "pycdc": "Python .pyc", "Ghidra (Go)": "Go binaries", "Ghidra": "PE / ELF / Mach-O"}


def _portable_downloads() -> dict[str, list[tuple[str, str, str | None]]]:
    """plugin name -> [(url, filename in tools_bin, extract-to subdir or None)]"""
    from ..plugins.android_plugin import JADX_URL
    from ..plugins.java_plugin import CFR_URL
    from ..plugins.pyinstaller_plugin import PYINSTXTRACTOR_URL
    return {
        "CFR": [(CFR_URL, CFR_URL.rsplit("/", 1)[1], None)],
        "jadx": [(JADX_URL, "jadx.zip", "jadx")],
        "PyInstaller": [(PYINSTXTRACTOR_URL, "pyinstxtractor.py", None)],
    }


def doctor_rows(plugins=None, with_versions: bool = True) -> list[DoctorRow]:
    if plugins is None:
        from ..plugins import all_plugins
        plugins = all_plugins()
    rows, seen = [], set()
    for p in plugins:
        if p.name in seen:
            continue
        seen.add(p.name)
        ok, where = p.is_available()
        version = p.version() if (ok and with_versions) else ""
        rows.append(DoctorRow(p.name, FORMATS.get(p.name, ""), ok, where, version,
                              p.install_hint(), p.name in _portable_downloads()))
    for label, finder, hint in (
            ("java (runtime)", toolchain.java, "winget install EclipseAdoptium.Temurin.21.JDK"),
            ("node/npx (runtime)", lambda: toolchain.which("npx"), "winget install OpenJS.NodeJS.LTS"),
            ("dotnet (runtime)", lambda: toolchain.which("dotnet"), "winget install Microsoft.DotNet.SDK.8")):
        path = finder()
        ver = ""
        if path and with_versions:
            args = ["-version"] if label.startswith("java") else ["--version"]
            ver = toolchain.probe_version([str(path), *args])
        rows.append(DoctorRow(label, "prerequisite", bool(path), str(path or "not found"),
                              ver, hint, False))
    return rows


def format_doctor_table(rows: list[DoctorRow]) -> str:
    headers = ("Plugin / Tool", "Formats", "Status", "Location", "Version")
    data = [(r.name, r.formats, "OK" if r.available else "MISSING",
             r.location[:72], r.version[:44]) for r in rows]
    widths = [max(len(h), *(len(d[i]) for d in data)) for i, h in enumerate(headers)]
    sep = "+".join("-" * (w + 2) for w in widths)
    out = [" | ".join(h.ljust(w) for h, w in zip(headers, widths)), sep]
    out += [" | ".join(c.ljust(w) for c, w in zip(d, widths)) for d in data]
    missing = [r for r in rows if not r.available]
    if missing:
        out += ["", "Install hints:"]
        out += [f"  - {r.name}: {r.hint}" for r in missing]
    return "\n".join(out)


def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    dest = dest.resolve()
    for member in zf.infolist():
        target = (dest / member.filename).resolve()
        if dest != target and dest not in target.parents:
            raise ValueError(f"unsafe path in archive: {member.filename}")
    zf.extractall(dest)


def download_portable(plugin_name: str, log: Callable[[str], None] = print) -> bool:
    """Download a portable tool into ./tools_bin. Returns True on success."""
    items = _portable_downloads().get(plugin_name)
    if not items:
        log(f"{plugin_name}: no portable download available")
        return False
    TOOLS_BIN.mkdir(parents=True, exist_ok=True)
    for url, filename, extract_to in items:
        dest = TOOLS_BIN / filename
        log(f"Downloading {url} -> {dest}")
        tmp = dest.with_suffix(dest.suffix + ".part")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Aperio-setup"})
            with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as f:
                shutil.copyfileobj(resp, f, length=1 << 16)
            if tmp.stat().st_size == 0:
                raise OSError("empty download")
            tmp.replace(dest)
            if extract_to:
                target = TOOLS_BIN / extract_to
                with zipfile.ZipFile(dest) as zf:
                    _safe_extract(zf, target)
                dest.unlink()
                for script in (target / "bin").glob("jadx*"):
                    script.chmod(script.stat().st_mode | 0o111)
                log(f"Extracted to {target}")
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            log(f"FAILED {url}: {exc}")
            tmp.unlink(missing_ok=True)
            return False
    log(f"{plugin_name}: installed into {TOOLS_BIN}")
    return True


def run_setup(log: Callable[[str], None] = print) -> int:
    log(f"Portable tools -> {TOOLS_BIN}")
    failures = sum(not download_portable(name, log) for name in _portable_downloads())
    log("")
    log("System tools (run these yourself; Aperio never installs system packages):")
    for r in doctor_rows(with_versions=False):
        if not r.available and not r.portable:
            log(f"  {r.name:<20} {r.hint}")
    return 1 if failures else 0

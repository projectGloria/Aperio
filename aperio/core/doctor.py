"""Toolchain health (--doctor) and portable tool installation (--setup)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

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


def _portable_names() -> set[str]:
    from .installer import PLUGIN_COMPONENTS
    return set(PLUGIN_COMPONENTS)


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
                              p.install_hint(), p.name in _portable_names()))
    for label, finder, hint in (
            ("java (runtime)", toolchain.java, "python aperio.py --setup  (portable JDK 25)"),
            ("node (runtime)", lambda: toolchain.bundled_node() or toolchain.which("node"),
             "python aperio.py --setup  (portable Node.js)")):
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


def download_portable(plugin_name: str, log: Callable[[str], None] = print) -> bool:
    """Install a plugin's tool (and its runtime) into ./tools_bin. True on success."""
    from .installer import install_for_plugin
    return install_for_plugin(plugin_name, log)


def run_setup(log: Callable[[str], None] = print) -> int:
    from .installer import install_all
    failures = install_all(log)
    log("")
    log(format_doctor_table(doctor_rows()))
    return 1 if failures else 0

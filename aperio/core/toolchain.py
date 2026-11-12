"""Locate external tools on PATH, in ./tools_bin, or via environment variables."""
from __future__ import annotations

import os
import shutil
import threading
from pathlib import Path

from ..config import TOOLS_BIN

IS_WINDOWS = os.name == "nt"


def _tools_bin_dirs() -> list[Path]:
    if not TOOLS_BIN.is_dir():
        return []
    dirs = [TOOLS_BIN]
    for child in sorted(TOOLS_BIN.iterdir()):
        if child.is_dir():
            dirs += [child, child / "bin", child / "support"]
    return [d for d in dirs if d.is_dir()]


def which(*names: str) -> Path | None:
    """First match in ./tools_bin (and its sub-folders) then PATH."""
    search = os.pathsep.join(str(d) for d in _tools_bin_dirs())
    for name in names:
        if search:
            hit = shutil.which(name, path=search)
            if hit:
                return Path(hit)
    for name in names:
        hit = shutil.which(name)
        if hit:
            return Path(hit)
    return None


def find_file(*patterns: str, env_var: str | None = None) -> Path | None:
    """Find a file (e.g. cfr-*.jar) via env var or glob in ./tools_bin."""
    if env_var and os.environ.get(env_var):
        p = Path(os.environ[env_var])
        if p.is_file():
            return p
    for d in _tools_bin_dirs():
        for pattern in patterns:
            hits = sorted(d.glob(pattern), reverse=True)
            if hits:
                return hits[0]
    return None


def java() -> Path | None:
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        cand = Path(java_home) / "bin" / ("java.exe" if IS_WINDOWS else "java")
        if cand.is_file():
            return cand
    return which("java")


def ghidra_headless() -> Path | None:
    script = "analyzeHeadless.bat" if IS_WINDOWS else "analyzeHeadless"
    roots = []
    if os.environ.get("GHIDRA_INSTALL_DIR"):
        roots.append(Path(os.environ["GHIDRA_INSTALL_DIR"]))
    if TOOLS_BIN.is_dir():
        roots += sorted(TOOLS_BIN.glob("ghidra*"), reverse=True)
    for root in roots:
        cand = root / "support" / script
        if cand.is_file():
            return cand
    return which(script)


def probe_version(cmd: list[str], timeout: float = 15) -> str:
    """Run a version command synchronously (doctor only; never on the GUI thread)."""
    from . import procutil  # local import: procutil is independent of toolchain
    res = procutil.run(cmd, timeout=timeout, cancel_event=threading.Event())
    if res.timed_out:
        return "(version probe timed out)"
    for line in (res.stdout + "\n" + res.stderr).splitlines():
        if line.strip() and not line.startswith("failed to start"):
            return line.strip()[:120]
    return "(no version output)" if res.returncode is not None else res.stderr[:120]

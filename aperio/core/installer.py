"""Portable tool installation into ./tools_bin (used by --setup and the Doctor dialog).

Every decompiler *and* the runtime it needs (JDK 25, Node.js) is installed
here, so Aperio works on a machine with no Java, Node, .NET, CMake or C++
compiler installed. pycdc has no official binaries, so it is compiled from
source with a throw-away portable Zig toolchain (zig c++), which is deleted
after the build.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable

from ..config import TOOLS_BIN
from . import toolchain

Log = Callable[[str], None]
IS_WINDOWS = os.name == "nt"

JDK_MAJOR = 25  # Ghidra 12.x requires JDK 25 (application.java.min)
NODE_VERSION = "26.13.1"
ASAR_VERSION = "4.3.1"
CFR_VERSION = "0.152"
JADX_VERSION = "1.5.6"
ILSPY_VERSION = "11.2.0.10050"
GHIDRA_TAG, GHIDRA_ZIP = "Ghidra_12.2_build", "ghidra_12.2_PUBLIC_20261016.zip"
ZIG_VERSION = "0.17.1"
PYCDC_SRC = "https://github.com/zrax/pycdc/archive/refs/heads/master.zip"
PYINSTXTRACTOR_URL = ("https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/"
                      "master/pyinstxtractor.py")


# --------------------------------------------------------------- platform
def _os_arch() -> tuple[str, str]:
    osn = {"win32": "windows", "darwin": "mac"}.get(sys.platform, "linux")
    m = platform.machine().lower()
    arch = "aarch64" if m in ("arm64", "aarch64") else "x64"
    return osn, arch


def _exe(name: str) -> str:
    return name + ".exe" if IS_WINDOWS else name


# --------------------------------------------------------------- download / extract
def _download(url: str, dest: Path, log: Log) -> Path:
    log(f"Downloading {url}")
    tmp = dest.with_name(dest.name + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "Aperio-setup"})
    with urllib.request.urlopen(req, timeout=300) as resp, open(tmp, "wb") as f:
        shutil.copyfileobj(resp, f, length=1 << 20)
    if tmp.stat().st_size == 0:
        tmp.unlink()
        raise OSError(f"empty download: {url}")
    tmp.replace(dest)
    return dest


def _check_member(dest: Path, name: str) -> None:
    target = (dest / name).resolve()
    if dest != target and dest not in target.parents:
        raise ValueError(f"unsafe path in archive: {name}")


def _extract(archive: Path, dest: Path) -> None:
    """Extract zip / tar.(gz|xz) after rejecting path-traversal members."""
    dest.mkdir(parents=True, exist_ok=True)
    dest = dest.resolve()
    with open(archive, "rb") as f:
        magic = f.read(4)
    if magic.startswith(b"PK"):
        with zipfile.ZipFile(archive) as zf:
            for m in zf.infolist():
                _check_member(dest, m.filename)
            zf.extractall(dest)
            if not IS_WINDOWS:  # restore unix exec bits stored in the zip
                for m in zf.infolist():
                    mode = (m.external_attr >> 16) & 0o777
                    if mode:
                        (dest / m.filename).chmod(mode)
    else:
        with tarfile.open(archive) as tf:
            for m in tf.getmembers():
                _check_member(dest, m.name)
            tf.extractall(dest, filter="data")


def _install_tree(archive: Path, final: Path, flatten: bool = True) -> None:
    """Extract into a staging dir, then move the single top-level folder to `final`."""
    stage = Path(tempfile.mkdtemp(prefix="stage_", dir=TOOLS_BIN))
    try:
        _extract(archive, stage)
        children = list(stage.iterdir())
        src = children[0] if flatten and len(children) == 1 and children[0].is_dir() else stage
        if final.exists():
            shutil.rmtree(final)
        shutil.move(str(src), str(final))
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        archive.unlink(missing_ok=True)


def _run(cmd: list[str], log: Log, cwd: Path | None = None, timeout: float = 1800) -> None:
    from . import procutil
    res = procutil.run(cmd, timeout=timeout, cancel_event=threading.Event(), cwd=cwd,
                       env=toolchain.tool_env(),
                       on_line=lambda s, ln: log(f"  {ln}") if s != "cmd" else None)
    if not res.ok:
        tail = (res.stderr or res.stdout).strip().splitlines()[-8:]
        raise OSError(f"command failed ({res.returncode}): {res.command}\n" + "\n".join(tail))


# --------------------------------------------------------------- components
def _jdk(log: Log) -> None:
    osn, arch = _os_arch()
    url = (f"https://api.adoptium.net/v3/binary/latest/{JDK_MAJOR}/ga/{osn}/{arch}/"
           f"jdk/hotspot/normal/eclipse")
    archive = _download(url, TOOLS_BIN / "jdk.download", log)
    _install_tree(archive, TOOLS_BIN / "jdk")
    home = TOOLS_BIN / "jdk"
    if (home / "Contents" / "Home").is_dir():  # macOS bundle layout
        tmp = TOOLS_BIN / "jdk_mac"
        home.rename(tmp)
        shutil.move(str(tmp / "Contents" / "Home"), str(home))
        shutil.rmtree(tmp, ignore_errors=True)


def _node(log: Log) -> None:
    osn, arch = _os_arch()
    plat = {"windows": "win", "mac": "darwin", "linux": "linux"}[osn]
    narch = "arm64" if arch == "aarch64" else "x64"
    ext = "zip" if IS_WINDOWS else "tar.xz"
    url = f"https://nodejs.org/dist/v{NODE_VERSION}/node-v{NODE_VERSION}-{plat}-{narch}.{ext}"
    _install_tree(_download(url, TOOLS_BIN / "node.download", log), TOOLS_BIN / "node")


def _asar(log: Log) -> None:
    node = toolchain.bundled_node()
    npm = next((p for p in (TOOLS_BIN / "node" / "node_modules/npm/bin/npm-cli.js",
                            TOOLS_BIN / "node" / "lib/node_modules/npm/bin/npm-cli.js")
                if p.is_file()), None)
    if not node or not npm:
        raise OSError("bundled Node.js/npm missing")
    prefix = TOOLS_BIN / "asar"
    prefix.mkdir(parents=True, exist_ok=True)
    _run([str(node), str(npm), "install", "--prefix", str(prefix), "--no-audit", "--no-fund",
          "--loglevel=error", f"@electron/asar@{ASAR_VERSION}"], log)


def _cfr(log: Log) -> None:
    url = (f"https://github.com/leibnitz27/cfr/releases/download/{CFR_VERSION}/"
           f"cfr-{CFR_VERSION}.jar")
    _download(url, TOOLS_BIN / f"cfr-{CFR_VERSION}.jar", log)


def _jadx(log: Log) -> None:
    url = (f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/"
           f"jadx-{JADX_VERSION}.zip")
    archive = _download(url, TOOLS_BIN / "jadx.download", log)
    _install_tree(archive, TOOLS_BIN / "jadx", flatten=False)
    for script in (TOOLS_BIN / "jadx" / "bin").glob("jadx*"):
        script.chmod(script.stat().st_mode | 0o111)


def _pyinstxtractor(log: Log) -> None:
    _download(PYINSTXTRACTOR_URL, TOOLS_BIN / "pyinstxtractor.py", log)


def _ilspy(log: Log) -> None:
    """ilspycmd ships as a self-contained native exe per RID: no .NET runtime needed."""
    osn, arch = _os_arch()
    rid = {"windows": "win", "linux": "linux", "mac": "osx"}[osn] + \
        ("-arm64" if arch == "aarch64" else "-x64")
    pkg = f"ilspycmd.{rid}"
    url = (f"https://api.nuget.org/v3-flatcontainer/{pkg}/{ILSPY_VERSION}/"
           f"{pkg}.{ILSPY_VERSION}.nupkg")
    try:
        archive = _download(url, TOOLS_BIN / "ilspycmd.download", log)
    except OSError as exc:
        raise OSError(f"no self-contained ilspycmd for {rid}: {exc}") from exc
    stage = TOOLS_BIN / "ilspycmd_stage"
    try:
        _extract(archive, stage)
        src = stage / "tools" / "any" / rid
        final = TOOLS_BIN / "ilspycmd"
        if final.exists():
            shutil.rmtree(final)
        shutil.move(str(src), str(final))
        exe = final / _exe("ilspycmd")
        exe.chmod(exe.stat().st_mode | 0o111)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        archive.unlink(missing_ok=True)


def _ghidra(log: Log) -> None:
    url = (f"https://github.com/NationalSecurityAgency/ghidra/releases/download/"
           f"{GHIDRA_TAG}/{GHIDRA_ZIP}")
    name = GHIDRA_ZIP.rsplit("_", 1)[0]  # ghidra_12.2_PUBLIC
    for old in TOOLS_BIN.glob("ghidra*"):
        if old.is_dir():
            shutil.rmtree(old)
    _install_tree(_download(url, TOOLS_BIN / "ghidra.download", log), TOOLS_BIN / name)


def _pycdc(log: Log) -> None:
    """Build pycdc from source with a temporary portable Zig (clang) toolchain."""
    osn, arch = _os_arch()
    zarch = "aarch64" if arch == "aarch64" else "x86_64"
    zos = {"windows": "windows", "mac": "macos", "linux": "linux"}[osn]
    ext = "zip" if IS_WINDOWS else "tar.xz"
    work = Path(tempfile.mkdtemp(prefix="pycdc_build_", dir=TOOLS_BIN))
    try:
        _install_tree(_download(PYCDC_SRC, work / "src.zip", log), work / "src")
        zig_url = (f"https://ziglang.org/download/{ZIG_VERSION}/"
                   f"zig-{zarch}-{zos}-{ZIG_VERSION}.{ext}")
        _install_tree(_download(zig_url, work / f"zig.{ext}", log), work / "zig")
        src = work / "src"
        sources = sorted(str(p.relative_to(src)) for p in
                         [*src.glob("*.cpp"), *(src / "bytes").glob("*.cpp")]
                         if p.name != "pycdas.cpp")
        out = TOOLS_BIN / "pycdc"
        out.mkdir(parents=True, exist_ok=True)
        log(f"Compiling pycdc ({len(sources)} files) with zig c++ ...")
        _run([str(work / "zig" / _exe("zig")), "c++", "-O2", "-std=c++11", "-I.",
              "-o", str(out / _exe("pycdc")), *sources], log, cwd=src)
        if (src / "LICENSE").is_file():
            shutil.copy(src / "LICENSE", out / "LICENSE")
        for junk in out.glob("pycdc.pdb"):
            junk.unlink()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _have_ghidra() -> bool:
    return any((d / "support").is_dir() for d in TOOLS_BIN.glob("ghidra*"))


# name -> (installer, "already installed?" check)
COMPONENTS: dict[str, tuple[Callable[[Log], None], Callable[[], bool]]] = {
    "jdk": (_jdk, lambda: toolchain.bundled_java_home() is not None),
    "node": (_node, lambda: toolchain.bundled_node() is not None),
    "asar": (_asar, lambda: (TOOLS_BIN / "asar/node_modules/@electron/asar/package.json").is_file()),
    "cfr": (_cfr, lambda: any(TOOLS_BIN.glob("cfr*.jar"))),
    "jadx": (_jadx, lambda: (TOOLS_BIN / "jadx/bin").is_dir()),
    "pyinstxtractor": (_pyinstxtractor, lambda: (TOOLS_BIN / "pyinstxtractor.py").is_file()),
    "ilspycmd": (_ilspy, lambda: (TOOLS_BIN / "ilspycmd" / _exe("ilspycmd")).is_file()),
    "pycdc": (_pycdc, lambda: (TOOLS_BIN / "pycdc" / _exe("pycdc")).is_file()),
    "ghidra": (_ghidra, _have_ghidra),
}

# plugin name -> components it needs (runtime first)
PLUGIN_COMPONENTS: dict[str, list[str]] = {
    "asar": ["node", "asar"],
    "PyInstaller": ["pyinstxtractor", "pycdc"],
    "ILSpy": ["ilspycmd"],
    "jadx": ["jdk", "jadx"],
    "CFR": ["jdk", "cfr"],
    "pycdc": ["pycdc"],
    "Ghidra (Go)": ["jdk", "ghidra"],
    "Ghidra": ["jdk", "ghidra"],
}


def install_component(name: str, log: Log = print, force: bool = False) -> bool:
    fn, present = COMPONENTS[name]
    if present() and not force:
        log(f"{name}: already installed")
        return True
    TOOLS_BIN.mkdir(parents=True, exist_ok=True)
    try:
        fn(log)
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError,
            subprocess.SubprocessError) as exc:
        log(f"{name}: FAILED - {exc}")
        return False
    ok = present()
    log(f"{name}: {'installed' if ok else 'FAILED (not found after install)'}")
    return ok


def install_for_plugin(plugin_name: str, log: Log = print) -> bool:
    comps = PLUGIN_COMPONENTS.get(plugin_name)
    if not comps:
        log(f"{plugin_name}: no portable download available")
        return False
    return all([install_component(c, log) for c in comps])


def install_all(log: Log = print) -> int:
    """Install every component. Returns the number of failures."""
    log(f"Portable tools -> {TOOLS_BIN}")
    return sum(not install_component(c, log) for c in COMPONENTS)

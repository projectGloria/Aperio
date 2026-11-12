"""Target enumeration, output-path mirroring and the Electron stub rule."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Chromium / Electron runtime libraries shipped next to every Electron stub.
CHROMIUM_RUNTIME = {
    "libcef.dll", "ffmpeg.dll", "d3dcompiler_47.dll", "libegl.dll", "libglesv2.dll",
    "vk_swiftshader.dll", "vulkan-1.dll", "dxcompiler.dll", "dxil.dll",
    "chrome_elf.dll", "libffmpeg.so", "libegl.so", "libglesv2.so",
    "libvk_swiftshader.so", "libvulkan.so.1", "chrome-sandbox", "chrome_crashpad_handler",
}


@dataclass
class ScanEntry:
    path: Path
    rel_path: Path
    electron_root: Path | None = None   # set when inside an Electron app folder


def electron_roots(root: Path) -> set[Path]:
    """Directories that contain resources/app.asar."""
    roots = set()
    for asar in root.rglob("app.asar"):
        if asar.parent.name.lower() == "resources" and asar.is_file():
            roots.add(asar.parent.parent)
    return roots


def is_electron_stub(entry: ScanEntry, is_native: bool) -> bool:
    """Called only for files already classified as native by content."""
    if entry.electron_root is None or not is_native:
        return False
    try:
        rel = entry.path.relative_to(entry.electron_root)
    except ValueError:
        return False
    if rel.parts and rel.parts[0].lower() == "resources":
        return False
    return len(rel.parts) == 1 or entry.path.name.lower() in CHROMIUM_RUNTIME


def enumerate_target(target: Path, exclude: Path | None = None) -> list[ScanEntry]:
    target = target.resolve()
    if target.is_file():
        return [ScanEntry(target, Path(target.name))]
    exclude = exclude.resolve() if exclude else None
    roots = sorted(electron_roots(target), key=lambda p: len(p.parts), reverse=True)
    entries: list[ScanEntry] = []
    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        d = Path(dirpath)
        if exclude and (d == exclude or exclude in d.parents):
            dirnames[:] = []
            continue
        dirnames[:] = sorted(n for n in dirnames
                             if not (exclude and (d / n).resolve() == exclude))
        for name in sorted(filenames):
            p = d / name
            if p.is_symlink() or not p.is_file():
                continue
            e_root = next((r for r in roots if r == d or r in p.parents), None)
            entries.append(ScanEntry(p, p.relative_to(target), e_root))
    return entries


def output_dir_for(out_root: Path, rel_path: Path) -> Path:
    """<out>/<relative parent>/<filename>_unpacked/"""
    return out_root / rel_path.parent / f"{rel_path.name}_unpacked"

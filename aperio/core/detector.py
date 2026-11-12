"""Content-based file analysis. Never looks at file extensions.

`analyze(path)` parses a file once into a `FileInfo`; plugins call the
predicates below from their `detect()` methods. `classify()` walks plugins in
strict priority order and returns the first match.
"""
from __future__ import annotations

import bisect
import functools
import json
import mmap
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from . import binfmt

if TYPE_CHECKING:  # pragma: no cover
    from ..plugins.base import DecompilerPlugin

HEADER_SIZE = 4096
PYINSTALLER_COOKIE = b"MEI\x0c\x0b\x0a\x0b\x0e"
GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"
GO_SECTIONS = {".go.buildinfo", ".gopclntab", "__go_buildinfo", "__gopclntab"}
PYI_SECTIONS = {"pydata", ".pydata"}
MAX_MARKER_SCAN = 2 << 30  # 2 GiB

# Lowest magic number of each CPython 3.x release (MAGIC_NUMBER in importlib).
_PY3_MAGICS = [(3000, "3.0"), (3090, "3.1"), (3150, "3.2"), (3190, "3.3"),
               (3250, "3.4"), (3320, "3.5"), (3360, "3.6"), (3390, "3.7"),
               (3400, "3.8"), (3420, "3.9"), (3430, "3.10"), (3450, "3.11"),
               (3500, "3.12"), (3550, "3.13"), (3600, "3.14"), (3650, "3.15")]
_PY2_MAGICS = {20121: "1.5", 50428: "1.6", 50823: "2.0", 60202: "2.1",
               60717: "2.2", 62011: "2.3", 62021: "2.3", 62041: "2.4",
               62061: "2.4", 62071: "2.5", 62081: "2.5", 62091: "2.5",
               62092: "2.5", 62101: "2.5", 62111: "2.5", 62121: "2.5",
               62131: "2.5", 62151: "2.6", 62161: "2.6", 62171: "2.7",
               62181: "2.7", 62191: "2.7", 62201: "2.7", 62211: "2.7"}


@dataclass
class FileInfo:
    path: Path
    size: int
    header: bytes
    container: str | None = None          # PE / ELF / Mach-O / ZIP / ASAR / DEX / CLASS / PYC
    native: dict | None = None            # parsed PE/ELF/Mach-O structure
    zip_names: list[str] = field(default_factory=list)
    pyinstaller_cookie: bool = False
    go_marker: bool = False
    pyc_version: str | None = None
    asar_files: int | None = None
    java_version: int | None = None

    @property
    def section_names(self) -> set[str]:
        return {s["name"] for s in (self.native or {}).get("sections", [])}

    @property
    def is_native(self) -> bool:
        return self.native is not None

    def metadata(self) -> dict:
        """Human readable metadata for the inspector / report."""
        md = {"size": self.size, "magic": self.header[:16].hex(" "),
              "container": self.container or "unknown"}
        if self.native:
            md.update(format=self.native.get("format"), arch=self.native.get("arch"))
            if self.native.get("container") == "PE":
                md["clr_directory"] = (f"RVA=0x{self.native['clr_rva']:X} "
                                       f"Size=0x{self.native['clr_size']:X}")
            md["sections"] = ", ".join(sorted(self.section_names)[:40]) or "-"
        if self.pyinstaller_cookie:
            md["pyinstaller_cookie"] = "MEI\\x0c\\x0b\\x0a\\x0b\\x0e found"
        if self.go_marker:
            md["go_buildinfo"] = "present"
        if self.pyc_version:
            md["python_version"] = self.pyc_version
        if self.java_version:
            md["class_major_version"] = self.java_version
        if self.zip_names:
            md["zip_entries"] = len(self.zip_names)
        if self.asar_files is not None:
            md["asar_top_level_entries"] = self.asar_files
        return md


# ---------------------------------------------------------------- predicates
def asar_header(header: bytes) -> dict | None:
    """Electron ASAR = Chromium Pickle: [u32 4][u32 hdr_size] then a pickle of
    [u32 payload][u32 json_len][json...]."""
    if len(header) < 16:
        return None
    a, hdr_size, payload, json_len = struct.unpack_from("<IIII", header, 0)
    if a != 4 or payload != hdr_size - 4 or not 0 < json_len <= payload - 4:
        return None
    if not header[16:].startswith(b'{"files"'):
        return None
    return {"json_len": json_len, "hdr_size": hdr_size}


def pyc_info(header: bytes) -> str | None:
    """Return the CPython version for a structurally valid .pyc header."""
    if len(header) < 9 or header[2:4] != b"\r\n":
        return None
    magic = struct.unpack_from("<H", header, 0)[0]
    if magic in _PY2_MAGICS:
        version, hdr_len = _PY2_MAGICS[magic], 8
    elif 3000 <= magic < 3800:
        idx = bisect.bisect_right([m for m, _ in _PY3_MAGICS], magic) - 1
        version = _PY3_MAGICS[idx][1]
        hdr_len = 16 if magic >= 3392 else 12 if magic >= 3230 else 8
        if hdr_len == 16:
            if len(header) < 17:
                return None
            flags = struct.unpack_from("<I", header, 4)[0]
            if flags not in (0, 1, 3):
                return None
    else:
        return None
    if len(header) <= hdr_len or header[hdr_len] not in (0x63, 0xE3):
        return None  # marshalled code object must follow the header
    return version


def java_class_version(header: bytes) -> int | None:
    if len(header) < 10 or header[:4] != b"\xca\xfe\xba\xbe":
        return None
    minor, major = struct.unpack_from(">HH", header, 4)
    return major if 45 <= major <= 80 else None


def is_dex(header: bytes) -> bool:
    return header[:4] == b"dex\n" and header[7:8] == b"\0" and header[4:7].isdigit()


def is_apk(info: FileInfo) -> bool:
    names = info.zip_names
    return any(n == "AndroidManifest.xml" or
               (n.startswith("classes") and n.endswith(".dex") and "/" not in n)
               for n in names)


def is_java_archive(info: FileInfo) -> bool:
    return not is_apk(info) and any(
        n.endswith(".class") or n.upper() == "META-INF/MANIFEST.MF" for n in info.zip_names)


def is_dotnet(info: FileInfo) -> bool:
    n = info.native
    return bool(n and n.get("container") == "PE" and n["clr_rva"] and n["clr_size"])


def is_pyinstaller(info: FileInfo) -> bool:
    return info.is_native and (info.pyinstaller_cookie or bool(info.section_names & PYI_SECTIONS))


def is_go(info: FileInfo) -> bool:
    return info.is_native and (info.go_marker or bool(info.section_names & GO_SECTIONS))


# ----------------------------------------------------------------- analysis
def _scan_markers(path: Path, size: int) -> tuple[bool, bool]:
    if size == 0 or size > MAX_MARKER_SCAN:
        return False, False
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        return mm.rfind(PYINSTALLER_COOKIE) != -1, mm.find(GO_BUILDINFO_MAGIC) != -1


def _analyze_uncached(path: Path) -> FileInfo:
    size = path.stat().st_size
    with open(path, "rb") as f:
        header = f.read(HEADER_SIZE)
        info = FileInfo(path=path, size=size, header=header)
        native = None
        if header[:2] == b"MZ":
            native = binfmt.parse_pe(f, size)
        elif header[:4] == b"\x7fELF":
            native = binfmt.parse_elf(f, size)
        elif header[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                            b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
            native = binfmt.parse_macho(f, size)
        elif header[:4] == b"\xca\xfe\xba\xbe":
            info.java_version = java_class_version(header)
            if info.java_version:
                info.container = "CLASS"
            else:
                native = binfmt.parse_fat(header)
    if native:
        info.native = native
        info.container = native["container"]
        info.pyinstaller_cookie, info.go_marker = _scan_markers(path, size)
        return info
    if info.container:
        return info
    if asar_header(header):
        info.container = "ASAR"
        try:
            meta = asar_header(header)
            with open(path, "rb") as f:
                f.seek(16)
                tree = json.loads(f.read(meta["json_len"]))
            info.asar_files = len(tree.get("files", {}))
        except (ValueError, OSError):
            info.asar_files = None
    elif header[:4] == b"PK\x03\x04":
        info.container = "ZIP"
        try:
            with zipfile.ZipFile(path) as zf:
                info.zip_names = zf.namelist()
        except (zipfile.BadZipFile, OSError, ValueError):
            info.zip_names = []
    elif is_dex(header):
        info.container = "DEX"
    elif (ver := pyc_info(header)) is not None:
        info.container, info.pyc_version = "PYC", ver
    return info


@functools.lru_cache(maxsize=4096)
def _analyze_key(path_str: str, _mtime: int, _size: int) -> FileInfo:
    return _analyze_uncached(Path(path_str))


def analyze(path: Path) -> FileInfo:
    st = path.stat()
    return _analyze_key(str(path), st.st_mtime_ns, st.st_size)


def classify(path: Path, plugins: Iterable["DecompilerPlugin"]):
    """Return (plugin|None, FileInfo). Plugins are tried by ascending priority."""
    info = analyze(path)
    for plugin in sorted(plugins, key=lambda p: p.priority):
        if plugin.detect(path, info.header):
            return plugin, info
    return None, info

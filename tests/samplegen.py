"""Builders for structurally valid synthetic binaries used by the tests.

These are real headers (correct offsets, tables and sizes) - just without
meaningful code - so the detector exercises its genuine parsing paths.
"""
from __future__ import annotations

import json
import struct
import zipfile
from pathlib import Path


def make_pe(sections=(".text", ".rdata", ".data"), clr=False, pe32plus=True,
            payload: bytes = b"") -> bytes:
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    opt_size = 240 if pe32plus else 224
    coff = struct.pack("<4sHHIIIHH", b"PE\0\0", 0x8664 if pe32plus else 0x14C,
                       len(sections), 0, 0, 0, opt_size, 0x22)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if pe32plus else 0x10B)
    nrva_off, dd_off = (108, 112) if pe32plus else (92, 96)
    struct.pack_into("<I", opt, nrva_off, 16)
    if clr:
        struct.pack_into("<II", opt, dd_off + 14 * 8, 0x2008, 0x48)
    headers_len = e_lfanew + len(coff) + opt_size + 40 * len(sections)
    data_off = (headers_len + 0x1FF) & ~0x1FF
    sec_table = b""
    for i, name in enumerate(sections):
        sec_table += struct.pack("<8sIIIIIIHHI", name.encode()[:8], 0x200,
                                 0x1000 * (i + 1), 0x200, data_off + i * 0x200,
                                 0, 0, 0, 0, 0x60000020)
    body = bytes(dos) + coff + bytes(opt) + sec_table
    body = body.ljust(data_off, b"\0") + b"\0" * (0x200 * len(sections))
    return body + payload


def make_elf64(sections=(".text", ".data"), payload: bytes = b"") -> bytes:
    names = [""] + list(sections) + [".shstrtab"]
    strtab = b""
    offsets = []
    for n in names:
        offsets.append(len(strtab))
        strtab += n.encode() + b"\0"
    strtab_off = 64
    shoff = (strtab_off + len(strtab) + 7) & ~7
    shnum = len(names)
    ehdr = bytearray(64)
    ehdr[0:16] = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", ehdr, 16, 2, 62, 1, 0x401000, 0, shoff,
                     0, 64, 56, 0, 64, shnum, shnum - 1)
    shdrs = b""
    for i, n in enumerate(names):
        if i == 0:
            shdrs += b"\0" * 64
            continue
        is_str = n == ".shstrtab"
        shdrs += struct.pack("<IIQQQQIIQQ", offsets[i], 3 if is_str else 1, 0, 0,
                             strtab_off if is_str else 0, len(strtab) if is_str else 0,
                             0, 0, 1, 0)
    out = bytes(ehdr) + strtab
    return out.ljust(shoff, b"\0") + shdrs + payload


def make_macho64(sections=(("__text", "__TEXT"),), payload: bytes = b"") -> bytes:
    nsects = len(sections)
    cmdsize = 72 + 80 * nsects
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 1, cmdsize, 0, 0)
    seg = struct.pack("<II16sQQQQiiII", 0x19, cmdsize, b"__TEXT", 0, 0, 0, 0, 7, 5, nsects, 0)
    for sect, segname in sections:
        seg += struct.pack("<16s16sQQIIIIIIII", sect.encode(), segname.encode(),
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return hdr + seg + payload


def make_fat_macho(n_arch=2) -> bytes:
    out = struct.pack(">II", 0xCAFEBABE, n_arch)
    for cpu in (0x01000007, 0x0100000C)[:n_arch]:
        out += struct.pack(">iiIII", cpu, 3, 0x1000, 0x100, 12)
    return out.ljust(64, b"\0")


def make_class(major=61) -> bytes:
    # magic, minor, major, constant_pool_count, then minimal garbage
    return struct.pack(">IHHH", 0xCAFEBABE, 0, major, 1) + b"\0" * 16


def make_dex() -> bytes:
    return b"dex\n035\0" + b"\0" * 104


def make_asar(path: Path, files: dict[str, bytes]) -> None:
    tree, offset, blob = {"files": {}}, 0, b""
    for name, data in files.items():
        tree["files"][name] = {"size": len(data), "offset": str(offset)}
        offset += len(data)
        blob += data
    js = json.dumps(tree, separators=(",", ":")).encode()
    json_len = len(js)
    padded = js + b"\0" * ((4 - json_len % 4) % 4)
    header_pickle = struct.pack("<II", len(padded) + 4, json_len) + padded
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<II", 4, len(header_pickle)) + header_pickle + blob)


def make_zip(path: Path, names: list[str]) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for n in names:
            zf.writestr(n, b"x")


def make_pyc_bytes(magic: int = 3571, flags: int = 0) -> bytes:
    return struct.pack("<H", magic) + b"\r\n" + struct.pack("<III", flags, 0, 0) + b"\xe3" + b"\0" * 32

"""Struct-based parsers for PE, ELF and Mach-O containers.

Each parser receives an open binary file object and returns a dict (or None if
the structure is not valid). Parsers never trust offsets blindly: every read is
bounds-checked against the real file size.
"""
from __future__ import annotations

import struct
from typing import BinaryIO

PE_MACHINES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0x1C4: "ARMv7",
               0xAA64: "ARM64", 0x200: "IA64", 0x0: "unknown"}
ELF_MACHINES = {3: "x86", 62: "x64", 40: "ARM", 183: "ARM64", 8: "MIPS",
                20: "PPC", 21: "PPC64", 243: "RISC-V"}
MACHO_CPUS = {7: "x86", 0x01000007: "x64", 12: "ARM", 0x0100000C: "ARM64",
              18: "PPC", 0x01000012: "PPC64"}

IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14


def _read_at(f: BinaryIO, offset: int, size: int, file_size: int) -> bytes | None:
    if offset < 0 or size < 0 or offset + size > file_size:
        return None
    f.seek(offset)
    data = f.read(size)
    return data if len(data) == size else None


def parse_pe(f: BinaryIO, file_size: int) -> dict | None:
    """Parse DOS + NT headers, data directories and section table."""
    dos = _read_at(f, 0, 64, file_size)
    if not dos or dos[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    nt = _read_at(f, e_lfanew, 24, file_size)
    if not nt or nt[:4] != b"PE\0\0":
        return None
    machine, nsections, _ts, _sym, _nsym, opt_size, chars = struct.unpack_from(
        "<HHIIIHH", nt, 4)
    opt_off = e_lfanew + 24
    opt = _read_at(f, opt_off, opt_size, file_size) if opt_size else b""
    if opt is None or len(opt) < 2:
        return None
    magic = struct.unpack_from("<H", opt, 0)[0]
    if magic == 0x10B:
        fmt, dd_off, nrva_off = "PE32", 96, 92
    elif magic == 0x20B:
        fmt, dd_off, nrva_off = "PE32+", 112, 108
    else:
        return None
    data_dirs: list[tuple[int, int]] = []
    if len(opt) >= nrva_off + 4:
        nrva = min(struct.unpack_from("<I", opt, nrva_off)[0], 16)
        for i in range(nrva):
            off = dd_off + i * 8
            if off + 8 > len(opt):
                break
            data_dirs.append(struct.unpack_from("<II", opt, off))
    sections = []
    sec_off = opt_off + opt_size
    for i in range(min(nsections, 96)):
        raw = _read_at(f, sec_off + i * 40, 40, file_size)
        if raw is None:
            break
        name = raw[:8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", raw, 8)
        sections.append({"name": name, "vaddr": vaddr, "vsize": vsize,
                         "raw_ptr": rptr, "raw_size": rsize})
    clr = (data_dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
           if len(data_dirs) > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR else (0, 0))
    return {
        "container": "PE", "format": fmt,
        "arch": PE_MACHINES.get(machine, hex(machine)),
        "is_dll": bool(chars & 0x2000),
        "data_directories": data_dirs,
        "clr_rva": clr[0], "clr_size": clr[1],
        "sections": sections,
    }


def parse_elf(f: BinaryIO, file_size: int) -> dict | None:
    ident = _read_at(f, 0, 64, file_size) or _read_at(f, 0, 52, file_size)
    if not ident or ident[:4] != b"\x7fELF":
        return None
    ei_class, ei_data = ident[4], ident[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    end = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    if is64:
        if len(ident) < 64:
            return None
        e_type, e_machine = struct.unpack_from(end + "HH", ident, 16)
        e_shoff = struct.unpack_from(end + "Q", ident, 40)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", ident, 58)
    else:
        e_type, e_machine = struct.unpack_from(end + "HH", ident, 16)
        e_shoff = struct.unpack_from(end + "I", ident, 32)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", ident, 46)
    info = {"container": "ELF", "format": "ELF64" if is64 else "ELF32",
            "arch": ELF_MACHINES.get(e_machine, str(e_machine)),
            "endian": "little" if ei_data == 1 else "big",
            "elf_type": {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, str(e_type)),
            "sections": []}
    if not e_shoff or not e_shnum or e_shnum > 4096 or e_shstrndx >= e_shnum:
        return info
    shdrs = []
    for i in range(e_shnum):
        raw = _read_at(f, e_shoff + i * e_shentsize, e_shentsize, file_size)
        if raw is None:
            return info
        if is64:
            name, _t, _fl, _addr, off, size = struct.unpack_from(end + "IIQQQQ", raw, 0)
        else:
            name, _t, _fl, _addr, off, size = struct.unpack_from(end + "IIIIII", raw, 0)
        shdrs.append((name, off, size))
    _n, str_off, str_size = shdrs[e_shstrndx]
    strtab = _read_at(f, str_off, min(str_size, 1 << 20), file_size) or b""
    for name_idx, off, size in shdrs:
        end_idx = strtab.find(b"\0", name_idx)
        name = strtab[name_idx:end_idx if end_idx >= 0 else None].decode("latin-1")
        info["sections"].append({"name": name, "raw_ptr": off, "raw_size": size})
    return info


def parse_macho(f: BinaryIO, file_size: int) -> dict | None:
    head = _read_at(f, 0, 32, file_size)
    if not head:
        return None
    magic_be = struct.unpack_from(">I", head, 0)[0]
    table = {0xFEEDFACE: (">", False), 0xFEEDFACF: (">", True),
             0xCEFAEDFE: ("<", False), 0xCFFAEDFE: ("<", True)}
    if magic_be not in table:
        return None
    end, is64 = table[magic_be]
    cputype, _sub, filetype, ncmds, sizeofcmds = struct.unpack_from(end + "iiIII", head, 4)
    hdr_size = 32 if is64 else 28
    info = {"container": "Mach-O", "format": "Mach-O 64" if is64 else "Mach-O 32",
            "arch": MACHO_CPUS.get(cputype & 0xFFFFFFFF, str(cputype)),
            "sections": []}
    cmds = _read_at(f, hdr_size, min(sizeofcmds, 4 << 20), file_size)
    if cmds is None:
        return info
    pos = 0
    for _ in range(min(ncmds, 4096)):
        if pos + 8 > len(cmds):
            break
        cmd, cmdsize = struct.unpack_from(end + "II", cmds, pos)
        if cmdsize < 8:
            break
        if cmd in (0x1, 0x19):  # LC_SEGMENT / LC_SEGMENT_64
            seg64 = cmd == 0x19
            nsects_off = pos + (64 if seg64 else 48)
            sect_base = pos + (72 if seg64 else 56)
            sect_size = 80 if seg64 else 68
            if nsects_off + 4 <= len(cmds):
                nsects = struct.unpack_from(end + "I", cmds, nsects_off)[0]
                for s in range(min(nsects, 256)):
                    so = sect_base + s * sect_size
                    if so + 32 > len(cmds):
                        break
                    sect = cmds[so:so + 16].rstrip(b"\0").decode("latin-1")
                    seg = cmds[so + 16:so + 32].rstrip(b"\0").decode("latin-1")
                    info["sections"].append({"name": sect, "segment": seg})
        pos += cmdsize
    return info


def parse_fat(head: bytes) -> dict | None:
    """Universal (fat) Mach-O: CAFEBABE + nfat_arch. Java classes share the
    magic but carry minor/major version (major >= 45) in bytes 4-7."""
    if len(head) < 8 or head[:4] != b"\xca\xfe\xba\xbe":
        return None
    nfat = struct.unpack_from(">I", head, 4)[0]
    if not 0 < nfat < 45:
        return None
    arches = []
    for i in range(min(nfat, 16)):
        off = 8 + i * 20
        if off + 4 > len(head):
            break
        cpu = struct.unpack_from(">I", head, off)[0]
        arches.append(MACHO_CPUS.get(cpu, str(cpu)))
    return {"container": "Mach-O", "format": "Mach-O Universal",
            "arch": "+".join(arches) or "unknown", "sections": []}

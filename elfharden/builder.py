"""Deterministic minimal ELF byte fixtures for offline tests.

Hand-assembled with :mod:`struct` (no toolchain, no execution) and kept
parseable by pyelftools. The fixture pair shares identical section
declarations and payload while program headers select different loading
views, so the auditor must surface a conflict rather than guess.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_EXEC = 2
EM_X86_64 = 62

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X = 1
PF_W = 2
PF_R = 4

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHF_WRITE = 1
SHF_ALLOC = 2
SHF_EXECINSTR = 4

DT_NULL = 0
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 8
DF_1_NOW = 1

EHDR_SIZE = 64
PHDR_SIZE = 56
SHDR_SIZE = 64
DYN_SIZE = 16
BASE_VADDR = 0x400000


@dataclass(frozen=True)
class LoadProfile:
    """How program headers present the shared payload at load time."""

    name: str
    stack_executable: bool
    include_relro: bool
    dynamic_now: bool


STRICT_PROFILE = LoadProfile(
    name="strict", stack_executable=False, include_relro=True, dynamic_now=True
)
LAX_PROFILE = LoadProfile(
    name="lax", stack_executable=True, include_relro=False, dynamic_now=False
)


@dataclass(frozen=True)
class BuildLayout:
    phnum: int
    phoff: int
    dyn_full_offset: int
    dyn_lax_offset: int
    shstr_offset: int
    note_offset: int
    gotplt_offset: int
    shoff: int
    total_size: int


# Fixed program-header count: when RELRO is absent its slot stays PT_NULL so
# every later offset stays identical across the fixture pair.
PHNUM = 5
SHSTR_SIZE = 45


def _layout(profile: LoadProfile) -> BuildLayout:
    phnum = PHNUM
    phoff = EHDR_SIZE
    phdr_end = phoff + phnum * PHDR_SIZE
    dyn_full_offset = phdr_end
    dyn_lax_offset = dyn_full_offset + 2 * DYN_SIZE
    shstr_offset = dyn_lax_offset + 2 * DYN_SIZE
    note_offset = shstr_offset + SHSTR_SIZE
    gotplt_offset = note_offset + 8
    shoff = gotplt_offset + 16
    total_size = shoff + 6 * SHDR_SIZE
    return BuildLayout(
        phnum=phnum,
        phoff=phoff,
        dyn_full_offset=dyn_full_offset,
        dyn_lax_offset=dyn_lax_offset,
        shstr_offset=shstr_offset,
        note_offset=note_offset,
        gotplt_offset=gotplt_offset,
        shoff=shoff,
        total_size=total_size,
    )


def build_elf(profile: LoadProfile) -> bytes:
    layout = _layout(profile)
    buf = bytearray(layout.total_size)
    _emit_ehdr(buf, layout, profile)
    _emit_phdrs(buf, layout, profile)
    _emit_payload(buf, layout)
    _emit_shdrs(buf, layout)
    return bytes(buf)


def fixture_pair() -> tuple[bytes, bytes]:
    """Identical section declarations/payload, different load views."""
    return build_elf(STRICT_PROFILE), build_elf(LAX_PROFILE)


def section_declaration_signature(data: bytes) -> bytes:
    """Slice covering shstrtab and the section header table."""
    layout = _layout(STRICT_PROFILE)
    return data[layout.shstr_offset : layout.total_size]


def _emit_ehdr(buf: bytearray, layout: BuildLayout, profile: LoadProfile) -> None:
    buf[0:4] = b"\x7fELF"
    buf[4] = ELFCLASS64
    buf[5] = ELFDATA2LSB
    buf[6] = EV_CURRENT
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        buf,
        16,
        ET_EXEC,
        EM_X86_64,
        EV_CURRENT,
        BASE_VADDR,
        layout.phoff,
        layout.shoff,
        0,
        EHDR_SIZE,
        PHDR_SIZE,
        layout.phnum,
        SHDR_SIZE,
        6,
        4,
    )


def _emit_phdrs(buf: bytearray, layout: BuildLayout, profile: LoadProfile) -> None:
    stack_flags = PF_R | PF_W | (PF_X if profile.stack_executable else 0)
    dynamic_offset = layout.dyn_full_offset if profile.dynamic_now else layout.dyn_lax_offset
    headers = [
        (PT_LOAD, PF_R | PF_W | PF_X, 0, BASE_VADDR, BASE_VADDR,
         layout.total_size, layout.total_size, 0x1000),
        (PT_DYNAMIC, PF_R | PF_W, dynamic_offset,
         BASE_VADDR + dynamic_offset, BASE_VADDR + dynamic_offset,
         2 * DYN_SIZE, 2 * DYN_SIZE, 8),
        (PT_GNU_STACK, stack_flags, 0, 0, 0, 0, 0, 16),
    ]
    if profile.include_relro:
        relro_size = (layout.gotplt_offset + 16) - layout.dyn_full_offset
        headers.append(
            (PT_GNU_RELRO, PF_R, layout.dyn_full_offset,
             BASE_VADDR + layout.dyn_full_offset, BASE_VADDR + layout.dyn_full_offset,
             relro_size, relro_size, 1)
        )
    else:
        # Keep the slot (and all offsets) stable; an unused PT_NULL entry.
        headers.append((0, 0, 0, 0, 0, 0, 0, 8))
    cursor = layout.phoff
    for p_type, flags, offset, vaddr, paddr, filesz, memsz, align in headers:
        struct.pack_into(
            "<IIQQQQQQ",
            buf,
            cursor,
            p_type, flags, offset, vaddr, paddr, filesz, memsz, align,
        )
        cursor += PHDR_SIZE


def _emit_payload(buf: bytearray, layout: BuildLayout) -> None:
    struct.pack_into("<qQ", buf, layout.dyn_full_offset, DT_FLAGS, DF_BIND_NOW)
    struct.pack_into("<qQ", buf, layout.dyn_full_offset + DYN_SIZE, DT_NULL, 0)
    struct.pack_into("<qQ", buf, layout.dyn_lax_offset, DT_FLAGS_1, 0)
    struct.pack_into("<qQ", buf, layout.dyn_lax_offset + DYN_SIZE, DT_NULL, 0)
    strings = b'\x00.dynamic\x00.got.plt\x00.note.GNU-stack\x00.shstrtab\x00'
    buf[layout.shstr_offset : layout.shstr_offset + len(strings)] = strings
    buf[layout.note_offset : layout.note_offset + 8] = b"\x00" * 8


def _emit_shdrs(buf: bytearray, layout: BuildLayout) -> None:
    dynamic_name = 1
    gotplt_name = 10
    note_name = 19
    strtab_name = 35
    entries = [
        (0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
        (dynamic_name, SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE,
         BASE_VADDR + layout.dyn_full_offset, layout.dyn_full_offset,
         2 * DYN_SIZE, 0, 0, 8, 0),
        (gotplt_name, SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
         BASE_VADDR + layout.gotplt_offset, layout.gotplt_offset,
         16, 0, 0, 8, 0),
        (note_name, SHT_PROGBITS, 0, 0, layout.note_offset, 8, 0, 0, 1, 0),
        (strtab_name, SHT_STRTAB, 0, 0, layout.shstr_offset, SHSTR_SIZE, 0, 0, 1, 0),
        (0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
    ]
    cursor = layout.shoff
    for entry in entries:
        struct.pack_into("<IIQQQQIIQQ", buf, cursor, *entry)
        cursor += SHDR_SIZE

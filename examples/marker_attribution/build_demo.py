#!/usr/bin/env python3
"""Build the two linked ELF demonstration programs and their manifest.

The workspace can run on macOS without a Linux cross-linker.  The generator
therefore starts from two ordinary GCC/clang-linked x86-64 ET_EXEC files shipped
with pyelftools and appends a non-allocated ``.note.obs`` section.  Program
headers and existing load mappings remain unchanged.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = Path(__file__).resolve().parent
OBS_NOTE_TYPE = 0x4F425301

PROGRAM_A_SOURCE = REPO_ROOT / "test/testfiles_for_readelf/issue103.elf"
PROGRAM_B_SOURCE = REPO_ROOT / "test/testfiles_for_readelf/struct-bitfield-packed.elf"

A_NOTES = [
    {
        "provider": "acme.firmware",
        "payload": {
            "v": 1,
            "name": "boot.attested",
            "address": "0x400420",
            "size": 16,
            "event": "boot.complete",
        },
    },
    {
        "provider": "acme.observability",
        "payload": {
            "v": 1,
            "name": "heartbeat",
            "address": "0x400440",
            "size": 16,
            "event": "alive",
        },
    },
    {
        "provider": "beta.driver",
        "payload": {
            "v": 1,
            "name": "heartbeat",
            "address": "0x400468",
            "size": 16,
            "event": "driver.watchdog",
        },
    },
    {
        "provider": "acme.observability",
        "payload": {
            "v": 1,
            "name": "trace.flush",
            "address": "0x400490",
            "size": 16,
            "event": "trace.flush",
        },
    },
    {
        "provider": "beta.driver",
        "payload": {
            "v": 1,
            "name": "shadow.event",
            "address": "0x4004c0",
            "size": 8,
            "event": "shadow",
        },
    },
    {
        "provider": "gamma.telemetry",
        "payload": {
            "v": 1,
            "name": "telemetry.dma",
            "address": "0x480100",
            "size": 32,
            "event": "dma.batch",
        },
    },
    {
        "provider": "acme.runtime",
        "payload": {
            "v": 1,
            "name": "runtime.watermark",
            "address": "0x60099c",
            "size": 20,
            "event": "watermark",
        },
    },
]

B_NOTES = [
    {
        "provider": "acme.firmware",
        "payload": {
            "v": 1,
            "name": "boot.attested",
            "address": "0x400420",
            "size": 16,
            "event": "boot.complete",
        },
    },
    {
        "provider": "acme.observability",
        "payload": {
            "v": 1,
            "name": "heartbeat",
            "address": "0x400440",
            "size": 16,
            "event": "alive",
        },
    },
    {
        "provider": "beta.tracing",
        "payload": {
            "v": 1,
            "name": "trace.flush",
            "address": "0x400470",
            "size": 16,
            "event": "trace.flush",
        },
    },
    {
        "provider": "release.ops",
        "payload": {
            "v": 1,
            "name": "release.gate",
            "address": "0x4004a0",
            "size": 16,
            "event": "gate.passed",
        },
    },
    {
        "provider": "beta.driver",
        "payload": {
            "v": 1,
            "name": "debug.probe",
            "address": "0x4004c8",
            "size": 8,
            "event": "probe",
        },
    },
]


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def build_note(provider: str, payload: dict[str, Any]) -> bytes:
    name = provider.encode("utf-8") + b"\0"
    descriptor = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    header = struct.pack("<III", len(name), len(descriptor), OBS_NOTE_TYPE)
    name_padding = b"\0" * (align_up(len(name), 4) - len(name))
    desc_padding = b"\0" * (align_up(len(descriptor), 4) - len(descriptor))
    return header + name + name_padding + descriptor + desc_padding


def inject_note_section(
    source: Path, destination: Path, notes: list[dict[str, Any]]
) -> None:
    data = bytearray(source.read_bytes())
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError(f"{source} is not a little-endian ELF64 file")

    (
        _ident,
        e_type,
        e_machine,
        _e_version,
        _e_entry,
        _e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    if e_shentsize != 64:
        raise ValueError(f"unsupported section header size: {e_shentsize}")

    shstr_header_offset = e_shoff + e_shstrndx * e_shentsize
    (
        _sh_name,
        _sh_type,
        _sh_flags,
        _sh_addr,
        shstr_offset,
        shstr_size,
        *_rest,
    ) = struct.unpack_from("<IIQQQQIIQQ", data, shstr_header_offset)
    shstrtab = bytes(data[shstr_offset : shstr_offset + shstr_size])
    if not shstrtab.endswith(b"\0"):
        shstrtab += b"\0"

    note_name_offset = len(shstrtab)
    shstrtab += b".note.obs\0"
    shstr_name_offset = len(shstrtab)
    shstrtab += b".shstrtab.obs\0"

    if len(data) % 8:
        data.extend(b"\0" * (8 - len(data) % 8))
    note_offset = len(data)
    note_blob = b"".join(
        build_note(item["provider"], item["payload"]) for item in notes
    )
    data.extend(note_blob)
    note_size = len(note_blob)

    shstr_offset_new = len(data)
    data.extend(shstrtab)

    if len(data) % 8:
        data.extend(b"\0" * (8 - len(data) % 8))
    new_shoff = len(data)

    old_headers = [
        bytes(data[e_shoff + index * e_shentsize : e_shoff + (index + 1) * e_shentsize])
        for index in range(e_shnum)
    ]
    data.extend(b"".join(old_headers))

    note_header = struct.pack(
        "<IIQQQQIIQQ",
        note_name_offset,
        7,  # SHT_NOTE
        0,
        0,
        note_offset,
        note_size,
        0,
        0,
        8,
        0,
    )
    shstr_header = struct.pack(
        "<IIQQQQIIQQ",
        shstr_name_offset,
        3,  # SHT_STRTAB
        0,
        0,
        shstr_offset_new,
        len(shstrtab),
        0,
        0,
        1,
        0,
    )
    data.extend(note_header)
    data.extend(shstr_header)

    struct.pack_into("<Q", data, 0x28, new_shoff)
    struct.pack_into("<H", data, 0x3C, e_shnum + 2)
    struct.pack_into("<H", data, 0x3E, e_shnum + 1)

    destination.write_bytes(data)
    destination.chmod(0o755)


def build_manifest() -> dict[str, Any]:
    approval = {
        "status": "approved_before_release",
        "approved_at": "2026-11-26T10:00:00+08:00",
    }
    release_at = "2026-11-28T10:00:00+08:00"
    return {
        "schema": "observability-attribution-manifest/1",
        "release": "2026-11-27-review-candidate",
        "release_at": release_at,
        "approval_policy": "Exact name, provider, artifact, section, and address must match.",
        "markers": [
            {
                "name": "boot.attested",
                "provider": "acme.firmware",
                "section": ".text",
                "address": "0x400420",
                "approved": True,
                "approval": approval,
            },
            {
                "name": "heartbeat",
                "provider": "acme.observability",
                "section": ".text",
                "address": "0x400440",
                "approved": True,
                "approval": approval,
            },
            {
                "name": "trace.flush",
                "provider": "acme.observability",
                "section": ".text",
                "address": "0x400490",
                "approved": True,
                "approval": approval,
            },
            {
                "name": "release.gate",
                "provider": "release.ops",
                "artifact": "program_b.elf",
                "section": ".text",
                "address": "0x4004a0",
                "approved": True,
                "approval": approval,
            },
            {
                "name": "telemetry.dma",
                "provider": "gamma.telemetry",
                "artifact": "program_a.elf",
                "approved": True,
                "approval": approval,
            },
            {
                "name": "runtime.watermark",
                "provider": "acme.runtime",
                "artifact": "program_a.elf",
                "section": ".bss",
                "address": "0x60099c",
                "approved": True,
                "approval": approval,
            },
        ],
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    program_a = OUT_DIR / "program_a.elf"
    program_b = OUT_DIR / "program_b.elf"
    inject_note_section(PROGRAM_A_SOURCE, program_a, A_NOTES)
    inject_note_section(PROGRAM_B_SOURCE, program_b, B_NOTES)
    manifest = build_manifest()
    (OUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {program_a.relative_to(REPO_ROOT)}")
    print(f"wrote {program_b.relative_to(REPO_ROOT)}")
    print("wrote examples/marker_attribution/manifest.json")


if __name__ == "__main__":
    main()

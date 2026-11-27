from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from dissect.fat.exfat import name_hash, utf16_units

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

EOC = 0xFFFFFFFF


def upcase_table(mapping: dict[int, int], length: int = 256) -> bytes:
    """Build an uncompressed up-case table covering ``length`` code points."""
    table = list(range(length))
    for source, target in mapping.items():
        table[source] = target
    return b"".join(struct.pack("<H", value) for value in table)


def _volume_entry(label: str) -> bytes:
    entry = bytearray(32)
    entry[0] = 0x83
    label_data = label.encode("utf-16-le")
    entry[1] = len(label_data) // 2
    entry[2 : 2 + len(label_data)] = label_data
    return bytes(entry)


def _upcase_entry(start_cluster: int, length: int) -> bytes:
    entry = bytearray(32)
    entry[0] = 0x82
    struct.pack_into("<I", entry, 4, 0xE619D30D)
    struct.pack_into("<I", entry, 20, start_cluster)
    struct.pack_into("<Q", entry, 24, length)
    return bytes(entry)


def _file_entry(name: str, file_hash: int, slot: int) -> bytes:
    units = utf16_units(name)
    filename_count = -(-len(units) // 15)

    metadata = bytearray(32)
    metadata[0] = 0x85
    metadata[1] = 1 + filename_count
    metadata[4] = 0x20

    stream = bytearray(32)
    stream[0] = 0xC0
    stream[1] = 0x01
    stream[2] = 0x00
    stream[3] = len(units)
    struct.pack_into("<H", stream, 4, file_hash)
    struct.pack_into("<I", stream, 20, 0)
    struct.pack_into("<Q", stream, 24, 0)

    filename_entries = []
    for index in range(filename_count):
        filename = bytearray(32)
        filename[0] = 0xC1
        filename[1] = 0x00
        chunk = units[index * 15 : (index + 1) * 15]
        padded = chunk + (0,) * (15 - len(chunk))
        struct.pack_into("<15H", filename, 2, *padded)
        filename_entries.append(bytes(filename))

    # The parser does not validate this checksum, but populate it so the entries look realistic.
    struct.pack_into("<H", metadata, 2, slot)
    return bytes(metadata + stream + b"".join(filename_entries))


def build_exfat_image(
    path: Path,
    names: Iterable[str],
    *,
    upcase_mapping: dict[int, int] | None = None,
    include_upcase: bool = True,
) -> dict[str, int]:
    """Create a small one-cluster exFAT root directory and return each name's stored hash."""
    names = list(names)

    if include_upcase:
        table_data = upcase_table(upcase_mapping or {})
        mapping = list(range(0x10000))
        for index in range(256):
            mapping[index] = struct.unpack("<H", table_data[index * 2 : index * 2 + 2])[0]
    else:
        table_data = b""
        mapping = list(range(0x10000))

    def key(name: str) -> tuple[int, ...]:
        return tuple(mapping[unit] for unit in utf16_units(name))

    names = list(names)
    if len(names) > 4:
        raise ValueError("Test image supports at most four file entries")

    root = bytearray(512)
    offset = 0
    root[offset : offset + 32] = _volume_entry("TEST")
    offset += 32

    if include_upcase:
        root[offset : offset + 32] = _upcase_entry(3, len(table_data))
        offset += 32

    hashes = {}
    for slot, name in enumerate(names):
        stored_hash = name_hash(key(name))
        hashes[name] = stored_hash
        entry = _file_entry(name, stored_hash, slot)
        root[offset : offset + len(entry)] = entry
        offset += len(entry)

    data = bytearray(4 * 512)
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x76\x90"
    boot[3:11] = b"EXFAT   "
    struct.pack_into("<I", boot, 0x50, 1)
    struct.pack_into("<I", boot, 0x54, 1)
    struct.pack_into("<I", boot, 0x58, 2)
    struct.pack_into("<I", boot, 0x5C, 2)
    struct.pack_into("<I", boot, 0x60, 2)
    boot[0x6C] = 9
    boot[0x6D] = 0
    boot[0x6E] = 1
    boot[0x6F] = 0x80
    boot[0x1FE:0x200] = b"\x55\xaa"
    data[0:512] = boot

    fat = bytearray(512)
    struct.pack_into("<I", fat, 2 * 4, EOC)
    if include_upcase:
        struct.pack_into("<I", fat, 3 * 4, EOC)
    data[512:1024] = fat

    data[1024:1536] = root
    if include_upcase:
        data[1536 : 1536 + len(table_data)] = table_data

    path.write_bytes(data)
    return hashes

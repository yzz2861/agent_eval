#    This file is part of python-registry.
#
#   Minimal, dependency free synthetic registry hive writer used by the test
#   suite.  The generated hives are parseable by RegistryParse but require no
#   live Windows registry access.  Inputs are treated as read-only.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from __future__ import unicode_literals

import struct

from . import RegistryParse


HBIN_SIZE = 0x1000
CELL_AREA_START = 0x20
CELL_ALIGN = 8


def _align8(size):
    return (size + CELL_ALIGN - 1) & ~(CELL_ALIGN - 1)


def _cell(data):
    total = _align8(len(data) + 4)
    return struct.pack("<i", -total) + data + b"\x00" * (total - 4 - len(data))


def _lh_hash(name_bytes, compressed):
    total = 0
    if compressed:
        for byte in name_bytes:
            if byte < 0x80:
                total += ord(chr(byte).upper())
        return total & 0xFFFFFFFF
    for index in range(0, len(name_bytes) - 1, 2):
        low = name_bytes[index]
        high = name_bytes[index + 1]
        if high == 0 and low < 0x80:
            total += ord(chr(low).upper())
    return total & 0xFFFFFFFF


class SyntheticValue(object):
    def __init__(self, name, data=b"", data_type=RegistryParse.RegSZ,
                 compressed=None):
        self.name = name
        self.data = data
        self.data_type = data_type
        if compressed is None:
            try:
                name.encode("windows-1252")
                compressed = True
            except UnicodeEncodeError:
                compressed = False
        self.compressed = compressed

    def name_bytes(self):
        if self.compressed:
            return self.name.encode("windows-1252")
        return self.name.encode("utf-16le")


class SyntheticKey(object):
    def __init__(self, name, subkeys=None, values=None, compressed=None,
                 root=False):
        self.name = name
        self.subkeys = list(subkeys) if subkeys else []
        self.values = list(values) if values else []
        self.root = root
        if compressed is None:
            try:
                name.encode("windows-1252")
                compressed = True
            except UnicodeEncodeError:
                compressed = False
        self.compressed = compressed

    def name_bytes(self):
        if self.compressed:
            return self.name.encode("windows-1252")
        return self.name.encode("utf-16le")


class _Builder(object):
    """
    All offsets tracked here are relative to the start of the single HBIN.
    Cells live at offsets >= CELL_AREA_START.
    """
    def __init__(self):
        self.cells = bytearray(HBIN_SIZE - CELL_AREA_START)
        self.cursor = 0

    def alloc(self, blob):
        if self.cursor + len(blob) > len(self.cells):
            raise ValueError("synthetic hive exceeds one HBIN")
        offset = self.cursor
        self.cells[offset:offset + len(blob)] = blob
        self.cursor += len(blob)
        return CELL_AREA_START + offset

    def hbin_relative(self, cell_area_index):
        return CELL_AREA_START + cell_area_index

    def build_value(self, value):
        name_bytes = value.name_bytes()
        data = value.data
        if len(data) < 5:
            data_field = data + b"\x00" * (4 - len(data))
            raw_length = len(data) | 0x80000000
            data_offset_field = struct.unpack("<I", data_field)[0]
        else:
            data_cell = self.alloc(_cell(data))
            raw_length = len(data)
            data_offset_field = data_cell

        flags = 1 if value.compressed else 0
        record = b"vk"
        record += struct.pack("<H", len(name_bytes))
        record += struct.pack("<I", raw_length)
        record += struct.pack("<I", data_offset_field)
        record += struct.pack("<I", value.data_type)
        record += struct.pack("<H", flags)
        record += struct.pack("<H", 0)
        record += name_bytes
        return self.alloc(_cell(record))

    def build_values_list(self, offsets):
        blob = b"".join(struct.pack("<I", offset) for offset in offsets)
        return self.alloc(_cell(blob))

    def build_subkey_list(self, node, child_offsets):
        record = b"lh"
        record += struct.pack("<H", len(node.subkeys))
        for child, child_offset in zip(node.subkeys, child_offsets):
            name_bytes = child.name_bytes()
            record += struct.pack("<I", child_offset)
            record += struct.pack("<I", _lh_hash(name_bytes,
                                                  child.compressed))
        return self.alloc(_cell(record))

    def nk_record(self, node, parent_offset, subkey_list_offset,
                  values_list_offset, values_count):
        name_bytes = node.name_bytes()
        flags = 0
        if node.compressed:
            flags |= 0x0020
        if node.root:
            flags |= 0x0004

        record = bytearray(0x4C + len(name_bytes))
        record[0:2] = b"nk"
        struct.pack_into("<H", record, 0x2, flags)
        struct.pack_into("<Q", record, 0x4, 0)
        struct.pack_into("<I", record, 0xC, 0)
        struct.pack_into("<I", record, 0x10, parent_offset)
        struct.pack_into("<I", record, 0x14, len(node.subkeys))
        struct.pack_into("<I", record, 0x18, len(node.subkeys))
        struct.pack_into("<I", record, 0x1C, subkey_list_offset)
        struct.pack_into("<I", record, 0x20, 0)
        struct.pack_into("<I", record, 0x24, values_count)
        struct.pack_into("<I", record, 0x28, values_list_offset)
        for field in (0x2C, 0x30, 0x34, 0x38, 0x3C, 0x40):
            struct.pack_into("<I", record, field, 0xFFFFFFFF)
        struct.pack_into("<I", record, 0x44, 0)
        struct.pack_into("<H", record, 0x48, len(name_bytes))
        struct.pack_into("<H", record, 0x4A, 0)
        record[0x4C:0x4C + len(name_bytes)] = name_bytes
        return bytes(record)

    def build_key(self, node, parent_offset):
        own_offset = CELL_AREA_START + self.cursor
        nk_size = _align8(4 + 0x4C + len(node.name_bytes()))
        self.alloc(b"\x00" * nk_size)

        child_offsets = [self.build_key(child, own_offset)
                         for child in node.subkeys]
        value_offsets = [self.build_value(value) for value in node.values]

        subkey_list_offset = (self.build_subkey_list(node, child_offsets)
                              if child_offsets else 0xFFFFFFFF)
        values_count = len(value_offsets)
        values_list_offset = (self.build_values_list(value_offsets)
                              if value_offsets else 0xFFFFFFFF)

        record = self.nk_record(node, parent_offset, subkey_list_offset,
                                values_list_offset, values_count)
        cell = _cell(record)
        target = own_offset - CELL_AREA_START
        self.cells[target:target + len(cell)] = cell
        return own_offset


def build_hive(root, hive_name="synthetic"):
    """
    Serialize a SyntheticKey tree into a complete, in-memory registry hive
    byte string.  The returned bytes can be wrapped by io.BytesIO and opened
    with Registry.Registry; nothing is written to the system registry.
    """
    root.root = True
    builder = _Builder()
    root_relative = builder.build_key(root, CELL_AREA_START)

    hbin = bytearray(HBIN_SIZE)
    hbin[0:4] = b"hbin"
    struct.pack_into("<I", hbin, 0x4, 0)
    struct.pack_into("<I", hbin, 0x8, HBIN_SIZE)
    hbin[CELL_AREA_START:CELL_AREA_START + len(builder.cells)] = builder.cells

    header = bytearray(0x1000)
    header[0:4] = b"regf"
    struct.pack_into("<I", header, 0x4, 1)
    struct.pack_into("<I", header, 0x8, 1)
    struct.pack_into("<I", header, 0x14, 1)
    struct.pack_into("<I", header, 0x18, 3)
    struct.pack_into("<I", header, 0x1C, 0)
    struct.pack_into("<I", header, 0x20, 1)
    struct.pack_into("<I", header, 0x24, root_relative)
    struct.pack_into("<I", header, 0x28, HBIN_SIZE)
    struct.pack_into("<I", header, 0x2C, 1)
    encoded_name = hive_name.encode("utf-16le")[:62]
    header[0x30:0x30 + len(encoded_name)] = encoded_name

    checksum = 0
    for index in range(0, 0x200, 4):
        checksum ^= struct.unpack_from("<I", bytes(header), index)[0]
    if checksum == 0:
        checksum = 1
    elif checksum == 0xFFFFFFFF:
        checksum = 0xFFFFFFFE
    struct.pack_into("<I", header, 0x1FC, checksum)

    return bytes(header) + bytes(hbin)


def open_synthetic(root, hive_name="synthetic"):
    import io
    from .Registry import Registry
    return Registry(io.BytesIO(build_hive(root, hive_name)))

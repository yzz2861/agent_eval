#!/bin/python

#    This file is part of python-registry.
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
"""
A minimal, self-contained Windows registry hive writer.

It implements only the subset of the hive file format required by the
mount-view tests: a REGF header, one HBIN and nk/vk/li cells with inline
data cells. That is enough to build tiny hives containing ordinary keys and
RegLink symbolic-link keys without depending on a Windows host or any third
party hive generator.
"""
from __future__ import print_function

import struct

from .Registry import RegDWord
from .Registry import RegLink
from .Registry import RegSZ

HBIN_OFFSET = 0x1000


def _utf16le(text):
    return text.encode("utf-16le")


class ValueSpec(object):
    """
    One value (vk record plus inline data) to attach to a key.
    """
    def __init__(self, name, data_type, data):
        self.name = name
        self.data_type = data_type
        self.data = data

    @staticmethod
    def string(name, text):
        return ValueSpec(name, RegSZ, _utf16le(text) + b"\x00\x00")

    @staticmethod
    def dword(name, value):
        return ValueSpec(name, RegDWord, struct.pack("<I", value))

    @staticmethod
    def link(name, target_path):
        return ValueSpec(name, RegLink,
                         _utf16le(target_path) + b"\x00\x00")


class HiveBuilder(object):
    """
    Build a tiny, single-HBIN registry hive from an in-memory tree.
    """
    def __init__(self, evidence_id, internal_hive_name, root_name="ROOT"):
        self.evidence_id = evidence_id
        self.internal_hive_name = internal_hive_name
        self.root_name = root_name
        self._tree = {"__values__": [], "__children__": {}}
        self._nk_offsets = {}

    def add_key(self, path_parts, values=None):
        node = self._tree
        for part in path_parts:
            if part not in node["__children__"]:
                node["__children__"][part] = {
                    "__values__": [], "__children__": {}}
            node = node["__children__"][part]
        for value in values or []:
            node["__values__"].append(self._as_value_spec(value))
        return node

    @staticmethod
    def _as_value_spec(value):
        if isinstance(value, ValueSpec):
            return value
        name, data_type, data = value
        return ValueSpec(name, data_type, data)

    def key_offset(self, path_parts):
        """
        Absolute file offset of a key's nk record, available after build().
        """
        return self._nk_offsets[tuple(path_parts)]

    def build(self):
        cells = []

        def emit_cell(raw):
            total = len(raw) + 4
            if total % 8 != 0:
                total += 8 - (total % 8)
            cell = bytearray(total)
            struct.pack_into("<i", cell, 0, -total)
            cell[4:4 + len(raw)] = raw
            cells.append(cell)
            return 0x20 + sum(len(c) for c in cells[:-1]) + 4

        def emit_value(value):
            value = self._as_value_spec(value)
            data_rel = emit_cell(value.data)
            name_raw = _utf16le(value.name)
            vk_size = 0x14 + len(name_raw)  # name_raw is UTF-16LE bytes
            if vk_size % 4 != 0:
                vk_size += 4 - (vk_size % 4)
            vk = bytearray(vk_size)
            vk[0:2] = b"vk"
            struct.pack_into("<H", vk, 0x2, len(name_raw))  # parser reads byte count
            struct.pack_into("<I", vk, 0x4, len(value.data))
            struct.pack_into("<I", vk, 0x8, data_rel - 4)  # VK data field points at the cell start
            struct.pack_into("<I", vk, 0xC, value.data_type)
            struct.pack_into("<H", vk, 0x10, 0)
            vk[0x14:0x14 + len(name_raw)] = name_raw
            return emit_cell(bytes(vk))

        def emit_subkey_list(child_rels):
            raw = bytearray(4 + 4 * len(child_rels))
            raw[0:2] = b"li"
            struct.pack_into("<H", raw, 0x2, len(child_rels))
            for index, rel in enumerate(child_rels):
                struct.pack_into("<I", raw, 4 + 4 * index, rel - 4)
            return emit_cell(bytes(raw))

        def emit_nk(name, is_root, values, child_rels, parent_rel,
                    value_list_rel, subkey_list_rel):
            name_raw = _utf16le(name)
            nk_size = 0x50 + len(name_raw)
            if nk_size % 4 != 0:
                nk_size += 4 - (nk_size % 4)
            nk = bytearray(nk_size)
            nk[0:2] = b"nk"
            # UTF-16LE names: keep the ASCII-name flag (0x20) clear.
            flags = 0
            if is_root:
                flags |= 0x04
            if any(v.data_type == RegLink for v in values):
                flags |= 0x10
            struct.pack_into("<H", nk, 0x2, flags)
            struct.pack_into("<Q", nk, 0x4, 0)
            struct.pack_into("<Q", nk, 0xC, 0)
            return emit_nk_tail(nk, name_raw, name, values, child_rels,
                                parent_rel, value_list_rel, subkey_list_rel)

        def emit_nk_tail(nk, name_raw, name, values, child_rels,
                         parent_rel, value_list_rel, subkey_list_rel):
            struct.pack_into("<I", nk, 0x10,
                             parent_rel if parent_rel is not None
                             else 0xFFFFFFFF)
            struct.pack_into("<I", nk, 0x14, len(child_rels))
            struct.pack_into("<I", nk, 0x18, 0)
            struct.pack_into("<I", nk, 0x1C,
                             subkey_list_rel - 4 if subkey_list_rel is not None
                             else 0xFFFFFFFF)
            struct.pack_into("<I", nk, 0x20, 0)
            struct.pack_into("<I", nk, 0x24, len(values))
            struct.pack_into("<I", nk, 0x28,
                             value_list_rel - 4 if value_list_rel is not None
                             else 0xFFFFFFFF)
            struct.pack_into("<I", nk, 0x2C, 0xFFFFFFFF)
            struct.pack_into("<I", nk, 0x30, 0xFFFFFFFF)
            struct.pack_into("<I", nk, 0x34, 0xFFFFFFFF)
            struct.pack_into("<I", nk, 0x38, 0xFFFFFFFF)
            struct.pack_into("<I", nk, 0x3C, 0xFFFFFFFF)
            struct.pack_into("<I", nk, 0x40, 0xFFFFFFFF)
            struct.pack_into("<I", nk, 0x44, 0xFFFFFFFF)
            struct.pack_into("<H", nk, 0x48, len(name_raw))
            struct.pack_into("<H", nk, 0x4A, 0)
            nk[0x4C:0x4C + len(name_raw)] = name_raw
            return emit_cell(bytes(nk))

        def build_node(node, parts, parent_rel):
            child_rels = []
            for child_name in sorted(node["__children__"].keys()):
                child = node["__children__"][child_name]
                child_rels.append(build_node(child, parts + [child_name], None))

            vk_rels = [emit_value(v) for v in node["__values__"]]
            value_list_rel = None
            if vk_rels:
                list_raw = bytearray(4 * len(vk_rels))
                for index, rel in enumerate(vk_rels):
                    struct.pack_into("<I", list_raw, 4 * index, rel - 4)
                value_list_rel = emit_cell(bytes(list_raw))

            subkey_list_rel = emit_subkey_list(child_rels) if child_rels else None
            name = self.root_name if not parts else parts[-1]
            value_specs = [HiveBuilder._as_value_spec(v) for v in node["__values__"]]
            nk_rel = emit_nk(name, not parts, value_specs, child_rels,
                             parent_rel, value_list_rel, subkey_list_rel)
            for child_rel in child_rels:
                cell_offset = child_rel - 0x20 - 4
                cursor = 0
                for cell in cells:
                    if cursor == cell_offset:
                        struct.pack_into("<I", cell, 0x4 + 0x10, nk_rel - 4)
                        break
                    cursor += len(cell)
            self._nk_offsets[tuple(parts)] = HBIN_OFFSET + nk_rel
            return nk_rel

        root_rel = build_node(self._tree, [], None)

        data = b"".join(cells)
        hbin_size = 0x20 + len(data)
        hbin_size = ((hbin_size + 0xFFF) // 0x1000) * 0x1000
        hbin = bytearray(hbin_size)
        hbin[0:4] = b"hbin"
        struct.pack_into("<I", hbin, 0x4, 0)
        struct.pack_into("<I", hbin, 0x8, hbin_size)
        struct.pack_into("<Q", hbin, 0xC, 0)
        hbin[0x20:0x20 + len(data)] = data

        header = bytearray(HBIN_OFFSET)
        header[0:4] = b"regf"
        struct.pack_into("<I", header, 0x4, 1)
        struct.pack_into("<I", header, 0x8, 1)
        struct.pack_into("<Q", header, 0xC, 0)
        struct.pack_into("<I", header, 0x14, 1)
        struct.pack_into("<I", header, 0x18, 3)
        struct.pack_into("<I", header, 0x1C, 0)
        struct.pack_into("<I", header, 0x20, 1)
        struct.pack_into("<I", header, 0x24, root_rel - 4)
        struct.pack_into("<I", header, 0x28, hbin_size)
        struct.pack_into("<I", header, 0x2C, 1)
        name_utf16 = _utf16le(self.internal_hive_name)[:64]
        header[0x30:0x30 + len(name_utf16)] = name_utf16

        checksum = 0
        for index in range(0, 0x1FC, 4):
            checksum ^= struct.unpack_from("<I", header, index)[0]
        if checksum == 0:
            checksum = 1
        elif checksum == 0xFFFFFFFF:
            checksum = 0xFFFFFFFE
        struct.pack_into("<I", header, 0x1FC, checksum)

        return bytes(header) + bytes(hbin)

#!/bin/python

#    This file is part of python-registry.
#
#   A small, self contained, write-only producer of synthetic registry hive
#   images.  It deliberately supports just enough of the on-disk format to be
#   re-opened by the read-only parser in Registry.RegistryParse, and it exposes
#   the low level knobs (declared data length, inline storage, raw bytes) that
#   forensic tooling needs in order to craft edge cases such as missing string
#   terminators or length/type mismatches.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0

from __future__ import print_function

import struct


REGF_SIZE = 0x1000
HBIN_SIZE = 0x1000
HBIN_PAYLOAD_OFFSET = 0x20
INLINE_THRESHOLD = 5
INLINE_FLAG = 0x80000000


def _align8(value):
    return (value + 7) & ~7


class SyntheticHive(object):
    """
    Build a minimal, single-HBIN registry hive image in memory.

    The produced byte string is a well formed primary file (valid ``regf``
    header, checksum, ``hbin`` block, root ``nk`` record and ``sk`` security
    record) so that :class:`Registry.Registry` can parse it.  Individual values
    may still carry intentionally malformed data when the caller supplies an
    explicit raw payload or a mismatched declared length.
    """

    def __init__(self, root_name, hive_name):
        """
        Arguments:
        - `root_name`: name stored in the root key record.
        - `hive_name`: UTF-16LE internal file name placed in the header.
        """
        self._root_name = root_name
        self._hive_name = hive_name
        self._subkeys = []
        self._values = []

    def add_value(self, name, data_type, raw, declared_length=None,
                  force_inline=False):
        """
        Attach a value to the root key.

        Arguments:
        - `name`: value name (``""`` denotes the default value).
        - `data_type`: registry type code (e.g. ``RegSZ``).
        - `raw`: exact bytes to store as the value data.
        - `declared_length`: length written into the VK record.  Defaults to
          ``len(raw)``; pass a different value to synthesize length anomalies.
        - `force_inline`: store up to four bytes inside the VK record even when
          the declared length would normally imply a separate data cell.
        """
        self._values.append({
            "key": None,
            "name": name,
            "type": data_type,
            "raw": bytes(raw),
            "declared_length": len(raw) if declared_length is None
            else declared_length,
            "force_inline": force_inline,
        })

    def add_key_value(self, key_name, name, data_type, raw,
                      declared_length=None, force_inline=False):
        """Attach a value to a named subkey, creating the subkey as needed."""
        if key_name not in self._subkeys:
            self._subkeys.append(key_name)
        self._values.append({
            "key": key_name,
            "name": name,
            "type": data_type,
            "raw": bytes(raw),
            "declared_length": len(raw) if declared_length is None
            else declared_length,
            "force_inline": force_inline,
        })

    @staticmethod
    def sz(text):
        """Encode ``text`` as a properly terminated UTF-16LE REG_SZ payload."""
        return (text + u"\x00").encode("utf-16le")

    @staticmethod
    def dword(number):
        """Encode an unsigned 32 bit integer as a REG_DWORD payload."""
        return struct.pack("<I", number & 0xFFFFFFFF)

    @staticmethod
    def qword(number):
        """Encode an unsigned 64 bit integer as a REG_QWORD payload."""
        return struct.pack("<Q", number & 0xFFFFFFFFFFFFFFFF)

    @staticmethod
    def multi_sz(texts):
        """Encode a sequence of strings as a double-null terminated REG_MULTI_SZ."""
        encoded = u"".join(text + u"\x00" for text in texts) + u"\x00"
        return encoded.encode("utf-16le")

    @staticmethod
    def _cell(body):
        total = _align8(len(body) + 4)
        size = -total
        return struct.pack("<i", size) + body + bytearray(total - 4 - len(body))

    def _build_sk(self):
        # A minimal self-relative security descriptor.  The parser only checks
        # the "sk" signature and the SK list links; a null descriptor is valid.
        descriptor = struct.pack("<HHIIII", 1, 0, 0, 0, 0, 0)
        body = b"sk" + struct.pack("<II", 0, 0) + descriptor
        return self._cell(body)

    def build(self):
        """Return the complete hive image as a byte string."""
        root_values = [v for v in self._values if v["key"] is None]
        subkey_names = list(self._subkeys)
        subkey_values = dict(
            (name, [v for v in self._values if v["key"] == name])
            for name in subkey_names)

        layout = _HiveLayout(self._root_name, self._hive_name)
        layout.add_slot("sk")
        for name in subkey_names:
            for index, _value in enumerate(subkey_values[name]):
                if not self._is_inline(_value):
                    layout.add_slot(self._data_slot(name, index))
                layout.add_slot(self._vk_slot(name, index))
            layout.add_slot(self._vlist_slot(name))
        for index, _value in enumerate(root_values):
            if not self._is_inline(_value):
                layout.add_slot(self._data_slot(None, index))
            layout.add_slot(self._vk_slot(None, index))
        if root_values:
            layout.add_slot("root::vlist")
        if subkey_names:
            layout.add_slot("root::lh")
        for name in subkey_names:
            layout.add_slot(self._nk_slot(name))
        layout.add_slot("root::nk")

        def render(slot, resolver):
            if slot == "sk":
                return self._build_sk()
            if "::data::" in slot:
                value = self._slot_value(slot, root_values, subkey_values)
                return self._cell(value["raw"])
            if "::vk::" in slot:
                value = self._slot_value(slot, root_values, subkey_values)
                return self._render_vk(value, slot, resolver)
            if slot == "root::vlist":
                rels = [resolver(self._vk_slot(None, i)) for i in range(len(root_values))]
                body = b"".join(struct.pack("<I", rel) for rel in rels)
                return self._cell(body)
            if slot.endswith("::vlist"):
                name = slot.split("::")[0]
                vals = subkey_values[name]
                rels = [resolver(self._vk_slot(name, i)) for i in range(len(vals))]
                body = b"".join(struct.pack("<I", rel) for rel in rels)
                return self._cell(body)
            if slot == "root::lh":
                entries = b""
                for name in subkey_names:
                    entries += struct.pack("<II", resolver(self._nk_slot(name)), 0)
                header = b"lh" + struct.pack("<H", len(subkey_names))
                return self._cell(header + entries)
            if slot == "root::nk":
                vlist = resolver("root::vlist") if root_values else 0xFFFFFFFF
                lh = resolver("root::lh") if subkey_names else 0xFFFFFFFF
                return self._render_nk(self._root_name, resolver("sk"), 0,
                                       len(subkey_names), lh,
                                       len(root_values), vlist, True)
            if slot.endswith("::nk"):
                name = slot.split("::")[0]
                vals = subkey_values[name]
                vlist = resolver(self._vlist_slot(name)) if vals else 0xFFFFFFFF
                return self._render_nk(name, resolver("sk"),
                                       resolver("root::nk"), 0, 0xFFFFFFFF,
                                       len(vals), vlist, False)
            raise RegistryHiveBuildError("unknown layout slot %r" % slot)

        layout.measure(render)
        return layout.assemble(render, resolver=lambda slot: layout._slot_rels[slot])

    @staticmethod
    def _is_inline(value):
        return value["force_inline"] or value["declared_length"] < INLINE_THRESHOLD

    @staticmethod
    def _data_slot(name, index):
        prefix = "root" if name is None else name
        return prefix + "::data::" + str(index)

    @staticmethod
    def _vk_slot(name, index):
        prefix = "root" if name is None else name
        return prefix + "::vk::" + str(index)

    @staticmethod
    def _vlist_slot(name):
        return ("root" if name is None else name) + "::vlist"

    @staticmethod
    def _nk_slot(name):
        return name + "::nk"

    @staticmethod
    def _slot_value(slot, root_values, subkey_values):
        parts = slot.split("::")
        index = int(parts[2])
        if parts[0] == "root":
            return root_values[index]
        return subkey_values[parts[0]][index]

    def _render_vk(self, value, slot, resolver):
        raw = value["raw"]
        declared = value["declared_length"]
        name_bytes = value["name"].encode("ascii")
        body = bytearray(0x14)
        struct.pack_into("<H", body, 0x0, 0x6B76)
        struct.pack_into("<H", body, 0x2, len(name_bytes))
        if self._is_inline(value):
            length_field = declared | INLINE_FLAG
            inline_area = bytearray(4)
            inline_area[:len(raw)] = raw
            struct.pack_into("<I", body, 0x8,
                             struct.unpack("<I", bytes(inline_area))[0])
        else:
            length_field = declared
            data_slot = slot.replace("::vk::", "::data::")
            struct.pack_into("<I", body, 0x8, resolver(data_slot))
        struct.pack_into("<I", body, 0x4, length_field)
        struct.pack_into("<I", body, 0xC, value["type"])
        struct.pack_into("<H", body, 0x10, 0x1)
        body += name_bytes
        return self._cell(bytes(body))

    def _render_nk(self, name, sk_rel, parent_rel, subkey_count,
                   subkey_list_rel, value_count, values_list_rel, is_root):
        flags = 0x0020
        if is_root:
            flags |= 0x0004
        name_bytes = name.encode("ascii")
        body = bytearray(0x4C)
        struct.pack_into("<HH", body, 0x0, 0x6B6E, flags)
        struct.pack_into("<Q", body, 0x4, 0)
        struct.pack_into("<I", body, 0x10, parent_rel)
        struct.pack_into("<I", body, 0x14, subkey_count)
        struct.pack_into("<I", body, 0x1C, subkey_list_rel)
        struct.pack_into("<I", body, 0x24, value_count)
        struct.pack_into("<I", body, 0x28, values_list_rel)
        struct.pack_into("<I", body, 0x2C, sk_rel)
        struct.pack_into("<H", body, 0x48, len(name_bytes))
        body += name_bytes
        return self._cell(bytes(body))


class _HiveLayout(object):
    """Two phase planner for the single 0x1000 byte HBIN payload region."""

    def __init__(self, root_name, hive_name):
        self._root_name = root_name
        self._hive_name = hive_name
        self._slots = []
        self._slot_rels = {}

    def add_slot(self, name):
        if name in self._slot_rels:
            raise RegistryHiveBuildError("duplicate layout slot %r" % name)
        self._slots.append(name)

    def measure(self, render):
        cursor = HBIN_PAYLOAD_OFFSET
        for slot in self._slots:
            self._slot_rels[slot] = cursor
            cell = render(slot, lambda _name: 0)
            cursor += len(cell)
        used = cursor
        available = HBIN_SIZE - HBIN_PAYLOAD_OFFSET
        if used > available:
            raise RegistryHiveBuildError(
                "synthetic hive exceeds the single %d byte HBIN" % HBIN_SIZE)

    def assemble(self, render, resolver):
        remaining = (HBIN_SIZE - HBIN_PAYLOAD_OFFSET)
        arena = bytearray()
        cursor = HBIN_PAYLOAD_OFFSET
        for slot in self._slots:
            cell = render(slot, resolver)
            expected = self._slot_rels[slot]
            if expected != cursor:
                raise RegistryHiveBuildError("layout drift at slot %r" % slot)
            arena += cell
            cursor += len(cell)
        free_size = _align8(remaining - len(arena))
        if free_size > remaining - len(arena):
            free_size -= 8
        if free_size >= 4:
            arena += struct.pack("<i", free_size)
            arena += bytearray(free_size - 4)

        header = bytearray(REGF_SIZE)
        struct.pack_into("<I", header, 0x0, 0x66676572)
        struct.pack_into("<II", header, 0x4, 1, 1)
        struct.pack_into("<Q", header, 0xC, 0)
        struct.pack_into("<I", header, 0x14, 1)
        struct.pack_into("<I", header, 0x18, 3)
        struct.pack_into("<I", header, 0x1C, 0)
        struct.pack_into("<I", header, 0x20, 1)
        struct.pack_into("<I", header, 0x24, self._slot_rels["root::nk"])
        struct.pack_into("<I", header, 0x28, HBIN_SIZE)
        struct.pack_into("<I", header, 0x2C, 1)
        name_encoded = self._hive_name.encode("utf-16le")[:62]
        header[0x30:0x30 + len(name_encoded)] = name_encoded
        checksum = self._checksum(bytes(header[:0x200]))
        struct.pack_into("<I", header, 0x1FC, checksum)

        hbin = bytearray(HBIN_SIZE)
        struct.pack_into("<I", hbin, 0x0, 0x6E696268)
        struct.pack_into("<I", hbin, 0x4, 0)
        struct.pack_into("<Q", hbin, 0x8, HBIN_SIZE)
        struct.pack_into("<Q", hbin, 0x10, 0)
        hbin[HBIN_PAYLOAD_OFFSET:HBIN_PAYLOAD_OFFSET + len(arena)] = bytes(arena)
        return bytes(header) + bytes(hbin)

    @staticmethod
    def _checksum(header_block):
        checksum = 0
        for index in range(0, 0x200, 4):
            checksum ^= struct.unpack_from("<I", header_block, index)[0]
        if checksum == 0:
            return 1
        if checksum == 0xFFFFFFFF:
            return 0xFFFFFFFE
        return checksum


class RegistryHiveBuildError(Exception):
    """Raised when the synthetic image cannot be laid out."""

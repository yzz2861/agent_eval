"""
Small deterministic Registry hive builder used by the identity tests.

Only the subset needed to exercise the high-level python-registry parser is
implemented: REGF header, one HBIN, NK/VK cells, direct subkey lists, value
lists and inline or cell-backed value data.
"""
from __future__ import print_function

import struct


REGF_MAGIC = 0x66676572
HBIN_MAGIC = 0x6E696268

REG_NONE = 0x0000
REG_SZ = 0x0001
REG_EXPAND_SZ = 0x0002
REG_BINARY = 0x0003
REG_DWORD = 0x0004
REG_LINK = 0x0006

HBIN_BASE = 0x1000
HBIN_HEADER = 0x20
CELL_HEADER = 0x4


def pad8(data):
    remainder = len(data) % 8
    if remainder:
        data += b"\x00" * (8 - remainder)
    return data


def utf16(text):
    return (text + "\x00").encode("utf-16le")


def dword(value):
    return struct.pack("<I", value & 0xFFFFFFFF)


def sid_bytes(sid):
    """Encode a textual SID into the binary Windows representation."""
    parts = sid.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    subauthorities = [int(part) for part in parts[3:]]
    return (struct.pack("<BB", revision, len(subauthorities))
            + authority.to_bytes(6, "big")
            + struct.pack("<" + ("I" * len(subauthorities)),
                          *subauthorities))


def sam_v(username, full_name=None, profile_path=None):
    """Build the fixed-header + UTF-16 string layout of a SAM ``V`` value."""
    base = 0xCC
    data = bytearray(base)
    fields = (
        (0x0C, username),
        (0x18, full_name),
        (0x6C, profile_path),
    )
    for position, text in fields:
        if not text:
            continue
        encoded = text.encode("utf-16le")
        struct.pack_into("<I", data, position, len(data) - base)
        struct.pack_into("<I", data, position + 4, len(encoded))
        data += encoded
    return bytes(data)


def sam_f(rid, flags=0):
    data = bytearray(0x50)
    struct.pack_into("<I", data, 0x30, rid)
    struct.pack_into("<H", data, 0x38, flags)
    return bytes(data)


class Cell(object):
    def __init__(self, payload=b""):
        self.set_payload(payload)
        self.relative_offset = None

    def set_payload(self, payload):
        self.payload = pad8(payload)
        self.size = CELL_HEADER + len(self.payload)

    def render(self):
        return struct.pack("<i", -self.size) + self.payload


class HiveBuilder(object):
    """Build a tiny hive that the unmodified Registry.Registry can open."""

    def __init__(self, internal_name, root_name="ROOT"):
        self.internal_name = internal_name
        self.cells = []
        self.root = self._create_nk(root_name, is_root=True)

    def _new_cell(self, payload=b""):
        cell = Cell(payload)
        self.cells.append(cell)
        return cell

    def _create_nk(self, name, is_root=False):
        name_bytes = name.encode("windows-1252")
        flags = 0x0020
        if is_root:
            flags |= 0x0004
        payload = bytearray(0x4C)
        payload[0x0:0x2] = b"nk"
        struct.pack_into("<H", payload, 0x2, flags)
        struct.pack_into("<I", payload, 0x10, 0xFFFFFFFF)
        struct.pack_into("<I", payload, 0x14, 0)
        struct.pack_into("<I", payload, 0x1C, 0xFFFFFFFF)
        struct.pack_into("<I", payload, 0x24, 0)
        struct.pack_into("<I", payload, 0x28, 0xFFFFFFFF)
        struct.pack_into("<I", payload, 0x30, 0xFFFFFFFF)
        struct.pack_into("<I", payload, 0x34, 0xFFFFFFFF)
        struct.pack_into("<H", payload, 0x48, len(name_bytes))
        payload += name_bytes
        return {
            "cell": self._new_cell(bytes(payload)),
            "name": name,
            "is_root": is_root,
            "parent": None,
            "subkeys": [],
            "values": [],
            "subkey_list": None,
            "value_list": None,
        }

    def add_key(self, parent, name, values=None):
        key = self._create_nk(name)
        key["parent"] = parent
        parent["subkeys"].append(key)
        for value_name, pair in (values or {}).items():
            value_type, raw = pair
            self.add_value(key, value_name, value_type, raw)
        return key

    def add_value(self, key, name, value_type, raw):
        name_bytes = name.encode("windows-1252") if name else b""
        if len(raw) < 5:
            data_field = raw.ljust(4, b"\x00")[:4]
            stored_length = len(raw) | 0x80000000
            data_cell = None
        else:
            data_cell = self._new_cell(raw)
            data_field = None
            stored_length = len(raw)

        flags = 0x0001 if name_bytes else 0x0000
        payload = bytearray(0x14)
        payload[0x0:0x2] = b"vk"
        struct.pack_into("<H", payload, 0x2, len(name_bytes))
        struct.pack_into("<I", payload, 0x4, stored_length)
        struct.pack_into("<I", payload, 0x8, 0)
        struct.pack_into("<I", payload, 0xC, value_type)
        struct.pack_into("<H", payload, 0x10, flags)
        if data_field is not None:
            payload[0x8:0xC] = data_field
        payload += name_bytes
        vk_cell = self._new_cell(bytes(payload))

        key["values"].append({
            "vk": vk_cell,
            "data": data_cell,
            "name": name,
            "type": value_type,
            "raw": raw,
        })
        return vk_cell

    def _all_keys(self):
        result = []
        stack = [self.root]
        while stack:
            key = stack.pop()
            result.append(key)
            stack.extend(reversed(key["subkeys"]))
        return result

    def build(self):
        cursor = HBIN_HEADER
        for cell in self.cells:
            cell.relative_offset = cursor
            cursor += cell.size

        for key in self._all_keys():
            if key["subkeys"]:
                entries = b""
                for child in key["subkeys"]:
                    entries += struct.pack("<I", child["cell"].relative_offset)
                    entries += b"\x00\x00\x00\x00"
                payload = (b"lf" + struct.pack("<H", len(key["subkeys"]))
                           + entries)
                key["subkey_list"] = self._new_cell(payload)
            if key["values"]:
                entries = b"".join(
                    struct.pack("<I", value["vk"].relative_offset)
                    for value in key["values"])
                key["value_list"] = self._new_cell(entries)

        for cell in self.cells:
            if cell.relative_offset is None:
                cell.relative_offset = cursor
                cursor += cell.size

        for key in self._all_keys():
            base = key["cell"].relative_offset + CELL_HEADER
            if key["parent"] is not None:
                self._patch_dword(base + 0x10,
                                  key["parent"]["cell"].relative_offset)
            if key["subkeys"]:
                self._patch_dword(base + 0x14, len(key["subkeys"]))
                self._patch_dword(base + 0x1C,
                                  key["subkey_list"].relative_offset)
            if key["values"]:
                self._patch_dword(base + 0x24, len(key["values"]))
                self._patch_dword(base + 0x28,
                                  key["value_list"].relative_offset)

        for key in self._all_keys():
            for value in key["values"]:
                if value["data"] is not None:
                    vk_base = value["vk"].relative_offset + CELL_HEADER
                    self._patch_dword(vk_base + 0x8,
                                      value["data"].relative_offset)

        return self._render_file(cursor)

    def _patch_dword(self, absolute_offset, value):
        for cell in self.cells:
            record_start = cell.relative_offset + CELL_HEADER
            record_end = record_start + len(cell.payload)
            if record_start <= absolute_offset < record_end:
                within = absolute_offset - record_start
                cell.payload = (
                    cell.payload[:within]
                    + struct.pack("<I", value)
                    + cell.payload[within + 4:])
                return
        raise RuntimeError("cannot patch offset 0x%x" % absolute_offset)

    def _render_file(self, used_data_end):
        hbin_size = max(((used_data_end + 0xFFF) // 0x1000) * 0x1000,
                        0x1000)
        hbin = bytearray(hbin_size)
        struct.pack_into("<I", hbin, 0x0, HBIN_MAGIC)
        struct.pack_into("<I", hbin, 0x4, 0)
        struct.pack_into("<I", hbin, 0x8, hbin_size)
        struct.pack_into("<I", hbin, 0xC, 0)
        struct.pack_into("<Q", hbin, 0x14, 0)
        for cell in self.cells:
            start = cell.relative_offset
            hbin[start:start + cell.size] = cell.render()
        used = HBIN_HEADER + sum(cell.size for cell in self.cells)
        free_size = hbin_size - used
        if free_size >= CELL_HEADER:
            struct.pack_into("<i", hbin, used, free_size)

        regf = bytearray(HBIN_BASE)
        struct.pack_into("<I", regf, 0x0, REGF_MAGIC)
        struct.pack_into("<I", regf, 0x4, 1)
        struct.pack_into("<I", regf, 0x8, 1)
        struct.pack_into("<Q", regf, 0xC, 0)
        struct.pack_into("<I", regf, 0x14, 1)
        struct.pack_into("<I", regf, 0x18, 3)
        struct.pack_into("<I", regf, 0x1C, 0)
        struct.pack_into("<I", regf, 0x20, 1)
        struct.pack_into("<I", regf, 0x24,
                         self.root["cell"].relative_offset)
        struct.pack_into("<I", regf, 0x28, hbin_size)
        struct.pack_into("<I", regf, 0x2C, 1)
        name_utf16 = self.internal_name.encode("utf-16le")[:62].ljust(
            64, b"\x00")
        regf[0x30:0x70] = name_utf16
        checksum = 0
        for index in range(0, 0x200, 4):
            checksum ^= struct.unpack_from("<I", regf, index)[0]
        if checksum == 0:
            checksum = 1
        struct.pack_into("<I", regf, 0x1FC, checksum)
        return bytes(regf) + bytes(hbin)

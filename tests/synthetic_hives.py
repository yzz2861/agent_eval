"""Pure-Python synthetic Registry hives for cross-platform tests."""

import io
import struct

from Registry import Registry


HBIN_FILE_OFFSET = 0x1000
HBIN_REL_OFFSET = 0x1000
ROOT_CELL_REL = 0x20
FIRST_KEY_SLOT_REL = 0x80
KEY_SLOT_SIZE = 0x80
AUX_START_REL = 0x1000

T_OLD = 130000000000000000
T_NEW = T_OLD + 100000000
T_OTHER = T_OLD + 500000000


class ValueSpec(object):
    def __init__(self, name, dword=None, data=None, data_type=0x0004,
                 offset=None):
        self.name = name
        if dword is not None:
            self.data = struct.pack("<I", dword)
        else:
            self.data = data or b""
        self.data_type = data_type
        self.offset = offset
        self.rel = None


class KeySpec(object):
    def __init__(self, name, timestamp=T_OLD, values=(), children=(),
                 offset=None):
        self.name = name
        self.timestamp = timestamp
        self.values = list(values)
        self.children = list(children)
        self.offset = offset
        self.rel = None
        self.parent = None
        for child in self.children:
            child.parent = self

    def add(self, child):
        child.parent = self
        self.children.append(child)
        return child


def _align8(size):
    return (size + 7) & ~7


class SyntheticHive(object):
    """A tiny deterministic hive writer used only by tests."""

    def __init__(self, hbin_size=0x3000):
        self.hbin_size = hbin_size
        self.buf = bytearray(HBIN_FILE_OFFSET + hbin_size)
        self.aux_cursor = AUX_START_REL
        self.cells = []
        self.reserved = []
        self._write_regf_header()
        self._write_hbin_header()

    def _write_regf_header(self):
        buf = self.buf
        struct.pack_into("<I", buf, 0x00, 0x66676572)  # "regf"
        struct.pack_into("<I", buf, 0x04, 1)
        struct.pack_into("<I", buf, 0x08, 1)
        struct.pack_into("<Q", buf, 0x0C, T_OLD)
        struct.pack_into("<I", buf, 0x14, 1)
        struct.pack_into("<I", buf, 0x18, 3)
        struct.pack_into("<I", buf, 0x1C, 0)  # primary hive
        struct.pack_into("<I", buf, 0x20, 1)
        struct.pack_into("<I", buf, 0x24, ROOT_CELL_REL)
        struct.pack_into("<I", buf, 0x28, self.hbin_size)
        struct.pack_into("<I", buf, 0x2C, 1)
        name = "synthetic".encode("utf-16le") + bytes(2)
        buf[0x30:0x30 + len(name)] = name
        struct.pack_into("<I", buf, 0x1FC, self._checksum())

    def _write_hbin_header(self):
        base = HBIN_FILE_OFFSET
        struct.pack_into("<I", self.buf, base + 0x00, 0x6E696268)  # "hbin"
        struct.pack_into("<I", self.buf, base + 0x04, 0)
        struct.pack_into("<I", self.buf, base + 0x08, self.hbin_size)

    def _checksum(self):
        view = self.buf[:0x200]
        checksum = 0
        for offset in range(0, 0x1FC, 4):
            checksum ^= struct.unpack_from("<I", view, offset)[0]
        if checksum == 0:
            return 1
        if checksum == 0xFFFFFFFF:
            return 0xFFFFFFFE
        return checksum

    def _put_cell(self, rel, data):
        cell_size = _align8(4 + len(data))
        if rel < 0x20 or rel + cell_size > self.hbin_size:
            raise ValueError("synthetic cell is outside its HBIN")
        for old_rel, old_size in self.cells:
            if rel < old_rel + old_size and old_rel < rel + cell_size:
                raise ValueError("synthetic cells overlap at 0x%x" % rel)
        self.cells.append((rel, cell_size))
        file_offset = HBIN_FILE_OFFSET + rel
        struct.pack_into("<i", self.buf, file_offset, -cell_size)
        self.buf[file_offset + 4:file_offset + 4 + len(data)] = data
        return rel

    def _alloc_cell(self, data):
        rel = self._put_cell(self.aux_cursor, data)
        cell_size = _align8(4 + len(data))
        self.aux_cursor += cell_size
        return rel

    def _assign_offsets(self, key):
        if key.rel is None:
            if key.offset is not None:
                key.rel = key.offset
            else:
                candidate = FIRST_KEY_SLOT_REL
                while any(
                    candidate < rel + size and rel < candidate + KEY_SLOT_SIZE
                    for rel, size in self.reserved
                ):
                    candidate += KEY_SLOT_SIZE
                key.rel = candidate
            self.reserved.append((key.rel, KEY_SLOT_SIZE))
        for child in key.children:
            self._assign_offsets(child)

    def _write_value(self, value):
        name_bytes = value.name.encode("windows-1252")
        record = bytearray(0x14)
        record[0:2] = b"vk"
        struct.pack_into("<H", record, 0x02, len(name_bytes))
        struct.pack_into("<I", record, 0x04, len(value.data))
        struct.pack_into("<I", record, 0x0C, value.data_type)
        if name_bytes:
            struct.pack_into("<H", record, 0x10, 1)  # ASCII name
        if len(value.data) <= 4:
            padded = value.data + bytes(4 - len(value.data))
            struct.pack_into("<I", record, 0x08,
                             struct.unpack("<I", padded[:4])[0])
        else:
            data_rel = self._alloc_cell(value.data)
            struct.pack_into("<I", record, 0x08, data_rel)
        data = bytes(record) + name_bytes
        if value.offset is not None:
            value.rel = self._put_cell(value.offset, data)
        else:
            value.rel = self._alloc_cell(data)
        return value.rel

    def _write_key(self, key, parent_rel):
        value_rels = [self._write_value(value) for value in key.values]
        values_list_rel = None
        if value_rels:
            values_list = b"".join(struct.pack("<I", rel) for rel in value_rels)
            values_list_rel = self._alloc_cell(values_list)

        for child in key.children:
            self._write_key(child, key.rel)

        subkey_list_rel = None
        if key.children:
            entries = b"".join(struct.pack("<I", child.rel)
                               for child in key.children)
            subkey_list = b"li" + struct.pack("<H", len(key.children)) + entries
            subkey_list_rel = self._alloc_cell(subkey_list)

        name_bytes = key.name.encode("windows-1252")
        record = bytearray(0x4C)
        record[0:2] = b"nk"
        flags = 0x0020  # ASCII name
        if parent_rel == 0xFFFFFFFF:
            flags |= 0x0004  # root
        struct.pack_into("<H", record, 0x02, flags)
        struct.pack_into("<Q", record, 0x04, key.timestamp)
        struct.pack_into("<I", record, 0x10, parent_rel)
        struct.pack_into("<I", record, 0x14, len(key.children))
        struct.pack_into("<I", record, 0x18, len(key.children))
        struct.pack_into("<I", record, 0x1C,
                         subkey_list_rel if subkey_list_rel is not None else 0xFFFFFFFF)
        struct.pack_into("<I", record, 0x20,
                         subkey_list_rel if subkey_list_rel is not None else 0xFFFFFFFF)
        struct.pack_into("<I", record, 0x24, len(key.values))
        struct.pack_into("<I", record, 0x28,
                         values_list_rel if values_list_rel is not None else 0xFFFFFFFF)
        struct.pack_into("<I", record, 0x2C, 0xFFFFFFFF)
        struct.pack_into("<I", record, 0x30, 0xFFFFFFFF)
        struct.pack_into("<H", record, 0x48, len(name_bytes))
        record[0x4C:0x4C + len(name_bytes)] = name_bytes
        self._put_cell(key.rel, bytes(record) + name_bytes)

    def build(self, root):
        root.offset = root.offset if root.offset is not None else ROOT_CELL_REL
        self._assign_offsets(root)
        self._write_key(root, 0xFFFFFFFF)
        struct.pack_into("<I", self.buf, 0x1FC, self._checksum())
        return bytes(self.buf)


def make_registry(root):
    data = SyntheticHive().build(root)
    return Registry.Registry(io.BytesIO(data)), data


def dword_value(name, number, offset=None):
    return ValueSpec(name, dword=number, offset=offset)

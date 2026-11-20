"""Synthetic PE32+ builder used to create deterministic test samples.

The builder emits real, parseable PE bytes with delay-import directories and
load-config guard tables. It never invokes the system loader and does not
depend on any external toolchain.
"""

from __future__ import annotations

import struct


IMAGE_BASE = 0x140000000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200


def align(value, boundary):
    if value % boundary:
        return value + boundary - (value % boundary)
    return value


class Buffer:
    """RVA-addressed byte buffer that records relocation entries."""

    def __init__(self):
        self._chunks = []
        self.relocations = []

    def tell(self):
        return sum(len(chunk) for chunk in self._chunks)

    def put(self, data):
        self._chunks.append(data)
        return self.tell() - len(data)

    def u16(self, value):
        return self.put(struct.pack("<H", value))

    def u32(self, value):
        return self.put(struct.pack("<I", value))

    def u64(self, value):
        return self.put(struct.pack("<Q", value))

    def cstr(self, text):
        return self.put(text.encode("ascii") + b"\x00")

    def reserve_u64(self, mark_relocation=False):
        offset = self.tell()
        self.u64(0)
        if mark_relocation:
            self.relocations.append(offset)
        return offset

    def bytes(self):
        return b"".join(self._chunks)


class SampleSpec:
    """Declarative description of one synthetic delay-loaded DLL."""

    def __init__(self, dll, symbols, bound=False):
        self.dll = dll
        self.symbols = symbols
        self.bound = bound


def _is_ordinal(symbol):
    return isinstance(symbol, int)


class Layout:
    def __init__(self, specs):
        self.specs = specs
        self.text_rva = 0x1000
        self.rdata_rva = 0x2000
        self.data_rva = 0x3000
        self.text_size = 0x200
        self.rdata_blocks = {}
        self.data_blocks = {}
        self.hint_names = {}
        self._plan_rdata()
        self._plan_data()

    def _plan_rdata(self):
        cursor = self.rdata_rva
        self.dll_names = {}
        self.hint_name_rvas = {}
        self.ints = {}
        self.iats = {}
        self.bound_iats = {}
        self.unload_iats = {}
        self.descriptors = {}
        for spec in self.specs:
            self.dll_names[spec.dll] = cursor
            cursor += len(spec.dll) + 1
        for spec in self.specs:
            hint_rvas = []
            for symbol in spec.symbols:
                if _is_ordinal(symbol):
                    hint_rvas.append(None)
                    continue
                hint_rvas.append(cursor)
                blob = struct.pack("<H", 0) + symbol.encode("ascii") + b"\x00"
                self.hint_names[cursor] = blob
                cursor += len(blob)
            self.hint_name_rvas[spec.dll] = hint_rvas
        thunk = 8
        for spec in self.specs:
            count = len(spec.symbols)
            self.ints[spec.dll] = cursor
            cursor += (count + 1) * thunk
            self.iats[spec.dll] = cursor
            cursor += (count + 1) * thunk
            if spec.bound:
                self.bound_iats[spec.dll] = cursor
                cursor += (count + 1) * thunk
            self.unload_iats[spec.dll] = cursor
            cursor += (count + 1) * thunk
        descriptor_rva = cursor
        for spec in self.specs:
            self.descriptors[spec.dll] = descriptor_rva
            descriptor_rva += 32
        self.directory_end_rva = descriptor_rva + 32
        cursor = self.directory_end_rva
        self.rdata_size = align(cursor - self.rdata_rva, SECTION_ALIGNMENT)

    def _plan_data(self):
        cursor = self.data_rva
        self._load_config_rva = cursor
        cursor += 0x140
        self.phmod_slots = {}
        for spec in self.specs:
            self.phmod_slots[spec.dll] = cursor
            cursor += 8
        self.guard_check_slot = cursor
        cursor += 8
        self.guard_dispatch_slot = cursor
        cursor += 8
        self.guard_iat_table = cursor
        all_iat = []
        for spec in self.specs:
            base = self.iats[spec.dll]
            for index in range(len(spec.symbols)):
                all_iat.append(base + index * 8)
        self.guard_iat_entries = all_iat
        cursor += (len(all_iat) + 1) * 8
        self.data_size = align(cursor - self.data_rva, SECTION_ALIGNMENT)

    @property
    def delay_directory_rva(self):
        first = next(iter(self.descriptors.values()))
        return first
    @property
    def load_config_rva(self):
        return self._load_config_rva


ORDINAL_FLAG_64 = 0x8000000000000000


def _assemble_rdata(layout):
    buffer = Buffer()
    base = layout.rdata_rva
    def pad_to(rva):
        target = rva - base
        current = buffer.tell()
        if target > current:
            buffer.put(b"\x00" * (target - current))
    for spec in layout.specs:
        pad_to(layout.dll_names[spec.dll])
        buffer.cstr(spec.dll)
    for spec in layout.specs:
        for rva, blob in layout.hint_names.items():
            if rva in layout.hint_name_rvas[spec.dll]:
                pad_to(rva)
                buffer.put(blob)
    thunk = 8
    for spec in layout.specs:
        pad_to(layout.ints[spec.dll])
        for index, symbol in enumerate(spec.symbols):
            if _is_ordinal(symbol):
                buffer.u64(ORDINAL_FLAG_64 | symbol)
            else:
                buffer.u64(layout.hint_name_rvas[spec.dll][index])
        buffer.u64(0)
        pad_to(layout.iats[spec.dll])
        for index, symbol in enumerate(spec.symbols):
            if _is_ordinal(symbol):
                buffer.u64(ORDINAL_FLAG_64 | symbol)
            elif spec.bound:
                buffer.u64(IMAGE_BASE + 0x70000 + index * 0x100)
            else:
                buffer.u64(layout.hint_name_rvas[spec.dll][index])
        buffer.u64(0)
        if spec.bound:
            pad_to(layout.bound_iats[spec.dll])
            for index, symbol in enumerate(spec.symbols):
                if _is_ordinal(symbol):
                    buffer.u64(ORDINAL_FLAG_64 | symbol)
                else:
                    buffer.u64(IMAGE_BASE + 0x70000 + index * 0x100)
            buffer.u64(0)
        pad_to(layout.unload_iats[spec.dll])
        for index, symbol in enumerate(spec.symbols):
            if _is_ordinal(symbol):
                buffer.u64(ORDINAL_FLAG_64 | symbol)
            else:
                buffer.u64(layout.hint_name_rvas[spec.dll][index])
        buffer.u64(0)
    for spec in layout.specs:
        pad_to(layout.descriptors[spec.dll])
        desc = layout.descriptors[spec.dll]
        buffer.u32(0)
        buffer.u32(layout.dll_names[spec.dll])
        buffer.u32(layout.phmod_slots[spec.dll])
        buffer.u32(layout.iats[spec.dll])
        buffer.u32(layout.ints[spec.dll])
        buffer.u32(layout.bound_iats.get(spec.dll, 0))
        buffer.u32(layout.unload_iats[spec.dll])
        buffer.u32(0x12345678 if spec.bound else 0)
    pad_to(layout.directory_end_rva)
    for _ in range(8):
        buffer.u32(0)
    padding = align(buffer.tell(), SECTION_ALIGNMENT) - buffer.tell()
    buffer.put(b"\x00" * padding)
    return buffer.bytes()



def _assemble_data(layout):
    buffer = Buffer()
    base = layout.data_rva
    def pad_to(rva):
        target = rva - base
        current = buffer.tell()
        if target > current:
            buffer.put(b"\x00" * (target - current))
    pad_to(layout.load_config_rva)
    config_blob = _load_config_bytes(layout)
    buffer.put(config_blob)
    for spec in layout.specs:
        pad_to(layout.phmod_slots[spec.dll])
        buffer.reserve_u64(mark_relocation=True)
    pad_to(layout.guard_check_slot)
    buffer.reserve_u64(mark_relocation=True)
    pad_to(layout.guard_dispatch_slot)
    buffer.reserve_u64(mark_relocation=True)
    pad_to(layout.guard_iat_table)
    for entry in layout.guard_iat_entries:
        buffer.u64(entry)
    buffer.u64(0)
    padding = align(buffer.tell(), SECTION_ALIGNMENT) - buffer.tell()
    buffer.put(b"\x00" * padding)
    return buffer.bytes(), buffer.relocations
    blob = b"".join(parts)
def _load_config_bytes(layout):
    """Pack IMAGE_LOAD_CONFIG_DIRECTORY64 using documented field offsets."""
    blob = bytearray(0x140)
    struct.pack_into("<I", blob, 0x00, 0x140)
    struct.pack_into("<Q", blob, 0x70, layout.guard_check_slot)
    struct.pack_into("<Q", blob, 0x78, layout.guard_dispatch_slot)
    struct.pack_into("<Q", blob, 0x80, layout.guard_iat_table)
    struct.pack_into("<Q", blob, 0x88, len(layout.guard_iat_entries))
    struct.pack_into("<I", blob, 0x90, 0x10500)
    struct.pack_into("<Q", blob, 0xA0, layout.guard_iat_table)
    struct.pack_into("<Q", blob, 0xA8, len(layout.guard_iat_entries))
    return bytes(blob)






def _dos_header():
    header = bytearray(0x80)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    return bytes(header)


def _section_header(name, virtual_size, virtual_address, raw_size, raw_pointer, characteristics):
    name_bytes = name.encode("ascii")[:8].ljust(8, b"\x00")
    return (
        name_bytes
        + struct.pack("<I", virtual_size)
        + struct.pack("<I", virtual_address)
        + struct.pack("<I", raw_size)
        + struct.pack("<I", raw_pointer)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<H", 0)
        + struct.pack("<H", 0)
        + struct.pack("<I", characteristics)
    )


def _relocation_bytes(rvas):
    blocks = []
    pages = {}
    for rva in rvas:
        pages.setdefault(rva & ~0xFFF, []).append(rva & 0xFFF)
    for page in sorted(pages):
        entries = sorted(pages[page])
        size = 8 + 2 * (len(entries) + 1)
        header = struct.pack("<II", page, size)
        body = b"".join(struct.pack("<H", 0xA000 | offset) for offset in entries)
        body += struct.pack("<H", 0)
        blocks.append(header + body)
    return b"".join(blocks)


def _file_header(number_sections):
    return struct.pack(
        "<HHIIIHH",
        0x8664,
        number_sections,
        0,
        0,
        0,
        0xF0,
        0x0022,
    )

def _data_directories(layout, reloc_rva, reloc_size):
    entries = [(0, 0)] * 16
    entries[10] = (layout.load_config_rva, 0x140)
    entries[13] = (layout.delay_directory_rva,
                   layout.directory_end_rva - layout.delay_directory_rva)
    entries[5] = (reloc_rva, reloc_size)
    return b"".join(struct.pack("<II", rva, size) for rva, size in entries)




def _optional_header(layout, size_of_image, size_of_headers, directories):
    header = bytearray(0x70)
    struct.pack_into("<HBB", header, 0x00, 0x20B, 14, 0)
    struct.pack_into("<I", header, 0x04, layout.text_size)
    struct.pack_into("<I", header, 0x08, layout.rdata_size)
    struct.pack_into("<I", header, 0x0C, layout.data_size)
    struct.pack_into("<I", header, 0x10, 0)
    struct.pack_into("<I", header, 0x14, layout.text_rva)
    struct.pack_into("<Q", header, 0x18, IMAGE_BASE)
    struct.pack_into("<I", header, 0x20, SECTION_ALIGNMENT)
    struct.pack_into("<I", header, 0x24, FILE_ALIGNMENT)
    struct.pack_into("<HH", header, 0x28, 6, 0)
    struct.pack_into("<HH", header, 0x2C, 0, 0)
    struct.pack_into("<HH", header, 0x30, 6, 0)
    struct.pack_into("<I", header, 0x34, 0)
    struct.pack_into("<I", header, 0x38, size_of_image)
    struct.pack_into("<I", header, 0x3C, size_of_headers)
    struct.pack_into("<I", header, 0x40, 0)
    struct.pack_into("<HH", header, 0x44, 3, 0x8160)
    struct.pack_into("<Q", header, 0x48, 0x100000)
    struct.pack_into("<Q", header, 0x50, 0x1000)
    struct.pack_into("<Q", header, 0x58, 0x100000)
    struct.pack_into("<Q", header, 0x60, 0x1000)
    struct.pack_into("<I", header, 0x68, 0)
    struct.pack_into("<I", header, 0x6C, 16)
    return bytes(header) + directories





def build_sample(specs):
    layout = Layout(specs)
    text = b"\xC3" * layout.text_size
    rdata = _assemble_rdata(layout)
    data, data_relocations = _assemble_data(layout)
    reloc_section_rva = 0x4000
    reloc_rvas = [layout.data_rva + offset for offset in data_relocations]
    reloc_blob = _relocation_bytes(reloc_rvas)
    headers_size = 0x400
    text_raw = align(len(text), FILE_ALIGNMENT)
    rdata_raw = align(len(rdata), FILE_ALIGNMENT)
    data_raw = align(len(data), FILE_ALIGNMENT)
    reloc_raw = align(len(reloc_blob), FILE_ALIGNMENT)
    size_of_image = 0x5000
    directories = _data_directories(layout, reloc_section_rva, len(reloc_blob))
    optional = _optional_header(layout, size_of_image, headers_size, directories)
    header_blob = _dos_header() + b"PE\x00\x00" + _file_header(4) + optional
    section_headers = b"".join((
        _section_header(".text", layout.text_size, layout.text_rva, text_raw, headers_size, 0x60000020),
        _section_header(".rdata", layout.rdata_size, layout.rdata_rva, rdata_raw, headers_size + text_raw, 0x40000040),
        _section_header(".data", layout.data_size, layout.data_rva, data_raw, headers_size + text_raw + rdata_raw, 0xC0000040),
        _section_header(".reloc", len(reloc_blob), reloc_section_rva, reloc_raw, headers_size + text_raw + rdata_raw + data_raw, 0x42000040),
    ))
    head = header_blob + section_headers
    head = head.ljust(headers_size, b"\x00")
    image = head
    image += text.ljust(text_raw, b"\x00")
    image += rdata.ljust(rdata_raw, b"\x00")
    image += data.ljust(data_raw, b"\x00")
    image += reloc_blob.ljust(reloc_raw, b"\x00")
    return image, layout

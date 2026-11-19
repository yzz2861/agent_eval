"""Hand-crafted, sub-64KB PE images for loading-strategy view tests.

Everything is assembled with struct from raw bytes: no binary is executed and
no operating-system loader is invoked. The images intentionally exercise:

* one RVA backed by several sections (overlapping sections),
* a file truncated inside a declared raw range,
* a legal shared section and a BSS zero-fill tail,
* an alignment value outside the documented PE/COFF rules.
"""

import struct

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
SIZE_OF_HEADERS = 0x200

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_SHARED = 0x10000000


def _section_header(name, virtual_size, virtual_address, size_of_raw_data,
                    pointer_to_raw_data, characteristics):
    name_bytes = name.encode("ascii")[:8].ljust(8, b"\x00")
    return struct.pack(
        "<8sIIIIIIHHI",
        name_bytes,
        virtual_size,
        virtual_address,
        size_of_raw_data,
        pointer_to_raw_data,
        0,
        0,
        0,
        0,
        characteristics,
    )


def _optional_header_pe32(entry_rva, size_of_image, file_alignment,
                          section_alignment, size_of_headers, image_base,
                          export_rva, export_size):
    # 96-byte PE32 optional header, then 16 data directories (128 bytes).
    header = bytearray(96)
    struct.pack_into("<H", header, 0, 0x10B)      # Magic
    header[2] = 14                                  # MajorLinkerVersion
    struct.pack_into("<I", header, 16, entry_rva)  # AddressOfEntryPoint
    # Windows-specific fields begin at offset 28.
    struct.pack_into("<I", header, 28, image_base)          # ImageBase
    struct.pack_into("<I", header, 32, section_alignment)   # SectionAlignment
    struct.pack_into("<I", header, 36, file_alignment)      # FileAlignment
    struct.pack_into("<I", header, 56, size_of_image)       # SizeOfImage
    struct.pack_into("<I", header, 60, size_of_headers)     # SizeOfHeaders
    struct.pack_into("<H", header, 68, 3)   # MajorOperatingSystemVersion
    struct.pack_into("<H", header, 70, 0)   # MinorOperatingSystemVersion
    struct.pack_into("<I", header, 76, 0x100000)  # SizeOfStackReserve
    struct.pack_into("<I", header, 80, 0x1000)    # SizeOfStackCommit
    struct.pack_into("<I", header, 84, 0x100000)  # SizeOfHeapReserve
    struct.pack_into("<I", header, 88, 0x1000)    # SizeOfHeapCommit
    struct.pack_into("<I", header, 92, 16)        # NumberOfRvaAndSizes

    directories = bytearray(128)
    struct.pack_into("<II", directories, 0, export_rva, export_size)
    return bytes(header) + bytes(directories)


def assemble_pe(sections, entry_rva, file_alignment=FILE_ALIGNMENT,
                section_alignment=SECTION_ALIGNMENT, size_of_headers=SIZE_OF_HEADERS,
                image_base=0x400000, export_rva=0, export_size=0,
                truncate_to=None):
    """Assemble a PE32 image.

    sections is a list of dicts with keys: name, virtual_address,
    virtual_size, pointer_to_raw_data, raw (bytes), characteristics.
    Raw data blocks are placed verbatim at pointer_to_raw_data; the caller
    controls padding and can therefore create overlaps and truncation.
    """

    number_of_sections = len(sections)
    highest_end = max(
        (section["virtual_address"] + section["virtual_size"]
         for section in sections),
        default=size_of_headers,
    )
    computed_size_of_image = (
        (highest_end + section_alignment - 1) // section_alignment
    ) * section_alignment
    optional = _optional_header_pe32(
        entry_rva,
        computed_size_of_image,
        file_alignment,
        section_alignment,
        size_of_headers,
        image_base,
        export_rva,
        export_size,
    )

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    e_lfanew = 0x40
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    coff = struct.pack(
        "<HHIIIHH",
        0x14C,
        number_of_sections,
        0,
        0,
        0,
        len(optional),
        0x0102,
    )
    pe_sig = b"PE\x00\x00"
    section_table = b"".join(
        _section_header(
            section["name"],
            section["virtual_size"],
            section["virtual_address"],
            len(section["raw"]),
            section["pointer_to_raw_data"],
            section["characteristics"],
        )
        for section in sections
    )
    nt = pe_sig + coff + optional + section_table
    if e_lfanew + len(nt) > size_of_headers:
        raise ValueError("headers overflow SizeOfHeaders")

    highest_raw = max(
        (section["pointer_to_raw_data"] + len(section["raw"])
         for section in sections),
        default=size_of_headers,
    )
    image = bytearray(max(size_of_headers, highest_raw))
    image[0 : len(dos)] = dos
    image[e_lfanew : e_lfanew + len(nt)] = nt

    for section in sections:
        start = section["pointer_to_raw_data"]
        end = start + len(section["raw"])
        image[start:end] = section["raw"]

    if truncate_to is not None:
        image = image[:truncate_to]
    return bytes(image)


CODE_EXEC = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
DATA_RW = (
    IMAGE_SCN_CNT_INITIALIZED_DATA
    | IMAGE_SCN_MEM_READ
    | IMAGE_SCN_MEM_WRITE
)
SHARED_R = (
    IMAGE_SCN_CNT_INITIALIZED_DATA
    | IMAGE_SCN_MEM_READ
    | IMAGE_SCN_MEM_SHARED
)


def build_overlapping_sections():
    """Two sections claim the same RVA but hold different file bytes.

    Section A (.text) maps RVA 0x1000..0x1100 to raw 0x200..0x300 and fills
    it with 0xAA. Section B (.ovl) maps the same RVA range to raw
    0x400..0x500 and fills it with 0xBB. The entry point lives at RVA 0x1000,
    so its byte is ambiguous under the file-backed strategy.
    """

    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": 0x100,
            "pointer_to_raw_data": 0x200,
            "raw": b"\xaa" * 0x100,
            "characteristics": CODE_EXEC,
        },
        {
            "name": ".ovl",
            "virtual_address": 0x1000,
            "virtual_size": 0x100,
            "pointer_to_raw_data": 0x400,
            "raw": b"\xbb" * 0x100,
            "characteristics": DATA_RW,
        },
    ]
    return assemble_pe(sections, entry_rva=0x1000)


def build_truncated_section():
    """A section declares 0x200 raw bytes but the file ends after 0x80.

    RVA 0x1000..0x107f is still on disk; RVA 0x1080..0x11ff points past EOF
    and must be reported as truncated rather than silently zero filled by the
    file-backed view.
    """

    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": 0x200,
            "pointer_to_raw_data": 0x200,
            "raw": b"\xcc" * 0x80,
            "characteristics": CODE_EXEC,
        }
    ]
    full = assemble_pe(sections, entry_rva=0x1000)
    return full[: 0x280]


def build_shared_and_bss():
    """A legal shared section plus a BSS tail and a normal code section.

    .shared (RVA 0x2000..0x2080) is marked IMAGE_SCN_MEM_SHARED. .bss
    (RVA 0x3000..0x3100) has no raw data and is pure zero fill. The entry
    point is in .text at RVA 0x1000.
    """

    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": 0x100,
            "pointer_to_raw_data": 0x200,
            "raw": b"\x90" * 0x100,
            "characteristics": CODE_EXEC,
        },
        {
            "name": ".shared",
            "virtual_address": 0x2000,
            "virtual_size": 0x80,
            "pointer_to_raw_data": 0x400,
            "raw": b"\x42" * 0x80,
            "characteristics": SHARED_R,
        },
        {
            "name": ".bss",
            "virtual_address": 0x3000,
            "virtual_size": 0x100,
            "pointer_to_raw_data": 0,
            "raw": b"",
            "characteristics": DATA_RW,
        },
    ]
    return assemble_pe(sections, entry_rva=0x1000)


def build_illegal_alignment():
    """FileAlignment 0x100 is below the documented minimum of 0x200."""

    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": 0x100,
            "pointer_to_raw_data": 0x200,
            "raw": b"\xdd" * 0x100,
            "characteristics": CODE_EXEC,
        }
    ]
    return assemble_pe(
        sections,
        entry_rva=0x1000,
        file_alignment=0x100,
        section_alignment=0x1000,
        size_of_headers=0x200,
    )


def build_export_overlap():
    """An export target RVA sits inside the overlapping-section range.

    The export directory and AddressOfFunctions table live in .rdata; the
    single exported function points at RVA 0x1000, which is also claimed by
    both .text and .ovl, so its target byte is strategy dependent.
    """

    export_rva = 0x4000
    func_table_rva = 0x4028
    target_rva = 0x1000

    export_directory = bytearray(40)
    struct.pack_into("<I", export_directory, 0, 0)
    struct.pack_into("<I", export_directory, 12, 0)
    struct.pack_into("<I", export_directory, 16, 1)
    struct.pack_into("<I", export_directory, 20, 1)
    struct.pack_into("<I", export_directory, 24, 0)
    struct.pack_into("<I", export_directory, 28, func_table_rva)
    struct.pack_into("<I", export_directory, 32, 0)
    struct.pack_into("<I", export_directory, 36, 0)
    func_table = struct.pack("<I", target_rva)
    rdata_raw = (bytes(export_directory) + func_table).ljust(0x100, b"\x00")

    sections = [
        {
            "name": ".text",
            "virtual_address": 0x1000,
            "virtual_size": 0x100,
            "pointer_to_raw_data": 0x200,
            "raw": b"\xaa" * 0x100,
            "characteristics": CODE_EXEC,
        },
        {
            "name": ".ovl",
            "virtual_address": 0x1000,
            "virtual_size": 0x100,
            "pointer_to_raw_data": 0x400,
            "raw": b"\xbb" * 0x100,
            "characteristics": DATA_RW,
        },
        {
            "name": ".rdata",
            "virtual_address": 0x4000,
            "virtual_size": 0x100,
            "pointer_to_raw_data": 0x600,
            "raw": rdata_raw,
            "characteristics": DATA_RW,
        },
    ]
    return assemble_pe(
        sections,
        entry_rva=0x1000,
        export_rva=export_rva,
        export_size=40,
    )


def build_pe32_plus():
    """A minimal PE32+ image exercising the 8-byte ImageBase header layout."""

    optional = bytearray(112)
    struct.pack_into("<H", optional, 0, 0x20B)
    optional[2] = 14
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<Q", optional, 24, 0x140000000)
    struct.pack_into("<I", optional, 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", optional, 36, FILE_ALIGNMENT)
    struct.pack_into("<I", optional, 56, 0x2000)
    struct.pack_into("<I", optional, 60, SIZE_OF_HEADERS)
    struct.pack_into("<I", optional, 108, 16)
    optional += b"\x00" * 128

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x100,
        0x1000,
        0x100,
        0x200,
        0,
        0,
        0,
        0,
        CODE_EXEC,
    )

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack(
        "<HHIIIHH", 0x8664, 1, 0, 0, 0, len(optional), 0x0022
    )
    nt = b"PE\x00\x00" + coff + bytes(optional) + section_header
    image = bytearray(0x400)
    image[0:0x40] = dos
    image[0x40 : 0x40 + len(nt)] = nt
    image[0x200:0x300] = b"\xf4" * 0x100
    return bytes(image)

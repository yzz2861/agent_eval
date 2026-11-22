"""Synthetic PE fixtures for load-config guard declaration verification."""

import struct

import pefile


IMAGE_BASE = 0x400000
SECTION_RVA = 0x1000
SECTION_RAW = 0x400
LOAD_CONFIG_RVA = SECTION_RVA
LOAD_CONFIG_SIZE = 0xC0


def _build_guard_pe(table_rva, virtual_size=0x2000, declared_size=LOAD_CONFIG_SIZE):
    """Build a very small PE32 with a readable load configuration.

    ``table_rva`` is where the GuardCFFunctionTable is declared.  The file
    always ends at the end of the section's raw data, so callers can make the
    table partially readable or entirely virtual-only without changing any of
    the surface flags.
    """

    file_size = SECTION_RAW * 2
    size_of_image = SECTION_RVA + virtual_size
    size_of_image = (size_of_image + 0xFFF) & ~0xFFF

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine = I386
        1,  # NumberOfSections
        0,
        0,
        0,
        0xE0,  # SizeOfOptionalHeader
        0x2102,  # IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
    )

    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,  # PE32
        14,
        0,
        SECTION_RAW,
        SECTION_RAW,
        0,
        SECTION_RVA + 0x10,  # AddressOfEntryPoint
        SECTION_RVA,
        SECTION_RVA,
        IMAGE_BASE,
        0x1000,  # SectionAlignment
        0x200,  # FileAlignment
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        size_of_image,
        0x400,  # SizeOfHeaders
        0,
        3,  # Console
        pefile.IMAGE_DLLCHARACTERISTICS_GUARD_CF,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    assert len(optional) == 0x60

    directories = [(0, 0)] * 16
    directories[10] = (LOAD_CONFIG_RVA, declared_size)
    optional += b"".join(struct.pack("<II", rva, size) for rva, size in directories)

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        virtual_size,
        SECTION_RVA,
        SECTION_RAW,
        SECTION_RAW,
        0,
        0,
        0,
        0,
        0x60000020,  # code | execute | read
    )

    data = bytearray(file_size)
    data[0:0x40] = dos
    data[0x40:0x44] = b"PE\x00\x00"
    data[0x44 : 0x44 + len(coff)] = coff
    offset = 0x44 + len(coff)
    data[offset : offset + len(optional)] = optional
    offset += len(optional)
    data[offset : offset + len(section)] = section
    data[SECTION_RAW:file_size] = b"\xCC" * SECTION_RAW

    load_config = bytearray(LOAD_CONFIG_SIZE)
    struct.pack_into("<I", load_config, 0x00, declared_size)
    struct.pack_into("<I", load_config, 0x48, IMAGE_BASE + SECTION_RVA + 0x10)
    struct.pack_into("<I", load_config, 0x50, IMAGE_BASE + table_rva)
    struct.pack_into("<I", load_config, 0x54, 2)  # GuardCFFunctionCount
    struct.pack_into(
        "<I",
        load_config,
        0x58,
        pefile.IMAGE_GUARD_CF_INSTRUMENTED
        | pefile.IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,
    )
    data[SECTION_RAW : SECTION_RAW + LOAD_CONFIG_SIZE] = load_config

    # First table entry is a valid RVA into .text.  A second entry would start
    # exactly at EOF for the partial fixture.
    if table_rva < SECTION_RVA + virtual_size:
        table_offset = table_rva - SECTION_RVA + SECTION_RAW
        if table_offset < file_size:
            struct.pack_into("<I", data, table_offset, SECTION_RVA + 0x10)

    return bytes(data)


def test_partial_guard_table_evidence():
    """One readable table entry is enough for a partial conclusion."""

    data = _build_guard_pe(table_rva=SECTION_RVA + SECTION_RAW - 4)
    pe = pefile.PE(data=data)
    report = pe.verify_guard_declarations()

    assert pe.DIRECTORY_ENTRY_LOAD_CONFIG.guard_declarations.status == "partial"
    assert pe.guard_declarations.status == report.status
    assert report["status"] == "partial"
    assert report.guard_flags == (
        pefile.IMAGE_GUARD_CF_INSTRUMENTED
        | pefile.IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
    )
    assert report.fields["GuardFlags"].witness == "present"
    assert report.fields["GuardFlags"].coverage == "readable"

    table = report.declarations["cfg_function_table"].tables[0]
    assert table.coverage == "partial"
    assert table.readable_length == 4
    assert table.readable_entry_count == 1
    assert table.valid_entry_count == 1
    assert table.table_file_offset == SECTION_RAW * 2 - 4
    assert table.table_rva == SECTION_RVA + SECTION_RAW - 4

    assert report.declarations["cfg_function_table"].conclusion == "partial"
    assert report.status == "partial"


def test_pending_guard_table_has_same_surface_flag():
    """The same flags with a virtual-only table stay pending, never zero."""

    partial = _build_guard_pe(table_rva=SECTION_RVA + SECTION_RAW - 4)
    pending = _build_guard_pe(table_rva=SECTION_RVA + 0x800)

    partial_report = pefile.PE(data=partial).verify_guard_declarations()
    pending_report = pefile.PE(data=pending).verify_guard_declarations()

    assert partial_report.guard_flags == pending_report.guard_flags
    assert (
        partial_report.fields["GuardFlags"].raw_value
        == pending_report.fields["GuardFlags"].raw_value
    )

    table = pending_report.declarations["cfg_function_table"].tables[0]
    assert table.coverage == "unreadable"
    assert table.readable_length == 0
    assert table.readable_entry_count == 0
    assert table.valid_entry_count == 0
    assert table.table_file_offset == SECTION_RAW + 0x800
    assert table.table_rva == SECTION_RVA + 0x800

    assert pending_report.declarations["cfg_function_table"].conclusion == "pending"
    assert pending_report.status == "pending"


def test_absent_guard_flags_is_not_zero():
    """An older, shorter load config has no GuardFlags witness."""

    data = _build_guard_pe(
        table_rva=SECTION_RVA + 0x800,
        virtual_size=0x2000,
        declared_size=0x50,
    )
    report = pefile.PE(data=data).verify_guard_declarations()

    guard_flags = report.fields["GuardFlags"]
    assert guard_flags.witness == "absent"
    assert guard_flags.value is None
    assert guard_flags.raw_value is not None
    assert report.guard_flags is None
    assert report.status == "absent"
    assert report.declarations["cfg_instrumented"].conclusion == "absent"


def test_declared_off_is_distinct_from_absent():
    """A readable zero GuardFlags is an explicit off declaration."""

    data = bytearray(_build_guard_pe(table_rva=SECTION_RVA + 0x800))
    struct.pack_into("<I", data, SECTION_RAW + 0x58, 0)
    report = pefile.PE(data=bytes(data)).verify_guard_declarations()

    assert report.fields["GuardFlags"].witness == "present"
    assert report.fields["GuardFlags"].coverage == "readable"
    assert report.fields["GuardFlags"].value == 0
    assert report.guard_flags == 0
    assert report.status == "off"
    assert report.declarations["cfg_instrumented"].conclusion == "off"


def test_declared_but_unreadable_guard_flags_is_pending():
    """A declared field outside the readable raw range is not zero."""

    data = _build_guard_pe(table_rva=SECTION_RVA + 0x800)
    report = pefile.PE(data=data[:0x404]).verify_guard_declarations()

    guard_flags = report.fields["GuardFlags"]
    assert guard_flags.witness == "present"
    assert guard_flags.coverage == "unreadable"
    assert guard_flags.value is None
    assert report.guard_flags is None
    assert report.status == "pending"
    assert report.declarations["cfg_instrumented"].conclusion == "pending"

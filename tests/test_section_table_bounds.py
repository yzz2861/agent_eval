import struct

import pefile


SECTION_HEADER_SIZE = 40
SECTION_TABLE_OFFSET = 0x178
RAW_DATA_OFFSET = 0x400


def make_section(
    name=b".text",
    virtual_size=0x200,
    virtual_address=0x1000,
    size_of_raw_data=0x200,
    pointer_to_raw_data=RAW_DATA_OFFSET,
    characteristics=0x60000020,
):
    return struct.pack(
        "<8sIIIIIIHHI",
        name.ljust(8, b"\0")[:8],
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


def make_pe(
    section_headers,
    raw_data=b"",
    number_of_sections=None,
    section_alignment=0x1000,
    file_alignment=0x200,
):
    if number_of_sections is None:
        number_of_sections = len(section_headers)

    data = bytearray(SECTION_TABLE_OFFSET + len(section_headers) * SECTION_HEADER_SIZE)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"

    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        0x14C,
        number_of_sections,
        0,
        0,
        0,
        0xE0,
        0x102,
    )

    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 4, len(raw_data))
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<I", data, optional + 32, section_alignment)
    struct.pack_into("<I", data, optional + 36, file_alignment)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<H", data, optional + 68, 2)
    struct.pack_into("<I", data, optional + 92, 16)

    for index, header in enumerate(section_headers):
        start = SECTION_TABLE_OFFSET + index * SECTION_HEADER_SIZE
        data[start : start + SECTION_HEADER_SIZE] = header

    if raw_data:
        data.extend(b"\0" * (RAW_DATA_OFFSET - len(data)))
        data.extend(raw_data)
    return bytes(data)


def warnings_for_section(pe, index):
    return [
        warning
        for warning in pe.get_warnings()
        if f"section {index}" in warning.lower()
    ]


def test_truncated_section_table_stops_before_partial_header():
    data = make_pe(
        [make_section()],
        number_of_sections=2,
    )

    with pefile.PE(data=data) as pe:
        assert len(pe.sections) == 1
        warnings = warnings_for_section(pe, 1)
        assert any("truncated" in warning.lower() for warning in warnings)
        assert all("\xcc" not in warning for warning in warnings)


def test_truncated_section_data_is_clamped_to_file():
    payload = b"\xcc" * 0x100
    data = make_pe(
        [
            make_section(
                virtual_size=0x200,
                size_of_raw_data=0x200,
                pointer_to_raw_data=RAW_DATA_OFFSET,
            )
        ],
        raw_data=payload,
    )

    with pefile.PE(data=data) as pe:
        section = pe.sections[0]
        assert section.get_data() == payload
        assert len(section.get_data()) <= len(pe.__data__) - RAW_DATA_OFFSET
        assert any(
            "SizeOfRawData is larger than file" in warning
            for warning in warnings_for_section(pe, 0)
        )


def test_huge_declaration_is_not_used_as_read_length():
    payload = b"\xcc" * 0x80
    data = make_pe(
        [
            make_section(
                virtual_size=0xFFFFFFFF,
                size_of_raw_data=0xFFFFFFFF,
                pointer_to_raw_data=RAW_DATA_OFFSET,
            )
        ],
        raw_data=payload,
    )

    with pefile.PE(data=data) as pe:
        section = pe.sections[0]
        assert section.get_data() == payload
        assert len(section.get_data()) <= len(pe.__data__) - RAW_DATA_OFFSET
        assert any(
            "SizeOfRawData is" in warning
            for warning in warnings_for_section(pe, 0)
        )

        image = pe.get_memory_mapped_image(max_virtual_address=0x2000)
        assert len(image) <= 0x2000


def test_overlapping_sections_are_preserved_and_reported():
    payload = bytes(range(0x100)) * 3
    data = make_pe(
        [
            make_section(
                name=b".one",
                virtual_size=0x200,
                virtual_address=0x1000,
                size_of_raw_data=0x200,
                pointer_to_raw_data=RAW_DATA_OFFSET,
            ),
            make_section(
                name=b".two",
                virtual_size=0x200,
                virtual_address=0x1100,
                size_of_raw_data=0x200,
                pointer_to_raw_data=RAW_DATA_OFFSET + 0x100,
            ),
        ],
        raw_data=payload,
    )

    with pefile.PE(data=data) as pe:
        assert len(pe.sections) == 2
        assert [section.Name for section in pe.sections] == [
            b".one\0\0\0\0",
            b".two\0\0\0\0",
        ]
        assert pe.sections[0].get_data() == payload[:0x200]
        assert pe.sections[1].get_data() == payload[0x100:0x300]

        overlap_warnings = [
            warning
            for warning in pe.get_warnings()
            if "overlapping" in warning.lower()
        ]
        assert overlap_warnings
        assert all("section" in warning.lower() for warning in overlap_warnings)
        assert any(
            "sections 0 and 1" in warning.lower()
            for warning in overlap_warnings
        )


def test_zero_length_section_has_no_raw_data():
    payload = b"\xcc" * 0x200
    data = make_pe(
        [
            make_section(
                name=b".bss",
                virtual_size=0,
                virtual_address=0x1000,
                size_of_raw_data=0,
                pointer_to_raw_data=0,
            ),
            make_section(
                name=b".text",
                virtual_size=0x200,
                virtual_address=0x2000,
                size_of_raw_data=0x200,
                pointer_to_raw_data=RAW_DATA_OFFSET,
            ),
        ],
        raw_data=payload,
    )

    with pefile.PE(data=data) as pe:
        assert len(pe.sections) == 2
        by_name = {section.Name.rstrip(b"\0"): section for section in pe.sections}
        assert by_name[b".bss"].get_data() == b""
        assert not by_name[b".bss"].contains_offset(0)
        assert by_name[b".text"].get_data() == payload
        assert not any(
            "SizeOfRawData is larger than file" in warning
            for warning in warnings_for_section(pe, 0)
        )


def test_alignment_anomalies_include_section_index():
    data = make_pe(
        [
            make_section(
                virtual_size=0x123,
                virtual_address=0x1001,
                size_of_raw_data=0x123,
                pointer_to_raw_data=RAW_DATA_OFFSET + 1,
            )
        ],
        raw_data=b"\xcc" * 0x200,
    )

    with pefile.PE(data=data) as pe:
        warnings = warnings_for_section(pe, 0)
        assert any("PointerToRawData" in warning for warning in warnings)
        assert any("SizeOfRawData" in warning for warning in warnings)
        assert any("VirtualAddress" in warning for warning in warnings)


def test_get_data_rejects_rva_before_section():
    payload = b"\xcc" * 0x100
    data = make_pe(
        [
            make_section(
                virtual_size=0x100,
                virtual_address=0x1000,
                size_of_raw_data=0x100,
                pointer_to_raw_data=RAW_DATA_OFFSET,
            )
        ],
        raw_data=payload,
    )

    with pefile.PE(data=data) as pe:
        section = pe.sections[0]
        assert section.get_data(start=0x800, length=16) == b""

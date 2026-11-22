import struct

from dnfile import base, stream


SHARED = b"SharedAssembly"
DUPLICATE = b"SharedAssembly"
SUFFIX = b"Assembly"


def _stream_struct(name, size):
    stream_struct = base.StreamStruct(
        ("IMAGE_CLR_STREAM", ["I,Offset", "I,Size", "16s,Name"])
    )
    stream_struct.__unpack__(struct.pack("<II16s", 0, size, name))
    stream_struct.Name = name
    return stream_struct


def _assembly_ref_row(name_index, culture_index=0):
    return struct.pack(
        "<HHHHIHHHH",
        4,
        0,
        0,
        0,
        0,
        0,
        name_index,
        culture_index,
        0,
    )


def _build_metadata(lazy_load=False):
    # #Strings:
    #   0x00  ""
    #   0x01  "SharedAssembly"
    #   0x10  "SharedAssembly"     (same text, different offset)
    #   0x1f  "Assembly"           (valid standalone string)
    #
    # The suffix "Assembly" at 0x07 is inside the first string at 0x01.
    heap_data = (
        b"\x00"
        + SHARED
        + b"\x00"
        + DUPLICATE
        + b"\x00"
        + SUFFIX
        + b"\x00"
    )
    strings = stream.StringsHeap(
        0, _stream_struct(b"#Strings", len(heap_data)), heap_data
    )
    strings.file_offset = 0

    # Module row: Generation, Name, Mvid, EncId, EncBaseId.
    module_row = struct.pack("<HHHHH", 0, 1, 0, 0, 0)

    # Module.Name and two AssemblyRef.Name fields share offset 1.
    # AssemblyRef.Name row 3 uses the duplicate at offset 16.
    # AssemblyRef.Name row 4 points into the first string at offset 7.
    # AssemblyRef.Name row 5 has an out-of-range index and must not hide
    # the other valid references.
    assembly_ref_rows = b"".join(
        [
            _assembly_ref_row(1),
            _assembly_ref_row(1),
            _assembly_ref_row(16),
            _assembly_ref_row(7),
            _assembly_ref_row(0xFFFF),
        ]
    )

    mask_valid = (1 << 0) | (1 << 35)
    header = struct.pack("<IBBBBQQ", 0, 1, 1, 0, 0, mask_valid, 0)
    table_data = (
        header
        + struct.pack("<I", 1)
        + struct.pack("<I", 5)
        + module_row
        + assembly_ref_rows
    )

    guid_data = b""
    blob_data = b"\x00"
    guids = stream.GuidHeap(0, _stream_struct(b"#GUID", len(guid_data)), guid_data)
    blobs = stream.BlobHeap(0, _stream_struct(b"#Blob", len(blob_data)), blob_data)
    guids.file_offset = 0
    blobs.file_offset = 0

    tables = stream.MetaDataTables(
        0, _stream_struct(b"#~", len(table_data)), table_data
    )
    tables.file_offset = 0
    tables.parse([strings, guids, blobs], lazy_load=lazy_load)
    return tables, strings


def _name_refs(usage):
    return [ref for ref in usage if ref.field == "Name_StringIndex"]


def test_reverse_lookup_shared_and_duplicate_strings():
    tables, _ = _build_metadata()
    usage = tables.string_usage

    name_refs = _name_refs(usage)
    assert len(name_refs) == 6

    shared = tables.get_string_usage(1, 1 + len(SHARED))
    assert [(ref.table, ref.row_index, ref.field) for ref in shared.exact] == [
        ("Module", 1, "Name_StringIndex"),
        ("AssemblyRef", 1, "Name_StringIndex"),
        ("AssemblyRef", 2, "Name_StringIndex"),
    ]
    assert {ref.index for ref in shared.exact} == {1}
    assert all(ref.effective_end == 15 for ref in shared.exact)

    duplicate = tables.get_string_usage(16, 16 + len(DUPLICATE))
    assert [(ref.table, ref.row_index, ref.field) for ref in duplicate.exact] == [
        ("AssemblyRef", 3, "Name_StringIndex"),
    ]
    assert duplicate.exact[0].index == 16
    assert duplicate.exact[0].raw == DUPLICATE

    # The two strings are byte-for-byte identical but are different entries.
    assert shared.exact[0].raw == duplicate.exact[0].raw
    assert shared.exact[0].index != duplicate.exact[0].index
    assert shared.exact[0].start != duplicate.exact[0].start


def test_suffix_reference_is_an_incomplete_owner():
    tables, _ = _build_metadata()

    suffix_start = 1 + SHARED.index(SUFFIX)
    suffix_end = suffix_start + len(SUFFIX)
    usage = tables.get_string_usage(suffix_start, suffix_end)

    exact = [ref for ref in usage.exact if ref.table == "AssemblyRef"]
    assert len(exact) == 1
    assert exact[0].row_index == 4
    assert exact[0].index == suffix_start
    assert exact[0].raw == SUFFIX
    assert exact[0].boundary is False
    assert exact[0].shares_prefix is True
    assert exact[0].complete is False
    assert exact[0].incomplete is True
    assert exact[0] in usage.candidates

    # The longer string that owns the bytes before the suffix overlaps the
    # same range and is reported as a candidate rather than an exact owner.
    containing = [ref for ref in usage.references if ref.index == 1]
    assert containing
    assert all(ref in usage.candidates for ref in containing)
    assert usage.unowned == ()


def test_bad_index_does_not_hide_valid_references():
    tables, _ = _build_metadata()
    usage = tables.string_usage

    invalid = [ref for ref in _name_refs(usage) if not ref.valid]
    assert len(invalid) == 1
    assert invalid[0].table == "AssemblyRef"
    assert invalid[0].row_index == 5
    assert invalid[0].index == 0xFFFF
    assert invalid[0].start is None
    assert invalid[0].effective_end is None
    assert invalid[0].complete is False

    # Valid rows before and after the bad row are still inventoried.
    assert {ref.row_index for ref in _name_refs(usage) if ref.valid} == {1, 2, 3, 4}

    # Out-of-range queries are clamped and never raise.
    beyond = tables.get_string_usage(0x1000, 0x2000)
    assert beyond.start == tables.strings_heap.sizeof()
    assert beyond.end == beyond.start
    assert len(beyond) == 0


def test_lazy_loading_inventory_matches_full_load_without_forced_parse():
    full_tables, _ = _build_metadata(lazy_load=False)
    lazy_tables, _ = _build_metadata(lazy_load=True)

    full = [
        (ref.table, ref.row_index, ref.field, ref.index, ref.start, ref.end, ref.valid)
        for ref in full_tables.string_usage
    ]
    lazy = [
        (ref.table, ref.row_index, ref.field, ref.index, ref.start, ref.end, ref.valid)
        for ref in lazy_tables.string_usage
    ]
    assert lazy == full

    # Building the inventory reads row structures, but must not force the
    # lazy table to resolve coded indexes and run-lists.
    assert lazy_tables.AssemblyRef._loaded.name != "Loaded"
    assert "Name" not in lazy_tables.AssemblyRef[0].__dict__


def test_inventory_find_returns_each_byte_occurrence():
    tables, _ = _build_metadata()
    usage = tables.string_usage

    matches = usage.find(SHARED)
    assert len(matches) == 2
    assert [match.start for match in matches] == [1, 16]
    assert [len(match.exact) for match in matches] == [3, 1]

    assert usage.at(1) == matches[0].exact
    assert all(ref.index == 1 for ref in usage.references_to(1))

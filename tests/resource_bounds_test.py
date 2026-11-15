import struct

import pefile

RSRC_RVA = 0x1A0
RSRC_RAW = 0x160


def make_pe(res, declared_size=None):
    """Minimal PE32 (SectionAlignment == FileAlignment == 0x10) with a single
    .rsrc section holding the given resource tree blob.
    """
    va, ptr_raw = RSRC_RVA, RSRC_RAW

    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)
    size_of_image = (va + len(res) + 0xF) & ~0xF
    opt = struct.pack("<HBBIIIIII", 0x10B, 0, 0, 0, 0, 0, 0, 0, 0)
    opt += struct.pack("<III", 0x400000, 0x10, 0x10)
    opt += struct.pack("<HHHHHH", 4, 0, 0, 0, 4, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<II", size_of_image, ptr_raw)
    opt += struct.pack("<IHH", 0, 2, 0)
    opt += struct.pack("<IIII", 0, 0, 0, 0)
    opt += struct.pack("<II", 0, 16)
    dirs = [(0, 0)] * 16
    dirs[2] = (va, declared_size if declared_size is not None else len(res))
    for rva, sz in dirs:
        opt += struct.pack("<II", rva, sz)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".rsrc\x00\x00\x00",
        len(res),
        va,
        len(res),
        ptr_raw,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    return dos + b"PE\x00\x00" + coff + opt + section + res


def dir_header(num_entries):
    return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, num_entries)


def dir_entry(name, offset):
    return struct.pack("<II", name, offset)


def data_entry(offset, size):
    return struct.pack("<IIII", RSRC_RVA + offset, size, 0, 0)


def icon_tree(data=b"TEST", data_size=None):
    """A regular three-level RT_ICON resource tree."""
    blob = dir_header(1) + dir_entry(3, 0x80000000 | 0x18)
    blob += dir_header(1) + dir_entry(1, 0x80000000 | 0x30)  # @0x18
    blob += dir_header(1) + dir_entry(0x409, 0x48)  # @0x30
    blob += data_entry(0x58, len(data) if data_size is None else data_size)  # @0x48
    blob += data  # @0x58
    return blob


def deep_tree(depth):
    """A resource tree nested `depth` levels, one entry per directory."""
    level_size = 24  # 16-byte header + one 8-byte entry
    blob = bytearray()
    for i in range(depth):
        blob += dir_header(1)
        if i + 1 < depth:
            blob += dir_entry(1, 0x80000000 | ((i + 1) * level_size))
        else:
            blob += dir_entry(0x409, depth * level_size)
    blob += data_entry(depth * level_size + 16, 4)
    blob += b"TEST"
    return bytes(blob)


def version_blob():
    key = "VS_VERSION_INFO\0".encode("utf-16-le")
    fixed = struct.pack("<13I", 0xFEEF04BD, *([0] * 12))
    sfi_key = "StringFileInfo\0".encode("utf-16-le")
    sfi = struct.pack("<HHH", 6 + len(sfi_key), 0, 1) + sfi_key
    length = 40 + len(fixed) + len(sfi)  # 40 = 6-byte header + key + padding
    blob = struct.pack("<HHH", length, len(fixed), 1) + key
    blob += b"\0" * (40 - len(blob))
    blob += fixed
    blob += sfi
    return blob


def version_tree():
    blob = dir_header(1) + dir_entry(16, 0x80000000 | 0x18)  # RT_VERSION
    blob += dir_header(1) + dir_entry(1, 0x80000000 | 0x30)  # @0x18
    blob += dir_header(1) + dir_entry(0x409, 0x48)  # @0x30
    blob += data_entry(0x58, len(version_blob()))  # @0x48
    blob += version_blob()  # @0x58
    return blob


def walk_to_leaf(pe):
    node = pe.DIRECTORY_ENTRY_RESOURCE
    depth = 0
    while node.entries and hasattr(node.entries[0], "directory"):
        node = node.entries[0].directory
        depth += 1
    return node, depth


def test_valid_icon_tree_is_fully_parsed():
    pe = pefile.PE(data=make_pe(icon_tree()))
    entry = pe.DIRECTORY_ENTRY_RESOURCE.entries[0]
    assert entry.id == pefile.RESOURCE_TYPE["RT_ICON"]
    leaf = entry.directory.entries[0].directory.entries[0]
    assert leaf.id == 0x409
    assert leaf.data.struct.Size == 4
    assert pe.get_data(leaf.data.struct.OffsetToData, 4) == b"TEST"


def test_version_information_is_parsed():
    pe = pefile.PE(data=make_pe(version_tree()))
    assert pe.VS_VERSIONINFO[0].Key == b"VS_VERSION_INFO"
    assert pe.VS_FIXEDFILEINFO[0].Signature == 0xFEEF04BD
    assert pe.FileInfo[0][0].Key == b"StringFileInfo"


def test_deep_tree_hits_depth_budget_without_recursion_error():
    pe = pefile.PE(data=make_pe(deep_tree(5000)))
    assert any("Excessively nested table depth" in w for w in pe.get_warnings())
    _, depth = walk_to_leaf(pe)
    assert depth == pefile.MAX_RESOURCE_DEPTH


def test_deep_tree_parses_with_raised_depth_budget(monkeypatch):
    # 5000 nesting levels would exhaust the interpreter stack if the
    # traversal recursed once per level (default recursion limit is 1000).
    monkeypatch.setattr(pefile, "MAX_RESOURCE_DEPTH", 10000)
    pe = pefile.PE(data=make_pe(deep_tree(5000)))
    node, depth = walk_to_leaf(pe)
    assert depth == 4999
    leaf = node.entries[0]
    assert leaf.data.struct.Size == 4
    assert pe.get_data(leaf.data.struct.OffsetToData, 4) == b"TEST"


def test_circular_directory_reference_is_cut():
    blob = dir_header(1) + dir_entry(1, 0x80000000 | 0)
    pe = pefile.PE(data=make_pe(blob))
    warnings = pe.get_warnings()
    assert any("circular directory reference" in w for w in warnings)
    entry_offset = RSRC_RAW + 16
    assert any(f"{entry_offset:#x}" in w for w in warnings)
    assert pe.DIRECTORY_ENTRY_RESOURCE.entries == []


def test_two_node_cycle_terminates():
    blob = dir_header(1) + dir_entry(1, 0x80000000 | 0x18)
    blob += dir_header(1) + dir_entry(2, 0x80000000 | 0)  # @0x18
    pe = pefile.PE(data=make_pe(blob))
    warnings = pe.get_warnings()
    assert any("circular directory reference" in w for w in warnings)
    entry_offset = RSRC_RAW + 0x18 + 16
    assert any(f"{entry_offset:#x}" in w for w in warnings)
    entry = pe.DIRECTORY_ENTRY_RESOURCE.entries[0]
    assert entry.id == 1
    assert entry.directory.entries == []


def test_corrupt_data_entry_size_is_skipped_but_entry_kept():
    pe = pefile.PE(data=make_pe(icon_tree(data_size=0xFFFFFFFF)))
    warnings = pe.get_warnings()
    assert any("invalid data RVA" in w and "0xffffffff" in w for w in warnings)
    entry_offset = RSRC_RAW + 0x30 + 16
    assert any(f"{entry_offset:#x}" in w for w in warnings)
    leaf = (
        pe.DIRECTORY_ENTRY_RESOURCE.entries[0].directory.entries[0].directory.entries[0]
    )
    assert leaf.id == 0x409
    assert not hasattr(leaf, "data")


def test_out_of_bounds_directory_target_is_skipped_but_entry_kept():
    blob = dir_header(1) + dir_entry(5, 0x80000000 | 0x7FFFFF00)
    pe = pefile.PE(data=make_pe(blob))
    warnings = pe.get_warnings()
    assert any("lies outside the resource directory" in w for w in warnings)
    entry_offset = RSRC_RAW + 16
    assert any(f"{entry_offset:#x}" in w for w in warnings)
    entry = pe.DIRECTORY_ENTRY_RESOURCE.entries[0]
    assert entry.id == 5
    assert not hasattr(entry, "directory")


def test_unknown_type_keeps_name_but_skips_corrupt_data():
    blob = dir_header(1) + dir_entry(0x77, 0x80000000 | 0x18)
    blob += dir_header(1) + dir_entry(0x409, 0x30)  # @0x18
    blob += data_entry(0x40, 0xFFFFFFFF)  # @0x30, corrupt size
    blob += b"TEST"  # @0x40
    pe = pefile.PE(data=make_pe(blob))
    type_entry = pe.DIRECTORY_ENTRY_RESOURCE.entries[0]
    assert type_entry.id == 0x77
    leaf = type_entry.directory.entries[0]
    assert leaf.id == 0x409
    assert not hasattr(leaf, "data")

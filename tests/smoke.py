import struct

import pefile


def build():
    data = bytearray(0x6C0)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    struct.pack_into("<I", data, 0x80, 0x4550)
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 2, 0, 0, 0, 0xE0, 0x102)
    opt = 0x98
    struct.pack_into("<HBB", data, opt, 0x10B, 14, 0)
    struct.pack_into("<IIIIII", data, opt + 4, 0x200, 0x200, 0, 0x1000, 0x1000, 0x2000)
    struct.pack_into("<I", data, opt + 28, 0x400000)
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHHHH", data, opt + 40, 6, 0, 0, 0, 6, 0, 6, 0)
    struct.pack_into("<III", data, opt + 52, 0, 0x3000, 0x200)
    struct.pack_into("<I", data, opt + 64, 0x11223344)
    struct.pack_into("<HH", data, opt + 68, 3, 0)
    struct.pack_into("<IIII", data, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<II", data, opt + 88, 0, 16)
    security = opt + 0x60 + 32
    struct.pack_into("<II", data, security, 0x680, 0x40)
    section_table = opt + 0xE0
    sections = [
        (b".text", 0x1000, 0x1000, 0x200, 0x60000020),
        (b".rdata", 0x2000, 0x2000, 0x400, 0x40000040),
    ]
    for index, (name, virtual_size, virtual_address, raw, chars) in enumerate(sections):
        struct.pack_into(
            "<8sIIIIIIHHI",
            data,
            section_table + index * 40,
            name,
            virtual_size,
            virtual_address,
            0x200,
            raw,
            0,
            0,
            0,
            0,
            chars,
        )
    for index in range(0x200):
        data[0x200 + index] = (index * 7 + 1) & 0xFF
        data[0x400 + index] = (index * 11 + 3) & 0xFF
    data[0x600:0x680] = b"O" * 0x80
    struct.pack_into("<IHH", data, 0x680, 0x40, 0x200, 2)
    return bytes(data)


def test_smoke():
    pe = pefile.PE(data=build(), fast_load=True)
    coverage = pe.get_authenticode_coverage()
    print("STATUS", coverage.status, coverage.provable)
    print("ISSUES", [(item["code"], item["message"]) for item in coverage.issues])
    print("RANGES", [(item.start, item.end, item.kind, item.included, item.source) for item in coverage.ranges])
    print("OVERLAY", coverage.overlay_offset, coverage.overlay_size)
    assert coverage.provable

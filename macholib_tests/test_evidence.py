import contextlib
import os
import struct
import sys
import tempfile

from macholib import MachO, evidence, mach_o

if sys.version_info[:2] <= (2, 6):
    import unittest2 as unittest
else:
    import unittest

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ALL = 0x0
MH_FILETYPE_EXECUTE = 0x2

VMADDR = 0x100000000


def section_64(sectname, segname, addr, size, offset, flags):
    return struct.pack(
        ">16s16sQQIIIIIIII",
        sectname,
        segname,
        addr,
        size,
        offset,
        0,  # align
        0,  # reloff
        0,  # nreloc
        flags,
        0,  # reserved1
        0,  # reserved2
        0,  # reserved3
    )


def lc_segment_64(segname, vmaddr, vmsize, fileoff, filesize, sections):
    payload = struct.pack(
        ">16sQQQQIIII",
        segname,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        7,  # maxprot
        5,  # initprot
        len(sections),
        0,  # flags
    )
    payload += b"".join(sections)
    cmdsize = 8 + len(payload)
    return struct.pack(">II", mach_o.LC_SEGMENT_64, cmdsize) + payload


def thin_macho(cputype, load_commands, file_bytes=b""):
    header = struct.pack(
        ">IIIIIIII",
        mach_o.MH_MAGIC_64,
        cputype,
        CPU_SUBTYPE_ALL,
        MH_FILETYPE_EXECUTE,
        len(load_commands),
        sum(len(lc) for lc in load_commands),
        0,
        0,
    )
    return header + b"".join(load_commands) + file_bytes


def fat_macho(archs):
    # archs: list of (cputype, data); slices are placed at 0x1000
    # boundaries after the fat header.
    offset = 8 + 20 * len(archs)
    entries = []
    slices = []
    for cputype, data in archs:
        offset = (offset + 0xFFF) & ~0xFFF
        entries.append(
            struct.pack(">IIIII", cputype, CPU_SUBTYPE_ALL, offset, len(data), 12)
        )
        slices.append((offset, data))
        offset += len(data)
    result = struct.pack(
        ">II", mach_o.FAT_MAGIC, len(archs)
    ) + b"".join(entries)
    for slice_offset, data in slices:
        result += b"\x00" * (slice_offset - len(result))
        result += data
    return result


@contextlib.contextmanager
def temporary_macho_file(data):
    macho_file = tempfile.NamedTemporaryFile(delete=False)
    try:
        macho_file.write(data)
        macho_file.close()
        yield macho_file.name
    finally:
        os.unlink(macho_file.name)


def exhibit_macho(cputype=CPU_TYPE_ARM64):
    # One __TEXT segment: 0x2000 file bytes, 0x4000 of vm space.
    #   __text  [vmaddr, vmaddr+0x2000)        file-backed
    #   __bss   [vmaddr+0x2000, vmaddr+0x3000) S_ZEROFILL
    #   tail    [vmaddr+0x3000, vmaddr+0x4000) zero-fill past filesize
    segment = lc_segment_64(
        b"__TEXT",
        VMADDR,
        0x4000,
        0,
        0x2000,
        [
            section_64(
                b"__text", b"__TEXT", VMADDR, 0x2000, 0, mach_o.S_REGULAR
            ),
            section_64(
                b"__bss",
                b"__TEXT",
                VMADDR + 0x2000,
                0x1000,
                0,
                mach_o.S_ZEROFILL,
            ),
        ],
    )
    return thin_macho(cputype, [segment], b"\xAA" * 0x2000)


class TestSelectHeader(unittest.TestCase):
    def test_single_slice_default(self):
        with temporary_macho_file(exhibit_macho()) as filename:
            macho = MachO.MachO(filename)
            header = evidence.select_header(macho)
            self.assertIs(header, macho.headers[0])

    def test_fat_select_by_cputype_name(self):
        data = fat_macho(
            [
                (CPU_TYPE_X86_64, exhibit_macho(CPU_TYPE_X86_64)),
                (CPU_TYPE_ARM64, exhibit_macho()),
            ]
        )
        with temporary_macho_file(data) as filename:
            macho = MachO.MachO(filename)
            header = evidence.select_header(macho, cputype="ARM64")
            self.assertEqual(header.header.cputype, CPU_TYPE_ARM64)
            header = evidence.select_header(macho, cputype=CPU_TYPE_X86_64)
            self.assertEqual(header.header.cputype, CPU_TYPE_X86_64)

    def test_fat_without_cputype_is_ambiguous(self):
        data = fat_macho(
            [
                (CPU_TYPE_X86_64, exhibit_macho(CPU_TYPE_X86_64)),
                (CPU_TYPE_ARM64, exhibit_macho()),
            ]
        )
        with temporary_macho_file(data) as filename:
            macho = MachO.MachO(filename)
            with self.assertRaises(ValueError):
                evidence.select_header(macho)

    def test_no_matching_slice(self):
        with temporary_macho_file(exhibit_macho()) as filename:
            macho = MachO.MachO(filename)
            with self.assertRaises(ValueError):
                evidence.select_header(macho, cputype="PowerPC64")
            with self.assertRaises(ValueError):
                evidence.select_header(macho, cputype="not-a-cpu")


class TestAuditAddressRange(unittest.TestCase):
    def audit(self, address, size, slide=0):
        with temporary_macho_file(exhibit_macho()) as filename:
            return evidence.audit_file(filename, address, size, slide=slide)

    def test_query_spanning_three_categories(self):
        # Crosses file-backed bytes, the zerofill section, the zero-
        # filled segment tail and finally unmapped space.
        chunks = self.audit(VMADDR + 0x1800, 0x3800)
        self.assertEqual(
            [chunk.category for chunk in chunks],
            [
                evidence.FILE_BACKED,
                evidence.ZERO_FILL,
                evidence.ZERO_FILL,
                evidence.UNMAPPED,
            ],
        )

        self.assertEqual(chunks[0].address, VMADDR + 0x1800)
        self.assertEqual(chunks[0].size, 0x800)
        self.assertEqual(chunks[0].file_offset, 0x1800)
        self.assertEqual(chunks[0].sectname, "__text")

        self.assertEqual(chunks[1].address, VMADDR + 0x2000)
        self.assertEqual(chunks[1].size, 0x1000)
        self.assertIsNone(chunks[1].file_offset)
        self.assertEqual(chunks[1].sectname, "__bss")

        self.assertEqual(chunks[2].address, VMADDR + 0x3000)
        self.assertEqual(chunks[2].size, 0x1000)
        self.assertIsNone(chunks[2].sectname)

        self.assertEqual(chunks[3].address, VMADDR + 0x4000)
        self.assertEqual(chunks[3].size, 0x1000)
        self.assertIsNone(chunks[3].segname)

        # The chunks tile the whole query range without gaps.
        self.assertEqual(chunks[0].address, VMADDR + 0x1800)
        for first, second in zip(chunks, chunks[1:]):
            self.assertEqual(first.end, second.address)
        self.assertEqual(chunks[-1].end, VMADDR + 0x1800 + 0x3800)

    def test_file_backed_chunk_preserves_file_range(self):
        chunks = self.audit(VMADDR + 0x100, 0x400)
        self.assertEqual(len(chunks), 1)
        (chunk,) = chunks
        self.assertEqual(chunk.category, evidence.FILE_BACKED)
        self.assertEqual(chunk.file_offset, 0x100)
        self.assertEqual(chunk.size, 0x400)
        self.assertEqual(chunk.image_address, VMADDR + 0x100)

    def test_slide_maps_observed_addresses(self):
        slide = 0x4000
        chunks = self.audit(VMADDR + slide + 0x100, 0x400, slide=slide)
        self.assertEqual(len(chunks), 1)
        (chunk,) = chunks
        self.assertEqual(chunk.category, evidence.FILE_BACKED)
        self.assertEqual(chunk.address, VMADDR + slide + 0x100)
        self.assertEqual(chunk.image_address, VMADDR + 0x100)
        self.assertEqual(chunk.file_offset, 0x100)

    def test_zerofill_section_types(self):
        for flags in (
            mach_o.S_ZEROFILL,
            mach_o.S_GB_ZEROFILL,
            mach_o.S_THREAD_LOCAL_ZEROFILL,
        ):
            segment = lc_segment_64(
                b"__DATA",
                VMADDR,
                0x2000,
                0,
                0x2000,
                [
                    section_64(
                        b"__zerofill",
                        b"__DATA",
                        VMADDR,
                        0x1000,
                        0,
                        flags,
                    )
                ],
            )
            data = thin_macho(CPU_TYPE_ARM64, [segment], b"\xAA" * 0x2000)
            with temporary_macho_file(data) as filename:
                chunks = evidence.audit_file(filename, VMADDR, 0x1000)
            self.assertEqual(len(chunks), 1)
            self.assertEqual(chunks[0].category, evidence.ZERO_FILL)
            self.assertIsNone(chunks[0].file_offset)

    def test_unmapped_range(self):
        chunks = self.audit(VMADDR + 0x10000, 0x100)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].category, evidence.UNMAPPED)
        self.assertIsNone(chunks[0].file_offset)

    def test_invalid_size(self):
        with temporary_macho_file(exhibit_macho()) as filename:
            macho = MachO.MachO(filename)
            header = macho.headers[0]
            for size in (0, -1):
                with self.assertRaises(ValueError):
                    evidence.audit_address_range(header, VMADDR, size)

    def test_describe_is_json_serializable(self):
        import json

        chunks = self.audit(VMADDR + 0x1800, 0x3800)
        for chunk in chunks:
            description = chunk.describe()
            json.dumps(description)
            self.assertEqual(description["address"], chunk.address)
            self.assertEqual(description["category"], chunk.category)

    def test_fat_slice_file_offsets_preserved(self):
        # The audit must report the file range recorded by the selected
        # slice unchanged, so the bytes can be carved from the original
        # file.
        arm64_segment = lc_segment_64(
            b"__TEXT",
            VMADDR,
            0x1000,
            0x1000,
            0x1000,
            [
                section_64(
                    b"__text", b"__TEXT", VMADDR, 0x1000, 0x1000,
                    mach_o.S_REGULAR,
                ),
            ],
        )
        arm64 = thin_macho(
            CPU_TYPE_ARM64, [arm64_segment], b"\x00" * 0x2000
        )
        data = fat_macho(
            [
                (CPU_TYPE_X86_64, exhibit_macho(CPU_TYPE_X86_64)),
                (CPU_TYPE_ARM64, arm64),
            ]
        )
        with temporary_macho_file(data) as filename:
            chunks = evidence.audit_file(
                filename, VMADDR + 0x40, 0x80, cputype="ARM64"
            )
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].category, evidence.FILE_BACKED)
        self.assertEqual(chunks[0].file_offset, 0x1040)

if __name__ == "__main__":
    unittest.main()

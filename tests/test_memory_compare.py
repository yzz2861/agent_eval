import struct
import unittest

import pefile


PAGE_SIZE = 0x1000
IMAGE_SIZE = 0x4000
TEXT_RVA = 0x1000
TEXT_RAW = 0x200
RDATA_RVA = 0x2000
RDATA_RAW = 0x400
RELOC_RVA = 0x3000
RELOC_RAW = 0x600
CODE_RVA = 0x1000
RELOC_SITE_RVA = 0x1100
UNKNOWN_SITE_RVA = 0x1108
IAT_RVA = 0x2000
ILT_RVA = 0x2020
IMPORT_DESC_RVA = 0x2040
HINT_NAME_RVA = 0x2080
DLL_NAME_RVA = 0x20A0


def _section_header(name, virtual_size, virtual_address, raw_size, raw_pointer, characteristics):
    return struct.pack(
        "<8sIIIIIIHHI",
        name.encode("ascii").ljust(8, b"\0"),
        virtual_size,
        virtual_address,
        raw_size,
        raw_pointer,
        0,
        0,
        0,
        0,
        characteristics,
    )


def _optional_header(is_64, data_directories):
    if is_64:
        image_base = 0x140000000
        optional_size = 0xF0
        header = struct.pack(
            "<HBBIIIII",
            0x20B,
            14,
            0,
            0x200,
            0x600,
            0,
            CODE_RVA,
            CODE_RVA,
        )
        header += struct.pack("<Q", image_base)
        header += struct.pack("<II", PAGE_SIZE, 0x200)
    else:
        image_base = 0x400000
        optional_size = 0xE0
        header = struct.pack(
            "<HBBIIIIII",
            0x10B,
            14,
            0,
            0x200,
            0x600,
            0,
            CODE_RVA,
            CODE_RVA,
            RDATA_RVA,
        )
        header += struct.pack("<III", image_base, PAGE_SIZE, 0x200)

    header += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    header += struct.pack("<I", 0)
    header += struct.pack("<II", IMAGE_SIZE, 0x200)
    header += struct.pack("<I", 0)
    header += struct.pack("<HH", 2, 0x8100)
    if is_64:
        header += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    else:
        header += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    header += struct.pack("<II", 0, 16)

    assert len(header) == (112 if is_64 else 96)
    for rva, size in data_directories:
        header += struct.pack("<II", rva, size)
    assert len(header) == optional_size
    return header, image_base, optional_size


def _relocation_block(page_rva, relocation_type, offsets):
    entries = [(relocation_type, offset) for offset in offsets]
    while len(entries) % 2:
        entries.append((0, 0))
    words = b"".join(
        struct.pack("<H", (entry_type << 12) | offset)
        for entry_type, offset in entries
    )
    return struct.pack("<II", page_rva, 8 + len(words)) + words


def build_synthetic_pe(bits=32, unknown_relocation=False, iat_conflict_relocation=False):
    is_64 = bits == 64
    pointer_size = 8 if is_64 else 4
    pointer_format = "<Q" if is_64 else "<I"
    machine = 0x8664 if is_64 else 0x14C
    relocation_type = 10 if is_64 else 3
    characteristics = 0x22 if is_64 else 0x0102

    reloc_data = _relocation_block(
        RELOC_SITE_RVA & ~0xFFF,
        relocation_type,
        [RELOC_SITE_RVA & 0xFFF],
    )
    if unknown_relocation:
        reloc_data += _relocation_block(
            UNKNOWN_SITE_RVA & ~0xFFF,
            14,
            [UNKNOWN_SITE_RVA & 0xFFF],
        )
    if iat_conflict_relocation:
        reloc_data += _relocation_block(
            IAT_RVA & ~0xFFF, relocation_type, [IAT_RVA & 0xFFF]
        )

    directories = [(0, 0)] * 16
    directories[1] = (IMPORT_DESC_RVA, 40)
    directories[5] = (RELOC_RVA, len(reloc_data))
    directories[12] = (IAT_RVA, 2 * pointer_size)

    optional_header, image_base, optional_size = _optional_header(
        is_64, directories
    )
    coff_header = struct.pack(
        "<HHIIIHH", machine, 3, 0, 0, 0, optional_size, characteristics
    )

    disk = bytearray(0x800)
    disk[0:2] = b"MZ"
    struct.pack_into("<I", disk, 0x3C, 64)
    disk[64:68] = b"PE\0\0"
    disk[68:88] = coff_header
    optional_offset = 88
    disk[optional_offset : optional_offset + len(optional_header)] = optional_header

    section_offset = optional_offset + optional_size
    sections = b"".join(
        [
            _section_header(".text", 0x200, TEXT_RVA, 0x200, TEXT_RAW, 0x60000020),
            _section_header(".rdata", 0x200, RDATA_RVA, 0x200, RDATA_RAW, 0x40000040),
            _section_header(".reloc", 0x200, RELOC_RVA, 0x200, RELOC_RAW, 0x42000040),
        ]
    )
    disk[section_offset : section_offset + len(sections)] = sections

    text = bytearray(0x200)
    code = b"\x31\xC0\x40\xC3"
    text[: len(code)] = code
    struct.pack_into(
        pointer_format,
        text,
        RELOC_SITE_RVA - TEXT_RVA,
        image_base + CODE_RVA,
    )
    text[UNKNOWN_SITE_RVA - TEXT_RVA : UNKNOWN_SITE_RVA - TEXT_RVA + 8] = b'\"' * 8
    disk[TEXT_RAW : TEXT_RAW + len(text)] = text

    rdata = bytearray(0x200)
    struct.pack_into(
        pointer_format, rdata, IAT_RVA - RDATA_RVA, HINT_NAME_RVA
    )
    struct.pack_into(
        pointer_format, rdata, ILT_RVA - RDATA_RVA, HINT_NAME_RVA
    )
    import_descriptor = struct.pack(
        "<IIIII", ILT_RVA, 0, 0, DLL_NAME_RVA, IAT_RVA
    )
    descriptor_offset = IMPORT_DESC_RVA - RDATA_RVA
    rdata[descriptor_offset : descriptor_offset + len(import_descriptor)] = (
        import_descriptor
    )

    hint_offset = HINT_NAME_RVA - RDATA_RVA
    struct.pack_into("<H", rdata, hint_offset, 0)
    function_name = b"callee\0"
    rdata[hint_offset + 2 : hint_offset + 2 + len(function_name)] = function_name

    dll_offset = DLL_NAME_RVA - RDATA_RVA
    dll_name = b"sample.dll\0"
    rdata[dll_offset : dll_offset + len(dll_name)] = dll_name
    disk[RDATA_RAW : RDATA_RAW + len(rdata)] = rdata

    disk[RELOC_RAW : RELOC_RAW + len(reloc_data)] = reloc_data

    layout = {
        "bits": bits,
        "pointer_size": pointer_size,
        "pointer_format": pointer_format,
        "image_base": image_base,
        "actual_base": image_base + 0x100000,
        "relocation_type": relocation_type,
    }
    return bytes(disk), layout


def mapped_image(disk):
    pe = pefile.PE(data=disk)
    image = bytearray(pe.get_memory_mapped_image())
    image.extend(b"\0" * (IMAGE_SIZE - len(image)))
    return pe, image


def loader_image(disk, layout, iat_value=None):
    _pe, image = mapped_image(disk)
    actual_base = layout["actual_base"]
    pointer_size = layout["pointer_size"]
    pointer_format = layout["pointer_format"]

    struct.pack_into(
        pointer_format,
        image,
        RELOC_SITE_RVA,
        actual_base + CODE_RVA,
    )
    if iat_value is None:
        iat_value = 0x71231234 if pointer_size == 4 else 0x00007FF011223344
    struct.pack_into(pointer_format, image, IAT_RVA, iat_value)
    return image


def page_fragments(image, actual_base, omitted_pages=()):
    fragments = []
    for page in range(IMAGE_SIZE // PAGE_SIZE):
        if page in omitted_pages:
            continue
        start = page * PAGE_SIZE
        fragments.append(
            (actual_base + start, bytes(image[start : start + PAGE_SIZE]))
        )
    return fragments


def interval_tuples(findings):
    return [(item.rva_start, item.rva_end) for item in findings]


def one(findings, kind=None):
    if kind is not None:
        findings = [item for item in findings if item.kind == kind]
    assert len(findings) == 1, [(item.kind, item.rva_start, item.rva_end) for item in findings]
    return findings[0]


class MemoryCompareTests(unittest.TestCase):
    def assert_range(self, finding, start, end):
        self.assertEqual((finding.rva_start, finding.rva_end), (start, end))
        self.assertEqual(finding.length, end - start)

    def test_legal_relocation_and_iat_binding_x86(self):
        self.legal_relocation_and_iat_binding(32)

    def test_legal_relocation_and_iat_binding_x64(self):
        self.legal_relocation_and_iat_binding(64)

    def legal_relocation_and_iat_binding(self, bits):
        disk, layout = build_synthetic_pe(bits)
        image = loader_image(disk, layout)
        result = pefile.compare_memory_image(
            disk,
            page_fragments(image, layout["actual_base"]),
            layout["actual_base"],
        )

        width = layout["pointer_size"]
        reloc_claim = one(result.claims, "base_relocation")
        self.assert_range(reloc_claim, RELOC_SITE_RVA, RELOC_SITE_RVA + width)
        self.assertEqual(reloc_claim.expected, bytes(image[RELOC_SITE_RVA:RELOC_SITE_RVA + width]))

        iat_claim = one(result.claims, "iat_binding")
        self.assert_range(iat_claim, IAT_RVA, IAT_RVA + width)
        self.assertEqual(iat_claim.dll, b"sample.dll")
        self.assertEqual(iat_claim.import_name, "callee")

        self.assertEqual(result.suspicious_differences, [])
        self.assertEqual(result.conflicts, [])
        explained_kinds = {item.explanation for item in result.explained_changes}
        self.assertIn("base_relocation", explained_kinds)
        self.assertIn("iat_binding", explained_kinds)
        self.assertTrue(
            all(item.claim_ids for item in result.explained_changes)
        )

    def test_code_patch_has_exact_byte_interval_x86(self):
        self.code_patch_has_exact_byte_interval(32)

    def test_code_patch_has_exact_byte_interval_x64(self):
        self.code_patch_has_exact_byte_interval(64)

    def code_patch_has_exact_byte_interval(self, bits):
        disk, layout = build_synthetic_pe(bits)
        image = loader_image(disk, layout)
        image[CODE_RVA + 1] = 0xCC

        result = pefile.compare_memory_image(
            disk,
            page_fragments(image, layout["actual_base"]),
            layout["actual_base"],
        )

        patch = one(result.suspicious_differences)
        self.assert_range(patch, CODE_RVA + 1, CODE_RVA + 2)
        self.assertEqual(patch.disk_bytes, b"\xC0")
        self.assertEqual(patch.memory_bytes, b"\xCC")
        self.assertEqual(patch.explanation, "unexplained_difference")

    def test_iat_binding_is_precise_but_unverified_without_resolver(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                disk, layout = build_synthetic_pe(bits)
                image = loader_image(disk, layout)
                result = pefile.compare_memory_image(
                    disk,
                    page_fragments(image, layout["actual_base"]),
                    layout["actual_base"],
                )
                iat_claim = one(
                    [item for item in result.claims if item.kind == "iat_binding"]
                )
                self.assert_range(
                    iat_claim, IAT_RVA, IAT_RVA + layout["pointer_size"]
                )
                iat_change = one(
                    [
                        item
                        for item in result.explained_changes
                        if item.explanation == "iat_binding"
                    ]
                )
                self.assertEqual(
                    (iat_change.rva_start, iat_change.rva_end),
                    (IAT_RVA, IAT_RVA + (6 if bits == 64 else 4)),
                )
                self.assertNotEqual(iat_change.verification, "exact")
                self.assertIn(iat_change, result.unverified_loader_changes)

    def test_verified_iat_overwrite_is_suspicious_exact_slot(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                disk, layout = build_synthetic_pe(bits)
                good_target = 0x71231234 if bits == 32 else 0x00007FF011221000
                bad_target = 0xDEADBEEF if bits == 32 else 0xDEADBEEFCAFEBABE
                image = loader_image(disk, layout, iat_value=bad_target)
                result = pefile.compare_memory_image(
                    disk,
                    page_fragments(image, layout["actual_base"]),
                    layout["actual_base"],
                    resolved_iat={IAT_RVA: good_target},
                )
                bad_slot = one(result.suspicious_differences)
                width = layout["pointer_size"]
                self.assert_range(bad_slot, IAT_RVA, IAT_RVA + width)
                self.assertEqual(bad_slot.explanation, "iat_binding_mismatch")

                good_image = loader_image(disk, layout, iat_value=good_target)
                clean = pefile.compare_memory_image(
                    disk,
                    page_fragments(good_image, layout["actual_base"]),
                    layout["actual_base"],
                    resolved_iat={IAT_RVA: good_target},
                )
                self.assertEqual(clean.suspicious_differences, [])

    def test_missing_page_is_unavailable_not_zero_compared(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                disk, layout = build_synthetic_pe(bits)
                image = loader_image(disk, layout)
                result = pefile.compare_memory_image(
                    disk,
                    page_fragments(image, layout["actual_base"], omitted_pages=(3,)),
                    layout["actual_base"],
                )
                missing = one(result.missing_pages)
                self.assert_range(missing, RELOC_RVA, IMAGE_SIZE)
                self.assertIn(
                    (RELOC_RVA, IMAGE_SIZE), interval_tuples(result.indeterminate_ranges)
                )
                self.assertFalse(
                    any(
                        start < IMAGE_SIZE and end > RELOC_RVA
                        for start, end in interval_tuples(result.suspicious_differences)
                    )
                )

    def test_unknown_relocation_is_undecidable_but_other_relocation_still_explained(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                disk, layout = build_synthetic_pe(bits, unknown_relocation=True)
                image = loader_image(disk, layout)
                image[UNKNOWN_SITE_RVA : UNKNOWN_SITE_RVA + 8] = b"\xEE" * 8
                result = pefile.compare_memory_image(
                    disk,
                    page_fragments(image, layout["actual_base"]),
                    layout["actual_base"],
                )

                reloc_claim = one(result.claims, "base_relocation")
                self.assertEqual(reloc_claim.rva_start, RELOC_SITE_RVA)

                unknown_region = one(result.indeterminate_ranges, "unknown_relocation_type")
                self.assertEqual(unknown_region.anchor_rva, UNKNOWN_SITE_RVA)
                self.assertEqual(unknown_region.rva_start, UNKNOWN_SITE_RVA)
                self.assertGreaterEqual(
                    unknown_region.rva_end - unknown_region.rva_start, 8
                )

                unknown_diff = one(result.indeterminate_differences)
                self.assert_range(
                    unknown_diff, UNKNOWN_SITE_RVA, UNKNOWN_SITE_RVA + 8
                )
                self.assertEqual(unknown_diff.explanation, "unknown_relocation_type")
                self.assertEqual(result.suspicious_differences, [])
                self.assertTrue(
                    any("other relocations remain active" in warning for warning in result.warnings)
                )

    def test_overlapping_relocation_and_iat_reports_conflict(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                disk, layout = build_synthetic_pe(
                    bits, iat_conflict_relocation=True
                )
                conflict_target = (
                    0xDEADBEEF if bits == 32 else 0xDEADBEEFCAFEBABE
                )
                image = loader_image(disk, layout, iat_value=conflict_target)
                result = pefile.compare_memory_image(
                    disk,
                    page_fragments(image, layout["actual_base"]),
                    layout["actual_base"],
                )
                width = layout["pointer_size"]
                conflict = one(result.conflicts)
                self.assert_range(conflict, IAT_RVA, IAT_RVA + width)
                self.assertGreaterEqual(len(conflict.claim_ids), 2)

                conflict_diff = one(result.indeterminate_differences)
                self.assert_range(conflict_diff, IAT_RVA, IAT_RVA + width)
                self.assertTrue(conflict_diff.conflict)
                self.assertEqual(conflict_diff.explanation, "explanation_conflict")

    def test_rva_addressed_fragments_and_read_only_pe(self):
        disk, layout = build_synthetic_pe(64)
        pe = pefile.PE(data=disk)
        image = loader_image(disk, layout)
        fragments = [
            pefile.MemoryFragment.at_rva(start, bytes(image[start : start + PAGE_SIZE]))
            for start in range(0, IMAGE_SIZE, PAGE_SIZE)
        ]
        original_base = pe.OPTIONAL_HEADER.ImageBase
        result = pe.compare_memory(fragments, layout["actual_base"])
        self.assertEqual(result.suspicious_differences, [])
        self.assertEqual(pe.OPTIONAL_HEADER.ImageBase, original_base)
        self.assertEqual(
            pe.get_qword_at_rva(RELOC_SITE_RVA), original_base + CODE_RVA
        )

    def test_rva_mapping_keyword_aliases_and_dict_output(self):
        disk, layout = build_synthetic_pe(32)
        image = loader_image(disk, layout)
        regions = {
            start: bytes(image[start : start + PAGE_SIZE])
            for start in range(0, IMAGE_SIZE, PAGE_SIZE)
        }
        result = pefile.compare_memory_image(
            disk,
            memory_regions=regions,
            actual_base=layout["actual_base"],
        )
        self.assertEqual(result.suspicious_differences, [])
        self.assertEqual(result.missing_pages, [])
        serialized = result.to_dict()
        self.assertEqual(serialized["summary"]["suspicious_differences"], 0)


if __name__ == "__main__":
    unittest.main()

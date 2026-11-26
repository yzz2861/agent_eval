"""Forensic comparison tests for equal values and distinct raw records."""
import struct
import unittest
from io import BytesIO

from elftools.elf.elffile import ELFFile
from elftools.elf.evidence import (
    build_report,
    collect_evidence,
    compare_evidence,
    count_independent_evidence,
)

ET_REL = 1
EM_AARCH64 = 183
SHT_NOTE = 7
NT_GNU_PROPERTY_TYPE_0 = 5


def _gnu_property_note(endian: str, properties: list[tuple[int, bytes]]) -> bytes:
    descriptor = bytearray()
    for property_type, data in properties:
        record = struct.pack(endian + "II", property_type, len(data)) + data
        record += b"\0" * (-len(record) % 8)
        descriptor.extend(record)

    name = b"GNU\0"
    header = struct.pack(
        endian + "III", len(name), len(descriptor), NT_GNU_PROPERTY_TYPE_0
    )
    return header + name + bytes(descriptor)


def _in_memory_elf(little_endian: bool) -> ELFFile:
    endian = "<" if little_endian else ">"
    security_value = struct.pack(endian + "I", 3)
    unknown_data = b"\x12\x34\x56\x78"
    notes = [
        _gnu_property_note(endian, [(0xC0000000, security_value)]),
        _gnu_property_note(endian, [(0xC0000000, security_value)]),
        _gnu_property_note(endian, [(0x11112222, unknown_data)]),
    ]
    section_names = [
        ".shstrtab",
        ".note.security.one",
        ".note.security.two",
        ".note.unknown",
    ]

    shstrtab = bytearray(b"\0")
    name_offsets: dict[str, int] = {}
    for name in section_names:
        name_offsets[name] = len(shstrtab)
        shstrtab.extend(name.encode("ascii") + b"\0")

    ehdr_size = 64
    offsets: list[int] = []
    cursor = ehdr_size
    for note in notes:
        cursor = (cursor + 7) & ~7
        offsets.append(cursor)
        cursor += len(note)

    shstr_offset = cursor
    cursor += len(shstrtab)
    shoff = (cursor + 7) & ~7
    null_section_count = 1
    shnum = null_section_count + len(section_names)
    blob = bytearray(shoff + shnum * 64)

    ident = (
        b"\x7fELF"
        + bytes([2, 1 if little_endian else 2, 1, 0])
        + b"\0" * 8
    )
    ehdr = struct.pack(
        endian + "16sHHIQQQIHHHHHH",
        ident,
        ET_REL,
        EM_AARCH64,
        1,
        0,
        0,
        shoff,
        0,
        64,
        0,
        0,
        64,
        shnum,
        1,
    )
    blob[0:len(ehdr)] = ehdr

    for offset, note in zip(offsets, notes):
        blob[offset:offset + len(note)] = note
    blob[shstr_offset:shstr_offset + len(shstrtab)] = shstrtab

    shdr_format = endian + "IIQQQQIIQQ"
    shdrs = [b"\0" * 64]
    shdrs.append(struct.pack(
        shdr_format,
        name_offsets[".shstrtab"], 3, 0, 0, shstr_offset, len(shstrtab),
        0, 0, 1, 0,
    ))
    for name, offset, note in zip(section_names[1:], offsets, notes):
        shdrs.append(struct.pack(
            shdr_format,
            name_offsets[name], SHT_NOTE, 0, 0, offset, len(note),
            0, 0, 8, 0,
        ))

    for index, shdr in enumerate(shdrs):
        start = shoff + index * 64
        blob[start:start + len(shdr)] = shdr

    return ELFFile(BytesIO(bytes(blob)))


def little_endian_fixture() -> ELFFile:
    return _in_memory_elf(little_endian=True)


def big_endian_fixture() -> ELFFile:
    return _in_memory_elf(little_endian=False)


class EvidenceComparisonTest(unittest.TestCase):
    def setUp(self) -> None:
        self.little_elf = little_endian_fixture()
        self.big_elf = big_endian_fixture()
        self.little = collect_evidence(self.little_elf, "little-endian-fixture")
        self.big = collect_evidence(self.big_elf, "big-endian-fixture")

    def test_fixtures_are_normal_and_endian_specific(self) -> None:
        self.assertTrue(self.little_elf.little_endian)
        self.assertFalse(self.big_elf.little_endian)
        self.assertEqual(len(self.little), 3)
        self.assertEqual(len(self.big), 3)
        for record in self.little + self.big:
            self.assertEqual(record.section_description, "NOTE")
            self.assertEqual(record.note_type, "NT_GNU_PROPERTY_TYPE_0")
            self.assertEqual(record.raw[12:16], b"GNU\0")
            self.assertEqual(len(record.raw), record.size)

    def test_reviewer_can_confirm_security_metric_meaning(self) -> None:
        known = [record for record in self.little + self.big
                 if record.value_determinate]
        self.assertEqual(len(known), 4)
        for record in known:
            self.assertEqual(
                record.record_type,
                "GNU_PROPERTY_AARCH64_FEATURE_1_AND",
            )
            self.assertEqual(record.numeric_value, 3)
            self.assertIn("aarch64 feature", record.meaning)
            self.assertIn("bti", record.meaning)
            self.assertIn("pac", record.meaning)

        unknown = [record for record in self.little + self.big
                   if not record.value_determinate]
        self.assertEqual(len(unknown), 2)
        for record in unknown:
            self.assertIsNone(record.numeric_value)
            self.assertIsInstance(record.record_type, int)
            self.assertIn("unknown type", record.meaning)

    def test_two_sections_with_same_value_are_two_records(self) -> None:
        first, second = self.little[0], self.little[1]

        self.assertEqual(first.numeric_value, second.numeric_value)
        self.assertEqual(first.raw, second.raw)
        self.assertNotEqual(first.section_name, second.section_name)
        self.assertNotEqual(first.raw_range, second.raw_range)
        self.assertNotEqual(first.key, second.key)

        comparison = compare_evidence(first, second)
        self.assertTrue(comparison.numeric_equivalent)
        self.assertTrue(comparison.raw_bytes_equal)
        self.assertFalse(comparison.same_raw_range)
        self.assertTrue(comparison.distinct_raw_record)
        self.assertIn("numeric_value_equivalent", comparison.labels)
        self.assertIn("different_raw_range", comparison.labels)
        self.assertIn("independent_evidence", comparison.labels)

    def test_equal_numeric_value_does_not_merge_endian_records(self) -> None:
        little = self.little[0]
        big = self.big[0]

        self.assertEqual(little.numeric_value, big.numeric_value)
        self.assertEqual(little.meaning, big.meaning)
        self.assertEqual(little.raw_range, big.raw_range)
        self.assertNotEqual(little.raw, big.raw)

        comparison = compare_evidence(little, big)
        self.assertTrue(comparison.numeric_equivalent)
        self.assertTrue(comparison.meanings_equal)
        self.assertTrue(comparison.raw_encoding_differs)
        self.assertFalse(comparison.raw_bytes_equal)
        self.assertFalse(comparison.same_raw_range)
        self.assertTrue(comparison.distinct_raw_record)
        self.assertIn("numeric_value_equivalent", comparison.labels)
        self.assertIn("raw_bytes_different", comparison.labels)

    def test_unknown_parsed_field_is_indeterminate(self) -> None:
        little_unknown = self.little[2]
        big_unknown = self.big[2]

        comparison = compare_evidence(little_unknown, big_unknown)
        self.assertIsNone(comparison.values_equivalent)
        self.assertTrue(comparison.value_indeterminate)
        self.assertIn("parsed_field_indeterminate", comparison.labels)

        known_vs_unknown = compare_evidence(self.little[0], little_unknown)
        self.assertIsNone(known_vs_unknown.values_equivalent)
        self.assertTrue(known_vs_unknown.value_indeterminate)

    def test_report_counts_independent_occurrences_not_values(self) -> None:
        little_report = build_report(self.little_elf, "little-endian-fixture")
        big_report = build_report(self.big_elf, "big-endian-fixture")
        self.assertEqual(little_report.independent_count, 3)
        self.assertEqual(big_report.independent_count, 3)

        all_records = self.little + self.big
        self.assertEqual(count_independent_evidence(all_records), 6)
        default_le = collect_evidence(self.little_elf)
        default_be = collect_evidence(self.big_elf)
        self.assertEqual(count_independent_evidence(default_le + default_be), 6)
        groups = little_report.numeric_groups()
        self.assertEqual(len(groups), 1)
        grouped_records = next(iter(groups.values()))
        self.assertEqual(len(grouped_records), 2)


if __name__ == "__main__":
    unittest.main()

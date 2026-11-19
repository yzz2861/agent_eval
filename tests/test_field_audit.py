import io
import json
import unittest

from elftools.elf.elffile import ELFFile

from elf_table_audit import (
    AuditTable,
    RelocEvidence,
    RelocForm,
    VerdictKind,
    classify_fields,
    iter_archive_members,
)
from elf_table_audit.audit import _classify_field

REL_OBJECT = "fixtures/micro_ftab_rel_i386.o"
RELA_OBJECT = "fixtures/micro_ftab_rela_x86_64.o"
ARCHIVE = "fixtures/micro_ftab.a"
OVERLAP_OBJECT = "fixtures/overlap_ftab_rel_i386.o"


class ThreeSlotContractTest(unittest.TestCase):
    def _kinds(self, result):
        return {v.field_index: v.kind for v in result.fields}

    def test_rel_three_slots(self):
        (result,) = classify_fields(REL_OBJECT, [AuditTable("ftab", ".rodata", 4, 0, 3)])
        kinds = self._kinds(result)
        self.assertEqual((kinds[0], kinds[1], kinds[2]), (VerdictKind.PROVEN, VerdictKind.GAP, VerdictKind.GAP))
        self.assertEqual(result.summary(), {"proven": 1, "candidate": 0, "gap": 2})

    def test_rela_three_slots(self):
        (result,) = classify_fields(RELA_OBJECT, [AuditTable("ftab", ".rodata", 8, 0, 3)])
        kinds = self._kinds(result)
        self.assertEqual((kinds[0], kinds[1], kinds[2]), (VerdictKind.PROVEN, VerdictKind.GAP, VerdictKind.GAP))

    def test_proven_slot_carries_relocation_evidence(self):
        (result,) = classify_fields(REL_OBJECT, [AuditTable("ftab", ".rodata", 4, 0, 3)])
        proven = next(v for v in result.fields if v.kind is VerdictKind.PROVEN)
        self.assertEqual(len(proven.relocations), 1)
        evidence = proven.relocations[0]
        self.assertEqual(evidence.form, RelocForm.REL)
        self.assertEqual(evidence.symbol_name, "firmware_entry")
        self.assertIsNone(evidence.addend)
        self.assertIn("REL", evidence.addend_source)
        self.assertTrue(any("firmware_entry" in r for r in proven.reasons))

    def test_rela_exposes_inline_addend(self):
        (result,) = classify_fields(RELA_OBJECT, [AuditTable("ftab", ".rodata", 8, 0, 3)])
        evidence = result.fields[0].relocations[0]
        self.assertEqual(evidence.form, RelocForm.RELA)
        self.assertEqual(evidence.addend, 0)
        self.assertIn("RELA", evidence.addend_source)

    def test_zero_byte_relocated_slot_is_not_empty(self):
        # The exact regression the old byte-only inventory got wrong.
        (result,) = classify_fields(REL_OBJECT, [AuditTable("ftab", ".rodata", 4, 0, 3)])
        relocated, empty = result.fields[0], result.fields[1]
        self.assertEqual(relocated.raw_value, 0)
        self.assertEqual(empty.raw_value, 0)
        self.assertIs(relocated.kind, VerdictKind.PROVEN)
        self.assertIs(empty.kind, VerdictKind.GAP)
        self.assertEqual(relocated.relocations[0].r_offset, relocated.section_offset)
        self.assertEqual(empty.relocations, ())

    def test_unexplained_nonzero_slot_is_gap(self):
        (result,) = classify_fields(REL_OBJECT, [AuditTable("ftab", ".rodata", 4, 0, 3)])
        gap = result.fields[2]
        self.assertIs(gap.kind, VerdictKind.GAP)
        self.assertNotEqual(gap.raw_value, 0)
        self.assertTrue(any("no attribution basis" in r for r in gap.reasons))


class ArchiveTest(unittest.TestCase):
    def test_archive_lists_both_elf_members(self):
        with open(ARCHIVE, "rb") as handle:
            buffer = handle.read()
        members = iter_archive_members(buffer)
        self.assertEqual([m.name for m in members], [
            "micro_ftab_rel_i386.o", "micro_ftab_rela_x86_64.o"
        ])
        self.assertTrue(all(m.is_elf for m in members))

    def test_classify_archive_audits_each_member(self):
        results = classify_fields(ARCHIVE, [AuditTable("ftab", ".rodata", 4, 0, 3)])
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.member_name is not None for r in results))
        for result in results:
            self.assertEqual(result.summary()["proven"], 1)


class OverlapTest(unittest.TestCase):
    def test_overlapping_ranges_are_reported_with_source(self):
        tables = [
            AuditTable("group_a", ".rodata", 4, 0, 2),
            AuditTable("group_b", ".rodata", 4, 1, 2),
        ]
        (result,) = classify_fields(OVERLAP_OBJECT, tables)
        self.assertEqual(len(result.overlaps), 1)
        note = result.overlaps[0]
        self.assertEqual({note.range_a, note.range_b}, {"group_a", "group_b"})
        self.assertEqual(note.first_shared_offset, 4)
        shared = [v for v in result.fields if v.field_index == 1]
        labels = {label for v in shared for label in v.overlaps}
        self.assertIn("group_a", labels)
        self.assertIn("group_b", labels)


class ClassificationUnitTest(unittest.TestCase):
    def _evidence(self, name=("x",), note=None, arch=True):
        symbol = None if name is None else name[0]
        return RelocEvidence(
            reloc_section=".rel.x", entry_index=0, form=RelocForm.REL,
            r_offset=0, r_info_type=1, r_info_type_name="R_X", r_info_sym=2,
            symbol_name=symbol, symbol_section="section#3", symbol_index=2,
            addend=None, addend_source="REL", note=note,
        )

    def test_named_symbol_is_proven_even_when_undefined(self):
        kind, _ = _classify_field(4, 0, [self._evidence(note="undefined")], True)
        self.assertIs(kind, VerdictKind.PROVEN)

    def test_unnamed_symbol_is_candidate(self):
        kind, reasons = _classify_field(4, 0, [self._evidence(name=None)], True)
        self.assertIs(kind, VerdictKind.CANDIDATE)
        self.assertTrue(any("unnamed" in r for r in reasons))

    def test_unsupported_architecture_downgrades_to_candidate(self):
        kind, reasons = _classify_field(4, 0, [self._evidence()], False)
        self.assertIs(kind, VerdictKind.CANDIDATE)
        self.assertTrue(any("architecture" in r for r in reasons))

    def test_no_relocation_zero_is_gap(self):
        kind, _ = _classify_field(4, 0, [], True)
        self.assertIs(kind, VerdictKind.GAP)

    def test_no_relocation_nonzero_is_gap(self):
        kind, _ = _classify_field(4, 0xDEAD, [], True)
        self.assertIs(kind, VerdictKind.GAP)

    def test_invalid_width_rejected(self):
        with self.assertRaises(ValueError):
            classify_fields(REL_OBJECT, [AuditTable("ftab", ".rodata", 3, 0, 1)])


class ReadOnlyAndSerializationTest(unittest.TestCase):
    def test_input_file_is_not_modified(self):
        with open(REL_OBJECT, "rb") as handle:
            before = handle.read()
        classify_fields(REL_OBJECT, [AuditTable("ftab", ".rodata", 4, 0, 3)])
        with open(REL_OBJECT, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)

    def test_result_dict_declares_read_only_and_no_application(self):
        (result,) = classify_fields(REL_OBJECT, [AuditTable("ftab", ".rodata", 4, 0, 3)])
        payload = result.to_dict()
        self.assertTrue(payload["read_only"])
        self.assertFalse(payload["relocations_applied"])
        json.dumps(payload)

    def test_elf_opened_from_in_memory_buffer(self):
        with open(REL_OBJECT, "rb") as handle:
            buffer = handle.read()
        elf = ELFFile(io.BytesIO(buffer))
        self.assertEqual(elf["e_machine"], "EM_386")


if __name__ == "__main__":
    unittest.main()

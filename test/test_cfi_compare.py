#-------------------------------------------------------------------------------
# elftools tests
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
import struct
import unittest
from io import BytesIO
from os.path import join

from elftools.dwarf.callframe import (
    CFARule,
    CallFrameInfo,
    DecodedCallFrameTable,
    FDE,
    RegisterRule,
)
from elftools.dwarf.cfi_compare import (
    AddressMap,
    ComparisonStatus,
    FrameFile,
    FramePair,
    RuleSource,
    compare_decoded_tables,
    compare_frame_files,
    compare_rule_segments,
    segments_from_fde,
)
from elftools.dwarf.structs import DWARFStructs


def _cie_bytes():
    body = (
        b'\x01'                    # version
        b'\x00'                    # augmentation
        b'\x01'                    # code alignment
        b'\x01'                    # data alignment
        b'\x08'                    # return address register
        b'\x0c\x07\x08'            # DW_CFA_def_cfa r7 + 8
        b'\x88\x01'                # DW_CFA_offset r8 1
    )
    return struct.pack('<I', len(body) + 4) + b'\xff\xff\xff\xff' + body


def _fde_bytes(start, size, r6_offset):
    instructions = (
        b'\x50'                    # DW_CFA_advance_loc 0x10
        + b'\x05\x06' + bytes([r6_offset])  # DW_CFA_offset_extended r6
        + b'\x50'                  # DW_CFA_advance_loc 0x10
        + b'\x07\x06'              # DW_CFA_undefined r6
    )
    body = (
        struct.pack('<I', 0)       # CIE pointer
        + struct.pack('<I', start)
        + struct.pack('<I', size)
        + instructions
    )
    return struct.pack('<I', len(body)) + body


def _parse_single_fde(start, size, r6_offset):
    data = _cie_bytes() + _fde_bytes(start, size, r6_offset)
    structs = DWARFStructs(
        little_endian=True, dwarf_format=32, address_size=4)
    cfi = CallFrameInfo(
        BytesIO(data), len(data), address=0, base_structs=structs)
    entries = cfi.get_entries()
    fdes = [entry for entry in entries if isinstance(entry, FDE)]
    assert len(fdes) == 1
    return fdes[0]


class TestCFICompare(unittest.TestCase):
    def test_synthetic_fdes_mark_exact_partial_divergence(self):
        left = segments_from_fde(
            _parse_single_fde(0x1000, 0x30, 4),
            side='left',
            path='artifact.o',
            section='.eh_frame')
        right = segments_from_fde(
            _parse_single_fde(0x1000, 0x30, 8),
            side='right',
            path='artifact.o.debug',
            section='.debug_frame')

        intervals = compare_rule_segments(left, right)

        self.assertEqual(
            [(i.start, i.end, i.status) for i in intervals],
            [
                (0x1000, 0x1010, ComparisonStatus.SAME),
                (0x1010, 0x1020, ComparisonStatus.DIFFERENT),
                (0x1020, 0x1030, ComparisonStatus.SAME),
            ])
        difference = intervals[1].differences[0]
        self.assertEqual(difference.field, 'r6')
        self.assertEqual(difference.left, 'cfa+4')
        self.assertEqual(difference.right, 'cfa+8')

    def test_short_decoded_tables_only_diverge_in_middle(self):
        def line(pc, r6_rule=None):
            result = {
                'pc': pc,
                'cfa': CFARule(reg=7, offset=8),
                8: RegisterRule(RegisterRule.OFFSET, 1),
            }
            if r6_rule is not None:
                result[6] = r6_rule
            return result

        left = DecodedCallFrameTable(
            table=[
                line(0x2000),
                line(0x2010, RegisterRule(RegisterRule.OFFSET, 4)),
                line(0x2020, RegisterRule(RegisterRule.UNDEFINED)),
            ],
            reg_order=[8, 6])
        right = DecodedCallFrameTable(
            table=[
                line(0x2000),
                line(0x2010, RegisterRule(RegisterRule.OFFSET, 8)),
                line(0x2020, RegisterRule(RegisterRule.UNDEFINED)),
            ],
            reg_order=[8, 6])

        intervals = compare_decoded_tables(
            left,
            right,
            start=0x2000,
            end=0x2030)

        self.assertEqual(
            [(i.start, i.end, i.status) for i in intervals],
            [
                (0x2000, 0x2010, ComparisonStatus.SAME),
                (0x2010, 0x2020, ComparisonStatus.DIFFERENT),
                (0x2020, 0x2030, ComparisonStatus.SAME),
            ])

    def test_expressions_are_incomparable_and_keep_provenance(self):
        left_source = RuleSource(
            side='left',
            path='artifact.elf',
            section='.eh_frame',
            fde_offset=0x40,
            cie_offset=0x10,
            line_index=0,
            pc=0x3000)
        right_source = RuleSource(
            side='right',
            path='artifact.debug',
            section='.debug_frame',
            fde_offset=0x80,
            cie_offset=0x20,
            line_index=0,
            pc=0x3000)
        left = [{
            'pc': 0x3000,
            'cfa': CFARule(reg=7, offset=8),
            6: RegisterRule(RegisterRule.EXPRESSION, [0x90, 0x01]),
        }]
        right = [{
            'pc': 0x3000,
            'cfa': CFARule(reg=7, offset=8),
            6: RegisterRule(RegisterRule.EXPRESSION, [0x90, 0x01]),
        }]

        intervals = compare_decoded_tables(
            left,
            right,
            start=0x3000,
            end=0x3010,
            left_source=left_source,
            right_source=right_source)

        self.assertEqual(len(intervals), 1)
        interval = intervals[0]
        self.assertEqual(interval.status, ComparisonStatus.INCOMPARABLE)
        self.assertEqual(interval.differences, ())
        self.assertEqual(len(interval.expressions), 2)
        for expression in interval.expressions:
            self.assertEqual(expression.expression, b'\x90\x01')
            self.assertEqual(expression.source.line_index, 0)
            self.assertEqual(expression.source.pc, 0x3000)
        self.assertEqual(
            {rule.source.path for rule in interval.incomparable_rules},
            {'artifact.elf', 'artifact.debug'})

    def test_address_map_uses_right_to_left_bias(self):
        address_map = AddressMap(-0x1000)
        self.assertEqual(address_map.map_address(0x2000), 0x1000)
        self.assertEqual(
            address_map.map_range(0x2000, 0x2010), (0x1000, 0x1010))

    def test_gap_on_one_side_is_not_reported_as_different(self):
        left = [{
            'pc': 0x4000,
            'cfa': CFARule(reg=7, offset=8),
        }]
        right = [{
            'pc': 0x4000,
            'cfa': CFARule(reg=7, offset=8),
        }]

        intervals = compare_decoded_tables(
            left,
            right,
            start=0x4000,
            end=0x4010,
            right_end=0x4008)

        self.assertEqual(
            [(i.start, i.end, i.status) for i in intervals],
            [
                (0x4000, 0x4008, ComparisonStatus.SAME),
                (0x4008, 0x4010, ComparisonStatus.LEFT_ONLY),
            ])

    def test_elf_backed_sections_are_paired_and_auditable(self):
        path = join('test', 'testfiles_for_unittests', 'sample_exe64.elf')

        comparison = compare_frame_files(FramePair(
            left=FrameFile(path, '.eh_frame'),
            right=FrameFile(path, '.debug_frame')))

        self.assertEqual(comparison.left_file.section, '.eh_frame')
        self.assertEqual(comparison.right_file.section, '.debug_frame')
        self.assertEqual(len(comparison.left_file.sha256), 64)
        self.assertTrue(comparison.matched_fdes)
        self.assertTrue(comparison.is_clean)
        self.assertEqual(comparison.summary()['different'], 0)
        self.assertEqual(comparison.summary()['incomparable'], 0)
        self.assertFalse(comparison.unmatched_intervals)


if __name__ == '__main__':
    unittest.main()

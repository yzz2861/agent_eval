#-------------------------------------------------------------------------------
# elftools tests
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
import unittest
from io import BytesIO

from elftools.dwarf.constants import DW_LNS
from elftools.dwarf.lineprogram import LineProgram, LineProgramError
from elftools.dwarf.structs import DWARFStructs


def _uleb128(value):
    encoded = []
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def _sleb128(value):
    encoded = []
    while True:
        byte = value & 0x7f
        value >>= 7
        sign = byte & 0x40
        if (value == 0 and not sign) or (value == -1 and sign):
            encoded.append(byte)
            return bytes(encoded)
        encoded.append(byte | 0x80)


class TestLineProgram(unittest.TestCase):
    def _make_program_in_stream(self, stream):
        """ Create a LineProgram from the given program encoded in a stream
        """
        ds = DWARFStructs(little_endian=True, dwarf_format=32, address_size=4)
        header = ds.Dwarf_lineprog_header.parse(
            b'\x04\x10\x00\x00'    # initial length
            b'\x03\x00'            # version
            b'\x20\x00\x00\x00'    # header length
            b'\x01\x01\x01\x0F'    # flags
            b'\x0A'                # opcode_base
            b'\x00\x01\x04\x08\x0C\x01\x01\x01\x00' # standard_opcode_lengths
            # 2 dir names followed by a NULL
            b'\x61\x62\x00\x70\x00\x00'
            # a file entry
            b'\x61\x72\x00\x0C\x0D\x0F'
            # and another entry
            b'\x45\x50\x51\x00\x86\x12\x07\x08'
            # followed by NULL
            b'\x00')

        lp = LineProgram(header, stream, ds, 0, len(stream.getvalue()))
        return lp

    def _make_v4_program_in_stream(self, stream, *, opcode_base=10,
                                   standard_opcode_lengths=None,
                                   directories=(b'ab', b'p'),
                                   files=((b'ar', 1), (b'EPQ', 2)),
                                   maximum_operations_per_instruction=1,
                                   line_base=1, line_range=15):
        if standard_opcode_lengths is None:
            standard_opcode_lengths = [0, 1, 1, 1, 1, 0, 0, 0, 1]
        header_bytes = b''.join((
            b'\x00\x00\x00\x00',                 # initial length
            b'\x04\x00',                         # version
            b'\x00\x00\x00\x00',                 # header length
            b'\x01',                             # minimum_instruction_length
            bytes([maximum_operations_per_instruction]),
            b'\x01',                             # default_is_stmt
            bytes([line_base & 0xff]),            # line_base
            bytes([line_range]),                 # line_range
            bytes([opcode_base]),
            bytes(standard_opcode_lengths),
            b''.join(directory + b'\x00' for directory in directories),
            b'\x00',
            b''.join(
                name + b'\x00' + _uleb128(dir_index) + b'\x00\x00'
                for name, dir_index in files),
            b'\x00',
        ))
        return self._make_program_with_header(
            stream, header_bytes, version=4)

    def _make_v5_program_in_stream(self, stream, *,
                                   files=((b'a.c', 0), (b'b.h', 1))):
        standard_opcode_lengths = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]
        header_bytes = b''.join((
            b'\x00\x00\x00\x00',                 # initial length
            b'\x05\x00',                         # version
            b'\x04',                             # address_size
            b'\x00',                             # segment_selector_size
            b'\x00\x00\x00\x00',                 # header length
            b'\x01',                             # minimum_instruction_length
            b'\x01',                             # maximum_operations_per_instruction
            b'\x01',                             # default_is_stmt
            b'\xfb',                             # line_base = -5
            b'\x0e',                             # line_range
            b'\x0d',                             # opcode_base
            bytes(standard_opcode_lengths),
            # One directory entry format: DW_LNCT_path, DW_FORM_string.
            b'\x01\x01\x08',
            b'\x02' + b'.\x00d\x00',
            # File entry format: path (string), directory_index (data1).
            b'\x02\x01\x08\x02\x0b',
            _uleb128(len(files)),
            b''.join(
                name + b'\x00' + bytes([dir_index])
                for name, dir_index in files),
        ))
        return self._make_program_with_header(
            stream, header_bytes, version=5)

    def _make_program_with_header(self, stream, header_bytes, version):
        ds = DWARFStructs(
            little_endian=True, dwarf_format=32, address_size=4,
            dwarf_version=version)
        header = ds.Dwarf_lineprog_header.parse(header_bytes)
        return LineProgram(header, stream, ds, 0, len(stream.getvalue()))

    def assertLineState(self, state, **kwargs):
        """ Assert that the state attributes specified in kwargs have the given
            values (the rest are default).
        """
        for k, v in kwargs.items():
            self.assertEqual(getattr(state, k), v)

    def test_spec_sample_59(self):
        # Sample in figure 59 of DWARFv3
        s = BytesIO(
            b'\x02\xb9\x04'
            b'\x0b'
            b'\x38'
            b'\x82'
            b'\x73'
            b'\x02\x02'
            b'\x00\x01\x01')

        lp = self._make_program_in_stream(s)
        linetable = lp.get_entries()

        self.assertEqual(len(linetable), 7)
        self.assertIs(linetable[0].state, None)  # doesn't modify state
        self.assertEqual(linetable[0].command, DW_LNS.advance_pc)
        self.assertEqual(linetable[0].args, [0x239])
        self.assertLineState(linetable[1].state, address=0x239, line=3)
        self.assertEqual(linetable[1].command, 0xb)
        self.assertEqual(linetable[1].args, [2, 0, 0])
        self.assertLineState(linetable[2].state, address=0x23c, line=5)
        self.assertLineState(linetable[3].state, address=0x244, line=6)
        self.assertLineState(linetable[4].state, address=0x24b, line=7, end_sequence=False)
        self.assertEqual(linetable[5].command, DW_LNS.advance_pc)
        self.assertEqual(linetable[5].args, [2])
        self.assertLineState(linetable[6].state, address=0x24d, line=7, end_sequence=True)

    def test_spec_sample_60(self):
        # Sample in figure 60 of DWARFv3
        s = BytesIO(
            b'\x09\x39\x02'
            b'\x0b'
            b'\x09\x03\x00'
            b'\x0b'
            b'\x09\x08\x00'
            b'\x0a'
            b'\x09\x07\x00'
            b'\x0a'
            b'\x09\x02\x00'
            b'\x00\x01\x01')

        lp = self._make_program_in_stream(s)
        linetable = lp.get_entries()

        self.assertEqual(len(linetable), 10)
        self.assertIs(linetable[0].state, None)  # doesn't modify state
        self.assertEqual(linetable[0].command, DW_LNS.fixed_advance_pc)
        self.assertEqual(linetable[0].args, [0x239])
        self.assertLineState(linetable[1].state, address=0x239, line=3)
        self.assertLineState(linetable[3].state, address=0x23c, line=5)
        self.assertLineState(linetable[5].state, address=0x244, line=6)
        self.assertLineState(linetable[7].state, address=0x24b, line=7, end_sequence=False)
        self.assertLineState(linetable[9].state, address=0x24d, line=7, end_sequence=True)

    def test_lne_set_discriminator(self):
        """
        Tests the handling of DWARFv4's new DW_LNE.set_discriminator opcode.
        """
        s = BytesIO()
        s.write(
            b'\x00\x02\x04\x05' +  # DW_LNE.set_discriminator (discriminator=0x05)
            b'\x01' +              # DW_LNS.copy
            b'\x00\x01\x01'        # DW_LNE.end_sequence
        )

        lp = self._make_program_in_stream(s)
        linetable = lp.get_entries()

        # We expect two entries, since DW_LNE.set_discriminator does not add
        # an entry of its own.
        self.assertEqual(len(linetable), 2)
        self.assertEqual(linetable[0].command, DW_LNS.copy)
        self.assertLineState(linetable[0].state, discriminator=0x05)
        self.assertLineState(linetable[1].state, discriminator=0x00, end_sequence=True)

    def test_bad_file_index_is_rejected(self):
        s = BytesIO(
            b'\x04' + _uleb128(65535) +     # DW_LNS.set_file 65535
            b'\x01' +                       # DW_LNS.copy
            b'\x00\x01\x01')                # DW_LNE.end_sequence

        lp = self._make_v4_program_in_stream(s)
        with self.assertRaises(LineProgramError) as caught:
            lp.get_entries()

        error = caught.exception
        self.assertEqual(error.opcode_offset, 0)
        self.assertEqual(error.current_file, 1)
        self.assertEqual(error.dimension, 'file')
        self.assertIn('65535', str(error))
        self.assertIn('opcode offset 0x0', str(error))
        self.assertIn('file 1', str(error))
        self.assertIn('dimension file', str(error))

    def test_v4_and_v5_file_index_bases(self):
        # DWARF4 file numbers are 1-based.
        s = BytesIO(
            b'\x04\x01' +                   # set_file 1
            b'\x01' +                       # copy
            b'\x00\x01\x01')
        entries = self._make_v4_program_in_stream(s).get_entries()
        self.assertEqual(entries[1].state.file, 1)

        s = BytesIO(
            b'\x04\x00' +                   # set_file 0 (DWARF5 only)
            b'\x01' +                       # copy
            b'\x00\x01\x01')
        entries = self._make_v5_program_in_stream(s).get_entries()
        self.assertEqual(entries[1].state.file, 0)

        s = BytesIO(b'\x04\x02')            # file 2 is out of range in v5
        with self.assertRaises(LineProgramError) as caught:
            self._make_v5_program_in_stream(s).get_entries()
        self.assertEqual(caught.exception.dimension, 'file')

        s = BytesIO(b'\x04\x00')            # file 0 is out of range in v4
        with self.assertRaises(LineProgramError) as caught:
            self._make_v4_program_in_stream(s).get_entries()
        self.assertEqual(caught.exception.dimension, 'file')

    def test_huge_advance_pc_is_rejected(self):
        s = BytesIO(b'\x02' + _uleb128(1 << 32))
        with self.assertRaises(LineProgramError) as caught:
            self._make_v4_program_in_stream(s).get_entries()

        error = caught.exception
        self.assertEqual(error.opcode_offset, 0)
        self.assertEqual(error.current_file, 1)
        self.assertEqual(error.dimension, 'address')
        self.assertIn('address overflow', str(error))
        self.assertIn('32-bit target limit', str(error))

    def test_address_overflow_after_set_address(self):
        s = BytesIO(
            b'\x00\x05\x02\xff\xff\xff\xff' +  # set_address 0xffffffff
            b'\x09\x01\x00')                   # fixed_advance_pc 1
        with self.assertRaises(LineProgramError) as caught:
            self._make_v4_program_in_stream(s).get_entries()

        error = caught.exception
        self.assertEqual(error.opcode_offset, 7)
        self.assertEqual(error.dimension, 'address')

    def test_sequence_offset_limit(self):
        s = BytesIO(b'\x02\x05' + b'\x02\x05')
        lp = self._make_v4_program_in_stream(s)
        lp.max_sequence_offset = 8
        with self.assertRaises(LineProgramError) as caught:
            lp.get_entries()

        error = caught.exception
        self.assertEqual(error.opcode_offset, 2)
        self.assertEqual(error.current_file, 1)
        self.assertEqual(error.dimension, 'sequence_offset')
        self.assertIn('max_sequence_offset=8', str(error))

    def test_sequence_offset_resets_at_end_sequence(self):
        s = BytesIO(
            b'\x02\x05' +                   # advance 5
            b'\x00\x01\x01' +               # end sequence
            b'\x02\x05' +                   # advance 5 in next sequence
            b'\x00\x01\x01')
        lp = self._make_v4_program_in_stream(s)
        lp.max_sequence_offset = 5
        entries = lp.get_entries()
        self.assertEqual(len(entries), 4)
        self.assertTrue(entries[1].state.end_sequence)
        self.assertTrue(entries[3].state.end_sequence)

    def test_define_file_extends_the_file_table(self):
        s = BytesIO(
            b'\x00\x06\x03\x61\x00\x01\x00\x00' +  # define_file a, dir 1
            b'\x04\x02' +                          # set_file 2
            b'\x01' +                              # copy
            b'\x00\x01\x01')
        lp = self._make_v4_program_in_stream(s, files=((b'ar', 1),))
        entries = lp.get_entries()
        self.assertEqual(len(lp.header.file_entry), 2)
        self.assertEqual(entries[-2].state.file, 2)

    def test_line_overflow_and_underflow(self):
        s = BytesIO(b'\x03' + _sleb128(1 << 32))
        with self.assertRaises(LineProgramError) as caught:
            self._make_v4_program_in_stream(s).get_entries()
        self.assertEqual(caught.exception.dimension, 'line')

        s = BytesIO(b'\x03' + _sleb128(-2))
        with self.assertRaises(LineProgramError) as caught:
            self._make_v4_program_in_stream(s).get_entries()
        self.assertEqual(caught.exception.dimension, 'line')

    def test_max_entries_limit(self):
        s = BytesIO(b'\x01\x01\x01')
        lp = self._make_v4_program_in_stream(s)
        lp.max_entries = 2
        with self.assertRaises(LineProgramError) as caught:
            lp.get_entries()

        error = caught.exception
        self.assertEqual(error.opcode_offset, 2)
        self.assertEqual(error.dimension, 'entry_count')
        self.assertIn('max_entries=2', str(error))

    def test_unknown_standard_opcode_is_skipped(self):
        std_lengths = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 2, 0]
        s = BytesIO(
            b'\x0e\x01\x02' +               # unknown standard opcode 14
            b'\x01' +                       # copy
            b'\x00\x01\x01')
        entries = self._make_v4_program_in_stream(
            s, opcode_base=16,
            standard_opcode_lengths=std_lengths).get_entries()
        self.assertEqual([entry.command for entry in entries],
                         [DW_LNS.copy, 0x01])
        self.assertEqual(entries[0].state.address, 0)
        self.assertEqual(entries[0].state.line, 1)

    def test_unknown_extended_opcode_is_skipped(self):
        s = BytesIO(
            b'\x00\x03\x80\xaa\xbb' +       # unknown extended opcode
            b'\x01' +                       # copy
            b'\x00\x01\x01')
        entries = self._make_v4_program_in_stream(s).get_entries()
        self.assertEqual([entry.command for entry in entries],
                         [DW_LNS.copy, 0x01])

    def test_empty_sequence(self):
        entries = self._make_v4_program_in_stream(BytesIO(b'')).get_entries()
        self.assertEqual(entries, [])

        s = BytesIO(
            b'\x00\x01\x01' +               # empty sequence
            b'\x00\x01\x01')                # another empty sequence
        entries = self._make_v4_program_in_stream(s).get_entries()
        self.assertEqual(len(entries), 2)
        for entry in entries:
            self.assertTrue(entry.state.end_sequence)
            self.assertEqual(entry.state.address, 0)
            self.assertEqual(entry.state.line, 1)
            self.assertEqual(entry.state.file, 1)

    def test_missing_end_sequence_stops_without_synthetic_row(self):
        s = BytesIO(b'\x01')                # copy, but no end_sequence
        entries = self._make_v4_program_in_stream(s).get_entries()
        self.assertEqual(len(entries), 1)
        self.assertFalse(entries[-1].state.end_sequence)

    def test_v4_and_v5_legal_programs(self):
        # The figure 59 program from DWARFv3/4 with maximum_operations_per_instruction=1.
        s = BytesIO(
            b'\x02\xb9\x04'
            b'\x0b'
            b'\x38'
            b'\x82'
            b'\x73'
            b'\x02\x02'
            b'\x00\x01\x01')
        entries = self._make_v4_program_in_stream(s).get_entries()
        self.assertEqual(len(entries), 7)
        self.assertLineState(entries[1].state, address=0x239, line=3)
        self.assertLineState(entries[6].state, address=0x24d, line=7,
                             end_sequence=True)

        # A DWARF5 program using the 0-based file table and its file_names
        # representation (without the DWARFInfo compatibility file_entry).
        s = BytesIO(
            b'\x04\x00' +                   # set_file 0
            b'\x02\x02' +                   # advance_pc 2
            b'\x01' +                       # copy
            b'\x00\x01\x01')                # end_sequence
        lp = self._make_v5_program_in_stream(s)
        self.assertIsNone(lp.header.get('file_entry'))
        entries = lp.get_entries()
        self.assertEqual(len(entries), 4)
        self.assertLineState(entries[2].state, address=2, line=1, file=0)
        self.assertLineState(entries[3].state, address=2, line=1, file=0,
                             end_sequence=True)


if __name__ == '__main__':
    unittest.main()

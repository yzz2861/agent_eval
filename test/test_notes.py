import os
import struct
import unittest
from io import BytesIO

from elftools.common.exceptions import NoteDuplicateError, NoteParseError
from elftools.construct import Container
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection
from elftools.elf.segments import NoteSegment
from elftools.elf.structs import ELFStructs


def _align4(data):
    return data + b'\0' * (-len(data) % 4)


def _build_note(name=b'GNU\0', desc=b'', note_type=3, *,
                namesz=None, descsz=None, endian='<'):
    """Build a raw note. Length fields can deliberately disagree with data."""
    if namesz is None:
        namesz = len(name)
    if descsz is None:
        descsz = len(desc)
    return (
        struct.pack(f'{endian}III', namesz, descsz, note_type)
        + _align4(name)
        + _align4(desc)
    )


class _BoundedBytesIO(BytesIO):
    """A stream that records reads and refuses to read past a source bound."""

    def __init__(self, data, read_limit=None):
        super().__init__(data)
        self.read_limit = read_limit
        self.reads = []

    def read(self, size=-1):
        start = self.tell()
        if size is not None and size >= 0:
            end = start + size
            if self.read_limit is not None and end > self.read_limit:
                raise AssertionError(
                    f'read [{start:#x}, {end:#x}) crossed source bound '
                    f'{self.read_limit:#x}')
            self.reads.append((start, end))
        return super().read(size)


class _FakeELFFile:
    def __init__(self, data, *, elfclass=64, e_type='ET_EXEC',
                 read_limit=None):
        self.stream = _BoundedBytesIO(data, read_limit)
        self.stream_len = len(data)
        self.elfclass = elfclass
        self.structs = ELFStructs(little_endian=True, elfclass=elfclass)
        self.structs.create_basic_structs()
        self.structs.create_advanced_structs()
        self.header = Container(e_type=e_type)

    def __getitem__(self, name):
        return self.header[name]


def _note_section(section_data, *, offset=0x20, vaddr=0x400000,
                  elfclass=64, e_type='ET_EXEC', tail=b''):
    data = b'\0' * offset + section_data + tail
    elf = _FakeELFFile(
        data, elfclass=elfclass, e_type=e_type,
        read_limit=offset + len(section_data))
    header = Container(
        sh_type='SHT_NOTE',
        sh_offset=offset,
        sh_size=len(section_data),
        sh_flags=0,
        sh_addralign=4,
        sh_addr=vaddr,
    )
    return NoteSection(header, '.note.test', elf)


def _note_segment(section_data, *, offset=0x20, vaddr=0x400000,
                  elfclass=64, e_type='ET_EXEC'):
    data = b'\0' * offset + section_data
    elf = _FakeELFFile(data, elfclass=elfclass, e_type=e_type)
    header = Container(
        p_type='PT_NOTE',
        p_offset=offset,
        p_filesz=len(section_data),
        p_memsz=len(section_data),
        p_vaddr=vaddr,
    )
    return NoteSegment(header, elf.stream, elf)


def _assert_note_in_source(testcase, note, section, *, tolerant=0):
    start = section['sh_offset']
    end = start + section['sh_size']
    for offset_key, size_key in (
            ('n_raw_offset', 'n_raw_size'),
            ('n_header_offset', 'n_header_size'),
            ('n_name_offset', 'n_name_size'),
            ('n_name_padding_offset', 'n_name_padding_size'),
            ('n_desc_offset', 'n_desc_size'),
            ('n_desc_padding_offset', 'n_desc_padding_size')):
        offset = note[offset_key]
        size = note[size_key]
        testcase.assertGreaterEqual(offset, start, offset_key)
        testcase.assertLessEqual(offset + size, end + tolerant,
                                 f'{offset_key} ends outside source')


class TestNotes(unittest.TestCase):
    def test_note_after_gnu_property_type_note(self):
        with ELFFile.load_from_path(os.path.join('test', 'testfiles_for_unittests', 'note_after_gnu_property', 'main.elf')) as elf:
            note_sections = [section for section in elf.iter_sections() if isinstance(section, NoteSection)]
            # There's only one note section in this file:
            self.assertEqual(len(note_sections), 1)
            notes = list(note_sections[0].iter_notes())
            # There are 2 notes in this section:
            self.assertEqual(len(notes), 2)
            # The first note is the GNU_PROPERTY_TYPE_0 note:
            self.assertEqual(notes[0].n_type, 'NT_GNU_PROPERTY_TYPE_0')
            # It should only have two Elf_Props (and not attempt to parse the note after it as Elf_Props):
            self.assertEqual(len(notes[0].n_desc), 2)

    def test_note_segment_with_8_byte_alignment(self):
        with ELFFile.load_from_path(os.path.join('test', 'testfiles_for_unittests', 'note_with_segment_padding', 'main.elf')) as elf:
            note_sections = [section for section in elf.iter_sections() if isinstance(section, NoteSection)]
            # There's only one note section in this file:
            self.assertEqual(len(note_sections), 1)
            notes = list(note_sections[0].iter_notes())
            # There's one note in this section:
            self.assertEqual(len(notes), 1)

    def test_note_tc3xx_blinky(self):
        with ELFFile.load_from_path(os.path.join('test', 'testfiles_for_unittests', 'note_tc3xxx_blinky.elf')) as elf:
            note_sections = [section for section in elf.iter_sections() if isinstance(section, NoteSection)]
            # There's only one note section in this file:
            self.assertEqual(len(note_sections), 1)
            notes = list(note_sections[0].iter_notes())
            # All 522 notes belong to Altium, whose type numbers are not GNU's.
            self.assertEqual(len(notes), 522)
            self.assertTrue(all(isinstance(note.n_type, int) for note in notes))


class TestNoteValidation(unittest.TestCase):
    def test_64bit_note_source_metadata_and_known_descriptors(self):
        build_id = _build_note(
            desc=b'\x01\x23\x45\x67\x89\xab\xcd\xef', note_type=3)
        abi_tag = _build_note(
            desc=struct.pack('<IIII', 0, 3, 2, 1), note_type=1)
        # The same numeric type as GNU build-id must remain an unknown owner.
        unknown_owner = _build_note(
            name=b'ACME\0', desc=b'\xaa\xbb\xcc', note_type=3)
        section = _note_section(build_id + abi_tag + unknown_owner, elfclass=64)
        notes = list(section.iter_notes())

        self.assertEqual(len(notes), 3)
        self.assertEqual(notes[0].n_type, 'NT_GNU_BUILD_ID')
        self.assertEqual(notes[0].n_desc, '0123456789abcdef')
        self.assertEqual(notes[1].n_type, 'NT_GNU_ABI_TAG')
        self.assertEqual(notes[1].n_desc['abi_os'], 'ELF_NOTE_OS_LINUX')
        self.assertEqual(notes[1].n_desc['abi_major'], 3)
        self.assertEqual(notes[1].n_desc['abi_minor'], 2)
        self.assertEqual(notes[1].n_desc['abi_tiny'], 1)

        unknown = notes[2]
        self.assertEqual(unknown.n_name, 'ACME')
        self.assertEqual(unknown.n_type, 3)
        self.assertEqual(unknown.n_type_raw, 3)
        self.assertEqual(unknown.n_descdata, b'\xaa\xbb\xcc')
        self.assertEqual(unknown.n_desc, b'\xaa\xbb\xcc')

        for note in notes:
            self.assertEqual(note.n_source_type, 'section')
            self.assertEqual(note.n_source_name, '.note.test')
            self.assertEqual(note.n_file_offset, note.n_offset)
            self.assertEqual(
                note.n_source_offset, note.n_offset - section['sh_offset'])
            self.assertEqual(
                note.n_vaddr, section['sh_addr'] + note.n_source_offset)
            self.assertEqual(
                note.n_section_offset, note.n_source_offset)
            self.assertIsNone(note.n_segment_offset)
            self.assertEqual(note.n_status, 'ok')
            self.assertFalse(note.n_is_corrupt)
            self.assertFalse(note.n_conflict)
            _assert_note_in_source(self, note, section)

    def test_segment_source_metadata(self):
        section_data = _build_note(desc=b'\x10\x20\x30\x40', note_type=3)
        segment = _note_segment(section_data, offset=0x28, vaddr=0x7fff0000)
        note = next(segment.iter_notes())
        self.assertEqual(note.n_source_type, 'segment')
        self.assertEqual(note.n_segment_offset, 0)
        self.assertEqual(note.n_source_offset, 0)
        self.assertEqual(note.n_file_offset, 0x28)
        self.assertEqual(note.n_vaddr, 0x7fff0000)
        self.assertIsNone(note.n_section_offset)
        self.assertEqual(note.n_raw_offset, 0x28)
        self.assertEqual(note.n_end_offset, 0x28 + len(section_data))

    def test_name_without_nul_is_reported_with_offset_and_category(self):
        note_data = _build_note(
            name=b'GNU', namesz=3, desc=b'\x01\x02', descsz=2, note_type=3)
        section = _note_section(note_data)
        with self.assertRaises(NoteParseError) as caught:
            list(section.iter_notes())
        error = caught.exception
        self.assertEqual(error.category, 'missing_name_terminator')
        self.assertEqual(error.offset, section['sh_offset'] + 12)
        self.assertEqual(error.note_offset, section['sh_offset'])

    def test_bad_alignment_is_rejected_before_header_read(self):
        note_data = _build_note(desc=b'\x01', note_type=3)
        section = _note_section(note_data, offset=0x21)
        with self.assertRaises(NoteParseError) as caught:
            list(section.iter_notes())
        error = caught.exception
        self.assertEqual(error.category, 'bad_alignment')
        self.assertEqual(error.offset, section['sh_offset'])
        # Only the one-byte prefix (for the trailing check) and no header were
        # read at the misaligned offset.
        self.assertTrue(all(end <= section['sh_offset'] + section['sh_size']
                            for _, end in section.elffile.stream.reads))

    def test_truncated_header_is_reported_before_reading_next_source(self):
        # A partial header: namesz is present but descsz/type are missing.
        section = _note_section(struct.pack('<I', 4))
        with self.assertRaises(NoteParseError) as caught:
            list(section.iter_notes())
        error = caught.exception
        self.assertEqual(error.category, 'truncated_header')
        self.assertEqual(error.offset, section['sh_offset'])
        corrupt = next(section.iter_notes(on_error='record'))
        self.assertEqual(
            corrupt.n_error['category'], 'truncated_header')
        self.assertEqual(
            corrupt.n_error['offset'], section['sh_offset'])

    def test_missing_alignment_padding_is_reported(self):
        # A five-byte name needs three bytes of padding before the descriptor.
        section = _note_section(
            struct.pack('<III', 5, 0, 3) + b'ACME\0')
        with self.assertRaises(NoteParseError) as caught:
            list(section.iter_notes())
        error = caught.exception
        self.assertEqual(error.category, 'bad_alignment')
        self.assertEqual(error.offset, section['sh_offset'] + 12)

    def test_desc_out_of_bounds_does_not_read_next_section(self):
        declared_desc = b'\x11' * 8
        malformed = _build_note(
            name=b'GNU\0', desc=declared_desc, descsz=0x200, note_type=3)
        next_section = _build_note(desc=b'\x22\x33', note_type=3)
        section = _note_section(malformed, tail=next_section)

        with self.assertRaises(NoteParseError) as caught:
            list(section.iter_notes())
        error = caught.exception
        self.assertEqual(error.category, 'desc_out_of_bounds')
        self.assertEqual(error.offset, section['sh_offset'] + 16)
        self.assertEqual(error.note_offset, section['sh_offset'])
        for start, end in section.elffile.stream.reads:
            self.assertLessEqual(
                end, section['sh_offset'] + section['sh_size'])

        notes = list(section.iter_notes(on_error='record'))
        self.assertEqual(len(notes), 1)
        corrupt = notes[0]
        self.assertTrue(corrupt.n_is_corrupt)
        self.assertEqual(corrupt.n_status, 'corrupt')
        self.assertEqual(corrupt.n_error['category'], 'desc_out_of_bounds')
        self.assertEqual(
            corrupt.n_error['offset'], section['sh_offset'] + 16)

    def test_unknown_owner_preserves_raw_descriptor_and_type(self):
        note_data = _build_note(
            name=b'Vendor\0', desc=b'\xde\xad\xbe\xef', note_type=3)
        section = _note_section(note_data)
        note = next(section.iter_notes())
        self.assertEqual(note.n_name, 'Vendor')
        self.assertEqual(note.n_name_raw, b'Vendor\0')
        self.assertEqual(note.n_type, 3)
        self.assertEqual(note.n_type_raw, 3)
        self.assertEqual(note.n_descdata, b'\xde\xad\xbe\xef')
        self.assertEqual(note.n_desc, b'\xde\xad\xbe\xef')

    def test_duplicate_build_ids_are_returned_and_marked(self):
        first = _build_note(desc=b'\x01\x02\x03\x04', note_type=3)
        second = _build_note(desc=b'\x05\x06\x07\x08', note_type=3)
        third = _build_note(desc=b'\x09\x0a\x0b\x0c', note_type=3)
        section = _note_section(first + second + third)
        notes = list(section.iter_notes())

        self.assertEqual(len(notes), 3)
        self.assertEqual(
            [note.n_desc for note in notes],
            ['01020304', '05060708', '090a0b0c'])
        for note in notes:
            self.assertTrue(note.n_duplicate_group)
            self.assertTrue(note.n_conflict)
            self.assertEqual(note.n_duplicate_count, 3)
            self.assertEqual(
                note.n_duplicate_offsets,
                [section['sh_offset'] + i * len(first) for i in range(3)])
        self.assertEqual(notes[0].n_duplicate_index, 0)
        self.assertFalse(notes[0].n_duplicate)
        self.assertIsNone(notes[0].n_duplicate_of)
        self.assertEqual(notes[1].n_duplicate_index, 1)
        self.assertTrue(notes[1].n_duplicate)
        self.assertEqual(notes[1].n_duplicate_of, notes[0].n_offset)

        marked = list(section.iter_notes(duplicate_policy='mark'))
        self.assertEqual(len(marked), 3)
        self.assertTrue(all(note.n_conflict for note in marked))

        with self.assertRaises(NoteDuplicateError) as caught:
            list(section.iter_notes(duplicate_policy='reject'))
        error = caught.exception
        self.assertEqual(error.category, 'duplicate_note_type')
        self.assertEqual(error.offset, notes[1].n_offset)

    def test_cross_section_bytes_are_not_parsed_as_another_note(self):
        first = _build_note(desc=b'\x01\x02', note_type=3)
        second = _build_note(desc=b'\x03\x04', note_type=3)
        section = _note_section(first)
        # Append a syntactically valid note after the section's declared end.
        section.elffile.stream.seek(0, 2)
        section.elffile.stream.write(second)
        section.elffile.stream.seek(0)
        notes = list(section.iter_notes())
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0].n_desc, '0102')
        self.assertEqual(notes[0].n_end_offset,
                         section['sh_offset'] + section['sh_size'])

    def test_valid_64bit_core_sample_keeps_known_fields(self):
        with ELFFile.load_from_path(os.path.join(
                'test', 'testfiles_for_unittests', 'core_linux64.elf')) as elf:
            seen_prpsinfo = False
            seen_prstatus = False
            for segment in elf.iter_segments():
                if not isinstance(segment, NoteSegment):
                    continue
                start = segment['p_offset']
                end = start + segment['p_filesz']
                for note in segment.iter_notes():
                    self.assertEqual(note.n_source_type, 'segment')
                    self.assertGreaterEqual(note.n_raw_offset, start)
                    self.assertLessEqual(note.n_end_offset, end)
                    self.assertEqual(
                        note.n_segment_offset, note.n_offset - start)
                    self.assertEqual(
                        note.n_vaddr,
                        segment['p_vaddr'] + note.n_segment_offset)
                    if note.n_type == 'NT_PRPSINFO':
                        seen_prpsinfo = True
                        desc = note.n_desc
                        self.assertEqual(desc['pr_pid'], 23395)
                        self.assertEqual(
                            desc['pr_fname'], b'coredump_self\x00\x00\x00')
                    elif note.n_type == 'NT_PRSTATUS':
                        seen_prstatus = True
                        self.assertIsInstance(note.n_desc, bytes)
                        self.assertEqual(note.n_desc, note.n_descdata)
            self.assertTrue(seen_prpsinfo)
            self.assertTrue(seen_prstatus)

#------------------------------------------------------------------------------
# elftools tests
#
# This code is in the public domain
#------------------------------------------------------------------------------
""" Firmware archive review: tracing a note's public identifier back to the
    original short material it was archived from.

    A firmware component may carry several SHT_NOTE sections whose notes share
    the same owner name (the note's public identifier).  The owner name alone
    therefore cannot identify a record; its identity is only meaningful in
    combination with the scope that owns it (its note section/segment).  These
    tests build two minimal, harmless ELF images purely from fixed in-memory
    structures -- a canonical sample holding two same-named notes and a
    reordered sample in which the note payloads are written to the file in the
    opposite order -- and assert that swapping the write order does not
    attribute one note's material to the other note's source.

    Interface limitation kept on record (not worked around): the note
    containers yielded by NoteSection.iter_notes()/NoteSegment.iter_notes()
    expose n_offset/n_size within the file but carry no back-reference to the
    section or segment they were read from, so pyelftools offers no direct
    evidence linking a yielded note to its owning scope.  The provenance link
    asserted here is established by the caller, by iterating notes per scope.
"""
import io
import struct
import unittest

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection


SHT_NOTE = 7
NOTE_OWNER = b'ACME\x00'
BOOT_DESC = b'BOOT-2026-0001'
APP_DESC = b'APP-2026-0002'
BOOT_SECTION = '.note.fw_boot'
APP_SECTION = '.note.fw_app'


def _pad4(data):
    return data + b'\x00' * (-len(data) % 4)


def _note_blob(desc):
    """ A single note: Elf_Nhdr followed by the 4-byte aligned owner name and
        descriptor (the archived short material).
    """
    return (struct.pack('<III', len(NOTE_OWNER), len(desc), 1)
            + _pad4(NOTE_OWNER) + _pad4(desc))


def _build_firmware_elf(swap_note_data=False):
    """ A minimal 64-bit little-endian ET_REL image with two SHT_NOTE
        sections, each holding one note owned by NOTE_OWNER.

        When swap_note_data is True the two note payloads are written to the
        file in the opposite order, while the section headers keep their
        original order and still point at their own payload.
    """
    blobs = {
        BOOT_SECTION: _note_blob(BOOT_DESC),
        APP_SECTION: _note_blob(APP_DESC),
    }
    # File placement order of the payloads; the section header order is fixed.
    placement_order = [BOOT_SECTION, APP_SECTION]
    if swap_note_data:
        placement_order.reverse()

    data = struct.pack(
        '<16sHHIQQQIHHHHHH',
        b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 8,  # e_ident: ELF64, LE
        1,      # e_type: ET_REL
        0,      # e_machine: EM_NONE
        1,      # e_version
        0,      # e_entry
        0,      # e_phoff: no program headers
        0,      # e_shoff: patched below
        0,      # e_flags
        64,     # e_ehsize
        0,      # e_phentsize
        0,      # e_phnum
        64,     # e_shentsize
        4,      # e_shnum
        3,      # e_shstrndx
    )

    offsets = {}
    for section_name in placement_order:
        data += b'\x00' * (-len(data) % 4)
        offsets[section_name] = len(data)
        data += blobs[section_name]

    shstrtab = (b'\x00' + BOOT_SECTION.encode() + b'\x00'
                + APP_SECTION.encode() + b'\x00' + b'.shstrtab\x00')
    name_offsets = {
        BOOT_SECTION: 1,
        APP_SECTION: 1 + len(BOOT_SECTION) + 1,
        '.shstrtab': 1 + len(BOOT_SECTION) + 1 + len(APP_SECTION) + 1,
    }
    data += b'\x00' * (-len(data) % 4)
    shstrtab_offset = len(data)
    data += shstrtab

    data += b'\x00' * (-len(data) % 8)
    shoff = len(data)

    def shdr(sh_name, sh_type, sh_offset, sh_size):
        return struct.pack(
            '<IIQQQQIIQQ',
            sh_name, sh_type,
            0,          # sh_flags
            0,          # sh_addr
            sh_offset, sh_size,
            0,          # sh_link
            0,          # sh_info
            4,          # sh_addralign
            0,          # sh_entsize
        )

    data += b'\x00' * 64  # null section header
    for section_name in (BOOT_SECTION, APP_SECTION):
        data += shdr(name_offsets[section_name], SHT_NOTE,
                     offsets[section_name], len(blobs[section_name]))
    data += shdr(name_offsets['.shstrtab'], 3,  # SHT_STRTAB
                 shstrtab_offset, len(shstrtab))

    # Patch e_shoff (at offset 40 in the ELF64 header) now that the section
    # header table location is known.
    return data[:40] + struct.pack('<Q', shoff) + data[48:]


class TestNoteProvenance(unittest.TestCase):
    def _notes_by_section(self, elf):
        """ Map each note section name to its single note, establishing the
            note -> owning scope link at iteration time (see module docstring:
            the yielded note itself does not record its scope).
        """
        notes_by_section = {}
        for section in elf.iter_sections():
            if isinstance(section, NoteSection):
                notes = list(section.iter_notes())
                self.assertEqual(len(notes), 1)
                notes_by_section[section.name] = notes[0]
        self.assertEqual(set(notes_by_section), {BOOT_SECTION, APP_SECTION})
        return notes_by_section

    def test_note_identity_is_scoped_not_ordered(self):
        canonical = self._notes_by_section(
            ELFFile(io.BytesIO(_build_firmware_elf())))
        reordered = self._notes_by_section(
            ELFFile(io.BytesIO(_build_firmware_elf(swap_note_data=True))))

        # Both notes carry the same public identifier (owner name), so the
        # name alone cannot distinguish the two records.
        self.assertEqual(canonical[BOOT_SECTION]['n_name'],
                         canonical[APP_SECTION]['n_name'])

        # Each note's descriptor traces back to the short material archived
        # in its own section.
        self.assertEqual(canonical[BOOT_SECTION]['n_desc'], BOOT_DESC)
        self.assertEqual(canonical[APP_SECTION]['n_desc'], APP_DESC)

        # Swapping the write order of the payloads must not reattribute one
        # note's material to the other note's source.
        self.assertEqual(reordered[BOOT_SECTION]['n_desc'], BOOT_DESC)
        self.assertEqual(reordered[APP_SECTION]['n_desc'], APP_DESC)

        # In the reordered file the payload of the second section physically
        # precedes the payload of the first section, so file order (or
        # n_offset) alone would misattribute the records; only the identity
        # combined with the owning scope stays stable.
        self.assertLess(reordered[APP_SECTION]['n_offset'],
                        reordered[BOOT_SECTION]['n_offset'])
        self.assertNotEqual(canonical[BOOT_SECTION]['n_offset'],
                            reordered[BOOT_SECTION]['n_offset'])


if __name__ == '__main__':
    unittest.main()

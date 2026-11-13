import os
import unittest
from io import BytesIO
from unittest.mock import Mock

from elftools.common.exceptions import ELFRelocationError
from elftools.construct import Container
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import Relocation, RelocationHandler
from elftools.elf.sections import SymbolTableSection
from elftools.elf.structs import ELFStructs


class TestRelocation(unittest.TestCase):
    def _make_handler(self, arch):
        elf = Mock(spec=ELFFile)
        elf.get_machine_arch.return_value = arch
        elf.structs = ELFStructs(little_endian=True, elfclass=64)
        elf.structs.create_basic_structs()
        symtab = Mock(spec=SymbolTableSection)
        symtab.num_symbols.return_value = 1
        symtab.get_symbol.return_value = {'st_value': 0x100}
        return RelocationHandler(elf), symtab

    def test_find_relocations_duplicate_names(self):
        # Issue #564: verify relocation lookup for duplicate section names.
        # This does not test loading all of them through get_dwarf_info(),
        # which still selects only one DWARF section per name.
        path = os.path.join('test', 'testfiles_for_unittests', 'gmtime_r.o.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            handler = RelocationHandler(elf)
            for name in ('.debug_info', '.debug_line'):
                sections = [(i, s) for i, s in enumerate(elf.iter_sections()) if s.name == name]
                self.assertGreater(len(sections), 1)
                relocated = 0
                for index, section in sections:
                    with self.subTest(name=name, section=index):
                        relocation = handler.find_relocations_for_section(section)
                        if relocation is not None:
                            # The returned relocation must target this particular
                            # section, not another section with the same name.
                            self.assertEqual(relocation['sh_info'], index)
                            relocated += 1
                # Every .debug_info has relocations, but only one .debug_line
                # does; lookup must return None for the remaining line sections.
                self.assertEqual(relocated, len(sections) if name == '.debug_info' else 1)

    def test_find_relocations_rela(self):
        path = os.path.join('test', 'testfiles_for_unittests', 'sample_exe64.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            handler = RelocationHandler(elf)
            self.assertEqual(
                handler.find_relocations_for_section(elf.get_section_by_name('.plt')),
                elf.get_section_by_name('.rela.plt'))
            # .rela.dyn has sh_info == 0, which does not target the null section.
            self.assertIsNone(handler.find_relocations_for_section(elf.get_section(0)))

    def test_none_relocations(self):
        # Exercise every supported architecture, including both AArch64 codes
        # and both REL and RELA. NONE must ignore its symbol, offset and addend.
        cases = (
            ('x86', 0), ('x64', 0), ('MIPS', 0), ('ARM', 0),
            ('AArch64', 0), ('AArch64', 256), ('64-bit PowerPC', 0),
            ('IBM S/390', 0), ('Linux BPF - in-kernel virtual machine', 0),
            ('LoongArch', 0), ('RISC-V', 0),
        )
        targets = (
            (b'', 0, 0),
            (b'x\0', 0, 0),
            (b'abcdefgh', 0, 0),
            (b'x\0', 100, 100),
        )
        for arch, reloc_type in cases:
            for is_rela in (False, True):
                for data, offset, symbol in targets:
                    with self.subTest(arch=arch, type=reloc_type, rela=is_rela,
                                      data=data, offset=offset, symbol=symbol):
                        handler, symtab = self._make_handler(arch)
                        target = BytesIO(data)
                        stream = Mock(wraps=target)
                        entry = Container(r_info_type=reloc_type,
                                          r_info_sym=symbol, r_offset=offset)
                        if is_rela:
                            entry['r_addend'] = 123
                        reloc = Relocation(entry, handler.elffile)
                        handler._do_apply_relocation(stream, reloc, symtab)
                        self.assertEqual(stream.mock_calls, [])
                        self.assertEqual(symtab.mock_calls, [])
                        self.assertEqual(target.getvalue(), data)

    def test_non_none_relocation(self):
        handler, symtab = self._make_handler('x64')
        # R_X86_64_32 still resolves its symbol and writes S + A at r_offset.
        reloc = Relocation(Container(r_info_type=10, r_info_sym=0,
                                     r_offset=1, r_addend=0x23), handler.elffile)
        stream = BytesIO(b'\xaa\0\0\0\0\xbb')
        handler._do_apply_relocation(stream, reloc, symtab)
        self.assertEqual(stream.getvalue(), b'\xaa\x23\x01\0\0\xbb')
        symtab.get_symbol.assert_called_once_with(0)

    def test_unsupported_relocations(self):
        # A no-op code on one architecture must not be skipped on another.
        for arch, reloc_type in (('x64', 256), ('AArch64', 9999), ('<unknown>', 0)):
            with self.subTest(arch=arch, type=reloc_type):
                handler, symtab = self._make_handler(arch)
                reloc = Relocation(Container(r_info_type=reloc_type, r_info_sym=0,
                                             r_offset=0, r_addend=0), handler.elffile)
                with self.assertRaisesRegex(ELFRelocationError, 'Unsupported relocation type') as error:
                    handler._do_apply_relocation(BytesIO(), reloc, symtab)
                self.assertIn(f'type: {reloc_type}', str(error.exception))
                self.assertIn(f'for {arch}', str(error.exception))

    def test_unsupported_dynamic_relocation(self):
        # Issue #143: applying .rela.dyn requires dynamic-linker functionality
        # that the section relocation handler does not provide.
        path = os.path.join('test', 'testfiles_for_unittests', 'sample_exe64.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            data = elf.get_section_by_name('.got').data()
            stream = BytesIO(data)
            relocs = elf.get_section_by_name('.rela.dyn')
            with self.assertRaisesRegex(
                    ELFRelocationError,
                    r'Unsupported relocation type: 6 \(R_X86_64_GLOB_DAT\) for x64'):
                RelocationHandler(elf).apply_section_relocations(stream, relocs)
            self.assertEqual(stream.getvalue(), data)

    def test_mips_composed_relocation_is_not_none(self):
        # MIPS64 has up to three operations in a single relocation entry.
        for type2, type3 in ((2, 0), (0, 2)):
            with self.subTest(type2=type2, type3=type3):
                handler, symtab = self._make_handler('MIPS')
                reloc = Relocation(Container(r_info_type=0, r_type2=type2,
                                             r_type3=type3, r_info_sym=0,
                                             r_offset=0, r_addend=0), handler.elffile)
                with self.assertRaisesRegex(ELFRelocationError, 'Unsupported relocation type'):
                    handler._do_apply_relocation(BytesIO(b'\0' * 4), reloc, symtab)

    def test_tls_offsets_in_debug_info(self):
        # The location of a thread-local variable in the debug info of an
        # object file is its offset in its TLS section. The offsets are the
        # ones objdump --dwarf=info shows.
        test_dir = os.path.join('test', 'testfiles_for_unittests')
        for filename, offsets in (
            ('tls_relocs_x64_gcc.o', {'first': 4, 'second': 0, 'buffer': 0}),
            ('tls_relocs_x64_clang.o', {'first': 0, 'second': 4, 'buffer': 0}),
            ('tls_relocs_i386_gcc.o', {'first': 4, 'second': 0, 'buffer': 0}),
        ):
            with (self.subTest(filename=filename),
                  open(os.path.join(test_dir, filename), 'rb') as f):
                dwarfinfo = ELFFile(f).get_dwarf_info()
                locations = {}
                for cu in dwarfinfo.iter_CUs():
                    parser = DWARFExprParser(cu.structs)
                    for die in cu.iter_DIEs():
                        if die.tag == 'DW_TAG_variable':
                            expr = parser.parse_expr(die.attributes['DW_AT_location'].value)
                            locations[die.attributes['DW_AT_name'].value.decode()] = expr[0].args[0]
                self.assertEqual(locations, offsets)

    def test_dynamic_segment(self):
        """Verify that we can process relocations on the PT_DYNAMIC segment without section headers"""

        test_dir = os.path.join('test', 'testfiles_for_unittests')
        with open(os.path.join(test_dir, 'x64_bad_sections.elf'), 'rb') as f:
            elff = ELFFile(f)

            for seg in elff.iter_segments():
                if isinstance(seg, DynamicSegment):
                    relos = seg.get_relocation_tables()
                    self.assertEqual(set(relos), {'JMPREL', 'RELA'})

    def test_dynamic_section(self):
        """Verify that we can parse relocations from the .dynamic section"""

        test_dir = os.path.join('test', 'testfiles_for_unittests')
        with open(os.path.join(test_dir, 'sample_exe64.elf'), 'rb') as f:
            elff = ELFFile(f)

            for sect in elff.iter_sections():
                if isinstance(sect, DynamicSection):
                    relos = sect.get_relocation_tables()
                    self.assertEqual(set(relos), {'JMPREL', 'RELA'})

    def test_dynamic_section_solaris(self):
        """Verify that we can parse relocations from the .dynamic section"""

        test_dir = os.path.join('test', 'testfiles_for_unittests')
        with open(os.path.join(test_dir, 'exe_solaris32_cc.elf'), 'rb') as f:
            elff = ELFFile(f)

            for sect in elff.iter_sections():
                if isinstance(sect, DynamicSection):
                    relos = sect.get_relocation_tables()
                    self.assertEqual(set(relos), {'JMPREL', 'REL'})

    def test_rel_and_rela_traces(self):
        cases = (
            ('gmtime_r.o.elf', '.rel.debug_line'),
            ('tls_relocs_x64_gcc.o', '.rela.debug_line'),
        )
        test_dir = os.path.join('test', 'testfiles_for_unittests')
        for filename, section_name in cases:
            with (self.subTest(filename=filename, section=section_name),
                  open(os.path.join(test_dir, filename), 'rb') as f):
                elf = ELFFile(f)
                reloc_section = elf.get_section_by_name(section_name)
                target = elf.get_section(reloc_section['sh_info'])
                first = reloc_section.get_relocation(0)
                handler = RelocationHandler(elf)
                stream = BytesIO(target.data())
                handler.apply_section_relocations(stream, reloc_section)

                self.assertEqual(handler.diagnostics, [])
                trace = handler.traces[0]
                self.assertEqual(trace['target_section'], target)
                self.assertEqual(trace['target_section_index'],
                                 reloc_section['sh_info'])
                self.assertEqual(trace['target_offset'], first['r_offset'])
                self.assertEqual(
                    trace['target_file_offset'],
                    target['sh_offset'] + first['r_offset'])
                self.assertEqual(trace['entry_offset'],
                                 reloc_section['sh_offset'])
                self.assertEqual(
                    trace['relocation_section_index'],
                    elf.get_section_index(section_name))
                self.assertEqual(trace['symbol_table_index'],
                                 reloc_section['sh_link'])

    def test_relocation_version_provenance(self):
        path = os.path.join('test', 'testfiles_for_unittests',
                            'lib_versioned64.so.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            dynsym = elf.get_section_by_name('.dynsym')
            handler = RelocationHandler(elf)
            reloc = Relocation(
                Container(r_info_type=1, r_info_sym=3,
                          r_offset=0, r_addend=0), elf)
            handler._do_apply_relocation(
                BytesIO(b'\0' * 8), reloc, dynsym,
                symbol_table_index=elf.get_section_index('.dynsym'),
                diagnose=True)

        trace = handler.traces[-1]
        self.assertEqual(trace['symbol_name'], 'puts')
        self.assertEqual(trace['version']['name'], 'GLIBC_2.2.5')
        self.assertEqual(trace['version']['filename'], 'libc.so.6')
        self.assertEqual(trace['version_source']['kind'], 'verneed')
        self.assertEqual(trace['version_source']['filename'], 'libc.so.6')
        self.assertEqual(trace['version_source']['hash'], 157882997)
        self.assertEqual(handler.diagnostics, [])

    def test_relocation_symbol_table_mismatch(self):
        path = os.path.join('test', 'testfiles_for_unittests',
                            'lib_versioned64.so.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name('.symtab')
            handler = RelocationHandler(elf)
            reloc = Relocation(
                Container(r_info_type=1, r_info_sym=3,
                          r_offset=0, r_addend=0), elf)
            handler._do_apply_relocation(
                BytesIO(b'\0' * 8), reloc, symtab,
                symbol_table_index=elf.get_section_index('.symtab'),
                diagnose=True)

        trace = handler.traces[-1]
        # The same relocation index means 'puts' in .dynsym but a different
        # object in .symtab. Version provenance must not silently come from
        # the unrelated .gnu.version table.
        self.assertIsNone(trace['version'])
        codes = {diagnostic['code'] for diagnostic in handler.diagnostics}
        self.assertIn('relocation-symbol-not-in-version-table', codes)
        self.assertIn('relocation-symbol-table-mismatch', codes)

    def test_invalid_relocation_symbol_can_be_skipped(self):
        handler, symtab = self._make_handler('x64')
        reloc = Relocation(
            Container(r_info_type=10, r_info_sym=2,
                      r_offset=0, r_addend=0), handler.elffile)
        stream = BytesIO(b'\xaa' * 8)
        handler._do_apply_relocation(
            stream, reloc, symtab, strict=False)

        self.assertEqual(stream.getvalue(), b'\xaa' * 8)
        self.assertEqual(handler.diagnostics[0]['code'],
                         'relocation-symbol-not-in-table')
        self.assertEqual(handler.diagnostics[0]['symbol_index'], 2)
        self.assertEqual(handler.traces[0]['symbol_index'], 2)
        self.assertIsNone(handler.traces[0]['symbol'])

    def test_out_of_range_target_offset_is_diagnosed(self):
        path = os.path.join('test', 'testfiles_for_unittests',
                            'gmtime_r.o.elf')
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            reloc_section = elf.get_section_by_name('.rel.debug_line')
            target = elf.get_section(reloc_section['sh_info'])
            target_data = target.data()
            symtab = elf.get_section(reloc_section['sh_link'])
            original = reloc_section.get_relocation(0)
            reloc = Relocation(
                Container(r_info_type=original['r_info_type'],
                          r_info_sym=original['r_info_sym'],
                          r_offset=target.data_size), elf)
            handler = RelocationHandler(elf)
            stream = BytesIO(target_data)
            handler._do_apply_relocation(
                stream, reloc, symtab,
                target_section=target,
                relocation_section=reloc_section,
                symbol_table_index=reloc_section['sh_link'],
                diagnose=True, strict=False)

        self.assertEqual(stream.getvalue(), target_data)
        diagnostic = handler.diagnostics[0]
        self.assertEqual(diagnostic['code'],
                         'relocation-offset-out-of-range')
        self.assertEqual(diagnostic['reason'],
                         'relocation target outside target section')

if __name__ == '__main__':
    unittest.main()

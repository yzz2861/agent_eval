#------------------------------------------------------------------------------
# elftools tests
#
# Yann Rouillard (yann@pleiades.fr.eu.org)
# This code is in the public domain
#------------------------------------------------------------------------------
import os
import struct
import unittest
from io import BytesIO
from typing import ClassVar

from elftools.common.exceptions import ELFError
from elftools.common.utils import struct_parse
from elftools.elf.constants import VER_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import (
    GNUVerDefSection,
    GNUVerNeedSection,
    GNUVerSymSection,
)


class TestSymbolVersioning(unittest.TestCase):

    versym_reference_data: ClassVar = [
        {'name': '', 'ndx': 'VER_NDX_LOCAL'},
        {'name': '', 'ndx': 'VER_NDX_LOCAL'},
        {'name': '_ITM_deregisterTMCloneTable', 'ndx': 'VER_NDX_LOCAL'},
        {'name': 'puts', 'ndx': 5},
        {'name': 'strlcat', 'ndx': 'VER_NDX_LOCAL'},
        {'name': '__stack_chk_fail', 'ndx': 6},
        {'name': '__gmon_start__', 'ndx': 'VER_NDX_LOCAL'},
        {'name': 'gzoffset', 'ndx': 7},
        {'name': '_Jv_RegisterClasses', 'ndx': 'VER_NDX_LOCAL'},
        {'name': '_ITM_registerTMCloneTable', 'ndx': 'VER_NDX_LOCAL'},
        {'name': '__cxa_finalize', 'ndx': 5},
        {'name': '_edata', 'ndx': 'VER_NDX_GLOBAL'},
        {'name': 'VER_1.0', 'ndx': 2},
        {'name': 'function1_ver1_1', 'ndx': 'VER_NDX_GLOBAL'},
        {'name': '_end', 'ndx': 'VER_NDX_GLOBAL'},
        {'name': 'function1', 'ndx': 4 | 0x8000},
        {'name': '__bss_start', 'ndx': 'VER_NDX_GLOBAL'},
        {'name': 'function1', 'ndx': 2},
        {'name': 'VER_1.1', 'ndx': 3},
        {'name': '_init', 'ndx': 'VER_NDX_GLOBAL'},
        {'name': 'function1_ver1_0', 'ndx': 'VER_NDX_GLOBAL'},
        {'name': '_fini', 'ndx': 'VER_NDX_GLOBAL'},
        {'name': 'VER_1.2', 'ndx': 4},
        {'name': 'function2', 'ndx': 3},
    ]

    def test_versym_section(self):

        reference_data = TestSymbolVersioning.versym_reference_data

        with open(os.path.join('test', 'testfiles_for_unittests',
                               'lib_versioned64.so.elf'), 'rb') as f:
            elf = ELFFile(f)
            versym_section = None
            for section in elf.iter_sections():
                if isinstance(section, GNUVerSymSection):
                    versym_section = section
                    break

            self.assertIsNotNone(versym_section)

            for versym, ref_versym in zip(section.iter_symbols(),
                                                   reference_data):
                self.assertEqual(versym.name, ref_versym['name'])
                self.assertEqual(versym['ndx'], ref_versym['ndx'])

    def test_symbol_versions(self):
        with open(os.path.join('test', 'testfiles_for_unittests',
                               'lib_versioned64.so.elf'), 'rb') as f:
            elf = ELFFile(f)
            versym = elf.get_section_by_name('.gnu.version')
            self.assertTrue(versym.is_gnu)
            for n, index, name, filename, hidden in (
                    (0, 'VER_NDX_LOCAL', None, None, False),
                    (11, 'VER_NDX_GLOBAL', None, None, False),
                    (3, 5, 'GLIBC_2.2.5', 'libc.so.6', False),
                    (5, 6, 'GLIBC_2.4', 'libc.so.6', False),
                    (7, 7, 'ZLIB_1.2.3.5', 'libz.so.1', False),
                    (15, 4, 'VER_1.2', None, True),
                    (17, 2, 'VER_1.0', None, False),
                    (23, 3, 'VER_1.1', None, False)):
                with self.subTest(symbol=n):
                    self.assertEqual(versym.get_symbol_version(n), {
                        'index': index, 'name': name,
                        'filename': filename, 'hidden': hidden})
            self.assertIsNone(versym.get_symbol_version(-1))
            self.assertIsNone(versym.get_symbol_version(versym.num_symbols()))

    def test_sparse_version_indices(self):
        with open(os.path.join('test', 'testfiles_for_unittests',
                               'lib_versioned64.so.elf'), 'rb') as f:
            stream = BytesIO(f.read())
        elf = ELFFile(stream)
        verdef = elf.get_section_by_name('.gnu.version_d')
        versym = elf.get_section_by_name('.gnu.version')

        # Move definition 4 to index 42 without increasing the definition count.
        offset = verdef['sh_offset']
        for version, _ in verdef.iter_versions():
            if version['vd_ndx'] == 4:
                stream.seek(offset + 4)  # Elf_Verdef.vd_ndx
                stream.write(struct.pack('<H', 42))
                break
            offset += version['vd_next']
        stream.seek(versym['sh_offset'] + 15 * versym['sh_entsize'])
        stream.write(struct.pack('<H', 42 | 0x8000))

        self.assertEqual(versym.get_symbol_version(15), {
            'index': 42, 'name': 'VER_1.2', 'filename': None, 'hidden': True})

    def test_solaris_symbol_versions(self):
        with open(os.path.join('test', 'testfiles_for_unittests',
                               'exe_solaris32_cc.elf'), 'rb') as f:
            elf = ELFFile(f)
            versym = elf.get_section_by_name('.SUNW_versym')
            self.assertFalse(versym.is_gnu)
            self.assertEqual(versym.get_symbol_version(1), {
                'index': 'VER_NDX_GLOBAL', 'name': None,
                'filename': None, 'hidden': False})
            self.assertEqual(versym.get_symbol_version(15), {
                'index': 2, 'name': 'SYSVABI_1.3',
                'filename': 'libc.so.1', 'hidden': False})

    def _versioned_bytes(self) -> bytearray:
        path = os.path.join('test', 'testfiles_for_unittests',
                            'lib_versioned64.so.elf')
        with open(path, 'rb') as f:
            return bytearray(f.read())

    def _load_versioned(self, data: bytearray | None = None) -> ELFFile:
        return ELFFile(BytesIO(self._versioned_bytes() if data is None else data))

    def test_legal_sample_has_no_diagnostics(self):
        elf = self._load_versioned()
        for section in elf.iter_sections():
            if isinstance(section, (GNUVerDefSection, GNUVerNeedSection,
                                    GNUVerSymSection)):
                with self.subTest(section=section.name):
                    self.assertEqual(section.diagnostics, [])

    def test_out_of_range_versym_index(self):
        data = self._versioned_bytes()
        elf = ELFFile(BytesIO(data))
        versym = elf.get_section_by_name('.gnu.version')
        offset = versym['sh_offset'] + 17 * versym['sh_entsize']
        struct.pack_into('<H', data, offset, 42)

        elf = ELFFile(BytesIO(data))
        versym = elf.get_section_by_name('.gnu.version')
        info = versym.get_symbol_version_info(17)
        self.assertEqual(info['symbol_name'], 'function1')
        self.assertEqual(info['index'], 42)
        self.assertIsNone(info['version'])
        self.assertEqual(info['diagnostics'][0]['code'],
                         'versym-index-out-of-range')
        self.assertEqual(info['diagnostics'][0]['offset'], offset)
        self.assertEqual(info['diagnostics'][0]['symbol_index'], 17)
        with self.assertRaises(ELFError):
            versym.get_symbol_version(17)

    def test_hidden_bit_conflicts_with_requirement(self):
        data = self._versioned_bytes()
        elf = ELFFile(BytesIO(data))
        versym = elf.get_section_by_name('.gnu.version')
        # puts is undefined and gets its version from libc.so.6; silently
        # hiding that requirement changes the visible symbol contract.
        offset = versym['sh_offset'] + 3 * versym['sh_entsize']
        struct.pack_into('<H', data, offset, 5 | 0x8000)

        elf = ELFFile(BytesIO(data))
        versym = elf.get_section_by_name('.gnu.version')
        info = versym.get_symbol_version_info(3)
        self.assertEqual(info['symbol_name'], 'puts')
        self.assertTrue(info['hidden'])
        self.assertEqual(info['version']['name'], 'GLIBC_2.2.5')
        codes = {diagnostic['code'] for diagnostic in info['diagnostics']}
        self.assertIn('versym-hidden-undefined-symbol', codes)
        self.assertIn('versym-hidden-requirement', codes)

    def test_duplicate_version_name(self):
        data = self._versioned_bytes()
        elf = ELFFile(BytesIO(data))
        verdef = elf.get_section_by_name('.gnu.version_d')
        records = verdef.version_records
        definition_2 = next(record for record in records
                            if record['index'] == 2)
        definition_4 = next(record for record in records
                            if record['index'] == 4)
        name_2 = struct_parse(
            elf.structs.Elf_Verdaux, verdef.stream,
            stream_pos=definition_2['auxiliary_offset'])['vda_name']
        struct.pack_into('<I', data, definition_4['auxiliary_offset'], name_2)

        elf = ELFFile(BytesIO(data))
        verdef = elf.get_section_by_name('.gnu.version_d')
        diagnostics = verdef.diagnostics
        self.assertEqual(
            [diagnostic['code'] for diagnostic in diagnostics
             if diagnostic['code'] == 'duplicate-version-name'],
            ['duplicate-version-name'])
        duplicate = diagnostics[0]
        self.assertEqual(duplicate['version_index'], 4)
        self.assertEqual(duplicate['name'], 'VER_1.0')
        self.assertEqual(duplicate['offset'], definition_4['offset'])

    def test_verdef_verneed_conflict(self):
        data = self._versioned_bytes()
        elf = ELFFile(BytesIO(data))
        verneed = elf.get_section_by_name('.gnu.version_r')
        record_5 = next(record for record in verneed.version_records
                        if record['index'] == 5)
        # vna_other follows vna_hash(4), vna_flags(2).
        struct.pack_into('<H', data, record_5['auxiliary_offset'] + 6, 2)
        versym = elf.get_section_by_name('.gnu.version')
        struct.pack_into('<H', data,
                         versym['sh_offset'] + 3 * versym['sh_entsize'], 2)

        elf = ELFFile(BytesIO(data))
        versym = elf.get_section_by_name('.gnu.version')
        info = versym.get_symbol_version_info(3)
        self.assertEqual(info['symbol_name'], 'puts')
        self.assertEqual({source['kind'] for source in info['sources']},
                         {'verdef', 'verneed'})
        codes = {diagnostic['code'] for diagnostic in info['diagnostics']}
        self.assertIn('verdef-verneed-index-conflict', codes)
        self.assertIn('verdef-verneed-name-conflict', codes)

    def test_version_records_expose_hash_and_chain(self):
        elf = self._load_versioned()
        verdef = elf.get_section_by_name('.gnu.version_d')
        record = next(record for record in verdef.version_records
                      if record['index'] == 3)
        self.assertEqual(record['name'], 'VER_1.1')
        self.assertEqual(record['hash'], 0xaa82441)
        self.assertEqual(record['dependency_names'], ['VER_1.1', 'VER_1.0'])
        self.assertGreater(record['auxiliary_offset'], record['offset'])

    def test_corrupt_auxiliary_chain_is_skipped_with_reason(self):
        data = self._versioned_bytes()
        elf = ELFFile(BytesIO(data))
        verdef = elf.get_section_by_name('.gnu.version_d')
        record = next(record for record in verdef.version_records
                      if record['index'] == 3)
        # vda_name(4) is followed by vda_next(4). Declared count is 2, so a
        # zero link truncates the chain but must not abort the whole table.
        struct.pack_into('<I', data, record['auxiliary_offset'] + 4, 0)

        elf = ELFFile(BytesIO(data))
        verdef = elf.get_section_by_name('.gnu.version_d')
        diagnostics = verdef.diagnostics
        truncated = next(
            diagnostic for diagnostic in diagnostics
            if diagnostic['code'] == 'truncated-version-auxiliary-chain')
        self.assertEqual(truncated['offset'], record['auxiliary_offset'])
        self.assertIn('reason', truncated)
        self.assertEqual(verdef.version_records_by_index[3][0]['name'],
                         'VER_1.1')

    verneed_reference_data: ClassVar = [
        {'name': 'libz.so.1', 'vn_version': 1, 'vn_cnt': 1,
         'vernaux': [
            {'name': 'ZLIB_1.2.3.5', 'vna_flags': 0, 'vna_other': 7}]},
        {'name': 'libc.so.6', 'vn_version': 1, 'vn_cnt': 2,
         'vernaux': [
            {'name': 'GLIBC_2.4', 'vna_flags': 0, 'vna_other': 6},
            {'name': 'GLIBC_2.2.5', 'vna_flags': 0, 'vna_other': 5}]},
        ]

    def test_verneed_section(self):

        reference_data = TestSymbolVersioning.verneed_reference_data

        with open(os.path.join('test', 'testfiles_for_unittests',
                               'lib_versioned64.so.elf'), 'rb') as f:
            elf = ELFFile(f)
            verneed_section = None
            for section in elf.iter_sections():
                if isinstance(section, GNUVerNeedSection):
                    verneed_section = section
                    break

            self.assertIsNotNone(verneed_section)

            for (verneed, vernaux_iter), ref_verneed in zip(
                    section.iter_versions(), reference_data):

                self.assertEqual(verneed.name, ref_verneed['name'])
                self.assertEqual(verneed['vn_cnt'], ref_verneed['vn_cnt'])
                self.assertEqual(verneed['vn_version'],
                                 ref_verneed['vn_version'])

                for vernaux, ref_vernaux in zip(
                        vernaux_iter, ref_verneed['vernaux']):

                    self.assertEqual(vernaux.name, ref_vernaux['name'])
                    self.assertEqual(vernaux['vna_flags'],
                                     ref_vernaux['vna_flags'])
                    self.assertEqual(vernaux['vna_other'],
                                     ref_vernaux['vna_other'])

    verdef_reference_data: ClassVar = [
        {'vd_ndx': 1, 'vd_version': 1, 'vd_flags': VER_FLAGS.VER_FLG_BASE,
         'vd_cnt': 1,
         'verdaux': [
            {'name': 'lib_versioned.so.1'}]},
        {'vd_ndx': 2, 'vd_version': 1, 'vd_flags': 0, 'vd_cnt': 1,
         'verdaux': [
            {'name': 'VER_1.0'}]},
        {'vd_ndx': 3, 'vd_version': 1, 'vd_flags': 0, 'vd_cnt': 2,
         'verdaux': [
            {'name': 'VER_1.1'},
            {'name': 'VER_1.0'}]},
        {'vd_ndx': 4, 'vd_version': 1, 'vd_flags': 0, 'vd_cnt': 2,
         'verdaux': [
            {'name': 'VER_1.2'},
            {'name': 'VER_1.1'}]},
        ]

    def test_verdef_section(self):

        reference_data = TestSymbolVersioning.verdef_reference_data

        with open(os.path.join('test', 'testfiles_for_unittests',
                               'lib_versioned64.so.elf'), 'rb') as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if isinstance(section, GNUVerDefSection):
                    verdef_section = section
                    break

            self.assertIsNotNone(verdef_section)

            for (verdef, verdaux_iter), ref_verdef in zip(
                    section.iter_versions(), reference_data):

                self.assertEqual(verdef['vd_ndx'], ref_verdef['vd_ndx'])
                self.assertEqual(verdef['vd_version'],
                                 ref_verdef['vd_version'])
                self.assertEqual(verdef['vd_flags'], ref_verdef['vd_flags'])
                self.assertEqual(verdef['vd_cnt'], ref_verdef['vd_cnt'])

                for verdaux, ref_verdaux in zip(
                        verdaux_iter, ref_verdef['verdaux']):
                    self.assertEqual(verdaux.name, ref_verdaux['name'])


if __name__ == '__main__':
    unittest.main()

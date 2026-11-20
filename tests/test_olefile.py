"""
Tests for olefile
"""

from __future__ import print_function
import unittest

import os, sys
import io
import struct
import uuid
from shutil import copy2

# Insert the olefile package relative to this test dir in the sys.path
# to make sure we test the right one, in case another olefile version
# is also installed in the main python path.
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
# print('_thismodule_dir = %r' % _thismodule_dir)
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
# print('_parent_dir = %r' % _thirdparty_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile


class Test_isOleFile(unittest.TestCase):
    'Tests for the isOleFile function'

    def setUp(self):
        self.non_ole_file = u"tests/images/flower.jpg"
        self.ole_file = u"tests/images/test-ole-file.doc"

    def test_isOleFile_str_path_false(self):
        'Test isOleFile with a unicode filename of a non-OLE file'
        is_ole = olefile.isOleFile(filename=self.non_ole_file)
        self.assertFalse(is_ole)

    def test_isOleFile_str_path_true(self):
        'Test isOleFile with a unicode filename of an OLE file'
        is_ole = olefile.isOleFile(filename=self.ole_file)
        self.assertTrue(is_ole)

    def test_isOleFile_bytes_path_false(self):
        'Test isOleFile with a bytes filename of a non-OLE file'
        is_ole = olefile.isOleFile(filename=self.non_ole_file.encode('latin_1'))
        self.assertFalse(is_ole)

    def test_isOleFile_bytes_path_true(self):
        'Test isOleFile with a bytes filename of an OLE file'
        is_ole = olefile.isOleFile(filename=self.ole_file.encode('latin_1'))
        self.assertTrue(is_ole)

    def test_isOleFile_bytes_string_false(self):
        'Test isOleFile with contents of a non-OLE file in a bytes string as filename parameter'
        with open(self.non_ole_file, 'rb') as f:
            data = f.read()
        assert (len(data) >= olefile.MINIMAL_OLEFILE_SIZE)
        is_ole = olefile.isOleFile(filename=data)
        self.assertFalse(is_ole)

    def test_isOleFile_small_bytes_string_false(self):
        'Test isOleFile with contents of a small non-OLE file (<1536b) in a bytes string as filename parameter'
        data = b" " * 100
        # In this case, we expect a FileNotFoundError exception, because isOleFile treats filename as a path
        # due to issue #142
        if sys.version_info[0] < 3:
            # On Python 2.x, this case raises an IOError exception:
            expected_exception = IOError
        else:
            # On Python 3.x, this case raises a FileNotFoundError exception:
            expected_exception = FileNotFoundError
        with self.assertRaises(expected_exception):
            is_ole = olefile.isOleFile(filename=data)

    def test_isOleFile_bytes_string_true(self):
        'Test isOleFile with contents of an OLE file in a bytes string as filename parameter'
        with open(self.ole_file, 'rb') as f:
            data = f.read()
        assert(len(data) >= olefile.MINIMAL_OLEFILE_SIZE)
        is_ole = olefile.isOleFile(filename=data)
        self.assertTrue(is_ole)

    def test_isOleFile_bytes_data_false(self):
        'Test isOleFile with contents of a non-OLE file in a bytes string as data parameter'
        with open(self.non_ole_file, 'rb') as f:
            data = f.read()
        is_ole = olefile.isOleFile(data=data)
        self.assertFalse(is_ole)

    def test_isOleFile_bytes_data_true(self):
        'Test isOleFile with contents of an OLE file in a bytes string as data parameter'
        with open(self.ole_file, 'rb') as f:
            data = f.read()
        is_ole = olefile.isOleFile(data=data)
        self.assertTrue(is_ole)

    def test_isOleFile_small_bytes_data_false(self):
        'Test isOleFile with contents of a small non-OLE file (<1536b) in a bytes string as data parameter'
        data = b" " * 100
        is_ole = olefile.isOleFile(data=data)
        self.assertFalse(is_ole)

    def test_isOleFile_small_bytes_ole_magic_data_false(self):
        'Test isOleFile with contents of a small non-OLE file (<1536b) starting with OLE magic in a bytes string as data parameter'
        with open(self.ole_file, 'rb') as f:
            data = f.read(100)
        is_ole = olefile.isOleFile(data=data)
        self.assertFalse(is_ole)

    def test_isOleFile_file_false(self):
        'Test isOleFile with a non-OLE file object as filename parameter'
        with open(self.non_ole_file, 'rb') as f:
            is_ole = olefile.isOleFile(filename=f)
        self.assertFalse(is_ole)

    def test_isOleFile_file_true(self):
        'Test isOleFile with an OLE file object as filename parameter'
        with open(self.ole_file, 'rb') as f:
            is_ole = olefile.isOleFile(filename=f)
        self.assertTrue(is_ole)


class TestOleFileIO(unittest.TestCase):
    'Tests for the OleFileIO class'

    def setUp(self):
        self.non_ole_file = u"tests/images/flower.jpg"
        self.ole_file = u"tests/images/test-ole-file.doc"

    def test_context_manager(self):
        with olefile.OleFileIO(self.ole_file) as ole:
            exists = ole.exists('worddocument')
            self.assertTrue(exists)

    def test_exists_worddocument(self):
        ole = olefile.OleFileIO(self.ole_file)
        exists = ole.exists('worddocument')
        self.assertTrue(exists)
        ole.close()

    def test_exists_no_vba_macros(self):
        ole = olefile.OleFileIO(self.ole_file)
        exists = ole.exists('macros/vba')
        self.assertFalse(exists)
        ole.close()

    def test_get_type(self):
        ole = olefile.OleFileIO(self.ole_file)
        doc_type = ole.get_type('worddocument')
        self.assertEqual(doc_type, olefile.STGTY_STREAM)
        ole.close()

    def test_get_size(self):
        ole = olefile.OleFileIO(self.ole_file)
        size = ole.get_size('worddocument')
        self.assertGreater(size, 0)
        ole.close()

    def test_get_rootentry_name(self):
        ole = olefile.OleFileIO(self.ole_file)
        root = ole.get_rootentry_name()
        self.assertEqual(root, "Root Entry")
        ole.close()

    def test_meta(self):
        ole = olefile.OleFileIO(self.ole_file)
        meta = ole.get_metadata()
        self.assertEqual(meta.author, b"Laurence Ipsum")
        self.assertEqual(meta.num_pages, 1)
        ole.close()

    def test_minifat_writing(self):
        ole_file_copy = "tests/images/test-ole-file-copy.doc"
        minifat_stream_name = "\x01compobj"
        if os.path.isfile(ole_file_copy):
            os.remove(ole_file_copy)
        copy2(self.ole_file, ole_file_copy)

        ole = olefile.OleFileIO(ole_file_copy, write_mode = True)
        stream = ole.openstream(minifat_stream_name)
        self.assertTrue(stream.size < ole.minisectorcutoff)
        str_read = stream.read()
        self.assertTrue(len(str_read) == stream.size)
        self.assertTrue(str_read != b'\x00' * stream.size)
        stream.close()
        ole.write_stream(minifat_stream_name, b'\x00' * stream.size)
        ole.close()

        ole = olefile.OleFileIO(ole_file_copy)
        stream = ole.openstream(minifat_stream_name)
        self.assertTrue(stream.size < ole.minisectorcutoff)
        str_read_replaced = stream.read()
        self.assertTrue(len(str_read_replaced) == stream.size)
        self.assertTrue(str_read_replaced != str_read)
        self.assertTrue(str_read_replaced == b'\x00' * len(str_read))
        stream.close()
        ole.close()
        os.remove(ole_file_copy)

    def test_write_sect_too_large(self):
        'Test write_sect with data larger than a sector'
        # read OLE file in memory to avoid writing to disk
        with open(self.ole_file, 'rb') as f:
            file_in_memory = io.BytesIO(f.read())
        with olefile.OleFileIO(file_in_memory, write_mode=True) as ole:
            size = ole.sector_size + 1
            # Attempt to overwrite last sector (ole.nb_sect - 1) with data too large
            # it should raise ValueError:
            with self.assertRaises(ValueError):
                ole.write_sect(ole.nb_sect - 1, b"x" * size)


class FileHandleCloseTest(unittest.TestCase):
    """Test file handles are closed correctly."""

    def setUp(self):
        self.non_ole_file = "tests/images/flower.jpg"
        self.ole_file = "tests/images/test-ole-file.doc"

    def leaking_test_function(self):
        """Function that leaks an open OleFileIO."""
        ole = olefile.OleFileIO(self.ole_file)

    @unittest.skip('Cannot predict when __del__ is run, so cannot test that '
                   'it issues a warning')
    # requires python version 3.2 or higher
    def test_warning(self):
        """Test that warning is issued when ole file leaks open fp."""
        with self.assertWarns(olefile.OleFileIONotClosed):
            self.leaking_test_function()

    @unittest.skip('Cannot test attribute fp of OleFileIO instance that '
                   'failed to construct')
    def test_init_fail(self):
        """Test that file handle is closed if open() from __init__ fails."""
        ole = None
        try:
            ole = olefile.OleFileIO(self.non_ole_file)
            self.fail('Should have raised an exception')
        except Exception as exc:
            self.assertEqual(str(exc), 'not an OLE2 structured storage file')
            self.assertTrue(ole.fp.closed)   # ole is still None

    def test_context_manager(self):
        """Test that file handle is closed by context manager."""
        file_handle = None
        with olefile.OleFileIO(self.ole_file) as ole:
            file_handle = ole.fp
            self.assertFalse(file_handle.closed)
        self.assertTrue(file_handle.closed)

    def test_manual(self):
        """Test that simple manual close always closes self-created handle."""
        ole = olefile.OleFileIO(self.ole_file)
        self.assertFalse(ole.fp.closed)
        _ = ole.listdir()
        self.assertFalse(ole.fp.closed)
        ole.close()
        self.assertTrue(ole.fp.closed)

    # TODO: check if this test is still relevant
    # def test_fp_stays_open(self):
    #     """Test that fp is not automatically closed if provided by caller."""
    #     with open(self.ole_file, 'rb') as file_handle:
    #         self.assertFalse(file_handle.closed)
    #         with olefile.OleFileIO(file_handle) as ole:
    #             self.assertFalse(file_handle.closed)
    #             self.assertEqual(file_handle, ole.fp)
    #         # check that handle is still open, although ole is now closed
    #         self.assertFalse(file_handle.closed)
    #
    #         # do something with it
    #         file_handle.seek(0)
    #         self.assertTrue(olefile.isOleFile(file_handle))
    #
    #     # now should be closed
    #     self.assertTrue(file_handle.closed)


# --- helpers to build a minimal OLE file with two directory branches -------

_ENDOFCHAIN = 0xFFFFFFFE
_FREESECT = 0xFFFFFFFF
_FATSECT = 0xFFFFFFFD
_NOSTREAM = 0xFFFFFFFF
_SECTOR_SIZE = 512
# property streams are padded to the mini stream cutoff so that no MiniFAT
# is needed in the synthetic file:
_STREAM_SIZE = 4096

# FMTID of the SummaryInformation property set, see [MS-OLEPS] 2.18:
_SUMMARY_INFO_FMTID = uuid.UUID('f29f85e0-4ff9-1068-ab91-08002b27b3d9')


def _make_summary_stream(app_name):
    """Build a \\x05SummaryInformation stream declaring a creating application."""
    app = app_name.encode('latin_1')
    # property id 18 (creating_application), type VT_LPSTR (30):
    prop = struct.pack('<II', 30, len(app) + 1) + app + b'\x00'
    prop += b'\x00' * ((-len(prop)) % 4)
    section = struct.pack('<IIII', 16 + len(prop), 1, 18, 16) + prop
    header = (b'\xff\xfe'                # byte order
              + struct.pack('<HI', 0, 0)  # version, system identifier
              + b'\x00' * 16             # CLSID
              + struct.pack('<I', 1)     # one property set
              + _SUMMARY_INFO_FMTID.bytes_le
              + struct.pack('<I', 48))   # offset of the section
    data = header + section
    return data + b'\x00' * (_STREAM_SIZE - len(data))


def _make_direntry(name, entry_type, left, right, child, clsid_bytes,
                   start, size):
    """Build a 128-bytes OLE directory entry."""
    name_utf16 = name.encode('utf-16-le')
    name_buf = (name_utf16 + b'\x00\x00').ljust(64, b'\x00')
    return struct.pack('<64sHBBIII16sIQQIII', name_buf, len(name_utf16) + 2,
                       entry_type, 1, left, right, child, clsid_bytes,
                       0, 0, 0, start, size, 0)


def make_two_branch_ole(clsid_root, clsid_embedded, app_root, app_embedded):
    """
    Build a minimal OLE file (in memory) with two directory branches:

    - root storage, holding a \\x05SummaryInformation stream declaring
      app_root, plus WordDocument and 1Table streams
    - storage 'Embedded1', holding its own \\x05SummaryInformation stream
      declaring app_embedded, plus a Blob stream
    """
    stream_datas = [
        _make_summary_stream(app_root),      # sectors 0-7
        b'W' * _STREAM_SIZE,                 # WordDocument, sectors 8-15
        b'T' * _STREAM_SIZE,                 # 1Table, sectors 16-23
        _make_summary_stream(app_embedded),  # sectors 24-31
        b'B' * _STREAM_SIZE,                 # Blob, sectors 32-39
    ]
    entries = [
        _make_direntry('Root Entry', 5, _NOSTREAM, _NOSTREAM, 1,
                       clsid_root, _ENDOFCHAIN, 0),
        _make_direntry('\x05SummaryInformation', 2, _NOSTREAM, 2, _NOSTREAM,
                       b'\x00' * 16, 0, _STREAM_SIZE),
        _make_direntry('WordDocument', 2, _NOSTREAM, 3, _NOSTREAM,
                       b'\x00' * 16, 8, _STREAM_SIZE),
        _make_direntry('1Table', 2, _NOSTREAM, 4, _NOSTREAM,
                       b'\x00' * 16, 16, _STREAM_SIZE),
        _make_direntry('Embedded1', 1, _NOSTREAM, _NOSTREAM, 5,
                       clsid_embedded, 0, 0),
        _make_direntry('\x05SummaryInformation', 2, _NOSTREAM, 6, _NOSTREAM,
                       b'\x00' * 16, 24, _STREAM_SIZE),
        _make_direntry('Blob', 2, _NOSTREAM, _NOSTREAM, _NOSTREAM,
                       b'\x00' * 16, 32, _STREAM_SIZE),
    ]
    directory = b''.join(entries).ljust(2 * _SECTOR_SIZE, b'\x00')
    dir_start = len(stream_datas) * (_STREAM_SIZE // _SECTOR_SIZE)  # 40
    fat_start = dir_start + 2                                       # 42
    fat = [_FREESECT] * 128
    for first in (0, 8, 16, 24, 32):
        for sect in range(first, first + 7):
            fat[sect] = sect + 1
        fat[first + 7] = _ENDOFCHAIN
    fat[dir_start] = dir_start + 1
    fat[dir_start + 1] = _ENDOFCHAIN
    fat[fat_start] = _FATSECT
    header = struct.pack(
        '<8s16sHHHHH6sIIIIIIIII',
        olefile.MAGIC, b'\x00' * 16, 0x003E, 3, 0xFFFE, 9, 6, b'\x00' * 6,
        0,              # csectDir (0 for version 3)
        1,              # csectFat
        dir_start,      # sectDirStart
        0,              # transaction signature
        _STREAM_SIZE,   # mini stream cutoff
        _ENDOFCHAIN,    # sectMiniFatStart
        0,              # csectMiniFat
        _ENDOFCHAIN,    # sectDifStart
        0,              # csectDif
    )
    header += struct.pack('<109I', fat_start, *([_FREESECT] * 108))
    fat_sector = struct.pack('<128I', *fat)
    return header + b''.join(stream_datas) + directory + fat_sector


class Test_get_provenance(unittest.TestCase):
    'Tests for OleFileIO.get_provenance'

    CLSID_A = '11111111-2222-3333-4444-555555555555'
    CLSID_B = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
    APP_A = 'App A'

    def setUp(self):
        self.ole_data = make_two_branch_ole(
            clsid_root=uuid.UUID(self.CLSID_A).bytes_le,
            clsid_embedded=uuid.UUID(self.CLSID_B).bytes_le,
            app_root=self.APP_A,
            app_embedded=self.APP_A)
        self.known_identifiers = {
            self.CLSID_A: 'ProducerA',
            self.CLSID_B: 'ProducerB',
            self.APP_A: 'ProducerA',
        }
        self.layout_signatures = {
            'ProducerA': ['WordDocument', '1Table'],
            'ProducerB': ['BData'],
        }

    def test_fixture_is_valid_ole(self):
        'The synthetic two-branch file must be parseable by olefile'
        self.assertTrue(olefile.isOleFile(data=self.ole_data))
        ole = olefile.OleFileIO(self.ole_data)
        self.assertEqual(ole.listdir(streams=False, storages=True),
                         [['Embedded1']])
        self.assertEqual(ole.getclsid([]), self.CLSID_A)
        self.assertEqual(ole.getclsid(['Embedded1']), self.CLSID_B)
        ole.close()

    def test_two_branch_provenance(self):
        'One branch corroborated by layout, the other showing both claims'
        ole = olefile.OleFileIO(self.ole_data)
        records = ole.get_provenance(self.known_identifiers,
                                     self.layout_signatures)
        ole.close()
        # one provenance record per directory branch:
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].storage_path, ())
        self.assertEqual(records[1].storage_path, ('Embedded1',))

        # root branch: claims of producer A, corroborated by the
        # WordDocument/1Table stream layout:
        root = records[0]
        self.assertEqual(root.producers, ['ProducerA'])
        self.assertTrue(root.corroborated)
        self.assertTrue(all(claim.corroborated for claim in root.claims))
        self.assertTrue(all(claim.scope == () for claim in root.claims))

        # embedded branch: both declarations visible, the property claim
        # of producer A and the CLSID of producer B, none corroborated:
        embedded = records[1]
        self.assertEqual(embedded.producers, ['ProducerA', 'ProducerB'])
        self.assertFalse(embedded.corroborated)
        self.assertEqual(len(embedded.claims), 2)
        by_location = dict((claim.location, claim) for claim in embedded.claims)
        clsid_claim = by_location['directory entry CLSID']
        self.assertEqual(clsid_claim.declared, self.CLSID_B)
        self.assertEqual(clsid_claim.identified, 'ProducerB')
        self.assertEqual(clsid_claim.scope, ('Embedded1',))
        prop_claim = by_location['Embedded1/\x05SummaryInformation property 18'
                                 ' (creating_application)']
        self.assertEqual(prop_claim.declared, self.APP_A.encode('latin_1'))
        self.assertEqual(prop_claim.identified, 'ProducerA')
        self.assertEqual(prop_claim.scope, ('Embedded1',))

    def test_unverifiable_claims_keep_declared_values(self):
        'Without known identifiers, claims keep their original values'
        ole = olefile.OleFileIO(self.ole_data)
        records = ole.get_provenance()
        ole.close()
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertEqual(record.producers, [])
            self.assertFalse(record.corroborated)
            for claim in record.claims:
                self.assertIsNone(claim.identified)
        # declared values are preserved as found in the file:
        self.assertEqual(records[0].claims[0].declared, self.CLSID_A)
        self.assertEqual(records[1].claims[0].declared, self.CLSID_B)
        self.assertEqual(records[1].claims[1].declared,
                         self.APP_A.encode('latin_1'))

    def test_provenance_real_file(self):
        'The sample Word document yields a single corroborated root record'
        ole = olefile.OleFileIO(u'tests/images/test-ole-file.doc')
        records = ole.get_provenance(
            {'microsoft office word': 'Microsoft Word',
             '00020906-0000-0000-C000-000000000046': 'Microsoft Word'},
            {'Microsoft Word': ['WordDocument', '1Table']})
        ole.close()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.storage_path, ())
        self.assertEqual(record.producers, ['Microsoft Word'])
        self.assertTrue(record.corroborated)


if __name__ == '__main__':
    unittest.main()

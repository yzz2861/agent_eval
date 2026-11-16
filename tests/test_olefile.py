"""
Tests for olefile
"""

from __future__ import print_function
import unittest

import os, sys
import io
import struct
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


# --- Helpers to build minimal OLE files in memory ---------------------------
# Used by the security tests below to craft malformed FAT/DIFAT structures
# without relying on external sample files.

OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF
STGTY_STREAM = 2
STGTY_ROOT = 5
SECTOR_SIZE = 512


def make_direntry(name, entry_type, child_sid=NOSTREAM,
                  isect_start=ENDOFCHAIN, size=0):
    """Build a 128-bytes directory entry."""
    name_utf16 = name.encode('utf-16-le') + b'\x00\x00'
    return struct.pack(
        '<64sHBBIII16sIQQIII',
        name_utf16.ljust(64, b'\x00'), len(name_utf16), entry_type, 1,
        NOSTREAM, NOSTREAM, child_sid, b'\x00' * 16, 0, 0, 0,
        isect_start, size & 0xFFFFFFFF, (size >> 32) & 0xFFFFFFFF)


def make_header(num_fat_sectors, first_dir_sector, header_difat,
                first_difat_sector=ENDOFCHAIN, num_difat_sectors=0):
    """Build a 512-bytes OLE header (512-bytes sectors, no MiniFAT)."""
    header = struct.pack(
        '<8s16sHHHHHHLLLLLLLLLL',
        OLE_MAGIC, b'\x00' * 16, 0x003E, 3, 0xFFFE, 9, 6, 0, 0, 0,
        num_fat_sectors, first_dir_sector, 0, 0x1000,
        ENDOFCHAIN, 0, first_difat_sector, num_difat_sectors)
    difat = list(header_difat) + [FREESECT] * (109 - len(header_difat))
    return header + struct.pack('<109I', *difat)


def make_fat_sector(entries):
    """Build a 512-bytes FAT sector from a list of up to 128 entries."""
    entries = list(entries) + [FREESECT] * (128 - len(entries))
    return struct.pack('<128I', *entries)


def make_directory_sector(stream_isect_start, stream_size):
    """Build a 512-bytes directory sector: root entry + one stream 's'."""
    root = make_direntry('Root Entry', STGTY_ROOT, child_sid=1)
    stream = make_direntry('s', STGTY_STREAM,
                           isect_start=stream_isect_start, size=stream_size)
    return (root + stream).ljust(SECTOR_SIZE, b'\x00')


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


class TestMalformedFatChains(unittest.TestCase):
    """Security tests: malformed FAT/DIFAT chains must be rejected."""

    def make_fat_loop_file(self):
        """OLE file whose stream FAT chain loops: sectors 2 -> 3 -> 2 -> ..."""
        # sectors: 0=FAT, 1=directory, 2..11=data
        fat_entries = [FATSECT, ENDOFCHAIN, 3, 2] + [FREESECT] * 8
        header = make_header(num_fat_sectors=1, first_dir_sector=1,
                             header_difat=[0])
        # declared size >= mini stream cutoff so the stream is read via FAT,
        # and requires 9 sectors while the chain loops over 2 sectors:
        directory = make_directory_sector(stream_isect_start=2,
                                          stream_size=9 * SECTOR_SIZE)
        data = b''.join(bytes([i]) * SECTOR_SIZE for i in range(2, 12))
        return header + make_fat_sector(fat_entries) + directory + data

    def make_difat_overlap_file(self):
        """OLE file whose DIFAT references a FAT sector already listed in
        the header (FAT/DIFAT overlap)."""
        # sectors: 0..108=FAT, 109=DIFAT, 110=directory
        fat0 = [FATSECT] * 109 + [DIFSECT, ENDOFCHAIN]
        header = make_header(num_fat_sectors=110, first_dir_sector=110,
                             header_difat=list(range(109)),
                             first_difat_sector=109, num_difat_sectors=1)
        # the DIFAT sector points to sector 0, already used as a FAT sector:
        difat = [0] + [FREESECT] * 126 + [ENDOFCHAIN]
        sectors = [make_fat_sector(fat0)]
        sectors += [make_fat_sector([]) for _ in range(108)]
        sectors.append(struct.pack('<128I', *difat))
        sectors.append(make_directory_sector(ENDOFCHAIN, 0))
        return header + b''.join(sectors)

    def make_oversize_stream_file(self):
        """OLE file whose stream declares a size beyond the FAT capacity."""
        # sectors: 0=FAT, 1=directory, 2=data (only 3 sectors in the file)
        fat_entries = [FATSECT, ENDOFCHAIN, ENDOFCHAIN]
        header = make_header(num_fat_sectors=1, first_dir_sector=1,
                             header_difat=[0])
        directory = make_directory_sector(stream_isect_start=2,
                                          stream_size=10 * SECTOR_SIZE)
        return (header + make_fat_sector(fat_entries) + directory
                + bytes([7]) * SECTOR_SIZE)

    def make_valid_difat_file(self):
        """Valid large OLE file using a DIFAT sector (110 FAT sectors)."""
        # sectors: 0..108=FAT, 109=DIFAT, 110=FAT, 111=directory, 112..120=data
        fat0 = ([FATSECT] * 109 + [DIFSECT, FATSECT, ENDOFCHAIN]
                + list(range(113, 121)) + [ENDOFCHAIN])
        header = make_header(num_fat_sectors=110, first_dir_sector=111,
                             header_difat=list(range(109)),
                             first_difat_sector=109, num_difat_sectors=1)
        difat = [110] + [FREESECT] * 126 + [ENDOFCHAIN]
        sectors = [make_fat_sector(fat0)]
        sectors += [make_fat_sector([]) for _ in range(108)]
        sectors.append(struct.pack('<128I', *difat))
        sectors.append(make_fat_sector([]))
        sectors.append(make_directory_sector(stream_isect_start=112,
                                             stream_size=9 * SECTOR_SIZE))
        data = b''.join(bytes([i % 256]) * SECTOR_SIZE for i in range(112, 121))
        return header + b''.join(sectors) + data, data

    def make_sparse_end_file(self):
        """Valid OLE file whose last sector is physically truncated (sparse
        ending): the file ends before the last sector is complete."""
        # sectors: 0=FAT, 1=directory, 2..9=data, 10=data (only 88 bytes present)
        fat_entries = ([FATSECT, ENDOFCHAIN] + list(range(3, 11))
                       + [ENDOFCHAIN])
        header = make_header(num_fat_sectors=1, first_dir_sector=1,
                             header_difat=[0])
        stream_size = 8 * SECTOR_SIZE + 88
        directory = make_directory_sector(stream_isect_start=2,
                                          stream_size=stream_size)
        data = b''.join(bytes([i]) * SECTOR_SIZE for i in range(2, 10))
        data += bytes([10]) * 88
        return (header + make_fat_sector(fat_entries) + directory + data,
                data)

    def test_fat_loop_rejected(self):
        """A stream whose FAT chain loops must fail instead of returning
        duplicated sectors."""
        data = self.make_fat_loop_file()
        ole = olefile.OleFileIO(io.BytesIO(data))
        with self.assertRaises(IOError) as cm:
            ole.openstream('s')
        ole.close()
        # the error message must not embed the file contents:
        self.assertLess(len(str(cm.exception)), 200)

    def test_difat_overlap_rejected(self):
        """A DIFAT sector referencing an already used FAT sector must fail."""
        data = self.make_difat_overlap_file()
        with self.assertRaises(IOError) as cm:
            olefile.OleFileIO(io.BytesIO(data))
        self.assertLess(len(str(cm.exception)), 200)

    def test_stream_size_out_of_bounds_rejected(self):
        """A stream declaring a size larger than the FAT capacity must fail."""
        data = self.make_oversize_stream_file()
        ole = olefile.OleFileIO(io.BytesIO(data))
        with self.assertRaises(IOError) as cm:
            ole.openstream('s')
        ole.close()
        self.assertLess(len(str(cm.exception)), 200)

    def test_valid_difat_file_compatible(self):
        """A valid large file using DIFAT must still load and read correctly."""
        data, expected = self.make_valid_difat_file()
        ole = olefile.OleFileIO(io.BytesIO(data))
        stream = ole.openstream('s')
        self.assertEqual(stream.read(), expected)
        stream.close()
        ole.close()

    def test_sparse_end_file_compatible(self):
        """A file whose last sector is truncated at EOF must still read."""
        data, expected = self.make_sparse_end_file()
        ole = olefile.OleFileIO(io.BytesIO(data))
        stream = ole.openstream('s')
        self.assertEqual(stream.read(), expected)
        stream.close()
        ole.close()


if __name__ == '__main__':
    unittest.main()

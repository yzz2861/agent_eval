"""
Tests for olefile
"""

from __future__ import print_function
import unittest
import struct

import os, sys
import io
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


def make_tiny_shared_mini_ole():
    """
    Build a minimal valid OLE file in which two MiniFAT streams (StreamA and
    StreamB) both start at mini-sector 0.

    The file is 2560 bytes and has this layout:

        sector 0: FAT
        sector 1: directory (root, StreamA, StreamB)
        sector 2: MiniFAT (one entry, ENDOFCHAIN)
        sector 3: MiniStream (one 64-byte mini-sector)

    The shared mini-sector is the bottom-level evidence that an approval for
    one stream alone is not sufficient.
    """
    def direntry(name, entry_type, left=olefile.NOSTREAM,
                 right=olefile.NOSTREAM, child=olefile.NOSTREAM,
                 start=olefile.ENDOFCHAIN, size=0):
        name_utf16 = (name + u'\x00').encode('utf-16-le')
        name_raw = name_utf16 + b'\x00' * (64 - len(name_utf16))
        return struct.pack(
            '<64sHBBIII16sIQQIII',
            name_raw, len(name_utf16), entry_type, 1,
            left, right, child,
            b'\x00' * 16, 0, 0, 0,
            start, size & 0xFFFFFFFF, size >> 32)

    fmt_header = '<8s16sHHHHHHLLLLLLLLLL'
    header = struct.pack(
        fmt_header,
        olefile.MAGIC, b'\x00' * 16,
        0x003E, 3, 0xFFFE, 9, 6, 0, 0,
        0, 1, 1, 0, 0x1000, 2, 1, olefile.ENDOFCHAIN, 0)
    header += struct.pack(
        '<109I', 0, *([olefile.FREESECT] * 108))
    assert len(header) == 512

    fat_entries = [
        olefile.FATSECT,
        olefile.ENDOFCHAIN,   # directory sector
        olefile.ENDOFCHAIN,   # MiniFAT sector
        olefile.ENDOFCHAIN,   # MiniStream sector
    ]
    fat_entries += [olefile.FREESECT] * (128 - len(fat_entries))
    fat = struct.pack('<128I', *fat_entries)

    directory = b''.join([
        direntry(u'Root Entry', olefile.STGTY_ROOT, child=1,
                 start=3, size=64),
        direntry(u'StreamA', olefile.STGTY_STREAM, right=2,
                 start=0, size=64),
        direntry(u'StreamB', olefile.STGTY_STREAM, start=0, size=64),
        b'\x00' * 128,
    ])
    assert len(directory) == 512

    minifat_entries = [olefile.ENDOFCHAIN]
    minifat_entries += [olefile.FREESECT] * (128 - len(minifat_entries))
    minifat = struct.pack('<128I', *minifat_entries)

    ministream = b'SHARED-MINI-SECTOR' + b'X' * (64 - 18)
    ministream += b'\x00' * (512 - len(ministream))

    return header + fat + directory + minifat + ministream


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




class TestExportManifest(unittest.TestCase):
    "Tests for the pre-export forensic manifest"

    def setUp(self):
        self.data = make_tiny_shared_mini_ole()

    def _shared_gaps(self, manifest):
        return [gap for gap in manifest["gaps"]
                if gap["code"] == "shared_allocation_unit"]

    def test_shared_mini_sector_returns_locatable_gap(self):
        with olefile.OleFileIO(self.data) as ole:
            manifest = ole.export_manifest(["StreamA"])
            self.assertFalse(manifest["ok"])
            self.assertFalse(manifest["export_allowed"])
            self.assertEqual(manifest["export_streams"], ["StreamA"])
            self.assertNotIn("StreamB", manifest["export_streams"])
            gaps = self._shared_gaps(manifest)
            self.assertEqual(len(gaps), 1)
            gap = gaps[0]
            self.assertTrue(gap["requires_authorization"])
            self.assertTrue(gap["blocking"])
            self.assertEqual(gap["other_path"], "StreamB")
            self.assertEqual(gap["other_sid"], 2)
            self.assertEqual(gap["unit_kind"], "minisector")
            self.assertEqual(gap["unit_index"], 0)
            self.assertEqual(gap["sector"], 3)
            self.assertEqual(gap["file_offset"], 2048)
            self.assertEqual(gap["locator"]["file_offset"], 2048)
            entries = dict((entry["sid"], entry)
                           for entry in gap["shared_unit"]["directory_entries"])
            self.assertEqual(entries[1]["file_offset"], 1024 + 128)
            self.assertEqual(entries[2]["file_offset"], 1024 + 256)
            withheld = manifest["withheld_streams"]
            self.assertEqual([item["path"] for item in withheld], ["StreamB"])
            self.assertFalse(withheld[0]["exported"])
            self.assertFalse(withheld[0]["payload_included"])

    def test_dependencies_are_explicit(self):
        with olefile.OleFileIO(self.data) as ole:
            manifest = ole.export_manifest(["StreamA"])
            deps = manifest["dependencies"]
            self.assertEqual(deps["directory"]["sectors"], [1])
            self.assertEqual(deps["directory"]["entries_needed"][1]["sid"], 1)
            self.assertEqual(deps["fat"]["sectors"], [0])
            self.assertEqual(deps["minifat"]["sectors"], [2])
            self.assertEqual(deps["minifat"]["entries_needed"][0]["unit"], 0)
            self.assertEqual(deps["ministream"]["sectors"], [3])
            self.assertEqual(
                deps["ministream"]["approved_spans"][0]["file_offset"], 2048)
            self.assertTrue(deps["ministream"]["contains_unapproved_payload"])
            stream = manifest["streams_by_path"]["StreamA"]
            self.assertEqual(stream["directory_entry"]["sid"], 1)
            self.assertEqual(stream["directory_entry"]["file_offset"], 1024 + 128)
            self.assertEqual(stream["allocation_chain"], [0])
            self.assertEqual(stream["data_units"][0]["file_offset"], 2048)
            self.assertEqual(
                stream["allocation_table"]["entries"][0]["locator"]["file_offset"],
                1536)

    def test_approving_both_streams_resolves_shared_unit(self):
        with olefile.OleFileIO(self.data) as ole:
            manifest = ole.export_manifest(["StreamA", "StreamB"])
            self.assertTrue(manifest["ok"])
            self.assertTrue(manifest["export_allowed"])
            self.assertEqual(sorted(manifest["export_streams"]),
                             ["StreamA", "StreamB"])
            self.assertEqual(self._shared_gaps(manifest), [])
            shared = manifest["shared_units"][0]
            self.assertFalse(shared["requires_authorization"])
            self.assertEqual(sorted(shared["approved_streams"]),
                             ["StreamA", "StreamB"])
            self.assertEqual(manifest["withheld_streams"], [])

    def test_allow_shared_is_acknowledgement_not_expansion(self):
        with olefile.OleFileIO(self.data) as ole:
            manifest = ole.export_manifest(["StreamA"], allow_shared_units=True)
            self.assertTrue(manifest["ok"])
            self.assertEqual(manifest["export_streams"], ["StreamA"])
            gaps = self._shared_gaps(manifest)
            self.assertEqual(len(gaps), 1)
            self.assertTrue(gaps[0]["requires_authorization"])
            self.assertFalse(gaps[0]["blocking"])
            self.assertEqual(manifest["withheld_streams"][0]["path"], "StreamB")
            self.assertFalse(manifest["scope"]["widens_disclosure"])

    def test_missing_path_is_a_locatable_gap(self):
        with olefile.OleFileIO(self.data) as ole:
            manifest = ole.export_manifest(["StreamA/Missing"])
            gaps = [gap for gap in manifest["gaps"]
                    if gap["code"] == "stream_not_found"]
            self.assertEqual(len(gaps), 1)
            self.assertEqual(gaps[0]["locator"]["ancestor_sid"], 1)
            self.assertEqual(gaps[0]["file_offset"], 1024 + 128)

    def test_unreferenced_stream_is_still_detected(self):
        data = bytearray(make_tiny_shared_mini_ole())
        # Remove StreamA's right-sibling link so StreamB is no longer in the
        # storage tree, while its directory entry remains in the original.
        struct.pack_into('<I', data, 1024 + 128 + 72, 0xFFFFFFFF)
        with olefile.OleFileIO(bytes(data)) as ole:
            self.assertEqual(ole.listdir(), [['StreamA']])
            manifest = ole.export_manifest(['StreamA'])
            self.assertFalse(manifest['ok'])
            gaps = self._shared_gaps(manifest)
            self.assertEqual(len(gaps), 1)
            self.assertEqual(gaps[0]['other_sid'], 2)
            self.assertEqual(gaps[0]['other_path'], '<unreferenced SID 2>')
            self.assertEqual(gaps[0]['file_offset'], 2048)
            withheld = manifest['withheld_streams'][0]
            self.assertEqual(withheld['directory_entry']['file_offset'], 1280)
            self.assertFalse(withheld['payload_included'])

    def test_copy_plan_does_not_expand_scope(self):
        with olefile.OleFileIO(self.data) as ole:
            manifest = ole.export_manifest(['StreamA'])
            plan = manifest['copy_plan']
            self.assertEqual(plan['policy'], 'minimal-ranges-only')
            self.assertEqual(
                [item['path'] for item in plan['streams']], ['StreamA'])
            self.assertTrue(plan['excluded']['entire_directory_stream'])
            self.assertTrue(plan['excluded']['entire_ministream'])
            self.assertTrue(plan['excluded']['unapproved_stream_payloads'])
            self.assertEqual(plan['ministream_spans'][0]['file_offset'], 2048)
            self.assertNotIn(
                'StreamB', [item['path'] for item in plan['streams']])


if __name__ == '__main__':
    unittest.main()

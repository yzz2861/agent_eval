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


def _build_property_section(properties):
    """
    Build one PropertySet section from (property_id, VT type, payload) tuples.
    """
    table_end = 8 + 8 * len(properties)
    offsets = []
    values = []
    position = table_end
    for property_id, property_type, payload in properties:
        offsets.append(position)
        value = struct.pack('<I', property_type) + payload
        values.append(value)
        position += len(value)

    section = [struct.pack('<II', position, len(properties))]
    for (property_id, _, _), offset in zip(properties, offsets):
        section.append(struct.pack('<II', property_id, offset))
    section.extend(values)
    return b''.join(section)


def _build_property_set(sections):
    """
    Build a PropertySetStream from (fmtid, properties) tuples.
    """
    section_count = len(sections)
    header = (struct.pack('<HHI', 0xFFFE, 0, 0) + b'\x00' * 16 +
              struct.pack('<I', section_count))

    offset = 28 + 20 * section_count
    descriptors = []
    section_data = []
    for fmtid, properties in sections:
        section = _build_property_section(properties)
        descriptors.append(fmtid + struct.pack('<I', offset))
        section_data.append(section)
        offset += len(section)
        padding = (-offset) % 4
        if padding:
            section_data.append(b'\x00' * padding)
            offset += padding
    return header + b''.join(descriptors) + b''.join(section_data)


def _lpstr(value, codepage=1252):
    if codepage == 1200:
        raw = value.encode('utf-16le') + b'\x00\x00'
    else:
        raw = value.encode('cp1252') + b'\x00'
    return struct.pack('<I', len(raw)) + raw


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


class TestPropertySetParsing(unittest.TestCase):
    'Tests for bounded property set parsing'

    stream_name = "\x05SummaryInformation"

    def setUp(self):
        self.ole_file = "tests/images/test-ole-file.doc"

    def _open_with_stream(self, stream_data,
                          raise_defects=olefile.DEFECT_INCORRECT):
        ole = olefile.OleFileIO(self.ole_file, raise_defects=raise_defects)
        ole.openstream = lambda filename: io.BytesIO(stream_data)
        return ole

    def test_truncated_lpstr_is_bounded(self):
        properties = [
            (1, olefile.olefile.VT_I2, struct.pack('<h', 1252)),
            (2, olefile.olefile.VT_LPSTR, _lpstr('previous value')),
            (3, olefile.olefile.VT_LPSTR,
             struct.pack('<I', 4096) + b'not-enough'),
        ]
        stream = _build_property_set([(b'\x01' * 16, properties)])
        ole = self._open_with_stream(stream)
        try:
            with self.assertRaises(IOError) as raised:
                ole.getproperties(self.stream_name)
        finally:
            ole.close()

        message = str(raised.exception)
        self.assertIn('SummaryInformation', message)
        self.assertIn('property id 3', message)
        self.assertNotIn('not-enough', message)

    def test_truncated_lpstr_is_not_reused_when_defect_is_recorded(self):
        properties = [
            (1, olefile.olefile.VT_I2, struct.pack('<h', 1252)),
            (2, olefile.olefile.VT_LPSTR, _lpstr('previous value')),
            (3, olefile.olefile.VT_LPSTR,
             struct.pack('<I', 4096) + b'not-enough'),
        ]
        stream = _build_property_set([(b'\x01' * 16, properties)])
        ole = self._open_with_stream(stream, olefile.DEFECT_FATAL)
        try:
            values = ole.getproperties(self.stream_name)
            issues = list(ole.parsing_issues)
        finally:
            ole.close()

        self.assertEqual(values[2], b'previous value')
        self.assertNotIn(3, values)
        self.assertTrue(any('property id 3' in message
                            for _, message in issues))

    def test_unsupported_codepage_reports_property_id(self):
        properties = [
            (1, olefile.olefile.VT_I2, struct.pack('<h', 9999)),
            (2, olefile.olefile.VT_LPSTR, _lpstr('sensitive-value')),
        ]
        stream = _build_property_set([(b'\x01' * 16, properties)])
        ole = self._open_with_stream(stream)
        try:
            with self.assertRaises(IOError) as raised:
                ole.getproperties(self.stream_name)
        finally:
            ole.close()

        message = str(raised.exception)
        self.assertIn('SummaryInformation', message)
        self.assertIn('property id 1', message)
        self.assertIn('codepage', message)
        self.assertNotIn('sensitive-value', message)

    def test_valid_codepages_and_empty_values(self):
        properties = [
            (1, olefile.olefile.VT_I2, struct.pack('<h', 1252)),
            (2, olefile.olefile.VT_LPSTR, _lpstr(u'caf\xe9', 1252)),
            (3, olefile.olefile.VT_EMPTY, b''),
            (4, olefile.olefile.VT_NULL, b''),
            (5, olefile.olefile.VT_LPSTR, struct.pack('<I', 0)),
        ]
        stream = _build_property_set([(b'\x01' * 16, properties)])
        ole = self._open_with_stream(stream)
        try:
            values = ole.getproperties(self.stream_name)
        finally:
            ole.close()

        self.assertEqual(values[2], u'caf\xe9'.encode('cp1252'))
        self.assertIsNone(values[3])
        self.assertIsNone(values[4])
        self.assertEqual(values[5], b'')

    def test_utf16_codepage_is_decoded(self):
        properties = [
            (1, olefile.olefile.VT_I2, struct.pack('<h', 1200)),
            (2, olefile.olefile.VT_LPSTR, _lpstr(u'caf\xe9', 1200)),
        ]
        stream = _build_property_set([(b'\x01' * 16, properties)])
        ole = self._open_with_stream(stream)
        try:
            values = ole.getproperties(self.stream_name)
        finally:
            ole.close()

        self.assertEqual(values[2], u'caf\xe9'.encode('utf-8'))

    def test_multiple_sections_are_parsed_independently(self):
        first = [
            (1, olefile.olefile.VT_I2, struct.pack('<h', 1252)),
            (2, olefile.olefile.VT_LPSTR, _lpstr('first', 1252)),
        ]
        second = [
            (1, olefile.olefile.VT_I2, struct.pack('<h', 1200)),
            (3, olefile.olefile.VT_LPSTR, _lpstr(u'second', 1200)),
        ]
        stream = _build_property_set([
            (b'\x01' * 16, first),
            (b'\x02' * 16, second),
        ])
        ole = self._open_with_stream(stream)
        try:
            values = ole.getproperties(self.stream_name)
        finally:
            ole.close()

        self.assertEqual(values[1], 1200)
        self.assertEqual(values[2], b'first')
        self.assertEqual(values[3], b'second')

    def test_invalid_section_offset_reports_stream(self):
        properties = [
            (1, olefile.olefile.VT_I2, struct.pack('<h', 1252)),
        ]
        stream = bytearray(_build_property_set([(b'\x01' * 16, properties)]))
        struct.pack_into('<I', stream, 28 + 16, 0)
        ole = self._open_with_stream(bytes(stream))
        try:
            with self.assertRaises(IOError) as raised:
                ole.getproperties(self.stream_name)
        finally:
            ole.close()

        message = str(raised.exception)
        self.assertIn('SummaryInformation', message)
        self.assertIn('section offset', message)

    def test_unsupported_vt_type_reports_property_id(self):
        properties = [
            (1, olefile.olefile.VT_I2, struct.pack('<h', 1252)),
            (2, 0xFFFF, b''),
        ]
        stream = _build_property_set([(b'\x01' * 16, properties)])
        ole = self._open_with_stream(stream)
        try:
            with self.assertRaises(IOError) as raised:
                ole.getproperties(self.stream_name)
        finally:
            ole.close()

        message = str(raised.exception)
        self.assertIn('SummaryInformation', message)
        self.assertIn('property id 2', message)


if __name__ == '__main__':
    unittest.main()

"""
Tests for olefile encryption detection (detect_encryption)
"""

from __future__ import print_function
import unittest

import os, sys
import io
import struct

# Insert the olefile package relative to this test dir in the sys.path
# to make sure we test the right one, in case another olefile version
# is also installed in the main python path.
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile


# --- helpers to build minimal synthetic OLE2/CFB files in memory -------------

SECTOR_SIZE = 512
MINI_SECTOR_SIZE = 64
MINI_CUTOFF = 4096
FAT_ENTRIES_PER_SECTOR = SECTOR_SIZE // 4

ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF

STGTY_STREAM = 2
STGTY_ROOT = 5


def _dir_entry(name, entry_type, left, right, child, start_sect, size):
    'Build a 128-bytes directory entry'
    name_utf16 = name.encode('utf-16-le') + b'\x00\x00'
    return struct.pack(
        '<64sHBBIII16sIQQIII',
        name_utf16.ljust(64, b'\x00'), len(name_utf16), entry_type, 1,
        left, right, child, b'\x00' * 16, 0, 0, 0, start_sect,
        size & 0xFFFFFFFF, (size >> 32) & 0xFFFFFFFF)


def build_ole_file(streams):
    """
    Build a minimal OLE2 compound file (CFB) in memory, containing the given
    streams at the root of the storage tree.

    :param streams: list of (name, data) tuples, data as bytes
    :returns: bytes of the OLE file
    """
    # split streams between MiniFAT (< 4096 bytes) and regular FAT:
    mini_indexes = [i for i, (name, data) in enumerate(streams)
                    if 0 < len(data) < MINI_CUTOFF]
    big_indexes = [i for i, (name, data) in enumerate(streams)
                   if len(data) >= MINI_CUTOFF]
    # build the ministream and the MiniFAT:
    ministream = b''
    minifat = []
    mini_start = {}
    for i in mini_indexes:
        data = streams[i][1]
        count = (len(data) + MINI_SECTOR_SIZE - 1) // MINI_SECTOR_SIZE
        mini_start[i] = len(ministream) // MINI_SECTOR_SIZE
        for k in range(count):
            if k < count - 1:
                minifat.append(mini_start[i] + k + 1)
            else:
                minifat.append(ENDOFCHAIN)
        ministream += data.ljust(count * MINI_SECTOR_SIZE, b'\x00')
    # sector layout: 1 FAT sector, then directory, MiniFAT, ministream,
    # then the regular FAT streams:
    nb_dir_entries = 1 + len(streams)
    nb_dir_sect = (nb_dir_entries * 128 + SECTOR_SIZE - 1) // SECTOR_SIZE
    if minifat:
        nb_minifat_sect = (len(minifat) + FAT_ENTRIES_PER_SECTOR - 1) \
            // FAT_ENTRIES_PER_SECTOR
    else:
        nb_minifat_sect = 0
    if ministream:
        nb_ministream_sect = (len(ministream) + SECTOR_SIZE - 1) \
            // SECTOR_SIZE
    else:
        nb_ministream_sect = 0
    first_dir_sect = 1
    first_minifat_sect = 1 + nb_dir_sect if nb_minifat_sect else ENDOFCHAIN
    if nb_ministream_sect:
        first_ministream_sect = 1 + nb_dir_sect + nb_minifat_sect
    else:
        first_ministream_sect = ENDOFCHAIN
    next_sect = 1 + nb_dir_sect + nb_minifat_sect + nb_ministream_sect
    # FAT entries, in sector order:
    fat = [FATSECT]
    fat += [first_dir_sect + k + 1 if k < nb_dir_sect - 1 else ENDOFCHAIN
            for k in range(nb_dir_sect)]
    fat += [first_minifat_sect + k + 1 if k < nb_minifat_sect - 1
            else ENDOFCHAIN for k in range(nb_minifat_sect)]
    fat += [first_ministream_sect + k + 1 if k < nb_ministream_sect - 1
            else ENDOFCHAIN for k in range(nb_ministream_sect)]
    big_start = {}
    big_data = b''
    for i in big_indexes:
        data = streams[i][1]
        count = (len(data) + SECTOR_SIZE - 1) // SECTOR_SIZE
        big_start[i] = next_sect
        for k in range(count):
            fat.append(next_sect + k + 1 if k < count - 1 else ENDOFCHAIN)
        big_data += data.ljust(count * SECTOR_SIZE, b'\x00')
        next_sect += count
    assert len(fat) <= FAT_ENTRIES_PER_SECTOR, 'test file needs >1 FAT sector'
    # directory entries: root entry, then one entry per stream, chained
    # through the "right sibling" pointers:
    entries = [_dir_entry('Root Entry', STGTY_ROOT, NOSTREAM,
                          NOSTREAM, 1 if streams else NOSTREAM,
                          first_ministream_sect, len(ministream))]
    for i, (name, data) in enumerate(streams):
        right = i + 2 if i < len(streams) - 1 else NOSTREAM
        if len(data) == 0:
            start = ENDOFCHAIN
        elif i in mini_start:
            start = mini_start[i]
        else:
            start = big_start[i]
        entries.append(_dir_entry(name, STGTY_STREAM, NOSTREAM, right,
                                  NOSTREAM, start, len(data)))
    directory = b''.join(entries)
    directory = directory.ljust(nb_dir_sect * SECTOR_SIZE, b'\x00')
    # OLE header:
    header = struct.pack(
        '<8s16sHHHHHHLLLLLLLLLL',
        olefile.MAGIC, b'\x00' * 16, 0x003E, 3, 0xFFFE, 9, 6, 0, 0,
        0, 1, first_dir_sect, 0, MINI_CUTOFF,
        first_minifat_sect, nb_minifat_sect, ENDOFCHAIN, 0)
    header += struct.pack('<109L', *([0] + [FREESECT] * 108))
    assert len(header) == SECTOR_SIZE
    fat_data = struct.pack('<%dL' % FAT_ENTRIES_PER_SECTOR,
                           *(fat + [FREESECT] * (FAT_ENTRIES_PER_SECTOR
                                                 - len(fat))))
    if nb_minifat_sect:
        minifat_entries = minifat + [FREESECT] * (
            nb_minifat_sect * FAT_ENTRIES_PER_SECTOR - len(minifat))
        minifat_data = struct.pack('<%dL' % len(minifat_entries),
                                   *minifat_entries)
    else:
        minifat_data = b''
    ministream_data = ministream.ljust(nb_ministream_sect * SECTOR_SIZE,
                                       b'\x00')
    return header + fat_data + directory + minifat_data + ministream_data \
        + big_data


def make_encryption_info(version_major, version_minor, flags=0):
    'Build an EncryptionInfo stream with the given version fields'
    header = struct.pack('<HHI', version_major, version_minor, flags)
    return header.ljust(MINI_CUTOFF, b'\x00')


def make_encrypted_package(declared_size, payload_size):
    'Build an EncryptedPackage stream declaring the given original size'
    return struct.pack('<Q', declared_size) + b'\xA5' * payload_size


def make_encrypted_ole(version_major=4, version_minor=4, payload_size=8192):
    'Build a synthetic encrypted Office document (OLE file) in memory'
    return build_ole_file([
        ('EncryptionInfo', make_encryption_info(version_major,
                                                version_minor)),
        ('EncryptedPackage', make_encrypted_package(payload_size,
                                                    payload_size)),
    ])


# --- tests -------------------------------------------------------------------

class TestDetectEncryption(unittest.TestCase):
    'Tests for detect_encryption and OleFileIO.detect_encryption'

    def setUp(self):
        self.non_ole_file = u"tests/images/flower.jpg"
        self.ole_file = u"tests/images/test-ole-file.doc"

    def test_not_ole_path(self):
        'A non-OLE file must be reported as ENCRYPTION_NOT_OLE'
        result = olefile.detect_encryption(filename=self.non_ole_file)
        self.assertEqual(result, olefile.ENCRYPTION_NOT_OLE)

    def test_not_ole_data(self):
        'Non-OLE data in memory must be reported as ENCRYPTION_NOT_OLE'
        with open(self.non_ole_file, 'rb') as f:
            data = f.read()
        result = olefile.detect_encryption(data=data)
        self.assertEqual(result, olefile.ENCRYPTION_NOT_OLE)

    def test_plain_ole_not_encrypted(self):
        'A legitimate Office document (OLE) must not be reported as encrypted'
        result = olefile.detect_encryption(filename=self.ole_file)
        self.assertEqual(result, olefile.ENCRYPTION_NONE)

    def test_plain_ole_not_encrypted_method(self):
        'OleFileIO.detect_encryption on a legitimate Office document'
        with olefile.OleFileIO(self.ole_file) as ole:
            self.assertEqual(ole.detect_encryption(), olefile.ENCRYPTION_NONE)

    def test_plain_ole_stream_not_encrypted(self):
        'An OLE file with a normal stream must not be reported as encrypted'
        data = build_ole_file([('WordDocument', b'\x00' * MINI_CUTOFF)])
        result = olefile.detect_encryption(data=data)
        self.assertEqual(result, olefile.ENCRYPTION_NONE)

    def test_encrypted_agile(self):
        'EncryptionInfo version 4.4 means agile encryption'
        data = make_encrypted_ole(4, 4)
        result = olefile.detect_encryption(data=data)
        self.assertEqual(result, olefile.ENCRYPTION_AGILE)

    def test_encrypted_standard(self):
        'EncryptionInfo version 3.2/4.2 means standard encryption'
        for version_major in (3, 4):
            data = make_encrypted_ole(version_major, 2)
            result = olefile.detect_encryption(data=data)
            self.assertEqual(result, olefile.ENCRYPTION_STANDARD)

    def test_encrypted_method(self):
        'OleFileIO.detect_encryption on an encrypted package'
        data = make_encrypted_ole(4, 4)
        with olefile.OleFileIO(data) as ole:
            self.assertEqual(ole.detect_encryption(), olefile.ENCRYPTION_AGILE)

    def test_encrypted_file_object(self):
        'detect_encryption accepts a file-like object'
        data = make_encrypted_ole(4, 4)
        result = olefile.detect_encryption(filename=io.BytesIO(data))
        self.assertEqual(result, olefile.ENCRYPTION_AGILE)

    def test_unknown_version(self):
        'Unknown EncryptionInfo version fields give ENCRYPTION_UNKNOWN'
        data = make_encrypted_ole(9, 9)
        result = olefile.detect_encryption(data=data)
        self.assertEqual(result, olefile.ENCRYPTION_UNKNOWN)

    def test_truncated_encryption_info(self):
        'EncryptionInfo shorter than its version header is TRUNCATED'
        data = build_ole_file([
            ('EncryptionInfo', b'\x04\x00\x04\x00'),
            ('EncryptedPackage', make_encrypted_package(100, 100)),
        ])
        result = olefile.detect_encryption(data=data)
        self.assertEqual(result, olefile.ENCRYPTION_TRUNCATED)

    def test_truncated_encrypted_package(self):
        'EncryptedPackage smaller than its declared size is TRUNCATED'
        data = build_ole_file([
            ('EncryptionInfo', make_encryption_info(4, 4)),
            # declares 1 MB of payload but only holds 100 bytes:
            ('EncryptedPackage', make_encrypted_package(1024 * 1024, 100)),
        ])
        result = olefile.detect_encryption(data=data)
        self.assertEqual(result, olefile.ENCRYPTION_TRUNCATED)

    def test_truncated_file(self):
        'A truncated encrypted package file is reported as TRUNCATED'
        data = make_encrypted_ole(4, 4)
        # keep the header, FAT and directory intact, cut the stream data:
        truncated = data[:2560]
        result = olefile.detect_encryption(data=truncated)
        self.assertEqual(result, olefile.ENCRYPTION_TRUNCATED)

    def test_missing_encrypted_package(self):
        'EncryptionInfo without EncryptedPackage is CORRUPT'
        data = build_ole_file([
            ('EncryptionInfo', make_encryption_info(4, 4)),
        ])
        result = olefile.detect_encryption(data=data)
        self.assertEqual(result, olefile.ENCRYPTION_CORRUPT)

    def test_missing_encryption_info(self):
        'EncryptedPackage without EncryptionInfo is CORRUPT'
        data = build_ole_file([
            ('EncryptedPackage', make_encrypted_package(100, 100)),
        ])
        result = olefile.detect_encryption(data=data)
        self.assertEqual(result, olefile.ENCRYPTION_CORRUPT)

    def test_corrupt_ole(self):
        'A file with the OLE magic but a damaged structure is CORRUPT'
        data = make_encrypted_ole(4, 4)
        # corrupt the DIFAT entries in the header (offset 76 and beyond):
        damaged = data[:76] + b'\xff' * 8 + data[84:]
        result = olefile.detect_encryption(data=damaged)
        self.assertEqual(result, olefile.ENCRYPTION_CORRUPT)

    def test_encryption_names(self):
        'Every ENCRYPTION_* result has a human-readable name'
        for value in (olefile.ENCRYPTION_NOT_OLE, olefile.ENCRYPTION_NONE,
                      olefile.ENCRYPTION_STANDARD, olefile.ENCRYPTION_AGILE,
                      olefile.ENCRYPTION_UNKNOWN, olefile.ENCRYPTION_CORRUPT,
                      olefile.ENCRYPTION_TRUNCATED):
            self.assertIn(value, olefile.ENCRYPTION_NAMES)


if __name__ == '__main__':
    unittest.main()

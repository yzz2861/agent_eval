# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
import unittest

import filetype
from filetype.match import match

# Absolute path to fixtures directory
FIXTURES = os.path.dirname(os.path.abspath(__file__)) + '/fixtures'

JPEG_MAGIC = bytearray([0xFF, 0xD8, 0xFF, 0x00, 0x08])
PNG_MAGIC = bytearray([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])

# Variable garbage prefix lengths, incl. odd and larger-than-signature sizes
PREFIX_LENGTHS = (1, 7, 33, 255, 512)


def read_fixture(name):
    with open(os.path.join(FIXTURES, name), 'rb') as fp:
        return bytearray(fp.read())


def garbage(length):
    # Deterministic printable-ASCII junk, free of any known magic bytes
    return bytearray(b'A' * length)


class TestMatchSearchWindow(unittest.TestCase):
    def test_zero_offset_fast_path_unchanged(self):
        buf = garbage(16) + JPEG_MAGIC
        self.assertTrue(match(buf) is None)
        self.assertTrue(match(buf, search_window=0) is None)

    def test_zero_offset_fast_path_matches(self):
        kind = match(JPEG_MAGIC)
        self.assertTrue(kind is not None)
        self.assertEqual(kind.mime, 'image/jpeg')

    def test_search_window_locates_jpeg_with_variable_prefix(self):
        sample = read_fixture('sample.jpg')
        for prefix_length in PREFIX_LENGTHS:
            buf = garbage(prefix_length) + sample
            kind = match(buf, search_window=prefix_length)
            self.assertTrue(kind is not None)
            self.assertEqual(kind.mime, 'image/jpeg')
            self.assertEqual(kind.extension, 'jpg')

    def test_search_window_locates_png_with_variable_prefix(self):
        sample = read_fixture('sample.png')
        for prefix_length in PREFIX_LENGTHS:
            buf = garbage(prefix_length) + sample
            kind = match(buf, search_window=prefix_length)
            self.assertTrue(kind is not None)
            self.assertEqual(kind.mime, 'image/png')
            self.assertEqual(kind.extension, 'png')

    def test_search_window_locates_doc_with_variable_prefix(self):
        sample = read_fixture('sample.doc')
        for prefix_length in PREFIX_LENGTHS:
            buf = garbage(prefix_length) + sample
            kind = match(buf, search_window=prefix_length)
            self.assertTrue(kind is not None)
            self.assertEqual(kind.mime, 'application/msword')
            self.assertEqual(kind.extension, 'doc')

    def test_search_window_locates_docx_with_variable_prefix(self):
        sample = read_fixture('sample.docx')
        for prefix_length in PREFIX_LENGTHS:
            buf = garbage(prefix_length) + sample
            kind = match(buf, search_window=prefix_length)
            self.assertTrue(kind is not None)
            self.assertEqual(kind.extension, 'docx')

    def test_search_window_larger_than_prefix(self):
        buf = garbage(3) + PNG_MAGIC
        kind = match(buf, search_window=64)
        self.assertTrue(kind is not None)
        self.assertEqual(kind.mime, 'image/png')

    def test_search_window_smaller_than_prefix_misses(self):
        buf = garbage(64) + JPEG_MAGIC
        self.assertTrue(match(buf, search_window=8) is None)

    def test_min_match_length_skips_truncated_tail(self):
        buf = garbage(4) + JPEG_MAGIC
        # Only 5 signature bytes remain: below the minimum match length
        kind = match(buf, search_window=8, min_match_length=8)
        self.assertTrue(kind is None)

    def test_min_match_length_allows_sufficient_tail(self):
        buf = garbage(4) + JPEG_MAGIC
        kind = match(buf, search_window=8, min_match_length=5)
        self.assertTrue(kind is not None)
        self.assertEqual(kind.mime, 'image/jpeg')


class TestMatchSearchWindowFalsePositives(unittest.TestCase):
    def test_pure_garbage_never_matches(self):
        buf = garbage(4096)
        self.assertTrue(match(buf, search_window=4096) is None)

    def test_partial_signature_fragment_never_matches(self):
        # Incomplete JPEG magic (missing 0xFF trailer) inside garbage
        buf = garbage(100) + bytearray([0xFF, 0xD8]) + garbage(100)
        self.assertTrue(match(buf, search_window=200) is None)

    def test_garbage_prefixed_sample_not_guessed_by_default(self):
        buf = garbage(16) + read_fixture('sample.jpg')
        self.assertTrue(filetype.guess(buf) is None)


class TestGuessRegression(unittest.TestCase):
    def test_guess_fixtures_still_return_correct_mime(self):
        expected = {
            'sample.jpg': 'image/jpeg',
            'sample.png': 'image/png',
            'sample.gif': 'image/gif',
            'sample.tif': 'image/tiff',
            'sample.doc': 'application/msword',
            'sample.xls': 'application/vnd.ms-excel',
            'sample.ppt': 'application/vnd.ms-powerpoint',
        }
        for name, mime in expected.items():
            kind = filetype.guess(os.path.join(FIXTURES, name))
            self.assertTrue(kind is not None, name)
            self.assertEqual(kind.mime, mime, name)

    def test_guess_invalid_buffer_still_none(self):
        buf = bytearray([0xFF, 0x00, 0x00, 0x00, 0x00])
        self.assertTrue(filetype.guess(buf) is None)

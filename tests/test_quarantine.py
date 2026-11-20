# -*- coding: utf-8 -*-

from __future__ import absolute_import

import io
import os
import shutil
import tempfile
import unittest

import filetype
from filetype.types import IMAGE

FIXTURES = os.path.dirname(os.path.abspath(__file__)) + '/fixtures'


class SequentialStream(object):
    """Non-seekable, read-only stream over in-memory data."""

    def __init__(self, data, fail_on_read=None):
        self._buf = io.BytesIO(data)
        self._fail_on_read = fail_on_read
        self._reads = 0
        self.closed = False

    def read(self, size=-1):
        self._reads += 1
        fail = self._fail_on_read
        if fail is not None and self._reads >= fail:
            raise IOError('simulated read failure')
        return self._buf.read(size)

    def close(self):
        self.closed = True


class TestQuarantine(unittest.TestCase):
    def setUp(self):
        self.staging_dir = tempfile.mkdtemp(prefix='filetype-test-')

    def tearDown(self):
        shutil.rmtree(self.staging_dir, ignore_errors=True)

    def staging_entries(self):
        return os.listdir(self.staging_dir)

    def test_sequential_stream_identified_and_staged(self):
        with open(FIXTURES + '/sample.png', 'rb') as fp:
            data = fp.read()
        result = filetype.quarantine(SequentialStream(data),
                                     staging_dir=self.staging_dir)
        try:
            self.assertTrue(result is not None)
            self.assertEqual(result.kind.mime, 'image/png')
            self.assertEqual(result.kind.extension, 'png')
            # handed-out handle reads exactly the identified bytes
            self.assertEqual(result.file.tell(), 0)
            self.assertEqual(result.read(), data)
            # staged file lives in the quarantine area while published
            self.assertEqual(os.path.dirname(result.path), self.staging_dir)
            self.assertEqual(len(self.staging_entries()), 1)
        finally:
            result.close()
        # closing the handle removes the staged temporary file
        self.assertTrue(result.closed)
        self.assertEqual(self.staging_entries(), [])

    def test_context_manager_cleans_up(self):
        with open(FIXTURES + '/sample.jpg', 'rb') as fp:
            data = fp.read()
        with filetype.quarantine(io.BytesIO(data),
                                 staging_dir=self.staging_dir) as result:
            self.assertEqual(result.kind.mime, 'image/jpeg')
            self.assertEqual(result.read(), data)
        self.assertTrue(result.closed)
        self.assertEqual(self.staging_entries(), [])

    def test_close_is_idempotent(self):
        result = filetype.quarantine(b'\xff\xd8\xff\x00\x08',
                                     staging_dir=self.staging_dir)
        result.close()
        result.close()
        self.assertTrue(result.closed)
        self.assertEqual(self.staging_entries(), [])

    def test_bytes_input(self):
        result = filetype.quarantine(bytearray([0xFF, 0xD8, 0xFF, 0x00, 0x08]),
                                     staging_dir=self.staging_dir)
        try:
            self.assertEqual(result.kind.extension, 'jpg')
        finally:
            result.close()

    def test_path_input_rejected(self):
        with self.assertRaises(TypeError):
            filetype.quarantine(FIXTURES + '/sample.png',
                                staging_dir=self.staging_dir)
        self.assertEqual(self.staging_entries(), [])

    def test_unknown_content_rejected(self):
        stream = SequentialStream(b'\x00' * 128)
        result = filetype.quarantine(stream, staging_dir=self.staging_dir)
        self.assertTrue(result is None)
        # original object: read from, never closed by the library
        self.assertFalse(stream.closed)
        # rejection leaves no consumable artifact behind
        self.assertEqual(self.staging_entries(), [])

    def test_size_limit_enforced(self):
        data = b'\xff\xd8\xff\x00\x08' + b'\x00' * 64
        with self.assertRaises(filetype.QuarantineSizeError):
            filetype.quarantine(SequentialStream(data), max_bytes=16,
                                staging_dir=self.staging_dir)
        self.assertEqual(self.staging_entries(), [])

    def test_size_limit_boundary(self):
        data = b'\xff\xd8\xff\x00\x08'
        result = filetype.quarantine(SequentialStream(data),
                                     max_bytes=len(data),
                                     staging_dir=self.staging_dir)
        try:
            self.assertEqual(result.read(), data)
        finally:
            result.close()

    def test_mid_read_failure_publishes_nothing(self):
        with open(FIXTURES + '/sample.png', 'rb') as fp:
            data = fp.read()
        stream = SequentialStream(data, fail_on_read=2)
        with self.assertRaises(filetype.QuarantineError):
            filetype.quarantine(stream, staging_dir=self.staging_dir)
        self.assertFalse(stream.closed)
        self.assertEqual(self.staging_entries(), [])

    def test_existing_matchers_reusable(self):
        with open(FIXTURES + '/sample.gif', 'rb') as fp:
            data = fp.read()
        result = filetype.quarantine(io.BytesIO(data),
                                     staging_dir=self.staging_dir)
        try:
            # standard matchers work directly on the published handle
            kind = filetype.match(result.file)
            self.assertEqual(kind.mime, 'image/gif')
            # handle position is preserved by get_bytes
            self.assertEqual(result.file.tell(), 0)
        finally:
            result.close()

    def test_custom_matcher_list(self):
        with open(FIXTURES + '/sample.png', 'rb') as fp:
            data = fp.read()
        result = filetype.quarantine(io.BytesIO(data), matchers=IMAGE,
                                     staging_dir=self.staging_dir)
        try:
            self.assertEqual(result.kind.extension, 'png')
        finally:
            result.close()

    def test_negative_max_bytes_rejected(self):
        with self.assertRaises(ValueError):
            filetype.quarantine(b'data', max_bytes=-1,
                                staging_dir=self.staging_dir)


if __name__ == '__main__':
    unittest.main()

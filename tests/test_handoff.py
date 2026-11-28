# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
import shutil
import tempfile
import unittest

import filetype
from filetype import (
    HandoffError,
    HandoffIntegrityError,
    HandoffNotFound,
    HandoffRegistry,
    HandoffStateError,
)


FIXTURES = os.path.dirname(os.path.abspath(__file__)) + '/fixtures'


class HandoffRegistryTest(unittest.TestCase):
    def setUp(self):
        self.workdir = tempfile.mkdtemp()
        self.first_source = os.path.join(self.workdir, 'first.jpg')
        self.second_source = os.path.join(self.workdir, 'second.png')
        shutil.copyfile(FIXTURES + '/sample.jpg', self.first_source)
        shutil.copyfile(FIXTURES + '/sample.png', self.second_source)
        self.registry = HandoffRegistry()

    def tearDown(self):
        shutil.rmtree(self.workdir)

    def test_handoff_separates_identity_summary_and_bytes(self):
        handoff = self.registry.register(self.first_source)
        with open(self.first_source, 'rb') as fp:
            expected_data = fp.read()
        expected_kind = filetype.guess(self.first_source)

        self.assertFalse(handoff.approved)
        self.assertEqual(handoff.fingerprint, filetype.fingerprint_file(
            self.first_source
        ))
        self.assertEqual(handoff.summary.mime, expected_kind.mime)
        self.assertEqual(handoff.summary.extension, expected_kind.extension)
        self.assertEqual(
            handoff.summary.signature, expected_data[:8192]
        )
        with self.assertRaises(HandoffStateError):
            handoff.read_bytes()

        handoff.approve()

        self.assertTrue(handoff.approved)
        self.assertEqual(handoff.read_bytes(), expected_data)

    def test_rename_keeps_identity_and_allows_delivery(self):
        handoff = self.registry.register(self.first_source)
        handoff.approve()

        working_path = os.path.join(self.workdir, 'renamed-work-item.jpg')
        shutil.move(self.first_source, working_path)

        self.assertFalse(handoff.verify())
        self.assertEqual(
            handoff.read_bytes(working_path), self._read(working_path)
        )
        self.assertEqual(handoff.source_path, os.path.abspath(working_path))
        self.assertTrue(handoff.verify())
        with self.assertRaises(HandoffNotFound):
            self.registry.get_by_path(self.first_source)

    def test_new_file_at_old_path_is_independently_judged(self):
        first = self.registry.register(self.first_source)
        first.approve()
        working_path = os.path.join(self.workdir, 'first-work-item.jpg')
        shutil.move(self.first_source, working_path)
        first.locate(working_path)

        shutil.move(self.second_source, self.first_source)

        replacement = self.registry.register(self.first_source)
        replacement.approve()

        self.assertNotEqual(first.id, replacement.id)
        self.assertNotEqual(first.fingerprint, replacement.fingerprint)
        self.assertEqual(replacement.summary.mime, 'image/png')
        self.assertEqual(replacement.summary.extension, 'png')
        self.assertEqual(
            self.registry.get_by_path(self.first_source).id, replacement.id
        )
        self.assertEqual(
            replacement.read_bytes(), self._read(self.first_source)
        )
        self.assertEqual(
            first.read_bytes(), self._read(working_path)
        )

    def test_cancel_stops_delivery_and_path_reuse_creates_new_object(self):
        old_handoff = self.registry.register(self.first_source)
        old_handoff.approve()
        old_handoff.cancel()

        self.assertFalse(old_handoff.approved)
        with self.assertRaises(HandoffStateError):
            old_handoff.read_bytes()
        with self.assertRaises(HandoffNotFound):
            self.registry.get_by_path(self.first_source)

        replacement = self.registry.register(self.first_source)

        self.assertNotEqual(old_handoff.id, replacement.id)
        self.assertFalse(replacement.approved)
        self.assertEqual(
            self.registry.get_by_path(self.first_source).id, replacement.id
        )
        self.assertFalse(old_handoff.approved)

    def test_consumption_rejects_changed_bytes_even_when_approved(self):
        handoff = self.registry.register(self.first_source)
        handoff.approve()

        with open(self.first_source, 'ab') as fp:
            fp.write(b'changed after approval')

        with self.assertRaises(HandoffIntegrityError):
            handoff.read_bytes()

    def test_relocate_rejects_file_with_another_identity(self):
        handoff = self.registry.register(self.first_source)
        handoff.approve()

        with self.assertRaises(HandoffIntegrityError):
            handoff.read_bytes(self.second_source)
        self.assertEqual(
            handoff.source_path, os.path.abspath(self.first_source)
        )

    def test_unrecognized_file_cannot_be_registered(self):
        unknown_path = os.path.join(self.workdir, 'unknown.bin')
        with open(unknown_path, 'wb') as fp:
            fp.write(b'not a supported file type')

        with self.assertRaises(HandoffError):
            self.registry.register(unknown_path)

    @staticmethod
    def _read(path):
        with open(path, 'rb') as fp:
            return fp.read()


if __name__ == '__main__':
    unittest.main()

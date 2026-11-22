"""
Tests for the read-only OLE directory evidence checker.
"""

from __future__ import print_function
import os
import sys
import unittest


_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile


Snapshot = olefile.DirectoryEntrySnapshot
PROVABLE = olefile.DIRECTORY_EVIDENCE_PROVABLE
NEEDS_CONFIRMATION = olefile.DIRECTORY_EVIDENCE_NEEDS_CONFIRMATION


def entry(sid, name, entry_type, left=olefile.NOSTREAM,
          right=olefile.NOSTREAM, child=olefile.NOSTREAM):
    return Snapshot(sid, name, entry_type, sid_left=left, sid_right=right,
                    sid_child=child)


class TestRealArchiveDirectoryEvidence(unittest.TestCase):
    def setUp(self):
        self.ole_file = os.path.join(
            os.path.dirname(__file__), 'images', 'test-ole-file.doc')

    def test_archive_is_provable_and_not_modified(self):
        with olefile.OleFileIO(self.ole_file) as ole:
            listing_before = ole.listdir(storages=True)
            links_before = tuple(
                (direntry.sid, direntry.sid_left, direntry.sid_right,
                 direntry.sid_child, direntry.used)
                for direntry in ole.direntries if direntry is not None)
            position_before = ole.directory_fp.tell()

            report = olefile.check_directory_evidence(ole)

            self.assertEqual(report.status, PROVABLE)
            self.assertEqual(report.conflicts, ())
            self.assertEqual(report.unclaimed, ())
            self.assertEqual(
                tuple(report.parent(0).owned_sids), (1, 2, 3, 4, 5))
            self.assertEqual(ole.listdir(storages=True), listing_before)
            self.assertEqual(
                tuple((direntry.sid, direntry.sid_left,
                       direntry.sid_right, direntry.sid_child,
                       direntry.used)
                      for direntry in ole.direntries
                      if direntry is not None),
                links_before)
            self.assertEqual(ole.directory_fp.tell(), position_before)

    def test_instance_alias_returns_evidence(self):
        with olefile.OleFileIO(self.ole_file) as ole:
            self.assertIsInstance(ole.directory_evidence(),
                                  olefile.DirectoryEvidence)


class TestDamagedDirectoryEvidence(unittest.TestCase):
    def test_same_name_different_sid_is_duplicate_name(self):
        entries = [
            entry(0, 'Root Entry', olefile.STGTY_ROOT, child=2),
            entry(1, 'same', olefile.STGTY_STREAM),
            entry(2, 'same', olefile.STGTY_STREAM, left=1),
        ]

        report = olefile.check_directory_evidence(entries)

        self.assertEqual(report.status, NEEDS_CONFIRMATION)
        self.assertEqual([conflict.kind for conflict in report.conflicts],
                         ['duplicate_name'])
        conflict = report.conflicts[0]
        self.assertEqual(conflict.sids, (1, 2))
        self.assertEqual(conflict.edges,
                         ((0, 'child', 2), (2, 'left', 1)))
        self.assertFalse(any(c.kind == 'duplicate_ownership'
                             for c in report.conflicts))

    def test_same_sid_twice_is_duplicate_ownership(self):
        entries = [
            entry(0, 'Root Entry', olefile.STGTY_ROOT, child=2),
            entry(2, 'b', olefile.STGTY_STREAM, left=3, right=3),
            entry(3, 'a', olefile.STGTY_STREAM),
        ]

        report = olefile.check_directory_evidence(entries)

        self.assertEqual([conflict.kind for conflict in report.conflicts],
                         ['duplicate_ownership'])
        conflict = report.conflicts[0]
        self.assertEqual(conflict.sids, (3,))
        self.assertEqual(conflict.edges,
                         ((0, 'child', 2), (2, 'left', 3),
                          (2, 'right', 3)))
        self.assertFalse(any(c.kind == 'duplicate_name'
                             for c in report.conflicts))
        self.assertEqual(sum(rel.child_sid == 3
                             for rel in report.relations), 2)

    def test_order_is_length_then_case_insensitive(self):
        entries = [
            entry(0, 'Root Entry', olefile.STGTY_ROOT, child=2),
            entry(1, 'b', olefile.STGTY_STREAM),
            entry(2, 'aa', olefile.STGTY_STREAM, left=1),
        ]

        report = olefile.check_directory_evidence(entries)

        self.assertEqual(report.status, PROVABLE)
        self.assertEqual(report.minimal_witnesses, ())

    def test_swap_two_edges_recovers_one_branch(self):
        before_entries = [
            entry(0, 'Root Entry', olefile.STGTY_ROOT, child=3),
            entry(1, 'A', olefile.STGTY_STORAGE, child=2),
            entry(2, 'X', olefile.STGTY_STREAM, left=4),
            entry(3, 'B', olefile.STGTY_STORAGE, left=1, child=2),
            entry(4, 'Y', olefile.STGTY_STREAM),
        ]

        before = olefile.check_directory_evidence(before_entries)

        self.assertEqual(before.parent(1).status, NEEDS_CONFIRMATION)
        self.assertEqual(before.parent(3).status, NEEDS_CONFIRMATION)
        self.assertEqual(
            sum(parent.status == NEEDS_CONFIRMATION
                for parent in before.parents if parent.owner_sid != 0), 2)
        self.assertTrue(any(conflict.kind == 'duplicate_ownership'
                            and conflict.sids == (2,)
                            for conflict in before.conflicts))

        # In a hypothetical copy, swap the targets of A.child (X) and
        # X.left (Y).  Y becomes A's child, while B keeps X.  The damaged
        # B branch is deliberately left broken.
        after_entries = [
            before_entries[0],
            before_entries[1].replace(sid_child=4),
            before_entries[2].replace(sid_left=2),
            before_entries[3],
            before_entries[4],
        ]

        after = olefile.check_directory_evidence(after_entries)

        self.assertEqual(after.parent(1).status, PROVABLE)
        self.assertEqual(after.parent(1).owned_sids, (4,))
        self.assertEqual(after.parent(3).status, NEEDS_CONFIRMATION)
        self.assertEqual(
            sum(parent.status == NEEDS_CONFIRMATION
                for parent in after.parents if parent.owner_sid != 0), 1)


if __name__ == '__main__':
    unittest.main()

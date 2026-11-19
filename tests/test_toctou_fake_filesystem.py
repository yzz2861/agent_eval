#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import time
import unittest

from tests.fake_filesystem import (
    FakeDescriptor,
    FakeFilesystem,
    SymlinkAttackError,
)


class TestFakeFilesystemToctou(unittest.TestCase):

    def test_check_then_reopen_has_exploitable_window(self):
        fs = FakeFilesystem()
        fs.add_file("/controlled/trusted", contents=b"trusted data")
        fs.add_file("/controlled/secret", contents=b"secret data")
        target = "/controlled/target"
        fs.add_file(target, contents=b"trusted data")

        # Attacker swaps the path for a symlink after the check but before
        # the reopen. The swap is scheduled, not threaded, so it is
        # deterministic and never races a real system directory.
        fs.schedule_symlink_swap(target, "/controlled/secret")

        if fs.exists(target):
            descriptor = fs.open_path(target)
            leaked = descriptor.read()

        self.assertEqual(leaked, b"secret data")
        self.assertNotEqual(leaked, b"trusted data")

    def test_no_follow_descriptor_blocks_the_same_attack(self):
        fs = FakeFilesystem()
        fs.add_file("/controlled/trusted", contents=b"trusted data")
        fs.add_file("/controlled/secret", contents=b"secret data")
        target = "/controlled/target"
        fs.add_file(target, contents=b"trusted data")

        fs.schedule_symlink_swap(target, "/controlled/secret")

        with self.assertRaises(SymlinkAttackError):
            fs.open_path(target, no_follow=True)

    def test_exclusive_create_refuses_swapped_symlink(self):
        fs = FakeFilesystem()
        fs.add_file("/controlled/secret", contents=b"secret data")
        target = "/controlled/new"

        fs.schedule_symlink_swap(target, "/controlled/secret")

        with self.assertRaises(SymlinkAttackError):
            fs.exclusive_create(target, contents=b"new data")

    def test_descriptor_reads_remain_pinned_after_path_swap(self):
        fs = FakeFilesystem()
        fs.add_file("/controlled/secret", contents=b"secret data")
        target = "/controlled/target"
        fs.add_file(target, contents=b"original data")

        descriptor = fs.open_path(target, no_follow=True)
        self.assertIsInstance(descriptor, FakeDescriptor)

        # Replacing the path after the descriptor is open cannot redirect
        # descriptor operations because no path re-resolution happens.
        swapped = type(fs.nodes[target])()
        swapped.symlink_target = "/controlled/secret"
        fs.nodes[target] = swapped

        self.assertEqual(descriptor.read(), b"original data")
        descriptor.close()

    def test_entire_suite_runs_within_time_budget(self):
        start = time.monotonic()
        fs = FakeFilesystem()
        fs.add_file("/controlled/a", contents=b"a")
        for index in range(100):
            path = "/controlled/path-{}".format(index)
            fs.add_file(path, contents=b"value")
            fs.schedule_symlink_swap(path, "/controlled/a")
            if fs.exists(path):
                try:
                    fs.open_path(path, no_follow=True)
                except SymlinkAttackError:
                    pass
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 2.0)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)


class SymlinkAttackError(AssertionError):
    pass


class FakeDescriptor(object):
    def __init__(self, fs, node, no_follow, exclusive, path):
        self.fs = fs
        self.node = node
        self.no_follow = no_follow
        self.exclusive = exclusive
        self.path = path
        self.closed = False

    def read(self):
        if self.closed:
            raise ValueError("descriptor is closed")
        return self.node.contents

    def close(self):
        self.closed = True


class FakeNode(object):
    def __init__(self, contents=b"", is_directory=False):
        self.contents = contents
        self.is_directory = is_directory
        self.symlink_target = None

    def is_symlink(self):
        return self.symlink_target is not None


class FakeFilesystem(object):
    """Deterministic, in-memory filesystem used to model TOCTOU races.

    It never touches the real filesystem or system directories. The attack
    window is modeled explicitly by scheduling a symlink swap, which makes the
    race reproducible without timing-dependent threads.
    """

    def __init__(self):
        self.nodes = {}
        self.descriptors = {}
        self._next_fd = 3
        self.pending_swap = None

    def add_file(self, path, contents=b""):
        self.nodes[path] = FakeNode(contents=contents)

    def add_directory(self, path):
        self.nodes[path] = FakeNode(is_directory=True)

    def schedule_symlink_swap(self, path, target):
        self.pending_swap = (path, target)

    def exists(self, path):
        self._run_pending_swap(path)
        return path in self.nodes

    def _run_pending_swap(self, path):
        if self.pending_swap is None:
            return
        swap_path, target = self.pending_swap
        if swap_path != path:
            return
        link = FakeNode()
        link.symlink_target = target
        self.nodes[swap_path] = link
        self.pending_swap = None

    def open_path(self, path, no_follow=False):
        self._run_pending_swap(path)
        node = self.nodes.get(path)
        if node is None:
            raise FileNotFoundError(path)
        if node.is_symlink():
            if no_follow:
                raise SymlinkAttackError(
                    "O_NOFOLLOW refused symlink at {}".format(path)
                )
            node = self.nodes[node.symlink_target]
        descriptor = FakeDescriptor(self, node, no_follow, False, path)
        return descriptor

    def exclusive_create(self, path, contents=b""):
        self._run_pending_swap(path)
        existing = self.nodes.get(path)
        if existing is not None and not existing.is_symlink():
            raise FileExistsError(path)
        if existing is not None and existing.is_symlink():
            raise SymlinkAttackError(
                "O_EXCL refused symlink at {}".format(path)
            )
        node = FakeNode(contents=contents)
        self.nodes[path] = node
        descriptor = FakeDescriptor(self, node, True, True, path)
        return descriptor

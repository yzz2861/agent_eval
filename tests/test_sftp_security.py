# Copyright (C) 2026  Paramiko
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Root-containment security tests for the server-mode SFTP implementation.

A real (loopback) SFTP server is started with its root pinned to a temporary
directory. Sensitive files and malicious links live *outside* that root, so
any successful read, write, rename or delete against them proves a sandbox
escape. All assertions are made through the public SFTP client API.
"""

import errno
import os
import shutil
import tempfile
import threading
import unicodedata

import pytest

from paramiko import RSAKey, SFTP, SFTPServer, Transport
from paramiko.sftp_path import (
    MAX_NAME,
    MAX_PATH,
    RootedPathResolver,
    SFTPPathError,
)

from ._loop import LoopSocket
from ._stub_sftp import StubServer, StubSFTPServer
from ._util import _support, slow


pytestmark = slow


class TestRootedPathResolver:
    """Deterministic, filesystem-level tests of the containment machinery."""

    def setup_method(self):
        self.tmp = tempfile.mkdtemp(prefix="paramiko-resolver-")
        self.root = os.path.join(self.tmp, "root")
        os.mkdir(self.root)
        os.mkdir(os.path.join(self.root, "sub"))
        self.outside = os.path.join(self.tmp, "outside.txt")
        open(self.outside, "w").write("secret")
        self.resolver = RootedPathResolver(self.root)

    def teardown_method(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_prefix_lookalike_directory_is_not_confused(self):
        # A string-prefix check would confuse /root-evil with /root. Drive
        # the lookalike name through a symlink so real resolution occurs.
        lookalike = self.root + "-evil"
        os.mkdir(lookalike)
        open(os.path.join(lookalike, "x"), "w").write("x")
        os.symlink(lookalike, os.path.join(self.root, "lookalike"))
        with pytest.raises(SFTPPathError) as exc:
            self.resolver.resolve("/lookalike/x")
        assert exc.value.errno == errno.EACCES

    def test_symlink_swap_after_initial_check_is_still_rejected(self):
        # Simulate the concurrent-rename window: a name is first a benign
        # directory entry, then gets swapped for an escaping symlink. The
        # resolver must evaluate the *current* filesystem state on every call.
        name = os.path.join(self.root, "swap")
        os.mkdir(name)
        benign = os.path.join(name, "f.txt")
        open(benign, "w").write("ok")
        assert self.resolver.resolve("/swap/f.txt") == os.path.realpath(benign)
        os.remove(benign)
        os.rmdir(name)
        os.symlink(self.outside, name)
        with pytest.raises(SFTPPathError) as exc:
            self.resolver.resolve("/swap/f.txt")
        assert exc.value.errno == errno.EACCES

    def test_case_variant_stays_inside_root_on_case_folding_fs(self):
        # normcase-based boundary logic must not reject casing variants that
        # legitimately live inside the root.
        target = os.path.join(self.root, "MixedCase.txt")
        open(target, "w").write("x")
        resolved = self.resolver.resolve("/mixedcase.txt")
        assert self.resolver._within_root(resolved)

    def test_normalization_rules(self):
        assert self.resolver.normalize_virtual("a/../b") == "/b"
        assert self.resolver.normalize_virtual("a/./b/") == "/a/b"
        assert (
            self.resolver.normalize_virtual("\\etc\\passwd") == "/etc/passwd"
        )
        nfd = unicodedata.normalize("NFD", "caf\u00e9")
        nfc = unicodedata.normalize("NFC", "caf\u00e9")
        assert self.resolver.normalize_virtual("/" + nfd) == "/" + nfc
        for bad in ("", "   "):
            with pytest.raises(SFTPPathError):
                self.resolver.normalize_virtual(bad)
        with pytest.raises(SFTPPathError):
            self.resolver.normalize_virtual("a\x00b")
        with pytest.raises(SFTPPathError):
            self.resolver.normalize_virtual("/" + "a" * (MAX_PATH + 1))
        with pytest.raises(SFTPPathError):
            self.resolver.normalize_virtual("/" + "a" * (MAX_NAME + 1))

    def test_root_itself_resolves(self):
        assert self.resolver.resolve("/") == self.resolver.root
        assert self.resolver.resolve(".") == self.resolver.root

    def test_link_targets_are_validated_against_root(self):
        # Relative target escaping via traversal.
        rel_escape = os.path.relpath(self.outside, self.root)
        with pytest.raises(SFTPPathError) as exc:
            self.resolver.resolve_link_target("/new_link", rel_escape)
        assert exc.value.errno == errno.EACCES
        # A virtual-absolute target is remapped under the root (it can never
        # name the host file), and backslash traversal is still rejected.
        contained = self.resolver.resolve_link_target(
            "/new_link", "/" + os.path.basename(self.outside)
        )
        assert self.resolver._within_root(contained)
        with pytest.raises(SFTPPathError):
            self.resolver.resolve_link_target(
                "/new_link", rel_escape.replace("/", "\\")
            )
        # A benign in-root target resolves fine.
        open(os.path.join(self.root, "inside.txt"), "w").write("x")
        result = self.resolver.resolve_link_target(
            "/sub/link", "../inside.txt"
        )
        assert result == os.path.join(self.resolver.root, "inside.txt")
        # A self-referencing target is rejected as a loop.
        with pytest.raises(SFTPPathError) as exc:
            self.resolver.resolve_link_target("/self", "self")
        assert exc.value.errno == errno.ELOOP


@pytest.fixture
def rooted_sftp():
    """An SFTP client whose server root is a fresh temporary directory."""
    sandbox_root = tempfile.mkdtemp(prefix="paramiko-sftp-root-")
    outside_dir = tempfile.mkdtemp(prefix="paramiko-sftp-outside-")
    outside_file = os.path.join(outside_dir, "secret.txt")
    with open(outside_file, "w") as fh:
        fh.write("top secret contents\n")

    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    tc = Transport(sockc)
    ts = Transport(socks)
    host_key = RSAKey.from_private_key_file(_support("rsa.key"))
    ts.add_server_key(host_key)
    event = threading.Event()
    ts.set_subsystem_handler(
        "sftp", SFTPServer, StubSFTPServer, sftp_root=sandbox_root
    )
    ts.start_server(event, StubServer())
    event.wait(1.0)
    tc.connect(username="slowdive", password="pygmalion")
    sftp = SFTP.from_transport(tc)

    yield sftp, sandbox_root, outside_dir, outside_file

    sftp.close()
    tc.close()
    ts.close()
    socks.close()
    sockc.close()
    shutil.rmtree(sandbox_root, ignore_errors=True)
    shutil.rmtree(outside_dir, ignore_errors=True)


class TestRootContainment:
    def _denied(self, callable_):
        with pytest.raises(IOError) as exc:
            callable_()
        return exc.value.errno

    def test_dotdot_traversal_cannot_open_outside_file(self, rooted_sftp):
        sftp, root, outside_dir, outside_file = rooted_sftp
        # The classic string-prefix bypass: the normalized virtual path stays
        # rooted, and the host /etc/passwd (or our marker file) is untouched.
        rel = os.path.relpath(outside_file, root)
        info = self._denied(lambda: sftp.open(rel, "r"))
        assert info in (errno.EACCES, errno.ENOENT)
        assert os.path.exists(outside_file)

    def test_dotdot_traversal_stat_list_remove_rename(self, rooted_sftp):
        sftp, root, outside_dir, outside_file = rooted_sftp
        rel = os.path.relpath(outside_file, root)
        assert self._denied(lambda: sftp.stat(rel)) in (
            errno.EACCES,
            errno.ENOENT,
        )
        assert self._denied(lambda: sftp.listdir(outside_dir)) in (
            errno.EACCES,
            errno.ENOENT,
        )
        assert self._denied(lambda: sftp.remove(rel)) in (
            errno.EACCES,
            errno.ENOENT,
        )
        assert self._denied(
            lambda: sftp.rename(rel, "/moved.txt")
        ) in (errno.EACCES, errno.ENOENT)
        assert self._denied(
            lambda: sftp.posix_rename(rel, "/moved.txt")
        ) in (errno.EACCES, errno.ENOENT)
        # Nothing outside the root was created or modified.
        assert not os.path.exists(os.path.join(root, "moved.txt"))
        assert open(outside_file).read() == "top secret contents\n"

    def test_absolute_outside_path_is_contained(self, rooted_sftp):
        sftp, root, outside_dir, outside_file = rooted_sftp
        # A host-absolute path must be interpreted under the root, not at the
        # real host location.
        info = self._denied(lambda: sftp.open(outside_file, "r"))
        assert info in (errno.EACCES, errno.ENOENT)
        with pytest.raises(IOError):
            sftp.stat(outside_file)

    def test_backslash_is_treated_as_separator(self, rooted_sftp):
        sftp, root, outside_dir, outside_file = rooted_sftp
        depth = len(os.path.relpath(outside_file, root).split(os.sep))
        payload = "\\".join([".."] * depth) + "\\secret.txt"
        with pytest.raises(IOError):
            sftp.open(payload, "r")
        assert open(outside_file).read() == "top secret contents\n"

    def test_empty_and_nul_and_oversized_paths_fail(self, rooted_sftp):
        sftp, root, _, _ = rooted_sftp
        for bad in ("", "   "):
            with pytest.raises(IOError):
                sftp.stat(bad)
        with pytest.raises(IOError):
            sftp.open("ok\x00.txt", "r")
        with pytest.raises(IOError):
            sftp.stat("/" + "a" * 5000)
        with pytest.raises(IOError):
            sftp.stat("/" + "b" * 300)

    def test_evil_symlink_to_outside_is_blocked(self, rooted_sftp):
        sftp, root, outside_dir, outside_file = rooted_sftp
        link = os.path.join(root, "evil.txt")
        os.symlink(outside_file, link)
        # stat/open follow the link and must be rejected at the boundary.
        with pytest.raises(IOError) as exc:
            sftp.stat("/evil.txt")
        assert exc.value.errno == errno.EACCES
        with pytest.raises(IOError):
            sftp.open("/evil.txt", "r")
        # remove/rename resolve the link target first, so they are refused too
        # and the outside file is never unlinked or moved.
        with pytest.raises(IOError):
            sftp.remove("/evil.txt")
        with pytest.raises(IOError):
            sftp.rename("/evil.txt", "/evil2.txt")
        assert os.path.islink(link)
        assert not os.path.lexists(os.path.join(root, "evil2.txt"))
        assert open(outside_file).read() == "top secret contents\n"

    def test_lstat_on_in_root_link_still_works(self, rooted_sftp):
        sftp, root, _, _ = rooted_sftp
        with sftp.open("/original.txt", "w") as fh:
            fh.write("inside\n")
        os.symlink(
            os.path.join(root, "original.txt"), os.path.join(root, "link")
        )
        # lstat must inspect the link, not follow it (and still succeed).
        attrs = sftp.lstat("/link")
        assert attrs.st_size == len(os.path.join(root, "original.txt"))
        # Following a safe in-root link continues to work for read ops.
        with sftp.open("/link", "r") as fh:
            assert fh.read() == b"inside\n"

    def test_symlink_creation_targeting_outside_rejected(self, rooted_sftp):
        sftp, root, outside_dir, outside_file = rooted_sftp
        rel_target = os.path.relpath(outside_file, root)
        with pytest.raises(IOError):
            sftp.symlink(rel_target, "/new_evil")
        assert not os.path.lexists(os.path.join(root, "new_evil"))
        # A backslash-smuggled relative target cannot bypass the check.
        depth = len(rel_target.split("/"))
        backslash_target = "\\".join([".."] * (depth - 1)) + "\\secret.txt"
        with pytest.raises(IOError):
            sftp.symlink(backslash_target, "/bs_evil")
        assert not os.path.lexists(os.path.join(root, "bs_evil"))
        # A virtual-absolute target is remapped under the root (chroot
        # semantics) instead of being read at the host location. The created
        # link must therefore dangle inside the root, never touch the host
        # file, and be unreadable via stat.
        virtual_target = "/" + os.path.basename(outside_file)
        sftp.symlink(virtual_target, "/abs_inside")
        link_path = os.path.join(root, "abs_inside")
        assert os.path.islink(link_path)
        with pytest.raises(IOError):
            sftp.stat("/abs_inside")
        os.remove(link_path)
        # Traversal hidden inside a virtual-absolute path is still caught by
        # the boundary check and no link gets created.
        virtual_escape = "/sub/../../" + os.path.basename(outside_file)
        with pytest.raises(IOError):
            sftp.symlink(virtual_escape, "/abs_safe")
        assert not os.path.lexists(os.path.join(root, "abs_safe"))

    def test_symlink_loop_fails_without_reading_target(self, rooted_sftp):
        sftp, root, _, outside_file = rooted_sftp
        loop = os.path.join(root, "loop")
        os.symlink("loop", loop)
        for op in (
            lambda: sftp.stat("/loop"),
            lambda: sftp.open("/loop", "r"),
        ):
            # SFTP v3 has no loop-specific status; the server rejects the
            # request with a generic failure instead of serving loop data.
            with pytest.raises(IOError):
                op()
        # Mutual loop through a subdirectory.
        loopdir = os.path.join(root, "loopdir")
        os.mkdir(loopdir)
        os.symlink(os.path.join(loopdir, "b"), os.path.join(loopdir, "a"))
        os.symlink(os.path.join(loopdir, "a"), os.path.join(loopdir, "b"))
        with pytest.raises(IOError):
            sftp.stat("/loopdir/a")

    def test_relative_paths_spaces_and_unicode_and_root_work(
        self, rooted_sftp
    ):
        sftp, root, _, _ = rooted_sftp
        sftp.mkdir("/sub")
        with sftp.open("sub/../sub/space file.txt", "w") as fh:
            fh.write("spaced\n")
        assert sftp.listdir("/sub") == ["space file.txt"]
        nfc = unicodedata.normalize("NFC", "caf\u00e9.txt")
        nfd = unicodedata.normalize("NFD", "caf\u00e9.txt")
        with sftp.open("/" + nfc, "w") as fh:
            fh.write("unicode\n")
        # NFD spelling must hit the same file.
        assert sftp.stat("/" + nfd).st_size == len("unicode\n")
        # The root directory itself remains listable/stat-able/read-only safe.
        entries = sftp.listdir("/")
        assert "sub" in entries and nfc in entries
        assert sftp.stat("/") is not None
        assert sftp.normalize(".").startswith("/")

    def test_hardlink_inside_root_remains_accessible(self, rooted_sftp):
        sftp, root, _, _ = rooted_sftp
        if not hasattr(os, "link"):
            pytest.skip("hard links not supported on this platform")
        local = os.path.join(root, "original.bin")
        with open(local, "w") as fh:
            fh.write("hard\n")
        os.link(local, os.path.join(root, "alias.bin"))
        with sftp.open("/alias.bin", "r") as fh:
            assert fh.read() == b"hard\n"
        sftp.remove("/alias.bin")
        assert os.path.exists(local)

    def test_concurrent_rename_swap_is_rejected(self, rooted_sftp):
        sftp, root, outside_dir, outside_file = rooted_sftp
        safe_dir = os.path.join(root, "safe")
        os.mkdir(safe_dir)
        with open(os.path.join(safe_dir, "f.txt"), "w") as fh:
            fh.write("ok\n")
        evil_link = os.path.join(root, "swap")
        os.symlink(outside_file, evil_link)

        # First, the benign path works. Then a symlink swap is simulated by
        # resolving both names; the escaping resolution must be rejected even
        # though the benign one was valid moments earlier.
        assert sftp.stat("/safe/f.txt").st_size == 3
        with pytest.raises(IOError) as exc:
            sftp.stat("/swap")
        assert exc.value.errno == errno.EACCES
        # A real rename inside the root still functions afterwards.
        sftp.rename("/safe/f.txt", "/safe/moved.txt")
        assert sftp.stat("/safe/moved.txt").st_size == 3
        assert open(outside_file).read() == "top secret contents\n"

    def test_concurrent_symlink_swap_never_leaks(self, rooted_sftp):
        # Hammer the server from a background thread that alternates the
        # requested name between a benign directory and an escaping symlink.
        # No request may ever return bytes from the outside file.
        sftp, root, outside_dir, outside_file = rooted_sftp
        name = os.path.join(root, "race")
        os.mkdir(name)
        with open(os.path.join(name, "f.txt"), "w") as fh:
            fh.write("ok\n")
        stop = threading.Event()

        def swapper():
            while not stop.is_set():
                try:
                    if os.path.islink(name):
                        os.unlink(name)
                        os.mkdir(name)
                        with open(os.path.join(name, "f.txt"), "w") as fh:
                            fh.write("ok\n")
                    else:
                        shutil.rmtree(name, ignore_errors=True)
                        os.symlink(outside_file, name)
                except OSError:
                    pass

        thread = threading.Thread(target=swapper)
        thread.start()
        leaks = 0
        try:
            for _ in range(500):
                try:
                    with sftp.open("/race/f.txt", "r") as fh:
                        if fh.read() == b"top secret contents\n":
                            leaks += 1
                except IOError:
                    # A rejected swap is the safe outcome.
                    pass
        finally:
            stop.set()
            thread.join()
        assert leaks == 0
        assert open(outside_file).read() == "top secret contents\n"

    def test_no_write_side_effect_outside_root(self, rooted_sftp):
        sftp, root, outside_dir, outside_file = rooted_sftp
        target_outside = os.path.join(outside_dir, "pwned.txt")
        rel = os.path.relpath(target_outside, root)
        with pytest.raises(IOError):
            sftp.open(rel, "w")
        assert not os.path.exists(target_outside)
        # mkdir/rmdir containment.
        rel_dir = os.path.relpath(outside_dir, root)
        with pytest.raises(IOError):
            sftp.mkdir(rel_dir + "/newdir")
        assert not os.path.exists(os.path.join(outside_dir, "newdir"))
        with pytest.raises(IOError):
            sftp.rmdir(rel_dir)
        assert os.path.isdir(outside_dir)

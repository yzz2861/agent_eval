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
Root-directory containment helpers for server-mode SFTP.

Every filesystem path supplied by an SFTP client is treated as untrusted.
Before any handler is allowed to touch the local filesystem, the path goes
through the same pipeline here:

1. decode to text and normalize Unicode (to NFC) and separator characters
   (backslashes become forward slashes),
2. reject empty paths, NUL bytes and paths exceeding the platform limits,
3. map the virtual SFTP path onto the configured per-session root directory,
4. resolve symlinks component by component, detecting link loops,
5. verify (component-wise, never with a string prefix) that the resolved
   path stays inside the root directory.

The working directory of the process is never changed: all mapping is done
by joining under the root and resolving the resulting absolute path.
"""

import errno
import os
import unicodedata

from paramiko.sftp import (
    SFTP_BAD_MESSAGE,
    SFTP_FAILURE,
    SFTP_PERMISSION_DENIED,
)
from paramiko.util import u

# Maximum length of a normalized virtual path and of a single path component.
# These mirror the common POSIX limits and are applied before the filesystem
# is consulted, so an oversized request never reaches the OS.
MAX_PATH = 4096
MAX_NAME = 255

# SFTP v3 has no dedicated symbolic-link-loop status, so a loop is reported
# with the generic FAILURE status (the same code an OS-level ELOOP produces
# through the normal errno translation path).
SFTP_LOOP_STATUS = SFTP_FAILURE


class SFTPPathError(Exception):
    """
    Raised when a client-supplied path cannot be safely mapped inside the
    configured SFTP root directory.

    :ivar int sftp_code: SFTP status code to return to the client.
    :ivar int errno: closest matching ``errno`` value, when applicable.
    """

    def __init__(self, message, sftp_code, errno_code=None):
        super().__init__(message)
        self.sftp_code = sftp_code
        self.errno = errno_code


class RootedPathResolver:
    """
    Resolve untrusted SFTP paths against a fixed root directory.

    One resolver is created per SFTP server (and per server interface), so
    every request of a session is constrained to the same ``root``. The root
    itself is resolved once, up front, via :func:`os.path.realpath`; the
    process working directory is never modified.

    :param str root: absolute local directory that is the SFTP root.
    """

    def __init__(self, root):
        if root is None:
            root = os.getcwd()
        self.root = os.path.realpath(os.path.abspath(u(root)))

    def normalize_virtual(self, path):
        """
        Decode and normalize a client path without touching the filesystem.

        Backslashes are treated as path separators (they are valid filename
        characters on POSIX, so accepting them as separators would let a
        client bypass checks that only understand ``/``), Unicode is folded
        to NFC so NFC/NFD spellings compare equal, and ``.``/``..`` segments
        are collapsed without ever leaving the virtual root.

        :param str path: raw path from the SFTP request.
        :return: an absolute, normalized virtual path beginning with ``/``.
        :raises SFTPPathError: for empty, NUL-containing or oversized paths.
        """
        if path is None:
            raise SFTPPathError(
                "Empty path", SFTP_BAD_MESSAGE, errno.ENOENT
            )
        path = u(path)
        if "\x00" in path:
            raise SFTPPathError(
                "Path contains a NUL byte", SFTP_BAD_MESSAGE, errno.EINVAL
            )
        # Unify separators first so normalization sees a single syntax. On
        # Windows this is the native separator; on POSIX it must not be able
        # to smuggle path components past validation.
        path = path.replace("\\", "/")
        # Fold compatibility/decomposition differences (NFC vs NFD, ligatures
        # and friends) so equivalent spellings cannot dodge comparisons.
        path = unicodedata.normalize("NFC", path)
        if len(path) == 0 or path.strip() == "":
            raise SFTPPathError(
                "Empty path", SFTP_BAD_MESSAGE, errno.ENOENT
            )
        if not os.path.isabs(path):
            path = "/" + path
        normalized = os.path.normpath(path)
        if os.name == "nt":
            normalized = normalized.replace("\\", "/")
        if normalized != "/":
            normalized = normalized.rstrip("/") or "/"
        if len(normalized) > MAX_PATH:
            raise SFTPPathError(
                "Path too long", SFTP_FAILURE, errno.ENAMETOOLONG
            )
        for component in normalized.split("/"):
            if len(component) > MAX_NAME:
                raise SFTPPathError(
                    "File name too long",
                    SFTP_FAILURE,
                    errno.ENAMETOOLONG,
                )
        return normalized

    def local_path(self, virtual_path):
        """
        Map a (normalized) virtual path to an unresolved local path.

        The returned location always sits directly under :attr:`root`; this
        does not resolve symlinks and is intended as the input to
        :meth:`resolve`.
        """
        virtual_path = self.normalize_virtual(virtual_path)
        relative = virtual_path.lstrip("/")
        if not relative:
            return self.root
        return os.path.join(self.root, relative)

    def resolve(self, path):
        """
        Return the safe, symlink-resolved local path for a client request.
        
        :param str path: raw or normalized path from the SFTP request.
        :return: a real local path guaranteed to be inside :attr:`root`.
        :raises SFTPPathError: if the path escapes the root, is missing or
            contains a symbolic-link loop.
        """
        candidate = self.local_path(path)
        return self._resolve(candidate, follow_final=True)

    def resolve_lstat(self, path):
        """
        Resolve a path for an ``lstat``/``readlink`` style request.

        Symlinks in parent directories are resolved (and checked for loops
        and root containment), but the final component is *not* followed,
        so the link itself can be inspected.
        """
        candidate = self.local_path(path)
        return self._resolve(candidate, follow_final=False)

    def resolve_link_target(self, link_path, target):
        """
        Validate the target of a *new* symbolic link before it is created.

        Absolute targets are mapped from the virtual root; relative targets
        are interpreted relative to the directory that will contain the link,
        matching the kernel's interpretation. A target that resolves outside
        the root is rejected even though the link itself would live inside.

        :param str link_path: virtual path at which the link will be created.
        :param str target: raw target string supplied by the client.
        :return: the validated local path the link may point at.
        """
        target = u(target)
        if "\x00" in target:
            raise SFTPPathError(
                "Symlink target contains a NUL byte",
                SFTP_BAD_MESSAGE,
                errno.EINVAL,
            )
        target = unicodedata.normalize("NFC", target.replace("\\", "/"))
        link_local = self.local_path(link_path)
        if os.path.isabs(target):
            # Virtual-absolute target: strip the leading separator, then join
            # *under* the root before normalizing. This makes the root an
            # unbreakable chroot prefix: a leading slash can never name a host
            # location and any surviving traversal is contained by the
            # boundary check below.
            candidate = os.path.normpath(
                os.path.join(self.root, target.lstrip("/"))
            )
        else:
            # Kernel semantics: a relative target is resolved from the
            # directory containing the new link.
            candidate = os.path.normpath(
                os.path.join(os.path.dirname(link_local), target)
            )
        # Reuse the full component walker so a looping or escaping target is
        # caught before the link is ever created. The target may not exist
        # yet (dangling links are legal), so only the existing prefix is
        # resolved and the missing tail is kept verbatim.
        real = self._resolve(candidate, follow_final=True)
        if real == link_local:
            raise SFTPPathError(
                "Symlink would point at itself",
                SFTP_LOOP_STATUS,
                errno.ELOOP,
            )
        return real

    def is_within_root(self, path):
        """Non-raising variant of the containment check for a client path."""
        try:
            self.resolve(path)
        except SFTPPathError:
            return False
        return True

    def _within_root(self, real_path):
        # Component-wise comparison using commonpath: a string prefix check
        # would treat /srv/root-evil as a child of /srv/root. normcase makes
        # the comparison correct on case-insensitive (Windows/macOS) disks.
        root = os.path.normcase(self.root)
        candidate = os.path.normcase(real_path)
        try:
            return os.path.commonpath([root, candidate]) == root
        except ValueError:
            # Different drives (Windows) or otherwise incomparable paths.
            return False

    def _resolve(self, candidate, follow_final):
        # Walk every component under the trusted root, resolving symlinks
        # manually with readlink(). Doing the resolution here (instead of
        # trusting os.path.realpath, which silently keeps loops) lets us
        # reject escapes and link loops before any handler touches a file.
        # normpath first collapses any literal ``..`` segments; the component
        # walk below then deals with symlink-induced traversal.
        candidate = os.path.normpath(candidate)
        # Reject any literal traversal (a ``..`` that normpath could not
        # absorb inside the root) before touching the filesystem.
        if not self._within_root(candidate):
            raise SFTPPathError(
                "Path escapes the SFTP root",
                SFTP_PERMISSION_DENIED,
                errno.EACCES,
            )
        if not hasattr(os, "readlink") or os.name == "nt":
            # Platforms without POSIX symlink semantics: fall back to
            # realpath plus the component-wise containment boundary.
            real = os.path.realpath(candidate)
            if not self._within_root(real):
                raise SFTPPathError(
                    "Path escapes the SFTP root",
                    SFTP_PERMISSION_DENIED,
                    errno.EACCES,
                )
            return real
        relative = os.path.relpath(candidate, self.root)
        if relative == os.curdir:
            return self.root
        current = self.root
        visited = set()
        components = relative.split(os.sep)
        for index, component in enumerate(components):
            current = os.path.join(current, component)
            is_final = index == len(components) - 1
            if is_final and not follow_final:
                # lstat/readlink: keep the final link itself, but its
                # location must still be inside the root.
                if not self._within_root(current):
                    raise SFTPPathError(
                        "Path escapes the SFTP root",
                        SFTP_PERMISSION_DENIED,
                        errno.EACCES,
                    )
                return current
            current = self._follow_symlinks(current, visited)
            if not self._within_root(current):
                raise SFTPPathError(
                    "Path escapes the SFTP root",
                    SFTP_PERMISSION_DENIED,
                    errno.EACCES,
                )
        return current

    def _follow_symlinks(self, path, visited):
        # Follow the symlink chain at one path component. A not-yet-existing
        # tail component (e.g. a file being created) is simply returned.
        while True:
            try:
                identity = os.lstat(path)[0:2]
            except OSError as error:
                if error.errno in (errno.ENOENT, errno.EINVAL, errno.ENOTDIR):
                    return path
                if error.errno == errno.ELOOP:
                    break
                raise SFTPPathError(
                    os.strerror(error.errno),
                    SFTP_LOOP_STATUS,
                    error.errno,
                )
            if not os.path.islink(path):
                return path
            if identity in visited:
                break
            visited.add(identity)
            try:
                target = os.readlink(path)
            except OSError as error:
                raise SFTPPathError(
                    os.strerror(error.errno),
                    SFTP_LOOP_STATUS,
                    error.errno,
                )
            if os.path.isabs(target):
                # Host-absolute link (e.g. /etc/passwd): follow it literally;
                # the containment check on the next iteration rejects it.
                path = os.path.normpath(target)
            else:
                path = os.path.normpath(
                    os.path.join(os.path.dirname(path), target)
                )
            if not self._within_root(path):
                raise SFTPPathError(
                    "Symlink escapes the SFTP root",
                    SFTP_PERMISSION_DENIED,
                    errno.EACCES,
                )
        raise SFTPPathError(
            "Too many levels of symbolic links",
            SFTP_LOOP_STATUS,
            errno.ELOOP,
        )

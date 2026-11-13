# Copyright (C) 2003-2009  Robey Pointer <robeypointer@gmail.com>
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
A stub SFTP server for loopback SFTP testing.
"""

import os

from paramiko import (
    AUTH_SUCCESSFUL,
    OPEN_SUCCEEDED,
    SFTPAttributes,
    SFTPHandle,
    SFTPServer,
    SFTPServerInterface,
    SFTP_FAILURE,
    SFTP_PERMISSION_DENIED,
    SFTP_OK,
    ServerInterface,
)
from paramiko.common import o666
from paramiko.sftp_path import RootedPathResolver, SFTPPathError


class StubServer(ServerInterface):
    def check_auth_password(self, username, password):
        # all are allowed
        return AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED


class StubSFTPHandle(SFTPHandle):
    def stat(self):
        try:
            return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def chattr(self, attr):
        # python doesn't have equivalents to fchown or fchmod, so we have to
        # use the stored filename
        try:
            SFTPServer.set_file_attr(self.filename, attr)
            return SFTP_OK
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)


class StubSFTPServer(SFTPServerInterface):
    # assume current folder is a fine root
    # (the tests always create and eventually delete a subfolder, so there
    # shouldn't be any mess)
    ROOT = os.getcwd()

    def __init__(self, server, *args, sftp_root=None, **kwargs):
        super().__init__(server, *args, **kwargs)
        # Share one root definition with the SFTPServer's own containment
        # layer instead of reconstructing paths with string concatenation.
        self.ROOT = os.path.realpath(sftp_root or self.ROOT)
        self._resolver = RootedPathResolver(self.ROOT)

    def _realpath(self, path, follow_final=True):
        # Map the (already server-validated) virtual path to a real local
        # path, resolving symlinks and re-checking the root boundary right
        # before the caller performs its syscall. This closes the window in
        # which a directory could be renamed or a symlink swapped after the
        # SFTPServer-level check ran.
        if follow_final:
            return self._resolver.resolve(path)
        return self._resolver.resolve_lstat(path)

    def _path_error(self, error):
        # A containment/loop failure discovered immediately before a syscall
        # (e.g. another client swapped a symlink in the meantime) becomes a
        # normal SFTP status instead of an unhandled exception.
        return error.sftp_code

    def list_folder(self, path):
        try:
            path = self._realpath(path)
            out = []
            flist = os.listdir(path)
            for fname in flist:
                attr = SFTPAttributes.from_stat(
                    os.stat(os.path.join(path, fname))
                )
                attr.filename = fname
                out.append(attr)
            return out
        except SFTPPathError as e:
            return self._path_error(e)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def stat(self, path):
        try:
            path = self._realpath(path)
            return SFTPAttributes.from_stat(os.stat(path))
        except SFTPPathError as e:
            return self._path_error(e)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        try:
            path = self._realpath(path, follow_final=False)
            return SFTPAttributes.from_stat(os.lstat(path))
        except SFTPPathError as e:
            return self._path_error(e)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    def open(self, path, flags, attr):
        try:
            path = self._realpath(path)
            binary_flag = getattr(os, "O_BINARY", 0)
            flags |= binary_flag
            mode = getattr(attr, "st_mode", None)
            if mode is not None:
                fd = os.open(path, flags, mode)
            else:
                # os.open() defaults to 0777 which is
                # an odd default mode for files
                fd = os.open(path, flags, o666)
        except SFTPPathError as e:
            return self._path_error(e)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        if (flags & os.O_CREAT) and (attr is not None):
            attr._flags &= ~attr.FLAG_PERMISSIONS
            SFTPServer.set_file_attr(path, attr)
        if flags & os.O_WRONLY:
            if flags & os.O_APPEND:
                fstr = "ab"
            else:
                fstr = "wb"
        elif flags & os.O_RDWR:
            if flags & os.O_APPEND:
                fstr = "a+b"
            else:
                fstr = "r+b"
        else:
            # O_RDONLY (== 0)
            fstr = "rb"
        try:
            f = os.fdopen(fd, fstr)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        fobj = StubSFTPHandle(flags)
        fobj.filename = path
        fobj.readfile = f
        fobj.writefile = f
        return fobj

    def remove(self, path):
        try:
            path = self._realpath(path)
            os.remove(path)
        except SFTPPathError as e:
            return self._path_error(e)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def rename(self, oldpath, newpath):
        try:
            oldpath = self._realpath(oldpath)
            newpath = self._realpath(newpath)
        except SFTPPathError as e:
            return self._path_error(e)
        if os.path.exists(newpath):
            return SFTP_FAILURE
        try:
            os.rename(oldpath, newpath)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def posix_rename(self, oldpath, newpath):
        try:
            oldpath = self._realpath(oldpath)
            newpath = self._realpath(newpath)
        except SFTPPathError as e:
            return self._path_error(e)
        try:
            os.rename(oldpath, newpath)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def mkdir(self, path, attr):
        try:
            path = self._realpath(path)
            os.mkdir(path)
            if attr is not None:
                SFTPServer.set_file_attr(path, attr)
        except SFTPPathError as e:
            return self._path_error(e)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def rmdir(self, path):
        try:
            path = self._realpath(path)
            os.rmdir(path)
        except SFTPPathError as e:
            return self._path_error(e)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def chattr(self, path, attr):
        try:
            path = self._realpath(path)
            SFTPServer.set_file_attr(path, attr)
        except SFTPPathError as e:
            return self._path_error(e)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def symlink(self, target_path, path):
        try:
            path = self._realpath(path, follow_final=False)
            if (len(target_path) > 0) and (target_path[0] == "/"):
                # absolute symlink
                target_path = os.path.normpath(
                    os.path.join(self.ROOT, target_path[1:])
                )
            else:
                # compute relative to path
                abspath = os.path.normpath(
                    os.path.join(os.path.dirname(path), target_path)
                )
                if not self._resolver._within_root(
                    os.path.realpath(abspath)
                ):
                    # the SFTPServer layer already rejects this, but keep the
                    # reference implementation safe on its own as well.
                    return SFTP_PERMISSION_DENIED
            os.symlink(target_path, path)
        except SFTPPathError as e:
            return self._path_error(e)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def readlink(self, path):
        try:
            path = self._realpath(path, follow_final=False)
            symlink = os.readlink(path)
        except SFTPPathError as e:
            return self._path_error(e)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        # if it's absolute, remove the root
        if os.path.isabs(symlink):
            if self._resolver._within_root(os.path.realpath(symlink)):
                symlink = "/" + os.path.relpath(symlink, self.ROOT)
            else:
                symlink = "<error>"
        return symlink

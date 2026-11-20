# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
import tempfile

from .match import match
from .types import TYPES

_DEFAULT_MAX_BYTES = 64 * 1024 * 1024
_CHUNK_SIZE = 64 * 1024
_TEMP_PREFIX = 'filetype-quarantine-'


class QuarantineError(Exception):
    """
    Raised when an object cannot be staged into the quarantine area.
    """


class QuarantineSizeError(QuarantineError):
    """
    Raised when the staged object exceeds the configured byte limit.
    """


class QuarantinedFile(object):
    """
    Identified content staged in the quarantine area.

    Ownership and cleanup contract:
      * The caller owns this object and MUST call close() exactly once
        (directly or via the ``with`` statement) when done.
      * close() closes the exposed file handle and removes the staged
        temporary file. It is idempotent.
      * The library never closes the caller's original input object.

    Attributes:
        kind: matched filetype Type instance.
        path: absolute path of the staged temporary file. Informational
            only; consumers should use ``file``/``read()`` instead of
            re-opening the path.
        file: read-only binary handle to the staged content, positioned
            at offset 0. It yields exactly the bytes that took part in
            type identification.
    """

    def __init__(self, kind, path, fileobj):
        self.kind = kind
        self.path = path
        self.file = fileobj
        self._closed = False

    @property
    def closed(self):
        return self._closed

    def read(self, *args, **kwargs):
        return self.file.read(*args, **kwargs)

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.file.close()
        finally:
            _remove_quietly(self.path)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __repr__(self):
        return 'QuarantinedFile(kind=%r, path=%r)' % (self.kind, self.path)


def quarantine(obj, max_bytes=_DEFAULT_MAX_BYTES, staging_dir=None,
               matchers=TYPES):
    """
    Stages an untrusted object into the quarantine area, identifies its
    type from the staged bytes and hands back a handle to that exact
    content, so downstream consumers never rely on a caller-supplied
    path or extension as proof of type.

    The object is staged by streaming it into a temporary file (up to
    ``max_bytes``), which also works for sequential, non-seekable
    inputs. Identification reuses the standard matchers against the
    staged copy, guaranteeing that the identified bytes and the bytes
    handed to downstream consumers are the same content.

    Args:
        obj: file-like object with read() (seekable or sequential),
            bytes, bytearray or memoryview. Paths are intentionally not
            accepted: open the file and pass the handle instead.
        max_bytes: maximum number of bytes to stage. Reading beyond the
            limit raises QuarantineSizeError. None means unlimited.
        staging_dir: directory used for staged temporary files.
            Defaults to the system temporary directory.
        matchers: matcher list to identify with. Defaults to TYPES.

    Returns:
        A QuarantinedFile if a matcher identified the staged content.
        None if no matcher matched (rejection): the staged temporary
        file has already been removed and nothing consumable remains.

    Raises:
        TypeError: if obj is not a supported input type.
        QuarantineSizeError: if obj exceeds max_bytes.
        QuarantineError: if obj cannot be read or staged.

    Side effects on the original object, in every outcome (success,
    rejection or error): it is only read, sequentially and from its
    current position, consuming at most max_bytes + 1 bytes. It is
    never written to, never seeked and never closed by this function.

    Failure atomicity: if reading or staging fails midway, or the
    content is rejected, the temporary file is removed before this
    function returns or raises, so no partial result is ever
    published. After any rejected or failed call the staging directory
    contains no leftover file from that call.
    """
    if max_bytes is not None and max_bytes < 0:
        raise ValueError('max_bytes must be a non-negative integer or None')

    fd, path = tempfile.mkstemp(prefix=_TEMP_PREFIX, dir=staging_dir)
    try:
        with os.fdopen(fd, 'wb') as dst:
            _stage(obj, dst, max_bytes)
        kind = match(path, matchers)
    except Exception:
        _remove_quietly(path)
        raise

    if kind is None:
        _remove_quietly(path)
        return None

    return QuarantinedFile(kind=kind, path=path, fileobj=open(path, 'rb'))


def _stage(obj, dst, max_bytes):
    if isinstance(obj, (bytes, bytearray, memoryview)):
        data = bytes(obj)
        _check_size(len(data), max_bytes)
        dst.write(data)
        return

    if not hasattr(obj, 'read'):
        raise TypeError('Unsupported type as quarantine input: %s'
                        % type(obj))

    remaining = max_bytes
    while True:
        size = _CHUNK_SIZE if remaining is None \
            else min(_CHUNK_SIZE, remaining + 1)
        try:
            chunk = obj.read(size)
        except Exception as err:
            raise QuarantineError(
                'failed to read quarantine input: %s' % err)
        if not chunk:
            return
        if remaining is not None and len(chunk) > remaining:
            raise QuarantineSizeError(
                'quarantine input exceeds max_bytes limit of %d'
                % max_bytes)
        try:
            dst.write(chunk)
        except Exception as err:
            raise QuarantineError(
                'failed to stage quarantine input: %s' % err)
        if remaining is not None:
            remaining -= len(chunk)


def _check_size(length, max_bytes):
    if max_bytes is not None and length > max_bytes:
        raise QuarantineSizeError(
            'quarantine input exceeds max_bytes limit of %d' % max_bytes)


def _remove_quietly(path):
    try:
        os.remove(path)
    except OSError:
        pass

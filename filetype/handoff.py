# -*- coding: utf-8 -*-

from __future__ import absolute_import

import hashlib
import os

from .filetype import guess


_READ_CHUNK_SIZE = 1024 * 1024


class HandoffError(Exception):
    """Base exception for file handoff failures."""


class HandoffNotFound(HandoffError):
    """Raised when a handoff object cannot be found."""


class HandoffStateError(HandoffError):
    """Raised when a handoff operation is not valid in the current state."""


class HandoffIntegrityError(HandoffError):
    """Raised when a file no longer matches its handoff identity."""


def fingerprint_bytes(data):
    """Returns the SHA-256 fingerprint for a bytes-like value."""
    return hashlib.sha256(bytes(data)).hexdigest()


def fingerprint_file(path):
    """Streams a file from disk and returns its SHA-256 fingerprint."""
    digest = hashlib.sha256()
    with open(path, 'rb') as fp:
        for chunk in iter(lambda: fp.read(_READ_CHUNK_SIZE), b''):
            digest.update(chunk)
    return digest.hexdigest()


class RecognitionSummary(object):
    """Immutable file type information captured when a file is registered."""

    def __init__(self, mime, extension, signature):
        self.__mime = mime
        self.__extension = extension
        self.__signature = bytes(bytearray(signature))

    @classmethod
    def from_file(cls, path):
        kind = guess(path)
        if kind is None:
            return None

        with open(path, 'rb') as fp:
            signature = fp.read(8192)
        return cls(kind.mime, kind.extension, signature)

    @property
    def mime(self):
        return self.__mime

    @property
    def extension(self):
        return self.__extension

    @property
    def signature(self):
        return self.__signature

    def __eq__(self, other):
        if not isinstance(other, RecognitionSummary):
            return NotImplemented
        return (
            self.mime == other.mime
            and self.extension == other.extension
            and self.signature == other.signature
        )

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self.__mime, self.__extension, self.__signature))

    def __repr__(self):
        return 'RecognitionSummary(mime=%r, extension=%r)' % (
            self.__mime, self.__extension
        )


class HandoffObject(object):
    """Verifiable identity, recognition summary and byte source for one file."""

    def __init__(self, handoff_id, digest, summary, registry):
        self.__id = handoff_id
        self.__digest = digest
        self.__summary = summary
        self.__registry = registry

    @property
    def id(self):
        return self.__id

    @property
    def source_path(self):
        return self.__registry.get_path(self.__id)

    @property
    def fingerprint(self):
        return self.__digest

    @property
    def summary(self):
        return self.__summary

    @property
    def approved(self):
        return self.__registry.is_approved(self.__id)

    def approve(self):
        self.__registry.approve(self.__id)

    def cancel(self):
        self.__registry.cancel(self.__id)

    def locate(self, path):
        """Binds this identity to the path where the file was moved."""
        self.__registry.relocate(self.__id, path)

    def read_bytes(self, path=None):
        """Returns current bytes after optional relocation and verification."""
        if path is not None:
            self.locate(path)
        return self.__registry.read_bytes(self.__id)

    def verify(self):
        """Returns True when the current file still has this identity."""
        return self.__registry.verify(self.__id)

    def __eq__(self, other):
        if not isinstance(other, HandoffObject):
            return NotImplemented
        return self.__id == other.__id and self.__registry is other.__registry

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self.__registry, self.__id))

    def __repr__(self):
        return 'HandoffObject(id=%r, source_path=%r, fingerprint=%r)' % (
            self.__id, self.source_path, self.__digest
        )


class HandoffRegistry(object):
    """In-memory registry controlling handoff approval and consumption."""

    def __init__(self):
        self.__records = {}
        self.__paths = {}
        self.__next_id = 1

    def register(self, path):
        """Recognizes a path and creates a new, initially unapproved handoff."""
        absolute_path = os.path.abspath(path)
        digest = fingerprint_file(absolute_path)
        summary = RecognitionSummary.from_file(absolute_path)
        if summary is None:
            raise HandoffError('File type could not be recognized: %s' % path)

        handoff_id = self.__next_id
        self.__next_id += 1
        self.__records[handoff_id] = {
            'path': absolute_path,
            'fingerprint': digest,
            'summary': summary,
            'approved': False,
        }
        self.__paths[absolute_path] = handoff_id
        return HandoffObject(handoff_id, digest, summary, self)

    def get(self, handoff_id):
        record = self.__record(handoff_id)
        return HandoffObject(
            handoff_id,
            record['fingerprint'],
            record['summary'],
            self,
        )

    def get_path(self, handoff_id):
        return self.__record(handoff_id)['path']

    def get_by_path(self, path):
        handoff_id = self.__paths.get(os.path.abspath(path))
        if handoff_id is None:
            raise HandoffNotFound('No handoff registered for path: %s' % path)
        return self.get(handoff_id)

    def approve(self, handoff_id):
        self.__record(handoff_id)['approved'] = True

    def cancel(self, handoff_id):
        record = self.__record(handoff_id)
        record['approved'] = False
        self.__paths.pop(record['path'], None)

    def is_approved(self, handoff_id):
        return self.__record(handoff_id)['approved']

    def relocate(self, handoff_id, path):
        record = self.__record(handoff_id)
        old_path = record['path']
        absolute_path = os.path.abspath(path)

        if fingerprint_file(absolute_path) != record['fingerprint']:
            raise HandoffIntegrityError(
                'File at path does not match handoff identity: %s' % path
            )

        self.__paths.pop(old_path, None)
        record['path'] = absolute_path
        self.__paths[absolute_path] = handoff_id

    def verify(self, handoff_id):
        record = self.__record(handoff_id)
        if not os.path.isfile(record['path']):
            return False
        return fingerprint_file(record['path']) == record['fingerprint']

    def read_bytes(self, handoff_id):
        record = self.__record(handoff_id)
        if not record['approved']:
            raise HandoffStateError('Handoff is not approved: %s' % handoff_id)

        path = record['path']
        if not os.path.isfile(path):
            raise HandoffIntegrityError(
                'Handoff file is no longer available: %s' % path
            )

        digest = fingerprint_file(path)
        if digest != record['fingerprint']:
            raise HandoffIntegrityError(
                'File content does not match handoff identity: %s' % path
            )

        with open(path, 'rb') as fp:
            return fp.read()

    def __record(self, handoff_id):
        try:
            return self.__records[handoff_id]
        except KeyError:
            raise HandoffNotFound(
                'Unknown handoff object: %s' % handoff_id
            )

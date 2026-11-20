#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""
Single-source incremental handoff for partially collected EVTX files.

A host collector snapshots an ``.evtx`` file every few seconds.  The last
chunk in a snapshot may still be held open by the event log service and
therefore only partially written.  Re-ingesting every snapshot would
duplicate records, while ingesting an unfinished chunk would hand off data
that can still change underneath us.

This module implements a single-source, resumable handoff loop:

* only chunks whose magic and checksum verify (and therefore cannot be
  rewritten in place) are handed off; an unfinished tail chunk is deferred
  until a later snapshot proves it stable;
* a :class:`Checkpoint` binds the source identifier to the byte range that
  has already been confirmed with the evidence store, together with a digest
  of that range, so any rewrite of previously confirmed bytes is detected as
  an explicit fork;
* every record carries a stable :func:`handoff_key` derived solely from the
  source identifier and the record's physical position, which lets the store
  safely deduplicate retries when an acknowledgement is lost.
"""
from __future__ import absolute_import

import hashlib
import json
import mmap
from dataclasses import dataclass

from .Evtx import ChunkHeader

HEADER_SIZE = 0x1000
CHUNK_SIZE = 0x10000


class IncrementalException(Exception):
    """Base class for failures raised by the incremental handoff logic."""


class ForkDetectedError(IncrementalException):
    """
    Raised when the bytes previously confirmed for a source no longer match
    the checkpoint, i.e. the source content was rewritten instead of merely
    appended to.
    """


def handoff_key(source_id, chunk_offset, record_offset, record_num):
    """
    Build the stable key under which a record is known to the evidence store.

    The key is a pure function of the source identifier and the physical
    position of the record, so re-reading the same (stable) material always
    produces the same key even if an earlier handoff acknowledgement was
    lost and the handoff has to be retried.

    Args:
      source_id (str): stable identifier of the EVTX source.
      chunk_offset (int): absolute file offset of the chunk header.
      record_offset (int): absolute file offset of the record.
      record_num (int): the ``EventRecordID`` stored in the record.

    Returns:
      str: a hex digest safe to use as a dictionary key.
    """
    identity = "evtx:{}:chunk={}:record={}:num={}".format(
        source_id, chunk_offset, record_offset, record_num
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RecordLocator:
    """
    Physical position of a handed-off record, sufficient to find it again.

    Attributes:
      source_id (str): stable identifier of the EVTX source.
      chunk_offset (int): absolute file offset of the containing chunk.
      record_offset (int): absolute file offset of the record.
      record_num (int): the ``EventRecordID`` stored in the record.
    """

    source_id: str
    chunk_offset: int
    record_offset: int
    record_num: int

    @property
    def key(self):
        """The stable handoff key (see :func:`handoff_key`)."""
        return handoff_key(
            self.source_id, self.chunk_offset, self.record_offset, self.record_num
        )

    def as_dict(self):
        return {
            "source_id": self.source_id,
            "chunk_offset": self.chunk_offset,
            "record_offset": self.record_offset,
            "record_num": self.record_num,
            "handoff_key": self.key,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            source_id=d["source_id"],
            chunk_offset=d["chunk_offset"],
            record_offset=d["record_offset"],
            record_num=d["record_num"],
        )


class Checkpoint(object):
    """
    Immutable handoff state for one EVTX source.

    The checkpoint binds:

    * ``source_id`` - the source this state belongs to; a different source
      must never resume from this checkpoint;
    * ``confirmed_end`` - the absolute byte offset up to which every chunk has
      been confirmed with the evidence store.  It is always chunk aligned
      (the file header itself is never confirmed content);
    * ``digest`` - a running SHA-256 over the confirmed byte range, which
      makes any rewrite of confirmed bytes visible as a fork.
    """

    FORMAT = "python-evtx-incremental-checkpoint/v1"

    def __init__(self, source_id, confirmed_end=HEADER_SIZE, digest=None):
        self._source_id = source_id
        self._confirmed_end = confirmed_end
        self._digest = digest or hashlib.sha256(b"").hexdigest()

    @classmethod
    def initial(cls, source_id):
        """Return the empty checkpoint for a freshly observed source."""
        return cls(source_id, HEADER_SIZE, hashlib.sha256(b"").hexdigest())

    @property
    def source_id(self):
        return self._source_id

    @property
    def confirmed_end(self):
        return self._confirmed_end

    @property
    def digest(self):
        return self._digest

    def advance(self, confirmed_end, chunk_data):
        """
        Return a checkpoint covering one additional confirmed chunk.

        Args:
          confirmed_end (int): new absolute end offset of confirmed bytes.
          chunk_data (bytes): the raw bytes of the newly confirmed chunk.

        Returns:
          Checkpoint: the updated checkpoint.
        """
        new_digest = hashlib.sha256(bytes.fromhex(self._digest) + chunk_data)
        return Checkpoint(self._source_id, confirmed_end, new_digest.hexdigest())

    @staticmethod
    def _chain_digest(digest_hex, chunk_data):
        """Extend the running digest chain with one confirmed chunk."""
        return hashlib.sha256(bytes.fromhex(digest_hex) + bytes(chunk_data)).hexdigest()

    def verify(self, source_id, buf):
        """
        Ensure the buffer is a continuation of the confirmed source.

        Raises :class:`ForkDetectedError` if the caller presents a different
        source, if previously confirmed bytes were truncated, or if the
        confirmed byte range was rewritten.
        """
        if source_id != self._source_id:
            raise ForkDetectedError(
                "checkpoint belongs to source {!r}, not {!r}".format(self._source_id, source_id)
            )
        if len(buf) < self._confirmed_end:
            raise ForkDetectedError(
                "source truncated: {} bytes present, {} previously confirmed".format(
                    len(buf), self._confirmed_end
                )
            )
        # Replay the per-chunk digest chain so the check stays incremental
        # and matches the digests produced by `advance`.
        observed = hashlib.sha256(b"").hexdigest()
        offset = HEADER_SIZE
        while offset < self._confirmed_end:
            observed = self._chain_digest(observed, buf[offset : offset + CHUNK_SIZE])
            offset += CHUNK_SIZE
        if observed != self._digest:
            raise ForkDetectedError(
                "confirmed byte range [{}, {}) was rewritten for source {!r}".format(
                    HEADER_SIZE, self._confirmed_end, source_id
                )
            )

    def to_json(self):
        return json.dumps(
            {
                "format": self.FORMAT,
                "source_id": self._source_id,
                "confirmed_end": self._confirmed_end,
                "digest": self._digest,
            },
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, text):
        d = json.loads(text)
        if d.get("format") != cls.FORMAT:
            raise IncrementalException("unsupported checkpoint format: {!r}".format(d.get("format")))
        return cls(d["source_id"], d["confirmed_end"], d["digest"])


class InMemoryEvidenceStore(object):
    """
    A minimal evidence store backed by an in-memory dictionary.

    Writes are idempotent on the stable handoff key: retrying a handoff whose
    acknowledgement was lost returns the existing entry instead of creating a
    second copy.
    """

    def __init__(self):
        self._entries = {}

    def put(self, key, entry):
        """
        Store an entry under its handoff key.

        Args:
          key (str): the stable handoff key.
          entry (dict): the record payload and locator.

        Returns:
          bool: ``True`` if a new entry was created, ``False`` if an entry
          with the same key was already present (a safe retry).

        Raises:
          IncrementalException: if the same key refers to conflicting
            content, which would indicate a key collision or corruption.
        """
        existing = self._entries.get(key)
        if existing is not None:
            if existing != entry:
                raise IncrementalException("conflicting entries for handoff key {}".format(key))
            return False
        self._entries[key] = entry
        return True

    def get(self, key):
        """Return the entry stored under ``key`` or ``None``."""
        return self._entries.get(key)

    def __contains__(self, key):
        return key in self._entries

    def __len__(self):
        return len(self._entries)

    def keys(self):
        return self._entries.keys()


@dataclass(frozen=True)
class HandoffRecord:
    """
    One record handed off during a scan.

    Attributes:
      locator (RecordLocator): physical position of the record.
      entry (dict): the payload stored in the evidence store.
      created (bool): whether the store created a new entry (``False`` when
        the record was already present, e.g. during a retried handoff).
    """

    locator: RecordLocator
    entry: dict
    created: bool


def _is_stable_chunk(chunk, chunk_end, buf_len):
    """
    A chunk is stable evidence only when it is fully present and its magic
    plus header/data checksums verify.  A partially written tail chunk fails
    these checks and is deferred to a later snapshot.
    """
    if chunk_end > buf_len:
        return False
    try:
        return chunk.check_magic() and chunk.verify()
    except Exception:
        return False


def handoff_incremental(source_id, buf, store, checkpoint=None, serializer=None):
    """
    Hand off all newly stable records of a single EVTX source.

    Only complete, checksum-verified chunks are considered.  Records inside
    them are written to ``store`` under a stable handoff key, which makes the
    operation safe to retry.  The unfinished tail chunk, if any, is left
    untouched until a subsequent snapshot contains a verifiable copy.

    Args:
      source_id (str): stable identifier of the EVTX source.
      buf (bytes-like): the current snapshot of the EVTX file (e.g. an
        ``mmap`` or ``bytes``).
      store (InMemoryEvidenceStore): destination evidence store.
      checkpoint (Checkpoint): the last confirmed checkpoint, or ``None`` for
        a first observation.
      serializer (Callable[[Record], dict]): optional custom payload builder.
        By default the rendered XML and raw record bytes are stored.

    Returns:
      tuple(Iterator[HandoffRecord], Checkpoint): the records handed off
      during this scan and the new checkpoint covering every confirmed
      chunk.
    """
    if checkpoint is None:
        checkpoint = Checkpoint.initial(source_id)
    checkpoint.verify(source_id, buf)

    handed_off = []
    current = checkpoint
    chunk_offset = current.confirmed_end

    while chunk_offset + CHUNK_SIZE <= len(buf):
        chunk_end = chunk_offset + CHUNK_SIZE
        chunk = ChunkHeader(buf, chunk_offset)
        if not _is_stable_chunk(chunk, chunk_end, len(buf)):
            # Unstable tail: wait for a later snapshot to complete it.
            break

        for record in chunk.records():
            record_offset = record.offset()
            locator = RecordLocator(source_id, chunk_offset, record_offset, record.record_num())
            if serializer is not None:
                payload = serializer(record)
            else:
                payload = {"xml": record.xml(), "data": record.data().hex()}
            entry = {"locator": locator.as_dict(), "payload": payload}
            created = store.put(locator.key, entry)
            handed_off.append(HandoffRecord(locator, entry, created))

        # The whole chunk is confirmed: only now advance the checkpoint.
        current = current.advance(chunk_end, bytes(buf[chunk_offset:chunk_end]))
        chunk_offset = chunk_end

    return iter(handed_off), current


def handoff_file_incremental(source_id, path, store, checkpoint=None, serializer=None):
    """
    File-based variant of :func:`handoff_incremental`.

    Opens ``path`` read-only via ``mmap`` and delegates to
    :func:`handoff_incremental`.
    """
    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as buf:
            return handoff_incremental(source_id, buf, store, checkpoint, serializer)

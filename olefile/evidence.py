"""
Offline evidence query for OLE2 compound documents.

This module builds an offline query index on top of olefile's existing
directory reading (OleFileIO.listdir) and stream locating
(OleFileIO._find / OleFileIO.openstream) capabilities.

Use case: several compound documents are kept as preserved evidence.  Two of
them may expose the *same* stream name (for example one stream living in a
root storage approved for handover, and another stream with the identical
name found in a restricted copy).  This module combines:

- preservation clearances (who may see which evidence),
- a provenance index (which document holds which stream, with hashes),
- excerpt records (approved byte ranges retained from each stream),

and answers queries such as "which preserved documents hold this stream, and
over which byte range can the retained excerpts confirm the content?".

Important properties:

- A matching stream *name* never implies matching *content*: consistency is
  only reported from hashes computed over the confirmable range.
- Callers with different clearances receive different indexes.  Entries a
  caller is not cleared for are replaced by keyed HMAC pseudonyms, so the
  caller cannot infer the hidden stream names from the output.
"""

from __future__ import print_function

import hashlib
import hmac
import os

from .olefile import OleFileIO, isOleFile


# --- Preservation clearance levels (ordered) --------------------------------

#: caller cleared for material approved for handover only
CLEARANCE_HANDOVER = 1
#: caller cleared for restricted copies
CLEARANCE_RESTRICTED = 2
#: caller cleared for the full preserved custody
CLEARANCE_CUSTODIAN = 3

_CLEARANCE_NAMES = {
    CLEARANCE_HANDOVER: 'handover',
    CLEARANCE_RESTRICTED: 'restricted',
    CLEARANCE_CUSTODIAN: 'custodian',
}


def _normalise_path(stream_path):
    """
    Convert a stream path (string with '/' separators or sequence of names)
    to a normalised tuple of lower-case names, matching olefile's
    case-insensitive stream lookup.
    """
    if isinstance(stream_path, str):
        parts = [p for p in stream_path.split('/') if p]
    else:
        parts = [str(p) for p in stream_path]
    if not parts:
        raise ValueError('empty stream path')
    return tuple(p.lower() for p in parts)


def _display_path(path_key):
    return '/'.join(path_key)


class ExcerptRecord(object):
    """
    An approved excerpt (byte range) retained from one stream of one
    preserved document.

    :param record_id: unique identifier of this excerpt record
    :param evidence_id: identifier of the preserved document it belongs to
    :param stream_path: path of the stream inside the document
        (string 'storage/stream' or sequence of names)
    :param offset: first byte of the retained excerpt
    :param length: number of bytes retained
    :param clearance: minimum clearance required to use this record
    :param approved: whether preservation approved retaining this excerpt
    """

    def __init__(self, record_id, evidence_id, stream_path, offset, length,
                 clearance=CLEARANCE_CUSTODIAN, approved=True):
        if offset < 0:
            raise ValueError('excerpt offset must be >= 0')
        if length <= 0:
            raise ValueError('excerpt length must be > 0')
        self.record_id = record_id
        self.evidence_id = evidence_id
        self.stream_key = _normalise_path(stream_path)
        self.offset = offset
        self.length = length
        self.clearance = clearance
        self.approved = approved

    @property
    def end(self):
        'first byte after the excerpt'
        return self.offset + self.length

    def visible_to(self, clearance):
        return self.approved and clearance >= self.clearance


class _StreamEvidence(object):
    'Internal record for one stream of one preserved document.'

    __slots__ = ('evidence_id', 'path', 'stream_key', 'size', 'sha256',
                 'data', 'min_clearance', 'handover_allowed')

    def __init__(self, evidence_id, path, data, min_clearance,
                 handover_allowed):
        self.evidence_id = evidence_id
        self.path = list(path)
        self.stream_key = _normalise_path(path)
        self.size = len(data)
        self.sha256 = hashlib.sha256(data).hexdigest()
        # bytes are kept private to the index; query output only exposes
        # hashes, never raw content
        self.data = data
        self.min_clearance = min_clearance
        self.handover_allowed = handover_allowed

    def effective_clearance(self):
        if self.handover_allowed:
            return min(self.min_clearance, CLEARANCE_HANDOVER)
        return self.min_clearance

    def visible_to(self, clearance):
        return clearance >= self.effective_clearance()


class EvidenceIndex(object):
    """
    Offline evidence index over preserved OLE2 compound documents.

    Documents are registered once (the OLE files are not needed afterwards),
    then all queries are answered offline from the preserved data.

    :param pseudonym_key: secret key used to pseudonymise entries a caller
        is not cleared for.  If None, a random key is generated.  The key
        must stay private to the indexing party: because stream names have
        low entropy, only a keyed HMAC prevents a caller from inferring a
        hidden stream name by dictionary guessing.
    """

    def __init__(self, pseudonym_key=None):
        if pseudonym_key is None:
            pseudonym_key = os.urandom(32)
        if not isinstance(pseudonym_key, bytes):
            pseudonym_key = pseudonym_key.encode('utf-8')
        self._key = pseudonym_key
        self._streams = []       # list of _StreamEvidence
        self._excerpts = []      # list of ExcerptRecord
        self._evidence_ids = {}  # evidence_id -> min_clearance

    # -- registration ---------------------------------------------------------

    def register_document(self, evidence_id, ole, min_clearance,
                          handover_allowed=False):
        """
        Register a preserved compound document into the index.

        Uses olefile's directory reading (listdir) and stream locating
        (_find / openstream) to capture every stream's content, size and
        digest.  The document is not needed after registration.

        :param evidence_id: identifier of the preserved document
        :param ole: an open OleFileIO instance, or a filename/data accepted
            by OleFileIO
        :param min_clearance: clearance required to query this document
        :param handover_allowed: True if the document's root storage is
            approved for handover (its streams become visible at
            CLEARANCE_HANDOVER)
        :returns: number of streams registered
        """
        close_after = False
        if not isinstance(ole, OleFileIO):
            if not isOleFile(ole):
                raise IOError('not an OLE2 compound document: %r' % (ole,))
            ole = OleFileIO(ole)
            close_after = True
        try:
            count = 0
            for path in ole.listdir(streams=True, storages=False):
                # locate the entry in the directory tree, then read it
                sid = ole._find(path)
                entry = ole.direntries[sid]
                with ole.openstream(path) as fp:
                    data = fp.read()
                if len(data) != entry.size:
                    raise IOError('stream size mismatch for %r' % (path,))
                self._streams.append(_StreamEvidence(
                    evidence_id, path, data, min_clearance,
                    handover_allowed))
                count += 1
        finally:
            if close_after:
                ole.close()
        self._evidence_ids[evidence_id] = min_clearance
        return count

    def add_excerpt(self, record):
        'Add an approved ExcerptRecord to the index.'
        if not isinstance(record, ExcerptRecord):
            raise TypeError('expected an ExcerptRecord')
        self._excerpts.append(record)

    # -- pseudonymisation -----------------------------------------------------

    def _pseudonym(self, evidence_id, stream_key):
        msg = ('%s\x00%s' % (evidence_id, _display_path(stream_key)))
        return hmac.new(self._key, msg.encode('utf-8'),
                        hashlib.sha256).hexdigest()

    # -- queries --------------------------------------------------------------

    def provenance_index(self, clearance):
        """
        Provenance index as visible to a caller with the given clearance.

        Visible entries carry the real evidence id, stream path, size and
        SHA-256 digest.  Hidden entries are replaced by keyed pseudonyms
        that reveal neither the evidence id nor the stream name.

        :returns: dict with keys 'clearance', 'entries', 'redacted'
        """
        entries = []
        redacted = []
        for ev in self._streams:
            if ev.visible_to(clearance):
                entries.append({
                    'evidence_id': ev.evidence_id,
                    'stream': list(ev.path),
                    'size': ev.size,
                    'sha256': ev.sha256,
                    'handover_allowed': ev.handover_allowed,
                })
            else:
                redacted.append({
                    'token': self._pseudonym(ev.evidence_id, ev.stream_key),
                    'min_clearance': ev.effective_clearance(),
                })
        entries.sort(key=lambda e: (e['evidence_id'], e['stream']))
        redacted.sort(key=lambda e: e['token'])
        return {
            'clearance': clearance,
            'entries': entries,
            'redacted': redacted,
        }

    def confirmable_range(self, stream_path, clearance):
        """
        Intersection of the approved excerpt ranges retained for the given
        stream, limited to records visible to the caller.

        :returns: (start, end) tuple, or None if no visible approved
            excerpt covers the stream or the excerpts do not overlap
        """
        key = _normalise_path(stream_path)
        start = None
        end = None
        for rec in self._excerpts:
            if rec.stream_key != key or not rec.visible_to(clearance):
                continue
            if start is None:
                start, end = rec.offset, rec.end
            else:
                start = max(start, rec.offset)
                end = min(end, rec.end)
        if start is None or end is None or start >= end:
            return None
        return (start, end)

    def query_stream(self, stream_path, clearance):
        """
        Combined offline query for one stream name.

        Merges preservation permissions, the provenance index and the
        excerpt records.  Content consistency is reported only when at
        least two visible documents hold the stream *and* an overlapping
        confirmable range exists; identical names alone never count as
        identical content.

        :returns: dict describing visible/hidden matches, the confirmable
            range and the consistency verdict
        """
        key = _normalise_path(stream_path)
        visible = []
        redacted = []
        for ev in self._streams:
            if ev.stream_key != key:
                continue
            if ev.visible_to(clearance):
                visible.append(ev)
            else:
                redacted.append({
                    'token': self._pseudonym(ev.evidence_id, ev.stream_key),
                    'min_clearance': ev.effective_clearance(),
                })
        redacted.sort(key=lambda e: e['token'])

        notes = []
        confirmable = self.confirmable_range(key, clearance)
        range_hashes = {}
        consistent = None

        if confirmable is None:
            notes.append('no overlapping approved excerpt range: content '
                         'cannot be confirmed from the retained excerpts')
        else:
            start, end = confirmable
            for ev in visible:
                clamped_end = min(end, ev.size)
                if start >= clamped_end:
                    notes.append('confirmable range exceeds stream size in '
                                 'evidence %r' % (ev.evidence_id,))
                    continue
                digest = hashlib.sha256(ev.data[start:clamped_end])
                range_hashes[ev.evidence_id] = digest.hexdigest()

        if len(visible) < 2:
            notes.append('fewer than two visible sources hold this stream '
                         'name: identical names do not establish identical '
                         'content')
        elif confirmable is not None and len(range_hashes) == len(visible):
            digests = set(range_hashes.values())
            consistent = (len(digests) == 1)
            if consistent:
                notes.append('content digests match over the confirmable '
                             'range')
            else:
                notes.append('content digests differ over the confirmable '
                             'range despite the identical stream name')

        return {
            'stream': _display_path(key),
            'clearance': clearance,
            'visible': [{
                'evidence_id': ev.evidence_id,
                'stream': list(ev.path),
                'size': ev.size,
                'sha256': ev.sha256,
                'handover_allowed': ev.handover_allowed,
            } for ev in visible],
            'redacted': redacted,
            'redacted_count': len(redacted),
            'confirmable_range': confirmable,
            'range_sha256': range_hashes,
            'content_consistent': consistent,
            'notes': notes,
        }

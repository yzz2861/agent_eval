# -*- coding: utf-8 -*-

"""
Read-only, layered file type inspection.

This module sits next to the regular :mod:`filetype.match` matchers. It never
opens a container itself: a caller-supplied :class:`ContainerAdapter` exposes
the local reading strategy, while the engine only walks the layers and runs
the existing signature matchers.

Every traversed layer is reported with the signature bytes that were actually
read as evidence, together with the type declared by the container entry.
A layer whose child is claimed by an upper layer but cannot be backed by read
evidence is reported as :data:`PENDING` ("needs further check") instead of
being guessed from its declared name.
"""

from __future__ import absolute_import

from collections import namedtuple

from .match import archive_match, match
from .utils import get_bytes


# Signature confirmed a supported file type.
IDENTIFIED = 'identified'

# Signature bytes were read, but no matcher accepts them.
UNKNOWN = 'unknown'

# An upper layer claims the entry, but no read evidence is available.
PENDING = 'pending'


class Entry(namedtuple('Entry', ('reference', 'name',
                                 'declared_mime', 'declared_extension'))):
    """
    Descriptor of a single member as it is declared by its parent container.

    Attributes:
        reference: adapter-specific locator used to read the member.
        name: member name as declared inside the container.
        declared_mime: declared MIME type, if any. Otherwise None.
        declared_extension: declared file extension, if any. Otherwise None.

    Entries are intentionally generic: two archives may carry members sharing
    the exact same ``name`` while pointing at different ``reference`` values.
    """

    __slots__ = ()

    def __new__(cls, reference, name,
                declared_mime=None, declared_extension=None):
        return super(Entry, cls).__new__(
            cls, reference, name, declared_mime, declared_extension
        )


class ContainerAdapter(object):
    """
    Local read-only adapter protocol implemented by the caller.

    Subclasses describe how a specific container format (zip, tar, a custom
    archive room format...) is enumerated and read. The inspection engine
    treats this object as the only source of bytes and never performs its own
    file system access, so the whole traversal stays strictly read-only.
    """

    def children(self, entry):
        """
        Returns an iterable of :class:`Entry` declared inside ``entry``.

        Return an empty iterable for leaf entries. Raising an exception
        signals that the claimed children cannot be enumerated, which the
        engine records as a pending layer.
        """
        raise NotImplementedError

    def read_signature(self, entry):
        """
        Reads the header signature bytes of ``entry``.

        Returns:
            bytes, bytearray, memoryview or a file-like object holding the
            header of the member. Return None or an empty buffer when the
            member is claimed but no local read evidence exists.
        """
        raise NotImplementedError

    def is_truncated(self, entry):
        """
        Returns True when the member is known to be cut short on storage.

        Defaults to False; adapters with a local size/header check should
        override it so the report can distinguish a trimmed candidate.
        """
        return False


class LayerRecord(object):
    """
    Immutable inspection result for one container layer.

    Attributes:
        depth: zero-based depth of the layer inside the traversal.
        path: tuple of declared names from the root to this layer.
        entry: :class:`Entry` descriptor supplied by the adapter.
        index: ordinal position among the children of the same parent.
        signature: bytearray of the bytes actually read as evidence.
        truncated: whether the adapter reports the member as trimmed.
        kind: matched filetype Type instance. None unless identified.
        status: one of :data:`IDENTIFIED`, :data:`UNKNOWN`, :data:`PENDING`.
        reason: short human-readable explanation of the status.
    """

    __slots__ = (
        '_depth', '_path', '_entry', '_index', '_signature',
        '_truncated', '_kind', '_status', '_reason'
    )

    def __init__(self, depth, path, entry, index, signature,
                 truncated, kind, status, reason):
        self._depth = depth
        self._path = tuple(path)
        self._entry = entry
        self._index = index
        self._signature = bytearray(signature)
        self._truncated = truncated
        self._kind = kind
        self._status = status
        self._reason = reason

    @property
    def depth(self):
        return self._depth

    @property
    def path(self):
        return self._path

    @property
    def entry(self):
        return self._entry

    @property
    def index(self):
        return self._index

    @property
    def signature(self):
        return self._signature

    @property
    def truncated(self):
        return self._truncated

    @property
    def kind(self):
        return self._kind

    @property
    def status(self):
        return self._status

    @property
    def reason(self):
        return self._reason

    @property
    def name(self):
        return self._path[-1] if self._path else ''

    @property
    def declared_mime(self):
        return self._entry.declared_mime

    @property
    def declared_extension(self):
        return self._entry.declared_extension

    @property
    def mime(self):
        return self._kind.mime if self._kind else None

    @property
    def extension(self):
        return self._kind.extension if self._kind else None

    @property
    def identified(self):
        return self._status == IDENTIFIED

    @property
    def pending(self):
        return self._status == PENDING

    def __repr__(self):
        return (
            'LayerRecord(path=%r, status=%r, mime=%r, '
            'declared_mime=%r, signature=%d bytes, truncated=%r)'
        ) % (
            '/'.join(self._path), self._status, self.mime,
            self.declared_mime, len(self._signature), self._truncated
        )


def _read_evidence(adapter, entry):
    try:
        raw = adapter.read_signature(entry)
    except Exception as err:
        return bytearray(), 'read failed: %s' % err

    if raw is None:
        return bytearray(), 'no read evidence: member is claimed ' \
                            'but cannot be read locally'

    try:
        signature = get_bytes(raw)
    except TypeError as err:
        return bytearray(), 'unsupported signature payload: %s' % err

    if not signature:
        return bytearray(), 'no read evidence: empty signature returned'

    return signature, ''


def _append_pending(records, depth, path, entry, index, reason):
    records.append(LayerRecord(
        depth=depth,
        path=path,
        entry=entry,
        index=index,
        signature=bytearray(),
        truncated=False,
        kind=None,
        status=PENDING,
        reason=reason
    ))


def inspect_layers(adapter, root=None, max_depth=16):
    """
    Walks the container layers in read-only mode.

    Args:
        adapter: caller-supplied :class:`ContainerAdapter` instance.
        root: root :class:`Entry`. When None, a synthetic entry named
            ``'root'`` is passed to the adapter so it can expose top-level
            members. The synthetic root is only enumerated, never reported.
        max_depth: safety bound on the traversal depth.

    Returns:
        A depth-first ordered list of :class:`LayerRecord`, one per real
        layer.

    Raises:
        TypeError: if ``adapter`` is not a :class:`ContainerAdapter`.
    """
    if not isinstance(adapter, ContainerAdapter):
        raise TypeError('adapter must inherit from '
                        'filetype.layers.ContainerAdapter')

    if root is None:
        root = Entry(reference=None, name='root')
        synthetic_root = True
    else:
        synthetic_root = False

    records = []
    seen = set()

    def walk(entry, depth, path, index):
        signature, read_error = _read_evidence(adapter, entry)
        try:
            truncated = adapter.is_truncated(entry)
        except Exception:
            truncated = False

        kind = match(signature) if signature else None

        if not signature:
            status, reason = PENDING, read_error
        elif kind is not None:
            status = IDENTIFIED
            reason = 'signature matched %s' % kind.mime
        else:
            status = UNKNOWN
            reason = 'no matcher accepts the signature'

        if truncated:
            reason = ('%s (truncated member)' % reason) if reason \
                else 'truncated member'

        records.append(LayerRecord(
            depth=depth,
            path=path,
            entry=entry,
            index=index,
            signature=signature,
            truncated=truncated,
            kind=kind,
            status=status,
            reason=reason
        ))

        if depth >= max_depth:
            return

        # Only a layer whose own signature confirms an archive container can
        # legitimately expose children. A pending or unknown layer is a leaf
        # for evidence purposes: claiming children without container evidence
        # must not trigger another round of reads.
        if status != IDENTIFIED or archive_match(signature) is None:
            return

        marker = id(entry)
        if marker in seen:
            return
        seen.add(marker)

        try:
            members = list(adapter.children(entry))
        except Exception as err:
            _append_pending(
                records, depth + 1, path + ('<children>',), entry, 0,
                'claimed children cannot be enumerated: %s' % err
            )
            return

        for child_index, child in enumerate(members):
            walk(child, depth + 1,
                 path + (child.name,), child_index)

    if synthetic_root:
        try:
            members = list(adapter.children(root))
        except Exception as err:
            _append_pending(
                records, 0, (root.name,), root, 0,
                'claimed children cannot be enumerated: %s' % err
            )
            return records
        for child_index, child in enumerate(members):
            walk(child, 0, (child.name,), child_index)
    else:
        walk(root, 0, (root.name,), 0)

    return records


__all__ = (
    'Entry',
    'ContainerAdapter',
    'LayerRecord',
    'inspect_layers',
    'IDENTIFIED',
    'UNKNOWN',
    'PENDING',
)

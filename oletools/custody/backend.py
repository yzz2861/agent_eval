"""Progressive, manifest-driven custody inspection backend.

The backend implements the staged workflow:

1. A first pass only looks at structure (:func:`scan_file`) and seals the
   result into a :class:`~oletools.custody.manifest.CustodyManifest`.
   No embedded payload is read.
2. On every later pass the manifest is the input.  The current document is
   re-scanned structurally, then each previously recorded approval is
   re-associated with the new observation.  A replacement of the original
   file or a moved/removed same-named object explicitly revokes the old
   approval.
3. Only an object whose approval is still active can be released.  The
   release goes through a :class:`~oletools.custody.guard.RangeGate` that
   denies every byte outside the approved object, so an automated check can
   never read unapproved content first.
"""

import datetime

from .errors import (
    AccessDeniedError,
    CustodyError,
    ManifestError,
)
from .guard import GuardedFile, RangeGate
from .manifest import (
    ALGORITHM_SHA256,
    Approval,
    CustodyManifest,
    REASON_CONTENT_MISMATCH,
    REASON_FILE_REPLACED,
    REASON_OBJECT_MOVED,
    REASON_OBJECT_REMOVED,
    sha256_bytes,
)
from .scan import scan_file


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class InspectionResult(object):
    """Outcome of one progressive inspection pass.

    Attributes:
        manifest: the manifest updated by this pass.
        observation: the fresh structural observation.
        released: object ids whose content was actually handed out.
        revoked: mapping of approval id to revoke reason for approvals that
            lost validity during this pass.
        denied: object ids that could not be released because no active
            approval covers them.
    """

    def __init__(self, manifest, observation, released=None, revoked=None,
                 denied=None, history=None, released_objects=None):
        self.manifest = manifest
        self.observation = observation
        self.released = list(released or [])
        self.revoked = dict(revoked or {})
        self.denied = list(denied or [])
        self.history = list(history or [])
        self.released_objects = list(released_objects or [])

    def data_for(self, object_id):
        """Return the released payload for ``object_id`` or raise."""
        for item in self.released_objects:
            if item.observation.object_id == object_id:
                return item.data
        raise AccessDeniedError(object_id)

    @property
    def is_resealed(self):
        """True when no payload was released during this pass."""
        return not self.released

    def objects_still_observable(self):
        """Structural observations stay queryable even while sealed."""
        return list(self.observation.objects)

    def __repr__(self):
        return ('InspectionResult(released={0!r}, revoked={1!r}, '
                'denied={2!r})').format(
                    self.released, self.revoked, self.denied)


class Backend(object):
    """Stateless service object for progressive custody inspections."""

    def create_manifest(self, path):
        """First sampling: structure only, no payload bytes are consumed."""
        observation = scan_file(path)
        manifest = CustodyManifest(
            source_path=observation.source_path,
            root_digest=observation.root_sha256,
            algorithm=ALGORITHM_SHA256,
            root_size=observation.file_size,
            observations=observation.as_observations())
        manifest.add_history({
            'event': 'sealed',
            'at': _utc_now(),
            'root_digest': observation.root_sha256,
            'object_count': len(observation.objects),
            'note': 'structure-only observation; payloads not read',
        })
        return manifest, observation

    def grant_approval(self, manifest, object_id, approval_id=None,
                       content_digest=None):
        """Record a security-team approval for one observed object."""
        observation = self._find_observation(manifest, object_id)
        approval = Approval(
            approval_id=approval_id or
            'approval-{0}-{1}'.format(object_id, len(manifest.approvals) + 1),
            object_id=object_id, name=observation.name,
            offset=observation.offset, size=observation.size,
            content_digest=content_digest, granted_at=_utc_now())
        manifest.approvals.append(approval)
        manifest.add_history({
            'event': 'approval_granted',
            'at': approval.granted_at,
            'approval_id': approval.approval_id,
            'object_id': object_id,
        })
        return approval

    def inspect(self, path, manifest, release_ids=None,
                expected_digests=None):
        """Run a progressive pass using a previously sealed manifest.

        The structure of ``path`` is re-observed without reading payloads.
        Approvals carried by the manifest are re-associated with the fresh
        observations and revoked explicitly when the file was replaced or an
        object moved/disappeared.  Only active approvals can be released, and
        even then the read is constrained to that object's byte range.
        """
        release_ids = tuple(release_ids or ())
        expected_digests = dict(expected_digests or {})
        current = scan_file(path)
        self._validate_manifest(manifest, current)
        revoked = self._revoke_stale_approvals(manifest, current)
        released, denied, releases = self._release_approvals(
            path, manifest, current, release_ids, expected_digests,
            revoked)
        manifest.add_history({
            'event': 'inspection',
            'at': _utc_now(),
            'root_digest': current.root_sha256,
            'released': list(released),
            'revoked': dict(revoked),
            'denied': list(denied),
        })
        return InspectionResult(
            manifest=manifest, observation=current, released=released,
            revoked=revoked, denied=denied, released_objects=releases)

    # -- internals -----------------------------------------------------

    def _find_observation(self, manifest, object_id):
        for observation in manifest.observations:
            if observation.object_id == object_id:
                return observation
        raise ManifestError(
            'manifest contains no observation for object {0!r}'.format(
                object_id))

    def _validate_manifest(self, manifest, current):
        if not isinstance(manifest, CustodyManifest):
            raise ManifestError('a CustodyManifest is required as input')
        if manifest.root_digest is None:
            raise ManifestError('manifest has no sealed root digest')

    def _revoke_stale_approvals(self, manifest, current):
        """Explicitly invalidate approvals that no longer match the file.

        A same-named object that merely changed byte location is a move; an
        object that disappeared is a removal.  Only when none of the approved
        objects can be re-associated by name does the change count as a
        replacement of the whole original document.
        """
        revoked = {}
        replaced = manifest.root_digest != current.root_sha256
        current_by_name = {obj.name: obj for obj in current.objects}
        for approval in manifest.approvals:
            if not approval.is_active:
                continue
            fresh = current_by_name.get(approval.name)
            if fresh is None:
                self._revoke(
                    manifest, approval, revoked, REASON_OBJECT_REMOVED,
                    'object {0!r} no longer present'.format(approval.name))
                continue
            location_moved = (fresh.offset != approval.offset or
                              fresh.size != approval.size)
            if replaced and not location_moved:
                self._revoke(manifest, approval, revoked,
                             REASON_FILE_REPLACED,
                             'root digest {0} != {1}'.format(
                                 manifest.root_digest,
                                 current.root_sha256))
                continue
            if replaced and fresh.size != approval.size:
                self._revoke(manifest, approval, revoked,
                             REASON_FILE_REPLACED,
                             'size changed from {0} to {1}'.format(
                                 approval.size, fresh.size))
                continue
            if location_moved:
                self._revoke(
                    manifest, approval, revoked, REASON_OBJECT_MOVED,
                    'offset/size changed from ({0}, {1}) to ({2}, {3})'
                    .format(approval.offset, approval.size,
                            fresh.offset, fresh.size))
        return revoked

    def _revoke(self, manifest, approval, revoked, reason, detail):
        approval.revoke(reason, _utc_now())
        revoked[approval.approval_id] = reason
        manifest.add_history({
            'event': 'approval_revoked',
            'at': approval.revoked_at,
            'approval_id': approval.approval_id,
            'object_id': approval.object_id,
            'reason': reason,
            'detail': detail,
        })

    def _release_approvals(self, path, manifest, current, release_ids,
                           expected_digests, revoked):
        released = []
        denied = []
        releases = []
        wanted = set(release_ids)
        for approval in manifest.active_approvals():
            if wanted and approval.object_id not in wanted:
                continue
            fresh = self._fresh_object(current, approval)
            if fresh is None:
                denied.append(approval.object_id)
                continue
            data = self._read_approved_object(path, fresh)
            digest = sha256_bytes(data)
            expected = expected_digests.get(approval.object_id,
                                            approval.content_digest)
            if expected is not None and expected != digest:
                self._revoke(manifest, approval, revoked,
                             REASON_CONTENT_MISMATCH,
                             'digest {0} != expected {1}'.format(
                                 digest, expected))
                denied.append(approval.object_id)
                continue
            if approval.content_digest is None:
                approval.content_digest = digest
            released.append(approval.object_id)
            releases.append(ReleasedObject(approval, fresh, data, digest))
        for object_id in wanted:
            if object_id not in released and object_id not in denied:
                denied.append(object_id)
        return released, denied, releases

    def _fresh_object(self, current, approval):
        for obj in current.objects:
            if obj.object_id == approval.object_id:
                return obj
        for obj in current.objects:
            if obj.name == approval.name:
                return obj
        return None

    def _read_approved_object(self, path, observation):
        """Read one object through a gate covering only its own bytes."""
        if observation.kind == 'zip-member':
            return self._read_zip_member(path, observation)
        if observation.kind == 'ole-stream':
            return self._read_ole_stream(path, observation)
        start, length = self._physical_range(observation)
        gate = RangeGate(((start, start + length),))
        with open(path, 'rb') as raw:
            guarded = GuardedFile(raw, gate, name=path)
            return guarded.read_range(start, length)

    def _read_ole_stream(self, path, observation):
        """Reassemble an OLE stream sector by sector under a strict gate.

        Only the sectors belonging to the stream's FAT (or mini-FAT) chain
        are opened; the result is then truncated to the logical stream size
        so that trailing sector slack never leaks.
        """
        detail = observation.detail
        chain = list(detail.get('sector_chain') or ())
        if detail.get('mini_stream'):
            return self._read_ole_mini_stream(path, observation, chain)
        header_bytes = 512
        sector_size = detail.get('sector_size')
        if sector_size is None:
            sector_size = (detail['physical_length'] // len(chain)
                           if chain else observation.size)
        ranges = [(header_bytes + sid * sector_size,
                   header_bytes + (sid + 1) * sector_size)
                  for sid in chain]
        gate = RangeGate(tuple(ranges))
        pieces = []
        with open(path, 'rb') as raw:
            guarded = GuardedFile(raw, gate, name=path)
            for start, end in ranges:
                pieces.append(guarded.read_range(start, end - start))
        return b''.join(pieces)[:observation.size]

    def _read_ole_mini_stream(self, path, observation, chain):
        detail = observation.detail
        mini_sector_size = detail.get('mini_sector_size', 64)
        sector_size = detail.get('sector_size', 512)
        header_bytes = 512
        root_chain = list(detail.get('root_chain') or ())
        if not root_chain:
            raise CustodyError(
                'mini stream {0!r} has no root FAT chain'.format(
                    observation.name))
        ranges = []
        for mini_sid in chain:
            logical = mini_sid * mini_sector_size
            root_index, remainder = divmod(logical, sector_size)
            if root_index >= len(root_chain):
                raise CustodyError(
                    'mini sector {0} outside the root stream for {1!r}'
                    .format(mini_sid, observation.name))
            physical = (header_bytes +
                        root_chain[root_index] * sector_size + remainder)
            ranges.append((physical, physical + mini_sector_size))
        gate = RangeGate(tuple(ranges))
        pieces = []
        with open(path, 'rb') as raw:
            guarded = GuardedFile(raw, gate, name=path)
            for start, end in ranges:
                pieces.append(guarded.read_range(start, end - start))
        return b''.join(pieces)[:observation.size]

    def _physical_range(self, observation):
        detail = observation.detail
        start = detail.get('physical_offset', observation.offset)
        length = detail.get('physical_length', observation.size)
        if start is None or length is None:
            raise CustodyError(
                'object {0!r} has no resolvable physical location'.format(
                    observation.name))
        return int(start), int(length)

    def _read_zip_member(self, path, observation):
        """Decompress one approved ZIP member without opening neighbours."""
        start, physical_length = self._physical_range(observation)
        gate = RangeGate(((start, start + physical_length),))
        with open(path, 'rb') as raw:
            raw.seek(observation.detail['header_offset'])
            header_gate = RangeGate((
                (observation.detail['header_offset'], start),))
            guarded_header = GuardedFile(raw, header_gate, name=path)
            local_header = guarded_header.read_range(
                observation.detail['header_offset'],
                observation.detail['local_header_length'])
            guarded = GuardedFile(raw, gate, name=path)
            payload = guarded.read_range(start, physical_length)
        return _decompress_zip_member(observation, local_header, payload)


class ReleasedObject(object):
    """One object handed out through an active approval."""

    def __init__(self, approval, observation, data, digest):
        self.approval = approval
        self.observation = observation
        self.data = data
        self.digest = digest

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        return 'ReleasedObject({0!r}, {1} bytes)'.format(
            self.observation.name, len(self.data))


def _decompress_zip_member(observation, local_header, payload):
    """Decompress a member using only bytes already read via a gate."""
    import zlib
    compression = observation.detail.get('compression', 0)
    if compression == 0:
        return payload
    if compression == 8:
        return zlib.decompress(payload, -15)
    if compression == 9:
        return zlib.decompress(payload, -13)
    if compression == 12:
        import bz2
        return bz2.decompress(payload)
    raise CustodyError(
        'unsupported ZIP compression {0} for {1!r}'.format(
            compression, observation.name))


# Explicit progressive backend name used by some callers.
ProgressiveBackend = Backend

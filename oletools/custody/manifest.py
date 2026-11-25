"""Custody manifest: the persistent, serializable state of an inspection.

A manifest records two distinct kinds of information:

* :class:`Observation` entries describe the *structure* of a document, i.e.
  where embedded objects live, without ever holding their payload.  These are
  produced during the first, structure-only sampling and remain queryable on
  every later pass even when payload access is not granted.
* :class:`Approval` entries describe the *ranges* the security group has
  allowed to be handed out.  An approval is always anchored to the document
  fingerprint and to a concrete structural location (name, byte offset and
  size) observed when it was granted.
"""

import json


SCHEMA_VERSION = '1.0'

ALGORITHM_SHA256 = 'sha256'

APPROVAL_ACTIVE = 'active'
APPROVAL_REVOKED = 'revoked'

REASON_FILE_REPLACED = 'file_replaced'
REASON_OBJECT_MOVED = 'object_moved'
REASON_OBJECT_REMOVED = 'object_removed'
REASON_CONTENT_MISMATCH = 'content_mismatch'
REASON_MANUAL = 'manual'


class Observation(object):
    """Structural description of one embedded object.

    The object is identified by its container ``kind`` and ``name``; the
    ``offset``/``size`` pair is the physical location recorded at scan time
    and is used to detect that a same-named object has been moved.
    """

    def __init__(self, object_id, kind, name, offset, size, has_macros,
                 container=None, detail=None):
        self.object_id = object_id
        self.kind = kind
        self.name = name
        self.offset = int(offset)
        self.size = int(size)
        self.has_macros = bool(has_macros)
        self.container = container
        self.detail = dict(detail or {})

    def to_dict(self):
        return {
            'object_id': self.object_id,
            'kind': self.kind,
            'name': self.name,
            'offset': self.offset,
            'size': self.size,
            'has_macros': self.has_macros,
            'container': self.container,
            'detail': self.detail,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            object_id=data['object_id'],
            kind=data['kind'],
            name=data['name'],
            offset=data['offset'],
            size=data['size'],
            has_macros=data.get('has_macros', False),
            container=data.get('container'),
            detail=data.get('detail') or {},
        )

    def location_matches(self, other):
        """True when ``other`` occupies the same physical location."""
        return (self.name == other.name
                and self.offset == other.offset
                and self.size == other.size)

    def __repr__(self):
        return 'Observation({0!r}, offset={1}, size={2})'.format(
            self.name, self.offset, self.size)


class Approval(object):
    """A grant to read one object, possibly revoked on a later pass."""

    def __init__(self, approval_id, object_id, name, offset, size,
                 content_digest=None, status=APPROVAL_ACTIVE,
                 granted_at=None, revoked_at=None, revoke_reason=None):
        self.approval_id = approval_id
        self.object_id = object_id
        self.name = name
        self.offset = int(offset)
        self.size = int(size)
        self.content_digest = content_digest
        self.status = status
        self.granted_at = granted_at
        self.revoked_at = revoked_at
        self.revoke_reason = revoke_reason

    @property
    def is_active(self):
        return self.status == APPROVAL_ACTIVE

    def revoke(self, reason, when):
        self.status = APPROVAL_REVOKED
        self.revoked_at = when
        self.revoke_reason = reason

    def to_dict(self):
        return {
            'approval_id': self.approval_id,
            'object_id': self.object_id,
            'name': self.name,
            'offset': self.offset,
            'size': self.size,
            'content_digest': self.content_digest,
            'status': self.status,
            'granted_at': self.granted_at,
            'revoked_at': self.revoked_at,
            'revoke_reason': self.revoke_reason,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            approval_id=data['approval_id'],
            object_id=data['object_id'],
            name=data['name'],
            offset=data['offset'],
            size=data['size'],
            content_digest=data.get('content_digest'),
            status=data.get('status', APPROVAL_ACTIVE),
            granted_at=data.get('granted_at'),
            revoked_at=data.get('revoked_at'),
            revoke_reason=data.get('revoke_reason'),
        )


class CustodyManifest(object):
    """Full persistent state of a progressive inspection."""

    def __init__(self, source_path=None, root_digest=None,
                 algorithm=ALGORITHM_SHA256, root_size=0,
                 observations=None, approvals=None, history=None,
                 schema_version=SCHEMA_VERSION):
        self.schema_version = schema_version
        self.source_path = source_path
        self.root_digest = root_digest
        self.algorithm = algorithm
        self.root_size = int(root_size or 0)
        self.observations = list(observations or [])
        self.approvals = list(approvals or [])
        self.history = list(history or [])

    # -- lookups -------------------------------------------------------

    def observation_by_name(self, name):
        for observation in self.observations:
            if observation.name == name:
                return observation
        return None

    def active_approvals(self):
        return [approval for approval in self.approvals
                if approval.is_active]

    def approvals_for(self, object_id):
        return [approval for approval in self.approvals
                if approval.object_id == object_id]

    def add_history(self, entry):
        self.history.append(entry)

    # -- serialization -------------------------------------------------

    def to_dict(self):
        return {
            'schema_version': self.schema_version,
            'source_path': self.source_path,
            'root_digest': self.root_digest,
            'algorithm': self.algorithm,
            'root_size': self.root_size,
            'observations': [item.to_dict()
                             for item in self.observations],
            'approvals': [item.to_dict() for item in self.approvals],
            'history': self.history,
        }

    def to_json(self, indent=2):
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def save(self, path):
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(self.to_json())

    @classmethod
    def from_dict(cls, data):
        return cls(
            schema_version=data.get('schema_version', SCHEMA_VERSION),
            source_path=data.get('source_path'),
            root_digest=data.get('root_digest'),
            algorithm=data.get('algorithm', ALGORITHM_SHA256),
            root_size=data.get('root_size', 0),
            observations=[Observation.from_dict(item)
                          for item in data.get('observations', [])],
            approvals=[Approval.from_dict(item)
                       for item in data.get('approvals', [])],
            history=data.get('history', []),
        )

    @classmethod
    def load(cls, path):
        with open(path, 'r', encoding='utf-8') as handle:
            return cls.from_dict(json.load(handle))


def sha256_file(path):
    """Return the SHA-256 hex digest of a file, read in bounded chunks."""
    import hashlib
    hasher = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def sha256_bytes(data):
    """Return the SHA-256 hex digest of a bytes buffer."""
    import hashlib
    return hashlib.sha256(data).hexdigest()

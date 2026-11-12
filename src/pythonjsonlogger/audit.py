"""Explicitly opt-in, tamper-evident JSON audit logs.

This module deliberately does not change the behaviour of :class:`JsonFormatter`.
Applications enable auditing by choosing :class:`AuditFormatter` or
:class:`AuditFileHandler` for their existing ``logging`` logger.

Every audit record is a JSON object. User supplied log fields are kept at the top
level and audit metadata is stored in the reserved ``_audit`` field::

    {
      "_audit": {
        "chain_id": "...",
        "seq": 0,
        "timestamp": "2026-11-12T...Z",
        "prev_digest": "...",
        "key_id": "2026-11",
        "hmac": "...",
        "version": 1
      },
      "actor": "...",
      "message": "..."
    }

All JSON is emitted in a canonical form (sorted keys, no insignificant
whitespace).  ``prev_digest`` is the SHA-256 digest of the previous complete
record (or a chain-specific genesis digest for the first record), and ``hmac``
is HMAC-SHA-256 over the canonical record without the ``hmac`` member.  The
record's key ID is authenticated as part of that HMAC.

The verifier requires a known anchor to prove that a prefix has not been
removed.  ``AuditAnchor.genesis(chain_id)`` is the normal anchor for replaying
a whole stream.  A head anchor returned by a previous verification can be used
to resume verification.
"""

### IMPORTS
### ============================================================================
## Future
from __future__ import annotations

## Standard Library
from collections.abc import Iterable, Iterator, Mapping
import dataclasses
import datetime
import hashlib
import hmac as hmac_module
import json
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any
import uuid

## Application
from .json import JsonFormatter

### CONSTANTS
### ============================================================================
AUDIT_VERSION = 1
"""Version of the audit record schema."""

AUDIT_FIELD = "_audit"
"""Reserved top-level field containing audit metadata."""

_GENESIS_DOMAIN = b"pythonjsonlogger.audit.v1\x00"
_CANONICAL_SEPARATORS = (",", ":")


### EXCEPTIONS
### ============================================================================
class AuditChainError(Exception):
    """Base class for audit-chain errors."""


class AuditConfigurationError(AuditChainError, ValueError):
    """An audit formatter, key ring, or handler was configured incorrectly."""


class AuditIntegrityError(AuditChainError, ValueError):
    """A record failed structural, sequence, or cryptographic verification."""


class AuditWriteError(AuditChainError, OSError):
    """An audit buffer could not be flushed and the chain was not committed."""


### FUNCTIONS
### ============================================================================
def canonical_json(value: Any) -> str:
    """Serialize JSON data deterministically for hashing and output.

    The output has recursively sorted object keys, no insignificant whitespace,
    and non-ASCII text is emitted as UTF-8 rather than escaped.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=_CANONICAL_SEPARATORS,
        ensure_ascii=False,
        allow_nan=False,
    )


def _reject_nonfinite_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number {value!r} is not permitted")


def genesis_digest(chain_id: str) -> str:
    """Return the chain-specific digest immediately preceding sequence zero."""
    chain_id = _validate_chain_id(chain_id)
    return hashlib.sha256(_GENESIS_DOMAIN + chain_id.encode("utf-8")).hexdigest()


def record_digest(record: Mapping[str, Any]) -> str:
    """Return the SHA-256 digest of a complete canonical audit record."""
    return hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()


def _audit_input(record: Mapping[str, Any]) -> str:
    """Canonical bytes authenticated by the record HMAC (everything but hmac)."""
    clone = dict(record)
    audit = clone.get(AUDIT_FIELD)
    if not isinstance(audit, Mapping):
        raise AuditIntegrityError(f"record is missing the {AUDIT_FIELD!r} metadata object")
    audit_clone = dict(audit)
    audit_clone.pop("hmac", None)
    clone[AUDIT_FIELD] = audit_clone
    return canonical_json(clone)


def _local_secret(value: Any, *, key_id: str) -> bytes:
    """Coerce a key secret without ever including its value in an error."""
    if isinstance(value, AuditKey):
        if value.key_id != key_id:
            raise AuditConfigurationError(f"key ID mismatch for registered key {key_id!r}")
        return value._secret_bytes
    if isinstance(value, str):
        secret = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray, memoryview)):
        secret = bytes(value)
    else:
        raise AuditConfigurationError(f"secret for key {key_id!r} must be str or bytes")
    if not secret:
        raise AuditConfigurationError(f"secret for key {key_id!r} must not be empty")
    return secret


def _validate_key_id(key_id: Any) -> str:
    if not isinstance(key_id, str) or not key_id:
        raise AuditConfigurationError("key_id must be a non-empty string")
    return key_id


def _validate_chain_id(chain_id: Any) -> str:
    if not isinstance(chain_id, str) or not chain_id:
        raise AuditConfigurationError("chain_id must be a non-empty string")
    return chain_id


### KEYS
### ============================================================================
class AuditKey:
    """A named HMAC secret with a redacted representation."""

    __slots__ = ("_key_id", "_secret_bytes")

    def __init__(self, key_id: str, secret: str | bytes | bytearray | memoryview) -> None:
        self._key_id = _validate_key_id(key_id)
        self._secret_bytes = _local_secret(secret, key_id=self._key_id)

    @property
    def key_id(self) -> str:
        """The identifier written to audit records and used for key rotation."""
        return self._key_id

    def __repr__(self) -> str:
        return f"AuditKey(key_id={self._key_id!r}, secret=<redacted>)"

    def __str__(self) -> str:
        return repr(self)


class AuditKeyRing:
    """A set of verification keys plus one active signing key.

    Rotating a key adds the new key and makes it active; previous keys remain
    available to verify historical records.  Key material is never included in
    ``repr``, ``str``, or configuration error messages.
    """

    def __init__(
        self,
        keys: Mapping[str, Any] | AuditKeyRing | None = None,
        *,
        active_key_id: str | None = None,
        key_id: str | None = None,
        key: Any = None,
        active: str | None = None,
    ) -> None:
        if active is not None:
            if active_key_id is not None:
                raise AuditConfigurationError("provide either active or active_key_id, not both")
            active_key_id = active
        self._keys: dict[str, bytes] = {}

        if isinstance(keys, AuditKeyRing):
            for existing_id in keys.key_ids:
                self._keys[existing_id] = keys._keys[existing_id]
            if active_key_id is None and key_id is None:
                active_key_id = keys._active_key_id
        elif keys is not None:
            if not isinstance(keys, Mapping):
                raise AuditConfigurationError("keys must be a mapping of key ID to secret")
            for item_id, item_secret in keys.items():
                item_key_id = _validate_key_id(item_id)
                self._keys[item_key_id] = _local_secret(item_secret, key_id=item_key_id)

        if key is not None:
            source_id = key_id or getattr(key, "key_id", None) or "default"
            source_id = _validate_key_id(source_id)
            if source_id in self._keys:
                raise AuditConfigurationError(f"key ID {source_id!r} is already registered")
            self._keys[source_id] = _local_secret(key, key_id=source_id)
            if active_key_id is None:
                active_key_id = source_id

        if key_id is not None:
            key_id = _validate_key_id(key_id)

        if active_key_id is None:
            active_key_id = next(iter(self._keys), None)
        if active_key_id is not None:
            active_key_id = _validate_key_id(active_key_id)
            if active_key_id not in self._keys:
                raise AuditConfigurationError(f"active key ID {active_key_id!r} is not registered")
        self._active_key_id = active_key_id

    @property
    def key_ids(self) -> tuple[str, ...]:
        """Registered key IDs in insertion order."""
        return tuple(self._keys)

    @property
    def active_key_id(self) -> str:
        """The key ID used for newly signed records."""
        if self._active_key_id is None:
            raise AuditConfigurationError("the key ring has no active key")
        return self._active_key_id

    def add_key(self, key_id: str, secret: str | bytes | bytearray | memoryview) -> None:
        """Register another verification key without changing the active key."""
        key_id = _validate_key_id(key_id)
        if key_id in self._keys:
            raise AuditConfigurationError(f"key ID {key_id!r} is already registered")
        self._keys[key_id] = _local_secret(secret, key_id=key_id)

    def activate(self, key_id: str) -> None:
        """Make an already registered key active for writing."""
        key_id = _validate_key_id(key_id)
        if key_id not in self._keys:
            raise AuditConfigurationError(f"key ID {key_id!r} is not registered")
        self._active_key_id = key_id

    def rotate(self, new_key_id: str, new_secret: str | bytes | bytearray | memoryview) -> str:
        """Register a new key, make it active, and keep old keys for verification."""
        new_key_id = _validate_key_id(new_key_id)
        if new_key_id in self._keys:
            raise AuditConfigurationError(f"key ID {new_key_id!r} is already registered")
        self._keys[new_key_id] = _local_secret(new_secret, key_id=new_key_id)
        self._active_key_id = new_key_id
        return new_key_id

    rotate_key = rotate

    def sign(self, data: str | bytes, key_id: str | None = None) -> str:
        """Return a hex HMAC-SHA-256 signature over ``data``."""
        signing_id = self.active_key_id if key_id is None else _validate_key_id(key_id)
        try:
            secret = self._keys[signing_id]
        except KeyError:
            raise AuditConfigurationError(f"unknown signing key ID {signing_id!r}") from None
        payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        return hmac_module.new(secret, payload, hashlib.sha256).hexdigest()

    def verify(self, data: str | bytes, signature: str, key_id: str) -> bool:
        """Verify ``signature`` for ``data`` using the identified key."""
        key_id = _validate_key_id(key_id)
        secret = self._keys.get(key_id)
        if secret is None or not isinstance(signature, str):
            return False
        payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        expected = hmac_module.new(secret, payload, hashlib.sha256).hexdigest()
        return hmac_module.compare_digest(expected, signature)

    def __contains__(self, key_id: object) -> bool:
        return key_id in self._keys

    def __repr__(self) -> str:
        return (
            f"AuditKeyRing(key_ids={list(self._keys)!r}, " f"active_key_id={self._active_key_id!r})"
        )

    def __str__(self) -> str:
        return repr(self)


def _build_key_ring(
    *,
    key_ring: AuditKeyRing | Mapping[str, Any] | None,
    keys: Mapping[str, Any] | None,
    key: Any,
    key_id: str | None,
    require_keys: bool = True,
) -> AuditKeyRing:
    if isinstance(key_ring, AuditKeyRing):
        if keys is not None or key is not None:
            raise AuditConfigurationError("provide either key_ring or keys/key, not both")
        if key_id is not None and key_id != key_ring.active_key_id:
            key_ring.activate(key_id)
        return key_ring
    if isinstance(key_ring, Mapping):
        if keys is not None:
            raise AuditConfigurationError("provide either key_ring or keys, not both")
        keys = key_ring
    elif key_ring is not None:
        raise AuditConfigurationError(
            "key_ring must be an AuditKeyRing or a mapping of key IDs to secrets"
        )
    if keys is not None and key is not None:
        raise AuditConfigurationError("provide either keys or key, not both")
    ring = AuditKeyRing(keys, active_key_id=key_id, key=key, key_id=key_id)
    if require_keys and not ring.key_ids:
        raise AuditConfigurationError("at least one audit HMAC key is required")
    return ring


### ANCHORS AND RECORDS
### ============================================================================
class AuditAnchor:
    """A known chain position from which verification can replay.

    ``sequence`` is the last already-verified sequence number, or ``-1`` for the
    genesis anchor.  ``digest`` is the digest of that last record.  Verification
    therefore expects a first record with ``sequence + 1`` and ``prev_digest ==
    digest``.
    """

    __slots__ = ("chain_id", "sequence", "digest")

    def __init__(
        self,
        chain_id: str,
        sequence: int = -1,
        digest: str | None = None,
        *,
        seq: int | None = None,
        head_digest: str | None = None,
    ) -> None:
        if seq is not None:
            if sequence != -1:
                raise AuditConfigurationError("provide either sequence or seq, not both")
            sequence = seq
        if head_digest is not None:
            if digest is not None:
                raise AuditConfigurationError("provide either digest or head_digest, not both")
            digest = head_digest
        self.chain_id = _validate_chain_id(chain_id)
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < -1:
            raise AuditConfigurationError("anchor sequence must be an integer >= -1")
        if digest is None:
            if sequence != -1:
                raise AuditConfigurationError(
                    "a non-genesis anchor requires the previous record digest"
                )
            digest = genesis_digest(chain_id)
        if not isinstance(digest, str) or not digest:
            raise AuditConfigurationError("anchor digest must be a non-empty string")
        self.sequence = sequence
        self.digest = digest

    @classmethod
    def genesis(cls, chain_id: str) -> AuditAnchor:
        """Return the anchor immediately preceding sequence zero."""
        return cls(chain_id=chain_id)

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> AuditAnchor:
        """Build a head anchor from a complete record."""
        audit = record.get(AUDIT_FIELD)
        if not isinstance(audit, Mapping):
            raise AuditIntegrityError(f"record is missing the {AUDIT_FIELD!r} metadata")
        chain_id = audit.get("chain_id")
        sequence = audit.get("seq")
        if (
            not isinstance(chain_id, str)
            or isinstance(sequence, bool)
            or not isinstance(sequence, int)
        ):
            raise AuditIntegrityError("record has invalid chain_id or seq metadata")
        return cls(chain_id, sequence, record_digest(record))

    from_head = from_record

    @property
    def next_sequence(self) -> int:
        """Sequence number the next replayed record must have."""
        return self.sequence + 1

    @property
    def seq(self) -> int:
        """Alias for ``sequence``."""
        return self.sequence

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable anchor representation."""
        return {"chain_id": self.chain_id, "sequence": self.sequence, "digest": self.digest}

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AuditAnchor):
            return NotImplemented
        return (
            self.chain_id == other.chain_id
            and self.sequence == other.sequence
            and self.digest == other.digest
        )

    def __hash__(self) -> int:
        return hash((self.chain_id, self.sequence, self.digest))

    def __repr__(self) -> str:
        return (
            f"AuditAnchor(chain_id={self.chain_id!r}, sequence={self.sequence!r}, "
            f"digest={self.digest!r})"
        )


def _coerce_anchor(value: AuditAnchor | Mapping[str, Any] | None) -> AuditAnchor | None:
    if value is None or isinstance(value, AuditAnchor):
        return value
    if not isinstance(value, Mapping):
        raise AuditConfigurationError("anchor must be an AuditAnchor, mapping, or None")
    if AUDIT_FIELD in value:
        return AuditAnchor.from_record(value)
    chain_id = value.get("chain_id", value.get("chain"))
    sequence = value.get("sequence", value.get("seq"))
    digest = value.get(
        "digest", value.get("head_digest", value.get("prev_digest", value.get("hash")))
    )
    if not isinstance(chain_id, str):
        raise AuditConfigurationError("anchor mapping requires a chain_id")
    if sequence is None:
        sequence = -1
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        raise AuditConfigurationError("anchor mapping sequence must be an integer")
    return AuditAnchor(chain_id, sequence, digest)


@dataclasses.dataclass(frozen=True)
class AuditRecord:
    """A signed record and the chain state produced while creating it.

    This object is an internal hand-off between the formatter and file handler.
    It is returned from ``AuditFormatter.build_record`` and is not serialized as
    part of the log line.
    """

    sequence: int
    timestamp: str
    previous_digest: str
    key_id: str
    digest: str
    line: str
    record: dict[str, Any]

    @property
    def seq(self) -> int:
        """Alias for ``sequence``."""
        return self.sequence


@dataclasses.dataclass(frozen=True)
class AuditVerification:
    """Result of a successful audit-chain replay."""

    records: tuple[dict[str, Any], ...]
    anchor: AuditAnchor | None

    @property
    def chain_id(self) -> str | None:
        """The verified chain ID, if the replay had one."""
        return None if self.anchor is None else self.anchor.chain_id

    @property
    def head(self) -> AuditAnchor | None:
        """Anchor for records following this verified prefix."""
        return self.anchor

    @property
    def count(self) -> int:
        """Number of replayed records."""
        return len(self.records)

    @property
    def valid(self) -> bool:
        """Successful verification always yields ``True``."""
        return True

    @property
    def sequence(self) -> int | None:
        """The last verified sequence number, if available."""
        return None if self.anchor is None else self.anchor.sequence

    @property
    def digest(self) -> str | None:
        """The last verified record digest, if available."""
        return None if self.anchor is None else self.anchor.digest

    @property
    def last_record(self) -> dict[str, Any] | None:
        """The most recent verified record, if any."""
        return self.records[-1] if self.records else None

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.records)

    def __bool__(self) -> bool:
        return True


### FORMATTER
### ============================================================================
def _format_record_time(created: Any) -> str:
    try:
        timestamp = float(created)
    except (TypeError, ValueError):
        timestamp = time.time()
    moment = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


class AuditFormatter(JsonFormatter):
    """JsonFormatter that emits an explicitly enabled, signed hash chain.

    Use this formatter directly with an existing handler, or use
    :class:`AuditFileHandler` when crash recovery and flush-then-commit ordering
    are required.  Normal :class:`JsonFormatter` behaviour is unaffected.

    Args:
        key_ring: an existing :class:`AuditKeyRing`.
        keys: a mapping of key ID to secret (for example ``{"old": ..., "new": ...}``).
        key: one secret, registered under ``key_id`` (default ``"default"``).
        key_id: active signing key ID.
        chain_id: logical log stream ID.  Defaults to a random UUID hex string.
        anchor: the last already-verified chain position to resume from.
        start_sequence: convenience alternative to ``anchor``.
        previous_digest: record digest immediately before ``start_sequence``.
        manual_commit: retain records until :meth:`commit` is called.  This is
            used by :class:`AuditFileHandler`; normal formatter users should not
            set it.
        kwargs: forwarded to :class:`JsonFormatter`.

    Audit mode uses canonical JSON and therefore rejects ``prefix`` and
    ``json_indent``, both of which would make a record span or prefix a line.
    """

    def __init__(
        self,
        *args,
        key_ring: AuditKeyRing | Mapping[str, Any] | None = None,
        keys: Mapping[str, Any] | None = None,
        key: Any = None,
        secret: Any = None,
        key_id: str | None = None,
        chain_id: str | None = None,
        anchor: AuditAnchor | Mapping[str, Any] | None = None,
        start_sequence: int | None = None,
        previous_digest: str | None = None,
        manual_commit: bool = False,
        **kwargs,
    ) -> None:
        alias_active_key_id = kwargs.pop("active_key_id", None)
        if alias_active_key_id is not None:
            if key_id is not None:
                raise AuditConfigurationError("provide either key_id or active_key_id, not both")
            key_id = alias_active_key_id
        alias_signing_key_id = kwargs.pop("signing_key_id", None)
        if alias_signing_key_id is not None:
            if key_id is not None:
                raise AuditConfigurationError("provide either key_id or signing_key_id, not both")
            key_id = alias_signing_key_id
        alias_keys = kwargs.pop("hmac_keys", None)
        alias_key = kwargs.pop("hmac_key", None)
        if alias_keys is not None:
            if keys is not None:
                raise AuditConfigurationError("provide either keys or hmac_keys, not both")
            keys = alias_keys
        if alias_key is not None:
            if key is not None or secret is not None:
                raise AuditConfigurationError("provide only one of key, secret, or hmac_key")
            key = alias_key
        alias_key_ring = kwargs.pop("keyring", None)
        if alias_key_ring is not None:
            if key_ring is not None:
                raise AuditConfigurationError("provide either key_ring or keyring, not both")
            key_ring = alias_key_ring
        if key_id is None:
            key_id = kwargs.pop("key_identifier", None)
        else:
            kwargs.pop("key_identifier", None)
        alias_chain_id = kwargs.pop("chain", None)
        if alias_chain_id is not None:
            if chain_id is not None:
                raise AuditConfigurationError("provide either chain_id or chain, not both")
            chain_id = alias_chain_id
        alias_stream_id = kwargs.pop("stream_id", None)
        if alias_stream_id is not None:
            if chain_id is not None:
                raise AuditConfigurationError("provide either chain_id or stream_id, not both")
            chain_id = alias_stream_id
        alias_anchor = kwargs.pop("resume_from", None)
        if alias_anchor is not None:
            if anchor is not None:
                raise AuditConfigurationError("provide either anchor or resume_from, not both")
            anchor = alias_anchor
        if secret is not None:
            if key is not None:
                raise AuditConfigurationError("provide either key or secret, not both")
            key = secret

        self._key_ring = _build_key_ring(key_ring=key_ring, keys=keys, key=key, key_id=key_id)
        self._audit_lock = threading.RLock()
        self._audit_local = threading.local()
        self._manual_commit = bool(manual_commit)
        self._pending: list[AuditRecord] = []
        self._last_record: AuditRecord | None = None

        supplied_anchor = _coerce_anchor(anchor)
        if chain_id is None and supplied_anchor is not None:
            chain_id = supplied_anchor.chain_id
        if chain_id is None:
            chain_id = uuid.uuid4().hex
        self._chain_id = _validate_chain_id(chain_id)

        if supplied_anchor is not None and supplied_anchor.chain_id != self._chain_id:
            raise AuditConfigurationError("anchor chain_id does not match chain_id")
        if start_sequence is not None:
            if supplied_anchor is not None:
                raise AuditConfigurationError("provide either anchor or start_sequence, not both")
            if (
                isinstance(start_sequence, bool)
                or not isinstance(start_sequence, int)
                or start_sequence < 0
            ):
                raise AuditConfigurationError("start_sequence must be an integer >= 0")
            if start_sequence == 0:
                supplied_anchor = AuditAnchor.genesis(self._chain_id)
            else:
                if previous_digest is None:
                    raise AuditConfigurationError("start_sequence > 0 requires previous_digest")
                supplied_anchor = AuditAnchor(self._chain_id, start_sequence - 1, previous_digest)
        elif previous_digest is not None:
            raise AuditConfigurationError("previous_digest requires start_sequence")

        if supplied_anchor is None:
            supplied_anchor = AuditAnchor.genesis(self._chain_id)

        self._issued_sequence = supplied_anchor.next_sequence
        self._issued_digest = supplied_anchor.digest
        self._committed_sequence = supplied_anchor.sequence
        self._committed_digest = supplied_anchor.digest

        super().__init__(*args, **kwargs)
        if self.prefix:
            raise AuditConfigurationError("AuditFormatter does not support a line prefix")
        if self.json_indent is not None:
            raise AuditConfigurationError("AuditFormatter does not support json_indent")

    @property
    def key_ring(self) -> AuditKeyRing:
        """The key ring used by this formatter."""
        return self._key_ring

    @property
    def chain_id(self) -> str:
        """Logical identifier for this audit chain."""
        return self._chain_id

    @property
    def key_id(self) -> str:
        """The key ID used for the next record."""
        return self._key_ring.active_key_id

    @property
    def head(self) -> AuditAnchor:
        """The last successfully committed/emitted chain position."""
        return AuditAnchor(self._chain_id, self._committed_sequence, self._committed_digest)

    @property
    def anchor(self) -> AuditAnchor:
        """Alias for :attr:`head`."""
        return self.head

    @property
    def sequence(self) -> int:
        """The last committed sequence number, or ``-1`` for an empty chain."""
        return self._committed_sequence

    @property
    def next_sequence(self) -> int:
        """The next sequence number that will be emitted."""
        return self._issued_sequence

    @property
    def pending_records(self) -> tuple[AuditRecord, ...]:
        """Records created in manual-commit mode that are not yet committed."""
        return tuple(self._pending)

    @property
    def last_record(self) -> AuditRecord | None:
        """The most recently created signed record, if any."""
        return self._last_record

    def rotate_key(self, key_id: str, secret: str | bytes | bytearray | memoryview) -> str:
        """Register a new active key while retaining old keys for verification."""
        return self._key_ring.rotate(key_id, secret)

    def commit(self, records: Iterable[AuditRecord] | AuditRecord | None = None) -> int:
        """Advance the committed head after records have been durably flushed.

        With ``None`` all pending records are committed.  Committing out of
        sequence, or committing a record that is not pending, raises an error
        and leaves the head unchanged.
        """
        with self._audit_lock:
            if records is None:
                selected = list(self._pending)
            elif isinstance(records, AuditRecord):
                selected = [records]
            else:
                selected = list(records)
            if not selected:
                return 0

            first = selected[0]
            if first.sequence != self._committed_sequence + 1:
                raise AuditIntegrityError(
                    "cannot commit records out of sequence; chain head unchanged"
                )
            previous = self._committed_digest
            for item in selected:
                if item.previous_digest != previous:
                    raise AuditIntegrityError(
                        "cannot commit a record whose predecessor is not committed"
                    )
                previous = item.digest

            last = selected[-1]
            self._committed_sequence = last.sequence
            self._committed_digest = last.digest
            committed_through = last.sequence
            self._pending = [item for item in self._pending if item.sequence > committed_through]
            return len(selected)

    def _set_manual_commit(self, enabled: bool) -> None:
        with self._audit_lock:
            if enabled and not self._manual_commit and self._pending:
                raise AuditConfigurationError("cannot switch commit modes with pending records")
            self._manual_commit = bool(enabled)

    def _restore_anchor(self, anchor: AuditAnchor) -> None:
        """Reset a not-yet-used formatter to a recovered chain position."""
        with self._audit_lock:
            if anchor.chain_id != self._chain_id:
                raise AuditConfigurationError("cannot restore a different chain ID")
            if self._pending or self._last_record is not None:
                raise AuditConfigurationError("cannot restore an anchor after records were emitted")
            self._issued_sequence = anchor.next_sequence
            self._issued_digest = anchor.digest
            self._committed_sequence = anchor.sequence
            self._committed_digest = anchor.digest

    def format(self, record: logging.LogRecord) -> str:
        """Format one record; sequence assignment and signing are serialized."""
        with self._audit_lock:
            previous_record = getattr(self._audit_local, "record", None)
            previous_line = getattr(self._audit_local, "line", None)
            self._audit_local.record = record
            self._audit_local.line = None
            try:
                return super().format(record)
            finally:
                self._audit_local.record = previous_record
                self._audit_local.line = previous_line

    def process_log_record(self, log_data: dict[str, Any]) -> dict[str, Any]:
        """Normalize log data and attach authenticated chain metadata."""
        if AUDIT_FIELD in log_data:
            raise AuditIntegrityError(f"log record contains the reserved {AUDIT_FIELD!r} field")
        payload = self._normalise_log_data(log_data)
        audit_record = self._build_audit_record(payload)
        self._audit_local.line = audit_record.line
        return audit_record.record

    def _normalise_log_data(self, log_data: dict[str, Any]) -> dict[str, Any]:
        try:
            encoded = json.dumps(
                log_data,
                cls=self.json_encoder,
                default=self.json_default,
                ensure_ascii=False,
            )
            normalised = json.loads(encoded, parse_constant=_reject_nonfinite_constant)
        except Exception:
            raise AuditIntegrityError("log record could not be normalized to JSON") from None
        if not isinstance(normalised, dict):
            raise AuditIntegrityError("log record did not normalize to a JSON object")
        return normalised

    def _build_audit_record(self, payload: dict[str, Any]) -> AuditRecord:
        with self._audit_lock:
            active_record = getattr(self._audit_local, "record", None)
            created = getattr(active_record, "created", None)
            timestamp = _format_record_time(created)
            sequence = self._issued_sequence
            previous_digest = self._issued_digest
            signing_key_id = self._key_ring.active_key_id

            metadata: dict[str, Any] = {
                "version": AUDIT_VERSION,
                "chain_id": self._chain_id,
                "seq": sequence,
                "timestamp": timestamp,
                "prev_digest": previous_digest,
                "key_id": signing_key_id,
            }
            signed_record = dict(payload)
            signed_record[AUDIT_FIELD] = metadata
            signed_input = _audit_input(signed_record)
            signature = self._key_ring.sign(signed_input, key_id=signing_key_id)
            metadata["hmac"] = signature
            line = canonical_json(signed_record)
            digest = hashlib.sha256(line.encode("utf-8")).hexdigest()

            result = AuditRecord(
                sequence=sequence,
                timestamp=timestamp,
                previous_digest=previous_digest,
                key_id=signing_key_id,
                digest=digest,
                line=line,
                record=signed_record,
            )
            self._issued_sequence += 1
            self._issued_digest = digest
            self._last_record = result
            if self._manual_commit:
                self._pending.append(result)
            else:
                self._committed_sequence = sequence
                self._committed_digest = digest
            return result

    def build_record(self, record: logging.LogRecord) -> AuditRecord:
        """Build a signed record without requiring a handler write.

        Resolution and payload construction follow normal ``format`` semantics.
        The returned byte line is not prefixed and can be flushed by a caller
        that later invokes :meth:`commit`.
        """
        with self._audit_lock:
            line = self.format(record)
            result = self._last_record
            if result is None or result.line != line:
                raise AuditIntegrityError("record formatting did not produce an audit record")
            return result

    def serialize_log_record(self, log_data: dict[str, Any]) -> str:
        """Return the exact canonical line that was signed for this record."""
        line = getattr(self._audit_local, "line", None)
        if line is None:
            raise AuditIntegrityError("AuditFormatter records must pass through format()")
        return line

    def __repr__(self) -> str:
        return (
            f"AuditFormatter(chain_id={self._chain_id!r}, key_id={self.key_id!r}, "
            f"sequence={self._committed_sequence!r})"
        )


### VERIFIER
### ============================================================================
class _DuplicateJSONKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _parse_json_record(text: str, index: int) -> dict[str, Any]:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except _DuplicateJSONKey as exc:
        raise AuditIntegrityError(
            f"audit record at index {index} contains duplicate JSON key {exc}"
        ) from None
    except ValueError:
        raise AuditIntegrityError(f"audit record at index {index} is not valid JSON") from None
    if not isinstance(value, dict):
        raise AuditIntegrityError(f"audit record at index {index} is not a JSON object")
    return value


def _iter_records(
    lines: str | bytes | os.PathLike[str] | Iterable[str | bytes | Mapping[str, Any]],
) -> Iterator[dict[str, Any]]:
    if isinstance(lines, os.PathLike):
        lines = Path(lines).read_bytes()
    if isinstance(lines, bytes):
        lines = lines.decode("utf-8")
    if isinstance(lines, str):
        # Accept a path for the common single-file replay case, while still
        # treating ordinary JSON-lines text as content.
        if "\n" not in lines and "\r" not in lines:
            try:
                candidate = Path(lines)
                if candidate.is_file():
                    lines = candidate.read_text(encoding="utf-8")
            except (OSError, ValueError):
                pass
        lines = lines.splitlines()

    for index, item in enumerate(lines):
        if isinstance(item, Mapping):
            yield dict(item)
            continue
        if isinstance(item, bytes):
            try:
                text = item.decode("utf-8")
            except UnicodeDecodeError:
                raise AuditIntegrityError(
                    f"audit record at index {index} is not valid UTF-8"
                ) from None
        elif isinstance(item, str):
            text = item
        else:
            raise AuditIntegrityError(f"unsupported audit record type at index {index}")
        if not text.strip():
            raise AuditIntegrityError(f"empty audit log line at index {index}")
        yield _parse_json_record(text.strip(), index)


class AuditVerifier:
    """Replay and verify a canonical audit chain from a known anchor."""

    def __init__(
        self,
        key_ring: AuditKeyRing | Mapping[str, Any] | None = None,
        anchor: AuditAnchor | Mapping[str, Any] | None = None,
        *,
        keys: Mapping[str, Any] | None = None,
        key: Any = None,
        secret: Any = None,
        key_id: str | None = None,
    ) -> None:
        if secret is not None:
            if key is not None:
                raise AuditConfigurationError("provide either key or secret, not both")
            key = secret
        self.key_ring = _build_key_ring(
            key_ring=key_ring,
            keys=keys,
            key=key,
            key_id=key_id,
            require_keys=False,
        )
        self.anchor = _coerce_anchor(anchor)

    def verify(
        self,
        lines: str | bytes | os.PathLike[str] | Iterable[str | bytes | Mapping[str, Any]],
        anchor: AuditAnchor | Mapping[str, Any] | None = None,
    ) -> AuditVerification:
        """Replay records, raising :class:`AuditIntegrityError` on any mismatch."""
        starting_anchor = self.anchor if anchor is None else _coerce_anchor(anchor)
        records: list[dict[str, Any]] = []
        expected_sequence: int | None = None
        expected_digest: str | None = None
        chain_id: str | None = None

        if starting_anchor is not None:
            chain_id = starting_anchor.chain_id
            expected_sequence = starting_anchor.next_sequence
            expected_digest = starting_anchor.digest

        for index, record in enumerate(_iter_records(lines)):
            audit = self._validate_structure(record, index)
            record_chain_id = audit["chain_id"]
            sequence = audit["seq"]
            previous_digest = audit["prev_digest"]
            key_id = audit["key_id"]
            signature = audit["hmac"]

            if chain_id is None:
                chain_id = record_chain_id
                expected_sequence = 0
                expected_digest = genesis_digest(chain_id)
            if record_chain_id != chain_id:
                raise AuditIntegrityError(
                    f"audit record {index}: chain_id {record_chain_id!r} does not match "
                    f"expected {chain_id!r} (cross-file splice)"
                )
            if sequence != expected_sequence:
                if sequence > expected_sequence:
                    reason = "record deletion or sequence gap"
                else:
                    reason = "duplicate or out-of-order sequence"
                raise AuditIntegrityError(
                    f"audit record {index}: expected seq {expected_sequence}, got {sequence} "
                    f"({reason})"
                )
            if previous_digest != expected_digest:
                raise AuditIntegrityError(
                    f"audit record {index}: previous digest mismatch "
                    "(record modified, deleted, or reordered)"
                )
            if key_id not in self.key_ring:
                raise AuditIntegrityError(
                    f"audit record {index}: unknown key ID {key_id!r}; "
                    "the historical key is required for verification"
                )
            if not self.key_ring.verify(_audit_input(record), signature, key_id=key_id):
                raise AuditIntegrityError(
                    f"audit record {index}: HMAC verification failed "
                    "(content or key ID was modified)"
                )

            expected_digest = record_digest(record)
            expected_sequence = sequence + 1
            records.append(record)

        if starting_anchor is None and not records:
            return AuditVerification(records=(), anchor=None)
        if chain_id is None:
            return AuditVerification(records=(), anchor=None)
        head = AuditAnchor(chain_id, expected_sequence - 1, expected_digest)
        return AuditVerification(records=tuple(records), anchor=head)

    def _validate_structure(self, record: dict[str, Any], index: int) -> dict[str, Any]:
        audit = record.get(AUDIT_FIELD)
        if not isinstance(audit, dict):
            raise AuditIntegrityError(f"audit record {index}: missing {AUDIT_FIELD!r} metadata")
        version = audit.get("version")
        if isinstance(version, bool) or version != AUDIT_VERSION:
            raise AuditIntegrityError(
                f"audit record {index}: unsupported audit version {version!r}"
            )
        chain_id = audit.get("chain_id")
        if not isinstance(chain_id, str) or not chain_id:
            raise AuditIntegrityError(f"audit record {index}: invalid chain_id")
        sequence = audit.get("seq")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise AuditIntegrityError(f"audit record {index}: invalid sequence")
        timestamp = audit.get("timestamp")
        if not isinstance(timestamp, str) or not timestamp:
            raise AuditIntegrityError(f"audit record {index}: invalid timestamp")
        previous_digest = audit.get("prev_digest")
        if not isinstance(previous_digest, str) or not previous_digest:
            raise AuditIntegrityError(f"audit record {index}: invalid prev_digest")
        key_id = audit.get("key_id")
        if not isinstance(key_id, str) or not key_id:
            raise AuditIntegrityError(f"audit record {index}: invalid key_id")
        signature = audit.get("hmac")
        if not isinstance(signature, str) or not signature:
            raise AuditIntegrityError(f"audit record {index}: invalid HMAC")
        return audit

    def verify_file(
        self,
        path: str | os.PathLike[str],
        anchor: AuditAnchor | Mapping[str, Any] | None = None,
    ) -> AuditVerification:
        """Verify a UTF-8 JSON-lines file."""
        return self.verify(Path(path).read_bytes(), anchor=anchor)

    def verify_records(
        self,
        records: Iterable[Mapping[str, Any] | str | bytes],
        anchor: AuditAnchor | Mapping[str, Any] | None = None,
    ) -> AuditVerification:
        """Alias for :meth:`verify`."""
        return self.verify(records, anchor=anchor)

    validate = verify
    verify_lines = verify
    verify_jsonl = verify

    def __repr__(self) -> str:
        return f"AuditVerifier(key_ring={self.key_ring!r}, anchor={self.anchor!r})"


def verify_audit_chain(
    lines: str | bytes | os.PathLike[str] | Iterable[str | bytes | Mapping[str, Any]],
    keys: AuditKeyRing | Mapping[str, Any] | None = None,
    anchor: AuditAnchor | Mapping[str, Any] | None = None,
    *,
    key_ring: AuditKeyRing | Mapping[str, Any] | None = None,
    key: Any = None,
    secret: Any = None,
    key_id: str | None = None,
) -> AuditVerification:
    """Convenience wrapper around :class:`AuditVerifier`."""
    verifier = AuditVerifier(
        keys if key_ring is None else key_ring,
        keys=keys if key_ring is not None else None,
        key=key,
        secret=secret,
        key_id=key_id,
        anchor=anchor,
    )
    return verifier.verify(lines)


verify_chain = verify_audit_chain
replay_audit_chain = verify_audit_chain
replay_chain = verify_audit_chain


### FILE HANDLER
### ============================================================================
def _read_recovery_lines(data: bytes) -> tuple[list[bytes], bytes]:
    if not data:
        return [], b""
    if data.endswith(b"\n"):
        return data[:-1].split(b"\n"), b""
    parts = data.split(b"\n")
    return parts[:-1], parts[-1]


def _complete_prefix_size(complete_lines: list[bytes]) -> int:
    return sum(len(line) + 1 for line in complete_lines)


class _TransactionalBuffer:
    """Buffers complete signed lines and rolls back a failed append."""

    def __init__(self, stream: Any, *, fsync: bool = False) -> None:
        self.stream = stream
        self.fsync = fsync

    def flush(self, records: Iterable[AuditRecord]) -> int:
        pending = list(records)
        if not pending:
            self.stream.flush()
            return 0

        start_size = self._stream_size()
        try:
            for item in pending:
                payload = item.line.encode("utf-8") + b"\n"
                self.stream.write(payload)
            self.stream.flush()
            if self.fsync:
                os.fsync(self.stream.fileno())
        except Exception:
            self._rollback(start_size)
            raise AuditWriteError(
                "audit buffer flush failed; chain head was not advanced"
            ) from None
        return len(pending)

    def _stream_size(self) -> int | None:
        try:
            return os.fstat(self.stream.fileno()).st_size
        except (AttributeError, OSError, ValueError):
            return None

    def _rollback(self, start_size: int | None) -> None:
        try:
            self.stream.flush()
        except Exception:
            pass
        try:
            self.stream.close()
        except Exception:
            pass
        if start_size is not None and getattr(self.stream, "name", None):
            try:
                with open(self.stream.name, "r+b") as handle:
                    handle.truncate(start_size)
            except OSError:
                pass


class AuditFileHandler(logging.Handler):
    """Append-only JSONL handler with ordered writes and crash recovery.

    Sequence assignment, signing, and stream writes are serialized by the
    handler lock.  Newly built records remain pending until the write and flush
    succeed; only then is the formatter's committed head advanced.  On a flush
    failure the partial append is rolled back and pending records are retained
    for an idempotent retry.  On restart the handler verifies the existing file
    and resumes from its last verified record (safe for key rotation as long as
    the old keys are present in the ring).

    Args:
        filename: JSONL file to append to.
        formatter: optional preconfigured :class:`AuditFormatter`.
        key_ring, keys, key, secret, key_id: key configuration when ``formatter``
            is omitted.
        chain_id: expected/configured chain ID.
        anchor: explicit verified prefix to resume from.
        recover: verify and resume an existing file (default ``True``).
        auto_flush: flush after each record (default ``True``).
        fsync: call ``os.fsync`` after a successful flush (default ``False``).
        delay: defer opening/verifying until the first record (default ``False``).
        mode: standard file mode; only append is used after initialization.  An
            explicit ``"w"``/``"wb"`` truncates the file once before the first open.
    """

    def __init__(
        self,
        filename: str | os.PathLike[str],
        mode: str = "a",
        *,
        formatter: AuditFormatter | None = None,
        key_ring: AuditKeyRing | Mapping[str, Any] | None = None,
        keys: Mapping[str, Any] | None = None,
        key: Any = None,
        secret: Any = None,
        key_id: str | None = None,
        chain_id: str | None = None,
        anchor: AuditAnchor | Mapping[str, Any] | None = None,
        recover: bool = True,
        auto_flush: bool = True,
        fsync: bool = False,
        delay: bool = False,
        encoding: str | None = "utf-8",
        errors: str | None = None,
        level: int = logging.NOTSET,
        **kwargs,
    ) -> None:
        alias_active_key_id = kwargs.pop("active_key_id", None)
        if alias_active_key_id is not None:
            if key_id is not None:
                raise AuditConfigurationError("provide either key_id or active_key_id, not both")
            key_id = alias_active_key_id
        alias_keys = kwargs.pop("hmac_keys", None)
        alias_key = kwargs.pop("hmac_key", None)
        alias_key_ring = kwargs.pop("keyring", None)
        if alias_keys is not None:
            if keys is not None:
                raise AuditConfigurationError("provide either keys or hmac_keys, not both")
            keys = alias_keys
        if alias_key is not None:
            if key is not None or secret is not None:
                raise AuditConfigurationError("provide only one of key, secret, or hmac_key")
            key = alias_key
        if alias_key_ring is not None:
            if key_ring is not None:
                raise AuditConfigurationError("provide either key_ring or keyring, not both")
            key_ring = alias_key_ring
        alias_chain_id = kwargs.pop("chain", None)
        if alias_chain_id is not None:
            if chain_id is not None:
                raise AuditConfigurationError("provide either chain_id or chain, not both")
            chain_id = alias_chain_id
        alias_anchor = kwargs.pop("resume_from", None)
        if alias_anchor is not None:
            if anchor is not None:
                raise AuditConfigurationError("provide either anchor or resume_from, not both")
            anchor = alias_anchor
        if kwargs:
            unexpected = next(iter(kwargs))
            raise AuditConfigurationError(f"unexpected audit handler option {unexpected!r}")
        if mode not in {"a", "ab", "w", "wb"}:
            raise AuditConfigurationError(
                "AuditFileHandler mode must be one of 'a', 'ab', 'w', or 'wb'"
            )
        if encoding is None:
            encoding = "utf-8"
        if encoding.lower().replace("-", "").replace("_", "") not in {
            "utf8",
            "utf8sig",
        }:
            raise AuditConfigurationError("audit files must use UTF-8 encoding")

        super().__init__(level=level)
        if formatter is not None:
            self.formatter = formatter
        self.filename = os.fsdecode(os.fspath(filename))
        self.recover = recover
        self.auto_flush = auto_flush
        self.fsync = fsync
        self.delay = delay
        self.encoding = encoding
        self.errors = errors
        self.mode = mode

        self._stream: Any = None
        self._buffer: _TransactionalBuffer | None = None
        self._formatter: AuditFormatter | None = formatter
        self._needs_separator = False
        self._initialized_file = False
        self._closed = False

        if secret is not None:
            if key is not None:
                raise AuditConfigurationError("provide either key or secret, not both")
            key = secret

        if formatter is not None:
            if any(item is not None for item in (key_ring, keys, key, key_id, chain_id, anchor)):
                raise AuditConfigurationError(
                    "key/anchor configuration must not be supplied with formatter"
                )
            self._key_ring = formatter.key_ring
            self._configured_chain_id = formatter.chain_id
            self._configured_anchor = formatter.head if formatter.sequence >= 0 else None
            formatter._set_manual_commit(True)
        else:
            self._key_ring = _build_key_ring(key_ring=key_ring, keys=keys, key=key, key_id=key_id)
            self._configured_chain_id = chain_id
            self._configured_anchor = _coerce_anchor(anchor)
            if (
                self._configured_anchor is not None
                and self._configured_chain_id is not None
                and self._configured_anchor.chain_id != self._configured_chain_id
            ):
                raise AuditConfigurationError("anchor chain_id does not match chain_id")
            if self._configured_chain_id is None and self._configured_anchor is not None:
                self._configured_chain_id = self._configured_anchor.chain_id

        if not delay:
            self._ensure_open()

    @property
    def audit_formatter(self) -> AuditFormatter:
        """The audit formatter used by this handler."""
        self._ensure_open()
        assert self._formatter is not None
        return self._formatter

    @property
    def stream(self) -> Any:
        """The open binary append stream."""
        self._ensure_open()
        return self._stream

    def _ensure_open(self) -> None:
        with self.lock:
            if self._closed:
                raise AuditConfigurationError("audit handler is closed")
            if self._stream is not None:
                return

            path = Path(self.filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            if not self._initialized_file:
                if self.mode in {"w", "wb"} and path.exists():
                    path.write_bytes(b"")
                self._initialized_file = True
            data = path.read_bytes() if path.exists() else b""
            recovered_anchor = self._configured_anchor
            recovered_chain_id = self._configured_chain_id
            needs_separator = False

            if data and not self.recover:
                raise AuditConfigurationError(
                    "existing audit file requires recovery; set recover=True"
                )

            if data:
                complete_lines, trailing = _read_recovery_lines(data)
                accepted_lines = complete_lines
                truncate_to: int | None = None

                if trailing:
                    try:
                        candidate = AuditVerifier(self._key_ring, anchor=recovered_anchor).verify(
                            complete_lines + [trailing]
                        )
                    except AuditIntegrityError:
                        candidate = None
                    if candidate is not None:
                        accepted_lines = complete_lines + [trailing]
                        needs_separator = True
                    else:
                        truncate_to = _complete_prefix_size(complete_lines)

                try:
                    verification = AuditVerifier(self._key_ring, anchor=recovered_anchor).verify(
                        accepted_lines
                    )
                except AuditIntegrityError as exc:
                    raise AuditIntegrityError(
                        f"existing audit file failed verification: {exc}"
                    ) from None

                if verification.chain_id is None and accepted_lines:
                    raise AuditIntegrityError("existing audit file contains no verified records")
                if verification.chain_id is not None and (
                    recovered_chain_id is not None and verification.chain_id != recovered_chain_id
                ):
                    raise AuditIntegrityError("existing audit file belongs to a different chain")
                if verification.chain_id is not None:
                    recovered_chain_id = verification.chain_id
                    recovered_anchor = verification.head

                if truncate_to is not None:
                    with open(path, "r+b") as handle:
                        handle.truncate(truncate_to)
                    data = data[:truncate_to]

            if recovered_chain_id is None:
                recovered_chain_id = uuid.uuid4().hex
            if recovered_anchor is None:
                recovered_anchor = AuditAnchor.genesis(recovered_chain_id)
            if recovered_anchor.chain_id != recovered_chain_id:
                raise AuditConfigurationError("recovered anchor has the wrong chain_id")

            if self._formatter is None:
                self._formatter = AuditFormatter(
                    key_ring=self._key_ring,
                    chain_id=recovered_chain_id,
                    anchor=recovered_anchor,
                    manual_commit=True,
                )
            else:
                if self._formatter.chain_id != recovered_chain_id:
                    raise AuditIntegrityError("existing audit file belongs to a different chain")
                try:
                    self._formatter._restore_anchor(recovered_anchor)
                except AuditConfigurationError:
                    if self._formatter.head != recovered_anchor:
                        raise

            # Keep the standard Handler.formatter attribute useful for callers
            # that inspect their configured handler, while audit_formatter remains
            # the typed accessor used internally.
            self.formatter = self._formatter

            self._stream = open(path, "ab")
            self._buffer = _TransactionalBuffer(self._stream, fsync=self.fsync)
            self._needs_separator = needs_separator
            if self._needs_separator:
                self._buffer.flush([])
            return

    def emit(self, record: logging.LogRecord) -> None:
        """Build and optionally flush one audit record under the handler lock."""
        self.acquire()
        try:
            try:
                formatter = self.audit_formatter
                formatter.format(record)
                if self.auto_flush:
                    self.flush()
            except Exception:
                self.handleError(record)
        finally:
            self.release()

    def flush(self) -> None:
        """Write all pending records, then advance the committed chain head."""
        self.acquire()
        try:
            self._ensure_open()
            assert self._buffer is not None
            self._buffer.stream = self._stream
            formatter = self.audit_formatter
            pending = formatter.pending_records
            if self._needs_separator:
                if pending:
                    with open(self.filename, "ab") as handle:
                        handle.write(b"\n")
                self._needs_separator = False
            try:
                written = self._buffer.flush(pending)
            except AuditWriteError:
                self._stream = None
                self._buffer = None
                raise
            if written:
                formatter.commit(pending)
        finally:
            self.release()

    def close(self) -> None:
        """Flush pending records and close the append stream."""
        self.acquire()
        try:
            if self._closed:
                return
            try:
                has_pending = self._formatter is not None and bool(self._formatter.pending_records)
                if self._stream is not None or has_pending:
                    self.flush()
            finally:
                stream = self._stream
                self._stream = None
                try:
                    if stream is not None:
                        stream.close()
                finally:
                    self._buffer = None
                    self._closed = True
                    super().close()
        finally:
            self.release()

    def __repr__(self) -> str:
        formatter = self._formatter
        return f"AuditFileHandler(filename={self.filename!r}, " f"formatter={formatter!r})"


### CONVENIENCE ALIASES
### ============================================================================
AuditJsonFormatter = AuditFormatter
AuditChainFormatter = AuditFormatter
AuditLogFormatter = AuditFormatter
AuditHmacFormatter = AuditFormatter
AuditTrailFormatter = AuditFormatter
TamperEvidentFormatter = AuditFormatter
AuditChainVerifier = AuditVerifier
ChainVerifier = AuditVerifier
AuditTrailVerifier = AuditVerifier
TamperEvidentVerifier = AuditVerifier
Verifier = AuditVerifier
KeyRing = AuditKeyRing
AuditHandler = AuditFileHandler
AuditChainHandler = AuditFileHandler


__all__ = [
    "AUDIT_FIELD",
    "AUDIT_VERSION",
    "AuditAnchor",
    "AuditChainError",
    "AuditChainFormatter",
    "AuditChainHandler",
    "AuditChainVerifier",
    "AuditConfigurationError",
    "AuditFileHandler",
    "AuditFormatter",
    "AuditHandler",
    "AuditHmacFormatter",
    "AuditIntegrityError",
    "AuditJsonFormatter",
    "AuditKey",
    "AuditKeyRing",
    "AuditLogFormatter",
    "AuditRecord",
    "AuditTrailFormatter",
    "AuditTrailVerifier",
    "AuditVerification",
    "AuditVerifier",
    "AuditWriteError",
    "ChainVerifier",
    "KeyRing",
    "TamperEvidentFormatter",
    "TamperEvidentVerifier",
    "Verifier",
    "canonical_json",
    "genesis_digest",
    "record_digest",
    "replay_audit_chain",
    "replay_chain",
    "verify_audit_chain",
    "verify_chain",
]

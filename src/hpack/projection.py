"""
Build redacted, traceable projections of offline HPACK header blocks.

The objects in this module are intended for training-data pipelines.  They
accept header blocks that were captured independently of one another and
replay them from caller-supplied, trusted HPACK dynamic-table checkpoints.
Only a small portion of the decoded data is retained in the projection: field
values are exported only when the field name is on the caller's allow-list.
Everything else is replaced by a redaction marker.  The encoded fragment bytes
are never copied into the projection or its report.

The report explicitly records:

* which fragments were proven (decoded) and which were not;
* the checkpoint used as the root of trust for each proven fragment;
* the policy version in force for each fragment;
* duplicate field occurrences without collapsing them; and
* policy additions that take effect part-way through the capture.

An unprovable fragment is never silently decoded against another fragment's
connection state.  A missing checkpoint, a checkpoint owned by another batch,
or an unresolvable dynamic-table reference all produce an explicit gap in the
report.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path as FilePath
from typing import Any, Literal

from .exceptions import HPACKDecodingError, InvalidTableIndexError
from .hpack import DEFAULT_MAX_HEADER_LIST_SIZE, Decoder
from .struct import HeaderTuple, NeverIndexedHeaderTuple
from .table import HeaderTable, table_entry_size

#: Value written to the projection for a field whose value was not retained.
REDACTED = "<redacted>"

Status = Literal["proven", "unproven"]
Reason = Literal[
    "missing_context",
    "missing_checkpoint",
    "missing_history",
    "state_mismatch",
    "invalid_checkpoint",
    "broken_chain",
    "decode_error",
]


def _as_name(value: str | bytes) -> str:
    """Return a normalized HTTP/2 field name."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").lower()
    return str(value).lower()


def _as_text(value: bytes | str) -> str:
    """Return decoded bytes for display without raising on invalid UTF-8."""
    if isinstance(value, str):
        return value
    return value.decode("utf-8", "replace")


def _as_bytes(value: bytes | bytearray | memoryview) -> bytes:
    """Return an immutable byte string for a fragment or table entry."""
    return bytes(value)


@dataclass(frozen=True)
class TableCheckpoint:
    """
    A trusted snapshot of a HPACK dynamic table.

    ``dynamic_entries`` is ordered from newest to oldest, matching
    :attr:`hpack.HeaderTable.dynamic_entries`.  A checkpoint records the table
    state immediately *before* the fragment that references it.  It is only
    accepted when the connection and batch identifiers agree (when both sides
    provide them), which prevents a pipeline from substituting state captured
    from an unrelated connection or batch.
    """

    checkpoint_id: str
    connection_id: str = ""
    batch_id: str = ""
    dynamic_entries: tuple[tuple[bytes, bytes], ...] = ()
    table_size: int = HeaderTable.DEFAULT_SIZE
    max_allowed_table_size: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.checkpoint_id, str) or not self.checkpoint_id:
            msg = "checkpoint_id must be a non-empty string"
            raise ValueError(msg)
        entries = tuple((_as_bytes(name), _as_bytes(value)) for name, value in self.dynamic_entries)
        object.__setattr__(self, "dynamic_entries", entries)
        if not isinstance(self.table_size, int) or self.table_size < 0:
            msg = "table_size must be a non-negative integer"
            raise ValueError(msg)
        if self.max_allowed_table_size is None:
            object.__setattr__(self, "max_allowed_table_size", max(self.table_size, HeaderTable.DEFAULT_SIZE))
        elif self.max_allowed_table_size < self.table_size:
            msg = "max_allowed_table_size must be at least table_size"
            raise ValueError(msg)

    def __repr__(self) -> str:
        """Represent checkpoint metadata without exposing table entry values."""
        return (
            f"TableCheckpoint(checkpoint_id={self.checkpoint_id!r}, "
            f"connection_id={self.connection_id!r}, batch_id={self.batch_id!r}, "
            f"entries={len(self.dynamic_entries)}, table_size={self.table_size!r})"
        )

    @property
    def used_size(self) -> int:
        """The number of bytes occupied by the checkpoint's dynamic entries."""
        return sum(table_entry_size(name, value) for name, value in self.dynamic_entries)

    @property
    def valid(self) -> bool:
        """Whether the entries fit in the declared table size."""
        return self.used_size <= self.table_size

    @classmethod
    def from_decoder(
        cls,
        decoder: Decoder,
        checkpoint_id: str,
        connection_id: str = "",
        batch_id: str = "",
    ) -> TableCheckpoint:
        """Capture the current dynamic table of ``decoder`` as a checkpoint."""
        table = decoder.header_table
        return cls(
            checkpoint_id=checkpoint_id,
            connection_id=connection_id,
            batch_id=batch_id,
            dynamic_entries=tuple(table.dynamic_entries),
            table_size=table.maxsize,
            max_allowed_table_size=decoder.max_allowed_table_size,
        )

    capture = from_decoder
    snapshot = from_decoder

    @classmethod
    def from_encoder(
        cls,
        encoder: Any,
        checkpoint_id: str,
        connection_id: str = "",
        batch_id: str = "",
    ) -> TableCheckpoint:
        """Capture the current dynamic table of an :class:`hpack.Encoder`."""
        table = encoder.header_table
        return cls(
            checkpoint_id=checkpoint_id,
            connection_id=connection_id,
            batch_id=batch_id,
            dynamic_entries=tuple(table.dynamic_entries),
            table_size=table.maxsize,
        )

    capture_encoder = from_encoder

    @classmethod
    def empty(
        cls,
        checkpoint_id: str = "empty",
        connection_id: str = "",
        batch_id: str = "",
    ) -> TableCheckpoint:
        """Return a checkpoint representing an empty dynamic table."""
        return cls(
            checkpoint_id=checkpoint_id,
            connection_id=connection_id,
            batch_id=batch_id,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize checkpoint metadata.

        The dynamic entries themselves are deliberately omitted: they may
        contain sensitive values and must not be written to an export.
        """
        return {
            "checkpoint_id": self.checkpoint_id,
            "connection_id": self.connection_id,
            "batch_id": self.batch_id,
            "table_size": self.table_size,
            "max_allowed_table_size": self.max_allowed_table_size,
            "entry_count": len(self.dynamic_entries),
            "used_size": self.used_size,
            "valid": self.valid,
        }


@dataclass(frozen=True)
class RedactionPolicy:
    """
    Controls which header values may be retained in a projection.

    :param allowed_fields: Field names whose values may be exported.  Matching
        is case-insensitive.  All other values are replaced by
        ``redaction_marker``.
    :param redaction_marker: The value written for a redacted field.
    :param include_redacted: When ``False``, fields that are not allowed are
        omitted entirely instead of being exported with a marker.
    :param redact_never_indexed: When ``True`` (the default), values carried in
        a :class:`hpack.NeverIndexedHeaderTuple` are always redacted, even if
        their name is allowed.
    """

    allowed_fields: frozenset[str] = frozenset()
    redaction_marker: str = REDACTED
    include_redacted: bool = True
    redact_never_indexed: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.allowed_fields, str):  # type: ignore[unreachable]
            normalized = frozenset({_as_name(self.allowed_fields)})
        else:
            normalized = frozenset(_as_name(field) for field in self.allowed_fields)
        object.__setattr__(self, "allowed_fields", normalized)
        if not isinstance(self.redaction_marker, str) or not self.redaction_marker:
            msg = "redaction_marker must be a non-empty string"
            raise ValueError(msg)

    def allows(self, name: str | bytes, *, never_indexed: bool = False) -> bool:
        """Return whether a field's value may be retained."""
        if never_indexed and self.redact_never_indexed:
            return False
        return _as_name(name) in self.allowed_fields

    def to_dict(self) -> dict[str, Any]:
        """Serialize the policy without any header values."""
        return {
            "allowed_fields": sorted(self.allowed_fields),
            "redaction_marker": self.redaction_marker,
            "include_redacted": self.include_redacted,
            "redact_never_indexed": self.redact_never_indexed,
        }


@dataclass(frozen=True)
class PolicyAddition:
    """
    Adds field names to the allow-list starting at ``at_fragment``.

    Additions are not retroactive: values in earlier fragments remain redacted
    even when the same field becomes allowed later.
    """

    at_fragment: int
    fields: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.at_fragment, int) or self.at_fragment < 0:
            msg = "at_fragment must be a non-negative integer"
            raise ValueError(msg)
        if isinstance(self.fields, str):  # type: ignore[unreachable]
            fields: tuple[str, ...] = (self.fields,)
        else:
            fields = tuple(self.fields)
        object.__setattr__(self, "fields", tuple(_as_name(field) for field in fields))


@dataclass(frozen=True)
class Fragment:
    """
    One independently captured HPACK header block.

    :param data: The encoded header block.  The bytes are only used during
        replay and are never stored in the resulting report.
    :param fragment_id: Optional stable identifier used in provenance records.
    :param connection_id: Optional connection identifier.  It is checked
        against the checkpoint.
    :param batch_id: Optional capture-batch identifier.  It is checked against
        the checkpoint so state from another batch cannot be substituted.
    :param checkpoint_id: Identifier of the trusted checkpoint that records the
        dynamic-table state immediately before this fragment.
    :param checkpoint: An inline trusted checkpoint.  Takes precedence over
        ``checkpoint_id``.
    :param continues_from_previous: Explicitly reuse the decoder produced by
        the immediately preceding proven fragment.  The connection and batch
        identifiers must match.
    :param fresh_context: Explicitly state that the fragment starts from a new,
        empty dynamic table.  A fragment with no checkpoint and no continuation
        is attempted from an empty table by default.
    :param requires_history: Explicitly require a checkpoint (or a previous
        proven fragment when continuing).  Without one the fragment is marked
        unprovable instead of being tried against an empty table.
    """

    data: bytes
    fragment_id: str | None = None
    connection_id: str | None = None
    batch_id: str | None = None
    checkpoint_id: str | None = None
    checkpoint: TableCheckpoint | None = None
    continues_from_previous: bool = False
    fresh_context: bool = False
    requires_history: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "data", _as_bytes(self.data))
        if self.checkpoint is not None and self.checkpoint_id is not None \
                and self.checkpoint.checkpoint_id != self.checkpoint_id:
            msg = "checkpoint_id does not match the supplied checkpoint object"
            raise ValueError(msg)
        if self.continues_from_previous and (self.checkpoint is not None or self.checkpoint_id is not None):
            msg = "a fragment cannot both continue from a previous fragment and use a checkpoint"
            raise ValueError(msg)
        if self.continues_from_previous and self.fresh_context:
            msg = "a fragment cannot both continue and declare a fresh context"
            raise ValueError(msg)
        if self.fresh_context and self.requires_history:
            msg = "a fragment cannot both declare a fresh context and require history"
            raise ValueError(msg)

    def __repr__(self) -> str:
        """Represent fragment metadata without exposing its encoded payload."""
        return (
            f"Fragment(fragment_id={self.fragment_id!r}, connection_id={self.connection_id!r}, "
            f"batch_id={self.batch_id!r}, checkpoint_id={self.checkpoint_id!r}, "
            f"encoded_size={len(self.data)})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize fragment metadata without exporting its encoded payload."""
        return {
            "fragment_id": self.fragment_id,
            "connection_id": self.connection_id,
            "batch_id": self.batch_id,
            "checkpoint_id": self.checkpoint_id,
            "encoded_size": len(self.data),
            "continues_from_previous": self.continues_from_previous,
            "fresh_context": self.fresh_context,
            "requires_history": self.requires_history,
        }


# Common alternative names used by capture tooling.
OfflineFragment = Fragment
HeaderFragment = Fragment
TrustedCheckpoint = TableCheckpoint
CompressionCheckpoint = TableCheckpoint


@dataclass(frozen=True)
class ProjectedHeader:
    """
    One header field in a redacted projection.

    For a redacted field, ``value`` contains only the policy's redaction
    marker.  The original value is not retained anywhere on this object.
    """

    name: str
    value: str
    redacted: bool
    occurrence: int
    duplicate: bool
    fragment_index: int
    field_index: int
    policy_version: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize this field, including only the redacted value."""
        return {
            "name": self.name,
            "value": self.value,
            "redacted": self.redacted,
            "occurrence": self.occurrence,
            "duplicate": self.duplicate,
            "fragment_index": self.fragment_index,
            "field_index": self.field_index,
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class FragmentProjection:
    """The replay result for one offline HPACK fragment."""

    index: int
    fragment_id: str | None
    status: Status
    reason: Reason | None
    checkpoint_id: str | None
    connection_id: str | None
    batch_id: str | None
    policy_version: int
    headers: tuple[ProjectedHeader, ...]
    encoded_size: int
    proof_chain: tuple[str, ...]
    omitted_field_count: int = 0
    redacted_field_count: int = 0
    error_type: str | None = None
    rejected_checkpoint_id: str | None = None

    @property
    def proven(self) -> bool:
        """Whether this fragment was fully decoded."""
        return self.status == "proven"

    @property
    def missing_history(self) -> bool:
        """Whether the fragment is unproven because its prior state is absent."""
        return self.reason in {
            "missing_context",
            "missing_checkpoint",
            "missing_history",
            "broken_chain",
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize this fragment's redacted result."""
        return {
            "index": self.index,
            "fragment_index": self.index,
            "fragment_id": self.fragment_id,
            "status": self.status,
            "proven": self.proven,
            "reason": self.reason,
            "missing_history": self.missing_history,
            "checkpoint_id": self.checkpoint_id,
            "connection_id": self.connection_id,
            "batch_id": self.batch_id,
            "policy_version": self.policy_version,
            "encoded_size": self.encoded_size,
            "proof_chain": list(self.proof_chain),
            "headers": [header.to_dict() for header in self.headers],
            "omitted_field_count": self.omitted_field_count,
            "redacted_field_count": self.redacted_field_count,
            "error_type": self.error_type,
            "rejected_checkpoint_id": self.rejected_checkpoint_id,
        }


@dataclass(frozen=True)
class ProjectionReport:
    """
    A complete redacted projection and its proof report.

    ``proven_ranges`` and ``unproven_ranges`` are inclusive ``(start, end)``
    pairs over fragment indices.  They make it explicit which parts of an
    offline capture can still be proven after a checkpoint is removed.
    """

    segments: tuple[FragmentProjection, ...]
    proven_ranges: tuple[tuple[int, int], ...]
    unproven_ranges: tuple[tuple[int, int], ...]
    policy_events: tuple[dict[str, Any], ...]
    policy: RedactionPolicy

    @property
    def fragments(self) -> tuple[FragmentProjection, ...]:
        """Alias for :attr:`segments`."""
        return self.segments

    @property
    def proven(self) -> bool:
        """Whether every fragment in the projection was proven."""
        return all(segment.proven for segment in self.segments)

    @property
    def proven_indices(self) -> tuple[int, ...]:
        """Indices of all proven fragments."""
        return tuple(segment.index for segment in self.segments if segment.proven)

    @property
    def unproven_indices(self) -> tuple[int, ...]:
        """Indices of all unproven fragments."""
        return tuple(segment.index for segment in self.segments if not segment.proven)

    @property
    def missing_history(self) -> bool:
        """Whether any fragment is unproven for lack of prior compression state."""
        return any(segment.missing_history for segment in self.segments)

    @property
    def proven_segments(self) -> tuple[FragmentProjection, ...]:
        """All fragments that were proven."""
        return tuple(segment for segment in self.segments if segment.proven)

    @property
    def unproven_segments(self) -> tuple[FragmentProjection, ...]:
        """All fragments that could not be proven."""
        return tuple(segment for segment in self.segments if not segment.proven)

    @property
    def headers(self) -> tuple[ProjectedHeader, ...]:
        """All projected headers, in fragment and field order."""
        return tuple(header for segment in self.segments for header in segment.headers)

    def summary(self) -> str:
        """Return a short human-readable proof summary."""
        if not self.segments:
            return "no fragments"
        proven = ", ".join(
            f"{start}" if start == end else f"{start}-{end}"
            for start, end in self.proven_ranges
        ) or "none"
        unproven = ", ".join(
            f"{start}" if start == end else f"{start}-{end}"
            for start, end in self.unproven_ranges
        ) or "none"
        return f"proven fragments: {proven}; unproven fragments: {unproven}"

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize the report.

        Redacted values appear as the policy's marker.  Raw fragment bytes,
        checkpoint entries, and decode exceptions are never included.
        """
        segments = [segment.to_dict() for segment in self.segments]
        return {
            "segments": segments,
            "fragments": segments,
            "proven_ranges": [list(item) for item in self.proven_ranges],
            "unproven_ranges": [list(item) for item in self.unproven_ranges],
            "policy": self.policy.to_dict(),
            "policy_events": [dict(event) for event in self.policy_events],
            "proven": self.proven,
            "summary": self.summary(),
        }

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialize the redacted report as JSON."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def save(self, path: str | FilePath, *, indent: int | None = 2) -> None:
        """Write the redacted JSON export to path."""
        FilePath(path).write_text(self.to_json(indent=indent), encoding="utf-8")


# Friendly aliases for callers that treat the report as the projection itself.
HeaderProjection = ProjectionReport
RedactedProjection = ProjectionReport
ProjectedFragment = FragmentProjection
ProjectionPolicy = RedactionPolicy
RedactedHeader = ProjectedHeader
DynamicTableCheckpoint = TableCheckpoint
EncodedFragment = Fragment
Checkpoint = TableCheckpoint
ReplayReport = ProjectionReport


def _normalize_policy(policy: RedactionPolicy | Iterable[str] | None) -> RedactionPolicy:
    if policy is None:
        return RedactionPolicy()
    if isinstance(policy, RedactionPolicy):
        return policy
    if isinstance(policy, str):
        return RedactionPolicy(allowed_fields=frozenset({policy}))
    return RedactionPolicy(allowed_fields=frozenset(policy))


def _normalize_additions(
    additions: Sequence[PolicyAddition] | Mapping[int, Iterable[str]],
) -> tuple[PolicyAddition, ...]:
    if isinstance(additions, Mapping):
        normalized = [
            PolicyAddition(at_fragment=index, fields=(fields,) if isinstance(fields, str) else tuple(fields))
            for index, fields in additions.items()
        ]
    else:
        normalized = list(additions)
    return tuple(sorted(normalized, key=lambda addition: addition.at_fragment))


def _normalize_checkpoints(
    checkpoints: Mapping[str, TableCheckpoint] | Iterable[TableCheckpoint] | None,
) -> dict[str, TableCheckpoint]:
    if checkpoints is None:
        return {}
    if isinstance(checkpoints, Mapping):
        items = list(checkpoints.items())
    else:
        items = [(checkpoint.checkpoint_id, checkpoint) for checkpoint in checkpoints]
    result: dict[str, TableCheckpoint] = {}
    for key, checkpoint in items:
        if key != checkpoint.checkpoint_id:
            msg = f"checkpoint mapping key {key!r} does not match checkpoint id {checkpoint.checkpoint_id!r}"
            raise ValueError(msg)
        if key in result:
            msg = f"duplicate checkpoint id {key!r}"
            raise ValueError(msg)
        result[key] = checkpoint
    return result


def _checkpoint_matches(fragment: Fragment, checkpoint: TableCheckpoint) -> bool:
    connection_mismatch = (
        fragment.connection_id is not None
        and bool(checkpoint.connection_id)
        and fragment.connection_id != checkpoint.connection_id
    )
    batch_mismatch = (
        fragment.batch_id is not None
        and bool(checkpoint.batch_id)
        and fragment.batch_id != checkpoint.batch_id
    )
    return not (connection_mismatch or batch_mismatch)


def _decoder_from_checkpoint(checkpoint: TableCheckpoint, max_header_list_size: int) -> Decoder:
    decoder = Decoder(max_header_list_size=max_header_list_size)
    if checkpoint.max_allowed_table_size is not None:
        decoder.max_allowed_table_size = checkpoint.max_allowed_table_size
    table = decoder.header_table
    table.maxsize = checkpoint.table_size
    for name, value in reversed(checkpoint.dynamic_entries):
        table.add(name, value)
    table.resized = False
    return decoder


def _project_headers(
    headers: Sequence[HeaderTuple],
    policy: RedactionPolicy,
    fragment_index: int,
    policy_version: int,
) -> tuple[tuple[ProjectedHeader, ...], int]:
    projected: list[ProjectedHeader] = []
    occurrences: dict[str, int] = {}
    omitted = 0
    for field_index, header in enumerate(headers):
        name = _as_text(header[0])
        never_indexed = isinstance(header, NeverIndexedHeaderTuple) or not header.indexable
        retained = policy.allows(name, never_indexed=never_indexed)
        occurrence = occurrences.get(name, 0)
        occurrences[name] = occurrence + 1
        if not retained and not policy.include_redacted:
            omitted += 1
            continue
        projected.append(
            ProjectedHeader(
                name=name,
                value=_as_text(header[1]) if retained else policy.redaction_marker,
                redacted=not retained,
                occurrence=occurrence,
                duplicate=occurrence > 0,
                fragment_index=fragment_index,
                field_index=field_index,
                policy_version=policy_version,
            ),
        )
    return tuple(projected), omitted


def _ranges(segments: Sequence[FragmentProjection], *, proven: bool) -> tuple[tuple[int, int], ...]:
    ranges: list[tuple[int, int]] = []
    start: int | None = None
    previous: int | None = None
    for segment in segments:
        if segment.proven is proven:
            if start is None:
                start = segment.index
            previous = segment.index
        elif start is not None:
            ranges.append((start, previous if previous is not None else start))
            start = None
            previous = None
    if start is not None:
        ranges.append((start, previous if previous is not None else start))
    return tuple(ranges)


def build_projection(  # noqa: C901, PLR0912, PLR0913, PLR0915
    fragments: Sequence[Fragment | bytes | bytearray | memoryview],
    *,
    policy: RedactionPolicy | Iterable[str] | None = None,
    checkpoints: Mapping[str, TableCheckpoint] | Iterable[TableCheckpoint] | None = None,
    additions: Sequence[PolicyAddition] | Mapping[int, Iterable[str]] = (),
    max_header_list_size: int = DEFAULT_MAX_HEADER_LIST_SIZE,
    allowed_fields: Iterable[str] | None = None,
    trusted_checkpoints: Mapping[str, TableCheckpoint] | Iterable[TableCheckpoint] | None = None,
    policy_additions: Sequence[PolicyAddition] | Mapping[int, Iterable[str]] | None = None,
) -> ProjectionReport:
    """
    Replay offline HPACK fragments into a redacted, traceable projection.

    Each fragment starts from its own trusted checkpoint (or an explicitly
    fresh context).  State is never silently shared between fragments; callers
    that know two fragments are contiguous may opt in with
    ``Fragment.continues_from_previous``.

    :param fragments: Header blocks to replay.  Bare byte strings are treated
        as fresh, independent fragments.
    :param policy: The redaction policy, or a bare iterable of allowed field
        names.
    :param checkpoints: Trusted dynamic-table checkpoints, keyed by id or given
        as an iterable.  Each checkpoint describes the state immediately before
        the fragment that names it.
    :param additions: Mid-capture allow-list additions.  They apply starting at
        the named fragment and do not retroactively reveal earlier values.
    :param max_header_list_size: The decompressed-size limit for one fragment.
    :param allowed_fields: Alias for ``policy`` when only an allow-list is
        needed.
    :param trusted_checkpoints: Alias for ``checkpoints``.
    :param policy_additions: Alias for ``additions``.
    :returns: A :class:`ProjectionReport` containing only redacted values.
    """
    if allowed_fields is not None:
        if policy is not None:
            msg = "pass either policy or allowed_fields, not both"
            raise ValueError(msg)
        policy = allowed_fields
    if trusted_checkpoints is not None:
        if checkpoints is not None:
            msg = "pass either checkpoints or trusted_checkpoints, not both"
            raise ValueError(msg)
        checkpoints = trusted_checkpoints
    if policy_additions is not None:
        if additions != ():
            msg = "pass either additions or policy_additions, not both"
            raise ValueError(msg)
        additions = policy_additions
    normalized_policy = _normalize_policy(policy)
    normalized_additions = _normalize_additions(additions)
    checkpoint_index = _normalize_checkpoints(checkpoints)
    fragments = [
        fragment if isinstance(fragment, Fragment) else Fragment(data=fragment)
        for fragment in fragments
    ]

    additions_by_index: dict[int, list[str]] = {}
    for addition in normalized_additions:
        additions_by_index.setdefault(addition.at_fragment, []).extend(addition.fields)
    policy_events: list[dict[str, Any]] = []
    effective_fields = set(normalized_policy.allowed_fields)
    version = 0

    segments: list[FragmentProjection] = []
    previous: FragmentProjection | None = None
    previous_decoder: Decoder | None = None

    for index, fragment in enumerate(fragments):
        if index in additions_by_index:
            newly_allowed = tuple(sorted(set(additions_by_index[index])))
            effective_fields.update(newly_allowed)
            version += 1
            policy_events.append(
                {
                    "fragment_index": index,
                    "policy_version": version,
                    "added_fields": list(newly_allowed),
                    "retroactive": False,
                },
            )
        fragment_policy = RedactionPolicy(
            allowed_fields=frozenset(effective_fields),
            redaction_marker=normalized_policy.redaction_marker,
            include_redacted=normalized_policy.include_redacted,
            redact_never_indexed=normalized_policy.redact_never_indexed,
        )

        decoder: Decoder | None = None
        reason: Reason | None = None
        checkpoint_used: TableCheckpoint | None = None
        rejected_checkpoint_id: str | None = None
        proof_chain: tuple[str, ...] = ()
        label = fragment.fragment_id or str(index)

        checkpoint = fragment.checkpoint
        if checkpoint is None and fragment.checkpoint_id is not None:
            checkpoint = checkpoint_index.get(fragment.checkpoint_id)
            if checkpoint is None:
                reason = "missing_checkpoint"

        if checkpoint is not None:
            if not _checkpoint_matches(fragment, checkpoint) or not checkpoint.valid:
                reason = "state_mismatch" if not _checkpoint_matches(fragment, checkpoint) else "invalid_checkpoint"
                rejected_checkpoint_id = checkpoint.checkpoint_id
            else:
                checkpoint_used = checkpoint
                decoder = _decoder_from_checkpoint(checkpoint, max_header_list_size)
                proof_chain = (f"checkpoint:{checkpoint.checkpoint_id}", label)
        elif reason is None and fragment.continues_from_previous:
            if previous is None or not previous.proven or previous_decoder is None:
                reason = "broken_chain"
            elif (
                previous.connection_id != fragment.connection_id
                or previous.batch_id != fragment.batch_id
            ):
                reason = "state_mismatch"
            else:
                decoder = previous_decoder
                proof_chain = (*previous.proof_chain, label)
        elif reason is None:
            if fragment.requires_history:
                reason = "missing_context"
            else:
                decoder = Decoder(max_header_list_size=max_header_list_size)
                proof_chain = (f"fresh:{label}",)

        headers: tuple[ProjectedHeader, ...] = ()
        omitted = 0
        error_type: str | None = None
        status: Status = "unproven"
        if decoder is not None:
            try:
                decoded = decoder.decode(fragment.data, raw=True)
            except HPACKDecodingError as error:
                if isinstance(error, InvalidTableIndexError):
                    known_connection = fragment.connection_id is not None or fragment.batch_id is not None
                    reason = "missing_context" if known_connection else "missing_history"
                else:
                    reason = "decode_error"
                error_type = type(error).__name__
                decoder = None
            else:
                status = "proven"
                headers, omitted = _project_headers(decoded, fragment_policy, index, version)

        if status != "proven":
            proof_chain = ()
            checkpoint_used = None if reason in {"missing_context", "missing_checkpoint"} else checkpoint_used
            omitted = 0

        segment = FragmentProjection(
            index=index,
            fragment_id=fragment.fragment_id,
            status=status,
            reason=reason,
            checkpoint_id=checkpoint_used.checkpoint_id if checkpoint_used is not None else None,
            connection_id=fragment.connection_id,
            batch_id=fragment.batch_id,
            policy_version=version,
            headers=headers,
            encoded_size=len(fragment.data),
            proof_chain=proof_chain,
            omitted_field_count=omitted,
            redacted_field_count=sum(header.redacted for header in headers),
            error_type=error_type,
            rejected_checkpoint_id=rejected_checkpoint_id,
        )
        segments.append(segment)
        previous = segment
        previous_decoder = decoder if status == "proven" else None

    return ProjectionReport(
        segments=tuple(segments),
        proven_ranges=_ranges(segments, proven=True),
        unproven_ranges=_ranges(segments, proven=False),
        policy_events=tuple(policy_events),
        policy=normalized_policy,
    )


def make_checkpoint(  # noqa: PLR0913
    entries: Iterable[tuple[bytes, bytes]] = (),
    *,
    checkpoint_id: str = "checkpoint",
    connection_id: str = "",
    batch_id: str = "",
    table_size: int = HeaderTable.DEFAULT_SIZE,
    max_allowed_table_size: int | None = None,
) -> TableCheckpoint:
    """Build a TableCheckpoint from explicit dynamic-table entries."""
    return TableCheckpoint(
        checkpoint_id=checkpoint_id,
        connection_id=connection_id,
        batch_id=batch_id,
        dynamic_entries=tuple(entries),
        table_size=table_size,
        max_allowed_table_size=max_allowed_table_size,
    )


create_checkpoint = make_checkpoint

# Convenience aliases used by callers with different vocabulary.
project_headers = build_projection
replay_projection = build_projection
replay_fragments = build_projection
build_redacted_projection = build_projection
project = build_projection


def redact_headers(
    headers: Iterable[HeaderTuple | tuple[bytes, bytes]],
    policy: RedactionPolicy | Iterable[str] | None = None,
    *,
    fragment_index: int = 0,
    policy_version: int = 0,
) -> tuple[ProjectedHeader, ...]:
    """
    Redact an already-decoded header list without retaining disallowed values.

    This is useful when a caller replays HPACK itself and only needs the
    projection step.
    """
    normalized_policy = _normalize_policy(policy)
    projected, _ = _project_headers(
        [header if isinstance(header, HeaderTuple) else HeaderTuple(*header) for header in headers],
        normalized_policy,
        fragment_index,
        policy_version,
    )
    return projected

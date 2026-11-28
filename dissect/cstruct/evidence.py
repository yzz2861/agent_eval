from __future__ import annotations

import io
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Literal

from dissect.cstruct.bitbuffer import BitBuffer
from dissect.cstruct.exception import Error
from dissect.cstruct.types.enum import EnumMetaType
from dissect.cstruct.types.structure import Structure, Union, UnionMetaType

if TYPE_CHECKING:
    from collections.abc import Sequence

    from dissect.cstruct.cstruct import cstruct


ApprovalInput = Iterable[str] | Mapping[str, bool] | str | None


class EvidenceError(Error):
    """Base error for union evidence operations."""


class UnknownApproval(EvidenceError, KeyError):
    """Raised when an approval names a member the union layout does not declare."""


class EvidenceMismatch(EvidenceError):
    """Raised when recomputation does not reproduce the recorded evidence digest."""


@dataclass(frozen=True)
class UnionMemberFailure:
    """Why an approved union member could not produce evidence."""

    member: str
    reason: str
    offset: int
    available: int
    required: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "member": self.member,
            "reason": self.reason,
            "offset": self.offset,
            "available": self.available,
            "required": self.required,
        }


@dataclass(frozen=True)
class UnionMemberEvidence:
    """A reproducible proof that one approved interpretation holds for the bytes."""

    member: str
    type_name: str
    offset: int
    size: int
    raw: bytes = field(repr=False)
    value: Any = field(repr=False, compare=False)
    raw_digest: str
    value_digest: str

    @property
    def end(self) -> int:
        return self.offset + self.size

    @property
    def byte_range(self) -> tuple[int, int]:
        return (self.offset, self.end)

    @property
    def raw_hex(self) -> str:
        return self.raw.hex()

    @property
    def value_text(self) -> str:
        return _value_text(self.value)

    def as_dict(self) -> dict[str, Any]:
        return {
            "member": self.member,
            "type": self.type_name,
            "offset": self.offset,
            "size": self.size,
            "byte_range": list(self.byte_range),
            "raw_hex": self.raw_hex,
            "raw_digest": self.raw_digest,
            "value": self.value_text,
            "value_digest": self.value_digest,
        }


@dataclass(frozen=True)
class UnionConflict:
    """Two approved interpretations that overlap in the same bytes but diverge."""

    left: str
    right: str
    shared_range: tuple[int, int]
    left_value_digest: str
    right_value_digest: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "left": self.left,
            "right": self.right,
            "shared_range": list(self.shared_range),
            "left_value_digest": self.left_value_digest,
            "right_value_digest": self.right_value_digest,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class UnionMemberVerdict:
    """Outcome for a member declared by the union layout."""

    member: str
    status: Literal["proven", "withheld", "unavailable"]
    evidence: UnionMemberEvidence | None = None
    failure: UnionMemberFailure | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"member": self.member, "status": self.status}
        if self.evidence is not None:
            result["evidence"] = self.evidence.as_dict()
        if self.failure is not None:
            result["failure"] = self.failure.as_dict()
        return result


@dataclass(frozen=True)
class UnionEvidence:
    """A reproducible union read under one approval set and one layout revision.

    Only approved members can become witnesses. Every witness contains the exact
    byte range and raw bytes it used, so callers can recompute the proof without
    re-encoding the sample. Members that were not approved are withheld rather
    than silently treated as absent.
    """

    layout_name: str
    revision: int | str | None
    members: tuple[str, ...]
    approvals: tuple[str, ...]
    withheld: tuple[str, ...]
    unknown_approvals: tuple[str, ...]
    basis: bytes = field(repr=False)
    basis_start: int
    basis_end: int
    basis_digest: str
    truncated: bool
    witnesses: tuple[UnionMemberEvidence, ...]
    failures: tuple[UnionMemberFailure, ...]
    conflicts: tuple[UnionConflict, ...]
    digest: str
    _union_type: type[Union] | None = field(default=None, repr=False, compare=False)

    @property
    def data_digest(self) -> str:
        return self.basis_digest

    @property
    def proven_members(self) -> tuple[str, ...]:
        return tuple(witness.member for witness in self.witnesses)

    @property
    def proofs(self) -> tuple[UnionMemberEvidence, ...]:
        return self.witnesses

    @property
    def provable_members(self) -> tuple[str, ...]:
        return self.proven_members

    @property
    def unavailable_members(self) -> tuple[str, ...]:
        return tuple(failure.member for failure in self.failures)

    @property
    def revoked_members(self) -> tuple[str, ...]:
        return self.withheld

    @property
    def has_divergence(self) -> bool:
        return bool(self.conflicts)

    @property
    def divergences(self) -> tuple[UnionConflict, ...]:
        return self.conflicts

    @property
    def verdicts(self) -> tuple[UnionMemberVerdict, ...]:
        witness_by_name = {witness.member: witness for witness in self.witnesses}
        failure_by_name = {failure.member: failure for failure in self.failures}
        verdicts = []
        for member in self.members:
            if (witness := witness_by_name.get(member)) is not None:
                verdicts.append(UnionMemberVerdict(member, "proven", witness))
            elif (failure := failure_by_name.get(member)) is not None:
                verdicts.append(UnionMemberVerdict(member, "unavailable", failure=failure))
            else:
                verdicts.append(UnionMemberVerdict(member, "withheld"))
        return tuple(verdicts)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly report; raw samples stay as hexadecimal strings."""
        return {
            "layout": self.layout_name,
            "revision": self.revision,
            "members": list(self.members),
            "approvals": list(self.approvals),
            "proven_members": list(self.proven_members),
            "withheld": list(self.withheld),
            "unavailable": list(self.unavailable_members),
            "unknown_approvals": list(self.unknown_approvals),
            "basis": {
                "start": self.basis_start,
                "end": self.basis_end,
                "digest": self.basis_digest,
                "truncated": self.truncated,
            },
            "witnesses": [witness.as_dict() for witness in self.witnesses],
            "failures": [failure.as_dict() for failure in self.failures],
            "conflicts": [conflict.as_dict() for conflict in self.conflicts],
            "digest": self.digest,
        }

    def recompute(self, union: type[Union] | str | None = None, *, cs: cstruct | None = None) -> UnionEvidence:
        """Re-read the retained bytes and verify the result digest and witnesses."""
        return recompute_union_evidence(self, union, cs=cs)


@dataclass(frozen=True)
class LayoutRevision:
    """One layout revision in a versioned union replay."""

    revision: int | str
    union: type[Union] | str
    approvals: ApprovalInput = None
    layout: str | None = None


def read_union_evidence(
    union: type[Union] | str,
    data: bytes | bytearray | memoryview,
    approvals: ApprovalInput = None,
    *,
    cs: cstruct | None = None,
    revision: int | str | None = None,
    layout: str | None = None,
    strict: bool = True,
) -> UnionEvidence:
    """Read a union through a concrete approval set and return member evidence.

    Approvals are member names. ``None`` approves every declared member, a string
    approves that single member, and a mapping approves every key with a truthy
    value. The same bytes can prove multiple members at once; overlapping members
    with divergent decoded values remain visible as :attr:`UnionEvidence.conflicts`.

    Args:
        union: Union type, or a type name that can be resolved through ``cs``.
        data: Bytes-like sample. It is not modified or re-encoded.
        approvals: Permitted member interpretations.
        cs: Optional cstruct instance used to resolve a type name.
        revision: Layout revision label, retained in the result and digest.
        layout: Optional layout label; defaults to the union type name.
        strict: Raise :class:`UnknownApproval` for undeclared member names.

    Returns:
        A deterministic evidence record for the sample under this approval.
    """
    union_type = _resolve_union(union, cs)
    sample = bytes(data)
    members = tuple(union_type.__members__.keys())
    requested, unknown = _normalize_approvals(members, approvals)

    if unknown and strict:
        raise UnknownApproval(f"Unknown union member(s): {', '.join(unknown)}")

    declared_size = union_type.__size__
    basis_end = len(sample) if declared_size is None else min(len(sample), declared_size)

    basis = sample[:basis_end]
    truncated = declared_size is not None and len(sample) < declared_size

    witnesses: list[UnionMemberEvidence] = []
    failures: list[UnionMemberFailure] = []
    for member in requested:
        field_obj = union_type.__members__[member]
        evidence, failure = _read_member(union_type, member, field_obj, sample)
        if evidence is not None:
            witnesses.append(evidence)
        elif failure is not None:
            failures.append(failure)

    conflicts = _find_conflicts(witnesses)
    withheld = tuple(member for member in members if member not in requested)

    result = UnionEvidence(
        layout_name=layout or union_type.__name__,
        revision=revision,
        members=members,
        approvals=requested,
        withheld=withheld,
        unknown_approvals=unknown,
        basis=basis,
        basis_start=0,
        basis_end=basis_end,
        basis_digest=sha256(basis).hexdigest(),
        truncated=truncated,
        witnesses=tuple(witnesses),
        failures=tuple(failures),
        conflicts=conflicts,
        digest="",
        _union_type=union_type,
    )
    return replace(result, digest=_evidence_digest(result))


def replay_union_evidence(
    data: bytes | bytearray | memoryview,
    revisions: Sequence[LayoutRevision | tuple[Any, ...] | Mapping[str, Any]],
    *,
    cs: cstruct | None = None,
    strict: bool = True,
) -> tuple[UnionEvidence, ...]:
    """Read the same bytes against two or more layout revisions, in caller order.

    Each result keeps its own revision, layout name and approval set, so layout
    changes can be compared without changing the sample bytes.
    """
    results = []
    for spec in revisions:
        if isinstance(spec, LayoutRevision):
            revision = spec.revision
            union_type = spec.union
            approvals = spec.approvals
            layout = spec.layout
        elif isinstance(spec, Mapping):
            revision = spec["revision"]
            union_type = spec["union"]
            approvals = spec.get("approvals")
            layout = spec.get("layout")
        else:
            parts = tuple(spec)
            if len(parts) == 2:
                revision, union_type = parts
                approvals = None
                layout = None
            elif len(parts) == 3:
                revision, union_type, approvals = parts
                layout = None
            elif len(parts) == 4:
                revision, union_type, approvals, layout = parts
            else:
                raise ValueError(
                    "A revision must be (revision, union), (revision, union, approvals) or "
                    "(revision, union, approvals, layout)"
                )

        results.append(
            read_union_evidence(
                union_type,
                data,
                approvals,
                cs=cs,
                revision=revision,
                layout=layout,
                strict=strict,
            )
        )

    return tuple(results)


def recompute_union_evidence(
    evidence: UnionEvidence,
    union: type[Union] | str | None = None,
    *,
    cs: cstruct | None = None,
) -> UnionEvidence:
    """Recompute evidence from its retained bytes and verify the recorded digest."""
    union_type = _resolve_union(union or evidence._union_type, cs)
    recorded_digest = _evidence_digest(evidence)
    if recorded_digest != evidence.digest:
        raise EvidenceMismatch(
            f"Evidence record was modified before recomputation: {evidence.digest} != {recorded_digest}"
        )

    recomputed = read_union_evidence(
        union_type,
        evidence.basis,
        evidence.approvals,
        revision=evidence.revision,
        layout=evidence.layout_name,
        strict=not evidence.unknown_approvals,
    )

    if recomputed.digest != recorded_digest:
        raise EvidenceMismatch(f"Evidence digest changed on recomputation: {recorded_digest} != {recomputed.digest}")

    return recomputed


def _resolve_union(union: type[Union] | str | None, cs: cstruct | None) -> type[Union]:
    if union is None:
        raise TypeError("A union type is required for recomputation")

    if isinstance(union, str):
        if cs is None:
            raise TypeError("A cstruct instance is required to resolve a union type name")
        union = cs.resolve(union)

    if not isinstance(union, UnionMetaType) or not issubclass(union, Union):
        raise TypeError(f"Expected a union type, got {union!r}")

    return union


def _normalize_approvals(members: tuple[str, ...], approvals: ApprovalInput) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if approvals is None or approvals == "*":
        requested_names = set(members)
    elif isinstance(approvals, str):
        requested_names = {approvals}
    elif isinstance(approvals, Mapping):
        requested_names = {name for name, allowed in approvals.items() if allowed}
    else:
        requested_names = set(approvals)

    requested = tuple(member for member in members if member in requested_names)
    unknown = tuple(sorted(requested_names.difference(members)))
    return requested, unknown


def _read_member(
    union_type: type[Union], member: str, field_obj: Any, data: bytes
) -> tuple[UnionMemberEvidence | None, UnionMemberFailure | None]:
    offset = field_obj.offset or 0
    available = max(0, len(data) - offset)
    declared_size = field_obj.type.__size__
    required = declared_size

    if declared_size is not None and available < declared_size:
        return None, UnionMemberFailure(member, "insufficient bytes", offset, available, required)

    stream = io.BytesIO(data)
    stream.seek(offset)
    endian = union_type.__cs__.endian
    try:
        if field_obj.bits:
            bit_buffer = BitBuffer(stream, endian=endian)
            if isinstance(field_obj.type, EnumMetaType):
                value = field_obj.type(bit_buffer.read(field_obj.type.__type__, field_obj.bits))
            else:
                value = bit_buffer.read(field_obj.type, field_obj.bits)
            consumed = declared_size or 0
        else:
            value = field_obj.type._read(stream, context={}, endian=endian)
            consumed = stream.tell() - offset
    except EOFError as exc:
        return None, UnionMemberFailure(member, str(exc) or "unexpected end of input", offset, available, required)
    except Exception as exc:  # A member-specific failure must not hide other approved members.
        return None, UnionMemberFailure(member, f"{type(exc).__name__}: {exc}", offset, available, required)

    if declared_size is not None:
        consumed = declared_size

    end = offset + consumed
    raw = data[offset:end]
    if len(raw) < consumed:
        return None, UnionMemberFailure(member, "insufficient bytes", offset, available, consumed)

    type_name = getattr(field_obj.type, "__name__", field_obj.type.__class__.__name__)
    return (
        UnionMemberEvidence(
            member=member,
            type_name=type_name,
            offset=offset,
            size=consumed,
            raw=raw,
            value=value,
            raw_digest=sha256(raw).hexdigest(),
            value_digest=sha256(_value_fingerprint(value)).hexdigest(),
        ),
        None,
    )


def _value_fingerprint(value: Any) -> bytes:
    if isinstance(value, Structure):
        try:
            rendered = value.dumps()
        except Exception:
            rendered = repr(value).encode()
        return b"structure:" + type(value).__name__.encode() + b":" + rendered

    if isinstance(value, (bytes, bytearray, memoryview)):
        return b"bytes:" + bytes(value)

    if isinstance(value, bool):
        return b"bool:" + (b"1" if value else b"0")

    if isinstance(value, int):
        return b"int:" + str(value).encode()

    if isinstance(value, float):
        return b"float:" + value.hex().encode()

    if isinstance(value, str):
        return b"str:" + value.encode()

    if isinstance(value, (list, tuple)):
        return b"sequence:[" + b",".join(_value_fingerprint(entry) for entry in value) + b"]"

    return f"{type(value).__module__}.{type(value).__qualname__}:{value!r}".encode()


def _value_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Structure):
        try:
            return value.dumps().hex()
        except Exception:
            pass
    return repr(value)


def _find_conflicts(witnesses: list[UnionMemberEvidence]) -> tuple[UnionConflict, ...]:
    conflicts = []
    for index, left in enumerate(witnesses):
        for right in witnesses[index + 1 :]:
            shared_start = max(left.offset, right.offset)
            shared_end = min(left.end, right.end)
            if shared_end <= shared_start:
                continue

            if left.value_digest != right.value_digest:
                reason = "same bytes decode to different values"
            elif left.type_name != right.type_name:
                reason = "same bytes are admitted by different member types"
            else:
                continue

            conflicts.append(
                UnionConflict(
                    left=left.member,
                    right=right.member,
                    shared_range=(shared_start, shared_end),
                    left_value_digest=left.value_digest,
                    right_value_digest=right.value_digest,
                    reason=reason,
                )
            )
    return tuple(conflicts)


def _evidence_digest(evidence: UnionEvidence) -> str:
    payload = {
        "layout": evidence.layout_name,
        "revision": evidence.revision,
        "members": evidence.members,
        "approvals": evidence.approvals,
        "withheld": evidence.withheld,
        "unknown_approvals": evidence.unknown_approvals,
        "basis": evidence.basis_digest,
        "basis_range": (evidence.basis_start, evidence.basis_end),
        "truncated": evidence.truncated,
        "witnesses": [
            (w.member, w.type_name, w.offset, w.size, w.raw_digest, w.value_digest) for w in evidence.witnesses
        ],
        "failures": [(f.member, f.reason, f.offset, f.available, f.required) for f in evidence.failures],
        "conflicts": [
            (c.left, c.right, c.shared_range, c.left_value_digest, c.right_value_digest, c.reason)
            for c in evidence.conflicts
        ],
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(serialized.encode()).hexdigest()


__all__ = [
    "EvidenceError",
    "EvidenceMismatch",
    "LayoutRevision",
    "UnionConflict",
    "UnionEvidence",
    "UnionMemberEvidence",
    "UnionMemberFailure",
    "UnionMemberVerdict",
    "UnknownApproval",
    "read_union_evidence",
    "recompute_union_evidence",
    "replay_union_evidence",
]

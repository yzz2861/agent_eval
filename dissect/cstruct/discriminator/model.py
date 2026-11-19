from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Callable


class CandidateStatus(str, Enum):
    """Status of one candidate schema after evaluating its invariants."""

    CONFIRMED = "confirmed"
    EXCLUDED = "excluded"
    PENDING = "pending"


class DiscriminationOutcome(str, Enum):
    """Aggregate outcome across every candidate."""

    UNIQUE_MATCH = "unique_match"
    AMBIGUOUS = "ambiguous"
    ALL_FAILED = "all_failed"


@dataclass(frozen=True, slots=True)
class Constraint:
    """A caller-declared invariant on a single fully readable field."""

    kind: str
    predicate: Callable[[object], bool]
    description: str

    def describe(self) -> str:
        return self.description

    def matches(self, value: object) -> bool:
        return bool(self.predicate(value))


def _render(value: object) -> str:
    return hex(value) if isinstance(value, int) else repr(value)


def equal_to(expected: object) -> Constraint:
    """Constraint requiring a field to equal ``expected``."""
    return Constraint("eq", lambda value: value == expected, f"== {_render(expected)}")


def one_of(*options: object) -> Constraint:
    """Constraint requiring an integer field to be one of ``options``."""
    rendered = ", ".join(_render(option) for option in options)
    allowed = frozenset(options)
    return Constraint("one_of", lambda value: value in allowed, f"in {{{rendered}}}")


def integer_range(low: int, high: int) -> Constraint:
    """Constraint requiring ``low <= value <= high`` for an integer field."""
    return Constraint(
        "range",
        lambda value: isinstance(value, int) and low <= value <= high,
        f"{low:#x} <= x <= {high:#x}",
    )


def masked_equals(mask: int, expected: int) -> Constraint:
    """Constraint requiring ``(field & mask) == expected``."""
    return Constraint(
        "masked",
        lambda value: isinstance(value, int) and (value & mask) == expected,
        f"(x & {mask:#x}) == {expected:#x}",
    )


def reserved_zero(mask: int) -> Constraint:
    """Constraint requiring the reserved bits selected by ``mask`` to be zero."""
    return masked_equals(mask, 0)


def byte_eq(expected: bytes) -> Constraint:
    """Constraint requiring a raw byte field to equal ``expected``."""
    return Constraint("bytes", lambda value: value == expected, f"== {expected!r}")


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """A fixed-offset, fixed-size field and its optional constraint."""

    name: str
    offset: int
    size: int
    kind: str = "uint"
    endian: str = "little"
    constraint: Constraint | None = None

    @property
    def span(self) -> tuple[int, int]:
        return (self.offset, self.offset + self.size)

    def parse(self, raw: bytes) -> int | bytes:
        if self.kind == "uint":
            return int.from_bytes(raw, byteorder=self.endian, signed=False)
        if self.kind == "bytes":
            return raw
        raise ValueError(f"unsupported field kind: {self.kind!r}")


@dataclass(frozen=True, slots=True)
class Violation:
    """A concrete semantic reason for excluding a candidate."""

    kind: str
    name: str
    reason: str
    span: tuple[tuple[int, int], ...] = ()
    observed: object = None


@dataclass(frozen=True, slots=True)
class Verdict:
    """Evaluation result for one candidate schema."""

    schema_name: str
    status: CandidateStatus
    violations: tuple[Violation, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    """One minimum-evidence entry that separates candidate pairs."""

    key: str
    span: tuple[int, int]
    constraints: dict[str, str]
    distinguishes: tuple[tuple[str, str], ...]
    missing_ranges: tuple[tuple[int, int], ...]
    involved_candidates: tuple[str, ...]
    readable_missing_ranges: tuple[tuple[int, int], ...] = ()

    @property
    def fully_readable(self) -> bool:
        return not self.missing_ranges

    @property
    def fetchable(self) -> bool:
        return bool(self.readable_missing_ranges)


@dataclass(frozen=True, slots=True)
class EvidencePlan:
    """Minimum evidence set separating surviving candidates.

    ``missing_ranges`` lists byte intervals that still need fetching. A plan
    with no items and ``intrinsic=True`` means every candidate reads fully and
    the record itself carries insufficient evidence to decide.
    """

    items: tuple[EvidenceItem, ...]
    missing_ranges: tuple[tuple[int, int], ...]
    resolvable: bool
    intrinsic: bool
    readable_missing_ranges: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True, slots=True)
class DiscriminationResult:
    """Full result of a multi-schema discrimination call."""

    outcome: DiscriminationOutcome
    verdicts: tuple[Verdict, ...]
    evidence_plan: EvidencePlan | None
    cache_stats: object = None

    @property
    def survivors(self) -> tuple[Verdict, ...]:
        return tuple(v for v in self.verdicts if v.status is not CandidateStatus.EXCLUDED)

    @property
    def unique(self) -> Verdict | None:
        if self.outcome is not DiscriminationOutcome.UNIQUE_MATCH:
            return None
        return self.survivors[0]


class InvariantContext(Protocol):
    """Isolated view handed to a record-level invariant."""

    def value(self, name: str) -> int | bytes:
        """Return a parsed field value, raising TruncatedRead when unreadable."""

    def bytes_for(self, offset: int, size: int) -> bytes:
        """Return raw bytes, raising TruncatedRead when the range is incomplete."""


@dataclass(frozen=True, slots=True)
class InvariantOutcome:
    """Trinary result of evaluating one record-level invariant."""

    violated: bool
    unknown: bool
    reason: str

    @staticmethod
    def satisfied(reason: str) -> InvariantOutcome:
        return InvariantOutcome(violated=False, unknown=False, reason=reason)

    @staticmethod
    def violation(reason: str) -> InvariantOutcome:
        return InvariantOutcome(violated=True, unknown=False, reason=reason)

    @staticmethod
    def undecidable(reason: str) -> InvariantOutcome:
        return InvariantOutcome(violated=False, unknown=True, reason=reason)


@runtime_checkable
class RecordInvariant(Protocol):
    """A structural invariant spanning one or more byte ranges of a record."""

    name: str

    def check(self, ctx: InvariantContext) -> InvariantOutcome:
        """Evaluate the invariant against one candidate's isolated context."""

    def describe(self) -> str:
        """Render the asserted invariant for evidence planning."""

    def evidence_spans(self, ctx: InvariantContext | None) -> tuple[tuple[int, int], ...]:
        """Byte ranges inspected while checking, used for evidence planning."""


@dataclass(frozen=True, slots=True)
class SchemaSpec:
    """A candidate schema: fixed fields plus record-level invariants."""

    name: str
    fields: tuple[FieldSpec, ...]
    invariants: tuple[RecordInvariant, ...] = ()
    _index: dict[str, FieldSpec] = field(init=False, repr=False, compare=False, default_factory=dict)

    def __post_init__(self) -> None:
        index = {spec.name: spec for spec in self.fields}
        object.__setattr__(self, "_index", index)

    def field(self, name: str) -> FieldSpec:
        try:
            return self._index[name]
        except KeyError:
            raise KeyError(f"schema {self.name!r} has no field {name!r}") from None

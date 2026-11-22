"""Evidence-aware reading for cstruct declarations.

The regular cstruct readers are strict: if a declared field is not present in
the data, reading raises an :class:`EOFError`.  That is the right default for
parsing, but it is inconvenient when examining records from multiple firmware
generations.  A newer declaration can describe all known fields, while an older
record only contains the bytes that existed in that generation.

This module provides the data model used by
:meth:`dissect.cstruct.types.structure.StructureMetaType.read_with_evidence`.
An evidence-aware read is lenient and returns the regular structure object plus
a :class:`ReadEvidence` view.  The view records, for every declared field,
whether it was read from the record, was genuinely absent, was truncated, or
received a default derived from known generation metadata.

The returned structure object is a normal cstruct object and can be passed to
existing consumers without changes.
"""

from __future__ import annotations

import io
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field as dataclass_field
from enum import Enum
from typing import TYPE_CHECKING, Any, BinaryIO

if TYPE_CHECKING:
    from dissect.cstruct.types.structure import StructureMetaType


class Presence(str, Enum):
    """How a declared field relates to the bytes of a record.

    The enum values are stable strings so they can be serialised in an audit
    trail.  ``PRESENT``, ``MISSING`` and ``DEFAULTED`` are aliases of ``READ``,
    ``ABSENT`` and ``DERIVED`` respectively.
    """

    READ = "read"
    """The field value was read from actual record bytes."""

    PRESENT = "read"
    """Alias of :attr:`READ`."""

    ABSENT = "absent"
    """The field is genuinely absent: no bytes exist at a field boundary."""

    MISSING = "absent"
    """Alias of :attr:`ABSENT`."""

    TRUNCATED = "truncated"
    """The record ended inside (or before) a field that should have bytes."""

    INSUFFICIENT = "truncated"
    """Alias of :attr:`TRUNCATED`."""

    DERIVED = "derived"
    """The value was derived from known generation metadata."""

    DEFAULTED = "derived"
    """Alias of :attr:`DERIVED`."""

    DERIVED_DEFAULT = "derived"
    """Alias of :attr:`DERIVED`."""

    GENERATION_DEFAULT = "derived"
    """Alias of :attr:`DERIVED`."""

    def __str__(self) -> str:
        return self.value

    @property
    def is_read(self) -> bool:
        """Whether the field value was read from record bytes."""
        return self is Presence.READ

    @property
    def is_absent(self) -> bool:
        """Whether the field is genuinely absent from the record."""
        return self is Presence.ABSENT

    @property
    def is_truncated(self) -> bool:
        """Whether the field was cut off by the end of the record."""
        return self is Presence.TRUNCATED

    @property
    def is_insufficient(self) -> bool:
        """Alias of :attr:`is_truncated`."""
        return self is Presence.TRUNCATED

    @property
    def is_derived(self) -> bool:
        """Whether the value was derived from known generation metadata."""
        return self is Presence.DERIVED

    @property
    def defaulted(self) -> bool:
        """Whether a default value was used for this field."""
        return self is not Presence.READ


@dataclass(frozen=True)
class FieldEvidence:
    """Evidence for one declared field in a record.

    Even when two fields have the same value (for example both zero), this
    object distinguishes a value that was actually read from the record from a
    value that was filled in with a default.
    """

    name: str
    presence: Presence
    value: Any
    offset: int = 0
    relative_offset: int = 0
    size: int | None = None
    available: int = 0
    consumed: int = 0
    raw: bytes = b""
    default: Any = None
    generation: Any = None
    introduced: Any = None
    removed: Any = None
    declaration: str | None = None
    reason: str = ""
    children: Mapping[str, FieldEvidence] | None = None

    @property
    def state(self) -> Presence:
        """Alias of :attr:`presence`."""
        return self.presence

    @property
    def is_read(self) -> bool:
        """Whether the value was read from record bytes."""
        return self.presence is Presence.READ

    @property
    def is_absent(self) -> bool:
        """Whether the field is genuinely absent from the record."""
        return self.presence is Presence.ABSENT

    @property
    def is_truncated(self) -> bool:
        """Whether the record ended inside this field."""
        return self.presence is Presence.TRUNCATED

    @property
    def is_derived(self) -> bool:
        """Whether the value was derived from known generation metadata."""
        return self.presence is Presence.DERIVED

    @property
    def defaulted(self) -> bool:
        """Whether a default value was used for this field."""
        return self.presence is not Presence.READ

    @property
    def is_present(self) -> bool:
        """Alias of :attr:`is_read`."""
        return self.is_read

    @property
    def was_read(self) -> bool:
        """Alias of :attr:`is_read`."""
        return self.is_read

    @property
    def is_default(self) -> bool:
        """Alias of :attr:`defaulted`."""
        return self.defaulted

    @property
    def bytes_read(self) -> int:
        """Alias of :attr:`consumed`."""
        return self.consumed

    @property
    def declared_size(self) -> int | None:
        """Alias of :attr:`size`."""
        return self.size

    @property
    def default_value(self) -> Any:
        """Alias of :attr:`default`."""
        return self.default

    @property
    def source(self) -> str:
        """Where the value came from: ``"bytes"`` or ``"default"``."""
        return "bytes" if self.is_read else "default"

    @property
    def default_source(self) -> str | None:
        """Why a default was used, if any.

        One of ``"generation"``, ``"absence"`` or ``"truncation"`` for a
        defaulted field, or ``None`` for a field that was read.
        """
        if self.is_derived:
            return "generation"
        if self.is_absent:
            return "absence"
        if self.is_truncated:
            return "truncation"
        return None



@dataclass(frozen=True)
class ReadEvidence(Mapping[str, FieldEvidence]):
    """An audit view of an evidence-aware read.

    The mapping part contains the evidence for every top-level field.  The
    other attributes describe the record and the declaration selection, so an
    audit trail can explain *why* a particular declaration was used.
    """

    fields: Mapping[str, FieldEvidence] = dataclass_field(default_factory=dict)
    declaration: str | None = None
    declaration_type: type | None = dataclass_field(default=None, repr=False, compare=False)
    declaration_generation: Any = None
    generation: Any = None
    selection: str = "explicit"
    basis: str = ""
    data_size: int = 0
    start: int = 0
    consumed: int = 0
    raw: bytes = b""

    def __getitem__(self, key: str) -> FieldEvidence:
        return self.fields[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.fields)

    def __len__(self) -> int:
        return len(self.fields)

    @property
    def complete(self) -> bool:
        """Whether every declared field was read from record bytes."""
        return all(field.is_read for field in self.fields.values())

    @property
    def read(self) -> dict[str, FieldEvidence]:
        """Evidence for fields that were read from record bytes."""
        return {name: field for name, field in self.fields.items() if field.is_read}

    @property
    def defaulted(self) -> dict[str, FieldEvidence]:
        """Evidence for fields that received a default value."""
        return {name: field for name, field in self.fields.items() if field.defaulted}

    @property
    def absent(self) -> dict[str, FieldEvidence]:
        """Evidence for fields that are genuinely absent."""
        return {name: field for name, field in self.fields.items() if field.is_absent}

    @property
    def missing(self) -> dict[str, FieldEvidence]:
        """Alias of :attr:`absent`."""
        return self.absent

    @property
    def truncated(self) -> dict[str, FieldEvidence]:
        """Evidence for fields that were cut off by insufficient bytes."""
        return {name: field for name, field in self.fields.items() if field.is_truncated}

    @property
    def insufficient(self) -> dict[str, FieldEvidence]:
        """Alias of :attr:`truncated`."""
        return self.truncated

    @property
    def derived(self) -> dict[str, FieldEvidence]:
        """Evidence for defaults derived from known generation metadata."""
        return {name: field for name, field in self.fields.items() if field.is_derived}

    @property
    def defaults(self) -> tuple[str, ...]:
        """Names of all fields that received a default value."""
        return tuple(self.defaulted)

    @property
    def is_complete(self) -> bool:
        """Alias of :attr:`complete`."""
        return self.complete

    @property
    def trailing(self) -> int:
        """Number of input bytes not consumed by the selected declaration."""
        return max(0, self.data_size - self.consumed)

    @property
    def presences(self) -> dict[str, Presence]:
        """Mapping of field name to presence state."""
        return {name: field.presence for name, field in self.fields.items()}

    @property
    def declaration_name(self) -> str | None:
        """Alias of :attr:`declaration`."""
        return self.declaration

    @property
    def selected_declaration(self) -> type | None:
        """Alias of :attr:`declaration_type`."""
        return self.declaration_type

    @property
    def declaration_size(self) -> int | None:
        """Static size of the selected declaration, if known."""
        return getattr(self.declaration_type, "__size__", None)

    @property
    def selected_by(self) -> str:
        """Alias of :attr:`selection`."""
        return self.selection

    @property
    def selection_basis(self) -> str:
        """Alias of :attr:`basis`."""
        return self.basis

    def for_field(self, name: str) -> FieldEvidence:
        """Return the evidence for the given field."""
        return self.fields[name]

    def __repr__(self) -> str:
        return (
            f"<ReadEvidence {self.declaration or '<anonymous>'} generation={self.generation!r} "
            f"fields={len(self.fields)} read={len(self.read)} absent={len(self.absent)} "
            f"truncated={len(self.truncated)} derived={len(self.derived)}>"
        )


@dataclass
class StreamSnapshot:
    """A seekable stream with the boundaries of the data to audit."""

    stream: BinaryIO
    start: int
    end: int
    size: int
    raw: bytes
    owned: bool = False


def prepare_stream(obj: BinaryIO | bytes | bytearray | memoryview) -> StreamSnapshot:
    """Return a seekable stream and a snapshot of the data to audit.

    Bytes-like input is wrapped in :class:`io.BytesIO`.  Non-seekable streams
    are read into memory.  The returned stream is positioned at the start of the
    data.
    """
    if isinstance(obj, memoryview):
        obj = obj.tobytes()
    if isinstance(obj, (bytes, bytearray)):
        data = bytes(obj)
        return StreamSnapshot(io.BytesIO(data), 0, len(data), len(data), data, owned=True)

    if not hasattr(obj, "read"):
        raise TypeError("Invalid object type, expected bytes-like data or a file-like object")

    try:
        seekable = obj.seekable()
    except Exception:
        seekable = False

    if not seekable:
        data = obj.read()
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("The stream did not return bytes")
        data = bytes(data)
        return StreamSnapshot(io.BytesIO(data), 0, len(data), len(data), data, owned=True)

    start = obj.tell()
    end = obj.seek(0, io.SEEK_END)
    obj.seek(start)
    # Do not read the whole remaining stream here: the evidence reader captures
    # the bytes of each field, and the raw bytes of the consumed structure.
    return StreamSnapshot(obj, start, end, end - start, b"")


@dataclass(frozen=True)
class SelectedDeclaration:
    """A declaration selected from a :class:`DeclarationSet`."""

    type: StructureMetaType
    generation: Any = None
    size: int | None = None
    selection: str = "explicit"
    basis: str = ""

    @property
    def declaration(self) -> StructureMetaType:
        """Alias of :attr:`type`."""
        return self.type

    @property
    def reason(self) -> str:
        """Alias of :attr:`basis`."""
        return self.basis


class DeclarationSet:
    """A set of declarations for different generations of a record.

    This is a small convenience layer that keeps the selected declaration and
    the reason for selecting it in the :class:`ReadEvidence` audit view.  A
    declaration can be registered explicitly with :meth:`add` or by iterating a
    mapping of generation to structure type::

        declarations = DeclarationSet("Record", {1: RecordV1, 2: RecordV2})
        record, evidence = declarations.read_with_evidence(data, generation=1)

    If no generation is given, the declaration whose static size best matches
    the input is selected and the evidence records that choice.
    """

    def __init__(
        self,
        name: str | None = None,
        declarations: Mapping[Any, StructureMetaType] | list[StructureMetaType] | None = None,
    ):
        if declarations is None and isinstance(name, (Mapping, list)):
            declarations = name
            name = None

        self.name = name
        self._declarations: dict[Any, StructureMetaType] = {}

        if declarations is not None:
            if isinstance(declarations, Mapping):
                for generation, type_ in declarations.items():
                    self.add(generation, type_)
            else:
                for index, type_ in enumerate(declarations):
                    generation = getattr(type_, "__generation__", None)
                    self.add(index if generation is None else generation, type_)

    def add(self, generation: Any, type_: StructureMetaType) -> None:
        """Register a declaration for a generation."""
        self._declarations[generation] = type_
        if self.name is None:
            self.name = getattr(type_, "__name__", None)

    def __getitem__(self, generation: Any) -> StructureMetaType:
        return self._declarations[generation]

    def __iter__(self) -> Iterator[Any]:
        return iter(self._declarations)

    def __len__(self) -> int:
        return len(self._declarations)

    def __repr__(self) -> str:
        return f"<DeclarationSet {self.name or '<anonymous>'} generations={list(self._declarations)!r}>"

    def select(self, *, generation: Any = None, size: int | None = None) -> SelectedDeclaration:
        """Select a declaration and return it with the basis for the choice."""
        if not self._declarations:
            raise ValueError("No declarations have been registered")

        if generation is not None:
            if generation in self._declarations:
                type_ = self._declarations[generation]
                return SelectedDeclaration(
                    type_,
                    generation=generation,
                    size=getattr(type_, "__size__", None),
                    selection="generation",
                    basis=f"explicitly requested generation {generation!r}",
                )

            numeric = all(isinstance(key, (int, float)) for key in self._declarations)
            if numeric and isinstance(generation, (int, float)):
                ordered = sorted(self._declarations)
                lower = [key for key in ordered if key <= generation]
                key = lower[-1] if lower else ordered[0]
                type_ = self._declarations[key]
                return SelectedDeclaration(
                    type_,
                    generation=key,
                    size=getattr(type_, "__size__", None),
                    selection="generation",
                    basis=(
                        f"requested generation {generation!r}; "
                        f"closest known declaration is generation {key!r}"
                    ),
                )

        if size is not None:
            candidates = [
                (key, type_)
                for key, type_ in self._declarations.items()
                if isinstance(getattr(type_, "__size__", None), int)
            ]
            if candidates:
                exact = [(key, type_) for key, type_ in candidates if type_.__size__ == size]
                if exact:
                    key, type_ = max(exact, key=_generation_sort_key)
                    return SelectedDeclaration(
                        type_,
                        generation=key,
                        size=type_.__size__,
                        selection="size",
                        basis=f"record size {size} exactly matches declaration generation {key!r}",
                    )

                key, type_ = min(
                    candidates,
                    key=lambda item: (abs(item[1].__size__ - size), -_generation_number(item[0])),
                )
                return SelectedDeclaration(
                    type_,
                    generation=key,
                    size=type_.__size__,
                    selection="size",
                    basis=(
                        f"record size {size} best matches declaration generation {key!r} "
                        f"(declared size {type_.__size__})"
                    ),
                )

        # Fall back to the newest declaration, which is the most complete view.
        key, type_ = max(self._declarations.items(), key=_generation_sort_key)
        return SelectedDeclaration(
            type_,
            generation=key,
            size=getattr(type_, "__size__", None),
            selection="fallback",
            basis=f"no generation or size matched; using latest declaration generation {key!r}",
        )

    def read_with_evidence(
        self,
        obj: BinaryIO | bytes | bytearray | memoryview,
        *,
        generation: Any = None,
        **kwargs: Any,
    ) -> tuple[Any, ReadEvidence]:
        """Select a declaration and read the record with evidence."""
        snapshot = prepare_stream(obj)
        selected = self.select(generation=generation, size=snapshot.size)
        result, evidence = selected.type.read_with_evidence(
            snapshot.stream,
            generation=generation if generation is not None else selected.generation,
            declaration=selected.type.__name__,
            declaration_generation=selected.generation,
            selection=selected.selection,
            basis=selected.basis,
            **kwargs,
        )
        return result, evidence

    def read(self, obj: BinaryIO | bytes | bytearray | memoryview, *, generation: Any = None, **kwargs: Any) -> Any:
        """Select a declaration and read the record, returning only the object."""
        return self.read_with_evidence(obj, generation=generation, **kwargs)[0]


Declarations = DeclarationSet
"""Alias of :class:`DeclarationSet`."""

FieldPresence = Presence
"""Alias of :class:`Presence`."""

FieldState = Presence
"""Alias of :class:`Presence`."""

Evidence = ReadEvidence
"""Alias of :class:`ReadEvidence`."""

RecordEvidence = ReadEvidence
"""Alias of :class:`ReadEvidence`."""


def _generation_number(generation: Any) -> float:
    """Return a generation as a number for tie-breaking, or zero if it is not numeric."""
    return generation if isinstance(generation, (int, float)) else 0


def _generation_sort_key(item: tuple[Any, StructureMetaType]) -> tuple[int, Any]:
    """Sort generations numerically where possible and keep unknown generations stable."""
    generation, _ = item
    if isinstance(generation, (int, float)):
        return (0, generation)
    return (1, str(generation))

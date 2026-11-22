from __future__ import annotations

import io
import warnings
from collections import ChainMap
from collections.abc import Mapping, MutableMapping
from contextlib import contextmanager
from enum import Enum
from functools import lru_cache
from itertools import chain, repeat
from operator import attrgetter
from textwrap import dedent
from types import FunctionType
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.cstruct.bitbuffer import BitBuffer
from dissect.cstruct.evidence import FieldEvidence, Presence, ReadEvidence, prepare_stream
from dissect.cstruct.expression import Expression
from dissect.cstruct.lexer import IDENTIFIER_TYPES
from dissect.cstruct.types.base import (
    _BUFFER_TYPES,
    _IMMUTABLE_TYPES,
    BaseArray,
    BaseType,
    MetaType,
    _is_buffer_type,
)
from dissect.cstruct.types.enum import EnumMetaType
from dissect.cstruct.types.pointer import Pointer
from dissect.cstruct.util import normalize_endianness

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from types import FunctionType

    from typing_extensions import Self

    from dissect.cstruct.cstruct import Endianness


_DEFAULT_UNSET = object()


class Field:
    """Structure field."""

    def __init__(
        self,
        name: str | None,
        type_: type[BaseType],
        bits: int | None = None,
        offset: int | None = None,
        *,
        introduced: Any = None,
        removed: Any = None,
        default: Any = _DEFAULT_UNSET,
    ):
        self.name = name  # The name of the field, or None if anonymous
        self._name = name or type_.__name__  # The name of the field, or the type name if anonymous
        self.type = type_
        self.bits = bits
        self.offset = offset
        self.alignment = type_.__alignment__ or 1
        # Optional declaration metadata for evidence-aware reads
        self.introduced = introduced
        self.removed = removed
        self.default = default
        self._has_default = default is not _DEFAULT_UNSET

    def __repr__(self) -> str:
        bits_str = f" : {self.bits}" if self.bits else ""
        return f"<Field {self.name} {self.type.__name__}{bits_str}>"


def _field_generation_info(
    field: Field, overrides: Mapping[str, Any] | None
) -> tuple[Any, Any]:
    """Return the introduced and removed generation for a field, with per-read overrides."""
    introduced = field.introduced
    removed = field.removed

    if overrides and field._name in overrides:
        spec = overrides[field._name]
        if isinstance(spec, Mapping):
            introduced = spec.get("introduced", introduced)
            removed = spec.get("removed", removed)
        elif isinstance(spec, tuple):
            introduced = spec[0]
            if len(spec) > 1:
                removed = spec[1]
        else:
            introduced = spec

    return introduced, removed


def _generation_state(generation: Any, introduced: Any, removed: Any) -> bool | None:
    """Return whether a field exists in the given generation.

    ``None`` means the generation is unknown, so no conclusion can be drawn
    from generation metadata alone.
    """
    if generation is None:
        return None

    try:
        if introduced is not None and generation < introduced:
            return False
        if removed is not None and generation > removed:
            return False
    except TypeError:
        return None

    return True


def _expected_field_size(field: Field) -> int | None:
    """Return the number of bytes a field is expected to occupy, if statically known."""
    try:
        return len(field.type)
    except TypeError:
        return None


def _resolve_field_default(
    field: Field, defaults: Mapping[str, Any] | None, generation: Any = None
) -> Any:
    """Return the default value for a field.

    A default can be a plain value, a callable, or a mapping of generation to
    value for defaults that differ between known generations.
    """
    if defaults and field._name in defaults:
        value = defaults[field._name]
    elif field._has_default:
        value = field.default
    else:
        return field.type.__default__()

    if isinstance(value, Mapping):
        if generation in value:
            return value[generation]
        if None in value:
            return value[None]
        return field.type.__default__()

    if callable(value) and not isinstance(value, type):
        try:
            value = value(generation)
        except TypeError:
            value = value()

    # cstruct initializers treat None as "use the type default", so keep the
    # evidence value consistent with the object that will be constructed.
    return field.type.__default__() if value is None else value


def _generation_reason(generation: Any, introduced: Any, removed: Any) -> str:
    if removed is not None and generation is not None and generation > removed:
        return f"field was removed after generation {removed!r}, record is generation {generation!r}"
    if introduced is not None and generation is not None and generation < introduced:
        return f"field was introduced in generation {introduced!r}, record is generation {generation!r}"
    return "field is not part of the record generation"


def _slice_stream(stream: BinaryIO, start: int, length: int) -> bytes:
    """Read bytes from a seekable stream without changing its position."""
    pos = stream.tell()
    try:
        stream.seek(start)
        return bytes(stream.read(length))
    finally:
        stream.seek(pos)


class StructureMetaType(MetaType):
    """Base metaclass for cstruct structure type classes."""

    __members__: dict[str, Field]
    """Mapping of field names to :class:`Field` objects, including "folded" fields from anonymous structures."""
    __lookup__: dict[str, Field]
    """Mapping of "raw" field names to :class:`Field` objects. E.g. holds the anonymous struct and not its fields."""
    __fields__: list[Field]
    """List of :class:`Field` objects for this structure. This is the structures' Single Source Of Truth."""

    # Internal
    __align__: bool
    __anonymous__: bool
    __updating__ = False
    __compiled__ = False
    __static_sizes__: dict[str, int]  # Cache of static sizes by field name

    def __new__(metacls, name: str, bases: tuple[type, ...], classdict: dict[str, Any], **kwargs) -> Self:  # type: ignore
        if (fields := classdict.pop("__members__", None)) is not None:
            metacls._update_fields(metacls, fields, align=classdict.get("__align__", False), classdict=classdict)

        return super().__new__(metacls, name, bases, classdict, **kwargs)

    def __call__(cls, *args, **kwargs) -> Self:  # type: ignore
        if len(args) == 1 and not kwargs:
            # Fast paths for the most common cases
            obj = args[0]
            if type(obj) in _BUFFER_TYPES:
                return cls._read(io.BytesIO(obj), endian=cls.__cs__.endian)

            if hasattr(obj, "read") and not isinstance(obj, cls):
                return cls._read(obj, endian=cls.__cs__.endian)

        if not args and not kwargs:
            obj = type.__call__(cls)
            object.__setattr__(obj, "__dynamic_sizes__", {})
            return obj

        return super().__call__(*args, **kwargs)

    def _update_fields(
        cls, fields: list[Field], align: bool = False, classdict: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        classdict = classdict or {}

        lookup = {}
        raw_lookup = {}
        field_names = []
        static_sizes = {}
        for field in fields:
            if field._name in lookup and field._name != "_":
                raise ValueError(f"Duplicate field name: {field._name}")

            if not field.type.__dynamic__:
                static_sizes[field._name] = field.type.__size__

            if isinstance(field.type, StructureMetaType) and field.name is None:
                for anon_field in field.type.__members__.values():
                    attr = f"{field._name}.{anon_field.name}"
                    classdict[anon_field.name] = property(attrgetter(attr), attrsetter(attr))

                lookup.update(field.type.__members__)
            else:
                lookup[field._name] = field

            raw_lookup[field._name] = field

        field_names = lookup.keys()
        classdict["__members__"] = lookup
        classdict["__lookup__"] = raw_lookup
        classdict["__fields__"] = fields
        classdict["__static_sizes__"] = static_sizes
        classdict["__bool__"] = _generate__bool__(field_names)

        if issubclass(cls, UnionMetaType) or isinstance(cls, UnionMetaType):
            classdict["__init__"] = _generate_union__init__(raw_lookup.values())
            # Not a great way to do this but it works for now
            classdict["__eq__"] = Union.__eq__
        else:
            classdict["__init__"] = _generate_structure__init__(raw_lookup.values())
            classdict["__eq__"] = _generate__eq__(field_names)

        classdict["__hash__"] = _generate__hash__(field_names)

        # If we're calling this as a class method or a function on the metaclass
        if issubclass(cls, type):
            size, alignment = cls._calculate_size_and_offsets(cls, fields, align)
        else:
            size, alignment = cls._calculate_size_and_offsets(fields, align)

        # TODO: generate cached_property for lazy reading

        classdict["__size__"] = size
        classdict["__alignment__"] = alignment
        classdict["__dynamic__"] = size is None

        return classdict

    def _calculate_size_and_offsets(cls, fields: list[Field], align: bool = False) -> tuple[int | None, int]:
        """Iterate all fields in this structure to calculate the field offsets and total structure size.

        If a structure has a dynamic field, further field offsets will be set to None and ``self.__dynamic__``
        will be set to ``True``.
        """
        # The current offset, set to None if we become dynamic
        offset = 0
        # The current alignment for this structure
        alignment = 0

        # The current bit field type
        bits_type = None
        # The offset of the current bit field, set to None if we become dynamic
        bits_field_offset = 0
        # How many bits we have left in the current bit field
        bits_remaining = 0

        for field in fields:
            if field.offset is not None:
                # If a field already has an offset, it's leading
                offset = field.offset

            if align and offset is not None:
                # Round to next alignment
                offset += -offset & (field.alignment - 1)

            # The alignment of this struct is equal to its largest members' alignment
            alignment = max(alignment, field.alignment)

            if field.bits:
                field_type = field.type

                if isinstance(field_type, EnumMetaType):
                    field_type = field_type.__type__

                # Bit fields have special logic
                if (
                    # Exhausted a bit field
                    bits_remaining == 0
                    # Moved to a bit field of another type, e.g. uint16 f1 : 8, uint32 f2 : 8;
                    or field_type != bits_type
                    # Still processing a bit field, but it's at a different offset due to alignment or a manual offset
                    or (None not in (offset, bits_field_offset) and offset > bits_field_offset + bits_type.__size__)
                ):
                    # ... if any of this is true, we have to move to the next field
                    bits_type = field_type
                    bits_count = bits_type.__size__ * 8
                    bits_remaining = bits_count
                    bits_field_offset = offset

                    if offset is not None:
                        # We're not dynamic, update the structure size and current offset
                        offset += bits_type.__size__

                    field.offset = bits_field_offset

                bits_remaining -= field.bits

                if bits_remaining < 0:
                    raise ValueError("Straddled bit fields are unsupported")
            else:
                # Reset bits stuff
                bits_type = None
                bits_field_offset = bits_remaining = 0

                field.offset = offset

                if offset is not None:
                    # We're not dynamic, update the structure size and current offset
                    try:
                        field_len = len(field.type)
                    except TypeError:
                        # This field is dynamic
                        offset = None
                        continue

                    offset += field_len

        if align and offset is not None:
            # Add "tail padding" if we need to align
            # This bit magic rounds up to the next alignment boundary
            # E.g. offset = 3; alignment = 8; -offset & (alignment - 1) = 5
            offset += -offset & (alignment - 1)

        # The structure size is whatever the currently calculated offset is
        return offset, alignment

    def _read(cls, stream: BinaryIO, *, context: dict[str, Any] | None = None, endian: Endianness) -> Self:  # type: ignore
        bit_buffer = None
        struct_start = stream.tell()

        result = {}
        sizes = {}
        for field in cls.__fields__:
            offset = stream.tell()

            if field.offset is not None and offset != struct_start + field.offset:
                # Field is at a specific offset, either aligned or added that way
                offset = struct_start + field.offset
                stream.seek(offset)

            if cls.__align__ and field.offset is None:
                # Previous field was dynamically sized and we need to align
                offset += -offset & (field.alignment - 1)
                stream.seek(offset)

            if field.bits:
                if bit_buffer is None:
                    bit_buffer = BitBuffer(stream, endian=endian)

                if isinstance(field.type, EnumMetaType):
                    value = field.type(bit_buffer.read(field.type.__type__, field.bits))
                else:
                    value = bit_buffer.read(field.type, field.bits)

                result[field._name] = value
                continue

            if bit_buffer is not None:
                bit_buffer.reset()

            value = field.type._read(stream, context=result, endian=endian)

            result[field._name] = value
            if field.type.__dynamic__:
                sizes[field._name] = stream.tell() - offset

        if cls.__align__:
            # Align the stream
            stream.seek(-stream.tell() & (cls.__alignment__ - 1), io.SEEK_CUR)

        # Using type.__call__ directly calls the __init__ method of the class
        # This is faster than calling cls() and bypasses the metaclass __call__ method
        obj = type.__call__(cls, **result)
        obj.__dynamic_sizes__ = sizes
        return obj

    def read_with_evidence(
        cls,
        obj: BinaryIO | bytes | bytearray | memoryview,
        *,
        endian: Endianness | str | None = None,
        generation: Any = None,
        field_generations: Mapping[str, Any] | None = None,
        defaults: Mapping[str, Any] | None = None,
        strict: bool = False,
        declaration: str | None = None,
        declaration_generation: Any = None,
        selection: str = "explicit",
        basis: str | None = None,
    ) -> tuple[Self, ReadEvidence]:  # type: ignore
        """Read data and return the regular object together with an audit view.

        Unlike the normal read methods, this is lenient by default: fields that
        are absent from the record or cut off by the end of the data are filled
        with their default values.  The returned :class:`ReadEvidence` records
        for every declared field whether its value came from actual bytes or
        from a default, and why.

        Args:
            obj: Bytes-like data or a file-like object.
            endian: Endianness to use. Defaults to the endianness of this
                structure's cstruct instance.
            generation: The generation of the record that is being read. When a
                field has ``introduced`` or ``removed`` metadata, this is used
                to distinguish a field that was never in the record from a
                record that was truncated inside the field.
            field_generations: Per-read generation metadata, for declarations
                that cannot carry it themselves.  Values can be an introduced
                generation, an ``(introduced, removed)`` tuple, or a mapping
                with ``introduced`` and/or ``removed`` keys.
            defaults: Optional per-field defaults to use instead of the type's
                default value, for example defaults derived from a known
                generation.
            strict: Raise the first :class:`EOFError` instead of filling in a
                default for truncated data.
            declaration: Name of the declaration to record in the audit view.
            declaration_generation: Generation of the selected declaration.
            selection: How the declaration was selected (``"explicit"`` is the
                default for a direct call).
            basis: Human-readable reason for selecting the declaration.

        Returns:
            A ``(value, evidence)`` tuple.  ``value`` is a normal cstruct
            object and can be passed to existing consumers unchanged.  The
            evidence is also available on the object as ``__evidence__``.
        """
        endian = normalize_endianness(endian) if endian is not None else cls.__cs__.endian
        if declaration_generation is None:
            declaration_generation = getattr(cls, "__generation__", None)
        snapshot = prepare_stream(obj)
        value, evidence = cls._read_with_evidence(
            snapshot.stream,
            endian=endian,
            generation=generation,
            field_generations=field_generations,
            defaults=defaults,
            strict=strict,
            declaration=declaration or cls.__name__,
            declaration_generation=declaration_generation,
            selection=selection,
            basis=basis or f"explicitly selected declaration {cls.__name__!r}",
            start=snapshot.start,
            end=snapshot.end,
            raw=snapshot.raw,
        )
        return value, evidence

    def read_audited(
        cls, obj: BinaryIO | bytes | bytearray | memoryview, **kwargs: Any
    ) -> tuple[Self, ReadEvidence]:  # type: ignore
        """Alias of :meth:`read_with_evidence`."""
        return cls.read_with_evidence(obj, **kwargs)

    def read_with_presence(
        cls, obj: BinaryIO | bytes | bytearray | memoryview, **kwargs: Any
    ) -> tuple[Self, ReadEvidence]:  # type: ignore
        """Alias of :meth:`read_with_evidence`."""
        return cls.read_with_evidence(obj, **kwargs)

    def _read_with_evidence(
        cls,
        stream: BinaryIO,
        *,
        context: dict[str, Any] | None = None,
        endian: Endianness,
        generation: Any = None,
        field_generations: Mapping[str, Any] | None = None,
        defaults: Mapping[str, Any] | None = None,
        strict: bool = False,
        declaration: str | None = None,
        declaration_generation: Any = None,
        selection: str = "explicit",
        basis: str = "",
        start: int | None = None,
        end: int | None = None,
        raw: bytes | None = None,
    ) -> tuple[Self, ReadEvidence]:  # type: ignore
        struct_start = stream.tell() if start is None else start
        if end is None:
            pos = stream.tell()
            end = stream.seek(0, io.SEEK_END)
            stream.seek(pos)

        result: dict[str, Any] = {}
        sizes: dict[str, int] = {}
        evidence: dict[str, FieldEvidence] = {}
        bit_buffer = None

        for field in cls.__fields__:
            if field.offset is not None:
                target = struct_start + field.offset
                if stream.tell() != target:
                    stream.seek(min(target, end))

            if cls.__align__ and field.offset is None:
                offset = stream.tell()
                aligned = offset + (-offset & (field.alignment - 1))
                stream.seek(min(aligned, end))

            field_offset = stream.tell()
            expected = _expected_field_size(field)
            available = max(0, end - field_offset)
            if expected is not None:
                available = min(available, expected)
            introduced, removed = _field_generation_info(field, field_generations)
            in_generation = _generation_state(generation, introduced, removed)
            default = _resolve_field_default(field, defaults, generation)

            if in_generation is True and introduced is None and removed is None:
                try:
                    if (
                        generation is not None
                        and declaration_generation is not None
                        and declaration_generation > generation
                        and available == 0
                    ):
                        in_generation = False
                        introduced = declaration_generation
                except TypeError:
                    pass

            if in_generation is False:
                value = default
                result[field._name] = value
                if field.type.__dynamic__:
                    sizes[field._name] = 0
                evidence[field._name] = FieldEvidence(
                    name=field._name,
                    presence=Presence.DERIVED,
                    value=value,
                    offset=field_offset,
                    relative_offset=field_offset - struct_start,
                    size=expected,
                    available=available,
                    consumed=0,
                    default=default,
                    generation=generation,
                    introduced=introduced,
                    removed=removed,
                    declaration=declaration,
                    reason=_generation_reason(generation, introduced, removed),
                )
                continue

            if bit_buffer is not None and not field.bits:
                bit_buffer.reset()
                bit_buffer = None

            try:
                children = None
                if field.bits:
                    if bit_buffer is None:
                        bit_buffer = BitBuffer(stream, endian=endian)

                    if isinstance(field.type, EnumMetaType):
                        value = field.type(bit_buffer.read(field.type.__type__, field.bits))
                    else:
                        value = bit_buffer.read(field.type, field.bits)
                elif isinstance(field.type, StructureMetaType) and not issubclass(field.type, Union):
                    field_end = end if expected is None else min(end, field_offset + expected)
                    value, nested = field.type._read_with_evidence(
                        stream,
                        context=result,
                        endian=endian,
                        generation=generation,
                        field_generations=field_generations,
                        defaults=defaults,
                        strict=strict,
                        declaration=field.type.__name__,
                        declaration_generation=getattr(
                            field.type, "__generation__", declaration_generation
                        ),
                        selection=selection,
                        basis=basis,
                        start=field_offset,
                        end=field_end,
                    )
                    children = nested.fields
                else:
                    value = field.type._read(stream, context=result, endian=endian)

                consumed = max(0, stream.tell() - field_offset)
                result[field._name] = value
                if field.type.__dynamic__:
                    sizes[field._name] = consumed

                presence = Presence.READ
                reason = "value read from record bytes"

                if children is not None:
                    if any(child.is_truncated for child in children.values()):
                        presence = Presence.TRUNCATED
                        reason = "one or more nested fields are truncated"
                    elif consumed == 0 and children and all(not child.is_read for child in children.values()):
                        if available == 0 and in_generation is None:
                            presence = Presence.ABSENT
                            reason = "no bytes remain at the field boundary"
                        elif available == 0:
                            presence = Presence.TRUNCATED
                            reason = "field belongs to the record generation but no bytes are available"
                        else:
                            presence = Presence.TRUNCATED
                            reason = "insufficient bytes for the nested structure"

                evidence[field._name] = FieldEvidence(
                    name=field._name,
                    presence=presence,
                    value=value,
                    offset=field_offset,
                    relative_offset=field_offset - struct_start,
                    size=expected,
                    available=available,
                    consumed=consumed,
                    raw=_slice_stream(stream, field_offset, consumed),
                    default=default,
                    generation=generation,
                    introduced=introduced,
                    removed=removed,
                    declaration=declaration,
                    reason=reason,
                    children=children,
                )
            except EOFError as exc:
                available = max(0, end - field_offset)
                if expected is not None:
                    available = min(available, expected)
                if available == 0 and in_generation is None:
                    presence = Presence.ABSENT
                    reason = "no bytes remain at the field boundary"
                else:
                    presence = Presence.TRUNCATED
                    if expected is None:
                        reason = f"insufficient bytes for dynamic field {field._name!r}: {exc}"
                    else:
                        reason = (
                            f"insufficient bytes for {field._name!r}: "
                            f"expected {expected}, only {available} available"
                        )

                if strict:
                    raise

                value = default
                result[field._name] = value
                if field.type.__dynamic__:
                    sizes[field._name] = 0

                consumed = min(available, expected) if expected is not None else available
                raw_field = _slice_stream(stream, field_offset, consumed)
                if expected is not None:
                    stream.seek(min(field_offset + expected, end))
                else:
                    stream.seek(end)

                evidence[field._name] = FieldEvidence(
                    name=field._name,
                    presence=presence,
                    value=value,
                    offset=field_offset,
                    relative_offset=field_offset - struct_start,
                    size=expected,
                    available=available,
                    consumed=consumed,
                    raw=raw_field,
                    default=default,
                    generation=generation,
                    introduced=introduced,
                    removed=removed,
                    declaration=declaration,
                    reason=reason,
                )

        if cls.__align__:
            stream.seek(min(end, stream.tell() + (-stream.tell() & (cls.__alignment__ - 1))))

        obj = type.__call__(cls, **result)
        obj.__dynamic_sizes__ = sizes

        consumed = max(0, stream.tell() - struct_start)
        view = ReadEvidence(
            fields=evidence,
            declaration=declaration or cls.__name__,
            declaration_type=cls,
            declaration_generation=declaration_generation,
            generation=generation,
            selection=selection,
            basis=basis,
            data_size=max(0, end - struct_start),
            start=struct_start,
            consumed=consumed,
            raw=(raw[:consumed] if raw else _slice_stream(stream, struct_start, consumed)),
        )
        object.__setattr__(obj, "__evidence__", view)
        return obj, view

    def _read_0(cls, stream: BinaryIO, *, context: dict[str, Any] | None = None, endian: Endianness) -> list[Self]:  # type: ignore
        result = []

        while obj := cls._read(stream, context=context, endian=endian):
            result.append(obj)

        return result

    def _write(cls, stream: BinaryIO, data: Structure, *, endian: Endianness) -> int:
        bit_buffer = None
        struct_start = stream.tell()

        for field in cls.__fields__:
            field_type = field.type

            if bit_buffer is not None and bit_buffer._type is not None:
                bit_field_type = (
                    (field_type.__type__ if isinstance(field_type, EnumMetaType) else field_type)
                    if field.bits
                    else None
                )
                # Current field is not a bit field, but previous was
                # Or, moved to a bit field of another type, e.g. uint16 f1 : 8, uint32 f2 : 8;
                if bit_buffer._type != bit_field_type:
                    # Flush the current bit buffer so we can process alignment properly
                    bit_buffer.flush()

            offset = stream.tell()

            if field.offset is not None and offset < struct_start + field.offset:
                # Field is at a specific offset, either aligned or added that way
                stream.write(b"\x00" * (struct_start + field.offset - offset))
                offset = struct_start + field.offset

            if cls.__align__ and field.offset is None:
                bit_type = bit_buffer._type if bit_buffer is not None else None
                if bit_type is None or bit_buffer._remaining == 0 or bit_type != field_type:
                    # Previous field was dynamically sized and we need to align
                    align_pad = -offset & (field.alignment - 1)
                    stream.write(b"\x00" * align_pad)
                    offset += align_pad

            value = getattr(data, field._name)
            if value is None:
                value = field_type.__default__()

            if field.bits:
                if bit_buffer is None:
                    bit_buffer = BitBuffer(stream, endian=endian)

                if isinstance(field_type, EnumMetaType):
                    bit_buffer.write(field_type.__type__, value.value, field.bits)
                else:
                    bit_buffer.write(field_type, value, field.bits)
            else:
                field_type._write(stream, value, endian=endian)

        if bit_buffer is not None and bit_buffer._type is not None:
            bit_buffer.flush()

        if cls.__align__:
            # Align the stream
            stream.write(b"\x00" * (-stream.tell() & (cls.__alignment__ - 1)))

        return stream.tell() - struct_start

    def set_field_metadata(
        cls,
        name: str,
        *,
        introduced: Any = _DEFAULT_UNSET,
        removed: Any = _DEFAULT_UNSET,
        default: Any = _DEFAULT_UNSET,
    ) -> None:
        """Set generation metadata on a declared field.

        This is useful for declarations loaded from C-style definitions, which
        have no syntax for generation metadata.  Use :func:`evidence.field`
        with declarative structures instead.

        Args:
            name: Name of the field, including folded anonymous fields.
            introduced: Generation in which the field was introduced.
            removed: Generation after which the field was removed.
            default: Value to use when the field is absent for a generation.
        """
        try:
            field = cls.__lookup__[name]
        except KeyError:
            field = cls.__members__[name]

        if introduced is not _DEFAULT_UNSET:
            field.introduced = introduced
        if removed is not _DEFAULT_UNSET:
            field.removed = removed
        if default is not _DEFAULT_UNSET:
            field.default = default
            field._has_default = True

        cls.commit()

    def add_field(
        cls,
        name: str,
        type_: type[BaseType],
        bits: int | None = None,
        offset: int | None = None,
        *,
        introduced: Any = None,
        removed: Any = None,
        default: Any = _DEFAULT_UNSET,
    ) -> None:
        field = Field(
            name,
            type_,
            bits=bits,
            offset=offset,
            introduced=introduced,
            removed=removed,
            default=default,
        )
        cls.__fields__.append(field)

        if not cls.__updating__:
            cls.commit()

    @contextmanager
    def start_update(cls) -> Iterator[None]:
        try:
            cls.__updating__ = True
            yield
        finally:
            cls.commit()
            cls.__updating__ = False

    def commit(cls) -> None:
        classdict = cls._update_fields(cls.__fields__, cls.__align__)

        for key, value in classdict.items():
            setattr(cls, key, value)

        if cls.__compiled__:
            # If the previous class was compiled try to compile this too
            from dissect.cstruct import compiler

            compiler.compile_structure(cls)

    def cdef(cls, *, recursive: bool = False) -> str:
        """Render this structure (or union) back to its C-style definition.

        When ``recursive=True``, any ``#define`` constants referenced in array sizes are emitted as well, so that the
        result can be parsed on its own. Note that the result is semantically equivalent to the original definition,
        but not necessarily identical.

        Args:
            recursive: Also emit the definitions of any types referenced by this structure.

        Returns:
            The C-style definition as a string.
        """

        def _decompose(type_: MetaType) -> tuple[MetaType, int, list[int | Expression | None]]:
            dimensions = []
            while issubclass(type_, BaseArray):
                dimensions.append(type_.__num_entries__)
                type_ = type_.__type__

            stars = 0
            while issubclass(type_, Pointer):
                stars += 1
                type_ = type_.__type__

            return type_, stars, dimensions

        def _deps(type_: StructureMetaType, seen: set[MetaType]) -> list[MetaType | str]:
            deps = []
            for field in type_.__fields__:
                base, _, dimensions = _decompose(field.type)

                for dim in dimensions:
                    if isinstance(dim, Expression):
                        for token in dim._tokens:
                            if (
                                token.type in IDENTIFIER_TYPES
                                and token.value in cls.__cs__.consts
                                and token.value not in seen
                            ):
                                deps.append(token.value)
                                seen.add(token.value)

                if isinstance(base, StructureMetaType) and base not in seen:
                    if base.__anonymous__:
                        # Anonymous structures are not emitted, but their dependencies are
                        deps.extend(_deps(base, seen))
                    else:
                        seen.add(base)
                        deps.extend(_deps(base, seen))
                        deps.append(base)

                elif isinstance(base, EnumMetaType) and base not in seen:
                    seen.add(base)
                    deps.append(base)

            return deps

        def _render_struct(type_: StructureMetaType, name: str) -> list[str]:
            keyword = "union" if isinstance(type_, UnionMetaType) else "struct"
            title = f"{keyword} {name}" if name else keyword

            lines = [f"{title} {{"]
            for field in type_.__fields__:
                base, stars, dimensions = _decompose(field.type)

                declarator = "*" * stars + (field.name or "") + "".join(f"[{dim or ''}]" for dim in dimensions)
                if field.bits is not None:
                    declarator = f"{declarator} : {field.bits}" if declarator else f": {field.bits}"

                if isinstance(base, StructureMetaType) and base.__anonymous__:
                    # Anonymous struct/union: inline the full definition
                    lines.extend(f"    {line}" for line in _render_struct(base, ""))
                    lines[-1] = f"{lines[-1]} {declarator};" if declarator else f"{lines[-1]};"
                else:
                    prefix = f"{base.__name__} " if declarator else base.__name__
                    lines.append(f"    {prefix}{declarator};")

            lines.append("}")
            return lines

        deps = _deps(cls, {cls}) if recursive else []
        deps.append(cls)

        consts = []
        blocks = []
        for type_ in deps:
            if isinstance(type_, str):
                consts.append(f"#define {type_} {cls.__cs__.consts[type_]!r}")
            elif isinstance(type_, EnumMetaType):
                blocks.append(type_.cdef())
            else:
                blocks.append("\n".join(_render_struct(type_, type_.__name__)) + ";")

        return ("\n".join(consts) + "\n\n" if consts else "") + ("\n\n".join(blocks) if blocks else "")

    @property
    def fields(cls) -> dict[str, Field]:
        """List of :class:`Field` objects for this structure."""
        warnings.warn(
            "The 'fields' property is deprecated, use '__members__' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return cls.__members__

    @property
    def lookup(cls) -> dict[str, Field]:
        """Mapping of "raw" field names to :class:`Field` objects."""
        warnings.warn(
            "The 'lookup' property is deprecated, use '__lookup__' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return cls.__lookup__


class Structure(BaseType, metaclass=StructureMetaType):
    """Base class for cstruct structure type classes.

    Note that setting attributes which do not correspond to a field in the structure results in undefined behavior.
    For performance reasons, the structure does not check if the field exists when writing to an attribute.
    """

    __dynamic_sizes__: dict[str, int]
    __evidence__: ReadEvidence | None = None

    @property
    def __presence__(self) -> ReadEvidence | None:
        """Alias of :attr:`__evidence__` for an evidence-aware read."""
        return self.__evidence__

    def __len__(self) -> int:
        return len(self.dumps())

    def __bytes__(self) -> bytes:
        return self.dumps()

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def __repr__(self) -> str:
        values = []
        for name, field in self.__class__.__members__.items():
            value = self[name]
            if issubclass(field.type, int) and not issubclass(field.type, (Pointer, Enum)):
                value = hex(value)
            else:
                value = repr(value)
            values.append(f"{name}={value}")

        return f"<{self.__class__.__name__} {' '.join(values)}>"

    @property
    def __values__(self) -> MutableMapping[str, Any]:
        return StructureValuesProxy(self)

    @property
    def __sizes__(self) -> Mapping[str, int | None]:
        # Structures created from values instead of parsed have no dynamic sizes
        return ChainMap(self.__class__.__static_sizes__, getattr(self, "__dynamic_sizes__", {}))


class StructureValuesProxy(MutableMapping):
    """A proxy for the values of fields of a Structure."""

    def __init__(self, struct: Structure):
        self._struct: Structure = struct

    def __getitem__(self, key: str) -> Any:
        if key in self:
            return getattr(self._struct, key)
        raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        if key in self:
            return setattr(self._struct, key, value)
        raise KeyError(key)

    def __contains__(self, key: str) -> bool:
        return key in self._struct.__class__.__members__

    def __iter__(self) -> Iterator[str]:
        return iter(self._struct.__class__.__members__)

    def __len__(self) -> int:
        return len(self._struct.__class__.__members__)

    def __repr__(self) -> str:
        return repr(dict(self))

    def __delitem__(self, _: str):
        # Is abstract in base, but deleting is not supported.
        raise NotImplementedError("Cannot delete fields from a Structure")


class UnionMetaType(StructureMetaType):
    """Base metaclass for cstruct union type classes."""

    def __call__(cls, *args, **kwargs) -> Self:  # type: ignore
        obj: Union = super().__call__(*args, **kwargs)

        if not hasattr(obj, "_buf"):
            # If we don't have a _buf attribute, we haven't read from a stream and are initializing with values
            # Set default internal attributes
            object.__setattr__(obj, "_buf", None)
            object.__setattr__(obj, "_endian", cls.__cs__.endian)

        # Calling with non-stream args or kwargs means we are initializing with values
        if (args and not (len(args) == 1 and (hasattr(args[0], "read") or _is_buffer_type(args[0])))) or kwargs:
            # We don't support user initialization of dynamic unions yet
            if cls.__dynamic__:
                raise NotImplementedError("Initializing a dynamic union is not yet supported")

            # User (partial) initialization, rebuild the union
            # First user-provided field is the one used to rebuild the union
            arg_fields = (field._name for _, field in zip(args, cls.__fields__, strict=False))
            kwarg_fields = (name for name in kwargs if name in cls.__lookup__)
            if (first_field := next(chain(arg_fields, kwarg_fields), None)) is not None:
                obj._rebuild(first_field)
        elif not args and not kwargs:
            # Initialized with default values
            # Note that we proxify here in case we have a default initialization (cls())
            # We don't proxify in case we read from a stream, as we do that later on in _read at a more appropriate time
            # Same with (partial) user initialization, we do that after rebuilding the union
            obj._proxify()

        return obj

    def _calculate_size_and_offsets(cls, fields: list[Field], align: bool = False) -> tuple[int | None, int]:
        size = 0
        alignment = 0

        for field in fields:
            if size is not None:
                try:
                    size = max(len(field.type), size)
                except TypeError:
                    size = None

            alignment = max(field.alignment, alignment)

        if align and size is not None:
            # Add "tail padding" if we need to align
            # This bit magic rounds up to the next alignment boundary
            # E.g. offset = 3; alignment = 8; -offset & (alignment - 1) = 5
            size += -size & (alignment - 1)

        return size, alignment

    def _read_fields(
        cls, stream: BinaryIO, *, context: dict[str, Any] | None = None, endian: Endianness
    ) -> tuple[dict[str, Any], dict[str, int]]:
        result = {}
        sizes = {}

        if cls.__size__ is None:
            offset = stream.tell()
            buf = stream
        else:
            offset = 0
            buf = io.BytesIO(stream.read(cls.__size__))

        for field in cls.__fields__:
            field_type = field.type

            start = 0
            if field.offset is not None:
                start = field.offset

            buf.seek(offset + start)
            value = field_type._read(buf, context=result, endian=endian)

            result[field._name] = value
            if field.type.__dynamic__:
                sizes[field._name] = buf.tell() - start

        return result, sizes

    def _read(cls, stream: BinaryIO, *, context: dict[str, Any] | None = None, endian: Endianness) -> Self:  # type: ignore
        if cls.__size__ is None:
            start = stream.tell()
            result, sizes = cls._read_fields(stream, context=context, endian=endian)
            size = stream.tell() - start
            stream.seek(start)
            buf = stream.read(size)
        elif "__init__" in cls.__dict__ and cls.__new__ is object.__new__:
            # Fast path for static unions
            buf = stream.read(cls.__size__)
            result, sizes = cls._read_fields(io.BytesIO(buf), endian=endian)

            obj: Union = object.__new__(cls)
            obj.__dict__.update(result)
            object.__setattr__(obj, "__dynamic_sizes__", sizes)
            object.__setattr__(obj, "_buf", buf)
            object.__setattr__(obj, "_endian", endian)
            obj._proxify()
            return obj
        else:
            result = {}
            sizes = {}
            buf = stream.read(cls.__size__)

        # Create the object and set the values
        # Using type.__call__ directly calls the __init__ method of the class
        # This is faster than calling cls() and bypasses the metaclass __call__ method
        # It also makes it easier to differentiate between user-initialization of the class
        # and initialization from a stream read
        obj: Union = type.__call__(cls, **result)
        object.__setattr__(obj, "__dynamic_sizes__", sizes)
        object.__setattr__(obj, "_buf", buf)
        object.__setattr__(obj, "_endian", endian)

        if cls.__size__ is not None:
            obj._update()

        # Proxify any nested structures
        obj._proxify()

        return obj

    def _read_with_evidence(
        cls,
        stream: BinaryIO,
        *,
        context: dict[str, Any] | None = None,
        endian: Endianness,
        generation: Any = None,
        field_generations: Mapping[str, Any] | None = None,
        defaults: Mapping[str, Any] | None = None,
        strict: bool = False,
        declaration: str | None = None,
        declaration_generation: Any = None,
        selection: str = "explicit",
        basis: str = "",
        start: int | None = None,
        end: int | None = None,
        raw: bytes | None = None,
    ) -> tuple[Self, ReadEvidence]:  # type: ignore
        struct_start = stream.tell() if start is None else start
        if end is None:
            pos = stream.tell()
            end = stream.seek(0, io.SEEK_END)
            stream.seek(pos)

        if cls.__size__ is not None:
            available = max(0, end - struct_start)
            buf = _slice_stream(stream, struct_start, min(cls.__size__, available))
            if available >= cls.__size__:
                obj = cls._read(io.BytesIO(buf), endian=endian)
            else:
                try:
                    obj = type.__call__(cls)
                except Exception:
                    obj = None
            stream.seek(min(struct_start + cls.__size__, end))
        else:
            try:
                obj = cls._read(stream, endian=endian)
            except EOFError:
                if strict:
                    raise
                obj = type.__call__(cls)
            buf = _slice_stream(stream, struct_start, max(0, stream.tell() - struct_start))

        result = {}
        evidence: dict[str, FieldEvidence] = {}
        full = cls.__size__ is not None and len(buf) >= cls.__size__

        for field in cls.__fields__:
            rel_offset = field.offset or 0
            field_offset = struct_start + rel_offset
            expected = _expected_field_size(field)
            field_available = max(0, end - field_offset)
            if expected is not None:
                field_available = min(field_available, expected)
            introduced, removed = _field_generation_info(field, field_generations)
            in_generation = _generation_state(generation, introduced, removed)
            default = _resolve_field_default(field, defaults, generation)
            value = getattr(obj, field._name, default) if obj is not None else default
            result[field._name] = value

            if in_generation is False:
                presence = Presence.DERIVED
                consumed = 0
                reason = _generation_reason(generation, introduced, removed)
            elif full:
                presence = Presence.READ
                consumed = expected if expected is not None else field_available
                reason = "value read from record bytes"
            elif expected is not None and field_available >= expected:
                try:
                    value = field.type._read(
                        io.BytesIO(buf[rel_offset : rel_offset + expected]),
                        context=result,
                        endian=endian,
                    )
                    presence = Presence.READ
                    consumed = expected
                    reason = "value read from record bytes"
                    if obj is not None:
                        object.__setattr__(obj, field._name, value)
                except EOFError:
                    presence = Presence.TRUNCATED
                    consumed = field_available
                    reason = "insufficient bytes for the union member"
            elif field_available == 0 and in_generation is None:
                presence = Presence.ABSENT
                consumed = 0
                reason = "no bytes remain at the field boundary"
            else:
                presence = Presence.TRUNCATED
                consumed = min(field_available, expected) if expected is not None else field_available
                reason = "insufficient bytes for the union member"

            evidence[field._name] = FieldEvidence(
                name=field._name,
                presence=presence,
                value=value,
                offset=field_offset,
                relative_offset=rel_offset,
                size=expected,
                available=field_available,
                consumed=consumed,
                raw=buf[rel_offset : rel_offset + (expected if expected is not None else field_available)],
                default=default,
                generation=generation,
                introduced=introduced,
                removed=removed,
                declaration=declaration,
                reason=reason,
            )

        if obj is None:
            obj = type.__call__(cls, **result)

        obj.__dynamic_sizes__ = {}
        view = ReadEvidence(
            fields=evidence,
            declaration=declaration or cls.__name__,
            declaration_type=cls,
            declaration_generation=declaration_generation,
            generation=generation,
            selection=selection,
            basis=basis,
            data_size=max(0, end - struct_start),
            start=struct_start,
            consumed=max(0, stream.tell() - struct_start),
            raw=raw if raw is not None else buf,
        )
        object.__setattr__(obj, "__evidence__", view)
        return obj, view

    def _write_field(cls) -> Field | None:
        """Return the field to write a union by, its largest field and preferably not an anonymous structure."""
        return max(cls.__fields__, key=lambda e: (e.type.__size__ or 0, e.name is not None), default=None)

    def _write(cls, stream: BinaryIO, data: Union, *, endian: Endianness) -> int:
        if cls.__dynamic__:
            raise NotImplementedError("Writing dynamic unions is not yet supported")

        offset = stream.tell()
        expected_offset = offset + len(cls)

        if (field := cls._write_field()) is not None:
            # Write the value
            field.type._write(stream, getattr(data, field._name), endian=endian)

        # If we haven't filled the union size yet, pad it
        if remaining := expected_offset - stream.tell():
            stream.write(b"\x00" * remaining)

        return stream.tell() - offset


class Union(Structure, metaclass=UnionMetaType):
    """Base class for cstruct union type classes."""

    _buf: bytes
    _endian: Endianness

    def __eq__(self, other: object) -> bool:
        return self.__class__ is other.__class__ and bytes(self) == bytes(other)

    def __setattr__(self, attr: str, value: Any) -> None:
        if self.__class__.__dynamic__:
            raise NotImplementedError("Modifying a dynamic union is not yet supported")

        super().__setattr__(attr, value)
        # Fields of an anonymous structure are rebuilt through the proxy of that structure
        if attr in self.__class__.__lookup__:
            self._rebuild(attr)

    def _rebuild(self, attr: str) -> None:
        if (cur_buf := getattr(self, "_buf", None)) is None:
            cur_buf = b"\x00" * self.__class__.__size__

        buf = io.BytesIO(cur_buf)
        field = self.__class__.__lookup__[attr]
        if field.offset:
            buf.seek(field.offset)

        if (value := getattr(self, attr)) is None:
            value = field.type.__default__()

        field.type._write(buf, value, endian=self._endian)

        object.__setattr__(self, "_buf", buf.getvalue())
        self._update()

        # (Re-)proxify all values
        self._proxify()

    def _update(self) -> None:
        result, sizes = self.__class__._read_fields(io.BytesIO(self._buf), endian=self._endian)
        self.__dict__.update(result)
        object.__setattr__(self, "__dynamic_sizes__", sizes)

    def _proxify(self) -> None:
        def _proxy_structure(value: Structure, attr: str | None = None) -> None:
            for field in value.__class__.__fields__:
                if issubclass(field.type, Structure):
                    nested_value = getattr(value, field._name)
                    # Changing a nested field rebuilds the union from the top level field it's in
                    member = attr or field._name
                    object.__setattr__(value, field._name, UnionProxy(self, member, nested_value))
                    # The value of a nested union is already a proxy, so continue with the value behind it
                    if isinstance(nested_value, UnionProxy):
                        nested_value = nested_value.__target__
                    _proxy_structure(nested_value, member)

        _proxy_structure(self)


class UnionProxy:
    __union__: Union
    __attr__: str
    __target__: Structure

    def __init__(self, union: Union, attr: str, target: Structure):
        object.__setattr__(self, "__union__", union)
        object.__setattr__(self, "__attr__", attr)
        object.__setattr__(self, "__target__", target)

    def __len__(self) -> int:
        return len(self.__target__.dumps())

    def __bytes__(self) -> bytes:
        return self.__target__.dumps()

    def __getitem__(self, item: str) -> Any:
        return getattr(self.__target__, item)

    def __repr__(self) -> str:
        return repr(self.__target__)

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.__target__, attr)

    def __setattr__(self, attr: str, value: Any) -> None:
        setattr(self.__target__, attr, value)
        self.__union__._rebuild(self.__attr__)


def attrsetter(path: str) -> Callable[[Any], Any]:
    path, _, attr = path.rpartition(".")
    path = path.split(".")

    def _func(obj: Any, value: Any) -> Any:
        for name in path:
            obj = getattr(obj, name)
        setattr(obj, attr, value)

    return _func


def _codegen(func: FunctionType) -> FunctionType:
    """Decorator that generates a template function with a specified number of fields.

    This code is a little complex but allows use to cache generated functions for a specific number of fields.
    For example, if we generate a structure with 10 fields, we can cache the generated code for that structure.
    We can then reuse that code and patch it with the correct field names when we create a new structure with 10 fields.

    The functions that are decorated with this decorator should take a list of field names and return a string of code.
    The decorated function is needs to be called with the number of fields, instead of the field names.
    The confusing part is that that the original function takes field names, but you then call it with
    the number of fields instead.

    Inspired by https://github.com/dabeaz/dataklasses.

    Args:
        func: The decorated function that takes a list of field names and returns a string of code.

    Returns:
        A cached function that generates the desired function code, to be called with the number of fields.
    """

    def make_func_code(num_fields: int) -> FunctionType:
        exec(func([f"_{n}" for n in range(num_fields)]), {}, d := {})
        return d.popitem()[1]

    make_func_code.__wrapped__ = func
    return lru_cache(make_func_code)


@_codegen
def _make_structure__init__(fields: list[str]) -> str:
    """Generates an ``__init__`` method for a structure with the specified fields.

    Args:
        fields: List of field names.
    """
    field_args = ", ".join(f"{field} = None" for field in fields)
    field_init = "\n".join(
        f" self.{name} = {name} if {name} is not None else _{i}_default()" for i, name in enumerate(fields)
    )

    code = f"def __init__(self{', ' + field_args or ''}):\n"
    return code + (field_init or " pass")


@_codegen
def _make_union__init__(fields: list[str]) -> str:
    """Generates an ``__init__`` method for a class with the specified fields using setattr.

    Args:
        fields: List of field names.
    """
    field_args = ", ".join(f"{field} = None" for field in fields)
    field_init = "\n".join(
        f" object.__setattr__(self, '{name}', {name} if {name} is not None else _{i}_default())"
        for i, name in enumerate(fields)
    )

    code = f"def __init__(self{', ' + field_args or ''}):\n"
    return code + (field_init or " pass")


@_codegen
def _make__eq__(fields: list[str]) -> str:
    """Generates an ``__eq__`` method for a class with the specified fields.

    Args:
        fields: List of field names.
    """
    self_vals = ",".join(f"self.{name}" for name in fields)
    other_vals = ",".join(f"other.{name}" for name in fields)

    if self_vals:
        self_vals += ","
    if other_vals:
        other_vals += ","

    # In the future this could be a looser check, e.g. an __eq__ on the classes, which compares the fields
    code = f"""
    def __eq__(self, other):
        if self.__class__ is other.__class__:
            return ({self_vals}) == ({other_vals})
        return False
    """

    return dedent(code)


@_codegen
def _make__bool__(fields: list[str]) -> str:
    """Generates a ``__bool__`` method for a class with the specified fields.

    Args:
        fields: List of field names.
    """
    vals = ", ".join(f"self.{name}" for name in fields)

    code = f"""
    def __bool__(self):
        return any([{vals}])
    """

    return dedent(code)


@_codegen
def _make__hash__(fields: list[str]) -> str:
    """Generates a ``__hash__`` method for a class with the specified fields.

    Args:
        fields: List of field names.
    """
    vals = ", ".join(f"self.{name}" for name in fields)

    code = f"""
    def __hash__(self):
        return hash(({vals}))
    """

    return dedent(code)


def _patch_attributes(func: FunctionType, fields: list[str], start: int = 0) -> FunctionType:
    """Patches a function's attributes.

    Args:
        func: The function to patch.
        fields: List of field names to add.
        start: The starting index for patching. Defaults to 0.
    """
    return type(func)(
        func.__code__.replace(co_names=(*func.__code__.co_names[:start], *fields)),
        func.__globals__,
    )


def _generate_structure__init__(fields: list[Field]) -> FunctionType:
    """Generates an ``__init__`` method for a structure with the specified fields.

    Args:
        fields: List of field names.
    """
    mapping = _generate_co_mapping(fields)

    template: FunctionType = _make_structure__init__(len(fields))
    return type(template)(
        template.__code__.replace(
            co_names=_remap_co_values(template.__code__.co_names, mapping),
            co_varnames=_remap_co_values(template.__code__.co_varnames, mapping),
        ),
        template.__globals__ | {f"__{field._name}_default__": _default_factory(field.type) for field in fields},
        argdefs=template.__defaults__,
    )


def _generate_union__init__(fields: list[Field]) -> FunctionType:
    """Generates an ``__init__`` method for a union with the specified fields.

    Args:
        fields: List of field names.
    """
    mapping = _generate_co_mapping(fields)

    template: FunctionType = _make_union__init__(len(fields))
    return type(template)(
        template.__code__.replace(
            co_consts=_remap_co_values(template.__code__.co_consts, mapping),
            co_names=_remap_co_values(template.__code__.co_names, mapping),
            co_varnames=_remap_co_values(template.__code__.co_varnames, mapping),
        ),
        template.__globals__ | {f"__{field._name}_default__": _default_factory(field.type) for field in fields},
        argdefs=template.__defaults__,
    )


def _default_factory(type_: type[BaseType]) -> Callable[[], Any]:
    """Return a function that returns default values of a type, which are only shared if they're immutable."""
    value = type_.__default__()
    return repeat(value).__next__ if isinstance(value, _IMMUTABLE_TYPES) else type_.__default__


def _generate_co_mapping(fields: list[Field]) -> dict[str, str]:
    """Generates a mapping of generated code object names to field names.

    The generated code uses names like ``_0``, ``_1``, etc. for fields, and ``_0_default``, ``_1_default``, etc.
    for default initializer values. Return a mapping of these names to the actual field names.

    Args:
        fields: List of field names.
    """
    return {
        key: value
        for i, field in enumerate(fields)
        for key, value in [(f"_{i}", field._name), (f"_{i}_default", f"__{field._name}_default__")]
    }


def _remap_co_values(value: tuple[Any, ...], mapping: dict[str, str]) -> tuple[Any, ...]:
    """Remaps code object values using a mapping.

    This is used to replace generated code object names with actual field names.

    Args:
        value: The original code object values.
        mapping: A mapping of generated code object names to field names.
    """
    # Only attempt to remap if the value is a string, otherwise return it as is
    # This is to avoid issues with trying to remap non-hashable types, and we only need to replace strings anyway
    return tuple(mapping.get(v, v) if isinstance(v, str) else v for v in value)


def _generate__eq__(fields: list[str]) -> FunctionType:
    """Generates an ``__eq__`` method for a class with the specified fields.

    Args:
        fields: List of field names.
    """
    return _patch_attributes(_make__eq__(len(fields)), fields, 1)


def _generate__bool__(fields: list[str]) -> FunctionType:
    """Generates a ``__bool__`` method for a class with the specified fields.

    Args:
        fields: List of field names.
    """
    return _patch_attributes(_make__bool__(len(fields)), fields, 1)


def _generate__hash__(fields: list[str]) -> FunctionType:
    """Generates a ``__hash__`` method for a class with the specified fields.

    Args:
        fields: List of field names.
    """
    return _patch_attributes(_make__hash__(len(fields)), fields, 1)

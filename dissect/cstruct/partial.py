"""Evaluate structures against partially known input.

Regular cstruct parses a complete byte string. Firmware images, memory dumps and
other evidence sources are not always complete, however. This module keeps track
of which input bits are known and which bits are unknown, and evaluates a small,
well-defined subset of cstruct definitions symbolically:

* integer fields, including integer bit fields,
* enum and flag fields,
* statically sized arrays of the above types,
* nested structures and unions,
* conditional (dynamic length) arrays whose length expression can be evaluated
  from the fields collected so far.

The result is a :class:`PartialResult` with one :class:`PartialField` per field.
An integer or enum field exposes a provable value range, and an enum or flag
field also exposes the branches that cannot be excluded. Unknown input bits are
reported as concrete byte and bit positions, together with suggestions for
collecting more data.

The caller supplies the collected bytes and the unknown bits::

    from dissect.cstruct import cstruct

    cs = cstruct().load(
        '''
        enum State : uint16 {
            IDLE = 0x0000,
            RUN  = 0x0100,
            FAULT = 0x0200,
        };

        struct record {
            uint8  version;
            State  state;
            uint16 flags;
        };
        '''
    )

    # The low byte of ``state`` is missing, the high byte is known to be 0x02.
    data = bytes([1, 0, 2, 0x34, 0x12])
    result = cs.record.read_partial(data, unknown_bytes=[1])

    assert result.fields["state"].range == (0x0200, 0x02FF)
    assert "FAULT" in result.fields["state"].possible_branches
    assert "RUN" in result.fields["state"].excluded_branches

Unknown bits can be described in a number of equivalent ways::

    read_partial(T, data, unknown=0b00000100)          # bit mask over the buffer
    read_partial(T, data, unknown_bytes=[2])           # whole bytes
    read_partial(T, data, unknown_bits=[16, 17, 18])   # individual bits
    read_partial(T, data, unknown={2: 0xF0})           # bits within a byte
    read_partial(T, data, unknown_fields=["state"])    # complete fields

Bit numbering follows the byte order of the input: bit ``n`` of byte ``i`` is
absolute bit ``i * 8 + n``, where bit 0 is the least significant bit. A byte mask
may use any non-zero value to mark a byte as unknown.

If no bits are unknown, the result is fully determined and compares equal to a
regular parsed structure. Individual exact fields also compare equal to their
regular parsed values.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field as dataclass_field
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO, Iterable, Iterator, Mapping, Sequence

from dissect.cstruct.exception import Error
from dissect.cstruct.types import (
    BaseArray,
    Char,
    Enum,
    Flag,
    Int,
    Packed,
    Pointer,
    Structure,
    Union,
    Void,
    Wchar,
)
from dissect.cstruct.types.enum import EnumMetaType
from dissect.cstruct.types.structure import StructureMetaType
from dissect.cstruct.util import normalize_endianness

if TYPE_CHECKING:
    from dissect.cstruct.cstruct import AllowedEndianness, Endianness, cstruct
    from dissect.cstruct.types.base import BaseType
    from dissect.cstruct.types.structure import Field


__all__ = [
    "Branch",
    "EnumBranch",
    "FieldAnalysis",
    "FieldValue",
    "IntRange",
    "IntegerRange",
    "Partial",
    "PartialBytes",
    "PartialError",
    "PartialField",
    "PartialEvaluation",
    "PartialRead",
    "PartialResult",
    "PartialStruct",
    "PartialStructure",
    "Suggestion",
    "SymbolicInt",
    "UnknownBits",
    "analyze_partial",
    "evaluate_partial",
    "parse_partial",
    "partial",
    "partial_eval",
    "partial_read",
    "read_partial",
]


class PartialError(Error):
    """Raised when a partial read cannot be evaluated."""


_DEFAULT_VARIANT_LIMIT = 256
_DEFAULT_CONTEXT_LIMIT = 256
_DEFAULT_ENUM_LIMIT = 65536
_INTEGER_FORMATS = frozenset("bBhHiIqQ")
_FLOAT_FORMATS = frozenset("efd")


def _popcount(value: int) -> int:
    return value.bit_count()


def _mask(width: int) -> int:
    return (1 << width) - 1 if width else 0


def _signed_value(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    return value - (1 << width) if value & sign else value


def _is_int_type(type_: type[BaseType]) -> bool:
    if isinstance(type_, EnumMetaType):
        type_ = type_.__type__

    if issubclass(type_, Int):
        return True

    return issubclass(type_, Packed) and type_.__fmt__ in _INTEGER_FORMATS


def _is_float_type(type_: type[BaseType]) -> bool:
    return issubclass(type_, Packed) and type_.__fmt__ in _FLOAT_FORMATS


def _int_info(type_: type[BaseType]) -> tuple[int, bool]:
    """Return the byte size and signedness of an integer type."""
    if isinstance(type_, EnumMetaType):
        type_ = type_.__type__

    if issubclass(type_, Int):
        return type_.__size__, type_.signed

    if issubclass(type_, Packed):
        return type_.__size__, type_.__fmt__.islower()

    if issubclass(type_, Pointer):
        return type_.__size__, False

    raise TypeError(f"Not an integer type: {type_!r}")


@dataclass(frozen=True)
class SymbolicInt:
    """An integer value in which some bits are known and others are unknown.

    ``value`` contains the known bits, with all unknown bits set to zero.
    ``known_mask`` has a one for every bit that is known. ``source_bits`` maps
    every bit in this value to its absolute bit position in the input buffer.
    """

    value: int
    known_mask: int
    width: int
    signed: bool = False
    source_bits: tuple[int, ...] | None = None

    @property
    def unknown_mask(self) -> int:
        return _mask(self.width) & ~self.known_mask

    @property
    def exact(self) -> bool:
        return self.unknown_mask == 0

    @property
    def complete(self) -> bool:
        return self.exact

    @property
    def unknown_bit_count(self) -> int:
        return _popcount(self.unknown_mask)

    @property
    def possible_count(self) -> int:
        """The number of concrete values represented by this field."""
        return 1 << self.unknown_bit_count

    @property
    def min(self) -> int:
        if self.exact:
            return self.to_signed(self.value) if self.signed else self.value

        sign = 1 << (self.width - 1)
        if self.signed:
            if self.known_mask & sign:
                # The sign bit is known. Two's complement ordering is monotonic
                # for the remaining bits in both the positive and negative case.
                low = self.value
                high = self.value | self.unknown_mask
            else:
                # Either sign is possible; the most negative value has the sign
                # bit set and all other unknown bits zero, and the largest value
                # has the sign bit clear and all other unknown bits set.
                low = self.value | sign
                high = self.value | (self.unknown_mask & ~sign)
            return self.to_signed(low)

        return self.value

    @property
    def max(self) -> int:
        if self.exact:
            return self.to_signed(self.value) if self.signed else self.value
        return self.to_signed(self.value | self.unknown_mask) if self.signed else (self.value | self.unknown_mask)

    @property
    def range(self) -> tuple[int, int]:
        return self.min, self.max

    @property
    def unknown_bit_positions(self) -> tuple[int, ...]:
        if self.source_bits is None:
            return ()
        return tuple(sorted(self.source_bits[i] for i in range(self.width) if not (self.known_mask >> i) & 1))

    @property
    def known_bit_positions(self) -> tuple[int, ...]:
        if self.source_bits is None:
            return ()
        return tuple(sorted(self.source_bits[i] for i in range(self.width) if (self.known_mask >> i) & 1))

    def to_signed(self, value: int) -> int:
        return _signed_value(value, self.width)

    def could_equal(self, value: int) -> bool:
        """Return whether ``value`` is one of the represented values."""
        return ((value & _mask(self.width)) & self.known_mask) == self.value

    def extract(self, start: int, width: int, *, source_bits: tuple[int, ...] | None = None) -> SymbolicInt:
        """Extract a bit field from this value."""
        if width > self.width or start < 0 or start + width > self.width:
            raise ValueError("Bit field is outside the storage value")

        mask = _mask(width) << start
        if source_bits is None:
            source_bits = self.source_bits[start : start + width] if self.source_bits else None

        return SymbolicInt(
            (self.value & mask) >> start,
            (self.known_mask & mask) >> start,
            width,
            signed=False,
            source_bits=source_bits,
        )

    def values(self, limit: int = _DEFAULT_CONTEXT_LIMIT) -> list[int]:
        """Enumerate the represented values, if there are not too many."""
        if self.possible_count > limit:
            raise PartialError(f"Too many possible values ({self.possible_count}) to enumerate")

        positions = [i for i in range(self.width) if (self.unknown_mask >> i) & 1]
        result = []
        for assignment in range(self.possible_count):
            raw = self.value
            for index, bit in enumerate(positions):
                if (assignment >> index) & 1:
                    raw |= 1 << bit
            result.append(self.to_signed(raw) if self.signed else raw)
        return result

    def first(self) -> int | None:
        return self.values(1)[0] if self.exact else None

    def __int__(self) -> int:
        if not self.exact:
            raise PartialError(f"Value is not exact, expected one of {self.possible_count} values")
        return self.to_signed(self.value) if self.signed else self.value

    def __index__(self) -> int:
        return int(self)

    def __bool__(self) -> bool:
        return bool(self.value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SymbolicInt):
            return (
                self.value == other.value
                and self.known_mask == other.known_mask
                and self.width == other.width
                and self.signed == other.signed
            )
        if isinstance(other, int):
            return self.exact and int(self) == other
        return NotImplemented

    def __repr__(self) -> str:
        if self.exact:
            return f"<SymbolicInt exact {int(self)}>"
        return (
            f"<SymbolicInt range 0x{self.min:x}..0x{self.max:x} "
            f"known=0x{self.known_mask:x} unknown={self.unknown_bit_count} bits>"
        )


IntegerRange = SymbolicInt
IntRange = SymbolicInt


class PartialBytes:
    """A byte buffer with an explicit known-bit mask.

    Args:
        data: The collected bytes. Bytes that were not collected can be omitted;
            reads beyond the end are treated as unknown.
        unknown: Unknown byte offsets, unknown field names (when the buffer is
            used through :func:`read_partial`), a per-byte mask, or a mapping of
            byte offsets to per-byte unknown masks.
        unknown_bits: Absolute bit positions that are unknown.
        unknown_bytes: Byte offsets that are completely unknown.
        known: The inverse of ``unknown``: a known-bit or known-byte mask.
    """

    def __init__(
        self,
        data: bytes | bytearray | memoryview | Iterable[int],
        unknown: Any = None,
        *,
        unknown_bits: Any = None,
        unknown_bytes: Any = None,
        known: Any = None,
    ):
        self.data = bytes(data)
        self.known = bytearray(b"\xff" * len(self.data))

        # An explicit known mask describes the complete set of collected bits,
        # so start from all-unknown before applying it.
        if known is not None:
            self.known = bytearray(len(self.data))
            self._apply_known(known)
        if unknown is not None:
            self._apply_unknown(unknown)
        if unknown_bits is not None:
            self._apply_bits(unknown_bits)
        if unknown_bytes is not None:
            self._apply_bytes(unknown_bytes)

    @property
    def size(self) -> int:
        return len(self.data)

    def _mark_byte_unknown(self, offset: int, mask: int = 0xFF) -> None:
        if offset < 0:
            offset += len(self.data)
        if 0 <= offset < len(self.data):
            self.known[offset] &= ~mask & 0xFF

    def _mark_bit_unknown(self, bit: int) -> None:
        if bit < 0:
            raise PartialError("Bit positions must not be negative")
        offset, bit_in_byte = divmod(bit, 8)
        self._mark_byte_unknown(offset, 1 << bit_in_byte)

    def _mark_byte_known(self, offset: int, mask: int = 0xFF) -> None:
        if offset < 0:
            offset += len(self.data)
        if 0 <= offset < len(self.data):
            self.known[offset] |= mask & 0xFF

    def _mark_bit_known(self, bit: int) -> None:
        if bit < 0:
            raise PartialError("Bit positions must not be negative")
        offset, bit_in_byte = divmod(bit, 8)
        self._mark_byte_known(offset, 1 << bit_in_byte)

    def _apply_unknown(self, unknown: Any) -> None:
        if isinstance(unknown, PartialBytes):
            self.known = bytearray(unknown.known)
            return

        if isinstance(unknown, Mapping):
            for key, value in unknown.items():
                if isinstance(key, str):
                    raise PartialError("Field names in an unknown mapping require read_partial with a type")
                if isinstance(value, bool):
                    if value:
                        self._mark_byte_unknown(int(key))
                elif isinstance(value, int):
                    self._mark_byte_unknown(int(key), value)
                elif isinstance(value, (bytes, bytearray, memoryview)):
                    mask = int.from_bytes(value, "little")
                    self._mark_byte_unknown(int(key), mask)
                else:
                    raise PartialError(f"Unsupported unknown mask for byte {key!r}: {value!r}")
            return

        if isinstance(unknown, int):
            self._apply_bits(unknown)
            return

        if isinstance(unknown, (bytes, bytearray, memoryview, str)):
            if isinstance(unknown, str):
                raise PartialError("Field names in unknown require read_partial with a type")

            unknown = bytes(unknown)
            if len(unknown) <= len(self.data) and len(self.data) > 0 and len(unknown) == len(self.data):
                # A per-byte mask. ``b"\x00\xff"`` marks the second byte unknown.
                # A mask of only zeroes and ones is still interpreted as bytes to
                # avoid surprising callers; use unknown_bits for bits.
                for offset, value in enumerate(unknown):
                    if value:
                        self._mark_byte_unknown(offset, 0xFF if value != 0xFF else 0xFF)
                return

            # A compact bit mask (little endian within the byte string).
            self._apply_bits(int.from_bytes(unknown, "little"))
            return

        if isinstance(unknown, slice):
            self._apply_bytes(range(*unknown.indices(len(self.data))))
            return

        if isinstance(unknown, Iterable):
            items = list(unknown)
            if (
                len(items) == len(self.data) * 8
                and all(isinstance(item, int) and item in (0, 1) for item in items)
            ):
                self._apply_bits([index for index, value in enumerate(items) if value])
                return
            for item in items:
                if isinstance(item, str):
                    raise PartialError("Field names in unknown require read_partial with a type")
                if isinstance(item, bool):
                    continue
                if isinstance(item, int):
                    self._mark_byte_unknown(item)
                elif isinstance(item, slice):
                    self._apply_bytes(range(*item.indices(len(self.data))))
                elif isinstance(item, tuple) and len(item) == 2:
                    self._apply_bytes(range(int(item[0]), int(item[1])))
                elif isinstance(item, tuple) and len(item) == 3:
                    self._apply_bytes(range(int(item[0]), int(item[1]), int(item[2])))
                else:
                    raise PartialError(f"Unsupported unknown specification: {item!r}")
            return

        raise PartialError(f"Unsupported unknown specification: {unknown!r}")

    def _apply_bits(self, bits: Any) -> None:
        if isinstance(bits, Mapping):
            for offset, mask in bits.items():
                self._mark_byte_unknown(int(offset), int(mask))
            return

        if isinstance(bits, int):
            while bits:
                least = bits & -bits
                self._mark_bit_unknown(least.bit_length() - 1)
                bits ^= least
            return

        if isinstance(bits, (bytes, bytearray, memoryview)):
            self._apply_bits(int.from_bytes(bits, "little"))
            return

        if isinstance(bits, slice):
            for bit in range(*bits.indices(len(self.data) * 8)):
                self._mark_bit_unknown(bit)
            return

        for item in bits:
            if isinstance(item, int):
                self._mark_bit_unknown(item)
            elif isinstance(item, slice):
                for bit in range(*item.indices(len(self.data) * 8)):
                    self._mark_bit_unknown(bit)
            elif isinstance(item, tuple) and len(item) in (2, 3):
                for bit in range(*item):
                    self._mark_bit_unknown(bit)
            else:
                raise PartialError(f"Unsupported unknown bit specification: {item!r}")

    def _apply_bytes(self, offsets: Any) -> None:
        if isinstance(offsets, (bytes, bytearray, memoryview)) and len(offsets) == len(self.data):
            for offset, value in enumerate(offsets):
                if value:
                    self._mark_byte_unknown(offset)
            return

        if isinstance(offsets, int):
            self._mark_byte_unknown(offsets)
            return
        if isinstance(offsets, slice):
            self._apply_bytes(range(*offsets.indices(len(self.data))))
            return
        for item in offsets:
            if isinstance(item, int):
                self._mark_byte_unknown(item)
            elif isinstance(item, slice):
                self._apply_bytes(range(*item.indices(len(self.data))))
            elif isinstance(item, tuple) and len(item) in (2, 3):
                self._apply_bytes(range(*item))
            else:
                raise PartialError(f"Unsupported unknown byte specification: {item!r}")

    def _apply_known(self, known: Any) -> None:
        if isinstance(known, int):
            width = len(self.data) * 8
            mask = known & _mask(width)
            for offset in range(len(self.data)):
                self.known[offset] = (mask >> (offset * 8)) & 0xFF
            return

        if isinstance(known, (bytes, bytearray, memoryview)):
            known = bytes(known)
            if len(known) == len(self.data):
                for offset, value in enumerate(known):
                    self.known[offset] = value
                return
            self._apply_known(int.from_bytes(known, "little"))
            return

        if isinstance(known, slice):
            for offset in range(*known.indices(len(self.data))):
                self._mark_byte_known(offset)
            return

        for item in known:
            if isinstance(item, int):
                self._mark_byte_known(item)
            elif isinstance(item, slice):
                for offset in range(*item.indices(len(self.data))):
                    self._mark_byte_known(offset)
            elif isinstance(item, tuple) and len(item) in (2, 3):
                for offset in range(*item):
                    self._mark_byte_known(offset)
            else:
                raise PartialError(f"Unsupported known specification: {item!r}")

    def known_mask(self, offset: int, size: int) -> bytes:
        return bytes(self.known[offset : offset + size]) if 0 <= offset < len(self.data) else bytes(size)

    def byte(self, offset: int) -> tuple[int, int]:
        """Return the known bits and their value for one byte."""
        if 0 <= offset < len(self.data):
            mask = self.known[offset]
            return mask, self.data[offset] & mask
        return 0, 0

    def symbolic(
        self,
        offset: int,
        size: int,
        endian: Endianness,
        *,
        signed: bool = False,
        bit_start: int | None = None,
        bit_width: int | None = None,
    ) -> SymbolicInt:
        """Return a symbolic integer read from ``size`` bytes at ``offset``."""
        width = size * 8
        value = 0
        known = 0
        source = [0] * width

        if endian == "<":
            for index in range(size):
                byte_mask, byte_value = self.byte(offset + index)
                value |= byte_value << (index * 8)
                known |= byte_mask << (index * 8)
                for bit in range(8):
                    source[index * 8 + bit] = (offset + index) * 8 + bit
        else:
            for index in range(size):
                byte_mask, byte_value = self.byte(offset + index)
                shift = (size - 1 - index) * 8
                value |= byte_value << shift
                known |= byte_mask << shift
                for bit in range(8):
                    source[shift + bit] = (offset + index) * 8 + bit

        result = SymbolicInt(value, known, width, signed=signed, source_bits=tuple(source))
        if bit_start is not None:
            bit_width = bit_width or (width - bit_start)
            result = result.extract(bit_start, bit_width)
        return result

    def bit(self, position: int) -> tuple[int, int]:
        """Return whether an absolute bit is known, and its value."""
        offset, bit_in_byte = divmod(position, 8)
        mask, value = self.byte(offset)
        if not (mask >> bit_in_byte) & 1:
            return 0, 0
        return 1, (value >> bit_in_byte) & 1

    @property
    def unknown_bytes(self) -> tuple[int, ...]:
        return tuple(offset for offset, mask in enumerate(self.known) if mask != 0xFF)

    @property
    def unknown_bits(self) -> tuple[int, ...]:
        result = []
        for offset, mask in enumerate(self.known):
            for bit in range(8):
                if not (mask >> bit) & 1:
                    result.append(offset * 8 + bit)
        return tuple(result)

    @property
    def exact(self) -> bool:
        return all(mask == 0xFF for mask in self.known)


UnknownBits = PartialBytes


@dataclass
class Suggestion:
    """A concrete suggestion for collecting more input data."""

    message: str
    field: str | None = None
    bits: tuple[int, ...] = ()
    bytes: tuple[int, ...] = ()
    kind: str = "collect"

    def __str__(self) -> str:
        return self.message

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.message == other
        if isinstance(other, Suggestion):
            return self.message == other.message
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "field": self.field,
            "message": self.message,
            "bits": list(self.bits),
            "bytes": list(self.bytes),
        }


@dataclass
class Branch:
    """One enum or flag branch that may or may not be possible."""

    name: str
    value: int | None = None
    possible: bool = True
    reason: str | None = None
    suggestions: list[Suggestion] = dataclass_field(default_factory=list)

    def __bool__(self) -> bool:
        return self.possible

    @property
    def is_possible(self) -> bool:
        return self.possible

    @property
    def excluded(self) -> bool:
        return not self.possible

    @property
    def impossible(self) -> bool:
        return not self.possible

    @property
    def explanation(self) -> str | None:
        return self.reason

    def __str__(self) -> str:
        return self.name

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.name == other
        if isinstance(other, Branch):
            return self.name == other.name and self.value == other.value
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.name, self.value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "possible": self.possible,
            "reason": self.reason,
            "suggestions": [suggestion.to_dict() for suggestion in self.suggestions],
        }


EnumBranch = Branch


class PartialField:
    """The result of evaluating one structure field against partial input."""

    def __init__(
        self,
        name: str,
        type_: type[BaseType] | None = None,
        *,
        path: str | None = None,
        offset: int | None = None,
        size: int | None = None,
        bits: int | None = None,
        kind: str = "unknown",
    ):
        self.name = name
        self.type = type_
        self.path = path or name
        self.offset = offset
        self.size = size
        self.bits = bits
        self.kind = kind

        self.value: Any = None
        self.symbolic: SymbolicInt | None = None
        self.children: dict[str, PartialField] = {}
        self.elements: list[PartialField] = []
        self.branches: list[Branch] = []
        self.suggestions: list[Suggestion] = []
        self.variants: list[PartialField] = []
        self.conditions: list[Branch] = []
        self.condition: str | None = None
        self.condition_state: str | None = None
        self._reason: str | None = None
        self._exact = False
        self._raw_known: bytes | None = None

    @property
    def exact(self) -> bool:
        if self.variants:
            if not all(variant.exact for variant in self.variants):
                return False
            first = self.variants[0].value
            return all(variant.value == first for variant in self.variants[1:])
        if self.symbolic is not None:
            return self.symbolic.exact
        return self._exact

    @property
    def complete(self) -> bool:
        return self.exact

    @property
    def known(self) -> bool:
        return self.exact

    @property
    def partial(self) -> bool:
        return not self.exact

    @property
    def range(self) -> tuple[int, int] | None:
        if self.variants:
            ranges = [variant.range for variant in self.variants if variant.range is not None]
            if ranges:
                return min(item[0] for item in ranges), max(item[1] for item in ranges)
        if self.symbolic is not None:
            return self.symbolic.range
        if self.elements:
            ranges = [element.range for element in self.elements if element.range is not None]
            if ranges:
                return min(item[0] for item in ranges), max(item[1] for item in ranges)
        return None

    @property
    def value_range(self) -> tuple[int, int] | None:
        return self.range

    @property
    def possible_range(self) -> tuple[int, int] | None:
        return self.range

    @property
    def min(self) -> int | None:
        return self.range[0] if self.range is not None else None

    @property
    def minimum(self) -> int | None:
        return self.min

    @property
    def max(self) -> int | None:
        return self.range[1] if self.range is not None else None

    @property
    def maximum(self) -> int | None:
        return self.max

    @property
    def possible_values(self) -> list[int]:
        if self.symbolic is not None:
            try:
                return self.symbolic.values(_DEFAULT_ENUM_LIMIT)
            except PartialError:
                return []
        if self.elements:
            return [element.value for element in self.elements if element.exact]
        return []

    @property
    def values(self) -> list[int]:
        return self.possible_values

    @property
    def possible_count(self) -> int | None:
        return self.symbolic.possible_count if self.symbolic else None

    @property
    def unknown_bits(self) -> tuple[int, ...]:
        if self.symbolic is not None:
            return self.symbolic.unknown_bit_positions
        return tuple(bit for child in self.children.values() for bit in child.unknown_bits)

    @property
    def unknown_bit_count(self) -> int:
        if self.symbolic is not None:
            return self.symbolic.unknown_bit_count
        return len(self.unknown_bits)

    @property
    def unknown_bytes(self) -> tuple[int, ...]:
        return tuple(sorted({bit // 8 for bit in self.unknown_bits}))

    @property
    def unknown_mask(self) -> int | None:
        return self.symbolic.unknown_mask if self.symbolic else None

    @property
    def known_mask(self) -> int | None:
        return self.symbolic.known_mask if self.symbolic else None

    @property
    def known_bits(self) -> tuple[int, ...]:
        if self.symbolic is not None:
            return self.symbolic.known_bit_positions
        return ()

    @property
    def possible_branches(self) -> list[Branch]:
        return [branch for branch in self.branches if branch.possible]

    @property
    def excluded_branches(self) -> list[Branch]:
        return [branch for branch in self.branches if not branch.possible]

    @property
    def possible_branch_names(self) -> list[str]:
        return [branch.name for branch in self.possible_branches]

    @property
    def excluded_branch_names(self) -> list[str]:
        return [branch.name for branch in self.excluded_branches]

    @property
    def branch_names(self) -> list[str]:
        return [branch.name for branch in self.branches]

    @property
    def possible_members(self) -> list[Branch]:
        return self.possible_branches

    @property
    def excluded_members(self) -> list[Branch]:
        return self.excluded_branches

    @property
    def members(self) -> list[Branch]:
        return self.branches

    @property
    def reason(self) -> str | None:
        return self._reason

    @property
    def why(self) -> str | None:
        return self._reason

    @property
    def advice(self) -> list[Suggestion]:
        return self.suggestions

    @property
    def recommendations(self) -> list[Suggestion]:
        return self.suggestions

    @property
    def further_collection(self) -> list[Suggestion]:
        return self.suggestions

    @property
    def uncertain(self) -> bool:
        return not self.exact

    @property
    def explanation(self) -> str | None:
        return self._reason

    @property
    def conditional(self) -> bool:
        return self.condition is not None

    @property
    def active(self) -> bool:
        return self.condition_state != "never"

    @property
    def possible_lengths(self) -> list[int]:
        if self.kind != "array":
            return []
        if self.variants:
            return sorted({len(variant.elements) for variant in self.variants})
        return [len(self.elements)]

    def get(self, name: str, default: Any = None) -> PartialField | Any:
        return self.children.get(name, default)

    def field(self, name: str) -> PartialField:
        return self.children[name]

    def __getitem__(self, name: str) -> PartialField:
        return self.children[name]

    def __contains__(self, name: str) -> bool:
        return name in self.children

    def __int__(self) -> int:
        if self.symbolic is not None:
            return int(self.symbolic)
        if isinstance(self.value, int):
            return int(self.value)
        raise PartialError(f"Field {self.path!r} is not an exact integer")

    def __index__(self) -> int:
        return int(self)

    def __bool__(self) -> bool:
        if self.exact and self.value is not None:
            return bool(self.value)
        return True

    def __eq__(self, other: object) -> bool:
        if isinstance(other, PartialField):
            return self.exact == other.exact and self.range == other.range and self.value == other.value
        if self.exact:
            return self.value == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.path, self.exact, self.value))

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "path": self.path,
            "type": self.type.__name__ if self.type is not None else None,
            "kind": self.kind,
            "offset": self.offset,
            "size": self.size,
            "bits": self.bits,
            "exact": self.exact,
        }
        if self.symbolic is not None:
            result.update(
                {
                    "value": int(self.symbolic) if self.symbolic.exact else None,
                    "min": self.symbolic.min,
                    "max": self.symbolic.max,
                    "possible_count": self.symbolic.possible_count,
                    "known_mask": self.symbolic.known_mask,
                    "unknown_mask": self.symbolic.unknown_mask,
                    "unknown_bits": list(self.unknown_bits),
                }
            )
        elif self.value is not None:
            result["value"] = self.value

        if self.branches:
            result["branches"] = [branch.to_dict() for branch in self.branches]
            result["possible_branches"] = self.possible_branch_names
            result["excluded_branches"] = self.excluded_branch_names

        if self.children:
            result["fields"] = {name: child.to_dict() for name, child in self.children.items()}
        if self.elements:
            result["elements"] = [element.to_dict() for element in self.elements]
        if self.suggestions:
            result["suggestions"] = [suggestion.to_dict() for suggestion in self.suggestions]
        if self._reason:
            result["reason"] = self._reason
        if self.condition is not None:
            result["condition"] = self.condition
            result["condition_state"] = self.condition_state
            result["possible_lengths"] = self.possible_lengths

        return result

    def __repr__(self) -> str:
        if self.symbolic is not None:
            state = f"exact={int(self.symbolic)}" if self.symbolic.exact else f"range={self.range}"
        elif self.kind == "struct":
            state = f"fields={len(self.children)}"
        else:
            state = f"exact={self.exact}"
        return f"<PartialField {self.path} {state}>"


FieldValue = PartialField
FieldAnalysis = PartialField


class PartialResult:
    """The result of :func:`read_partial` for a structure."""

    def __init__(
        self,
        type_: type[Structure],
        source: PartialBytes,
        *,
        value: Structure | None = None,
        truncated: bool = False,
    ):
        self.type = type_
        self.source = source
        self.fields: dict[str, PartialField] = {}
        self.value = value
        self.truncated = truncated
        self.suggestions: list[Suggestion] = []
        self.unresolved_layout = False

    @property
    def object(self) -> Structure | None:
        return self.value

    @property
    def struct(self) -> Structure | None:
        return self.value

    @property
    def exact(self) -> bool:
        return not self.truncated and all(field.exact for field in self.fields.values())

    @property
    def complete(self) -> bool:
        return self.exact

    @property
    def partial(self) -> bool:
        return not self.exact

    @property
    def unknown_bits(self) -> tuple[int, ...]:
        return tuple(bit for field in self.fields.values() for bit in field.unknown_bits)

    @property
    def unknown_bytes(self) -> tuple[int, ...]:
        return tuple(sorted({bit // 8 for bit in self.unknown_bits}))

    @property
    def ranges(self) -> dict[str, tuple[int, int]]:
        return {name: field.range for name, field in self.flat_fields.items() if field.range is not None}

    @property
    def possible_branches(self) -> dict[str, list[Branch]]:
        return {name: field.possible_branches for name, field in self.flat_fields.items() if field.branches}

    @property
    def excluded_branches(self) -> dict[str, list[Branch]]:
        return {name: field.excluded_branches for name, field in self.flat_fields.items() if field.branches}

    @property
    def flat_fields(self) -> dict[str, PartialField]:
        result = {}
        for name, field in self.fields.items():
            result[name] = field
            result.update(_flat_fields(field, name))
        return result

    @property
    def field_names(self) -> list[str]:
        return list(self.fields)

    @property
    def field_results(self) -> dict[str, PartialField]:
        return self.fields

    @property
    def branches(self) -> dict[str, list[Branch]]:
        return {name: field.branches for name, field in self.flat_fields.items() if field.branches}

    @property
    def advice(self) -> list[Suggestion]:
        return self.suggestions

    @property
    def recommendations(self) -> list[Suggestion]:
        return self.suggestions

    @property
    def further_collection(self) -> list[Suggestion]:
        return self.suggestions

    @property
    def values(self) -> dict[str, Any]:
        return {name: field.value if field.exact else field for name, field in self.fields.items()}

    @property
    def conditional_fields(self) -> dict[str, PartialField]:
        return {name: field for name, field in self.flat_fields.items() if field.conditional}

    def field(self, name: str) -> PartialField:
        if name in self.fields:
            return self.fields[name]
        flat = self.flat_fields
        if name in flat:
            return flat[name]
        # Anonymous structures fold their fields into the parent namespace.
        for path, field in flat.items():
            if path.endswith(f".{name}"):
                return field
        raise KeyError(name)

    def get(self, name: str, default: Any = None) -> PartialField | Any:
        try:
            return self.field(name)
        except KeyError:
            return default

    def __getitem__(self, name: str) -> PartialField:
        return self.field(name)

    def __iter__(self) -> Iterator[str]:
        return iter(self.fields)

    def __contains__(self, name: str) -> bool:
        return name in self.fields or name in self.flat_fields or any(
            path.endswith(f".{name}") for path in self.flat_fields
        )

    def __getattr__(self, name: str) -> Any:
        # Suffix helpers are convenient for interactive analysis:
        # result.state_range, result.state_branches, result.state_suggestions.
        for suffix, attribute in (
            ("_range", "range"),
            ("_min", "min"),
            ("_max", "max"),
            ("_branches", "branches"),
            ("_possible_branches", "possible_branches"),
            ("_excluded_branches", "excluded_branches"),
            ("_suggestions", "suggestions"),
        ):
            if name.endswith(suffix) and (field_name := name[: -len(suffix)]) in self.flat_fields:
                return getattr(self.flat_fields[field_name], attribute)

        if name in self.fields:
            field = self.fields[name]
            return field.value if field.exact and field.value is not None else field

        if name in self.flat_fields:
            field = self.flat_fields[name]
            return field.value if field.exact and field.value is not None else field

        for path, field in self.flat_fields.items():
            if path.endswith(f".{name}"):
                return field.value if field.exact and field.value is not None else field

        if self.value is not None and hasattr(self.value, name):
            return getattr(self.value, name)

        raise AttributeError(f"'{type(self).__name__}' object has no attribute {name!r}")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, PartialResult):
            return self.type is other.type and self.fields == other.fields
        if self.value is not None:
            return self.value == other
        return NotImplemented

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.__name__,
            "exact": self.exact,
            "truncated": self.truncated,
            "unknown_bits": list(self.unknown_bits),
            "unknown_bytes": list(self.unknown_bytes),
            "fields": {name: field.to_dict() for name, field in self.fields.items()},
            "suggestions": [suggestion.to_dict() for suggestion in self.suggestions],
        }

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), **kwargs)

    def __repr__(self) -> str:
        state = "exact" if self.exact else f"partial ({len(self.unknown_bits)} unknown bits)"
        return f"<PartialResult {self.type.__name__} {state}>"


PartialStructure = PartialResult
PartialStruct = PartialResult
PartialEvaluation = PartialResult


def _flat_fields(field: PartialField, prefix: str) -> dict[str, PartialField]:
    result = {}
    for name, child in field.children.items():
        path = f"{prefix}.{name}"
        result[path] = child
        result.update(_flat_fields(child, path))
    for index, element in enumerate(field.elements):
        path = f"{prefix}[{index}]"
        result[path] = element
        result.update(_flat_fields(element, path))
    return result


@dataclass
class _WalkState:
    cursor: int
    results: list[PartialField]
    contexts: list[dict[str, int]]
    bit_group: _BitGroup | None = None


@dataclass
class _BitGroup:
    offset: int
    size: int
    storage: SymbolicInt
    remaining: int
    endian: Endianness
    storage_type: type[BaseType]


class _PartialParser:
    def __init__(
        self,
        cs: cstruct,
        source: PartialBytes,
        *,
        endian: Endianness,
        variant_limit: int = _DEFAULT_VARIANT_LIMIT,
        context_limit: int = _DEFAULT_CONTEXT_LIMIT,
        enum_limit: int = _DEFAULT_ENUM_LIMIT,
    ):
        self.cs = cs
        self.source = source
        self.endian = endian
        self.variant_limit = variant_limit
        self.context_limit = context_limit
        self.enum_limit = enum_limit
        self.truncated = False

    def parse(self, type_: type[BaseType]) -> PartialResult:
        if not isinstance(type_, StructureMetaType):
            field = _pseudo_field(type_, "value")
            size = type_.__size__
            if size is None:
                size = len(self.source.data) if issubclass(type_, BaseArray) and type_.__null_terminated__ else 0
            result_field = self._parse_field(field, 0, size, "", [{}])
            result = PartialResult(type_, self.source, truncated=self.truncated)  # type: ignore[arg-type]
            result.fields = {"value": result_field}
            if result_field.exact:
                result.value = result_field.value
            result.suggestions = self._aggregate_suggestions(result)
            return result

        states = self._walk_struct(type_, 0, "", [{}])
        fields = _merge_states(states)

        value = None
        if self.source.exact:
            try:
                value = type_.read(BytesIO(self.source.data))
            except (EOFError, ValueError, struct.error):
                value = None

        result = PartialResult(type_, self.source, value=value, truncated=self.truncated)
        result.fields = {field.name or field._name: field for field in fields}
        if result.value is None and all(field.exact for field in result.fields.values()):
            try:
                result.value = type_.read(BytesIO(self.source.data))
            except (EOFError, ValueError, struct.error):
                pass
        result.suggestions = self._aggregate_suggestions(result)
        return result

    def _walk_struct(
        self,
        cls: type[Structure],
        base: int,
        path: str,
        contexts: list[dict[str, int]],
    ) -> list[_WalkState]:
        states = [_WalkState(base, [], contexts)]

        for field in cls.__fields__:
            next_states: list[_WalkState] = []

            for state in states:
                if len(next_states) >= self.variant_limit:
                    self.truncated = True
                    break

                field_type = field.type
                offset = base + field.offset if field.offset is not None and not field.bits else state.cursor
                if field.bits and field.offset is not None and state.bit_group is None:
                    offset = base + field.offset

                if cls.__align__ and field.offset is None and not field.bits and state.bit_group is None:
                    offset += -offset & (field.alignment - 1)

                if field.bits:
                    storage_type = field.type.__type__ if isinstance(field.type, EnumMetaType) else field.type
                    if (
                        state.bit_group is not None
                        and state.bit_group.remaining > 0
                        and state.bit_group.storage_type is storage_type
                    ):
                        # Continue the current storage value, like BitBuffer does.
                        offset = state.bit_group.offset
                    result, group, cursor = self._parse_bit_field(field, offset, path, state.bit_group)
                    next_states.append(
                        _WalkState(cursor, [*state.results, result], state.contexts, bit_group=group)
                    )
                    continue

                if state.bit_group is not None:
                    state.cursor = state.bit_group.offset + state.bit_group.size
                    state.bit_group = None
                    if field.offset is not None:
                        offset = base + field.offset
                    else:
                        offset = state.cursor

                sizes = self._field_size_options(field, offset, state.contexts)
                for size in sizes:
                    if size and offset + size > self.source.size:
                        self.truncated = True
                    result = self._parse_field(field, offset, size, path, state.contexts)
                    new_contexts = self._extend_contexts(state.contexts, result)
                    next_states.append(
                        _WalkState(offset + size, [*state.results, result], new_contexts)
                    )

            states = next_states[: self.variant_limit]
            if len(next_states) > self.variant_limit:
                self.truncated = True

        return states

    def _extend_contexts(
        self, contexts: list[dict[str, int]], field: PartialField
    ) -> list[dict[str, int]]:
        if field.symbolic is None:
            if field.exact and field.value is not None and isinstance(field.value, int):
                return [{**context, field.name: int(field.value)} for context in contexts]
            return contexts

        if field.symbolic.possible_count > self.context_limit:
            return contexts

        values = field.symbolic.values()
        result = []
        for context in contexts:
            for value in values:
                result.append({**context, field.name: value})
                if len(result) >= self.context_limit:
                    return result
        return result

    def _field_size_options(self, field: Field, offset: int, contexts: list[dict[str, int]]) -> list[int]:
        type_ = field.type

        if issubclass(type_, BaseArray):
            return self._array_size_options(type_, offset, contexts)

        if type_.__size__ is not None:
            return [type_.__size__]

        # A dynamically sized structure. Parse a concrete version to discover its
        # consumed size; if it depends on unknown fields we conservatively keep
        # that one layout and flag the result as truncated.
        try:
            stream = BytesIO(self.source.data[offset:])
            before = stream.tell()
            type_._read(stream, endian=self.endian)
            return [stream.tell() - before]
        except (EOFError, ValueError, struct.error):
            self.truncated = True
            return [0]

    def _array_size_options(
        self, type_: type[BaseArray], offset: int, contexts: list[dict[str, int]]
    ) -> list[int]:
        element_size = type_.__type__.__size__
        if element_size is None:
            self.truncated = True
            return [0]

        count = type_.__num_entries__
        if isinstance(count, int):
            return [max(0, count) * element_size]

        if count is None:
            # Null-terminated array. Find all possible terminator positions until
            # the first byte that is known to be non-zero.
            options = []
            index = offset
            while index < len(self.source.data):
                mask, _ = self.source.byte(index)
                if mask == 0xFF:
                    # Known byte: it ends the array if zero, otherwise continue.
                    if self.source.data[index] == 0:
                        options.append((index - offset + 1) * element_size)
                        break
                else:
                    options.append((index - offset + 1) * element_size)
                index += 1
                if len(options) >= self.variant_limit:
                    self.truncated = True
                    break
            if not options:
                options.append(0)
            return options

        expression = getattr(count, "expression", None)
        if expression == "EOF":
            remaining = max(0, len(self.source.data) - offset)
            return [(remaining // element_size) * element_size]

        counts = set()
        for context in contexts:
            try:
                value = count.evaluate(self.cs, context)
            except Exception:
                continue
            counts.add(max(0, int(value)))

        if not counts:
            # Try the regular path for a fully known prefix.
            try:
                value = count.evaluate(self.cs, {})
                counts.add(max(0, int(value)))
            except Exception:
                self.truncated = True
                counts.add(0)

        if len(counts) > self.variant_limit:
            self.truncated = True
            counts = set(sorted(counts)[: self.variant_limit])

        return sorted(count * element_size for count in counts)

    def _parse_bit_field(
        self,
        field: Field,
        offset: int,
        path: str,
        group: _BitGroup | None,
    ) -> tuple[PartialField, _BitGroup, int]:
        type_ = field.type
        storage_type = type_.__type__ if isinstance(type_, EnumMetaType) else type_
        storage_size = storage_type.__size__
        if storage_size is None:
            raise PartialError(f"Bit field {field._name!r} has a dynamic storage type")

        new_group = (
            group is None
            or group.remaining == 0
            or group.size != storage_size
            or group.storage_type is not storage_type
        )
        if new_group:
            storage = self.source.symbolic(offset, storage_size, self.endian, signed=False)
            group = _BitGroup(offset, storage_size, storage, storage_size * 8, self.endian, storage_type)

        if field.bits is None or field.bits > group.remaining:
            raise PartialError(f"Unsupported bit field width for {field._name!r}")

        if self.endian == "<":
            start = group.size * 8 - group.remaining
        else:
            start = group.remaining - field.bits

        result = group.storage.extract(start, field.bits)
        group.remaining -= field.bits
        cursor = group.offset + group.size

        field_result = self._field_from_symbolic(field, result, path, offset, group.size, bits=field.bits)
        return field_result, group, cursor

    def _parse_field(
        self,
        field: Field,
        offset: int,
        size: int,
        path: str,
        contexts: list[dict[str, int]],
    ) -> PartialField:
        type_ = field.type
        field_path = f"{path}.{field._name}" if path and field.name is not None else (path or field._name)

        if issubclass(type_, BaseArray):
            return self._parse_array(field, offset, size, path, contexts)

        if issubclass(type_, Union):
            return self._parse_union_field(field, offset, size, field_path)

        if issubclass(type_, Structure):
            return self._parse_structure_field(field, offset, size, field_path)

        if _is_int_type(type_):
            int_size, signed = _int_info(type_)
            symbolic = self.source.symbolic(offset, int_size, self.endian, signed=signed)
            return self._field_from_symbolic(field, symbolic, path, offset, int_size)

        if _is_float_type(type_):
            return self._parse_float_field(field, offset, size, path)

        if issubclass(type_, Char):
            return self._parse_bytes_field(field, offset, size, path)

        if issubclass(type_, Wchar):
            return self._parse_wchar_field(field, offset, size, path)

        if issubclass(type_, Void):
            result = PartialField(field._name, type_, path=field_path, offset=offset, size=0, kind="void")
            result._exact = True
            return result

        # Types that are not part of the supported symbolic subset are still
        # parsed normally when their bytes are known.
        result = PartialField(field._name, type_, path=field_path, offset=offset, size=size, kind="opaque")
        if self.source.known_mask(offset, size) == b"\xff" * size:
            try:
                result.value = type_.read(BytesIO(self.source.data[offset : offset + size]))
                result._exact = True
            except Exception:
                result._exact = False
        return result

    def _parse_union_field(
        self,
        field: Field,
        offset: int,
        size: int,
        field_path: str,
    ) -> PartialField:
        type_ = field.type
        result = PartialField(field._name, type_, path=field_path, offset=offset, size=size, kind="union")

        for member in type_.__fields__:
            member_offset = offset + (member.offset or 0)
            member_size = member.type.__size__
            if member_size is None:
                result._exact = False
                continue
            child = self._parse_field(
                _pseudo_field(member.type, member.name),
                member_offset,
                member_size,
                field_path,
                [{}],
            )
            result.children[member.name] = child

        result._exact = bool(self.source.known_mask(offset, size) == b"\xff" * size) and all(
            child.exact for child in result.children.values()
        )
        if result._exact:
            try:
                result.value = type_.read(BytesIO(self.source.data[offset : offset + size]))
            except Exception:
                result._exact = False
        if not result._exact:
            result.suggestions = [
                Suggestion(
                    f"Collect bytes {offset}..{offset + max(0, size - 1)} to resolve union {field_path!r}.",
                    field=field_path,
                    bits=result.unknown_bits,
                    bytes=result.unknown_bytes,
                )
            ]
        return result

    def _parse_structure_field(
        self,
        field: Field,
        offset: int,
        size: int,
        field_path: str,
    ) -> PartialField:
        type_ = field.type
        result = PartialField(field._name, type_, path=field_path, offset=offset, size=size, kind="struct")

        states = self._walk_struct(type_, offset, field_path, [{}])
        children = _merge_states(states)
        result.children = {child.name: child for child in children}
        result._exact = bool(self.source.known_mask(offset, size) == b"\xff" * size) and all(
            child.exact for child in result.children.values()
        )
        if result._exact:
            try:
                result.value = type_.read(BytesIO(self.source.data[offset : offset + size]))
            except Exception:
                result._exact = False
        if not result._exact:
            result.suggestions = [
                Suggestion(
                    f"Collect bytes {offset}..{offset + size - 1} to resolve "
                    f"{field_path!r} ({len(result.unknown_bits)} unknown bits).",
                    field=field_path,
                    bits=result.unknown_bits,
                    bytes=result.unknown_bytes,
                )
            ]
        return result

    def _parse_array(
        self,
        field: Field,
        offset: int,
        size: int,
        path: str,
        contexts: list[dict[str, int]],
    ) -> PartialField:
        type_ = field.type
        element_type = type_.__type__
        element_size = element_type.__size__
        field_path = f"{path}.{field._name}" if path and field.name is not None else (path or field._name)
        result = PartialField(field._name, type_, path=field_path, offset=offset, size=size, kind="array")
        num_entries = getattr(type_, "__num_entries__", None)
        if getattr(num_entries, "expression", None) not in (None, "EOF"):
            result.condition = num_entries.expression
            result.condition_state = "determined" if getattr(num_entries, "expression", None) else "open"

        if element_size is None:
            result._exact = False
            return result

        count = size // element_size if element_size else 0
        result.elements = []
        for index in range(count):
            element_offset = offset + index * element_size
            element_path = f"{field_path}[{index}]"
            if issubclass(element_type, Structure):
                element_field = self._parse_structure_field(
                    _pseudo_field(element_type, name=None),
                    element_offset,
                    element_size,
                    element_path,
                )
            elif _is_int_type(element_type):
                int_size, signed = _int_info(element_type)
                symbolic = self.source.symbolic(element_offset, int_size, self.endian, signed=signed)
                element_field = self._field_from_symbolic(
                    _pseudo_field(element_type, name=None), symbolic, element_path, element_offset, int_size
                )
            elif issubclass(element_type, (Char, Wchar)):
                element_field = self._parse_bytes_field(
                    _pseudo_field(element_type, name=None), element_offset, element_size, element_path
                )
            else:
                element_field = PartialField(
                    f"[{index}]", element_type, path=element_path, offset=element_offset, size=element_size
                )
                element_field._exact = self.source.known_mask(element_offset, element_size) == b"\xff" * element_size
                if element_field._exact:
                    try:
                        element_field.value = element_type.read(
                            BytesIO(self.source.data[element_offset : element_offset + element_size])
                        )
                    except Exception:
                        element_field._exact = False
            result.elements.append(element_field)

        result._exact = all(element.exact for element in result.elements)
        if result._exact:
            try:
                result.value = type_.read(BytesIO(self.source.data[offset : offset + size]))
            except Exception:
                result.value = [element.value for element in result.elements]

        if not result._exact:
            if result.condition is not None:
                result.condition_state = "open"
            result.suggestions = [
                Suggestion(
                    f"Collect bytes {offset}..{offset + max(0, size - 1)} to resolve "
                    f"{field_path!r} ({len(result.unknown_bits)} unknown bits).",
                    field=field_path,
                    bits=result.unknown_bits,
                    bytes=result.unknown_bytes,
                )
            ]
        return result

    def _parse_float_field(self, field: Field, offset: int, size: int, path: str) -> PartialField:
        field_path = f"{path}.{field._name}" if path and field.name is not None else (path or field._name)
        result = PartialField(field._name, field.type, path=field_path, offset=offset, size=size, kind="float")
        if self.source.known_mask(offset, size) == b"\xff" * size:
            try:
                result.value = field.type.read(BytesIO(self.source.data[offset : offset + size]))
                result._exact = True
            except Exception:
                result._exact = False
        if not result._exact:
            result.suggestions = [
                Suggestion(
                    f"Collect bytes {offset}..{offset + size - 1} to resolve float {field_path!r}.",
                    field=field_path,
                    bits=tuple(range(offset * 8, (offset + size) * 8)),
                    bytes=tuple(range(offset, offset + size)),
                )
            ]
        return result

    def _parse_bytes_field(self, field: Field, offset: int, size: int, path: str) -> PartialField:
        field_path = f"{path}.{field._name}" if path and field.name is not None else (path or field._name)
        result = PartialField(field._name, field.type, path=field_path, offset=offset, size=size, kind="bytes")
        masks = self.source.known_mask(offset, size)
        result._exact = masks == b"\xff" * size
        if result._exact:
            try:
                result.value = self.source.data[offset : offset + size]
            except Exception:
                result._exact = False
        if not result._exact:
            result._raw_known = masks
            result.suggestions = [
                Suggestion(
                    f"Collect bytes {offset}..{offset + max(0, size - 1)} to resolve {field_path!r}.",
                    field=field_path,
                    bits=tuple(
                        (offset + index) * 8 + bit
                        for index, mask in enumerate(masks)
                        for bit in range(8)
                        if not (mask >> bit) & 1
                    ),
                    bytes=tuple(offset + index for index, mask in enumerate(masks) if mask != 0xFF),
                )
            ]
        return result

    def _parse_wchar_field(self, field: Field, offset: int, size: int, path: str) -> PartialField:
        field_path = f"{path}.{field._name}" if path and field.name is not None else (path or field._name)
        result = PartialField(field._name, field.type, path=field_path, offset=offset, size=size, kind="wchar")
        if self.source.known_mask(offset, size) == b"\xff" * size:
            try:
                result.value = field.type.read(BytesIO(self.source.data[offset : offset + size]))
                result._exact = True
            except Exception:
                result._exact = False
        if not result._exact:
            result.suggestions = [
                Suggestion(
                    f"Collect bytes {offset}..{offset + max(0, size - 1)} to resolve {field_path!r}.",
                    field=field_path,
                    bits=tuple(range(offset * 8, (offset + size) * 8)),
                    bytes=tuple(range(offset, offset + size)),
                )
            ]
        return result

    def _field_from_symbolic(
        self,
        field: Field,
        symbolic: SymbolicInt,
        path: str,
        offset: int,
        size: int,
        *,
        bits: int | None = None,
    ) -> PartialField:
        field_path = f"{path}.{field._name}" if path and field.name is not None else (path or field._name)
        type_ = field.type
        kind = "int"
        if isinstance(type_, EnumMetaType):
            kind = "flag" if issubclass(type_, Flag) else "enum"
        elif bits is not None:
            kind = "bitfield"

        result = PartialField(
            field._name,
            type_,
            path=field_path,
            offset=offset,
            size=size,
            bits=bits,
            kind=kind,
        )
        result.symbolic = symbolic

        if symbolic.exact:
            try:
                result.value = type_(int(symbolic))
                result._exact = True
            except Exception:
                result.value = int(symbolic)
                result._exact = True

        if isinstance(type_, EnumMetaType):
            result.branches = self._enum_branches(type_, symbolic, field_path)

        self._add_integer_suggestions(result, symbolic, field_path)
        return result

    def _enum_branches(
        self, type_: type[Enum] | type[Flag], symbolic: SymbolicInt, field_path: str
    ) -> list[Branch]:
        rows = []
        values = {name: int(member.value) for name, member in type_.__members__.items()}

        is_flag = issubclass(type_, Flag)
        for name, value in values.items():
            if is_flag:
                possible = (value & symbolic.known_mask) == (symbolic.value & value)
            else:
                possible = symbolic.could_equal(value)
            reason = None
            suggestions = []

            if possible:
                # Bits in this member that are still unknown must be collected to
                # confirm the member. Bits that are already known to match are
                # not interesting for this branch.
                differing_unknown = (value ^ symbolic.value) & symbolic.unknown_mask
                if differing_unknown:
                    bits = tuple(
                        symbolic.source_bits[bit]
                        for bit in range(symbolic.width)
                        if (differing_unknown >> bit) & 1 and symbolic.source_bits is not None
                    )
                    if not bits:
                        # A bit field can itself be extracted from a larger group;
                        # the source mapping is still available in that case.
                        bits = tuple(
                            symbolic.source_bits[bit]
                            for bit in range(symbolic.width)
                            if (differing_unknown >> bit) & 1 and symbolic.source_bits is not None
                        )
                    if bits:
                        suggestions.append(
                            Suggestion(
                                f"Collect bit(s) {_format_bits(bits)} to confirm or exclude "
                                f"{field_path} == {name} (0x{value:x}).",
                                field=field_path,
                                bits=bits,
                                bytes=tuple(sorted({bit // 8 for bit in bits})),
                            )
                        )
            else:
                reason = (
                    _flag_exclusion_reason(name, value, symbolic)
                    if is_flag
                    else _branch_exclusion_reason(name, value, symbolic)
                )

            rows.append(
                Branch(
                    name=name,
                    value=value,
                    possible=possible,
                    reason=reason,
                    suggestions=suggestions,
                )
            )

        if not issubclass(type_, Flag) and self._has_unlisted_enum_value(values, symbolic):
            rows.append(
                Branch(
                    name="<unknown>",
                    value=None,
                    possible=True,
                    reason=None,
                )
            )

        if is_flag and symbolic.unknown_mask:
            covered = 0
            for value in values.values():
                covered |= value
            if symbolic.unknown_mask & ~covered:
                rows.append(Branch(name="<unknown-bits>", value=None, possible=True))

        return rows

    def _has_unlisted_enum_value(self, values: Mapping[str, int], symbolic: SymbolicInt) -> bool:
        known_values = set(values.values())
        if symbolic.possible_count <= self.enum_limit:
            return any(value not in known_values for value in symbolic.values(self.enum_limit))

        if symbolic.exact:
            return int(symbolic) not in known_values

        # With too many possibilities to enumerate, only claim an unlisted branch
        # exists when the known bits alone already cover all defined members or
        # when there are unknown bits outside the union of their known bits.
        union_mask = 0
        for value in known_values:
            union_mask |= value ^ symbolic.value
        return bool(symbolic.unknown_mask & ~union_mask) or bool(symbolic.unknown_mask)

    def _add_integer_suggestions(
        self, result: PartialField, symbolic: SymbolicInt, field_path: str
    ) -> None:
        if symbolic.exact:
            return

        bits = symbolic.unknown_bit_positions
        if bits:
            result.suggestions.append(
                Suggestion(
                    f"Collect bit(s) {_format_bits(bits)} "
                    f"(byte(s) {_format_bytes(tuple(sorted({bit // 8 for bit in bits})))}) "
                    f"to narrow {field_path!r} from 0x{symbolic.min:x}..0x{symbolic.max:x}.",
                    field=field_path,
                    bits=bits,
                    bytes=tuple(sorted({bit // 8 for bit in bits})),
                )
            )

        if result.branches:
            possible = [branch.name for branch in result.branches if branch.possible and branch.name != "<unknown>"]
            if len(possible) > 1:
                result.suggestions.append(
                    Suggestion(
                        f"Collect the unknown bits of {field_path!r} to distinguish "
                        f"between {', '.join(possible)}.",
                        field=field_path,
                        bits=bits,
                        bytes=tuple(sorted({bit // 8 for bit in bits})),
                        kind="distinguish",
                    )
                )

    def _aggregate_suggestions(self, result: PartialResult) -> list[Suggestion]:
        suggestions: list[Suggestion] = []
        seen = set()
        for field in result.flat_fields.values():
            for suggestion in field.suggestions:
                if suggestion.message not in seen:
                    seen.add(suggestion.message)
                    suggestions.append(suggestion)
            for branch in field.branches:
                for suggestion in branch.suggestions:
                    if suggestion.message not in seen:
                        seen.add(suggestion.message)
                        suggestions.append(suggestion)
        return suggestions


def _pseudo_field(type_: type[BaseType], name: str | None) -> Field:
    from dissect.cstruct.types.structure import Field

    return Field(name, type_)


def _format_bits(bits: Sequence[int]) -> str:
    if not bits:
        return ""
    ranges = []
    start = previous = bits[0]
    for bit in bits[1:]:
        if bit == previous + 1:
            previous = bit
            continue
        ranges.append(f"{start}" if start == previous else f"{start}-{previous}")
        start = previous = bit
    ranges.append(f"{start}" if start == previous else f"{start}-{previous}")
    return ", ".join(ranges)


def _format_bytes(offsets: Sequence[int]) -> str:
    if not offsets:
        return ""
    ranges = []
    start = previous = offsets[0]
    for offset in offsets[1:]:
        if offset == previous + 1:
            previous = offset
            continue
        ranges.append(f"{start}" if start == previous else f"{start}..{previous}")
        start = previous = offset
    ranges.append(f"{start}" if start == previous else f"{start}..{previous}")
    return ", ".join(ranges)


def _flag_exclusion_reason(name: str, value: int, symbolic: SymbolicInt) -> str:
    mismatch = value & symbolic.known_mask & ~symbolic.value
    details = []
    for bit in range(symbolic.width):
        if not (mismatch >> bit) & 1:
            continue
        absolute = symbolic.source_bits[bit] if symbolic.source_bits else None
        location = (
            f"absolute bit {absolute} (byte {absolute // 8}, bit {absolute % 8})"
            if absolute is not None
            else f"bit {bit}"
        )
        details.append(f"{location} is 0 in the collected bytes, but {name} (0x{value:x}) requires 1")
    if details:
        return "Excluded by known bits: " + "; ".join(details)
    return f"Excluded: {name} (0x{value:x}) does not match the known bits"


def _branch_exclusion_reason(name: str, value: int, symbolic: SymbolicInt) -> str:
    mismatch = (value ^ symbolic.value) & symbolic.known_mask
    details = []
    for bit in range(symbolic.width):
        if not (mismatch >> bit) & 1:
            continue
        required = (value >> bit) & 1
        observed = (symbolic.value >> bit) & 1
        absolute = symbolic.source_bits[bit] if symbolic.source_bits else None
        location = (
            f"absolute bit {absolute} (byte {absolute // 8}, bit {absolute % 8})"
            if absolute is not None
            else f"bit {bit}"
        )
        details.append(f"{location} is {observed} in the collected bytes, but {name} (0x{value:x}) requires {required}")

    if details:
        return "Excluded by known bits: " + "; ".join(details)
    return f"Excluded: {name} (0x{value:x}) does not match the known bits"


def _merge_states(states: list[_WalkState]) -> list[PartialField]:
    if len(states) == 1:
        return states[0].results

    merged: dict[str, PartialField] = {}
    order: list[str] = []
    for state in states:
        for field in state.results:
            if field.name not in merged:
                merged[field.name] = field
                order.append(field.name)
            else:
                merged[field.name] = _merge_field(merged[field.name], field)
    return [merged[name] for name in order]


def _merge_field(left: PartialField, right: PartialField) -> PartialField:
    if left is right or left == right:
        return left

    result = PartialField(left.name, left.type, path=left.path, offset=left.offset, size=left.size, kind=left.kind)
    result.variants = [*(left.variants or [left]), *(right.variants or [right])]
    result.symbolic = left.symbolic
    result.value = left.value if left.exact and left.value == right.value else None
    result._exact = left.exact and right.exact and left.value == right.value
    result.children = left.children or right.children
    result.elements = left.elements or right.elements
    result.branches = left.branches or right.branches
    result.suggestions = left.suggestions or right.suggestions
    result.condition = left.condition or right.condition
    result.condition_state = left.condition_state or right.condition_state
    if result.condition is not None and len(result.variants) > 1:
        result.condition_state = "open"
    result.conditions = left.conditions or right.conditions
    return result


def _resolve_unknown_fields(
    type_: type[Structure],
    source: PartialBytes,
    unknown_fields: Iterable[str],
) -> None:
    spans = _field_spans(type_)
    for name in unknown_fields:
        if name not in spans:
            matches = [key for key in spans if key.endswith(f".{name}")]
            if len(matches) != 1:
                raise PartialError(f"Unknown field {name!r} for {type_.__name__}")
            name = matches[0]
        for offset, size in spans[name]:
            for index in range(offset, offset + size):
                source._mark_byte_unknown(index)


def _field_spans(type_: type[Structure], *, base: int = 0) -> dict[str, list[tuple[int, int]]]:
    result: dict[str, list[tuple[int, int]]] = {}
    cursor = base
    bit_offset: int | None = None
    bit_type = None
    bit_remaining = 0

    for field in type_.__fields__:
        field_type = field.type.__type__ if isinstance(field.type, EnumMetaType) else field.type
        size = field_type.__size__
        if size is None:
            continue

        if field.bits:
            if bit_offset is not None and bit_remaining > 0 and bit_type is field_type:
                offset = bit_offset
            else:
                offset = base + field.offset if field.offset is not None else cursor
                bit_offset = offset
                bit_type = field_type
                bit_remaining = size * 8
                cursor = offset + size
            bit_remaining -= field.bits or 0
        else:
            bit_offset = None
            bit_type = None
            bit_remaining = 0
            if field.offset is None:
                continue
            offset = base + field.offset
            cursor = offset + size

        result[field._name] = [(offset, size)]
        if issubclass(field.type, Structure):
            for name, spans in _field_spans(field.type, base=offset).items():
                result[f"{field._name}.{name}"] = spans

    return result


def read_partial(
    type_: type[BaseType] | str,
    data: bytes | bytearray | memoryview | PartialBytes | BinaryIO,
    unknown: Any = None,
    *,
    unknown_bits: Any = None,
    unknown_bytes: Any = None,
    unknown_fields: Iterable[str] | None = None,
    known: Any = None,
    known_bits: Any = None,
    endian: AllowedEndianness | None = None,
    cs: cstruct | None = None,
    variant_limit: int = _DEFAULT_VARIANT_LIMIT,
    context_limit: int = _DEFAULT_CONTEXT_LIMIT,
    enum_limit: int = _DEFAULT_ENUM_LIMIT,
    **kwargs: Any,
) -> PartialResult:
    """Evaluate a structure against partially known input.

    Args:
        type_: A structure type, or the name of one in ``cs``.
        data: The collected bytes, a :class:`PartialBytes`, or a file-like object.
        unknown: Unknown byte offsets, a per-byte mask, a bit mask, a mapping of
            byte offsets to bit masks, or an iterable of field names.
        unknown_bits: Absolute bit positions that are unknown.
        unknown_bytes: Byte offsets that are completely unknown.
        unknown_fields: Field names that are completely unknown.
        known: The inverse of ``unknown``: a known-bit or known-byte mask.
        endian: Endianness to use. Defaults to the cstruct instance's endianness.
        cs: The cstruct instance to resolve type names and expressions against.
        variant_limit: Maximum number of conditional layout variants to explore.
        context_limit: Maximum number of concrete field values to use when
            evaluating conditional length expressions.
        enum_limit: Maximum number of values to enumerate for enum analysis.

    Returns:
        A :class:`PartialResult`.
    """
    if (value := kwargs.pop("unknown_mask", None)) is not None:
        unknown = value
    if (value := kwargs.pop("unknown_bitmask", None)) is not None:
        unknown_bits = value
    if (value := kwargs.pop("unknown_bit_positions", None)) is not None:
        unknown_bits = value
    if (value := kwargs.pop("known_mask", None)) is not None:
        known = value
    if (value := kwargs.pop("missing_bytes", None)) is not None:
        unknown_bytes = value
    if kwargs:
        unexpected = next(iter(kwargs))
        raise TypeError(f"read_partial() got an unexpected keyword argument {unexpected!r}")

    if isinstance(type_, str):
        if cs is None:
            raise PartialError("A cstruct instance is required to resolve a type name")
        type_ = cs.resolve(type_)

    cs = cs or type_.__cs__
    endian = normalize_endianness(endian) if endian is not None else cs.endian

    if isinstance(data, PartialBytes):
        source = data
    else:
        if hasattr(data, "read"):
            data = data.read()
        source = PartialBytes(data)

    if known is not None:
        source.known = bytearray(len(source.data))
        source._apply_known(known)
    if known_bits is not None:
        if isinstance(known_bits, int):
            source.known = bytearray(len(source.data))
            source._apply_known(known_bits)
        elif isinstance(known_bits, (bytes, bytearray, memoryview)):
            source.known = bytearray(len(source.data))
            source._apply_known(int.from_bytes(known_bits, "little"))
        else:
            known_bits = list(known_bits)
            if not any(value is not None for value in (unknown, unknown_bits, unknown_bytes)):
                source.known = bytearray(len(source.data))
            for bit in known_bits:
                if isinstance(bit, int):
                    source._mark_bit_known(bit)
                else:
                    raise PartialError(f"Unsupported known bit specification: {bit!r}")

    unknown_fields = list(unknown_fields or [])
    if isinstance(unknown, str):
        unknown_fields.append(unknown)
        unknown = None
    elif isinstance(unknown, Mapping) and any(isinstance(key, str) for key in unknown):
        field_unknown = {key: value for key, value in unknown.items() if isinstance(key, str)}
        if field_unknown:
            unknown_fields.extend(key for key, value in field_unknown.items() if value)
            unknown = {key: value for key, value in unknown.items() if not isinstance(key, str)}
    elif isinstance(unknown, Iterable) and not isinstance(unknown, (bytes, bytearray, memoryview, int, slice)):
        items = list(unknown)
        if any(isinstance(item, str) for item in items):
            unknown_fields.extend(item for item in items if isinstance(item, str))
            remaining = [item for item in items if not isinstance(item, str)]
            unknown = remaining or None

    if unknown is not None:
        temp = PartialBytes(b"")
        temp.data = source.data
        temp.known = bytearray(source.known)
        temp._apply_unknown(unknown)
        source.known = temp.known
    if unknown_bits is not None:
        source._apply_bits(unknown_bits)
    if unknown_bytes is not None:
        source._apply_bytes(unknown_bytes)
    if unknown_fields:
        _resolve_unknown_fields(type_, source, unknown_fields)

    parser = _PartialParser(
        cs,
        source,
        endian=endian,
        variant_limit=variant_limit,
        context_limit=context_limit,
        enum_limit=enum_limit,
    )
    return parser.parse(type_)


partial_read = read_partial
parse_partial = read_partial
Partial = read_partial
PartialRead = read_partial
evaluate_partial = read_partial
partial_eval = read_partial
analyze_partial = read_partial
partial = read_partial

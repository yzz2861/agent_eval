"""Built-in, caller-declarable structural invariants.

An invariant never treats a truncated read as a satisfied check: every
invariant returns one of satisfied / violated / undecidable, and undecidable
keeps the candidate pending instead of guessing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from dissect.cstruct.discriminator.exceptions import TruncatedRead

if TYPE_CHECKING:
    from collections.abc import Callable
from dissect.cstruct.discriminator.model import InvariantOutcome


def sum16(data: bytes) -> int:
    """Default checksum: 16-bit wrapping byte sum."""
    return sum(data) & 0xFFFF


@dataclass(frozen=True, slots=True)
class RecordLengthEquals:
    """The record must actually contain as many bytes as a size field declares.

    When ``constant`` is set the declared size must also equal it (fixed header
    layouts). A window shorter than the declared size is undecidable, never a
    violation: the remaining bytes may still arrive.
    """

    size_field: str
    constant: int | None = None
    name: str = "record_length"

    def describe(self) -> str:
        if self.constant is None:
            return f"record length == field {self.size_field!r}"
        return f"record length == field {self.size_field!r} == {self.constant}"

    def check(self, ctx: object) -> InvariantOutcome:
        declared = ctx.value(self.size_field)
        if not isinstance(declared, int):
            return InvariantOutcome.violation(f"{self.size_field} is not an integer: {declared!r}")
        if declared < 0:
            return InvariantOutcome.violation(f"declared record length {declared} is negative")
        if declared == 0:
            return InvariantOutcome.satisfied("record declares a zero-length body")
        if self.constant is not None and declared != self.constant:
            return InvariantOutcome.violation(f"declared length {declared} != fixed record size {self.constant}")
        try:
            ctx.bytes_for(declared - 1, 1)
        except TruncatedRead:
            return InvariantOutcome.undecidable(f"declared length {declared} exceeds the readable window")
        return InvariantOutcome.satisfied(f"record spans the declared {declared} byte(s)")

    def evidence_spans(self, ctx: object | None) -> tuple[tuple[int, int], ...]:
        if ctx is None:
            return ()
        try:
            declared = ctx.value(self.size_field)
        except TruncatedRead:
            return ()
        if isinstance(declared, int) and declared > 0:
            return ((declared - 1, declared),)
        return ()


@dataclass(frozen=True, slots=True)
class PayloadChecksum:
    """A checksum field must equal ``algorithm(payload[start:end])``.

    Range endpoints are absolute offsets, or field names whose parsed integer
    value is used as the endpoint (optionally offset by ``*_base``). Any
    unreadable endpoint or payload byte makes the check undecidable.
    """

    checksum_field: str
    start: int | str
    end: int | str
    start_base: int = 0
    end_base: int = 0
    algorithm: Callable[[bytes], int] = sum16
    name: str = "payload_checksum"

    def describe(self) -> str:
        return f"{self.checksum_field!r} == {self.algorithm.__name__}(payload[{self.start!r}..{self.end!r}])"

    def check(self, ctx: object) -> InvariantOutcome:
        checksum = ctx.value(self.checksum_field)
        if not isinstance(checksum, int):
            return InvariantOutcome.violation(f"{self.checksum_field} is not an integer: {checksum!r}")
        start = self._resolve(ctx, self.start, self.start_base)
        end = self._resolve(ctx, self.end, self.end_base)
        if start is None or end is None:
            return InvariantOutcome.undecidable("payload bounds are not fully readable")
        if end < start:
            return InvariantOutcome.violation(f"payload range [{start}, {end}) is inverted")
        try:
            payload = ctx.bytes_for(start, end - start)
        except TruncatedRead:
            return InvariantOutcome.undecidable(f"payload bytes [{start}, {end}) are incomplete")
        actual = self.algorithm(payload)
        if actual != checksum:
            return InvariantOutcome.violation(
                f"checksum {checksum:#x} != {self.algorithm.__name__}(payload) = {actual:#x}"
            )
        return InvariantOutcome.satisfied(f"checksum {checksum:#x} matches payload")

    def evidence_spans(self, ctx: object | None) -> tuple[tuple[int, int], ...]:
        if ctx is None:
            return ()
        try:
            start = self._resolve(ctx, self.start, self.start_base)
            end = self._resolve(ctx, self.end, self.end_base)
        except TruncatedRead:
            return ()
        if start is None or end is None or end < start:
            return ()
        return ((start, end),)

    @staticmethod
    def _resolve(ctx: object, endpoint: int | str, base: int) -> int | None:
        if isinstance(endpoint, int):
            return base + endpoint
        try:
            value = ctx.value(endpoint)
        except TruncatedRead:
            return None
        if not isinstance(value, int):
            return None
        return base + value

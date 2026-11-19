from __future__ import annotations


class DiscriminatorError(Exception):
    """Base class for multi-schema discriminator errors."""


class TruncatedRead(DiscriminatorError):
    """Raised when a required byte range is absent from the readable window.

    This is deliberately distinct from a zero byte: callers must be able to
    tell "missing evidence" apart from "evidence says no".
    """

    def __init__(self, offset: int, size: int, available: int) -> None:
        self.offset = offset
        self.size = size
        self.available = available
        super().__init__(f"need {size} byte(s) at offset {offset}, window only has {available}")


class SchemaDefinitionError(DiscriminatorError):
    """Raised when a candidate schema is declared inconsistently."""

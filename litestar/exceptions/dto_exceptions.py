from __future__ import annotations

from litestar.exceptions import LitestarException

__all__ = ("DTOFactoryException", "InvalidAnnotationException", "UnloadedFieldException")


class DTOFactoryException(LitestarException):
    """Base DTO exception type."""


class InvalidAnnotationException(DTOFactoryException):
    """Unexpected DTO type argument."""


class UnloadedFieldException(DTOFactoryException):
    """A field that has not been loaded on the source object was encountered during serialization."""

    def __init__(self, field_path: str) -> None:
        """Initialize the exception.

        Args:
            field_path: Dot-separated path of the unloaded field, relative to the
                root object being serialized (e.g. ``"author.name"``).
        """
        self.field_path = field_path
        super().__init__(
            f"Cannot serialize field '{field_path}': it has not been loaded on the source object. "
            "Load the field before serialization, or set 'unloaded_fields_strategy' to 'omit'."
        )

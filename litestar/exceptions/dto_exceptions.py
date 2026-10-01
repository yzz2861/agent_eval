from __future__ import annotations

from litestar.exceptions import LitestarException

__all__ = ("DTOFactoryException", "InvalidAnnotationException", "UnloadedFieldException")


class DTOFactoryException(LitestarException):
    """Base DTO exception type."""


class InvalidAnnotationException(DTOFactoryException):
    """Unexpected DTO type argument."""


class UnloadedFieldException(DTOFactoryException):
    """A field that has not been loaded was encountered during DTO serialization."""

    def __init__(self, field_path: str) -> None:
        """Initialize ``UnloadedFieldException``.

        Args:
            field_path: Dotted path of the field that has not been loaded, e.g. ``"user.address"``.
        """
        self.field_path = field_path
        super().__init__(
            f"Field '{field_path}' has not been loaded and the DTO's 'unloaded_fields_strategy' is set to 'raise'"
        )

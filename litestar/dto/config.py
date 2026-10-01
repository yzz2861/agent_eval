from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from litestar.exceptions import ImproperlyConfiguredException

if TYPE_CHECKING:
    from litestar.dto.types import RenameStrategy, UnloadedFieldsStrategy

__all__ = ("DTOConfig",)


@dataclass(frozen=True)
class DTOConfig:
    """Control the generated DTO."""

    exclude: set[str] = field(default_factory=set)
    """Explicitly exclude fields from the generated DTO.

    If exclude is specified, all fields not specified in exclude will be included by default.

    Notes:
        - The field names are dot-separated paths to nested fields, e.g. ``"address.street"`` will
            exclude the ``"street"`` field from a nested ``"address"`` model.
        - 'exclude' mutually exclusive with 'include' - specifying both values will raise an
            ``ImproperlyConfiguredException``.
    """
    include: set[str] = field(default_factory=set)
    """Explicitly include fields in the generated DTO.

    If include is specified, all fields not specified in include will be excluded by default.

    Notes:
        - The field names are dot-separated paths to nested fields, e.g. ``"address.street"`` will
            include the ``"street"`` field from a nested ``"address"`` model.
        - 'include' mutually exclusive with 'exclude' - specifying both values will raise an
            ``ImproperlyConfiguredException``.
    """
    rename_fields: dict[str, str] = field(default_factory=dict)
    """Mapping of field names, to new name."""
    rename_strategy: RenameStrategy | None = None
    """Rename all fields using a pre-defined strategy or a custom strategy.

    The pre-defined strategies are: `upper`, `lower`, `camel`, `pascal`.

    A custom strategy is any callable that accepts a string as an argument and
    return a string.

    Fields defined in ``rename_fields`` are ignored."""
    max_nested_depth: int = 1
    """The maximum depth of nested items allowed for data transfer."""
    partial: bool = False
    """Allow transfer of partial data."""
    underscore_fields_private: bool = True
    """Fields starting with an underscore are considered private and excluded from data transfer."""
    experimental_codegen_backend: bool | None = None
    """Use the experimental codegen backend"""
    forbid_unknown_fields: bool = False
    """Raise an exception for fields present in the raw data that are not defined on the model"""
    unloaded_fields_strategy: UnloadedFieldsStrategy | None = None
    """Control how fields that have not been loaded on the source object are handled during
    serialization.

    This only applies when encoding data, i.e. for return DTOs, and only has an effect if the
    DTO's :meth:`AbstractDTO.is_field_loaded <litestar.dto.AbstractDTO.is_field_loaded>` hook is
    able to detect unloaded fields for the model type, e.g. lazy-loaded SQLAlchemy attributes.

    - ``None`` (default): Unloaded fields are not treated specially. Accessing them may trigger
        lazy loading, e.g. a SQL query.
    - ``"omit"``: Unloaded fields are omitted from the serialized output.
    - ``"raise"``: A :class:`UnloadedFieldException <litestar.exceptions.dto_exceptions.UnloadedFieldException>`
        including the dotted path of the field is raised.
    """

    def __post_init__(self) -> None:
        if self.include and self.exclude:
            raise ImproperlyConfiguredException(
                "'include' and 'exclude' are mutually exclusive options, please use one of them"
            )

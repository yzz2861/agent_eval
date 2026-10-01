from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from litestar.exceptions import ImproperlyConfiguredException

if TYPE_CHECKING:
    from litestar.dto.types import RenameStrategy

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
    unloaded_fields_strategy: Literal["omit", "raise"] | None = None
    """Strategy to apply when a field of the source object has not been loaded.

    When set, the DTO asks its adapter (see
    :meth:`AbstractDTO.get_unloaded_fields <litestar.dto.AbstractDTO.get_unloaded_fields>`)
    whether a field has been loaded on the source object *before* reading it, ensuring
    that serialization never triggers I/O - such as a SQL query - as a side effect.

    The following strategies are supported:

    - ``"omit"``: Unloaded fields are omitted from the serialized output.
    - ``"raise"``: An :class:`UnloadedFieldException <litestar.exceptions.UnloadedFieldException>`
      is raised, carrying the dot-separated path of the unloaded field.

    Fields that have been loaded with a value of ``None`` are not considered unloaded.

    Notes:
        - The strategy only applies when serializing model instances (i.e. on the
          response path), not when parsing incoming data.
        - SQLAlchemy ORM instances are supported out of the box. Other object types
          can be supported by registering a checker with
          :func:`register_unloaded_fields_checker <litestar.dto.register_unloaded_fields_checker>`
          or by overriding ``AbstractDTO.get_unloaded_fields`` on the DTO adapter.
    """

    def __post_init__(self) -> None:
        if self.include and self.exclude:
            raise ImproperlyConfiguredException(
                "'include' and 'exclude' are mutually exclusive options, please use one of them"
            )
        if self.unloaded_fields_strategy not in (None, "omit", "raise"):
            raise ImproperlyConfiguredException(
                "'unloaded_fields_strategy' must be one of 'omit', 'raise' or None, "
                f"got '{self.unloaded_fields_strategy}'"
            )

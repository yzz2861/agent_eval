from __future__ import annotations

from threading import local
from typing import Any, Callable, Union

from attrs import frozen

#: A single segment of a path: a string mapping key or an integer sequence index.
PathSegment = Union[str, int]


@frozen
class AttributeOverride:
    omit_if_default: bool | None = None
    rename: str | None = None
    omit: bool | None = None  # Omit the field completely.
    struct_hook: Callable[[Any, Any], Any] | None = None  # Structure hook to use.
    unstruct_hook: Callable[[Any], Any] | None = None  # Structure hook to use.
    path: tuple[PathSegment, ...] | None = None  # Path to map the field to.


neutral = AttributeOverride()
already_generating = local()

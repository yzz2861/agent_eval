"""Type aliases.

.. warning::

    This module is provisional. Types may be modified, added, and removed between minor releases.
"""

from __future__ import annotations

import typing
from types import EllipsisType

T = typing.TypeVar("T")

#: A type that can be either a sequence of strings or a set of strings
StrSequenceOrSet: typing.TypeAlias = typing.Sequence[str] | typing.AbstractSet[str]

#: A structured mask for partial deserialization.
#:
#: Keys are schema field names (attribute names, not ``data_key`` values),
#: collection indices (``int``), or the wildcard index ``...`` (Ellipsis),
#: which applies to every element of a collection. Values are either ``True``
#: (the field may be missing) or another mask for a nested structure.
PartialMask: typing.TypeAlias = dict[
    str | int | EllipsisType, "typing.Literal[True] | PartialMask"
]

#: Type for validator functions
Validator: typing.TypeAlias = typing.Callable[[typing.Any], typing.Any]

#: Type for a single error message value, which can be a string, list, or dict
ErrorMessageValue: typing.TypeAlias = str | list | dict

#: Type for error_messages dictionaries passed to fields
ErrorMessages: typing.TypeAlias = dict[str, ErrorMessageValue]

#: A valid option for the ``unknown`` schema option and argument
UnknownOption: typing.TypeAlias = typing.Literal["exclude", "include", "raise"]

#: Type for field-level pre-load functions
PreLoadCallable = typing.Callable[[typing.Any], typing.Any]
#: Type for field-level post-load functions
PostLoadCallable = typing.Callable[[T], T]


class SchemaValidator(typing.Protocol):
    def __call__(
        self,
        output: typing.Any,
        original_data: typing.Any = ...,
        *,
        partial: bool | StrSequenceOrSet | PartialMask | None = None,
        unknown: UnknownOption | None = None,
        many: bool = False,
    ) -> None: ...


class RenderModule(typing.Protocol):
    def dumps(
        self, obj: typing.Any, *args: typing.Any, **kwargs: typing.Any
    ) -> str: ...

    def loads(
        self, s: str | bytes | bytearray, *args: typing.Any, **kwargs: typing.Any
    ) -> typing.Any: ...

"""Type aliases.

.. warning::

    This module is provisional. Types may be modified, added, and removed between minor releases.
"""

from __future__ import annotations

import typing

T = typing.TypeVar("T")

#: A type that can be either a sequence of strings or a set of strings
StrSequenceOrSet: typing.TypeAlias = typing.Sequence[str] | typing.AbstractSet[str]

#: A structured partial mask. Maps schema field names to `True` (the field may
#: be missing) or to a nested mask. Within a mask applied to a collection
#: (``many=True``), keys may also be integer indices or the ``"*"`` wildcard,
#: mapping to the mask for the corresponding elements.
PartialMask: typing.TypeAlias = typing.Mapping[str | int, "bool | PartialMask"]

#: Valid options for the ``partial`` argument
PartialOption: typing.TypeAlias = bool | StrSequenceOrSet | PartialMask | None

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
        partial: PartialOption = None,
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

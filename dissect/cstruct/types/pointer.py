from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING, Any, BinaryIO, Generic, TypeVar

from dissect.cstruct.exception import NullPointerDereference
from dissect.cstruct.trace import NodeKind, current_tracer
from dissect.cstruct.types.base import BaseType, normalize_endianness
from dissect.cstruct.types.char import Char
from dissect.cstruct.types.void import Void

if TYPE_CHECKING:
    from collections.abc import Callable

    from typing_extensions import Self

    from dissect.cstruct.cstruct import AllowedEndianness, Endianness

T = TypeVar("T", bound=BaseType)


class Pointer(int, BaseType, Generic[T]):
    """Pointer to some other type."""

    __type__: type[T]
    __stream: BinaryIO | None
    __context: dict[str, Any] | None
    __endian: Endianness

    def __new__(
        cls, value: int, stream: BinaryIO | None, *, context: dict[str, Any] | None = None, endian: Endianness
    ) -> Self:
        obj = super().__new__(cls, value)
        obj.__stream = stream
        obj.__context = context
        obj.__endian = endian
        object.__setattr__(obj, "_trace_node", None)
        object.__setattr__(obj, "_trace_deref_node", None)
        obj.dereference = cache(obj.dereference)
        return obj

    def __repr__(self) -> str:
        return f"<{self.__type__.__name__}* @ {self:#x}>"

    def __str__(self) -> str:
        return str(self.dereference())

    def __getattr__(self, attr: str) -> Any:
        if attr.startswith("_trace_"):
            raise AttributeError(attr)
        return getattr(self.dereference(), attr)

    @staticmethod
    def __op(op: Callable[[int, int], int]) -> Callable[[Self, int], Self]:
        def method(self: Self, other: int) -> Self:
            result = type.__call__(
                self.__class__,
                op(self, other),
                self.__stream,
                context=self.__context,
                endian=self.__endian,
            )
            object.__setattr__(result, "_trace_node", getattr(self, "_trace_node", None))
            return result

        return method

    __add__ = __op(int.__add__)
    __sub__ = __op(int.__sub__)
    __mul__ = __op(int.__mul__)
    __floordiv__ = __op(int.__floordiv__)
    __mod__ = __op(int.__mod__)
    __pow__ = __op(int.__pow__)
    __lshift__ = __op(int.__lshift__)
    __rshift__ = __op(int.__rshift__)
    __and__ = __op(int.__and__)
    __xor__ = __op(int.__xor__)
    __or__ = __op(int.__or__)

    @classmethod
    def __default__(cls) -> Self:
        return cls.__new__(
            cls,
            cls.__cs__.pointer.__default__(),
            None,
            context=None,
            endian=cls.__cs__.endian,
        )

    @classmethod
    def _read(cls, stream: BinaryIO, *, context: dict[str, Any] | None = None, endian: Endianness) -> Self:
        pointer = cls.__new__(
            cls,
            cls.__cs__.pointer._read(stream, context=context, endian=endian),
            stream,
            context=context,
            endian=endian,
        )
        tracer = current_tracer(stream)
        if tracer is not None:
            pointer._trace_node = tracer.current
        return pointer

    @classmethod
    def _write(cls, stream: BinaryIO, data: int, *, endian: Endianness) -> int:
        return cls.__cs__.pointer._write(stream, data, endian=endian)

    def dereference(self, *, endian: AllowedEndianness | None = None) -> T | None:
        """Dereference the pointer and read the value it points to.

        Args:
            endian: Optional endianness to use when reading the value.
                    If not provided, the endianness used when reading the pointer itself will be used.
        """
        if self == 0 or self.__stream is None:
            raise NullPointerDereference

        endian = normalize_endianness(endian) if endian is not None else self.__endian
        if issubclass(self.__type__, Void):
            return None

        tracer = current_tracer(self.__stream)
        position = self.__stream.tell()
        self.__stream.seek(self)

        if tracer is None:
            if issubclass(self.__type__, Char):
                # This makes the assumption that a char pointer is a null-terminated string
                value = self.__type__._read_0(self.__stream, context=self.__context, endian=endian)
            else:
                value = self.__type__._read(self.__stream, context=self.__context, endian=endian)
        else:
            parent = getattr(self, "_trace_node", None) or tracer.current
            node = tracer.begin_on(parent, "dereference", NodeKind.DEREFERENCE, self.__type__.__name__ + "*")
            try:
                node.target_address = int(self)
                if issubclass(self.__type__, Char):
                    value = self.__type__._read_0(self.__stream, context=self.__context, endian=endian)
                else:
                    value = self.__type__._read(self.__stream, context=self.__context, endian=endian)
                self._trace_deref_node = node
            finally:
                tracer.end()

        # Restore the stream position after reading the value
        self.__stream.seek(position)
        return value

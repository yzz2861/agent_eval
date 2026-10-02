from __future__ import annotations

from asyncio import BaseTransport
from typing import TYPE_CHECKING, Protocol


if TYPE_CHECKING:
    from sanic.http.constants import HTTP
    from sanic.models.asgi import ASGIScope


class HTMLProtocol(Protocol):
    def __html__(self) -> str | bytes: ...

    def _repr_html_(self) -> str | bytes: ...


class Range(Protocol):
    start: int
    end: int
    size: int
    total: int
    __slots__ = ()


class MultipartRange(Range, Protocol):
    boundary: str
    content_type: str
    media_type: str
    multipart: bool
    overhead: int
    ranges: tuple[tuple[int, int], ...]
    __slots__ = ()


class TransportProtocol(BaseTransport):
    scope: ASGIScope
    version: HTTP
    __slots__ = ()

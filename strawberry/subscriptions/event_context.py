from __future__ import annotations

import inspect
from collections.abc import (
    AsyncIterable,
    AsyncIterator,
    Awaitable,
    Iterator,
    Mapping,
)
from contextlib import AbstractAsyncContextManager, AbstractContextManager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from strawberry.types.info import Info


EventContextManager = AbstractContextManager[Any] | AbstractAsyncContextManager[Any]
EventContextManagerFactoryResult = EventContextManager | Awaitable[EventContextManager]


def get_event_context(
    factory: Any,
    *,
    event: Any,
    info: Info,
) -> EventContextManagerFactoryResult:
    try:
        parameters = inspect.signature(factory).parameters
    except (TypeError, ValueError):
        return factory(event, info=info)

    if len(parameters) >= 2:
        return factory(event, info=info)
    return factory(event)


def merge_event_context(connection_context: Any, event_context: Any) -> Any:
    if event_context is None:
        return connection_context
    if isinstance(connection_context, Mapping) and isinstance(event_context, Mapping):
        return LayeredMapping(event_context, connection_context)
    return event_context


class LayeredMapping(Mapping[Any, Any]):
    __slots__ = ("layers",)

    def __init__(self, *layers: Mapping[Any, Any]) -> None:
        self.layers = layers

    def __getitem__(self, key: Any) -> Any:
        for layer in self.layers:
            if key in layer:
                return layer[key]
        raise KeyError(key)

    def __iter__(self) -> Iterator[Any]:
        seen: set[Any] = set()
        for layer in self.layers:
            for key in layer:
                if key not in seen:
                    seen.add(key)
                    yield key

    def __len__(self) -> int:
        return len(set(self))


class EventContextAsyncIterable:
    def __init__(
        self,
        source: AsyncIterable[Any],
        *,
        factory: Any,
    ) -> None:
        self._source = source
        self.factory = factory
        self._info: Info | None = None

    def set_info(self, info: Info) -> None:
        self._info = info

    def __aiter__(self) -> EventContextAsyncIterator:
        return EventContextAsyncIterator(
            self._source.__aiter__(),
            factory=self.factory,
            info=self._info,
        )


class EventContextAsyncIterator:
    def __init__(
        self,
        iterator: AsyncIterator[Any],
        *,
        factory: Any,
        info: Info | None,
    ) -> None:
        self._iterator = iterator
        self.factory = factory
        self._info = info

    def __aiter__(self) -> EventContextAsyncIterator:
        return self

    async def __anext__(self) -> Any:
        event = await self._iterator.__anext__()
        assert self._info is not None
        return EventContextEvent(event=event, info=self._info, factory=self.factory)

    async def athrow(self, *args: Any, **kwargs: Any) -> Any:
        athrow = getattr(self._iterator, "athrow", None)
        if athrow is None:
            await self.aclose()
            raise TypeError("underlying async iterator does not support athrow")
        return await athrow(*args, **kwargs)

    async def aclose(self) -> None:
        aclose = getattr(self._iterator, "aclose", None)
        if aclose is not None:
            await aclose()


class EventContextEvent:
    __slots__ = ("event", "factory", "info")

    def __init__(self, *, event: Any, factory: Any, info: Info) -> None:
        self.event = event
        self.factory = factory
        self.info = info

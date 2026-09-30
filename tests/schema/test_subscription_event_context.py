from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncGenerator
from dataclasses import dataclass

import pytest

import strawberry
from strawberry.types.info import Info


@dataclass
class EventState:
    requests: list[int]
    entered: list[int]
    exited: list[tuple[int, str | None]]
    loaders: list[object]
    closed: bool = False

    @classmethod
    def create(cls) -> EventState:
        return cls(requests=[], entered=[], exited=[], loaders=[])


@dataclass
class SubscriptionEventPayload:
    value: int


@strawberry.type
class SubscriptionEvent:
    value: int

    @strawberry.field
    async def label(
        self,
        info: strawberry.Info,
    ) -> str:
        if info.context.get("raise_field_error"):
            raise ValueError("field failure")

        blocker = info.context.get("blocker")
        if blocker is not None:
            await blocker.wait()

        return (
            f"{self.value}:{info.context['event_id']}:{info.context['connection_id']}"
        )


def event_source(state: EventState) -> AsyncGenerator[SubscriptionEventPayload, None]:
    async def source() -> AsyncGenerator[SubscriptionEventPayload, None]:
        try:
            for value in (1, 2, 3):
                state.requests.append(value)
                yield SubscriptionEventPayload(value)
        finally:
            state.closed = True

    return source()


@contextlib.contextmanager
def sync_event_context(
    event: SubscriptionEventPayload,
    info: Info,
    *,
    state: EventState,
    first_enter: asyncio.Event | None = None,
) -> contextlib.AbstractContextManager[dict[str, object]]:
    assert info.context["connection_id"] == 100
    state.entered.append(event.value)
    loader = object()
    state.loaders.append(loader)
    if first_enter is not None:
        first_enter.set()
    try:
        yield {"event_id": event.value, "loader": loader}
    except GeneratorExit:
        state.exited.append((event.value, "GeneratorExit"))
        raise
    except Exception as exc:  # noqa: BLE001
        state.exited.append((event.value, type(exc).__name__))
    else:
        state.exited.append((event.value, None))


@contextlib.asynccontextmanager
async def async_event_context(
    event: SubscriptionEventPayload,
    info: Info,
    *,
    state: EventState,
    first_enter: asyncio.Event | None = None,
    enter_error: bool = False,
) -> AsyncGenerator[dict[str, object], None]:
    assert info.context["connection_id"] == 100
    state.entered.append(event.value)
    if enter_error and event.value == 2:
        raise RuntimeError("cannot enter event context")

    loader = object()
    state.loaders.append(loader)
    if first_enter is not None:
        first_enter.set()
    try:
        yield {"event_id": event.value, "loader": loader}
    except asyncio.CancelledError:
        state.exited.append((event.value, "CancelledError"))
        raise
    except GeneratorExit:
        state.exited.append((event.value, "GeneratorExit"))
        raise
    except Exception as exc:  # noqa: BLE001
        state.exited.append((event.value, type(exc).__name__))
    finally:
        if not state.exited or state.exited[-1][0] != event.value:
            state.exited.append((event.value, None))


def make_schema(
    *,
    context_getter,
    source: AsyncGenerator[SubscriptionEventPayload, None],
) -> strawberry.Schema:
    @strawberry.type
    class Query:
        ok: bool = True

    @strawberry.type
    class Subscription:
        @strawberry.subscription(event_context_getter=context_getter)
        async def events(self) -> AsyncGenerator[SubscriptionEvent, None]:
            return source

    return strawberry.Schema(query=Query, subscription=Subscription)


@pytest.mark.asyncio
@pytest.mark.parametrize("sync_context", [False, True])
async def test_event_context_is_isolated_and_keeps_connection_context(
    sync_context: bool,
) -> None:
    state = EventState.create()
    first_enter = asyncio.Event()

    if sync_context:

        def getter(event: SubscriptionEventPayload, info: Info):
            return sync_event_context(event, info, state=state)

    else:

        def getter(event: SubscriptionEventPayload, info: Info):
            return async_event_context(
                event,
                info,
                state=state,
                first_enter=first_enter,
            )

    schema = make_schema(
        context_getter=getter,
        source=event_source(state),
    )

    connection_context = {"connection_id": 100}
    stream = await schema.subscribe(
        "subscription { events { value label } }",
        context_value=connection_context,
    )

    first = await stream.__anext__()
    assert first.errors is None
    assert first.data == {"events": {"value": 1, "label": "1:1:100"}}
    assert connection_context == {"connection_id": 100}
    assert state.requests == [1]
    assert state.entered == [1]
    assert len(state.loaders) == 1
    results = [result async for result in stream]

    assert [result.data for result in results] == [
        {"events": {"value": 2, "label": "2:2:100"}},
        {"events": {"value": 3, "label": "3:3:100"}},
    ]
    assert state.requests == [1, 2, 3]
    assert state.entered == [1, 2, 3]
    assert state.exited == [(1, None), (2, None), (3, None)]
    assert len(set(state.loaders)) == 3
    assert state.closed


@pytest.mark.asyncio
async def test_slow_first_event_does_not_open_later_event_contexts() -> None:
    state = EventState.create()
    entered = asyncio.Event()
    release = asyncio.Event()

    def getter(event: SubscriptionEventPayload, info: Info):
        return async_event_context(
            event,
            info,
            state=state,
            first_enter=entered,
        )

    schema = make_schema(context_getter=getter, source=event_source(state))
    stream = await schema.subscribe(
        "subscription { events { value label } }",
        context_value={"connection_id": 100, "blocker": release},
    )

    result_task = asyncio.ensure_future(stream.__anext__())
    await entered.wait()
    assert state.requests == [1]
    assert state.entered == [1]

    release.set()
    result = await result_task
    assert result.errors is None

    await stream.aclose()
    assert state.exited == [(1, "GeneratorExit")]
    assert state.closed


@pytest.mark.asyncio
async def test_async_context_getter_can_return_an_awaitable() -> None:
    state = EventState.create()

    async def getter(event: SubscriptionEventPayload, info: Info):
        return sync_event_context(event, info, state=state)

    schema = make_schema(context_getter=getter, source=event_source(state))
    stream = await schema.subscribe(
        "subscription { events { value label } }",
        context_value={"connection_id": 100},
    )

    result = await stream.__anext__()
    assert result.errors is None
    await stream.aclose()

    assert state.entered == [1]
    assert state.exited == [(1, "GeneratorExit")]


@pytest.mark.asyncio
async def test_field_error_closes_event_context_with_error() -> None:
    state = EventState.create()

    def getter(event: SubscriptionEventPayload, info: Info):
        return async_event_context(event, info, state=state)

    schema = make_schema(context_getter=getter, source=event_source(state))
    stream = await schema.subscribe(
        "subscription { events { value label } }",
        context_value={"connection_id": 100, "raise_field_error": True},
    )

    results = [result async for result in stream]

    assert results[0].data is None
    assert results[0].errors
    assert state.exited[0] == (1, "GraphQLError")
    assert state.closed


@pytest.mark.asyncio
async def test_client_cancellation_closes_context_and_source() -> None:
    state = EventState.create()
    entered = asyncio.Event()
    release = asyncio.Event()

    @contextlib.asynccontextmanager
    async def getter(event: SubscriptionEventPayload, info: Info):
        async with async_event_context(
            event,
            info,
            state=state,
            first_enter=entered,
        ) as context:
            await release.wait()
            yield context

    schema = make_schema(context_getter=getter, source=event_source(state))
    stream = await schema.subscribe(
        "subscription { events { label } }",
        context_value={"connection_id": 100},
    )

    task = asyncio.ensure_future(stream.__anext__())
    await entered.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert state.exited == [(1, "CancelledError")]
    assert state.closed


@pytest.mark.asyncio
async def test_closing_after_an_event_closes_context_without_opening_next() -> None:
    state = EventState.create()

    schema = make_schema(
        context_getter=lambda event, info: async_event_context(
            event, info, state=state
        ),
        source=event_source(state),
    )
    stream = await schema.subscribe(
        "subscription { events { value label } }",
        context_value={"connection_id": 100},
    )

    result = await stream.__anext__()
    assert result.errors is None
    await stream.aclose()

    assert state.entered == [1]
    assert state.exited == [(1, "GeneratorExit")]
    assert state.requests == [1]
    assert state.closed


@pytest.mark.asyncio
async def test_context_enter_failure_is_reported_and_source_is_closed() -> None:
    state = EventState.create()

    schema = make_schema(
        context_getter=lambda event, info: async_event_context(
            event, info, state=state, enter_error=True
        ),
        source=event_source(state),
    )
    stream = await schema.subscribe(
        "subscription { events { value label } }",
        context_value={"connection_id": 100},
    )

    first = await stream.__anext__()
    assert first.errors is None
    second = await stream.__anext__()

    assert second.errors
    assert "cannot enter event context" in str(second.errors[0].original_error)
    assert state.entered == [1, 2]
    assert state.exited == [(1, None)]
    assert state.closed


@pytest.mark.asyncio
async def test_invalid_context_manager_is_reported_and_source_is_closed() -> None:
    state = EventState.create()

    def getter(event: SubscriptionEventPayload, info: Info):
        return None

    schema = make_schema(context_getter=getter, source=event_source(state))
    stream = await schema.subscribe(
        "subscription { events { value label } }",
        context_value={"connection_id": 100},
    )

    result = await stream.__anext__()

    assert result.errors
    assert "return a context manager" in str(result.errors[0])
    assert state.closed


@pytest.mark.asyncio
async def test_none_event_context_keeps_connection_context() -> None:
    state = EventState.create()

    @contextlib.asynccontextmanager
    async def getter(event: SubscriptionEventPayload, info: Info):
        assert info.context["connection_id"] == 100
        yield None

    schema = make_schema(context_getter=getter, source=event_source(state))
    stream = await schema.subscribe(
        "subscription { events { value } }",
        context_value={"connection_id": 100},
    )

    result = await stream.__anext__()

    assert result.errors is None
    assert result.data == {"events": {"value": 1}}

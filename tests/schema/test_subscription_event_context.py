from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncGenerator, AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import pytest

import strawberry
from strawberry.utils.aio import aclosing


@strawberry.type
class Query:
    name: str = "connection context"


@dataclass
class EventPayload:
    value: int


@strawberry.type
class Event:
    value: int

    @strawberry.field
    async def context_id(self, info: strawberry.Info) -> int:
        resolver_started = info.context.get("resolver_started")
        if resolver_started is not None:
            resolver_started.set()
        resolver_gate = info.context.get("resolver_gate")
        if resolver_gate is not None:
            await resolver_gate.wait()
        return info.context["event_id"]

    @strawberry.field
    async def checked(self, info: strawberry.Info) -> str:
        if info.context["event_id"] == 1:
            raise RuntimeError("field failed")
        return "ok"


def make_schema(
    event_context_getter: Callable[[Any, EventPayload], Any],
) -> strawberry.Schema:
    @strawberry.type
    class Subscription:
        @strawberry.subscription
        async def events(self) -> AsyncGenerator[Event, None]:
            yield EventPayload(value=1)
            yield EventPayload(value=2)

    return strawberry.Schema(
        query=Query,
        subscription=Subscription,
        subscription_event_context_getter=event_context_getter,
    )


@pytest.mark.asyncio
async def test_async_event_context_is_isolated_and_closed_after_delivery() -> None:
    events: list[str] = []
    opened: list[int] = []
    first_resolver_started = asyncio.Event()
    finish_first_resolver = asyncio.Event()

    @contextlib.asynccontextmanager
    async def event_context(
        connection_context: Any, event: EventPayload
    ) -> AsyncIterator[dict[str, Any]]:
        context_id = len(opened) + 1
        opened.append(context_id)
        events.append(f"enter {context_id}")
        resolver_gate = finish_first_resolver if context_id == 1 else None
        if resolver_gate is not None:
            first_resolver_started.set()
        try:
            yield {
                "connection": connection_context,
                "event_id": context_id,
                "event": event,
                "resolver_started": None,
                "resolver_gate": resolver_gate,
            }
        finally:
            events.append(f"exit {context_id}")

    schema = make_schema(event_context)
    connection_context = {"connection_id": 42}
    results = await schema.subscribe(
        "subscription { events { value contextId } }",
        context_value=connection_context,
    )

    try:
        first_task = asyncio.create_task(anext(results))
        await first_resolver_started.wait()
        await asyncio.sleep(0)
        assert opened == [1]
        assert events == ["enter 1"]

        finish_first_resolver.set()
        first = await first_task
        assert first.data == {"events": {"value": 1, "contextId": 1}}
        assert connection_context == {"connection_id": 42}

        assert events == ["enter 1"]
        second = await anext(results)
        assert second.data == {"events": {"value": 2, "contextId": 2}}
        assert events == ["enter 1", "exit 1", "enter 2"]
    finally:
        await results.aclose()

    assert events == ["enter 1", "exit 1", "enter 2", "exit 2"]
    assert opened == [1, 2]


@pytest.mark.asyncio
async def test_sync_event_context_is_supported() -> None:
    seen_contexts: list[int] = []

    @contextlib.contextmanager
    def event_context(connection_context: dict[str, Any], event: EventPayload):
        context_id = event.value + 10
        seen_contexts.append(context_id)
        try:
            yield {
                "connection": connection_context,
                "event_id": context_id,
                "resolver_started": None,
                "resolver_gate": None,
            }
        finally:
            seen_contexts.append(-context_id)

    schema = make_schema(event_context)

    async with aclosing(
        await schema.subscribe("subscription { events { value contextId } }")
    ) as results:
        first = await anext(results)
        second = await anext(results)

    assert first.data == {"events": {"value": 1, "contextId": 11}}
    assert second.data == {"events": {"value": 2, "contextId": 12}}
    assert seen_contexts == [11, -11, 12, -12]


@pytest.mark.asyncio
async def test_async_context_getter_can_be_awaitable() -> None:
    seen_contexts: list[int] = []

    @contextlib.contextmanager
    def manager(connection_context: Any, event: EventPayload):
        seen_contexts.append(event.value)
        yield {
            "event_id": event.value,
            "resolver_started": None,
            "resolver_gate": None,
        }

    async def event_context(connection_context: Any, event: EventPayload):
        return manager(connection_context, event)

    schema = make_schema(event_context)
    results = await schema.subscribe("subscription { events { value contextId } }")

    async with aclosing(results):
        first = await anext(results)
        second = await anext(results)

    assert first.data == {"events": {"value": 1, "contextId": 1}}
    assert second.data == {"events": {"value": 2, "contextId": 2}}
    assert seen_contexts == [1, 2]


@pytest.mark.asyncio
async def test_invalid_context_manager_returns_error_and_continues() -> None:
    calls = 0

    def event_context(connection_context: Any, event: EventPayload):
        nonlocal calls
        calls += 1
        if event.value == 1:
            return object()
        return contextlib.nullcontext(
            {
                "event_id": event.value,
                "resolver_started": None,
                "resolver_gate": None,
            }
        )

    schema = make_schema(event_context)
    results = await schema.subscribe("subscription { events { value } }")

    async with aclosing(results):
        first = await anext(results)
        assert first.errors
        assert "context manager" in first.errors[0].message
        second = await anext(results)
        assert second.data == {"events": {"value": 2}}

    assert calls == 2


@pytest.mark.asyncio
async def test_field_error_closes_context_before_next_event() -> None:
    events: list[str] = []

    @contextlib.asynccontextmanager
    async def event_context(connection_context: Any, event: EventPayload):
        events.append(f"enter {event.value}")
        try:
            yield {
                "event_id": event.value,
                "resolver_started": None,
                "resolver_gate": None,
            }
        except Exception as exc:
            events.append(f"error {event.value}: {exc}")
            raise
        finally:
            events.append(f"exit {event.value}")

    schema = make_schema(event_context)
    results = await schema.subscribe("subscription { events { value checked } }")

    async with aclosing(results):
        first = await anext(results)
        assert first.errors
        assert first.errors[0].message == "field failed"
        assert events == ["enter 1"]

        second = await anext(results)
        assert second.data == {"events": {"value": 2, "checked": "ok"}}
        assert events[0] == "enter 1"
        assert events[1].startswith("error 1: field failed")
        assert events[2:4] == ["exit 1", "enter 2"]

    assert events[2:] == ["exit 1", "enter 2", "exit 2"]
    assert events[-1] == "exit 2"


@pytest.mark.asyncio
async def test_context_entry_failure_returns_error_and_continues() -> None:
    entered: list[int] = []
    cleanup: list[str] = []

    @contextlib.asynccontextmanager
    async def event_context(connection_context: Any, event: EventPayload):
        if event.value == 1:
            cleanup.append("acquired")
            try:
                raise RuntimeError("context failed")
            finally:
                cleanup.append("released")
        entered.append(event.value)
        yield {
            "event_id": event.value,
            "resolver_started": None,
            "resolver_gate": None,
        }

    schema = make_schema(event_context)
    results = await schema.subscribe("subscription { events { value } }")

    async with aclosing(results):
        first = await anext(results)
        assert first.errors
        assert first.errors[0].message == "context failed"
        second = await anext(results)
        assert second.data == {"events": {"value": 2}}

    assert entered == [2]
    assert cleanup == ["acquired", "released"]


@pytest.mark.asyncio
async def test_cancellation_closes_event_context_before_source() -> None:
    events: list[str] = []
    source_started = asyncio.Event()
    event_context_entered = asyncio.Event()
    resolver_reached = asyncio.Event()
    block_resolver = asyncio.Event()

    @strawberry.type
    class CancellationSubscription:
        @strawberry.subscription
        async def events(self) -> AsyncGenerator[Event, None]:
            source_started.set()
            try:
                yield EventPayload(value=1)
            finally:
                events.append("source closed")

    @contextlib.asynccontextmanager
    async def event_context(connection_context: Any, event: EventPayload):
        event_context_entered.set()
        events.append("context entered")
        try:
            yield {
                "event_id": event.value,
                "resolver_started": resolver_reached,
                "resolver_gate": type(
                    "ImmediateGate",
                    (),
                    {"wait": block_resolver.wait},
                )(),
            }
        finally:
            events.append("context exited")

    schema = strawberry.Schema(
        query=Query,
        subscription=CancellationSubscription,
        subscription_event_context_getter=event_context,
    )
    results = await schema.subscribe("subscription { events { value contextId } }")
    receive_task = asyncio.create_task(anext(results))
    await source_started.wait()
    await event_context_entered.wait()
    await resolver_reached.wait()
    receive_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await receive_task

    await results.aclose()
    assert events == ["context entered", "context exited", "source closed"]


@pytest.mark.asyncio
async def test_early_close_exits_event_context_before_source() -> None:
    events: list[str] = []

    @strawberry.type
    class CloseSubscription:
        @strawberry.subscription
        async def events(self) -> AsyncGenerator[Event, None]:
            try:
                yield EventPayload(value=1)
                await asyncio.Event().wait()
            finally:
                events.append("source closed")

    @contextlib.asynccontextmanager
    async def event_context(connection_context: Any, event: EventPayload):
        events.append("context entered")
        try:
            yield {
                "event_id": event.value,
                "resolver_started": None,
                "resolver_gate": None,
            }
        finally:
            events.append("context exited")

    schema = strawberry.Schema(
        query=Query,
        subscription=CloseSubscription,
        subscription_event_context_getter=event_context,
    )
    results = await schema.subscribe("subscription { events { value } }")

    first = await anext(results)
    assert first.data == {"events": {"value": 1}}
    assert events == ["context entered"]

    await results.aclose()
    assert events == ["context entered", "context exited", "source closed"]


@pytest.mark.asyncio
async def test_connection_context_is_available_and_restored() -> None:
    observed_contexts: list[Any] = []

    @contextlib.asynccontextmanager
    async def event_context(connection_context: dict[str, Any], event: EventPayload):
        observed_contexts.append(connection_context)
        yield {
            "event_id": event.value,
            "resolver_started": None,
            "resolver_gate": None,
        }

    schema = make_schema(event_context)
    connection_context = {"connection": True}
    results = await schema.subscribe(
        "subscription { events { value } }",
        context_value=connection_context,
    )

    async with aclosing(results):
        await anext(results)
        await anext(results)

    assert observed_contexts == [connection_context, connection_context]


@pytest.mark.asyncio
async def test_stream_uses_event_context_for_subscriptions() -> None:
    seen_contexts: list[int] = []

    @contextlib.asynccontextmanager
    async def event_context(connection_context: Any, event: EventPayload):
        seen_contexts.append(event.value)
        yield {
            "event_id": event.value,
            "resolver_started": None,
            "resolver_gate": None,
        }

    schema = make_schema(event_context)
    results = await schema.stream("subscription { events { value contextId } }")

    async with aclosing(results):
        results_list = [result async for result in results]

    assert [result.data for result in results_list] == [
        {"events": {"value": 1, "contextId": 1}},
        {"events": {"value": 2, "contextId": 2}},
    ]
    assert seen_contexts == [1, 2]

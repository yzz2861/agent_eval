from __future__ import annotations

import asyncio
from typing import Any

import pytest

from quart import Quart
from quart import websocket
from quart import WebsocketRPC


@pytest.fixture(name="events")
def _events() -> list:
    return []


@pytest.fixture(name="app")
def _app(events: list) -> Quart:
    app = Quart(__name__)

    @app.websocket("/rpc")
    async def rpc() -> None:
        dispatcher = WebsocketRPC(websocket, max_concurrent=2)

        @dispatcher.method("slow")
        async def slow(params: Any) -> Any:
            events.append("slow-start")
            try:
                await asyncio.sleep(0.2)
                return params
            finally:
                events.append("slow-done")

        @dispatcher.method("fast")
        async def fast(params: Any) -> Any:
            return params

        @dispatcher.method("fail")
        async def fail(params: Any) -> Any:
            raise ValueError("boom")

        await dispatcher.run()
        events.append("closed")

    @app.websocket("/echo")
    async def echo() -> None:
        while True:
            await websocket.send(await websocket.receive())

    return app


async def test_parallel_slow_and_fast(app: Quart) -> None:
    test_client = app.test_client()
    async with test_client.websocket("/rpc") as test_websocket:
        await test_websocket.send_json({"id": 1, "method": "slow", "params": "a"})
        await test_websocket.send_json({"id": 2, "method": "fast", "params": "b"})
        first = await test_websocket.receive_json()
        second = await test_websocket.receive_json()
    # The fast call finishes first, each result carries its own id
    assert first == {"id": 2, "result": "b"}
    assert second == {"id": 1, "result": "a"}


async def test_cancel_only_cancels_target(app: Quart) -> None:
    test_client = app.test_client()
    async with test_client.websocket("/rpc") as test_websocket:
        await test_websocket.send_json({"id": 1, "method": "slow", "params": "a"})
        await test_websocket.send_json({"id": 2, "method": "fast", "params": "b"})
        await test_websocket.send_json({"cancel": 1})
        results = [
            await test_websocket.receive_json(),
            await test_websocket.receive_json(),
        ]
        # The connection survives the cancellation
        await test_websocket.send_json({"id": 3, "method": "fast", "params": "c"})
        third = await test_websocket.receive_json()
    assert {1, 2} == {message["id"] for message in results}
    cancelled = next(message for message in results if message["id"] == 1)
    assert cancelled["error"]["code"] == "cancelled"
    result = next(message for message in results if message["id"] == 2)
    assert result == {"id": 2, "result": "b"}
    assert third == {"id": 3, "result": "c"}


async def test_disconnect_cleans_up(app: Quart, events: list) -> None:
    test_client = app.test_client()
    async with test_client.websocket("/rpc") as test_websocket:
        await test_websocket.send_json({"id": 1, "method": "slow", "params": "a"})
        while "slow-start" not in events:
            await asyncio.sleep(0.01)
        await test_websocket.disconnect()
    # The in-flight call was cancelled and awaited before run() returned
    assert events == ["slow-start", "slow-done", "closed"]


async def test_busy_when_slots_exhausted(app: Quart) -> None:
    test_client = app.test_client()
    async with test_client.websocket("/rpc") as test_websocket:
        await test_websocket.send_json({"id": 1, "method": "slow", "params": "a"})
        await test_websocket.send_json({"id": 2, "method": "slow", "params": "b"})
        await test_websocket.send_json({"id": 3, "method": "fast", "params": "c"})
        busy = await test_websocket.receive_json()
        results = [
            await test_websocket.receive_json(),
            await test_websocket.receive_json(),
        ]
    assert busy["id"] == 3
    assert busy["error"]["code"] == "busy"
    assert {1, 2} == {message["id"] for message in results}
    assert all("result" in message for message in results)


async def test_handler_exception_becomes_error(app: Quart) -> None:
    test_client = app.test_client()
    async with test_client.websocket("/rpc") as test_websocket:
        await test_websocket.send_json({"id": 1, "method": "fail"})
        error = await test_websocket.receive_json()
        # The connection survives a handler exception
        await test_websocket.send_json({"id": 2, "method": "fast", "params": "b"})
        result = await test_websocket.receive_json()
    assert error == {"id": 1, "error": {"code": "internal", "message": "boom"}}
    assert result == {"id": 2, "result": "b"}


async def test_unknown_method(app: Quart) -> None:
    test_client = app.test_client()
    async with test_client.websocket("/rpc") as test_websocket:
        await test_websocket.send_json({"id": 1, "method": "missing"})
        error = await test_websocket.receive_json()
        await test_websocket.send_json({"id": 2, "method": "fast", "params": "b"})
        result = await test_websocket.receive_json()
    assert error["id"] == 1
    assert error["error"]["code"] == "method_not_found"
    assert result == {"id": 2, "result": "b"}


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        '["not", "a", "dict"]',
        '{"method": "fast"}',
        '{"id": 1}',
        '{"id": true, "method": "fast"}',
        '{"cancel": [1]}',
    ],
)
async def test_protocol_error_closes_connection(
    app: Quart, events: list, raw: str
) -> None:
    test_client = app.test_client()
    async with test_client.websocket("/rpc") as test_websocket:
        await test_websocket.send(raw)
    assert events == ["closed"]


async def test_duplicate_inflight_id_closes_connection(
    app: Quart, events: list
) -> None:
    test_client = app.test_client()
    async with test_client.websocket("/rpc") as test_websocket:
        await test_websocket.send_json({"id": 1, "method": "slow", "params": "a"})
        while "slow-start" not in events:
            await asyncio.sleep(0.01)
        await test_websocket.send_json({"id": 1, "method": "fast", "params": "b"})
    assert events == ["slow-start", "slow-done", "closed"]


async def test_id_reusable_after_completion(app: Quart) -> None:
    test_client = app.test_client()
    async with test_client.websocket("/rpc") as test_websocket:
        await test_websocket.send_json({"id": 1, "method": "fast", "params": "a"})
        first = await test_websocket.receive_json()
        await test_websocket.send_json({"id": 1, "method": "fast", "params": "b"})
        second = await test_websocket.receive_json()
    assert first == {"id": 1, "result": "a"}
    assert second == {"id": 1, "result": "b"}


async def test_concurrent_results_do_not_interleave() -> None:
    app = Quart(__name__)

    @app.websocket("/rpc")
    async def rpc() -> None:
        dispatcher = WebsocketRPC(websocket, max_concurrent=8)

        @dispatcher.method("fast")
        async def fast(params: Any) -> Any:
            await asyncio.sleep(0.01)
            return params

        await dispatcher.run()

    test_client = app.test_client()
    async with test_client.websocket("/rpc") as test_websocket:
        for index in range(6):
            await test_websocket.send_json(
                {"id": index, "method": "fast", "params": "x" * 1000}
            )
        results = [await test_websocket.receive_json() for _ in range(6)]
    # Every frame is a complete, valid response with a matching id
    assert {message["id"] for message in results} == set(range(6))
    assert all(message["result"] == "x" * 1000 for message in results)


async def test_raw_websocket_api_unaffected(app: Quart) -> None:
    test_client = app.test_client()
    async with test_client.websocket("/echo") as test_websocket:
        await test_websocket.send("ping")
        result = await test_websocket.receive()
    assert result == "ping"

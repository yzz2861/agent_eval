from __future__ import annotations

import asyncio

from quart import Quart
from quart import WebsocketCallClosedError
from quart import WebsocketCallConnection
from quart import WebsocketCallDispatcher
from quart import websocket


async def test_dispatcher_slow_fast_cancel_and_disconnect() -> None:
    app = Quart(__name__)
    cancelled = asyncio.Event()
    disconnected = asyncio.Event()

    async def slow(connection: object, delay: float) -> str:
        await asyncio.sleep(delay)
        return "slow result"

    async def fast(connection: object, value: str) -> str:
        return value

    async def wait(connection: WebsocketCallConnection) -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            if connection.closed:
                try:
                    await connection.send_json({"should": "not be sent"})
                except WebsocketCallClosedError:
                    disconnected.set()
            else:
                cancelled.set()
            raise

    @app.websocket("/ws")
    async def ws() -> None:
        await WebsocketCallDispatcher(
            websocket, {"slow": slow, "fast": fast, "wait": wait}, max_concurrency=4
        ).serve()

    async with app.test_client().websocket("/ws") as test_ws:
        await test_ws.send_json(
            {"id": 1, "method": "slow", "params": {"delay": 0.05}}
        )
        await test_ws.send_json(
            {"id": 2, "method": "fast", "params": {"value": "fast result"}}
        )

        assert await test_ws.receive_json() == {
            "id": 2,
            "result": "fast result",
        }
        assert await test_ws.receive_json() == {
            "id": 1,
            "result": "slow result",
        }

        await test_ws.send_json({"id": 3, "method": "wait", "params": {}})
        await asyncio.sleep(0.02)
        await test_ws.send_json({"id": 3, "method": "cancel", "params": {}})
        assert await test_ws.receive_json() == {
            "id": 3,
            "error": {"code": -32800, "message": "Call cancelled"},
        }
        assert cancelled.is_set()

        await test_ws.send_json({"id": 4, "method": "wait", "params": {}})
        await asyncio.sleep(0.02)

    assert disconnected.is_set()


async def test_dispatcher_returns_busy_without_queueing() -> None:
    app = Quart(__name__)

    async def slow(connection: object, delay: float) -> str:
        await asyncio.sleep(delay)
        return "slow result"

    async def fast(connection: object, value: str) -> str:
        return value

    @app.websocket("/ws")
    async def ws() -> None:
        await WebsocketCallDispatcher(
            websocket, {"slow": slow, "fast": fast}, max_concurrency=1
        ).serve()

    async with app.test_client().websocket("/ws") as test_ws:
        await test_ws.send_json(
            {"id": 1, "method": "slow", "params": {"delay": 0.1}}
        )
        await test_ws.send_json(
            {"id": 2, "method": "fast", "params": {"value": "fast result"}}
        )

        responses = [await test_ws.receive_json(), await test_ws.receive_json()]
        assert {
            "id": 2,
            "error": {"code": -32000, "message": "Server is busy"},
        } in responses
        assert {"id": 1, "result": "slow result"} in responses


async def test_dispatcher_returns_handler_exception_by_id() -> None:
    app = Quart(__name__)

    async def fail(connection: object) -> None:
        raise RuntimeError("boom")

    @app.websocket("/ws")
    async def ws() -> None:
        await WebsocketCallDispatcher(websocket, {"fail": fail}).serve()

    async with app.test_client().websocket("/ws") as test_ws:
        await test_ws.send_json({"id": "x", "method": "fail", "params": {}})
        assert await test_ws.receive_json() == {
            "id": "x",
            "error": {"code": -32000, "message": "boom"},
        }


async def test_dispatcher_rejects_duplicate_pending_id() -> None:
    app = Quart(__name__)

    async def wait(connection: object) -> None:
        await asyncio.Event().wait()

    @app.websocket("/ws")
    async def ws() -> None:
        await WebsocketCallDispatcher(websocket, {"wait": wait}).serve()

    async with app.test_client().websocket("/ws") as test_ws:
        request = {"id": 1, "method": "wait", "params": {}}
        await test_ws.send_json(request)
        await asyncio.sleep(0.02)
        await test_ws.send_json(request)
        await asyncio.sleep(0.02)


async def test_dispatcher_serialises_concurrent_results() -> None:
    app = Quart(__name__)
    all_started = asyncio.Event()
    started = 0

    async def result(connection: object, index: int) -> dict[str, int]:
        nonlocal started
        started += 1
        if started == 10:
            all_started.set()
        await all_started.wait()
        return {"index": index}

    @app.websocket("/ws")
    async def ws() -> None:
        await WebsocketCallDispatcher(
            websocket, {"result": result}, max_concurrency=10
        ).serve()

    async with app.test_client().websocket("/ws") as test_ws:
        for index in range(10):
            await test_ws.send_json(
                {"id": index, "method": "result", "params": {"index": index}}
            )

        responses = [await test_ws.receive_json() for _ in range(10)]

    assert responses == [
        {"id": index, "result": {"index": index}} for index in range(10)
    ] or sorted(responses, key=lambda item: item["id"]) == [
        {"id": index, "result": {"index": index}} for index in range(10)
    ]

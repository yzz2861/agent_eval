from __future__ import annotations

import asyncio
import threading
from collections import deque
from collections.abc import Callable, Iterable
from typing import Any

from ..app_wrappers import WSGIWrapper
from ..typing import ASGIReceiveCallable, ASGISendCallable, Scope, WSGIFramework

MAX_BODY_SIZE = 2**16

WSGICallable = Callable[[dict, Callable], Iterable[bytes]]

BUSY_BODY = b"Service busy, please retry later"


class InvalidPathError(Exception):
    pass


class _BusyError(Exception):
    """Raised when the WSGI capacity limits reject a request."""


class _Waiter:
    __slots__ = ("granted", "notify")

    def __init__(self, notify: Callable[[], None]) -> None:
        self.granted = False
        self.notify = notify


class _Slot:
    __slots__ = ("released",)

    def __init__(self) -> None:
        self.released = False


class _CapacityLimiter:
    """Bounds concurrently executing WSGI calls and the waiting queue.

    The bookkeeping is thread safe as slots are released from the worker
    thread running the WSGI callable, potentially after the coroutine
    that awaited it has been cancelled.
    """

    def __init__(self, max_concurrency: int | None, max_queue_size: int | None) -> None:
        self._max_concurrency = max_concurrency
        self._max_queue_size = max_queue_size
        self._lock = threading.Lock()
        self._executing = 0
        self._queue: deque[_Waiter] = deque()

    def enter(self, notify: Callable[[], None]) -> _Waiter | None:
        """Take a slot or enqueue, returning the waiter if queued."""
        with self._lock:
            if self._max_concurrency is None or self._executing < self._max_concurrency:
                self._executing += 1
                return None
            if self._max_queue_size is not None and len(self._queue) >= self._max_queue_size:
                raise _BusyError()
            waiter = _Waiter(notify)
            self._queue.append(waiter)
            return waiter

    def leave_queue(self, waiter: _Waiter) -> bool:
        """Remove the waiter from the queue.

        Returns True if a slot was granted to the waiter concurrently,
        in which case the caller owns the slot and must use or release
        it.
        """
        with self._lock:
            if waiter.granted:
                return True
            try:
                self._queue.remove(waiter)
            except ValueError:
                pass
            return False

    def release(self, slot: _Slot) -> None:
        with self._lock:
            if slot.released:
                return
            slot.released = True
            if self._queue:
                waiter = self._queue.popleft()
                waiter.granted = True
                notify: Callable[[], None] | None = waiter.notify
            else:
                self._executing -= 1
                notify = None
        if notify is not None:
            try:
                notify()
            except Exception:
                pass  # The event loop has already closed


class _WSGIMiddleware:
    def __init__(
        self,
        wsgi_app: WSGIFramework,
        max_body_size: int = MAX_BODY_SIZE,
        *,
        max_concurrency: int | None = None,
        max_queue_size: int | None = None,
        queue_timeout: float | None = None,
    ) -> None:
        self.wsgi_app = WSGIWrapper(wsgi_app, max_body_size)
        self.max_body_size = max_body_size
        self.max_concurrency = max_concurrency
        self.max_queue_size = max_queue_size
        self.queue_timeout = queue_timeout
        self._limiter = _CapacityLimiter(max_concurrency, max_queue_size)

    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        pass

    async def _send_busy(self, send: ASGISendCallable) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 503,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(BUSY_BODY)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": BUSY_BODY, "more_body": False})


class AsyncioWSGIMiddleware(_WSGIMiddleware):
    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        loop = asyncio.get_running_loop()

        def _call_soon(func: Callable, *args: Any) -> Any:
            future = asyncio.run_coroutine_threadsafe(func(*args), loop)
            return future.result()

        try:
            await self.wsgi_app(scope, receive, send, self._sync_spawn, _call_soon)
        except _BusyError:
            await self._send_busy(send)

    async def _sync_spawn(self, func: Callable, *args: Any) -> Any:
        slot = await self._acquire_slot()

        def _guarded() -> Any:
            try:
                return func(*args)
            finally:
                # Release from the worker thread, once the WSGI callable
                # (including response iteration and close) has truly exited.
                self._limiter.release(slot)

        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(None, _guarded)
        except BaseException:
            self._limiter.release(slot)
            raise
        # Shield the executor future so that cancelling this coroutine
        # cannot pretend the WSGI callable is no longer running.
        return await asyncio.shield(future)

    async def _acquire_slot(self) -> _Slot:
        loop = asyncio.get_running_loop()
        event = asyncio.Event()
        waiter = self._limiter.enter(lambda: loop.call_soon_threadsafe(event.set))
        if waiter is None:
            return _Slot()
        try:
            if self.queue_timeout is None:
                await event.wait()
            else:
                await asyncio.wait_for(event.wait(), self.queue_timeout)
        except asyncio.TimeoutError:
            if self._limiter.leave_queue(waiter):
                return _Slot()  # Granted as the timeout fired
            raise _BusyError()
        except BaseException:
            # Cancelled whilst queued, leave the queue immediately. If a
            # slot was granted concurrently it must be released unused.
            if self._limiter.leave_queue(waiter):
                self._limiter.release(_Slot())
            raise
        return _Slot()


class TrioWSGIMiddleware(_WSGIMiddleware):
    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        import trio

        async def _sync_spawn(func: Callable, *args: Any) -> Any:
            slot = await self._acquire_slot()
            started = threading.Event()

            def _guarded() -> Any:
                started.set()
                try:
                    return func(*args)
                finally:
                    # Release from the worker thread, once the WSGI callable
                    # (including response iteration and close) has truly exited.
                    self._limiter.release(slot)

            try:
                # An abandoned thread keeps running and releases the slot
                # when the WSGI callable truly exits.
                return await trio.to_thread.run_sync(_guarded, abandon_on_cancel=True)
            except BaseException:
                if not started.is_set():
                    # Cancelled before the thread started, the callable
                    # will never run and cannot release the slot itself.
                    self._limiter.release(slot)
                raise

        try:
            await self.wsgi_app(scope, receive, send, _sync_spawn, trio.from_thread.run)
        except _BusyError:
            await self._send_busy(send)

    async def _acquire_slot(self) -> _Slot:
        import trio

        event = trio.Event()
        token = trio.lowlevel.current_trio_token()
        waiter = self._limiter.enter(lambda: token.run_sync_soon(event.set))
        if waiter is None:
            return _Slot()
        try:
            if self.queue_timeout is None:
                await event.wait()
            else:
                with trio.fail_after(self.queue_timeout):
                    await event.wait()
        except trio.TooSlowError:
            if self._limiter.leave_queue(waiter):
                return _Slot()  # Granted as the timeout fired
            raise _BusyError()
        except BaseException:
            # Cancelled whilst queued, leave the queue immediately. If a
            # slot was granted concurrently it must be released unused.
            if self._limiter.leave_queue(waiter):
                self._limiter.release(_Slot())
            raise
        return _Slot()

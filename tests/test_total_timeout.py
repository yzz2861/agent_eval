"""
Tests for the optional total request time budget (`Timeout(..., total=...)`).

These tests use a controllable clock, patched into `httpx._client._monotonic`,
together with local transports that serve chunked responses or redirects,
advancing the clock as they go.
"""

import typing

import pytest

import httpx


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    clock = FakeClock()
    monkeypatch.setattr("httpx._client._monotonic", clock)
    return clock


class ChunkedStream(httpx.SyncByteStream):
    """
    A stream that yields chunks of a local response, where each chunk
    takes 'delay' seconds to arrive.
    """

    def __init__(self, chunks: list[bytes], clock: FakeClock, delay: float) -> None:
        self._chunks = chunks
        self._clock = clock
        self._delay = delay
        self.closed = False

    def __iter__(self) -> typing.Iterator[bytes]:
        for chunk in self._chunks:
            self._clock.advance(self._delay)
            yield chunk

    def close(self) -> None:
        self.closed = True


class ChunkedTransport(httpx.BaseTransport):
    def __init__(self, chunks: list[bytes], clock: FakeClock, delay: float) -> None:
        self.stream = ChunkedStream(chunks, clock, delay)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=self.stream)


class AsyncChunkedStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], clock: FakeClock, delay: float) -> None:
        self._chunks = chunks
        self._clock = clock
        self._delay = delay
        self.closed = False

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        for chunk in self._chunks:
            self._clock.advance(self._delay)
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


class AsyncChunkedTransport(httpx.AsyncBaseTransport):
    def __init__(self, chunks: list[bytes], clock: FakeClock, delay: float) -> None:
        self.stream = AsyncChunkedStream(chunks, clock, delay)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=self.stream)


class RedirectTransport(httpx.BaseTransport):
    """
    A local transport that responds with 'hops' redirects, each taking
    'delay' seconds, before finally returning a 200 response.
    """

    def __init__(self, clock: FakeClock, hops: int, delay: float) -> None:
        self._clock = clock
        self._hops = hops
        self._delay = delay
        self.requests = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        self._clock.advance(self._delay)
        if self.requests <= self._hops:
            location = f"/redirect-{self.requests}"
            return httpx.Response(302, headers={"Location": location}, content=b"")
        return httpx.Response(200, content=b"done")


class AsyncRedirectTransport(httpx.AsyncBaseTransport):
    def __init__(self, clock: FakeClock, hops: int, delay: float) -> None:
        self._clock = clock
        self._hops = hops
        self._delay = delay
        self.requests = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        self._clock.advance(self._delay)
        if self.requests <= self._hops:
            location = f"/redirect-{self.requests}"
            return httpx.Response(302, headers={"Location": location}, content=b"")
        return httpx.Response(200, content=b"done")


class StallingTransport(httpx.BaseTransport):
    """
    A transport that stalls for 'delay' seconds and then fails
    with a 'ReadTimeout'.
    """

    def __init__(self, clock: FakeClock, delay: float) -> None:
        self._clock = clock
        self._delay = delay

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self._clock.advance(self._delay)
        raise httpx.ReadTimeout("timed out")


def test_total_timeout_streaming_chunks(clock: FakeClock) -> None:
    """
    A steady stream of small chunks must not extend the total budget,
    even though each chunk arrives well within any read timeout.
    """
    transport = ChunkedTransport([b"chunk"] * 10, clock, delay=0.5)
    timeout = httpx.Timeout(None, total=2.0)

    with httpx.Client(transport=transport, timeout=timeout) as client:
        with pytest.raises(httpx.TotalTimeout) as exc_info:
            client.get("http://example.org/")

    assert not isinstance(exc_info.value, httpx.ReadTimeout)
    assert exc_info.value.request is not None
    # The connection is released once the budget is exhausted.
    assert transport.stream.closed


def test_total_timeout_not_reached(clock: FakeClock) -> None:
    transport = ChunkedTransport([b"chunk"] * 3, clock, delay=0.5)
    timeout = httpx.Timeout(None, total=2.0)

    with httpx.Client(transport=transport, timeout=timeout) as client:
        response = client.get("http://example.org/")

    assert response.content == b"chunk" * 3


def test_total_timeout_disabled(clock: FakeClock) -> None:
    """
    Without a total budget, slow dribbling responses behave exactly as before.
    """
    transport = ChunkedTransport([b"chunk"] * 10, clock, delay=0.5)

    with httpx.Client(transport=transport, timeout=None) as client:
        response = client.get("http://example.org/")

    assert response.content == b"chunk" * 10


def test_total_timeout_shared_across_redirects(clock: FakeClock) -> None:
    """
    Redirects share a single budget, rather than each getting a fresh one.
    """
    transport = RedirectTransport(clock, hops=3, delay=4.0)
    timeout = httpx.Timeout(None, total=10.0)

    with httpx.Client(
        transport=transport, timeout=timeout, follow_redirects=True
    ) as client:
        with pytest.raises(httpx.TotalTimeout) as exc_info:
            client.get("http://example.org/")

    assert not isinstance(exc_info.value, httpx.ReadTimeout)
    # Three 4s redirects exhaust the 10s budget, so the fourth request
    # is never issued. With per-redirect budgets all four would complete.
    assert transport.requests == 3


def test_total_timeout_distinct_from_read_timeout(clock: FakeClock) -> None:
    """
    A per-operation timeout that occurs because the total budget has been
    exhausted is re-raised as a 'TotalTimeout'.
    """
    transport = StallingTransport(clock, delay=5.0)
    timeout = httpx.Timeout(None, total=2.0)

    with httpx.Client(transport=transport, timeout=timeout) as client:
        with pytest.raises(httpx.TotalTimeout) as exc_info:
            client.get("http://example.org/")

    assert not isinstance(exc_info.value, httpx.ReadTimeout)


def test_total_timeout_stream_closed_early(clock: FakeClock) -> None:
    """
    Closing a streaming response early, within the budget, works as usual.
    """
    transport = ChunkedTransport([b"chunk"] * 10, clock, delay=0.5)
    timeout = httpx.Timeout(None, total=10.0)

    with httpx.Client(transport=transport, timeout=timeout) as client:
        with client.stream("GET", "http://example.org/") as response:
            chunk = next(response.iter_raw())
            assert chunk == b"chunk"

    assert transport.stream.closed


def test_total_timeout_streaming_response(clock: FakeClock) -> None:
    """
    A streaming response remains bound by the budget after the headers
    have been returned.
    """
    transport = ChunkedTransport([b"chunk"] * 10, clock, delay=0.5)
    timeout = httpx.Timeout(None, total=2.0)

    with httpx.Client(transport=transport, timeout=timeout) as client:
        with client.stream("GET", "http://example.org/") as response:
            assert response.status_code == 200
            with pytest.raises(httpx.TotalTimeout):
                for _chunk in response.iter_raw():
                    pass

    assert transport.stream.closed


@pytest.mark.anyio
async def test_async_total_timeout_streaming_chunks(clock: FakeClock) -> None:
    transport = AsyncChunkedTransport([b"chunk"] * 10, clock, delay=0.5)
    timeout = httpx.Timeout(None, total=2.0)

    async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
        with pytest.raises(httpx.TotalTimeout) as exc_info:
            await client.get("http://example.org/")

    assert not isinstance(exc_info.value, httpx.ReadTimeout)
    assert transport.stream.closed


@pytest.mark.anyio
async def test_async_total_timeout_shared_across_redirects(
    clock: FakeClock,
) -> None:
    transport = AsyncRedirectTransport(clock, hops=3, delay=4.0)
    timeout = httpx.Timeout(None, total=10.0)

    async with httpx.AsyncClient(
        transport=transport, timeout=timeout, follow_redirects=True
    ) as client:
        with pytest.raises(httpx.TotalTimeout) as exc_info:
            await client.get("http://example.org/")

    assert not isinstance(exc_info.value, httpx.ReadTimeout)
    assert transport.requests == 3


@pytest.mark.anyio
async def test_async_total_timeout_stream_closed_early(clock: FakeClock) -> None:
    transport = AsyncChunkedTransport([b"chunk"] * 10, clock, delay=0.5)
    timeout = httpx.Timeout(None, total=10.0)

    async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
        async with client.stream("GET", "http://example.org/") as response:
            chunks = [part async for part in response.aiter_raw()]
            assert chunks[0] == b"chunk"

    assert transport.stream.closed

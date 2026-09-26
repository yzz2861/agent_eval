"""
Tests for the optional `total=...` timeout budget, which covers the entire
request from `send()` through to the response being closed.

These tests use a controllable clock together with local chunked responses,
so that no real time needs to elapse.
"""

import typing

import pytest

import httpx
import httpx._client


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
    monkeypatch.setattr(httpx._client, "_monotonic", clock)
    return clock


class TrickleStream(httpx.SyncByteStream):
    """
    A stream that delivers a steady trickle of small chunks, advancing
    the clock as each chunk arrives.
    """

    def __init__(self, clock: FakeClock, chunks: list[bytes], step: float) -> None:
        self._clock = clock
        self._chunks = chunks
        self._step = step
        self.chunks_served = 0
        self.closed = False

    def __iter__(self) -> typing.Iterator[bytes]:
        for chunk in self._chunks:
            self._clock.advance(self._step)
            self.chunks_served += 1
            yield chunk

    def close(self) -> None:
        self.closed = True


class AsyncTrickleStream(httpx.AsyncByteStream):
    def __init__(self, clock: FakeClock, chunks: list[bytes], step: float) -> None:
        self._clock = clock
        self._chunks = chunks
        self._step = step
        self._generator: typing.AsyncIterator[bytes] | None = None
        self.chunks_served = 0
        self.closed = False

    async def _iterate(self) -> typing.AsyncIterator[bytes]:
        for chunk in self._chunks:
            self._clock.advance(self._step)
            self.chunks_served += 1
            yield chunk

    def __aiter__(self) -> typing.AsyncIterator[bytes]:
        self._generator = self._iterate()
        return self._generator

    async def aclose(self) -> None:
        self.closed = True
        if self._generator is not None:
            await self._generator.aclose()


class ChunkedTransport(httpx.AsyncBaseTransport, httpx.BaseTransport):
    """
    A local transport returning a chunked response that keeps
    delivering small chunks for as long as they are consumed.
    """

    def __init__(self, clock: FakeClock, chunks: list[bytes], step: float) -> None:
        self._clock = clock
        self._chunks = chunks
        self._step = step
        self.stream: TrickleStream | AsyncTrickleStream | None = None

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.stream = TrickleStream(self._clock, self._chunks, self._step)
        return httpx.Response(200, stream=self.stream)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.stream = AsyncTrickleStream(self._clock, self._chunks, self._step)
        return httpx.Response(200, stream=self.stream)


class RedirectTransport(httpx.AsyncBaseTransport, httpx.BaseTransport):
    """
    A local transport that redirects a fixed number of times before
    returning a 200 OK, advancing the clock on each request.
    """

    def __init__(self, clock: FakeClock, step: float, redirects: int) -> None:
        self._clock = clock
        self._step = step
        self._redirects = redirects
        self.requests: list[httpx.Request] = []

    def _respond(self, request: httpx.Request) -> httpx.Response:
        self._clock.advance(self._step)
        self.requests.append(request)
        if len(self.requests) <= self._redirects:
            location = f"/redirect-{len(self.requests)}".encode("ascii")
            return httpx.Response(302, headers=[(b"location", location)])
        return httpx.Response(200, content=b"Hello, world!")

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._respond(request)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self._respond(request)


def test_total_timeout_config() -> None:
    timeout = httpx.Timeout(5.0, total=30.0)
    assert timeout.total == 30.0
    assert "total" not in timeout.as_dict()
    assert repr(timeout) == "Timeout(timeout=5.0, total=30.0)"
    assert timeout == httpx.Timeout(5.0, total=30.0)
    assert timeout != httpx.Timeout(5.0)
    assert httpx.Timeout(timeout).total == 30.0
    assert httpx.Timeout(None).total is None
    assert httpx.Timeout(5.0).total is None


def test_total_timeout_extension_is_set() -> None:
    client = httpx.Client(timeout=httpx.Timeout(5.0, total=30.0))
    request = client.build_request("GET", "http://example.org/")
    assert request.extensions["total_timeout"] == 30.0

    client = httpx.Client()
    request = client.build_request("GET", "http://example.org/")
    assert "total_timeout" not in request.extensions


def test_total_timeout_is_distinguishable_from_read_timeout() -> None:
    assert issubclass(httpx.TotalTimeout, httpx.TimeoutException)
    assert not issubclass(httpx.TotalTimeout, httpx.ReadTimeout)


def test_total_timeout_bounds_streaming_response(clock: FakeClock) -> None:
    """
    A steady trickle of small chunks must not extend the total budget,
    even though each individual chunk arrives well within the read timeout.
    """
    chunks = [b"chunk"] * 10
    transport = ChunkedTransport(clock, chunks=chunks, step=0.3)
    timeout = httpx.Timeout(5.0, total=1.0)

    with httpx.Client(transport=transport, timeout=timeout) as client:
        with pytest.raises(httpx.TotalTimeout) as exc_info:
            client.get("http://example.org/")

    exc = exc_info.value
    assert not isinstance(exc, httpx.ReadTimeout)
    assert exc.request is not None

    # The budget was exhausted partway through the stream...
    assert clock.now == pytest.approx(1.2)
    stream = transport.stream
    assert isinstance(stream, TrickleStream)
    assert stream.chunks_served == 4
    # ...and the connection was released.
    assert stream.closed


@pytest.mark.anyio
async def test_total_timeout_bounds_streaming_response_async(
    clock: FakeClock,
) -> None:
    chunks = [b"chunk"] * 10
    transport = ChunkedTransport(clock, chunks=chunks, step=0.3)
    timeout = httpx.Timeout(5.0, total=1.0)

    async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
        with pytest.raises(httpx.TotalTimeout) as exc_info:
            await client.get("http://example.org/")

    exc = exc_info.value
    assert not isinstance(exc, httpx.ReadTimeout)
    assert exc.request is not None

    assert clock.now == pytest.approx(1.2)
    stream = transport.stream
    assert isinstance(stream, AsyncTrickleStream)
    assert stream.chunks_served == 4
    assert stream.closed


def test_total_timeout_shared_across_redirects(clock: FakeClock) -> None:
    """
    Three redirects must not be granted three separate budgets.
    """
    transport = RedirectTransport(clock, step=0.4, redirects=3)
    timeout = httpx.Timeout(5.0, total=1.0)

    with httpx.Client(transport=transport, timeout=timeout) as client:
        with pytest.raises(httpx.TotalTimeout):
            client.get("http://example.org/", follow_redirects=True)

    # The fourth request was never attempted, since the single shared
    # budget had been exhausted by the first three hops.
    assert len(transport.requests) == 3
    assert clock.now == pytest.approx(1.2)


@pytest.mark.anyio
async def test_total_timeout_shared_across_redirects_async(
    clock: FakeClock,
) -> None:
    transport = RedirectTransport(clock, step=0.4, redirects=3)
    timeout = httpx.Timeout(5.0, total=1.0)

    async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
        with pytest.raises(httpx.TotalTimeout):
            await client.get("http://example.org/", follow_redirects=True)

    assert len(transport.requests) == 3
    assert clock.now == pytest.approx(1.2)


def test_total_timeout_shared_across_auth_retries(clock: FakeClock) -> None:
    """
    Authentication retries draw down the same budget as everything else.
    """
    timeout = httpx.Timeout(5.0, total=1.0)
    auth = httpx.DigestAuth(username="user", password="pass")

    # Digest auth performs an initial request, then retries with a
    # digest header once it sees the 401 challenge.
    def handle_request(request: httpx.Request) -> httpx.Response:
        clock.advance(0.6)
        if "authorization" not in request.headers:
            return httpx.Response(
                401,
                headers=[
                    (b"www-authenticate", b'Digest realm="x", nonce="y", qop="auth"')
                ],
            )
        stream = TrickleStream(clock, chunks=[b"chunk"], step=0.5)
        return httpx.Response(200, stream=stream)

    transport = httpx.MockTransport(handle_request)
    with httpx.Client(transport=transport, timeout=timeout) as client:
        with pytest.raises(httpx.TotalTimeout):
            client.get("http://example.org/", auth=auth)


def test_total_timeout_disabled_leaves_timeouts_untouched(
    clock: FakeClock,
) -> None:
    """
    Without a total budget the existing timeouts are completely unaffected,
    however much time the overall request takes.
    """
    chunks = [b"chunk"] * 10
    transport = ChunkedTransport(clock, chunks=chunks, step=100.0)

    with httpx.Client(transport=transport) as client:
        response = client.get("http://example.org/")

    assert response.content == b"chunk" * 10
    assert clock.now == 1000.0


@pytest.mark.anyio
async def test_total_timeout_disabled_leaves_timeouts_untouched_async(
    clock: FakeClock,
) -> None:
    chunks = [b"chunk"] * 10
    transport = ChunkedTransport(clock, chunks=chunks, step=100.0)

    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get("http://example.org/")

    assert response.content == b"chunk" * 10
    assert clock.now == 1000.0


def test_total_timeout_response_closed_early_by_caller(clock: FakeClock) -> None:
    chunks = [b"chunk"] * 10
    transport = ChunkedTransport(clock, chunks=chunks, step=0.3)
    timeout = httpx.Timeout(5.0, total=1.0)

    with httpx.Client(transport=transport, timeout=timeout) as client:
        with client.stream("GET", "http://example.org/") as response:
            response.close()
        assert response.is_closed


@pytest.mark.anyio
async def test_total_timeout_response_closed_early_by_caller_async(
    clock: FakeClock,
) -> None:
    chunks = [b"chunk"] * 10
    transport = ChunkedTransport(clock, chunks=chunks, step=0.3)
    timeout = httpx.Timeout(5.0, total=1.0)

    async with httpx.AsyncClient(transport=transport, timeout=timeout) as client:
        async with client.stream("GET", "http://example.org/") as response:
            await response.aclose()
        assert response.is_closed


def test_total_timeout_clamps_per_operation_timeouts(clock: FakeClock) -> None:
    """
    Each stage of the request is capped at the remaining budget,
    rather than restarting the clock.
    """
    seen_timeouts: list[dict[str, float | None]] = []

    def handle_request(request: httpx.Request) -> httpx.Response:
        seen_timeouts.append(dict(request.extensions["timeout"]))
        clock.advance(0.4)
        if len(seen_timeouts) == 1:
            return httpx.Response(302, headers=[(b"location", b"/other")])
        return httpx.Response(200, content=b"Hello, world!")

    timeout = httpx.Timeout(5.0, total=1.0)
    transport = httpx.MockTransport(handle_request)
    with httpx.Client(transport=transport, timeout=timeout) as client:
        response = client.get("http://example.org/", follow_redirects=True)

    assert response.status_code == 200
    assert seen_timeouts[0] == {
        "connect": 1.0,
        "read": 1.0,
        "write": 1.0,
        "pool": 1.0,
    }
    assert seen_timeouts[1] == pytest.approx(
        {"connect": 0.6, "read": 0.6, "write": 0.6, "pool": 0.6}
    )

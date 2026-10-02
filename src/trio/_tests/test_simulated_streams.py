from __future__ import annotations

from math import inf

import pytest

from .. import _core, sleep
from ..abc import HalfCloseableStream
from ..testing import (
    LinkConfig,
    MockClock,
    SimulatedStream,
    check_half_closeable_stream,
    simulated_stream_pair,
)


async def read_exactly(stream: SimulatedStream, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = await stream.receive_some(n - len(buf))
        assert chunk, "unexpected EOF"
        buf += chunk
    return bytes(buf)


def test_link_config_validation() -> None:
    with pytest.raises(ValueError, match="bandwidth"):
        LinkConfig(bandwidth=0)
    with pytest.raises(ValueError, match="bandwidth"):
        LinkConfig(bandwidth=-3)
    with pytest.raises(ValueError, match="bandwidth"):
        LinkConfig(bandwidth=inf * 0)  # nan
    with pytest.raises(ValueError, match="latency"):
        LinkConfig(latency=-0.1)
    with pytest.raises(ValueError, match="buffer_size"):
        LinkConfig(buffer_size=0)
    with pytest.raises(ValueError, match="disconnect_after"):
        LinkConfig(disconnect_after=-1)
    with pytest.raises(TypeError):
        LinkConfig(buffer_size=1.5)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        LinkConfig(disconnect_after=1.5)  # type: ignore[arg-type]

    config = LinkConfig(bandwidth=100, latency=0.1, buffer_size=10, disconnect_after=5)
    assert config.bandwidth == 100
    assert config.latency == 0.1
    assert config.buffer_size == 10
    assert config.disconnect_after == 5
    assert "bandwidth=100.0" in repr(config)

    defaults = LinkConfig()
    assert defaults.bandwidth == inf
    assert defaults.latency == 0.0
    assert defaults.disconnect_after is None


async def test_simulated_stream_pair_basic() -> None:
    left, right = simulated_stream_pair()
    assert isinstance(left, HalfCloseableStream)
    assert isinstance(right, HalfCloseableStream)
    await left.send_all(b"123")
    assert await right.receive_some(10) == b"123"
    await right.send_all(bytearray(b"abc"))
    assert await left.receive_some(10) == b"abc"
    await left.send_all(memoryview(b"456"))
    await left.send_eof()
    assert await right.receive_some(10) == b"456"
    assert await right.receive_some(10) == b""


async def test_simulated_streams_with_generic_tests() -> None:
    async def stream_maker() -> tuple[SimulatedStream, SimulatedStream]:
        return simulated_stream_pair()

    await check_half_closeable_stream(stream_maker, None)

    async def small_buffer_stream_maker() -> tuple[SimulatedStream, SimulatedStream]:
        config = LinkConfig(buffer_size=16)
        return simulated_stream_pair(forward=config, backward=config)

    await check_half_closeable_stream(small_buffer_stream_maker, None)


async def test_request_response_protocol_timing(autojump_clock: MockClock) -> None:
    # A tiny bidirectional request/response protocol: 4-byte length header
    # (its own send_all) followed by the payload, in each direction.
    client, server = simulated_stream_pair(
        forward=LinkConfig(bandwidth=1000, latency=0.05),
        backward=LinkConfig(bandwidth=2000, latency=0.02),
    )
    record: dict[str, float] = {}

    async def send_message(stream: SimulatedStream, payload: bytes) -> None:
        await stream.send_all(len(payload).to_bytes(4, "little"))
        await stream.send_all(payload)

    async def server_main() -> None:
        header = await read_exactly(server, 4)
        record["request_first_byte"] = _core.current_time()
        length = int.from_bytes(header, "little")
        body = await read_exactly(server, length)
        record["request_complete"] = _core.current_time()
        await send_message(server, b"PONG:" + body)

    async def client_main() -> None:
        await send_message(client, b"ping" * 25)  # 100 bytes
        header = await read_exactly(client, 4)
        record["response_first_byte"] = _core.current_time()
        length = int.from_bytes(header, "little")
        body = await read_exactly(client, length)
        record["response_complete"] = _core.current_time()
        assert body == b"PONG:" + b"ping" * 25

    start = _core.current_time()
    async with _core.open_nursery() as nursery:
        nursery.start_soon(server_main)
        nursery.start_soon(client_main)

    # The 4-byte request header departs at 4/1000 s and takes another 50 ms
    # of propagation delay before the server can see its first byte.
    assert record["request_first_byte"] - start == pytest.approx(0.004 + 0.05)
    # The 100-byte request body finishes departing at 104/1000 s.
    assert record["request_complete"] - start == pytest.approx(0.104 + 0.05)
    # The 105-byte response is sent at 2000 B/s with 20 ms latency, and its
    # transmission only starts once the request has fully arrived.
    response_start = 0.104 + 0.05
    assert record["response_first_byte"] - start == pytest.approx(
        response_start + 4 / 2000 + 0.02,
    )
    assert record["response_complete"] - start == pytest.approx(
        response_start + 109 / 2000 + 0.02,
    )


async def test_throughput_and_backpressure(autojump_clock: MockClock) -> None:
    left, right = simulated_stream_pair(
        forward=LinkConfig(bandwidth=1000, latency=0.1, buffer_size=4096),
    )
    total = 4 * 4096
    times: dict[str, float] = {}

    async def sender() -> None:
        await left.send_all(b"x" * total)
        times["send_done"] = _core.current_time()

    async def receiver() -> None:
        assert await read_exactly(right, total) == b"x" * total
        times["receive_done"] = _core.current_time()

    start = _core.current_time()
    async with _core.open_nursery() as nursery:
        nursery.start_soon(sender)
        nursery.start_soon(receiver)

    # The buffer only holds 4096 bytes, so accepting the last segment has to
    # wait until the third segment has departed: backpressure in action.
    assert times["send_done"] - start == pytest.approx(3 * 4096 / 1000)
    # The last byte arrives after transmitting all 16384 bytes at 1000 B/s,
    # plus one latency period: exactly the configured throughput.
    assert times["receive_done"] - start == pytest.approx(4 * 4096 / 1000 + 0.1)


async def test_send_buffer_upper_bound(autojump_clock: MockClock) -> None:
    left, _right = simulated_stream_pair(
        forward=LinkConfig(bandwidth=1000, buffer_size=100),
    )
    # The first 100 bytes fit exactly into the send buffer.
    await left.send_all(b"a" * 100)
    assert _core.current_time() == pytest.approx(0)

    # The 101st byte cannot be accepted before the buffered segment has
    # departed at t=0.1: the buffer never holds more than its capacity.
    times: dict[str, float] = {}

    async def send_one_more() -> None:
        await left.send_all(b"b")
        times["one_more"] = _core.current_time()

    async with _core.open_nursery() as nursery:
        nursery.start_soon(send_one_more)
    assert times["one_more"] == pytest.approx(0.1)

    # One byte is buffered now (departs at 0.101); refill the other 99.
    await left.send_all(b"c" * 99)
    assert _core.current_time() == pytest.approx(0.1)
    # With the buffer full again, wait_send_all_might_not_block returns once
    # the one-byte segment departs and frees space.
    await left.wait_send_all_might_not_block()
    assert _core.current_time() == pytest.approx(0.101)


async def test_half_close_delivers_accepted_data_then_eof(
    autojump_clock: MockClock,
) -> None:
    left, right = simulated_stream_pair(
        forward=LinkConfig(bandwidth=1000, latency=0.05),
        backward=LinkConfig(bandwidth=1000, latency=0.05),
    )
    payload = bytes(range(256)) * 2  # 512 bytes
    record: dict[str, float] = {}

    async def sender() -> None:
        await left.send_all(payload)
        await left.send_eof()
        record["eof_sent"] = _core.current_time()

    async def receiver() -> None:
        assert await read_exactly(right, len(payload)) == payload
        record["data_done"] = _core.current_time()
        assert await right.receive_some(10) == b""
        record["eof_seen"] = _core.current_time()
        # The reverse direction is unaffected by the half-close.
        await right.send_all(b"still open")

    async with _core.open_nursery() as nursery:
        nursery.start_soon(sender)
        nursery.start_soon(receiver)

    # send_eof itself is instantaneous; the already-accepted data still
    # arrives at the usual time, and EOF comes only after all of it.
    assert record["eof_sent"] == pytest.approx(0)
    assert record["data_done"] == pytest.approx(0.512 + 0.05)
    assert record["eof_seen"] == pytest.approx(0.512 + 0.05)
    assert await read_exactly(left, 10) == b"still open"
    with pytest.raises(_core.ClosedResourceError):
        await left.send_all(b"nope")


async def test_disconnect_after(autojump_clock: MockClock) -> None:
    left, right = simulated_stream_pair(
        forward=LinkConfig(bandwidth=1000, latency=0.1, disconnect_after=10),
    )
    # Two segments that arrive at the same time; only the first 10 bytes
    # may be delivered before the link breaks.
    await left.send_all(b"a" * 10)
    await left.send_all(b"b" * 10)
    got = bytearray()
    with pytest.raises(_core.BrokenResourceError):
        while True:
            got += await right.receive_some(100)
    assert got == b"a" * 10
    # The break is sticky and visible on the send side too.
    with pytest.raises(_core.BrokenResourceError):
        await left.send_all(b"more")
    with pytest.raises(_core.BrokenResourceError):
        await left.wait_send_all_might_not_block()


async def test_disconnect_after_truncates_final_segment(
    autojump_clock: MockClock,
) -> None:
    left, right = simulated_stream_pair(
        forward=LinkConfig(bandwidth=100, buffer_size=10, disconnect_after=15),
    )
    record: dict[str, float] = {}
    got = bytearray()

    async def sender() -> None:
        with pytest.raises(_core.BrokenResourceError):
            await left.send_all(b"z" * 1000)
        record["sender_failed"] = _core.current_time()

    async def receiver() -> None:
        with pytest.raises(_core.BrokenResourceError):
            while True:
                got.extend(await right.receive_some(100))
        record["receiver_failed"] = _core.current_time()

    async with _core.open_nursery() as nursery:
        nursery.start_soon(sender)
        nursery.start_soon(receiver)

    # 10 bytes are delivered at t=0.1, 5 more (a truncated segment) at
    # t=0.2, at which point the link breaks: the blocked sender is woken up
    # with BrokenResourceError, and the receiver sees exactly 15 bytes.
    assert got == b"z" * 15
    assert record["receiver_failed"] == pytest.approx(0.2)
    assert record["sender_failed"] == pytest.approx(0.2)


async def test_disconnect_after_zero(autojump_clock: MockClock) -> None:
    left, right = simulated_stream_pair(forward=LinkConfig(disconnect_after=0))
    with pytest.raises(_core.BrokenResourceError):
        await left.send_all(b"x")
    with pytest.raises(_core.BrokenResourceError):
        await right.receive_some(1)


async def test_disconnect_after_not_reached(autojump_clock: MockClock) -> None:
    left, right = simulated_stream_pair(
        forward=LinkConfig(disconnect_after=100),
    )
    await left.send_all(b"short")
    assert await right.receive_some(10) == b"short"
    await left.send_eof()
    assert await right.receive_some(10) == b""


async def test_directions_do_not_block_each_other(autojump_clock: MockClock) -> None:
    left, right = simulated_stream_pair(
        forward=LinkConfig(bandwidth=10, buffer_size=10),
        # backward: default configuration, infinite bandwidth, no latency
    )
    # Fill the forward buffer completely; it takes 1 s to drain.
    await left.send_all(b"0123456789")
    times: dict[str, float] = {}

    async def clogged_sender() -> None:
        await left.send_all(b"x")
        times["clogged"] = _core.current_time()

    async def backward_sender() -> None:
        await right.send_all(b"ping")
        times["backward_sent"] = _core.current_time()

    async def backward_receiver() -> None:
        assert await read_exactly(left, 4) == b"ping"
        times["backward_received"] = _core.current_time()

    async with _core.open_nursery() as nursery:
        nursery.start_soon(clogged_sender)
        nursery.start_soon(backward_sender)
        nursery.start_soon(backward_receiver)

    # The clogged forward direction does not stall the backward direction.
    assert times["backward_sent"] == pytest.approx(0)
    assert times["backward_received"] == pytest.approx(0)
    assert times["clogged"] == pytest.approx(1.0)


async def test_cancelled_send_all_keeps_accepted_bytes(
    autojump_clock: MockClock,
) -> None:
    left, right = simulated_stream_pair(
        forward=LinkConfig(bandwidth=1000, buffer_size=10),
    )
    payload = b"a" * 25

    async def sender() -> None:
        await left.send_all(payload)

    async with _core.open_nursery() as nursery:
        nursery.start_soon(sender)
        # 10 bytes are accepted immediately, 10 more at t=0.01; at t=0.015
        # the sender is still blocked trying to accept the final 5.
        await sleep(0.015)
        nursery.cancel_scope.cancel()

    # The 20 bytes accepted before the cancellation are still delivered;
    # only the remaining 5 are discarded.
    await left.send_eof()
    got = bytearray()
    while True:
        chunk = await right.receive_some(100)
        if not chunk:
            break
        got += chunk
    assert got == payload[:20]


async def test_send_eof_after_close() -> None:
    left, _right = simulated_stream_pair()
    await left.aclose()
    with pytest.raises(_core.ClosedResourceError):
        await left.send_eof()


async def test_wait_send_all_might_not_block_after_peer_close() -> None:
    left, right = simulated_stream_pair()
    await right.aclose()
    with pytest.raises(_core.BrokenResourceError):
        await left.wait_send_all_might_not_block()

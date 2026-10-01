from __future__ import annotations

import os
import socket as stdlib_socket
import tempfile
from array import array

import pytest

import trio

from .. import socket as tsocket
from .._fd_channel import (
    _HEADER_STRUCT,
    MAX_FDS_PER_MESSAGE,
    MAX_MESSAGE_BYTES,
    FdChannel,
)
from ..testing import wait_all_tasks_blocked

pytestmark = pytest.mark.skipif(
    not hasattr(stdlib_socket, "SCM_RIGHTS"),
    reason="platform does not support SCM_RIGHTS fd passing",
)


def _make_channel_pair() -> tuple[FdChannel, FdChannel]:
    left, right = tsocket.socketpair()
    return FdChannel(left), FdChannel(right)


def _count_open_fds() -> int:
    for path in ("/proc/self/fd", "/dev/fd"):
        try:
            return len(os.listdir(path))
        except OSError:
            continue
    pytest.skip("cannot count open file descriptors on this platform")


async def _raw_send(sock: tsocket.SocketType, data: bytes, fds: list[int]) -> None:
    """Send a raw (possibly malformed) frame + fds on a Trio socket."""
    ancdata = []
    if fds:
        ancdata.append(
            (
                stdlib_socket.SOL_SOCKET,
                stdlib_socket.SCM_RIGHTS,
                array("i", fds).tobytes(),
            )
        )
    await sock.sendmsg([data], ancdata)


def _fresh_fd(contents: bytes = b"x") -> int:
    fd, path = tempfile.mkstemp()
    os.unlink(path)
    os.write(fd, contents)
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


async def test_rejects_unsupported_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    from .. import _fd_channel

    monkeypatch.setattr(_fd_channel, "_SUPPORTED", False)
    left, right = tsocket.socketpair()
    with left, right:
        with pytest.raises(NotImplementedError, match="SCM_RIGHTS"):
            FdChannel(left)


async def test_rejects_wrong_socket() -> None:
    stdlib_a, stdlib_b = stdlib_socket.socketpair()
    with stdlib_a, stdlib_b:
        with pytest.raises(TypeError, match="Trio socket"):
            FdChannel(stdlib_a)  # type: ignore[arg-type]

    # Unix sockets are required; TCP is not good enough
    with tsocket.socket() as tcp_sock:
        with pytest.raises(ValueError, match="AF_UNIX"):
            FdChannel(tcp_sock)

    # ... and they have to be stream sockets
    with tsocket.socket(family=tsocket.AF_UNIX, type=tsocket.SOCK_DGRAM) as dgram_sock:
        with pytest.raises(ValueError, match="SOCK_STREAM"):
            FdChannel(dgram_sock)


async def test_send_receive_tmpfile() -> None:
    sender, receiver = _make_channel_pair()
    async with sender, receiver:
        fd = _fresh_fd(b"hello fd passing")
        try:
            async with trio.open_nursery() as nursery:
                nursery.start_soon(sender.send_message, b"metadata", [fd])
                data, fds = await receiver.receive_message()
            assert data == b"metadata"
            assert len(fds) == 1
            # The received descriptor is a *new* handle; the sender's numeric
            # fd value means nothing on this side.
            assert fds[0] != fd
            assert not os.get_inheritable(fds[0])
            assert os.read(fds[0], 100) == b"hello fd passing"
            os.close(fds[0])
        finally:
            os.close(fd)


async def test_message_boundaries_preserved() -> None:
    sender, receiver = _make_channel_pair()
    async with sender, receiver:
        messages = [b"", b"a", b"bc" * 1000, bytes(range(256))]

        async def send_all() -> None:
            for message in messages:
                await sender.send_message(message)

        async with trio.open_nursery() as nursery:
            nursery.start_soon(send_all)
            for message in messages:
                data, fds = await receiver.receive_message()
                assert data == message
                assert fds == []


async def test_send_limits_enforced_locally() -> None:
    sender, receiver = _make_channel_pair()
    async with sender, receiver:
        with pytest.raises(ValueError, match="exceeds the limit"):
            await sender.send_message(b"x" * (MAX_MESSAGE_BYTES + 1))
        with pytest.raises(ValueError, match="file descriptors"):
            await sender.send_message(b"", list(range(MAX_FDS_PER_MESSAGE + 1)))
        # exact limits are fine
        async with trio.open_nursery() as nursery:
            nursery.start_soon(sender.send_message, b"x" * MAX_MESSAGE_BYTES)
            data, _ = await receiver.receive_message()
            assert len(data) == MAX_MESSAGE_BYTES


async def test_partial_sendmsg_does_not_duplicate_fds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sender, receiver = _make_channel_pair()
    async with sender, receiver:
        fd = _fresh_fd()
        try:
            real_sendmsg = sender.socket.sendmsg
            partial_write_happened = False

            async def flaky_sendmsg(buffers, ancdata=(), flags=0, address=None):
                nonlocal partial_write_happened
                # Force a partial write on the first call: only half the
                # frame goes out, but the ancillary data is consumed by the
                # kernel.
                if not partial_write_happened:
                    partial_write_happened = True
                    frame = bytes(buffers[0])
                    return await real_sendmsg(
                        [frame[: len(frame) // 2]], ancdata, flags, address
                    )
                return await real_sendmsg(buffers, ancdata, flags, address)

            monkeypatch.setattr(sender.socket, "sendmsg", flaky_sendmsg)
            payload = b"partial" * 100
            async with trio.open_nursery() as nursery:
                nursery.start_soon(sender.send_message, payload, [fd])
                data, fds = await receiver.receive_message()
            assert partial_write_happened
            assert data == payload
            # If the sender retried with ancillary data, we would see the fd
            # twice (and a count mismatch error) instead of exactly once.
            assert len(fds) == 1
            os.close(fds[0])
        finally:
            os.close(fd)


async def test_clean_eof_between_messages() -> None:
    sender, receiver = _make_channel_pair()
    async with sender, receiver:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(sender.send_message, b"last")
            assert (await receiver.receive_message())[0] == b"last"
        await sender.aclose()
        with pytest.raises(trio.EndOfChannel):
            await receiver.receive_message()


async def test_failed_receive_breaks_channel() -> None:
    sender, receiver = _make_channel_pair()
    async with sender, receiver:
        # Malformed header: absurd payload length
        bad_header = _HEADER_STRUCT.pack(MAX_MESSAGE_BYTES + 1, 0)
        await _raw_send(sender.socket, bad_header, [])
        with pytest.raises(trio.BrokenResourceError, match="exceeds the limit"):
            await receiver.receive_message()
        # The channel is now broken and refuses further operations
        with pytest.raises(trio.BrokenResourceError, match="broken state"):
            await receiver.receive_message()
        with pytest.raises(trio.BrokenResourceError, match="broken state"):
            await receiver.send_message(b"anything")


async def test_receive_failures_do_not_leak_fds() -> None:
    # Repeatedly provoke every receive-side failure mode with descriptors in
    # flight; the process-wide fd count must not grow.
    fds_before = _count_open_fds()

    for _ in range(10):
        # (a) malformed length in the header, fd attached
        sender, receiver = _make_channel_pair()
        async with sender, receiver:
            fd = _fresh_fd()
            bad_header = _HEADER_STRUCT.pack(MAX_MESSAGE_BYTES + 1, 1)
            await _raw_send(sender.socket, bad_header, [fd])
            os.close(fd)
            with pytest.raises(trio.BrokenResourceError, match="exceeds"):
                await receiver.receive_message()

        # (b) truncated message: header + fd arrive, then EOF mid-payload
        sender, receiver = _make_channel_pair()
        async with sender, receiver:
            fd = _fresh_fd()
            header = _HEADER_STRUCT.pack(100, 1)
            await _raw_send(sender.socket, header + b"short", [fd])
            os.close(fd)
            await sender.aclose()
            with pytest.raises(trio.BrokenResourceError, match="middle of a message"):
                await receiver.receive_message()

        # (c) fd count mismatch: header promises 2, only 1 arrives
        sender, receiver = _make_channel_pair()
        async with sender, receiver:
            fd = _fresh_fd()
            header = _HEADER_STRUCT.pack(4, 2)
            await _raw_send(sender.socket, header + b"data", [fd])
            os.close(fd)
            with pytest.raises(trio.BrokenResourceError, match="announced 2"):
                await receiver.receive_message()

        # (d) cancellation while a receive is in progress
        sender, receiver = _make_channel_pair()
        async with sender, receiver:
            fd = _fresh_fd()
            header = _HEADER_STRUCT.pack(10, 1)
            await _raw_send(sender.socket, header + b"half!", [fd])
            os.close(fd)
            async with trio.open_nursery() as nursery:
                nursery.start_soon(receiver.receive_message)
                await wait_all_tasks_blocked()
                nursery.cancel_scope.cancel()
            with pytest.raises(trio.BrokenResourceError, match="broken state"):
                await receiver.receive_message()

        # (e) peer blasts more fds than allowed
        sender, receiver = _make_channel_pair()
        async with sender, receiver:
            fds = [_fresh_fd() for _ in range(MAX_FDS_PER_MESSAGE + 1)]
            header = _HEADER_STRUCT.pack(0, MAX_FDS_PER_MESSAGE + 1)
            await _raw_send(sender.socket, header, fds)
            for fd in fds:
                os.close(fd)
            with pytest.raises(trio.BrokenResourceError):
                await receiver.receive_message()

    assert _count_open_fds() <= fds_before

from __future__ import annotations

import os
import socket as stdlib_socket
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import trio

from .. import socket as tsocket
from .._unix_fd_channel import (
    MAX_MESSAGE_DATA,
    MAX_MESSAGE_FDS,
    UnixFdChannel,
    UnixFdMessage,
    open_unix_fd_channel_pair,
)

pytestmark = pytest.mark.skipif(
    not hasattr(stdlib_socket, "AF_UNIX")
    or not hasattr(stdlib_socket.socket, "recvmsg"),
    reason="Unix fd channels require AF_UNIX and recvmsg",
)


async def test_socketpair_passes_temporary_file(tmp_path: Path) -> None:
    first_path = tmp_path / "metadata-first.bin"
    second_path = tmp_path / "metadata-second.bin"
    first_payload = b"first-temporary-file-payload"
    second_payload = b"second-temporary-file-payload"
    first_sender_fd = os.open(
        first_path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    second_sender_fd = os.open(
        second_path,
        os.O_RDWR | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    left, right = open_unix_fd_channel_pair()
    received_fds: list[int] = []

    try:
        os.write(first_sender_fd, first_payload)
        os.lseek(first_sender_fd, 0, os.SEEK_SET)
        os.write(second_sender_fd, second_payload)
        os.lseek(second_sender_fd, 0, os.SEEK_SET)

        await left.send(
            UnixFdMessage(b"metadata", [first_sender_fd, second_sender_fd]),
        )
        message = await right.receive()

        assert message.data == b"metadata"
        assert len(message.fds) == 2
        assert set(message.fds).isdisjoint({first_sender_fd, second_sender_fd})
        for received_fd, payload in zip(
            message.fds,
            (first_payload, second_payload),
            strict=True,
        ):
            assert not os.get_inheritable(received_fd)
            received_fds.append(received_fd)
            assert os.pread(received_fd, len(payload), 0) == payload

        inherited_fds = [fd for fd in message.fds if fd >= 3]
        assert len(inherited_fds) == len(message.fds)
        for inherited_fd in inherited_fds:
            child = subprocess.Popen(  # noqa: ASYNC220
                [
                    sys.executable,
                    "-c",
                    "import os,sys; sys.exit(os.path.isdir(f'/dev/fd/{sys.argv[1]}'))",
                    str(inherited_fd),
                ],
                close_fds=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            assert child.wait() == 0
    finally:
        os.close(first_sender_fd)
        os.close(second_sender_fd)
        await left.aclose()
        await right.aclose()
        for fd in received_fds:
            os.close(fd)


async def test_messages_keep_boundaries() -> None:
    left, right = open_unix_fd_channel_pair()

    try:
        await left.send((b"first", ()))
        await left.send((b"second-message", ()))
        assert await right.receive() == UnixFdMessage(b"first", ())
        assert await right.receive() == UnixFdMessage(b"second-message", ())
    finally:
        await left.aclose()
        await right.aclose()


async def test_end_of_channel() -> None:
    left, right = open_unix_fd_channel_pair()
    try:
        await left.aclose()

        with pytest.raises(trio.EndOfChannel):
            await right.receive()
    finally:
        await right.aclose()


async def test_constructor_requires_connected_unix_stream() -> None:
    stdlib_left, stdlib_right = stdlib_socket.socketpair()
    with pytest.raises(TypeError):
        UnixFdChannel.from_socket(stdlib_left)  # type: ignore[arg-type]
    stdlib_left.close()
    stdlib_right.close()

    datagram = tsocket.socket(tsocket.AF_UNIX, tsocket.SOCK_DGRAM)
    try:
        with pytest.raises(ValueError, match="SOCK_STREAM"):
            UnixFdChannel(datagram)
    finally:
        datagram.close()


async def test_limits_are_enforced() -> None:
    left, right = open_unix_fd_channel_pair()
    try:
        with pytest.raises(ValueError, match="maximum is"):
            await left.send((b"x" * (MAX_MESSAGE_DATA + 1), ()))
        with pytest.raises(ValueError, match="file descriptors"):
            await left.send((b"", [0] * (MAX_MESSAGE_FDS + 1)))

        await left.send((b"still usable", ()))
        assert await right.receive() == UnixFdMessage(b"still usable", ())
    finally:
        await left.aclose()
        await right.aclose()


async def test_partial_write_sends_ancillary_data_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    left, right = open_unix_fd_channel_pair()
    path = Path(os.devnull)
    file_fd = os.open(path, os.O_RDONLY)
    calls: list[int] = []
    original_sendmsg = left.socket.sendmsg

    async def split_sendmsg(
        buffers: list[memoryview],
        ancdata: object = (),
        flags: int = 0,
        address: object = None,
    ) -> int:
        calls.append(len(ancdata))
        if len(calls) == 1:
            buffers = [memoryview(buffers[0])[:1]]
        return await original_sendmsg(buffers, ancdata, flags, address)

    monkeypatch.setattr(left.socket, "sendmsg", split_sendmsg)

    try:
        await left.send((b"split", [file_fd]))
        message = await right.receive()
        assert message.data == b"split"
        assert len(message.fds) == 1
        assert calls[0] == 1
        assert calls[1:] == [0]
        os.close(message.fds[0])
    finally:
        os.close(file_fd)
        await left.aclose()
        await right.aclose()


async def test_truncated_ancillary_data_fails(tmp_path: Path) -> None:
    path = tmp_path / "truncated"
    file_fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    raw_sender, receiver_socket = tsocket.socketpair(
        tsocket.AF_UNIX,
        tsocket.SOCK_STREAM,
    )
    receiver = UnixFdChannel(receiver_socket)
    receiver._ancillary_size = 0

    try:
        await raw_sender.sendmsg(
            [struct.pack("=II", 0, 1)],
            [
                (
                    tsocket.SOL_SOCKET,
                    tsocket.SCM_RIGHTS,
                    struct.pack("=i", file_fd),
                )
            ],
        )
        with pytest.raises(ValueError, match=r"declared|truncated"):
            await receiver.receive()
        with pytest.raises(trio.ClosedResourceError):
            await receiver.receive()
    finally:
        raw_sender.close()
        await receiver.aclose()
        os.close(file_fd)


async def test_repeated_failures_close_received_fds(tmp_path: Path) -> None:
    path = tmp_path / "leak-check"
    file_fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(file_fd, b"payload")
    os.lseek(file_fd, 0, os.SEEK_SET)
    target = os.fstat(file_fd).st_dev, os.fstat(file_fd).st_ino

    def open_links() -> int:
        count = 0
        for entry in os.listdir("/dev/fd"):
            try:
                descriptor = int(entry)
                status = os.fstat(descriptor)
            except (OSError, ValueError):
                continue
            if (status.st_dev, status.st_ino) == target:
                count += 1
        return count

    failure_kinds = ("length", "mismatch", "too_many", "eof", "cancelled")

    try:
        assert open_links() == 1
        for iteration in range(10):
            kind = failure_kinds[iteration % len(failure_kinds)]
            raw_sender, receiver_socket = tsocket.socketpair(
                tsocket.AF_UNIX,
                tsocket.SOCK_STREAM,
            )
            receiver = UnixFdChannel(receiver_socket)
            outcome: list[BaseException] = []

            try:
                if kind == "length":
                    await raw_sender.send(
                        struct.pack("=II", MAX_MESSAGE_DATA + 1, 0),
                    )
                    with pytest.raises(ValueError, match="claims"):
                        await receiver.receive()

                elif kind == "mismatch":
                    await raw_sender.sendmsg(
                        [struct.pack("=II", 0, 3)],
                        [
                            (
                                tsocket.SOL_SOCKET,
                                tsocket.SCM_RIGHTS,
                                struct.pack("=2i", file_fd, file_fd),
                            )
                        ],
                    )
                    with pytest.raises(ValueError, match="declared"):
                        await receiver.receive()

                elif kind == "too_many":
                    await raw_sender.sendmsg(
                        [struct.pack("=II", 0, MAX_MESSAGE_FDS + 1)],
                        [
                            (
                                tsocket.SOL_SOCKET,
                                tsocket.SCM_RIGHTS,
                                struct.pack(
                                    f"={MAX_MESSAGE_FDS + 1}i",
                                    *([file_fd] * (MAX_MESSAGE_FDS + 1)),
                                ),
                            )
                        ],
                    )
                    with pytest.raises(ValueError, match="maximum is"):
                        await receiver.receive()

                elif kind == "eof":
                    await raw_sender.send(struct.pack("=II", 4, 0))
                    raw_sender.close()
                    with pytest.raises(ValueError, match="ended unexpectedly"):
                        await receiver.receive()

                else:

                    async def consume(
                        receiver: UnixFdChannel = receiver,
                        outcome: list[BaseException] = outcome,
                    ) -> None:
                        try:
                            await receiver.receive()
                        except BaseException as exc:  # type: ignore[explicit-any]
                            outcome.append(exc)

                    with trio.CancelScope() as scope:
                        async with trio.open_nursery() as nursery:
                            nursery.start_soon(consume)
                            await trio.testing.wait_all_tasks_blocked()
                            await raw_sender.sendmsg(
                                [struct.pack("=II", 1, 2)],
                                [
                                    (
                                        tsocket.SOL_SOCKET,
                                        tsocket.SCM_RIGHTS,
                                        struct.pack("=2i", file_fd, file_fd),
                                    )
                                ],
                            )
                            await trio.testing.wait_all_tasks_blocked()
                            scope.cancel()

                    assert isinstance(outcome[0], trio.Cancelled)

                with pytest.raises(trio.ClosedResourceError):
                    await receiver.receive()
                assert open_links() == 1
            finally:
                await receiver.aclose()
                raw_sender.close()

        assert open_links() == 1
    finally:
        os.close(file_fd)


def test_unsupported_platform_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from .. import _unix_fd_channel

    monkeypatch.setattr(
        _unix_fd_channel,
        "_supports_unix_fd_channels",
        lambda: False,
    )

    with pytest.raises(RuntimeError, match="not supported"):
        _unix_fd_channel.open_unix_fd_channel_pair()

    with pytest.raises(RuntimeError, match="not supported"):
        _unix_fd_channel.UnixFdChannel(object())

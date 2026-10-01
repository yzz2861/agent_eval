from __future__ import annotations

import errno
import os
import struct
from typing import TYPE_CHECKING, Protocol

import attrs

import trio

from . import socket as tsocket
from ._abc import Channel
from ._util import ConflictDetector, final

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ._socket import SocketType

    class _HasFileDescriptor(Protocol):
        def fileno(self) -> int: ...

    FileDescriptorLike = int | _HasFileDescriptor


MAX_MESSAGE_DATA = 64 * 1024
MAX_MESSAGE_FDS = 16

_HEADER = struct.Struct("=II")
_NATIVE_INT = struct.Struct("=i")

_AF_UNIX = getattr(tsocket, "AF_UNIX", None)
_SOCK_STREAM = getattr(tsocket, "SOCK_STREAM", None)
_SOL_SOCKET = getattr(tsocket, "SOL_SOCKET", None)
_SCM_RIGHTS = getattr(tsocket, "SCM_RIGHTS", None)
_RECV_CMSG_CLOEXEC = getattr(tsocket, "MSG_CMSG_CLOEXEC", 0)
_MSG_TRUNC = getattr(tsocket, "MSG_TRUNC", 0)
_MSG_CTRUNC = getattr(tsocket, "MSG_CTRUNC", 0)


@final
@attrs.frozen
class UnixFdMessage:
    """A message delivered through a :class:`UnixFdChannel`.

    The integer file descriptors in :attr:`fds` are newly created
    references in the receiving process. Their numeric values are unrelated
    to the numbers used by the sender.
    """

    data: bytes = b""
    fds: tuple[int, ...] = ()


def _supports_unix_fd_channels() -> bool:
    return (
        all(
            constant is not None
            for constant in (_AF_UNIX, _SOCK_STREAM, _SOL_SOCKET, _SCM_RIGHTS)
        )
        and hasattr(tsocket.SocketType, "sendmsg")
        and hasattr(
            tsocket.SocketType,
            "recvmsg",
        )
    )


def _require_unix_fd_channels() -> None:
    if not _supports_unix_fd_channels():
        raise RuntimeError(
            "Unix stream file descriptor passing requires AF_UNIX, "
            "SOCK_STREAM, SCM_RIGHTS, sendmsg, and recvmsg; this platform "
            "is not supported",
        )


def _close_fds(fds: Sequence[int]) -> None:
    for fd in fds:
        try:
            os.close(fd)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise


@final
class UnixFdChannel(Channel[UnixFdMessage]):
    """A message-oriented channel over a connected ``AF_UNIX`` stream socket.

    Each call to :meth:`send` produces exactly one message, and each call
    to :meth:`receive` returns exactly one message. File descriptors are
    passed with ``SCM_RIGHTS`` and are sent with the first ``sendmsg`` call
    for a frame, so partial writes never duplicate the ancillary data.

    A received file descriptor is a distinct reference owned by the
    receiving caller. Received descriptors are marked close-on-exec before
    the message is returned; on platforms without ``MSG_CMSG_CLOEXEC`` the
    flag is applied immediately after ``recvmsg`` returns. If reception is
    cancelled or fails, every descriptor received for that incomplete
    message is closed.

    A message may contain at most :data:`MAX_MESSAGE_DATA` bytes and
    :data:`MAX_MESSAGE_FDS` file descriptors.

    This class supports connected ``SOCK_STREAM`` Unix sockets only. It is
    not available on Windows or other platforms that lack the required
    socket APIs.
    """

    __slots__ = (
        "_ancillary_size",
        "_closed",
        "_receive_conflict_detector",
        "_send_conflict_detector",
        "socket",
    )

    def __init__(self, socket: SocketType) -> None:
        _require_unix_fd_channels()
        if not isinstance(socket, tsocket.SocketType):
            raise TypeError("UnixFdChannel requires a Trio socket object")
        if socket.family != _AF_UNIX:
            raise ValueError("UnixFdChannel requires an AF_UNIX socket")
        if socket.type != _SOCK_STREAM:
            raise ValueError("UnixFdChannel requires a SOCK_STREAM socket")

        self.socket = socket
        self._closed = False
        self._send_conflict_detector = ConflictDetector(
            "another task is currently sending on this UnixFdChannel",
        )
        self._receive_conflict_detector = ConflictDetector(
            "another task is currently receiving on this UnixFdChannel",
        )
        receive_buffer_size = socket.getsockopt(tsocket.SOL_SOCKET, tsocket.SO_RCVBUF)
        self._ancillary_size = max(
            tsocket.CMSG_SPACE(MAX_MESSAGE_FDS * _NATIVE_INT.size),
            tsocket.CMSG_SPACE(receive_buffer_size),
        )

    @classmethod
    def from_socket(cls, socket: SocketType) -> UnixFdChannel:
        """Wrap a connected Trio ``AF_UNIX`` stream socket."""
        return cls(socket)

    def _check_open(self) -> None:
        if self._closed or self.socket.fileno() == -1:
            raise trio.ClosedResourceError("this UnixFdChannel is closed")

    def _abort(self) -> None:
        self._closed = True
        self.socket.close()

    @staticmethod
    def _fd_number(descriptor: FileDescriptorLike) -> int:
        if hasattr(descriptor, "fileno"):
            descriptor = descriptor.fileno()
        if not isinstance(descriptor, int) or isinstance(descriptor, bool):
            raise TypeError("file descriptors must be integers or fileno() objects")
        if descriptor < 0:
            raise ValueError("file descriptors must be non-negative")
        return descriptor

    async def send(
        self,
        value: UnixFdMessage
        | tuple[bytes | bytearray | memoryview, Sequence[FileDescriptorLike]],
    ) -> None:
        """Send one bounded message and its file descriptors.

        The argument may be a :class:`UnixFdMessage` or a ``(data, fds)``
        tuple. File-like objects may be supplied in place of integer file
        descriptors; their :meth:`fileno` values are sent without taking
        ownership.
        """
        with self._send_conflict_detector:
            self._check_open()

            data, descriptors = self._encode_value(value)
            frame = _HEADER.pack(len(data), len(descriptors)) + data
            ancillary = (
                [
                    (
                        _SOL_SOCKET,
                        _SCM_RIGHTS,
                        struct.pack(f"={len(descriptors)}i", *descriptors),
                    )
                ]
                if descriptors
                else []
            )

            sent = 0
            try:
                with memoryview(frame) as frame_view:
                    while sent < len(frame_view):
                        sent += await self.socket.sendmsg(
                            [frame_view[sent:]],
                            ancillary if sent == 0 else [],
                        )
            except trio.Cancelled:
                self._abort()
                raise
            except OSError as exc:
                self._abort()
                raise trio.BrokenResourceError(
                    f"Unix fd channel connection broken: {exc}",
                ) from exc

    @staticmethod
    def _encode_value(
        value: UnixFdMessage
        | tuple[bytes | bytearray | memoryview, Sequence[FileDescriptorLike]],
    ) -> tuple[bytes, tuple[int, ...]]:
        if isinstance(value, UnixFdMessage):
            data = value.data
            descriptor_values = value.fds
        elif isinstance(value, tuple) and len(value) == 2:
            data, descriptor_values = value
        else:
            raise TypeError(
                "send() expects a UnixFdMessage or a (data, file descriptors) tuple",
            )

        if not isinstance(data, bytes | bytearray | memoryview):
            raise TypeError("message data must be bytes-like")
        data = bytes(data)
        if len(data) > MAX_MESSAGE_DATA:
            raise ValueError(
                f"message data is {len(data)} bytes; maximum is {MAX_MESSAGE_DATA}",
            )

        descriptors = tuple(
            UnixFdChannel._fd_number(descriptor) for descriptor in descriptor_values
        )
        if len(descriptors) > MAX_MESSAGE_FDS:
            raise ValueError(
                f"message has {len(descriptors)} file descriptors; maximum is "
                f"{MAX_MESSAGE_FDS}",
            )
        return data, descriptors

    @staticmethod
    def _extract_fds(
        ancillary: list[tuple[int, int, bytes]],
        received: list[int],
    ) -> None:
        new_fds: list[int] = []
        unexpected_ancillary = False
        malformed_ancillary = False
        for level, option, item in ancillary:
            if level != _SOL_SOCKET or option != _SCM_RIGHTS:
                unexpected_ancillary = True
                continue
            if len(item) % _NATIVE_INT.size:
                malformed_ancillary = True
            for (descriptor,) in struct.iter_unpack(
                "=i",
                item[: len(item) - len(item) % _NATIVE_INT.size],
            ):
                if descriptor < 0:
                    _close_fds(new_fds)
                    raise ValueError("received invalid file descriptor")
                new_fds.append(descriptor)

        try:
            for descriptor in new_fds:
                os.set_inheritable(descriptor, False)
        except BaseException:
            _close_fds(new_fds)
            raise

        if unexpected_ancillary or malformed_ancillary:
            _close_fds(new_fds)
            if unexpected_ancillary:
                raise ValueError("received unexpected ancillary data")
            raise ValueError("malformed SCM_RIGHTS ancillary data")
        received.extend(new_fds)

    async def receive(self) -> UnixFdMessage:
        """Receive one complete message and take ownership of its fds."""
        with self._receive_conflict_detector:
            self._check_open()

            chunks: list[bytes] = []
            received_fds: list[int] = []
            try:
                header_data = await self._receive_exact(
                    _HEADER.size,
                    chunks,
                    received_fds,
                    self._ancillary_size,
                    allow_end_of_channel=True,
                )
                data_length, descriptor_count = _HEADER.unpack(header_data)
                if data_length > MAX_MESSAGE_DATA:
                    raise ValueError(
                        f"message claims {data_length} bytes; "
                        f"maximum is {MAX_MESSAGE_DATA}",
                    )
                if descriptor_count > MAX_MESSAGE_FDS:
                    raise ValueError(
                        f"message claims {descriptor_count} file "
                        f"descriptors; maximum is {MAX_MESSAGE_FDS}",
                    )

                payload_chunks: list[bytes] = []
                payload_data = await self._receive_exact(
                    data_length,
                    payload_chunks,
                    received_fds,
                    0,
                    expect_ancillary=False,
                    allow_end_of_channel=False,
                )
                if len(received_fds) != descriptor_count:
                    raise ValueError(
                        f"message declared {descriptor_count} file "
                        f"descriptors but received {len(received_fds)}",
                    )

                return UnixFdMessage(payload_data, tuple(received_fds))
            except trio.EndOfChannel:
                raise
            except trio.Cancelled:
                _close_fds(received_fds)
                self._abort()
                raise
            except OSError as exc:
                _close_fds(received_fds)
                self._abort()
                raise trio.BrokenResourceError(
                    f"Unix fd channel connection broken: {exc}",
                ) from exc
            except BaseException:
                _close_fds(received_fds)
                self._abort()
                raise

    async def _receive_exact(
        self,
        size: int,
        chunks: list[bytes],
        received_fds: list[int],
        ancillary_size: int,
        *,
        expect_ancillary: bool = True,
        allow_end_of_channel: bool = True,
    ) -> bytes:
        while size:
            data, ancillary, flags, _address = await self.socket.recvmsg(
                size,
                ancillary_size,
                _RECV_CMSG_CLOEXEC,
            )
            if not data:
                if not allow_end_of_channel:
                    raise ValueError("Unix fd message ended unexpectedly")
                raise trio.EndOfChannel
            self._extract_fds(ancillary, received_fds)
            if flags & (_MSG_TRUNC | _MSG_CTRUNC):
                raise ValueError("received truncated Unix fd message")
            if not expect_ancillary and ancillary:
                raise ValueError("received ancillary data in message payload")
            chunks.append(data)
            size -= len(data)
        return b"".join(chunks)

    async def aclose(self) -> None:
        self._abort()
        await trio.lowlevel.checkpoint()


def open_unix_fd_channel_pair() -> tuple[UnixFdChannel, UnixFdChannel]:
    """Create a connected pair of :class:`UnixFdChannel` objects."""
    _require_unix_fd_channels()
    left_socket, right_socket = tsocket.socketpair(_AF_UNIX, _SOCK_STREAM)
    try:
        left_channel = UnixFdChannel(left_socket)
        right_channel = UnixFdChannel(right_socket)
    except BaseException:
        left_socket.close()
        right_socket.close()
        raise
    return left_channel, right_channel

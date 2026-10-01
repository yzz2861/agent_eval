"""Message-oriented channel with file descriptor passing.

This module builds a high-level, message-boundary-preserving channel on top
of the low-level :meth:`socket.socket.sendmsg`/:meth:`~socket.socket.recvmsg`
interface. Each message carries a small blob of metadata (arbitrary bytes)
plus zero or more already-open file descriptors, transferred between
processes with ``SCM_RIGHTS``.

Only connected Unix ``SOCK_STREAM`` sockets are supported. On platforms
without Unix domain sockets, ``sendmsg``/``recvmsg``, or
``SCM_RIGHTS`` (e.g. Windows), constructing :class:`FdChannel` raises
:exc:`NotImplementedError`.
"""

from __future__ import annotations

import os
import socket as _stdlib_socket
import struct
import warnings
from array import array
from typing import TYPE_CHECKING

import trio

from . import socket as tsocket
from ._highlevel_socket import _translate_socket_errors_to_stream_errors
from ._util import ConflictDetector, final

if TYPE_CHECKING:
    from ._socket import SocketType

#: Maximum number of payload bytes in a single message. Larger messages must
#: be split by the caller.
MAX_MESSAGE_BYTES = 2**16

#: Maximum number of file descriptors attached to a single message.
MAX_FDS_PER_MESSAGE = 16

# Message framing: a fixed-size big-endian header (payload length, fd count)
# followed by the payload. File descriptors travel out-of-band as ancillary
# data attached to the first sendmsg() of the message.
_HEADER_STRUCT = struct.Struct("!II")
_HEADER_SIZE = _HEADER_STRUCT.size

_INT_ARRAY = array("i")

#: True if this platform has everything we need (Unix sockets + sendmsg /
#: recvmsg + SCM_RIGHTS). Windows does not qualify.
_SUPPORTED = (
    hasattr(_stdlib_socket, "AF_UNIX")
    and hasattr(_stdlib_socket.socket, "sendmsg")
    and hasattr(_stdlib_socket.socket, "recvmsg")
    and hasattr(_stdlib_socket, "SCM_RIGHTS")
    and hasattr(_stdlib_socket, "CMSG_SPACE")
)

if _SUPPORTED:
    # Receive buffer for ancillary data. This is deliberately much larger
    # than MAX_FDS_PER_MESSAGE: both Linux and macOS refuse to send more
    # than ~253 descriptors per message (SCM_MAX_FD), so sizing the buffer
    # to hold 255 guarantees that a message which the kernel accepted can
    # never be truncated on receive. This matters because truncation is not
    # recoverable in userspace -- the kernel may install the truncated
    # descriptors into this process without reporting their numbers (macOS
    # does exactly that), which would leak them beyond our control.
    _KERNEL_MAX_FDS = 255
    _ANC_BUFSIZE = _stdlib_socket.CMSG_SPACE(_KERNEL_MAX_FDS * _INT_ARRAY.itemsize)
    _MSG_CTRUNC = getattr(_stdlib_socket, "MSG_CTRUNC", 0)


def _close_all(fds: list[int]) -> None:
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass
    fds.clear()


@final
class FdChannel(trio.abc.AsyncResource):
    """A message-oriented channel over a connected Unix stream socket.

    Each message consists of a byte string of metadata and zero or more open
    file descriptors. Message boundaries are preserved: one
    :meth:`send_message` call corresponds to exactly one
    :meth:`receive_message` call on the peer.

    Args:
      socket: A connected Trio socket object with family ``AF_UNIX`` and
          type ``SOCK_STREAM``.

    The number of payload bytes per message is limited to
    ``MAX_MESSAGE_BYTES`` and the number of file descriptors per message
    to ``MAX_FDS_PER_MESSAGE``; both limits are enforced on send and on
    receive.

    Received file descriptors are *new* handles in the receiving process;
    their numeric values are unrelated to the sender's. They are always
    delivered non-inheritable, so they cannot leak into child processes
    accidentally. Ownership of successfully delivered descriptors passes to
    the caller. If a receive fails for any reason -- truncation, a malformed
    header, a descriptor-count mismatch, or cancellation -- all descriptors
    that were received as part of the failed message are closed before the
    error propagates, and the channel is left in a broken state where
    further operations raise :exc:`trio.BrokenResourceError`.
    """

    def __init__(self, socket: SocketType) -> None:
        if not _SUPPORTED:
            raise NotImplementedError(
                "FdChannel requires Unix domain sockets with sendmsg/recvmsg "
                "and SCM_RIGHTS support, which this platform does not provide"
            )
        if not isinstance(socket, tsocket.SocketType):
            raise TypeError("FdChannel requires a Trio socket object")
        if socket.family != tsocket.AF_UNIX:
            raise ValueError("FdChannel requires an AF_UNIX socket")
        if socket.type != tsocket.SOCK_STREAM:
            raise ValueError("FdChannel requires a SOCK_STREAM socket")

        self._socket = socket
        self._send_conflict_detector = ConflictDetector(
            "another task is currently sending on this FdChannel",
        )
        self._receive_conflict_detector = ConflictDetector(
            "another task is currently receiving on this FdChannel",
        )
        self._broken = False

    @property
    def socket(self) -> SocketType:
        """The Trio socket object this channel wraps."""
        return self._socket

    def _check_usable(self) -> None:
        if self._broken:
            raise trio.BrokenResourceError(
                "this FdChannel was left in a broken state by a previous "
                "failed operation and can no longer be used"
            )
        if self._socket.fileno() == -1:
            raise trio.ClosedResourceError("socket was already closed")

    async def send_message(
        self,
        data: bytes | bytearray | memoryview,
        fds: list[int] | tuple[int, ...] = (),
    ) -> None:
        """Send one message: ``data`` plus zero or more open descriptors.

        The descriptors in ``fds`` remain owned by the caller; the
        receiver gets duplicates as new file descriptors. Raises
        :exc:`ValueError` if the message exceeds ``MAX_MESSAGE_BYTES``
        or ``MAX_FDS_PER_MESSAGE``.
        """
        payload = bytes(data)
        if len(payload) > MAX_MESSAGE_BYTES:
            raise ValueError(
                f"message payload of {len(payload)} bytes exceeds the "
                f"limit of {MAX_MESSAGE_BYTES} bytes"
            )
        fd_list = [int(fd) for fd in fds]
        if len(fd_list) > MAX_FDS_PER_MESSAGE:
            raise ValueError(
                f"cannot send {len(fd_list)} file descriptors in one "
                f"message; the limit is {MAX_FDS_PER_MESSAGE}"
            )

        header = _HEADER_STRUCT.pack(len(payload), len(fd_list))
        frame = header + payload
        with self._send_conflict_detector:
            self._check_usable()
            with _translate_socket_errors_to_stream_errors():
                if fd_list:
                    ancdata = [
                        (
                            _stdlib_socket.SOL_SOCKET,
                            _stdlib_socket.SCM_RIGHTS,
                            array("i", fd_list).tobytes(),
                        )
                    ]
                    sent = await self._socket.sendmsg([frame], ancdata)
                else:
                    sent = await self._socket.sendmsg([frame])
                # If the first sendmsg() wrote only part of the frame, the
                # ancillary data has already been consumed by the kernel and
                # must NOT be sent again -- the remaining bytes go out as
                # plain data.
                view = memoryview(frame)[sent:]
                while view:
                    sent = await self._socket.send(view)
                    view = view[sent:]

    async def receive_message(self) -> tuple[bytes, list[int]]:
        """Receive one message, returning ``(data, fds)``.

        The returned descriptors are new, non-inheritable handles owned by
        the caller. Raises :exc:`trio.EndOfChannel` if the peer closed the
        connection cleanly between messages. Any failure mid-message closes
        all descriptors received so far and breaks the channel.
        """
        with self._receive_conflict_detector:
            self._check_usable()
            received_fds: list[int] = []
            try:
                with _translate_socket_errors_to_stream_errors():
                    first = await self._read_chunk(_HEADER_SIZE, received_fds)
                if not first:
                    # Clean EOF exactly on a message boundary.
                    if received_fds:
                        raise trio.BrokenResourceError(
                            "received file descriptors without a message"
                        )
                    raise trio.EndOfChannel
                with _translate_socket_errors_to_stream_errors():
                    header = first + await self._read_exactly(
                        _HEADER_SIZE - len(first), received_fds
                    )
                payload_len, fd_count = _HEADER_STRUCT.unpack(header)
                if payload_len > MAX_MESSAGE_BYTES:
                    raise trio.BrokenResourceError(
                        f"peer announced a payload of {payload_len} bytes, "
                        f"which exceeds the limit of {MAX_MESSAGE_BYTES} "
                        "bytes"
                    )
                if fd_count > MAX_FDS_PER_MESSAGE:
                    raise trio.BrokenResourceError(
                        f"peer announced {fd_count} file descriptors, which "
                        f"exceeds the limit of {MAX_FDS_PER_MESSAGE}"
                    )
                with _translate_socket_errors_to_stream_errors():
                    payload = await self._read_exactly(payload_len, received_fds)
                if len(received_fds) != fd_count:
                    raise trio.BrokenResourceError(
                        f"message header announced {fd_count} file "
                        f"descriptors, but {len(received_fds)} were received"
                    )
            except trio.EndOfChannel:
                _close_all(received_fds)
                raise
            except BaseException:
                # Truncation, malformed header, count mismatch, cancellation,
                # ...: never leak descriptors we did not deliver, and never
                # trust the byte stream to be message-aligned again.
                _close_all(received_fds)
                self._broken = True
                raise
            # Descriptors must not leak into child processes. (CPython
            # already marks SCM_RIGHTS descriptors non-inheritable; do it
            # explicitly so the guarantee does not depend on that detail.)
            for fd in received_fds:
                os.set_inheritable(fd, False)
            return payload, received_fds

    async def _read_exactly(self, nbytes: int, received_fds: list[int]) -> bytes:
        buf = bytearray()
        while len(buf) < nbytes:
            chunk = await self._read_chunk(nbytes - len(buf), received_fds)
            if not chunk:
                raise trio.BrokenResourceError(
                    "connection closed in the middle of a message"
                )
            buf += chunk
        return bytes(buf)

    async def _read_chunk(self, want: int, received_fds: list[int]) -> bytes:
        with warnings.catch_warnings():
            # CPython warns about truncated/malformed ancillary data; we
            # detect the same condition ourselves via MSG_CTRUNC (and the
            # fd-count checks below) and report it as a BrokenResourceError.
            warnings.filterwarnings(
                "ignore",
                message="received malformed or improperly-truncated ancillary data",
                category=RuntimeWarning,
            )
            data, ancdata, msg_flags, _address = await self._socket.recvmsg(
                want, _ANC_BUFSIZE
            )
        # Parse the ancillary data *before* checking MSG_CTRUNC: even when
        # truncation occurred, the kernel may have delivered some
        # descriptors, and those must be accounted for (and closed on
        # failure) rather than leaked.
        for level, cmsg_type, cmsg_data in ancdata:
            if (
                level == _stdlib_socket.SOL_SOCKET
                and cmsg_type == _stdlib_socket.SCM_RIGHTS
            ):
                fd_array = array("i")
                usable = len(cmsg_data) - (len(cmsg_data) % _INT_ARRAY.itemsize)
                fd_array.frombytes(cmsg_data[:usable])
                received_fds.extend(fd_array.tolist())
        if msg_flags & _MSG_CTRUNC:
            raise trio.BrokenResourceError(
                "ancillary data was truncated; peer sent too many file "
                "descriptors at once"
            )
        if len(received_fds) > MAX_FDS_PER_MESSAGE:
            raise trio.BrokenResourceError(
                f"peer sent more than {MAX_FDS_PER_MESSAGE} file descriptors "
                "with one message"
            )
        return data

    async def aclose(self) -> None:
        """Close the underlying socket."""
        self._socket.close()
        await trio.lowlevel.checkpoint()

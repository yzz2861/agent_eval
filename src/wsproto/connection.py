"""
wsproto/connection
~~~~~~~~~~~~~~~~~~

An implementation of a WebSocket connection.
"""
from __future__ import annotations

from collections import deque
from enum import Enum
from typing import TYPE_CHECKING

from .events import (
    BytesMessage,
    CloseConnection,
    Event,
    Message,
    Ping,
    Pong,
    TextMessage,
)
from .frame_protocol import (
    CloseAuditCode,
    CloseAuditError,
    CloseAuditEvent,
    CloseReason,
    FrameProtocol,
    Opcode,
    ParseFailed,
)
from .utilities import LocalProtocolError

if TYPE_CHECKING:
    from collections.abc import Generator

    from .extensions import Extension


class ConnectionState(Enum):
    """
    RFC 6455, Section 4 - Opening Handshake
    """

    #: The opening handshake is in progress.
    CONNECTING = 0
    #: The opening handshake is complete.
    OPEN = 1
    #: The remote WebSocket has initiated a connection close.
    REMOTE_CLOSING = 2
    #: The local WebSocket (i.e. this instance) has initiated a connection close.
    LOCAL_CLOSING = 3
    #: The closing handshake has completed.
    CLOSED = 4
    #: The connection was rejected during the opening handshake.
    REJECTING = 5


class ConnectionType(Enum):
    """An enumeration of connection types."""

    #: This connection will act as client and talk to a remote server
    CLIENT = 1

    #: This connection will as as server and waits for client connections
    SERVER = 2


CLIENT = ConnectionType.CLIENT
SERVER = ConnectionType.SERVER


class Connection:
    """
    A low-level WebSocket connection object.

    This wraps two other protocol objects, an HTTP/1.1 protocol object used
    to do the initial HTTP upgrade handshake and a WebSocket frame protocol
    object used to exchange messages and other control frames.
    """

    def __init__(
        self,
        connection_type: ConnectionType,
        extensions: list[Extension] | None = None,
        trailing_data: bytes = b"",
        close_audit: bool = False,
    ) -> None:
        """
        Constructor

        :param wsproto.connection.ConnectionType connection_type: Whether this
            object is on the client- or server-side of a connection.
            To initialise as a client pass ``CLIENT`` otherwise pass ``SERVER``.
        :param list extensions: The proposed extensions.
        :param bytes trailing_data: Data that has been received, but not yet
            processed.
        :param bool close_audit: When true, validate outbound close codes and
            reasons and keep a one-to-one audit trail for close-handshake
            failures. Defaults to false so the legacy API and event ordering
            remain unchanged.
        """
        self.client = connection_type is ConnectionType.CLIENT
        self._events: deque[Event] = deque()
        self.close_audit = close_audit
        self._proto = FrameProtocol(
            self.client,
            extensions or [],
            close_audit=close_audit,
        )
        self._state = ConnectionState.OPEN
        self.receive_data(trailing_data)

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def audit_events(self) -> tuple[CloseAuditEvent, ...]:
        """Stable close-handshake findings, in the order they were observed."""
        return self._proto.audit_events

    def send(self, event: Event) -> bytes:
        data = b""
        if isinstance(event, Message) and self.state == ConnectionState.OPEN:
            data += self._proto.send_data(event.data, event.message_finished)
        elif isinstance(event, Ping) and self.state == ConnectionState.OPEN:
            data += self._proto.ping(event.payload)
        elif isinstance(event, Pong) and self.state == ConnectionState.OPEN:
            data += self._proto.pong(event.payload)
        elif isinstance(event, CloseConnection) and self.state in {
            ConnectionState.OPEN,
            ConnectionState.REMOTE_CLOSING,
        }:
            try:
                data += self._proto.close(event.code, event.reason)
            except CloseAuditError as exc:
                error = LocalProtocolError(str(exc))
                error.audit_code = exc.reason_code  # type: ignore[attr-defined]
                raise error from exc
            if self.state == ConnectionState.REMOTE_CLOSING:
                self._state = ConnectionState.CLOSED
            else:
                self._state = ConnectionState.LOCAL_CLOSING
        else:
            msg = f"Event {event} cannot be sent in state {self.state}."
            raise LocalProtocolError(
                msg,
            )
        return data

    def receive_data(self, data: bytes | None) -> None:
        """
        Pass some received data to the connection for handling.

        A list of events that the remote peer triggered by sending this data can
        be retrieved with :meth:`~wsproto.connection.Connection.events`.
        Passing bytes here does not itself apply every state transition caused
        by those events. For example, a remote close frame changes the
        connection state when its corresponding
        :class:`~wsproto.events.CloseConnection` event is yielded from
        :meth:`~wsproto.connection.Connection.events`.

        :param data: The data received from the remote peer on the network.
        :type data: ``bytes``
        """
        if data is None:
            # "If _The WebSocket Connection is Closed_ and no Close control
            # frame was received by the endpoint (such as could occur if the
            # underlying transport connection is lost), _The WebSocket
            # Connection Close Code_ is considered to be 1006."
            self._state = ConnectionState.CLOSED
            if self.close_audit and not self._proto._close_received:
                self._proto._record_audit(
                    CloseAuditCode.ABNORMAL_EOF,
                    "transport EOF without a CLOSE frame",
                    CloseReason.ABNORMAL_CLOSURE,
                )
            self._events.append(CloseConnection(code=CloseReason.ABNORMAL_CLOSURE))
            return

        receive_states = {ConnectionState.OPEN, ConnectionState.LOCAL_CLOSING}
        if self.close_audit:
            receive_states.add(ConnectionState.REMOTE_CLOSING)
        if self.state in receive_states:
            self._proto.receive_bytes(data)
        elif self.state is ConnectionState.CLOSED:
            msg = "Connection already closed."
            raise LocalProtocolError(msg)
        else:
            pass  # pragma: no cover

    def events(self) -> Generator[Event, None, None]:
        """
        Return a generator that provides any events that have been generated
        by protocol activity.

        Iterating this generator can advance the connection state while
        received frames are converted into events. For example, yielding a
        remote :class:`~wsproto.events.CloseConnection` event moves the
        connection into
        :attr:`~wsproto.connection.ConnectionState.REMOTE_CLOSING`.

        :returns: generator of :class:`Event <wsproto.events.Event>` subclasses
        """
        while self._events:
            yield self._events.popleft()

        try:
            for frame in self._proto.received_frames():
                if frame.opcode is Opcode.PING:
                    assert frame.frame_finished
                    assert frame.message_finished
                    assert isinstance(frame.payload, (bytes, bytearray))
                    yield Ping(payload=frame.payload)

                elif frame.opcode is Opcode.PONG:
                    assert frame.frame_finished
                    assert frame.message_finished
                    assert isinstance(frame.payload, (bytes, bytearray))
                    yield Pong(payload=frame.payload)

                elif frame.opcode is Opcode.CLOSE:
                    assert isinstance(frame.payload, tuple)
                    code, reason = frame.payload
                    if self.state is ConnectionState.LOCAL_CLOSING:
                        self._state = ConnectionState.CLOSED
                    else:
                        self._state = ConnectionState.REMOTE_CLOSING
                    yield CloseConnection(code=code, reason=reason)

                elif frame.opcode is Opcode.TEXT:
                    assert isinstance(frame.payload, str)
                    yield TextMessage(
                        data=frame.payload,
                        frame_finished=frame.frame_finished,
                        message_finished=frame.message_finished,
                    )

                elif frame.opcode is Opcode.BINARY:
                    assert isinstance(frame.payload, (bytes, bytearray))
                    yield BytesMessage(
                        data=frame.payload,
                        frame_finished=frame.frame_finished,
                        message_finished=frame.message_finished,
                    )

                else:
                    pass  # pragma: no cover
        except ParseFailed as exc:
            yield CloseConnection(code=exc.code, reason=str(exc))

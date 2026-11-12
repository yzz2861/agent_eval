from __future__ import annotations

import struct

import pytest

from wsproto.connection import CLIENT, SERVER, Connection, ConnectionState
from wsproto.events import (
    BytesMessage,
    CloseConnection,
    Ping,
    Pong,
    Request,
    TextMessage,
)
from wsproto.frame_protocol import CloseReason
from wsproto.utilities import LocalProtocolError


def _frame(opcode: int, payload: bytes, fin: bool = True) -> bytes:
    first = (0x80 if fin else 0) | opcode
    length = len(payload)
    if length <= 125:
        header = bytes([first, length])
    elif length <= 2**16 - 1:
        header = bytes([first, 126]) + struct.pack("!H", length)
    else:
        header = bytes([first, 127]) + struct.pack("!Q", length)
    return header + payload


@pytest.mark.parametrize("client_sends", [True, False])
@pytest.mark.parametrize("final", [True, False])
def test_send_message(client_sends: bool, final: bool) -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    if client_sends:
        local = client
        remote = server
    else:
        local = server
        remote = client

    data = b"x" * 23
    remote.receive_data(local.send(BytesMessage(data=data, message_finished=final)))
    if not final:
        assert list(remote.events()) == []
        remote.receive_data(
            local.send(BytesMessage(data=b"y", message_finished=True)),
        )
    event = next(remote.events())
    assert isinstance(event, BytesMessage)
    assert event.data == (data if final else data + b"y")
    assert event.message_finished is True


@pytest.mark.parametrize("client_sends", [True, False])
@pytest.mark.parametrize(
    "code, reason",
    [(CloseReason.NORMAL_CLOSURE, "bye"), (CloseReason.GOING_AWAY, "👋👋")],
)
def test_closure(client_sends: bool, code: CloseReason, reason: str) -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    if client_sends:
        local = client
        remote = server
    else:
        local = server
        remote = client

    remote.receive_data(local.send(CloseConnection(code=code, reason=reason)))
    event = next(remote.events())
    assert isinstance(event, CloseConnection)
    assert event.code is code
    assert event.reason == reason

    assert remote.state is ConnectionState.REMOTE_CLOSING
    assert local.state is ConnectionState.LOCAL_CLOSING

    local.receive_data(remote.send(event.response()))
    event = next(local.events())
    assert isinstance(event, CloseConnection)
    assert event.code is code
    assert event.reason == reason

    assert remote.state is ConnectionState.CLOSED  # type: ignore[comparison-overlap]
    assert local.state is ConnectionState.CLOSED

    with pytest.raises(LocalProtocolError):
        local.receive_data(b"foobar")


def test_abnormal_closure() -> None:
    client = Connection(CLIENT)
    client.receive_data(None)
    event = next(client.events())
    assert isinstance(event, CloseConnection)
    assert event.code is CloseReason.ABNORMAL_CLOSURE
    assert client.state is ConnectionState.CLOSED


def test_close_whilst_closing() -> None:
    client = Connection(CLIENT)
    client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))
    with pytest.raises(LocalProtocolError):
        client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))


def test_send_after_close() -> None:
    client = Connection(CLIENT)
    client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))
    with pytest.raises(LocalProtocolError):
        client.send(TextMessage(data="", message_finished=True))


@pytest.mark.parametrize("client_sends", [True, False])
def test_ping_pong(client_sends: bool) -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    if client_sends:
        local = client
        remote = server
    else:
        local = server
        remote = client

    payload = b"x" * 23
    remote.receive_data(local.send(Ping(payload=payload)))
    event = next(remote.events())
    assert isinstance(event, Ping)
    assert event.payload == payload

    local.receive_data(remote.send(event.response()))
    event = next(local.events())
    assert isinstance(event, Pong)
    assert event.payload == payload


def test_unsolicited_pong() -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    payload = b"x" * 23
    server.receive_data(client.send(Pong(payload=payload)))
    event = next(server.events())
    assert isinstance(event, Pong)
    assert event.payload == payload


@pytest.mark.parametrize("split_message", [True, False])
def test_data(split_message: bool) -> None:
    client = Connection(CLIENT)
    server = Connection(SERVER)

    data = "ƒñö®∂😎"
    server.receive_data(
        client.send(TextMessage(data=data, message_finished=not split_message)),
    )
    if split_message:
        assert list(server.events()) == []
        server.receive_data(client.send(TextMessage(data="", message_finished=True)))
    event = next(server.events())
    assert isinstance(event, TextMessage)
    assert event.data == data
    assert event.message_finished is True


def test_frame_protocol_gets_fed_garbage() -> None:
    client = Connection(CLIENT)

    payload = b"x" * 23
    frame = b"\x09" + bytearray([len(payload)]) + payload

    client.receive_data(frame)
    event = next(client.events())
    assert isinstance(event, CloseConnection)
    assert event.code == CloseReason.PROTOCOL_ERROR


def test_send_invalid_event() -> None:
    client = Connection(CLIENT)
    with pytest.raises(LocalProtocolError):
        client.send(Request(target="/", host="wsproto"))


def test_receive_data_when_closed() -> None:
    client = Connection(CLIENT)
    client._state = ConnectionState.CLOSED
    with pytest.raises(LocalProtocolError):
        client.receive_data(b"something")


def test_text_codepoint_split_across_frames_with_ping() -> None:
    client = Connection(CLIENT)
    text = "日志😀"
    payload = text.encode("utf-8")
    split = payload.index(b"\xf0\x9f\x98") + 2

    client.receive_data(
        _frame(0x1, payload[:split], fin=False)
        + _frame(0x9, b"ping")
        + _frame(0x0, payload[split:], fin=True),
    )
    events = list(client.events())
    assert [type(event) for event in events] == [Ping, TextMessage]
    assert events[1].data == text
    assert events[1].message_finished is True


def test_invalid_utf8_closes_without_data_event() -> None:
    client = Connection(CLIENT)
    client.receive_data(
        _frame(0x1, b"prefix", fin=False) + _frame(0x0, b"\xff", fin=True),
    )
    events = list(client.events())
    assert len(events) == 1
    assert isinstance(events[0], CloseConnection)
    assert events[0].code is CloseReason.INVALID_FRAME_PAYLOAD_DATA


def test_binary_message_skips_utf8_validation() -> None:
    client = Connection(CLIENT)
    client.receive_data(_frame(0x2, b"\xff", fin=True))
    events = list(client.events())
    assert len(events) == 1
    assert isinstance(events[0], BytesMessage)
    assert events[0].data == b"\xff"


def test_close_before_final_fragment_discards_message() -> None:
    client = Connection(CLIENT)
    client.receive_data(
        _frame(0x1, b"partial", fin=False)
        + _frame(0x8, struct.pack("!H", CloseReason.NORMAL_CLOSURE)),
    )
    events = list(client.events())
    assert len(events) == 1
    assert isinstance(events[0], CloseConnection)
    assert client.state is ConnectionState.REMOTE_CLOSING


def test_new_text_frame_during_fragmented_message() -> None:
    client = Connection(CLIENT)
    client.receive_data(
        _frame(0x1, b"part", fin=False) + _frame(0x1, b"rest", fin=True),
    )
    events = list(client.events())
    assert len(events) == 1
    assert isinstance(events[0], CloseConnection)
    assert events[0].code is CloseReason.PROTOCOL_ERROR


def test_empty_starting_continuation_is_a_protocol_error() -> None:
    client = Connection(CLIENT)
    client.receive_data(_frame(0x0, b"", fin=True))
    events = list(client.events())
    assert len(events) == 1
    assert isinstance(events[0], CloseConnection)
    assert events[0].code is CloseReason.PROTOCOL_ERROR


def test_unknown_opcode_is_a_protocol_error() -> None:
    client = Connection(CLIENT)
    client.receive_data(_frame(0xB, b"x", fin=True))
    events = list(client.events())
    assert len(events) == 1
    assert isinstance(events[0], CloseConnection)
    assert events[0].code is CloseReason.PROTOCOL_ERROR


def test_control_frames_do_not_change_message_length() -> None:
    client = Connection(CLIENT)
    first = b"x" * 125
    second = b"y" * 126
    client.receive_data(
        _frame(0x1, first, fin=False)
        + _frame(0x9, b"z" * 125)
        + _frame(0x0, second, fin=True),
    )
    events = list(client.events())
    assert len(events) == 2
    assert isinstance(events[0], Ping)
    assert isinstance(events[1], TextMessage)
    assert events[1].data == (first + second).decode("utf-8")

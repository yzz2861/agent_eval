from __future__ import annotations

import struct

import pytest

from wsproto import frame_protocol as fp
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
    event = next(remote.events())
    assert isinstance(event, BytesMessage)
    assert event.data == data
    assert event.message_finished is final


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
    event = next(server.events())
    assert isinstance(event, TextMessage)
    assert event.message_finished is not split_message


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


def _close_frame(code: int, reason: str = "") -> bytes:
    payload = struct.pack("!H", code) + reason.encode("utf-8")
    return b"\x88" + bytearray([len(payload)]) + payload


class TestCloseAudit:
    def test_duplicate_close_in_separate_buffers(self) -> None:
        client = Connection(CLIENT, close_audit=True)

        client.receive_data(_close_frame(CloseReason.NORMAL_CLOSURE))
        first = list(client.events())
        client.receive_data(_close_frame(CloseReason.GOING_AWAY))
        second = list(client.events())

        assert len(first) == 1
        assert second == []
        assert client.state is ConnectionState.REMOTE_CLOSING
        assert [audit.reason_code for audit in client.audit_events] == [
            fp.CloseAuditCode.DUPLICATE_CLOSE,
        ]

    def test_eof_after_invalid_close_keeps_eof_attribution_separate(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        client.receive_data(_close_frame(2998))
        invalid_close = next(client.events())
        assert invalid_close.code is CloseReason.PROTOCOL_ERROR

        client.receive_data(None)
        eof_close = next(client.events())

        assert eof_close.code is CloseReason.ABNORMAL_CLOSURE
        assert [audit.reason_code for audit in client.audit_events] == [
            fp.CloseAuditCode.INVALID_CLOSE_CODE,
            fp.CloseAuditCode.ABNORMAL_EOF,
        ]

    def test_eof_while_local_closing_is_abnormal(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE))
        assert client.state is ConnectionState.LOCAL_CLOSING

        client.receive_data(None)
        event = next(client.events())

        assert event.code is CloseReason.ABNORMAL_CLOSURE
        assert client.state is ConnectionState.CLOSED
        assert [audit.reason_code for audit in client.audit_events] == [
            fp.CloseAuditCode.ABNORMAL_EOF,
        ]

    def test_normal_mutual_close(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        server = Connection(SERVER, close_audit=True)

        server.receive_data(
            client.send(CloseConnection(code=CloseReason.NORMAL_CLOSURE)),
        )
        remote_close = next(server.events())
        assert remote_close.code is CloseReason.NORMAL_CLOSURE
        assert server.state is ConnectionState.REMOTE_CLOSING
        assert client.state is ConnectionState.LOCAL_CLOSING

        client.receive_data(server.send(remote_close.response()))
        local_close = next(client.events())
        assert local_close.code is CloseReason.NORMAL_CLOSURE

        assert client.state is ConnectionState.CLOSED
        assert server.state is ConnectionState.CLOSED
        assert client.audit_events == ()
        assert server.audit_events == ()

    def test_peer_initiated_close_preserves_code_and_chinese_reason(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        server = Connection(SERVER, close_audit=True)
        reason = "服务端即将重启"
        frame = _close_frame(CloseReason.GOING_AWAY, reason)

        client.receive_data(frame)
        event = next(client.events())

        assert isinstance(event, CloseConnection)
        assert event.code is CloseReason.GOING_AWAY
        assert event.reason == reason
        assert client.state is ConnectionState.REMOTE_CLOSING
        assert client.audit_events == ()

        response = client.send(event.response())
        server.receive_data(response)
        echoed = next(server.events())
        assert echoed.code is CloseReason.GOING_AWAY
        assert echoed.reason == reason
        assert client.state is ConnectionState.CLOSED
        assert client.audit_events == ()
        assert server.audit_events == ()

    def test_duplicate_close_yields_one_event_and_one_audit(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        client.receive_data(
            _close_frame(CloseReason.NORMAL_CLOSURE)
            + _close_frame(CloseReason.GOING_AWAY),
        )

        events = list(client.events())

        assert len(events) == 1
        assert events[0].code is CloseReason.NORMAL_CLOSURE
        assert client.state is ConnectionState.REMOTE_CLOSING
        assert [audit.reason_code for audit in client.audit_events] == [
            fp.CloseAuditCode.DUPLICATE_CLOSE,
        ]
        assert client.audit_events[0].close_code is CloseReason.GOING_AWAY

    def test_invalid_outbound_code_is_rejected_without_state_change(self) -> None:
        client = Connection(CLIENT, close_audit=True)

        for code in (
            CloseReason.NO_STATUS_RCVD,
            CloseReason.ABNORMAL_CLOSURE,
            CloseReason.TLS_HANDSHAKE_FAILED,
            1004,
            2999,
            5000,
        ):
            client = Connection(CLIENT, close_audit=True)
            with pytest.raises(LocalProtocolError) as exc:
                client.send(CloseConnection(code=code))
            assert exc.value.audit_code is fp.CloseAuditCode.INVALID_CLOSE_CODE
            assert client.state is ConnectionState.OPEN
            assert client.audit_events[-1].reason_code is (
                fp.CloseAuditCode.INVALID_CLOSE_CODE
            )

    def test_invalid_inbound_reserved_code(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        client.receive_data(_close_frame(2998))

        event = next(client.events())

        assert isinstance(event, CloseConnection)
        assert event.code is CloseReason.PROTOCOL_ERROR
        assert client.state is ConnectionState.OPEN
        assert [audit.reason_code for audit in client.audit_events] == [
            fp.CloseAuditCode.INVALID_CLOSE_CODE,
        ]

    def test_non_utf8_reason(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        payload = struct.pack("!H", CloseReason.NORMAL_CLOSURE) + b"\xff\xfe"
        client.receive_data(b"\x88\x04" + payload)

        event = next(client.events())

        assert isinstance(event, CloseConnection)
        assert event.code is CloseReason.INVALID_FRAME_PAYLOAD_DATA
        assert [audit.reason_code for audit in client.audit_events] == [
            fp.CloseAuditCode.INVALID_CLOSE_REASON,
        ]

    def test_overlong_reason(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        payload = struct.pack("!H", CloseReason.NORMAL_CLOSURE) + b"x" * 124
        frame = b"\x88\x7e\x00\x7e" + payload
        client.receive_data(frame)

        event = next(client.events())

        assert isinstance(event, CloseConnection)
        assert [audit.reason_code for audit in client.audit_events] == [
            fp.CloseAuditCode.CLOSE_REASON_TOO_LONG,
        ]

    def test_overlong_chinese_reason_is_rejected_before_sending(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        reason = "中" * 42

        with pytest.raises(LocalProtocolError) as exc:
            client.send(
                CloseConnection(
                    code=CloseReason.NORMAL_CLOSURE,
                    reason=reason,
                ),
            )

        assert exc.value.audit_code is fp.CloseAuditCode.CLOSE_REASON_TOO_LONG
        assert client.state is ConnectionState.OPEN
        assert client.audit_events[0].close_reason == reason

    def test_abnormal_eof_keeps_1006_and_does_not_fabricate_1000(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        client.receive_data(None)

        event = next(client.events())

        assert isinstance(event, CloseConnection)
        assert event.code is CloseReason.ABNORMAL_CLOSURE
        assert client.state is ConnectionState.CLOSED
        assert [audit.reason_code for audit in client.audit_events] == [
            fp.CloseAuditCode.ABNORMAL_EOF,
        ]
        assert client.audit_events[0].close_code is CloseReason.ABNORMAL_CLOSURE

    def test_data_after_close(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        client.receive_data(
            _close_frame(CloseReason.NORMAL_CLOSURE) + b"\x81\x05hello",
        )

        events = list(client.events())

        assert len(events) == 1
        assert isinstance(events[0], CloseConnection)
        assert [audit.reason_code for audit in client.audit_events] == [
            fp.CloseAuditCode.DATA_AFTER_CLOSE,
        ]

    def test_duplicate_close_then_data_are_both_audited(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        client.receive_data(
            _close_frame(CloseReason.NORMAL_CLOSURE)
            + _close_frame(CloseReason.GOING_AWAY)
            + b"\x81\x05hello",
        )

        events = list(client.events())

        assert len(events) == 1
        assert [audit.reason_code for audit in client.audit_events] == [
            fp.CloseAuditCode.DUPLICATE_CLOSE,
            fp.CloseAuditCode.DATA_AFTER_CLOSE,
        ]

    def test_outbound_lone_surrogate_reason(self) -> None:
        client = Connection(CLIENT, close_audit=True)
        with pytest.raises(LocalProtocolError) as exc:
            client.send(
                CloseConnection(
                    code=CloseReason.NORMAL_CLOSURE,
                    reason="broken\ud800",
                ),
            )
        assert exc.value.audit_code is fp.CloseAuditCode.INVALID_CLOSE_REASON
        assert client.audit_events[0].reason_code is (
            fp.CloseAuditCode.INVALID_CLOSE_REASON
        )

    def test_default_mode_has_empty_audit_trail_and_legacy_eof(self) -> None:
        client = Connection(CLIENT)
        client.receive_data(None)
        event = next(client.events())

        assert event.code is CloseReason.ABNORMAL_CLOSURE
        assert client.state is ConnectionState.CLOSED
        assert client.audit_events == ()

from __future__ import annotations

import pytest

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.settings


REQUEST_HEADERS = [
    (":authority", "example.com"),
    (":path", "/"),
    (":scheme", "https"),
    (":method", "GET"),
]


def priority_update_frame(
    target_stream_id: int,
    field: bytes,
    *,
    frame_stream_id: int = 0,
) -> bytes:
    length = 4 + len(field)
    return (
        bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF, 0x10, 0])
        + frame_stream_id.to_bytes(4, "big")
        + target_stream_id.to_bytes(4, "big")
        + field
    )


@pytest.fixture
def client_and_server():
    client = h2.connection.H2Connection()
    server = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
    client.initiate_connection()
    server.receive_data(client.data_to_send())
    client.receive_data(server.data_to_send())
    return client, server


class TestRFC9218:
    def test_send_and_receive_priority_update_before_negotiation(self, client_and_server) -> None:
        client, server = client_and_server

        client.send_priority_update(13, urgency=0, incremental=True)

        wire = client.data_to_send()
        assert wire == priority_update_frame(13, b"u=0,i")

        events = server.receive_data(wire)
        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.frame_stream_id == 0
        assert event.prioritized_stream_id == 13
        assert event.stream_id == 13
        assert event.urgency == 0
        assert event.incremental is True
        assert event.extensions == {}
        assert event.priority_field_value == b"u=0,i"

    def test_unknown_extension_parameters_are_exposed(self, client_and_server) -> None:
        _, server = client_and_server
        field = b'u=2;foo="bar",ext=?1;x=10,nested=("a" "b")'
        frame = priority_update_frame(7, field)

        events = server.receive_data(frame)
        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.urgency == 2
        assert event.incremental is False
        assert event.extensions[b"ext"][0] is True
        assert event.extensions[b"ext"][1][b"x"] == 10
        assert event.extensions[b"nested"][0][0][0] == b"a"
        assert event.extensions[b"nested"][0][1][0] == b"b"
        assert event.priority_field_value.startswith(b"u=2")

    def test_send_extensions_and_defaults(self, client_and_server) -> None:
        client, server = client_and_server

        client.send_priority_update(3, extensions=b"x=1")

        events = server.receive_data(client.data_to_send())
        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.urgency == 3
        assert event.incremental is False
        assert event.extensions == {b"x": (1, {})}

    def test_send_raw_priority_field_value(self, client_and_server) -> None:
        client, server = client_and_server
        raw_value = b'u=1,foo=:YWJj:'

        client.send_priority_update(5, priority_field_value=raw_value)

        events = server.receive_data(client.data_to_send())
        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.prioritized_stream_id == 5
        assert event.priority_field_value == raw_value
        assert event.extensions[b"foo"] == (b"abc", {})

    def test_send_rejects_invalid_raw_priority_field_value(self, client_and_server) -> None:
        client, _ = client_and_server

        with pytest.raises(h2.exceptions.ProtocolError):
            client.send_priority_update(1, priority_field_value=b"u=8")
        assert client.data_to_send() == b""

    def test_uncreated_and_closed_streams_do_not_store_state(self, client_and_server) -> None:
        _, server = client_and_server

        for stream_id in (101, 1):
            events = server.receive_data(priority_update_frame(stream_id, b"u=1"))
            assert isinstance(events[0], h2.events.PriorityUpdateReceived)
            assert stream_id not in server.streams

    def test_other_unknown_frame_remains_unknown(self, client_and_server) -> None:
        _, server = client_and_server
        frame = bytes.fromhex("000001400000000000ff")

        events = server.receive_data(frame)
        assert isinstance(events[0], h2.events.UnknownFrameReceived)

    def test_old_priority_remains_allowed_before_negotiation(self, client_and_server, frame_factory) -> None:
        _, server = client_and_server
        frame = frame_factory.build_priority_frame(stream_id=1, weight=15)

        events = server.receive_data(frame.serialize())
        assert isinstance(events[0], h2.events.PriorityUpdated)

    def test_local_advertisement_blocks_received_old_priority_before_ack(
        self,
        client_and_server,
        frame_factory,
    ) -> None:
        _, server = client_and_server
        server.update_settings({h2.settings.SettingCodes.NO_RFC7540_PRIORITIES: 1})
        server.data_to_send()
        frame = frame_factory.build_priority_frame(stream_id=1, weight=15)

        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(frame.serialize())
        goaway = server.data_to_send()
        assert int(h2.errors.ErrorCodes.PROTOCOL_ERROR).to_bytes(4, "big") in goaway

    def test_remote_advertisement_does_not_block_received_old_priority(
        self,
        client_and_server,
        frame_factory,
    ) -> None:
        client, _ = client_and_server
        client_setting = bytes.fromhex("000006040000000000000900000001")
        frame = frame_factory.build_priority_frame(stream_id=2, weight=15)

        client.receive_data(client_setting)
        events = client.receive_data(frame.serialize())
        assert isinstance(events[0], h2.events.PriorityUpdated)

    def test_local_advertisement_blocks_headers_priority_before_ack(
        self,
        client_and_server,
        frame_factory,
    ) -> None:
        _, server = client_and_server
        server.update_settings({h2.settings.SettingCodes.NO_RFC7540_PRIORITIES: 1})
        server.data_to_send()
        frame = frame_factory.build_headers_frame(
            REQUEST_HEADERS,
            stream_id=1,
            depends_on=0,
            stream_weight=15,
            exclusive=False,
        )
        frame.flags.add("PRIORITY")

        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(frame.serialize())

    def test_remote_no_rfc7540_priorities_blocks_old_priority_send(
        self,
        client_and_server,
    ) -> None:
        client, _ = client_and_server
        setting = bytes.fromhex("000006040000000000000900000001")

        client.receive_data(setting)
        client.data_to_send()

        with pytest.raises(h2.exceptions.ProtocolError):
            client.prioritize(1)

    def test_setting_zero_resumes_remote_old_priority_restriction(
        self,
        client_and_server,
    ) -> None:
        client, _ = client_and_server
        enable = bytes.fromhex("000006040000000000000900000001")
        disable = bytes.fromhex("000006040000000000000900000000")

        client.receive_data(enable)
        client.data_to_send()
        with pytest.raises(h2.exceptions.ProtocolError):
            client.prioritize(1)

        client.receive_data(disable)
        client.data_to_send()
        client.prioritize(1)
        assert client.data_to_send()

    def test_priority_update_works_after_negotiation(self, client_and_server) -> None:
        client, server = client_and_server
        setting = bytes.fromhex("000006040000000000000900000001")
        client.receive_data(setting)
        client.data_to_send()

        client.send_priority_update(1, urgency=6, incremental=True)
        events = server.receive_data(client.data_to_send())
        assert isinstance(events[0], h2.events.PriorityUpdateReceived)

    @pytest.mark.parametrize(
        ("payload", "exception"),
        [
            (b"\x00\x00\x00\x00u=3", h2.exceptions.ProtocolError),
            (b"\x00\x00\x00", h2.exceptions.FrameSizeError),
            (b"\x00\x00\x00\x01u=8", h2.exceptions.ProtocolError),
            (b"\x00\x00\x00\x01i=?2", h2.exceptions.ProtocolError),
            (b"\x00\x00\x00\x01i=?1;x=1", h2.exceptions.ProtocolError),
            (b"\x00\x00\x00\x01u", h2.exceptions.ProtocolError),
        ],
    )
    def test_invalid_priority_update_frames(
        self,
        client_and_server,
        payload,
        exception,
    ) -> None:
        _, server = client_and_server
        length = len(payload)
        header = bytes([
            (length >> 16) & 0xFF,
            (length >> 8) & 0xFF,
            length & 0xFF,
            0x10,
            0,
        ])
        raw = header + b"\x00\x00\x00\x00" + payload

        with pytest.raises(exception):
            server.receive_data(raw)

    def test_empty_priority_field_uses_defaults(self, client_and_server) -> None:
        _, server = client_and_server

        events = server.receive_data(priority_update_frame(1, b""))
        event = events[0]
        assert isinstance(event, h2.events.PriorityUpdateReceived)
        assert event.urgency == 3
        assert event.incremental is False
        assert event.extensions == {}
        assert event.priority_field_value == b""

    def test_priority_update_on_nonzero_frame_stream_is_connection_error(
        self,
        client_and_server,
    ) -> None:
        _, server = client_and_server
        frame = priority_update_frame(1, b"u=3", frame_stream_id=1)

        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(frame)

    def test_reserved_bit_is_connection_error(self, client_and_server) -> None:
        _, server = client_and_server
        raw = priority_update_frame(1, b"u=3")
        raw = raw[:9] + b"\x80\x00\x00\x01" + raw[13:]

        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(raw)

    def test_invalid_setting_value(self, client_and_server) -> None:
        _, server = client_and_server
        setting = bytes.fromhex("000006040000000000000900000002")

        with pytest.raises(h2.exceptions.InvalidSettingsValueError) as exc_info:
            server.receive_data(setting)
        assert exc_info.value.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR

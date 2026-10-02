from __future__ import annotations

import struct

import pytest

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.settings


def frame(type_code: int, stream_id: int, body: bytes, flags: int = 0) -> bytes:
    return len(body).to_bytes(3, "big") + bytes((type_code, flags)) + stream_id.to_bytes(4, "big") + body


def settings_frame(setting: int, value: int, ack: bool = False) -> bytes:
    flags = 1 if ack else 0
    body = struct.pack(">HI", setting, value) if not ack else b""
    return frame(0x4, 0, body, flags)


def priority_update(stream_id: int, field: bytes, connection_stream: int = 0, flags: int = 0) -> bytes:
    return frame(0x10, connection_stream, struct.pack(">I", stream_id) + field, flags)


class TestRFC9218:
    client_config = h2.config.H2Configuration(client_side=True)
    server_config = h2.config.H2Configuration(client_side=False)
    request_headers = [
        (b":method", b"GET"),
        (b":path", b"/"),
        (b":authority", b"example.com"),
        (b":scheme", b"https"),
    ]

    def _negotiated_server(self, frame_factory):
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()
        server.update_settings({h2.settings.SettingCodes.NO_RFC7540_PRIORITIES: 1})

        client = h2.connection.H2Connection(config=self.client_config)
        client.initiate_connection()
        client.clear_outbound_data_buffer()

        client.receive_data(server.data_to_send())
        client.update_settings({h2.settings.SettingCodes.NO_RFC7540_PRIORITIES: 1})
        server.receive_data(client.data_to_send())
        server.clear_outbound_data_buffer()
        client.clear_outbound_data_buffer()
        return client, server

    def test_send_priority_update_after_negotiation(self, frame_factory) -> None:
        client, server = self._negotiated_server(frame_factory)

        client.send_priority_update(
            stream_id=1,
            urgency=0,
            incremental=True,
            extension_parameters={b"foo": b'"bar"', b"flag": True},
        )

        body = struct.pack(">I", 1) + b'u=0;i,foo="bar",flag'
        assert client.data_to_send() == frame(0x10, 0, body)

        events = server.receive_data(frame(0x10, 0, body))
        assert not server.data_to_send()
        assert events == [
            h2.events.PriorityUpdateReceived(
                stream_id=1,
                urgency=0,
                incremental=True,
                extension_parameters={b"flag": b"?1", b"foo": b'"bar"'},
            ),
        ]

    def test_default_urgency_and_unknown_extension_parameter(self, frame_factory) -> None:
        _, server = self._negotiated_server(frame_factory)

        data = priority_update(3, b"foo=12;unknown,bar=(1 2),i")
        events = server.receive_data(data)

        assert events == [
            h2.events.PriorityUpdateReceived(
                stream_id=3,
                urgency=3,
                incremental=True,
                extension_parameters={b"foo": b"12;unknown", b"bar": b"(1 2)"},
            ),
        ]

    def test_unnegotiated_priority_update_is_unknown_frame(self, frame_factory) -> None:
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        events = server.receive_data(priority_update(1, b"u=0"))

        assert not server.data_to_send()
        assert len(events) == 1
        assert isinstance(events[0], h2.events.UnknownFrameReceived)
        assert events[0].frame.type == 0x10

    def test_unnegotiated_invalid_priority_update_is_still_unknown(self, frame_factory) -> None:
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        events = server.receive_data(frame(0x10, 0, b"\x00"))

        assert len(events) == 1
        assert isinstance(events[0], h2.events.UnknownFrameReceived)
        assert not server.data_to_send()

    def test_cannot_send_before_remote_setting_is_received(self, frame_factory) -> None:
        client = h2.connection.H2Connection(config=self.client_config)
        client.initiate_connection()
        client.receive_data(frame_factory.preamble())
        client.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.ProtocolError):
            client.send_priority_update(1, urgency=0)

        assert not client.data_to_send()

    def test_server_cannot_send_priority_update(self, frame_factory) -> None:
        _, server = self._negotiated_server(frame_factory)

        with pytest.raises(h2.exceptions.RFC1122Error):
            server.send_priority_update(stream_id=2, urgency=0)

    def test_future_stream_event_is_not_stored(self, frame_factory) -> None:
        _, server = self._negotiated_server(frame_factory)

        events = server.receive_data(priority_update(5, b"u=1;i"))

        assert len(events) == 1
        assert events[0].stream_id == 5
        assert server.streams == {}

    def test_implicitly_closed_stream_update_is_dropped(self, frame_factory) -> None:
        _, server = self._negotiated_server(frame_factory)

        events = server.receive_data(priority_update(5, b"u=0"))
        assert len(events) == 1

        events = server.receive_data(priority_update(3, b"u=0"))

        assert events == []
        assert server.streams == {}

    def test_half_closed_remote_stream_update_is_delivered(self, frame_factory) -> None:
        client, server = self._negotiated_server(frame_factory)
        client.send_headers(stream_id=1, headers=self.request_headers, end_stream=True)

        server.receive_data(client.data_to_send())
        assert server.streams[1].open

        events = server.receive_data(priority_update(1, b"u=0"))

        assert len(events) == 1
        assert events[0].stream_id == 1
        assert not server.data_to_send()

    def test_closed_stream_update_is_dropped(self, frame_factory) -> None:
        client, server = self._negotiated_server(frame_factory)
        client.send_headers(stream_id=1, headers=self.request_headers, end_stream=True)
        server.receive_data(client.data_to_send())
        server.send_headers(stream_id=1, headers=[(b":status", b"204")], end_stream=True)
        server.clear_outbound_data_buffer()
        assert server.streams[1].closed

        events = server.receive_data(priority_update(1, b"u=0"))

        assert events == []
        assert not server.data_to_send()

    @pytest.mark.parametrize(
        ("body", "error_code"),
        [
            (b"\x00", h2.errors.ErrorCodes.FRAME_SIZE_ERROR),
            (struct.pack(">I", 0) + b"u=0", h2.errors.ErrorCodes.PROTOCOL_ERROR),
            (struct.pack(">I", 2) + b"u=0", h2.errors.ErrorCodes.PROTOCOL_ERROR),
            (struct.pack(">I", 1) + b"u=8", h2.errors.ErrorCodes.PROTOCOL_ERROR),
            (struct.pack(">I", 1) + b"u=x", h2.errors.ErrorCodes.PROTOCOL_ERROR),
            (struct.pack(">I", 1) + b"u=0;i=?2", h2.errors.ErrorCodes.PROTOCOL_ERROR),
        ],
    )
    def test_invalid_negotiated_frame_terminates_connection(
        self, frame_factory, body, error_code,
    ) -> None:
        _, server = self._negotiated_server(frame_factory)

        with pytest.raises(h2.exceptions.ProtocolError) as exc_info:
            server.receive_data(frame(0x10, 0, body))

        assert exc_info.value.error_code == error_code
        assert server.data_to_send() == frame(
            0x7,
            0,
            struct.pack(">II", 0, int(error_code)),
        )

    def test_non_zero_connection_stream_is_protocol_error(self, frame_factory) -> None:
        _, server = self._negotiated_server(frame_factory)

        with pytest.raises(h2.exceptions.ProtocolError) as exc_info:
            server.receive_data(priority_update(1, b"u=0", connection_stream=2))

        assert exc_info.value.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR

    def test_other_unknown_extension_frames_remain_unknown(self, frame_factory) -> None:
        _, server = self._negotiated_server(frame_factory)

        events = server.receive_data(frame(0x99, 3, b"abc"))

        assert len(events) == 1
        assert isinstance(events[0], h2.events.UnknownFrameReceived)
        assert events[0].frame.type == 0x99

    def test_old_priority_is_ignored_after_remote_negotiation(self, frame_factory) -> None:
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        server.receive_data(settings_frame(h2.settings.SettingCodes.NO_RFC7540_PRIORITIES, 1))
        server.clear_outbound_data_buffer()

        events = server.receive_data(frame_factory.build_priority_frame(1, weight=15).serialize())

        assert events == []
        assert not server.data_to_send()

    def test_old_priority_cannot_be_sent_after_local_negotiation(self, frame_factory) -> None:
        client, _ = self._negotiated_server(frame_factory)

        with pytest.raises(h2.exceptions.ProtocolError):
            client.prioritize(stream_id=1)

    @pytest.mark.parametrize("value", [0xFFFFFFFF, 2])
    def test_invalid_setting_value(self, frame_factory, value) -> None:
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        with pytest.raises(h2.exceptions.InvalidSettingsValueError) as exc_info:
            server.receive_data(settings_frame(h2.settings.SettingCodes.NO_RFC7540_PRIORITIES, value))

        assert exc_info.value.error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR

    def test_local_setting_cannot_revert_to_zero(self, frame_factory) -> None:
        server = h2.connection.H2Connection(config=self.server_config)
        server.initiate_connection()
        server.receive_data(frame_factory.preamble())
        server.clear_outbound_data_buffer()

        server.update_settings({h2.settings.SettingCodes.NO_RFC7540_PRIORITIES: 1})
        with pytest.raises(h2.exceptions.ProtocolError):
            server.update_settings({h2.settings.SettingCodes.NO_RFC7540_PRIORITIES: 0})

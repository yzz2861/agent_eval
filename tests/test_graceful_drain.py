"""
test_graceful_drain
~~~~~~~~~~~~~~~~~~

Tests for graceful connection shutdown ("draining") via GOAWAY frames.

Unlike an immediate close, draining stops new streams from being accepted
while allowing the streams that were already accepted to keep exchanging
DATA frames and WINDOW_UPDATE frames until they end naturally. Only after
that is the connection closed.
"""

from __future__ import annotations

import pytest
from hyperframe.frame import GoAwayFrame

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions


class TestLocalDrain:
    """
    Graceful shutdown initiated locally (this peer sends the GOAWAY).
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]
    example_response_headers = [
        (":status", "200"),
        ("server", "fake-serv/0.1.0"),
    ]

    server_config = h2.config.H2Configuration(client_side=False)

    def test_graceful_close_enters_draining_state(self, frame_factory) -> None:
        """
        graceful_close() emits a GOAWAY but leaves the connection draining
        rather than closing it immediately.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        c.graceful_close()

        assert c.state_machine.state == h2.connection.ConnectionState.DRAINING
        assert c.draining is True
        assert c.draining_side == h2.connection.DrainSide.LOCAL

        expected = frame_factory.build_goaway_frame(last_stream_id=0)
        assert c.data_to_send() == expected.serialize()

    def test_graceful_close_uses_highest_inbound_stream(self, frame_factory) -> None:
        """
        The GOAWAY advertises the highest inbound stream ID by default.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())

        for stream_id in (1, 3):
            f = frame_factory.build_headers_frame(
                self.example_request_headers,
                stream_id=stream_id,
            )
            c.receive_data(f.serialize())

        c.clear_outbound_data_buffer()
        c.graceful_close()

        expected = frame_factory.build_goaway_frame(last_stream_id=3)
        assert c.data_to_send() == expected.serialize()

    def test_accepted_inbound_streams_keep_working(self, frame_factory) -> None:
        """
        A stream the remote peer opened before the GOAWAY keeps accepting
        DATA, sending DATA, updating windows and ending normally.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())

        request = frame_factory.build_headers_frame(
            self.example_request_headers,
            stream_id=1,
        )
        c.receive_data(request.serialize())
        c.clear_outbound_data_buffer()

        c.graceful_close(last_stream_id=1)
        assert c.data_to_send()  # GOAWAY is buffered

        # We can answer on the accepted stream normally.
        c.send_headers(
            stream_id=1,
            headers=self.example_response_headers,
        )
        c.send_data(stream_id=1, data=b"world")
        c.increment_flow_control_window(10, stream_id=1)

        # The peer can still send DATA and end its side of the stream.
        end_data = frame_factory.build_data_frame(
            b"world",
            flags=["END_STREAM"],
            stream_id=1,
        )
        events = c.receive_data(end_data.serialize())
        assert len(events) == 2
        assert isinstance(events[0], h2.events.DataReceived)
        assert events[0].stream_ended is not None
        assert isinstance(events[1], h2.events.StreamEnded)

        c.end_stream(stream_id=1)

        # Window updates on the connection still work after the stream ends.
        c.acknowledge_received_data(10, stream_id=1)
        c.increment_flow_control_window(10)

        # Only once everything is done do we close the connection for good.
        c.close_connection()
        assert c.state_machine.state == h2.connection.ConnectionState.CLOSED

    def test_new_inbound_stream_after_drain_is_refused(self, frame_factory) -> None:
        """
        A stream with an ID higher than the GOAWAY last_stream_id is refused
        with a RST_STREAM (REFUSED_STREAM), without being accepted.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())

        request = frame_factory.build_headers_frame(
            self.example_request_headers,
            stream_id=1,
        )
        c.receive_data(request.serialize())
        c.clear_outbound_data_buffer()

        c.graceful_close(last_stream_id=1)
        c.data_to_send()

        new_request = frame_factory.build_headers_frame(
            self.example_request_headers,
            stream_id=3,
        )
        events = c.receive_data(new_request.serialize())

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.StreamReset)
        assert event.stream_id == 3
        assert event.error_code == h2.errors.ErrorCodes.REFUSED_STREAM
        assert event.remote_reset is False

        rst = frame_factory.build_rst_stream_frame(
            stream_id=3,
            error_code=h2.errors.ErrorCodes.REFUSED_STREAM,
        )
        assert c.data_to_send() == rst.serialize()
        assert 3 not in c.streams
        # The connection is still draining, not closed.
        assert c.state_machine.state == h2.connection.ConnectionState.DRAINING

    def test_data_on_refused_stream_does_not_raise(self, frame_factory) -> None:
        """
        DATA that races a RST_STREAM refusal is treated as a stream error,
        not a connection error.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        c.graceful_close(last_stream_id=1)
        c.data_to_send()

        new_request = frame_factory.build_headers_frame(
            self.example_request_headers,
            stream_id=3,
        )
        c.receive_data(new_request.serialize())
        c.clear_outbound_data_buffer()

        data_frame = frame_factory.build_data_frame(
            b"late data",
            stream_id=3,
        )
        events = c.receive_data(data_frame.serialize())
        # The reset was already signalled; the racing DATA only produces
        # wire-level output, not a duplicate user-facing event.
        assert not any(isinstance(event, h2.events.StreamReset) for event in events)

        rst = frame_factory.build_rst_stream_frame(
            stream_id=3,
            error_code=h2.errors.ErrorCodes.STREAM_CLOSED,
        )
        # The DATA consumed connection-level flow control, so a connection
        # WINDOW_UPDATE may be emitted alongside the RST_STREAM.
        assert rst.serialize() in c.data_to_send()

    def test_repeated_graceful_close_can_only_tighten(self, frame_factory) -> None:
        """
        A second graceful_close() may lower the last stream ID but may not
        raise it.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())
        c.clear_outbound_data_buffer()

        c.graceful_close(last_stream_id=11)
        c.data_to_send()
        c.graceful_close(last_stream_id=5)

        expected = frame_factory.build_goaway_frame(last_stream_id=5)
        assert c.data_to_send() == expected.serialize()

        with pytest.raises(h2.exceptions.ProtocolError):
            c.graceful_close(last_stream_id=7)

        # The invalid GOAWAY was not emitted.
        assert not c.data_to_send()

    def test_two_phase_shutdown_then_final_close(self, frame_factory) -> None:
        """
        The canonical shutdown: send a broad GOAWAY, then a tightened one,
        finish the streams and finally close immediately.
        """
        c = h2.connection.H2Connection(config=self.server_config)
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())

        request = frame_factory.build_headers_frame(
            self.example_request_headers,
            stream_id=1,
        )
        c.receive_data(request.serialize())
        c.clear_outbound_data_buffer()

        # First GOAWAY reserves a generous last stream ID (in-flight requests
        # may still have been accepted), second one tightens it.
        c.graceful_close(last_stream_id=2**31 - 1)
        c.data_to_send()
        c.graceful_close(last_stream_id=1)
        c.data_to_send()

        assert c.draining_side == h2.connection.DrainSide.LOCAL

        data_frame = frame_factory.build_data_frame(
            b"done",
            flags=["END_STREAM"],
            stream_id=1,
        )
        events = c.receive_data(data_frame.serialize())
        assert isinstance(events[0], h2.events.DataReceived)
        assert events[0].stream_ended is not None

        c.end_stream(stream_id=1)
        c.close_connection(last_stream_id=1)
        assert c.state_machine.state == h2.connection.ConnectionState.CLOSED


class TestRemoteDrain:
    """
    Graceful shutdown initiated by the remote peer (we receive GOAWAY).
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]
    example_response_headers = [
        (":status", "200"),
        ("server", "fake-serv/0.1.0"),
    ]

    def test_remote_goaway_enters_draining_and_keeps_buffer(self, frame_factory) -> None:
        """
        Receiving a GOAWAY drains the connection and must not discard bytes
        already queued for sending on accepted streams.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()

        c.send_headers(stream_id=1, headers=self.example_request_headers)
        c.data_to_send()  # flush the preamble and request

        data_frame = frame_factory.build_data_frame(
            b"payload",
            stream_id=1,
        )
        c.send_data(stream_id=1, data=b"payload")
        queued_data = data_frame.serialize()

        goaway = frame_factory.build_goaway_frame(last_stream_id=1)
        events = c.receive_data(goaway.serialize())

        drain_events = [event for event in events if isinstance(event, h2.events.ConnectionDraining)]
        assert len(drain_events) == 1
        assert drain_events[0].stream_ids == []

        assert c.state_machine.state == h2.connection.ConnectionState.DRAINING
        assert c.draining_side == h2.connection.DrainSide.REMOTE

        # Bytes queued on the accepted stream before the GOAWAY were not
        # discarded and are still handed back to the caller.
        assert queued_data in c.data_to_send()

    def test_unaccepted_outbound_streams_are_reported_once(self, frame_factory) -> None:
        """
        Locally initiated streams above the GOAWAY last_stream_id are handed
        to the caller via the event; tightening GOAWAYs report new streams
        only once.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        for stream_id in (1, 3, 5):
            c.send_headers(
                stream_id=stream_id,
                headers=self.example_request_headers,
            )
        c.data_to_send()

        first = frame_factory.build_goaway_frame(last_stream_id=7)
        events = c.receive_data(first.serialize())
        assert events[0].stream_ids == []

        second = frame_factory.build_goaway_frame(last_stream_id=3)
        events = c.receive_data(second.serialize())
        assert events[0].stream_ids == [5]

        third = frame_factory.build_goaway_frame(last_stream_id=1)
        events = c.receive_data(third.serialize())
        assert events[0].stream_ids == [3]

        # Repeating the same GOAWAY does not re-report streams.
        repeat = frame_factory.build_goaway_frame(last_stream_id=1)
        events = c.receive_data(repeat.serialize())
        assert events[0].stream_ids == []

        # Accepted streams 1 still works.
        response = frame_factory.build_headers_frame(
            self.example_response_headers,
            stream_id=1,
        )
        c.receive_data(response.serialize())

    def test_cannot_initiate_new_stream_after_remote_goaway(self, frame_factory) -> None:
        """
        Creating a new outbound stream is forbidden once the remote peer is
        draining.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        goaway = frame_factory.build_goaway_frame(last_stream_id=0)
        c.receive_data(goaway.serialize())

        with pytest.raises(h2.exceptions.ProtocolError):
            c.send_headers(
                stream_id=1,
                headers=self.example_request_headers,
            )

        with pytest.raises(h2.exceptions.ProtocolError):
            c.push_stream(
                stream_id=1,
                promised_stream_id=2,
                request_headers=self.example_request_headers,
            )

    def test_remote_drain_does_not_touch_queued_bytes_on_other_streams(
        self,
        frame_factory,
    ) -> None:
        """
        Bytes queued on stream 1 must survive a GOAWAY that rejects stream 5:
        the two streams' send buffers are independent.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        c.send_headers(stream_id=1, headers=self.example_request_headers)
        c.send_data(stream_id=1, data=b"stream-one-bytes")
        c.send_headers(stream_id=5, headers=self.example_request_headers)
        stream_one_payload = frame_factory.build_data_frame(
            b"stream-one-bytes",
            stream_id=1,
        ).serialize()

        goaway = frame_factory.build_goaway_frame(last_stream_id=1)
        events = c.receive_data(goaway.serialize())
        assert events[0].stream_ids == [5]

        sent = c.data_to_send()
        assert stream_one_payload in sent

    def test_rst_stream_then_goaway_in_same_buffer(self, frame_factory) -> None:
        """
        When a RST_STREAM and a GOAWAY arrive in the same network buffer the
        reset stream is neither reported as unaccepted nor left open.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        c.send_headers(stream_id=1, headers=self.example_request_headers)
        c.send_headers(stream_id=3, headers=self.example_request_headers)
        c.data_to_send()

        rst = frame_factory.build_rst_stream_frame(stream_id=3)
        goaway = frame_factory.build_goaway_frame(last_stream_id=1)

        events = c.receive_data(rst.serialize() + goaway.serialize())

        assert len(events) == 2
        assert isinstance(events[0], h2.events.StreamReset)
        assert events[0].stream_id == 3
        assert isinstance(events[1], h2.events.ConnectionDraining)
        # Stream 3 was reset by the earlier frame and is not unaccepted.
        assert events[1].stream_ids == []

        # The accepted stream 1 keeps going.
        response = frame_factory.build_headers_frame(
            self.example_response_headers,
            stream_id=1,
        )
        c.receive_data(response.serialize())
        data = frame_factory.build_data_frame(
            b"ok",
            flags=["END_STREAM"],
            stream_id=1,
        )
        events = c.receive_data(data.serialize())
        assert isinstance(events[0], h2.events.DataReceived)

    def test_goaway_then_rst_stream_is_not_reported_again(self, frame_factory) -> None:
        """
        A stream reported as unaccepted by one GOAWAY is not re-reported by a
        later GOAWAY once it has been reset.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        c.send_headers(stream_id=1, headers=self.example_request_headers)
        c.send_headers(stream_id=3, headers=self.example_request_headers)
        c.data_to_send()

        goaway = frame_factory.build_goaway_frame(last_stream_id=1)
        events = c.receive_data(goaway.serialize())
        assert events[0].stream_ids == [3]

        rst = frame_factory.build_rst_stream_frame(stream_id=3)
        c.receive_data(rst.serialize())

        later = frame_factory.build_goaway_frame(last_stream_id=1)
        events = c.receive_data(later.serialize())
        assert events[0].stream_ids == []

    def test_interleaved_streams_drain_independently(self, frame_factory) -> None:
        """
        With several streams open, DATA frames on distinct accepted streams
        interleave normally while unaccepted ones are reported.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        c.send_headers(stream_id=1, headers=self.example_request_headers)
        c.send_headers(stream_id=3, headers=self.example_request_headers)
        c.send_headers(stream_id=5, headers=self.example_request_headers)
        c.data_to_send()

        goaway = frame_factory.build_goaway_frame(last_stream_id=3)
        events = c.receive_data(goaway.serialize())
        assert events[0].stream_ids == [5]

        # The server acknowledges both accepted requests.
        response1 = frame_factory.build_headers_frame(
            self.example_response_headers,
            stream_id=1,
        )
        response3 = frame_factory.build_headers_frame(
            self.example_response_headers,
            stream_id=3,
        )
        c.receive_data(response1.serialize() + response3.serialize())

        # Peer sends interleaved data on the two accepted streams.
        data1 = frame_factory.build_data_frame(b"aaaa", stream_id=1)
        data3 = frame_factory.build_data_frame(b"bbbb", stream_id=3)
        events = c.receive_data(
            data1.serialize() + data3.serialize() + data1.serialize(),
        )

        received = [(event.stream_id, bytes(event.data)) for event in events if isinstance(event, h2.events.DataReceived)]
        assert received == [(1, b"aaaa"), (3, b"bbbb"), (1, b"aaaa")]

        # We can respond on both streams and end them separately.
        c.send_data(stream_id=3, data=b"resp3", end_stream=True)
        c.send_data(stream_id=1, data=b"resp1", end_stream=True)
        assert c.local_flow_control_window(1) >= 0

    def test_flow_control_resumes_during_drain(self, frame_factory) -> None:
        """
        A stream blocked by flow control while draining resumes after a
        WINDOW_UPDATE, and data continues to flow until the stream ends.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.clear_outbound_data_buffer()

        c.send_headers(stream_id=1, headers=self.example_request_headers)
        c.data_to_send()

        # The default max frame size is 16KiB, so fill the window in chunks.
        while c.local_flow_control_window(1) >= 16384:
            c.send_data(stream_id=1, data=b"x" * 16384)
        remaining = c.local_flow_control_window(1)
        if remaining:
            c.send_data(stream_id=1, data=b"x" * remaining)

        goaway = frame_factory.build_goaway_frame(last_stream_id=1)
        c.receive_data(goaway.serialize())

        # The connection and stream windows are exhausted.
        assert c.local_flow_control_window(1) == 0
        with pytest.raises(h2.exceptions.FlowControlError):
            c.send_data(stream_id=1, data=b"more")

        # Peer opens both the connection and stream windows.
        conn_update = frame_factory.build_window_update_frame(
            stream_id=0,
            increment=10,
        )
        stream_update = frame_factory.build_window_update_frame(
            stream_id=1,
            increment=20,
        )
        events = c.receive_data(
            conn_update.serialize() + stream_update.serialize(),
        )
        assert len(events) == 2
        assert all(isinstance(event, h2.events.WindowUpdated) for event in events)

        assert c.local_flow_control_window(1) == 10
        c.send_data(stream_id=1, data=b"y" * 10, end_stream=True)

    def test_both_sides_draining(self, frame_factory) -> None:
        """
        When both peers send GOAWAY frames, draining_side is BOTH and the
        streams accepted by both sides still complete.
        """
        c = h2.connection.H2Connection(
            config=h2.config.H2Configuration(
                client_side=False,
            ),
        )
        c.initiate_connection()
        c.receive_data(frame_factory.preamble())

        request = frame_factory.build_headers_frame(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            stream_id=1,
        )
        c.receive_data(request.serialize())
        c.clear_outbound_data_buffer()

        # We drain locally first.
        c.graceful_close(last_stream_id=1)
        c.data_to_send()
        assert c.draining_side == h2.connection.DrainSide.LOCAL

        # The peer drains too.
        remote_goaway = frame_factory.build_goaway_frame(last_stream_id=0)
        events = c.receive_data(remote_goaway.serialize())
        assert isinstance(events[0], h2.events.ConnectionDraining)
        assert c.draining_side == h2.connection.DrainSide.BOTH

        # The existing inbound stream still completes.
        data = frame_factory.build_data_frame(
            b"body",
            flags=["END_STREAM"],
            stream_id=1,
        )
        events = c.receive_data(data.serialize())
        assert isinstance(events[0], h2.events.DataReceived)

    def test_goaway_after_immediate_close_still_terminates(self,
                                                           frame_factory) -> None:
        """
        A GOAWAY received after the connection was closed immediately retains
        the old ConnectionTerminated semantics rather than re-opening a
        draining state.
        """
        c = h2.connection.H2Connection()
        c.initiate_connection()
        c.close_connection()
        assert c.state_machine.state == h2.connection.ConnectionState.CLOSED
        c.clear_outbound_data_buffer()

        f = frame_factory.build_goaway_frame(last_stream_id=0)
        events = c.receive_data(f.serialize())

        assert len(events) == 1
        assert isinstance(events[0], h2.events.ConnectionTerminated)
        assert c.state_machine.state == h2.connection.ConnectionState.CLOSED
        assert c.draining is False

    def test_goaway_frame_is_directly_parseable(self) -> None:
        """
        Sanity check that hyperframe exposes the raw GOAWAY fields used by
        the ConnectionDraining event.
        """
        f = GoAwayFrame(0)
        f.last_stream_id = 3
        f.error_code = 0
        assert f.serialize()

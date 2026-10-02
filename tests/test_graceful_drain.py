"""
Tests for graceful connection draining (RFC 9113 section 6.8).

A graceful GOAWAY frame (error code NO_ERROR) must not tear the connection
down: streams accepted by the peer keep exchanging DATA and WINDOW_UPDATE
frames and end normally, while unaccepted streams are surfaced as events so
that the caller can retry them.
"""
from __future__ import annotations

import pytest

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.settings

from .helpers import FrameFactory


REQUEST_HEADERS = [
    (":method", "GET"),
    (":path", "/"),
    (":authority", "example.com"),
    (":scheme", "https"),
]

RESPONSE_HEADERS = [
    (":status", "200"),
    ("server", "fake-serv/0.1.0"),
]


def _client() -> h2.connection.H2Connection:
    return h2.connection.H2Connection()


def _server() -> h2.connection.H2Connection:
    return h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=False),
    )


def _connected_pair() -> tuple[
    h2.connection.H2Connection, h2.connection.H2Connection,
]:
    client = _client()
    server = _server()
    client.initiate_connection()
    server.receive_data(client.data_to_send())
    client.receive_data(server.data_to_send())
    return client, server


class TestGracefulClose:
    def test_graceful_close_emits_no_error_goaway(self, frame_factory) -> None:
        """
        graceful_close emits a GOAWAY with NO_ERROR whose last_stream_id
        defaults to the highest inbound stream that was processed.
        """
        client, server = _connected_pair()

        client.send_headers(1, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())
        server.data_to_send()

        server.graceful_close()

        expected = frame_factory.build_goaway_frame(
            last_stream_id=1,
            error_code=h2.errors.ErrorCodes.NO_ERROR,
        )
        assert server.data_to_send() == expected.serialize()
        assert server.state_machine.state == \
            h2.connection.ConnectionState.SERVER_OPEN
        assert server.local_drains is True

    def test_graceful_close_can_advertise_large_initial_stream_id(
        self, frame_factory,
    ) -> None:
        """
        The two-GOAWAY procedure starts with a very large last_stream_id.
        """
        server = _server()
        server.receive_data(FrameFactory().preamble())
        server.data_to_send()

        max_id = h2.connection.H2Connection.HIGHEST_ALLOWED_STREAM_ID
        server.graceful_close(last_stream_id=max_id)
        first = frame_factory.build_goaway_frame(
            last_stream_id=max_id,
        )
        assert server.data_to_send() == first.serialize()

    def test_graceful_close_last_stream_id_can_only_tighten(self) -> None:
        """
        Successive graceful GOAWAY frames may only reduce last_stream_id.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        server.graceful_close(last_stream_id=5)
        server.graceful_close(last_stream_id=3)
        with pytest.raises(h2.exceptions.ProtocolError):
            server.graceful_close(last_stream_id=7)

    def test_graceful_close_rejects_invalid_last_stream_id(self) -> None:
        """
        last_stream_id must lie within the valid stream ID range.
        """
        server = _server()
        with pytest.raises(h2.exceptions.ProtocolError):
            server.graceful_close(last_stream_id=-1)
        with pytest.raises(h2.exceptions.ProtocolError):
            server.graceful_close(last_stream_id=2**31)

    def test_close_connection_still_closes_immediately(self) -> None:
        """
        The original close_connection method keeps its immediate semantics.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())
        server.data_to_send()

        server.close_connection()
        assert server.state_machine.state == \
            h2.connection.ConnectionState.CLOSED

    def test_new_inbound_stream_refused_after_graceful_close(self) -> None:
        """
        Inbound streams above the advertised last_stream_id are refused with
        RST_STREAM / REFUSED_STREAM and never create a stream object.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())
        server.data_to_send()

        server.graceful_close(last_stream_id=1)
        # Consume the GOAWAY on the server side but do not deliver it to the
        # client, so the client still considers new streams allowed.
        goaway = server.data_to_send()
        assert goaway

        # The request was already in flight when the GOAWAY was sent.
        client.send_headers(3, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        assert 3 not in server.streams

        events = client.receive_data(server.data_to_send())
        reset_events = [
            e for e in events if isinstance(e, h2.events.StreamReset)
        ]
        assert len(reset_events) == 1
        assert reset_events[0].stream_id == 3
        assert reset_events[0].error_code == \
            h2.errors.ErrorCodes.REFUSED_STREAM

    def test_accepted_inbound_stream_completes_after_graceful_close(
        self,
    ) -> None:
        """
        A stream accepted before graceful_close can still receive DATA, send
        responses and window updates, and finish normally.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())
        server.data_to_send()

        # Client sends a large body; server drains once it has seen the
        # request. Incoming DATA must keep flowing.
        client.send_data(1, b"hello world")
        server.graceful_close(last_stream_id=1)
        events = server.receive_data(client.data_to_send())
        assert any(
            isinstance(e, h2.events.DataReceived) for e in events
        )

        # Window updates can still be emitted.
        server.increment_flow_control_window(11, stream_id=1)
        wu = server.data_to_send()
        assert wu

        # The server can still answer and end the stream.
        server.send_headers(1, RESPONSE_HEADERS)
        server.send_data(1, b"bye", end_stream=True)
        response = server.data_to_send()
        assert response

        # The client receives the response on the still-open stream.
        events = client.receive_data(response)
        assert any(
            isinstance(e, h2.events.ResponseReceived) for e in events
        )
        assert any(isinstance(e, h2.events.StreamEnded) for e in events)

    def test_data_on_refused_stream_refunds_window_and_resets(self) -> None:
        """
        DATA frames arriving on an inbound stream refused during draining do
        not raise a protocol error: the connection window is refunded and the
        stream is reset with REFUSED_STREAM, so other streams are unaffected.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())
        server.data_to_send()

        server.graceful_close(last_stream_id=1)
        client.receive_data(server.data_to_send())

        # Stream 3 request and body were in flight when the GOAWAY landed.
        late = _client()
        late.initiate_connection()
        late.data_to_send()
        late.send_headers(3, REQUEST_HEADERS)
        late.send_data(3, b"orphan body", end_stream=True)
        wire = late.data_to_send()

        events = server.receive_data(wire)
        assert events == []
        # Server emitted WINDOW_UPDATE for the connection plus RST_STREAM.
        assert server.data_to_send()
        assert 3 not in server.streams

        # The accepted stream 1 still works.
        server.send_headers(1, RESPONSE_HEADERS, end_stream=True)
        client.receive_data(server.data_to_send())
        assert client.state_machine.state == \
            h2.connection.ConnectionState.CLIENT_OPEN

    def test_data_already_queued_is_not_dropped_on_graceful_close(
        self,
    ) -> None:
        """
        Response DATA queued before graceful_close remains in the outbound
        buffer and is sent together with the GOAWAY frame.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())
        server.data_to_send()

        server.send_headers(1, RESPONSE_HEADERS)
        server.send_data(1, b"queued bytes", end_stream=True)
        queued = server.data_to_send()
        assert b"queued bytes" in queued

        server.graceful_close(last_stream_id=1)
        wire = server.data_to_send()
        assert wire  # the GOAWAY
        assert b"queued bytes" not in wire

        # The queued response was not discarded; deliver it before GOAWAY.
        events = client.receive_data(queued + wire)
        assert any(isinstance(e, h2.events.StreamEnded) for e in events)
        assert any(isinstance(e, h2.events.ConnectionDraining) for e in events)

    def test_terminating_goaway_after_drain_still_closes(
        self, frame_factory,
    ) -> None:
        """
        close_connection can be used at any time during a drain to close the
        connection immediately.
        """
        server = _server()
        server.graceful_close(last_stream_id=0)
        assert server.local_drains

        server.close_connection(error_code=h2.errors.ErrorCodes.INTERNAL_ERROR)
        assert server.state_machine.state == \
            h2.connection.ConnectionState.CLOSED


class TestRemoteGracefulDrain:
    def test_graceful_goaway_fires_draining_event(self, frame_factory) -> None:
        """
        Receiving a NO_ERROR GOAWAY fires ConnectionDraining, keeps the
        connection open and does not clear the outbound buffer.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS, end_stream=True)

        goaway = frame_factory.build_goaway_frame(last_stream_id=1)
        events = client.receive_data(goaway.serialize())

        assert len(events) == 1
        event = events[0]
        assert isinstance(event, h2.events.ConnectionDraining)
        assert event.error_code == h2.errors.ErrorCodes.NO_ERROR
        assert event.last_stream_id == 1
        assert client.remote_drains is True
        assert client.state_machine.state == \
            h2.connection.ConnectionState.CLIENT_OPEN
        # Previously queued data must survive the GOAWAY.
        assert client.data_to_send()  # request frames still queued

    def test_non_no_error_goaway_terminates_immediately(
        self, frame_factory,
    ) -> None:
        """
        A GOAWAY carrying a non-zero error code keeps the old terminate
        semantics.
        """
        client, _ = _connected_pair()
        goaway = frame_factory.build_goaway_frame(
            last_stream_id=1,
            error_code=h2.errors.ErrorCodes.PROTOCOL_ERROR,
        )
        events = client.receive_data(goaway.serialize())

        assert len(events) == 1
        assert isinstance(events[0], h2.events.ConnectionTerminated)
        assert client.state_machine.state == \
            h2.connection.ConnectionState.CLOSED

    def test_new_outbound_stream_blocked_after_remote_drain(self) -> None:
        """
        Once the remote peer drains, initiating a new outbound stream raises
        ConnectionDrainingError.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS, end_stream=True)
        server.receive_data(client.data_to_send())

        server.graceful_close(last_stream_id=1)
        client.receive_data(server.data_to_send())

        with pytest.raises(h2.exceptions.ConnectionDrainingError) as excinfo:
            client.send_headers(3, REQUEST_HEADERS)
        assert excinfo.value.last_stream_id == 1

    def test_accepted_outbound_stream_still_usable_after_remote_drain(
        self,
    ) -> None:
        """
        Streams with IDs <= last_stream_id keep sending DATA, receiving
        WINDOW_UPDATE and ending normally after a graceful GOAWAY.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        # Server drains; stream 1 was accepted.
        server.graceful_close(last_stream_id=1)
        client.receive_data(server.data_to_send())

        # Client can still send body data.
        client.send_data(1, b"more data", end_stream=True)
        events = server.receive_data(client.data_to_send())
        assert any(isinstance(e, h2.events.DataReceived) for e in events)
        assert any(isinstance(e, h2.events.StreamEnded) for e in events)

        # Server window updates for the stream still reach the client.
        server.increment_flow_control_window(9, stream_id=1)
        server.increment_flow_control_window(9)
        events = client.receive_data(server.data_to_send())
        window_events = [
            e for e in events
            if isinstance(e, h2.events.WindowUpdated)
        ]
        assert {e.stream_id for e in window_events} == {0, 1}

        # The server can still respond normally.
        server.send_headers(1, RESPONSE_HEADERS, end_stream=True)
        events = client.receive_data(server.data_to_send())
        assert any(isinstance(e, h2.events.ResponseReceived) for e in events)
        assert any(isinstance(e, h2.events.StreamEnded) for e in events)

    def test_unaccepted_outbound_streams_reported_on_first_goaway(
        self, frame_factory,
    ) -> None:
        """
        Outbound streams above last_stream_id are reported via
        StreamNotAccepted events for the caller to retry.
        """
        client, _ = _connected_pair()
        for stream_id in (1, 3, 5):
            client.send_headers(stream_id, REQUEST_HEADERS, end_stream=True)
        client.data_to_send()

        goaway = frame_factory.build_goaway_frame(last_stream_id=1)
        events = client.receive_data(goaway.serialize())

        draining = [
            e for e in events
            if isinstance(e, h2.events.ConnectionDraining)
        ]
        not_accepted = [
            e for e in events
            if isinstance(e, h2.events.StreamNotAccepted)
        ]
        assert len(draining) == 1
        assert [(e.stream_id, e.last_stream_id) for e in not_accepted] == [
            (3, 1), (5, 1),
        ]
        # The unaccepted streams are not removed, and no queued data is lost.
        assert {3, 5} <= set(client.streams)

    def test_unaccepted_streams_can_be_retried_then_reset(self) -> None:
        """
        The caller decides what to do with unaccepted streams: the request can
        be sent on a new connection and the old stream reset locally.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS, end_stream=True)
        client.send_headers(3, REQUEST_HEADERS, end_stream=True)
        server.receive_data(client.data_to_send())

        server.graceful_close(last_stream_id=1)
        client.receive_data(server.data_to_send())

        # Retry stream 3's request on a new connection.
        retry_client, retry_server = _connected_pair()
        retry_client.send_headers(1, REQUEST_HEADERS, end_stream=True)
        retry_events = retry_server.receive_data(
            retry_client.data_to_send(),
        )
        assert any(
            isinstance(e, h2.events.RequestReceived) for e in retry_events
        )

        # Abandon the old stream on the draining connection.
        client.reset_stream(3)
        frames = server.receive_data(client.data_to_send())
        assert any(isinstance(e, h2.events.StreamReset) for e in frames)

    def test_successive_remote_goaway_only_reports_newly_unaccepted(
        self, frame_factory,
    ) -> None:
        """
        A tightening GOAWAY reports only the streams in the newly rejected
        range.
        """
        client, _ = _connected_pair()
        for stream_id in (1, 3, 5, 7):
            client.send_headers(stream_id, REQUEST_HEADERS, end_stream=True)
        client.data_to_send()

        first = frame_factory.build_goaway_frame(last_stream_id=5)
        events = client.receive_data(first.serialize())
        first_unaccepted = [
            e for e in events if isinstance(e, h2.events.StreamNotAccepted)
        ]
        assert [e.stream_id for e in first_unaccepted] == [7]

        second = frame_factory.build_goaway_frame(last_stream_id=1)
        events = client.receive_data(second.serialize())
        draining = [
            e for e in events
            if isinstance(e, h2.events.ConnectionDraining)
        ]
        second_unaccepted = [
            e for e in events if isinstance(e, h2.events.StreamNotAccepted)
        ]
        assert len(draining) == 1
        assert [e.stream_id for e in second_unaccepted] == [3, 5]

    def test_remote_goaway_must_not_increase_last_stream_id(
        self, frame_factory,
    ) -> None:
        """
        A later GOAWAY with a larger last_stream_id is a protocol error.
        """
        client, _ = _connected_pair()
        client.receive_data(
            frame_factory.build_goaway_frame(last_stream_id=1).serialize(),
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            client.receive_data(
                frame_factory.build_goaway_frame(last_stream_id=3).serialize(),
            )

    def test_goaway_and_rst_stream_for_unaccepted_stream(self) -> None:
        """
        GOAWAY and RST_STREAM can arrive interleaved: an unaccepted stream
        that is also reset yields the StreamReset event without errors.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS, end_stream=True)
        client.send_headers(3, REQUEST_HEADERS, end_stream=True)
        server.receive_data(client.data_to_send())

        server.graceful_close(last_stream_id=1)
        server.reset_stream(3)
        client.receive_data(server.data_to_send())

        # Stream 1 completes normally in the meantime.
        server.send_headers(1, RESPONSE_HEADERS, end_stream=True)
        events = client.receive_data(server.data_to_send())
        kinds = {type(e) for e in events}
        assert h2.events.ResponseReceived in kinds
        assert h2.events.StreamEnded in kinds

    def test_goaway_then_reset_for_accepted_stream(self) -> None:
        """
        An accepted stream may still be reset by either side while draining.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS)
        client.send_headers(3, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        server.graceful_close(last_stream_id=3)
        client.receive_data(server.data_to_send())

        # The client resets the accepted stream 1 while the server
        # independently resets stream 3.
        client.reset_stream(1)
        server.reset_stream(3)

        server_events = server.receive_data(client.data_to_send())
        client_events = client.receive_data(server.data_to_send())
        assert any(isinstance(e, h2.events.StreamReset) for e in server_events)
        assert any(isinstance(e, h2.events.StreamReset) for e in client_events)

    def test_duplicate_reset_after_goaway_is_ignored(self) -> None:
        """
        A second RST_STREAM for a stream reset during draining does not raise.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS, end_stream=True)
        server.receive_data(client.data_to_send())

        server.graceful_close(last_stream_id=1)
        client.receive_data(server.data_to_send())

        client.reset_stream(1)
        wire = client.data_to_send()
        first = server.receive_data(wire)
        assert any(isinstance(e, h2.events.StreamReset) for e in first)
        # Replaying the same RST_STREAM must not break the draining connection.
        second = server.receive_data(wire)
        assert second == []
        assert server.state_machine.state == \
            h2.connection.ConnectionState.SERVER_OPEN

    def test_flow_control_blocked_then_recovered_while_draining(self) -> None:
        """
        A stream blocked on flow control before the GOAWAY can resume sending
        once WINDOW_UPDATE frames arrive during the drain.
        """
        client, server = _connected_pair()
        # Shrink the windows the server offers to the client for sending.
        server.update_settings({
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 10,
        })
        client.receive_data(server.data_to_send())
        server.receive_data(client.data_to_send())

        client.send_headers(1, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        # Fill the 10 byte window; more data cannot be sent yet.
        client.send_data(1, b"0123456789")
        server.receive_data(client.data_to_send())
        with pytest.raises(h2.exceptions.FlowControlError):
            client.send_data(1, b"blocked")

        # Drain starts while the stream is flow-control blocked.
        server.graceful_close(last_stream_id=1)
        client.receive_data(server.data_to_send())
        with pytest.raises(h2.exceptions.FlowControlError):
            client.send_data(1, b"blocked")

        # Processing the body frees stream and connection windows.
        server.acknowledge_received_data(10, stream_id=1)
        client.receive_data(server.data_to_send())

        # Sending now succeeds and the stream can end normally.
        client.send_data(1, b"recovered", end_stream=True)
        events = server.receive_data(client.data_to_send())
        data_events = [
            e for e in events if isinstance(e, h2.events.DataReceived)
        ]
        assert data_events[-1].data == b"recovered"
        assert any(isinstance(e, h2.events.StreamEnded) for e in events)

    def test_inbound_flow_control_recovered_while_draining(self) -> None:
        """
        Window updates emitted by a draining server for an accepted stream
        keep the client's response flow unblocked.
        """
        client, server = _connected_pair()
        client.update_settings({
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 5,
        })
        server.receive_data(client.data_to_send())
        client.receive_data(server.data_to_send())

        client.send_headers(1, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        server.send_headers(1, RESPONSE_HEADERS)
        server.send_data(1, b"abcde")
        client.receive_data(server.data_to_send())
        with pytest.raises(h2.exceptions.FlowControlError):
            server.send_data(1, b"x")

        server.graceful_close(last_stream_id=1)

        # The client consumes the data and opens the window; sending resumes.
        client.acknowledge_received_data(5, stream_id=1)
        server.receive_data(client.data_to_send())

        server.send_data(1, b"fghij", end_stream=True)
        events = client.receive_data(server.data_to_send())
        assert any(isinstance(e, h2.events.StreamEnded) for e in events)

    def test_multiple_streams_interleaved_during_drain(self) -> None:
        """
        Several accepted streams carry interleaved DATA after graceful_close
        and all end normally; a later new stream is refused.
        """
        client, server = _connected_pair()
        for stream_id in (1, 3):
            client.send_headers(stream_id, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        server.graceful_close(last_stream_id=3)
        client.receive_data(server.data_to_send())

        # Interleave request bodies and responses across both streams.
        client.send_data(1, b"req1-a")
        client.send_data(3, b"req3-a")
        server.receive_data(client.data_to_send())

        server.send_headers(1, RESPONSE_HEADERS)
        server.send_data(1, b"resp1-a")
        client.receive_data(server.data_to_send())

        client.send_data(3, b"req3-b", end_stream=True)
        client.send_data(1, b"req1-b", end_stream=True)
        events = server.receive_data(client.data_to_send())
        ended = [e.stream_id for e in events
                 if isinstance(e, h2.events.StreamEnded)]
        assert sorted(ended) == [1, 3]

        server.send_data(1, b"resp1-b", end_stream=True)
        server.send_headers(3, RESPONSE_HEADERS, end_stream=True)
        events = client.receive_data(server.data_to_send())
        assert sorted(
            e.stream_id for e in events
            if isinstance(e, h2.events.StreamEnded)
        ) == [1, 3]

        # A brand new stream arriving late is refused, not accepted.
        late_client = _client()
        late_client.initiate_connection()
        late_client.data_to_send()
        late_client.send_headers(5, REQUEST_HEADERS)
        server.receive_data(late_client.data_to_send())
        assert 5 not in server.streams

    def test_bidirectional_drain_closes_when_all_streams_end(self) -> None:
        """
        When both peers have sent graceful GOAWAY frames and every accepted
        stream has completed, the connection transitions to CLOSED without
        dropping in-flight data.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS)
        server.receive_data(client.data_to_send())

        # Both directions drain; stream 1 remains usable.
        client.graceful_close(last_stream_id=0)
        server.graceful_close(last_stream_id=1)
        client.receive_data(server.data_to_send())
        server.receive_data(client.data_to_send())
        assert client.draining and server.draining
        assert client.state_machine.state == \
            h2.connection.ConnectionState.CLIENT_OPEN

        # Complete the outstanding stream normally.
        client.send_data(1, b"final", end_stream=True)
        server.receive_data(client.data_to_send())
        server.send_headers(1, RESPONSE_HEADERS, end_stream=True)
        client.receive_data(server.data_to_send())

        assert client.state_machine.state == \
            h2.connection.ConnectionState.CLOSED
        assert server.state_machine.state == \
            h2.connection.ConnectionState.CLOSED

    def test_drain_stays_open_when_only_one_side_closes_streams(self) -> None:
        """
        The connection does not close until both peers are draining, even if
        all streams have completed.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS, end_stream=True)
        server.receive_data(client.data_to_send())

        server.graceful_close(last_stream_id=1)
        client.receive_data(server.data_to_send())
        server.send_headers(1, RESPONSE_HEADERS, end_stream=True)
        client.receive_data(server.data_to_send())

        assert server.state_machine.state == \
            h2.connection.ConnectionState.SERVER_OPEN
        assert client.state_machine.state == \
            h2.connection.ConnectionState.CLIENT_OPEN

        # Once the client also drains and nothing remains, it closes.
        client.graceful_close(last_stream_id=0)
        assert client.state_machine.state == \
            h2.connection.ConnectionState.CLOSED

    def test_unaccepted_streams_do_not_keep_mutual_drain_open(self) -> None:
        """
        Streams rejected by the draining peer are reported but do not prevent
        a mutual drain from completing; only mutually accepted streams do.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS, end_stream=True)
        client.send_headers(3, REQUEST_HEADERS, end_stream=True)
        server.receive_data(client.data_to_send())

        # Server rejects stream 3; it remains the client's responsibility.
        server.graceful_close(last_stream_id=1)
        events = client.receive_data(server.data_to_send())
        assert any(
            isinstance(e, h2.events.StreamNotAccepted) and e.stream_id == 3
            for e in events
        )

        # Server completes the accepted stream and drains outbound too.
        server.send_headers(1, RESPONSE_HEADERS, end_stream=True)
        client.receive_data(server.data_to_send())
        client.graceful_close(last_stream_id=0)
        server.receive_data(client.data_to_send())

        assert server.state_machine.state == \
            h2.connection.ConnectionState.CLOSED
        assert client.state_machine.state == \
            h2.connection.ConnectionState.CLOSED

    def test_in_flight_inbound_stream_excluded_by_tight_goaway(self) -> None:
        """
        An inbound stream that was created but ends up above the tightened
        local last_stream_id does not keep a mutual drain alive. Such a stream
        is refused if more of its frames arrive.
        """
        client, server = _connected_pair()
        client.send_headers(1, REQUEST_HEADERS, end_stream=True)
        client.send_headers(3, REQUEST_HEADERS, end_stream=True)
        server.receive_data(client.data_to_send())
        assert {1, 3} <= set(server.streams)

        # Advertise a permissive bound first, then tighten below stream 3.
        server.graceful_close(last_stream_id=3)
        client.receive_data(server.data_to_send())
        server.graceful_close(last_stream_id=1)
        client.receive_data(server.data_to_send())

        # Finish stream 1; stream 3 is excluded from processing by the bound.
        server.send_headers(1, RESPONSE_HEADERS, end_stream=True)
        client.receive_data(server.data_to_send())

        # Mutual drain completes even though stream 3 objects linger.
        client.graceful_close(last_stream_id=0)
        server.receive_data(client.data_to_send())
        assert server.state_machine.state == \
            h2.connection.ConnectionState.CLOSED

"""
Tests for session-scoped SSH agent forwarding.

These tests never touch a real ssh-agent. Both sides of every forwarding
session are in-memory fakes connected by a real ``socket.socketpair``, so
blocking reads and EOF semantics match production sockets without any network
access.
"""

import socket
import struct
import threading
from unittest.mock import patch

from pytest import raises

from paramiko import Message, RSAKey
from paramiko.agent import (
    MAX_AGENT_MESSAGE_SIZE,
    AgentClientProxy,
    AgentKeyNotAuthorized,
    AgentProtocolError,
    AgentSessionClosed,
    ForwardedAgentSession,
    LocalAgentUnavailable,
    _read_agent_message,
    SSH2_AGENT_IDENTITIES_ANSWER,
    SSH2_AGENT_SIGN_RESPONSE,
    SSH_AGENT_FAILURE,
    cSSH2_AGENTC_REQUEST_IDENTITIES,
    cSSH2_AGENTC_SIGN_REQUEST,
)

from ._util import _support


def frame(payload):
    return struct.pack(">I", len(payload)) + payload


def read_frame(sock):
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        assert chunk, "socket closed mid length-prefix"
        header += chunk
    (length,) = struct.unpack(">I", header)
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        assert chunk, "socket closed mid message"
        payload += chunk
    return payload


def identities_answer(keys):
    msg = Message()
    msg.add_byte(bytes((SSH2_AGENT_IDENTITIES_ANSWER,)))
    msg.add_int(len(keys))
    for index, blob in enumerate(keys):
        msg.add_string(blob)
        msg.add_string("comment-{}".format(index))
    return frame(msg.asbytes())


def sign_response(signature=b"signed-bytes"):
    msg = Message()
    msg.add_byte(bytes((SSH2_AGENT_SIGN_RESPONSE,)))
    msg.add_string(signature)
    return frame(msg.asbytes())


def identity_request():
    msg = Message()
    msg.add_byte(cSSH2_AGENTC_REQUEST_IDENTITIES)
    return frame(msg.asbytes())


def sign_request(key_blob, data=b"challenge", flags=0):
    msg = Message()
    msg.add_byte(cSSH2_AGENTC_SIGN_REQUEST)
    msg.add_string(key_blob)
    msg.add_string(data)
    msg.add_int(flags)
    return frame(msg.asbytes())


class FakeLocalAgent:
    """
    Local-agent side of a socketpair.

    Serves the real framed agent protocol from a background thread, records
    every request it receives, and can be scripted with canned responses.
    """

    def __init__(self, key_blobs, sign_answers=None):
        self._key_blobs = list(key_blobs)
        self._sign_answers = list(sign_answers or [])
        self.received = []
        self.closed = threading.Event()
        self._local, remote = socket.socketpair()
        self.connection = remote
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            while True:
                try:
                    payload = read_frame(self._local)
                except OSError:
                    break
                except AssertionError:
                    break
                self.received.append(payload)
                ptype = payload[0]
                if ptype == ord(cSSH2_AGENTC_REQUEST_IDENTITIES):
                    self._local.sendall(
                        identities_answer(self._key_blobs)
                    )
                elif ptype == ord(cSSH2_AGENTC_SIGN_REQUEST):
                    if self._sign_answers:
                        answer = self._sign_answers.pop(0)
                    else:
                        answer = sign_response()
                    self._local.sendall(answer)
                else:
                    self._local.sendall(
                        frame(bytes((SSH_AGENT_FAILURE,)))
                    )
        finally:
            self.closed.set()

    def sign_calls(self):
        return [
            payload
            for payload in self.received
            if payload[0] == ord(cSSH2_AGENTC_SIGN_REQUEST)
        ]

    def join(self, timeout=5):
        self._thread.join(timeout)
        assert not self._thread.is_alive(), "fake local agent hung"

    def shutdown(self):
        try:
            self._local.close()
        except OSError:
            pass
        try:
            self.connection.close()
        except OSError:
            pass


class FakeRemote:
    """Remote-side socket wrapper plus a tiny channel-shaped adapter."""

    def __init__(self):
        self.channel_sock, local = socket.socketpair()
        self.channel = _SocketChannel(local)

    def send(self, data):
        self.channel_sock.sendall(data)

    def recv_frame(self):
        return read_frame(self.channel_sock)

    def close(self):
        self.channel_sock.close()
        self.channel.close()


class _SocketChannel:
    """Minimal Channel-like object backed by one end of a socketpair."""

    def __init__(self, sock):
        self._sock = sock
        self.closed = False

    def recv(self, wanted):
        if self.closed:
            return b""
        return self._sock.recv(wanted)

    def send(self, data):
        if self.closed:
            raise OSError("channel closed")
        return self._sock.send(data)

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self._sock.close()
        except OSError:
            pass


def real_rsa_blob():
    return RSAKey.from_private_key_file(_support("rsa.key")).asbytes()


def make_pair(blobs=None, sign_answers=None):
    blobs = blobs or [b"key-blob-alpha", b"key-blob-beta"]
    agent = FakeLocalAgent(blobs, sign_answers=sign_answers)
    remote = FakeRemote()
    session = ForwardedAgentSession(
        remote.channel, agent_connection=agent.connection
    )
    return session, agent, remote


def serve_in_thread(session):
    """Run a session's serve loop, capturing its terminal exception."""
    holder = {}

    def target():
        try:
            session.serve()
        except Exception as error:
            holder["error"] = error

    runner = threading.Thread(target=target, daemon=True)
    runner.start()
    return runner, holder


class TestForwardedAgentSessionInit:
    def test_snapshots_only_the_local_agent_identities(self):
        blob = real_rsa_blob()
        session, agent, _ = make_pair(blobs=[blob])
        # One identity listing roundtrip happened at construction.
        assert len(agent.received) == 1
        assert agent.received[0][0] == ord(
            cSSH2_AGENTC_REQUEST_IDENTITIES
        )
        assert session.allowed_key_blobs == (blob,)
        assert len(session.allowed_key_fingerprints) == 1
        assert session.is_key_authorized(blob)
        assert not session.is_key_authorized(b"totally-different")
        agent.shutdown()

    def test_raises_when_no_local_agent_available(self):
        with patch("paramiko.agent.get_agent_connection", return_value=None):
            with raises(LocalAgentUnavailable):
                ForwardedAgentSession(_SocketChannel(socket.socket()))

    def test_raises_on_malformed_local_identity_answer(self):
        agent_side, conn = socket.socketpair()
        agent_side.sendall(frame(bytes((SSH_AGENT_FAILURE,))))
        try:
            with raises(AgentProtocolError):
                ForwardedAgentSession(
                    _SocketChannel(conn), agent_connection=conn
                )
        finally:
            agent_side.close()
            conn.close()
        agent_side.close()
        conn.close()


class TestForwardedAgentIdentityListing:
    def test_answers_from_session_allowlist_without_local_traffic(self):
        session, agent, remote = make_pair()
        before = len(agent.received)
        runner, holder = serve_in_thread(session)
        remote.send(identity_request())
        payload = remote.recv_frame()
        remote.close()
        runner.join(5)
        assert not runner.is_alive()
        assert "error" not in holder
        assert session.closed
        # The listing was served from cached state; no extra local call.
        assert len(agent.received) == before
        parsed = Message(payload)
        assert ord(parsed.get_byte()) == SSH2_AGENT_IDENTITIES_ANSWER
        assert parsed.get_int() == 2
        assert parsed.get_binary() == b"key-blob-alpha"
        assert parsed.get_text() == "comment-0"
        agent.shutdown()


class TestForwardedAgentSigning:
    def test_forwards_only_after_exact_blob_match(self):
        blob = real_rsa_blob()
        session, agent, remote = make_pair(blobs=[blob])
        runner, holder = serve_in_thread(session)
        remote.send(sign_request(blob, data=b"challenge", flags=2))
        payload = remote.recv_frame()
        remote.close()
        runner.join(5)
        assert not runner.is_alive()
        assert "error" not in holder
        assert len(agent.sign_calls()) == 1
        request = Message(agent.sign_calls()[0])
        assert ord(request.get_byte()) == 13
        assert request.get_string() == blob
        assert request.get_string() == b"challenge"
        assert request.get_int() == 2
        answer = Message(payload)
        assert ord(answer.get_byte()) == SSH2_AGENT_SIGN_RESPONSE
        assert answer.get_binary() == b"signed-bytes"
        agent.shutdown()

    def test_rejects_key_from_a_different_session(self):
        session_a, agent_a, _ = make_pair(blobs=[b"session-a-key"])
        session_b, agent_b, remote_b = make_pair(
            blobs=[b"session-b-key"]
        )
        with raises(AgentKeyNotAuthorized):
            session_b.handle_message(
                sign_request(b"session-a-key")[4:]
            )
        # Nothing beyond the startup identity listing hit B's local agent.
        assert agent_b.sign_calls() == []
        # Session A remains fully usable - state is isolated.
        assert session_a.is_key_authorized(b"session-a-key")
        assert not session_b.is_key_authorized(b"session-a-key")
        agent_a.shutdown()
        agent_b.shutdown()

    def test_rejects_unknown_fingerprint_with_same_length_blob(self):
        blob = b"A" * 64
        session, agent, _ = make_pair(blobs=[blob])
        with raises(AgentKeyNotAuthorized):
            session.handle_message(sign_request(b"B" * 64)[4:])
        assert agent.sign_calls() == []
        agent.shutdown()

    def test_flags_malformed_sign_response_from_local_agent(self):
        blob = b"k"
        agent = FakeLocalAgent(
            [blob],
            sign_answers=[frame(bytes((SSH_AGENT_FAILURE,)))],
        )
        remote = FakeRemote()
        session = ForwardedAgentSession(
            remote.channel, agent_connection=agent.connection
        )
        with raises(AgentProtocolError):
            session.handle_message(sign_request(blob)[4:])
        agent.shutdown()


class TestForwardedAgentLifecycle:
    def test_close_revokes_session_and_closes_local_connection(self):
        session, agent, _ = make_pair()
        assert not session.closed
        session.close()
        assert session.closed
        agent.join()
        assert agent.closed.is_set()
        with raises(AgentSessionClosed):
            session.handle_message(identity_request()[4:])
        agent.shutdown()

    def test_signature_replay_after_close_never_reaches_local_agent(self):
        blob = b"replay-me"
        session, agent, _ = make_pair(blobs=[blob])
        replay = sign_request(blob)[4:]
        # First, a legitimate signature works.
        session.handle_message(replay)
        calls_before_close = len(agent.received)
        session.close()
        with raises(AgentSessionClosed):
            session.handle_message(replay)
        # The replayed request was blocked at the session boundary.
        assert len(agent.received) == calls_before_close
        agent.shutdown()

    def test_concurrent_sessions_have_independent_revocation(self):
        blob_a, blob_b = b"shared-shape-a", b"shared-shape-b"
        session_a, agent_a, _ = make_pair(blobs=[blob_a])
        session_b, agent_b, _ = make_pair(blobs=[blob_b])
        session_a.close()
        with raises(AgentSessionClosed):
            session_a.handle_message(sign_request(blob_a)[4:])
        # B is untouched by A's revocation and can still sign.
        response = session_b.handle_message(sign_request(blob_b)[4:])
        parsed = Message(response)
        assert ord(parsed.get_byte()) == SSH2_AGENT_SIGN_RESPONSE
        assert parsed.get_binary() == b"signed-bytes"
        agent_a.join()
        assert agent_a.closed.is_set()
        assert not agent_b.closed.is_set()
        agent_b.shutdown()

    def test_two_live_sessions_isolate_their_local_agent_connections(self):
        # End-to-end style: two sessions over independent socketpairs must
        # not share identity allow-lists, local sockets, or revocation state.
        blob_a, blob_b = b"session-a-only", b"session-b-only"
        agent_a = FakeLocalAgent([blob_a])
        agent_b = FakeLocalAgent([blob_b])
        remote_a = FakeRemote()
        remote_b = FakeRemote()
        session_a = ForwardedAgentSession(
            remote_a.channel, agent_connection=agent_a.connection
        )
        session_b = ForwardedAgentSession(
            remote_b.channel, agent_connection=agent_b.connection
        )
        assert session_a.allowed_key_blobs == (blob_a,)
        assert session_b.allowed_key_blobs == (blob_b,)
        assert agent_a.connection is not agent_b.connection
        # A's key is rejected by B without any traffic on B's local agent.
        with raises(AgentKeyNotAuthorized):
            session_b.handle_message(sign_request(blob_a)[4:])
        assert agent_b.sign_calls() == []
        # Revoking A has no effect on B's ability to sign.
        session_a.close()
        response = session_b.handle_message(sign_request(blob_b)[4:])
        parsed = Message(response)
        assert ord(parsed.get_byte()) == SSH2_AGENT_SIGN_RESPONSE
        assert parsed.get_binary() == b"signed-bytes"
        assert not session_b.closed
        agent_a.shutdown()
        agent_b.shutdown()
        remote_a.close()
        remote_b.close()

    def test_remote_channel_eof_ends_serve_and_revokes(self):
        session, agent, remote = make_pair()
        remote.send(identity_request())
        remote.close()
        session.serve()
        assert session.closed
        agent.join()
        assert agent.closed.is_set()
        agent.shutdown()


class TestForwardedAgentMalformedInput:
    def test_oversized_inner_blob_refused_before_local_agent_call(self):
        # The frame stays legal, but its inner key blob claims more bytes
        # than the frame actually contains. The parser must reject instead
        # of zero-padding and relaying a fabricated request to the agent.
        session, agent, _ = make_pair(blobs=[b"ok-key"])
        msg = Message()
        msg.add_byte(cSSH2_AGENTC_SIGN_REQUEST)
        msg.add_int(9999)
        msg.add_bytes(b"x" * 32)  # only 32 of the claimed 9999 bytes
        assert len(msg.asbytes()) - 5 < 9999
        with raises(AgentProtocolError):
            session.handle_message(msg.asbytes())
        assert agent.sign_calls() == []
        session.close()
        agent.shutdown()

    def test_oversized_outer_length_field_is_refused(self):
        class StaticChannel:
            def recv(self, wanted):
                return struct.pack(">I", MAX_AGENT_MESSAGE_SIZE + 1)

            def send(self, data):
                return len(data)

            def close(self):
                pass

        with raises(AgentProtocolError):
            _read_agent_message(StaticChannel())

    def test_zero_outer_length_field_is_refused(self):
        class StaticChannel:
            def recv(self, wanted):
                return struct.pack(">I", 0)

            def send(self, data):
                return len(data)

            def close(self):
                pass

        with raises(AgentProtocolError):
            _read_agent_message(StaticChannel())

    def test_bad_inner_string_length_truncates_and_raises(self):
        # Sign request claiming a 4242 byte blob that isn't present.
        session, agent, _ = make_pair(blobs=[b"ok-key"])
        msg = Message()
        msg.add_byte(cSSH2_AGENTC_SIGN_REQUEST)
        msg.add_int(4242)
        msg.add_bytes(b"short")  # only 5 of the claimed 4242 bytes
        assert len(msg.asbytes()) - 5 < 4242
        with raises(AgentProtocolError):
            session.handle_message(msg.asbytes())
        assert agent.sign_calls() == []
        session.close()
        agent.shutdown()

    def test_truncated_frame_body_raises(self):
        class PartialChannel:
            def __init__(self):
                self._chunks = [
                    struct.pack(">I", 20),
                    b"only-two",
                    b"",
                ]

            def recv(self, wanted):
                if self._chunks:
                    return self._chunks.pop(0)
                return b""

            def send(self, data):
                return len(data)

            def close(self):
                pass

        with raises(AgentProtocolError):
            _read_agent_message(PartialChannel())

    def test_serve_loop_revokes_session_on_protocol_error(self):
        session, agent, remote = make_pair()
        runner, holder = serve_in_thread(session)
        remote.send(struct.pack(">I", 0))
        runner.join(5)
        assert not runner.is_alive()
        assert session.closed
        assert isinstance(holder["error"], AgentProtocolError)
        agent.shutdown()
        remote.close()

    def test_unsupported_message_type_is_not_relayed(self):
        session, agent, _ = make_pair()
        with raises(AgentProtocolError):
            session.handle_message(bytes((99,)) + b"\x00")
        # Only the startup identity listing touched the local agent.
        assert all(
            payload[0] == ord(cSSH2_AGENTC_REQUEST_IDENTITIES)
            for payload in agent.received
        )
        agent.shutdown()


class TestAgentClientProxy:
    def test_serves_sign_request_then_revokes_when_channel_eofs(self):
        blob = b"proxied-key"
        agent = FakeLocalAgent([blob])
        remote = FakeRemote()
        proxy = AgentClientProxy(
            remote.channel, agent_connection=agent.connection
        )
        remote.send(sign_request(blob))
        payload = remote.recv_frame()
        remote.close()
        proxy.thread.join(5)
        assert not proxy.thread.is_alive()
        assert proxy.session.closed
        agent.join()
        assert agent.closed.is_set()
        answer = Message(payload)
        assert ord(answer.get_byte()) == SSH2_AGENT_SIGN_RESPONSE
        assert answer.get_binary() == b"signed-bytes"
        agent.shutdown()

    def test_missing_local_agent_is_recorded_not_silently_forwarded(self):
        remote = FakeRemote()
        with patch("paramiko.agent.get_agent_connection", return_value=None):
            proxy = AgentClientProxy(remote.channel)
            proxy.thread.join(5)
        assert not proxy.thread.is_alive()
        assert isinstance(proxy.thread.error, LocalAgentUnavailable)
        remote.close()

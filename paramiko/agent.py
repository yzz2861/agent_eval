# Copyright (C) 2003-2007  John Rochester <john@jrochester.org>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
SSH Agent interface
"""

import os
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
from hashlib import sha256
from logging import DEBUG
from select import select

from paramiko.common import byte_chr, io_sleep
from paramiko.message import Message
from paramiko.pkey import PKey, UnknownKeyType
from paramiko.ssh_exception import (
    AgentKeyNotAuthorized,
    AgentProtocolError,
    AgentSessionClosed,
    AuthenticationException,
    LocalAgentUnavailable,
    SSHException,
)
from paramiko.util import asbytes, get_logger

cSSH2_AGENTC_REQUEST_IDENTITIES = byte_chr(11)
SSH2_AGENT_IDENTITIES_ANSWER = 12
cSSH2_AGENTC_SIGN_REQUEST = byte_chr(13)
SSH2_AGENT_SIGN_RESPONSE = 14
SSH_AGENT_FAILURE = 5

#: Maximum size, in bytes, of a single SSH agent message (including its 4 byte
#: length prefix) that we are willing to parse or emit. The real protocol has
#: no hard limit, but unbounded remote-controlled lengths make trivial memory
#: exhaustion and length-smuggling attacks possible.
MAX_AGENT_MESSAGE_SIZE = 256 * 1024

SSH_AGENT_RSA_SHA2_256 = 2
SSH_AGENT_RSA_SHA2_512 = 4
# NOTE: RFC mildly confusing; while these flags are OR'd together, OpenSSH at
# least really treats them like "AND"s, in the sense that if it finds the
# SHA256 flag set it won't continue looking at the SHA512 one; it
# short-circuits right away.
# Thus, we never want to eg submit 6 to say "either's good".
ALGORITHM_FLAG_MAP = {
    "rsa-sha2-256": SSH_AGENT_RSA_SHA2_256,
    "rsa-sha2-512": SSH_AGENT_RSA_SHA2_512,
}
for key, value in list(ALGORITHM_FLAG_MAP.items()):
    ALGORITHM_FLAG_MAP[f"{key}-cert-v01@openssh.com"] = value


# TODO (backwards incompat): rename all these - including making some of their
# methods public?
class AgentSSH:
    def __init__(self):
        self._conn = None
        self._keys = ()

    def get_keys(self):
        """
        Return the list of keys available through the SSH agent, if any.  If
        no SSH agent was running (or it couldn't be contacted), an empty list
        will be returned.

        This method performs no IO, just returns the list of keys retrieved
        when the connection was made.

        :return:
            a tuple of `.AgentKey` objects representing keys available on the
            SSH agent
        """
        return self._keys

    def _connect(self, conn):
        self._conn = conn
        ptype, result = self._send_message(cSSH2_AGENTC_REQUEST_IDENTITIES)
        if ptype != SSH2_AGENT_IDENTITIES_ANSWER:
            raise SSHException("could not get keys from ssh-agent")
        keys = []
        for i in range(result.get_int()):
            keys.append(
                AgentKey(
                    agent=self,
                    blob=result.get_binary(),
                    comment=result.get_text(),
                )
            )
        self._keys = tuple(keys)

    def _close(self):
        if self._conn is not None:
            self._conn.close()
        self._conn = None
        self._keys = ()

    def _send_message(self, msg):
        msg = asbytes(msg)
        self._conn.send(struct.pack(">I", len(msg)) + msg)
        data = self._read_all(4)
        msg = Message(self._read_all(struct.unpack(">I", data)[0]))
        return ord(msg.get_byte()), msg

    def _read_all(self, wanted):
        result = self._conn.recv(wanted)
        while len(result) < wanted:
            if len(result) == 0:
                raise SSHException("lost ssh-agent")
            extra = self._conn.recv(wanted - len(result))
            if len(extra) == 0:
                raise SSHException("lost ssh-agent")
            result += extra
        return result


class AgentProxyThread(threading.Thread):
    """
    Class in charge of communication between two channels.
    """

    def __init__(self, agent):
        threading.Thread.__init__(self, target=self.run)
        self._agent = agent
        self._exit = False

    def run(self):
        try:
            (r, addr) = self.get_connection()
            # Found that r should be either
            # a socket from the socket library or None
            self.__inr = r
            # The address should be an IP address as a string? or None
            self.__addr = addr
            self._agent.connect()
            if not isinstance(self._agent, int) and (
                self._agent._conn is None
                or not hasattr(self._agent._conn, "fileno")
            ):
                raise AuthenticationException("Unable to connect to SSH agent")
            self._communicate()
        except:
            # XXX Not sure what to do here ... raise or pass ?
            raise

    def _communicate(self):
        import fcntl

        oldflags = fcntl.fcntl(self.__inr, fcntl.F_GETFL)
        fcntl.fcntl(self.__inr, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)
        while not self._exit:
            events = select([self._agent._conn, self.__inr], [], [], 0.5)
            for fd in events[0]:
                if self._agent._conn == fd:
                    data = self._agent._conn.recv(512)
                    if len(data) != 0:
                        self.__inr.send(data)
                    else:
                        self._close()
                        break
                elif self.__inr == fd:
                    data = self.__inr.recv(512)
                    if len(data) != 0:
                        self._agent._conn.send(data)
                    else:
                        self._close()
                        break
            time.sleep(io_sleep)

    def _close(self):
        self._exit = True
        self.__inr.close()
        self._agent._conn.close()


class AgentLocalProxy(AgentProxyThread):
    """
    Class to be used when wanting to ask a local SSH Agent being
    asked from a remote fake agent (so use a unix socket for ex.)
    """

    def __init__(self, agent):
        AgentProxyThread.__init__(self, agent)

    def get_connection(self):
        """
        Return a pair of socket object and string address.

        May block!
        """
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.bind(self._agent._get_filename())
            conn.listen(1)
            (r, addr) = conn.accept()
            return r, addr
        except:
            raise


def _read_agent_message(conn):
    """
    Read one length-prefixed SSH agent message from ``conn``.

    Lengths are validated against `MAX_AGENT_MESSAGE_SIZE` instead of being
    trusted blindly, so a hostile peer cannot make us allocate arbitrary
    amounts of memory or wait forever for a claimed huge payload.
    """
    header = conn.recv(4)
    if not header:
        return b""
    while len(header) < 4:
        extra = conn.recv(4 - len(header))
        if not extra:
            raise AgentProtocolError(
                "truncated SSH agent message length prefix"
            )
        header += extra
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > MAX_AGENT_MESSAGE_SIZE:
        raise AgentProtocolError(
            "invalid SSH agent message length: {}".format(length)
        )
    payload = conn.recv(length)
    if not payload:
        raise AgentProtocolError("truncated SSH agent message body")
    while len(payload) < length:
        extra = conn.recv(length - len(payload))
        if not extra:
            raise AgentProtocolError("truncated SSH agent message body")
        payload += extra
    return payload


def _frame_message(payload):
    """Serialize an agent message payload with a checked length prefix."""
    payload = asbytes(payload)
    if len(payload) > MAX_AGENT_MESSAGE_SIZE:
        raise AgentProtocolError(
            "outbound SSH agent message exceeds size limit"
        )
    return struct.pack(">I", len(payload)) + payload


def _strict_string(message):
    """
    Read an SSH string, rejecting truncated or oversized payloads.

    `Message.get_string` silently zero-pads short data, which would let a
    malformed remote message be turned into a well-formed request to the local
    agent. We parse lengths ourselves so bad input stays a protocol error.
    """
    stream = message.packet
    header = stream.read(4)
    if len(header) != 4:
        raise AgentProtocolError("truncated SSH agent string length")
    (length,) = struct.unpack(">I", header)
    if length > MAX_AGENT_MESSAGE_SIZE:
        raise AgentProtocolError(
            "invalid SSH agent string length: {}".format(length)
        )
    data = stream.read(length)
    if len(data) != length:
        raise AgentProtocolError(
            "truncated SSH agent string: expected {} bytes, got {}".format(
                length, len(data)
            )
        )
    return data


class ForwardedAgentSession:
    """
    Session-scoped, policy-enforcing entry point for one forwarded agent.

    Each incoming ``auth-agent@openssh.com`` channel gets its own instance.
    The session opens a dedicated connection to the *local* agent, snapshots
    the identities that local agent exposes, and only forwards requests that
    refer to those allow-listed public key blobs. Remote bytes are never
    spliced into the local agent protocol: every request is parsed and
    re-serialized from validated fields, and every answer is parsed before
    being re-framed for the remote channel.

    Closing the session (including when the remote channel closes) immediately
    revokes it: subsequent requests raise `.AgentSessionClosed` and never reach
    the local agent. Concurrent sessions hold independent local connections,
    key allow-lists and closed flags.

    :param channel:
        the remote-side channel (or channel-like object) carrying SSH agent
        protocol bytes.
    :param agent_connection:
        optional pre-connected local agent connection; mainly useful for
        testing. When omitted, `get_agent_connection` is used.

    :raises `.LocalAgentUnavailable`:
        if no local SSH agent can be contacted.
    :raises `.AgentProtocolError`:
        if the local agent answers the initial identity request incorrectly.
    """

    def __init__(self, channel, agent_connection=None):
        self._channel = channel
        self._lock = threading.Lock()
        self._closed = False
        self._conn = agent_connection
        if self._conn is None:
            self._conn = get_agent_connection()
        if self._conn is None:
            raise LocalAgentUnavailable(
                "unable to connect to a local SSH agent for forwarding"
            )
        self._keys = ()
        try:
            self._load_identities()
        except BaseException:
            # A half-initialised session must not hold an open agent socket.
            self.close()
            raise

    @property
    def closed(self):
        return self._closed

    @property
    def allowed_key_blobs(self):
        """Tuple of public key blobs this session is allowed to sign with."""
        return tuple(self._key_blobs)

    @property
    def allowed_key_fingerprints(self):
        """Tuple of SHA256 fingerprints of the allow-listed key blobs."""
        return tuple(self._fingerprints)

    def is_key_authorized(self, key_blob):
        """Return whether ``key_blob`` matches one of this session's keys."""
        return sha256(asbytes(key_blob)).digest() in self._fingerprint_set

    def serve(self):
        """
        Drive the forwarding loop until the remote channel closes.

        Framing errors on the remote side are surfaced as
        `.AgentProtocolError`; policy violations raised by `handle_message`
        propagate to the caller. The session is always closed on exit.
        """
        try:
            while True:
                try:
                    payload = _read_agent_message(self._channel)
                except OSError:
                    # The channel was closed underneath us (locally or by
                    # the remote end); that is normal session teardown, not
                    # a malformed protocol message.
                    break
                if not payload:
                    break
                response = self.handle_message(payload)
                if response is not None:
                    self._channel.send(_frame_message(response))
        finally:
            self.close()

    def handle_message(self, payload):
        """
        Validate and service one remote agent message payload.

        Only identity listing and signing requests are part of the agent
        forwarding surface. Returns the raw payload to send back to the remote
        channel (without length prefix), or ``None`` for messages that warrant
        no answer.

        :raises `.AgentSessionClosed`:
            if the session has already been revoked.
        :raises `.AgentKeyNotAuthorized`:
            if a sign request names a key outside this session's allow-list.
        :raises `.AgentProtocolError`:
            if the message or a local agent answer is malformed.
        """
        with self._lock:
            if self._closed:
                raise AgentSessionClosed(
                    "agent forwarding session has been closed"
                )
            if not payload:
                raise AgentProtocolError("empty SSH agent message")
            request_type = ord(payload[:1])
            if request_type == ord(cSSH2_AGENTC_REQUEST_IDENTITIES):
                return self._identity_answer()
            if request_type == ord(cSSH2_AGENTC_SIGN_REQUEST):
                return self._handle_sign_request(Message(payload[1:]))
            # Unknown/unsupported agent message types get a protocol failure,
            # never a blind relay to the local agent.
            raise AgentProtocolError(
                "unsupported SSH agent message type: {}".format(request_type)
            )

    def close(self):
        """Revoke the session and close its local agent connection."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            conn = self._conn
            self._conn = None
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass

    def _load_identities(self):
        request = Message()
        request.add_byte(cSSH2_AGENTC_REQUEST_IDENTITIES)
        ptype, result = self._roundtrip(request)
        if ptype != SSH2_AGENT_IDENTITIES_ANSWER:
            raise AgentProtocolError(
                "local agent returned unexpected message {} while listing "
                "identities".format(ptype)
            )
        count = result.get_int()
        keys = []
        blobs = []
        comments = []
        for _ in range(count):
            blob = _strict_string(result)
            # Comments are strings too; validate rather than trust leftovers.
            comment = _strict_string(result)
            keys.append(AgentKey(agent=self, blob=blob))
            blobs.append(blob)
            comments.append(comment)
        if result.get_remainder():
            raise AgentProtocolError(
                "trailing bytes in agent identities answer"
            )
        self._keys = tuple(keys)
        self._key_blobs = tuple(blobs)
        self._key_comments = tuple(comments)
        self._fingerprints = tuple(
            sha256(blob).digest() for blob in blobs
        )
        self._fingerprint_set = set(self._fingerprints)

    def _identity_answer(self):
        answer = Message()
        answer.add_byte(byte_chr(SSH2_AGENT_IDENTITIES_ANSWER))
        answer.add_int(len(self._key_blobs))
        for blob, comment in zip(self._key_blobs, self._key_comments):
            answer.add_string(blob)
            answer.add_string(comment)
        return answer.asbytes()

    def _handle_sign_request(self, message):
        key_blob = _strict_string(message)
        data = _strict_string(message)
        flag_bytes = message.get_bytes(4)
        if len(flag_bytes) != 4:
            raise AgentProtocolError("truncated SSH agent sign request flags")
        if message.get_remainder():
            raise AgentProtocolError("trailing bytes in agent sign request")
        (flags,) = struct.unpack(">I", flag_bytes)
        # Match the exact allow-listed blob (fingerprint set backed) before
        # trusting the request enough to touch the local agent.
        if not self.is_key_authorized(key_blob):
            raise AgentKeyNotAuthorized(
                "signature requested for a key not granted to this "
                "forwarding session (sha256 fingerprint: {})".format(
                    sha256(key_blob).hexdigest()
                )
            )
        request = Message()
        request.add_byte(cSSH2_AGENTC_SIGN_REQUEST)
        request.add_string(key_blob)
        request.add_string(data)
        request.add_int(flags)
        ptype, result = self._roundtrip(request)
        if ptype != SSH2_AGENT_SIGN_RESPONSE:
            raise AgentProtocolError(
                "local agent returned unexpected message {} for sign "
                "request".format(ptype)
            )
        signature = _strict_string(result)
        if result.get_remainder():
            raise AgentProtocolError(
                "trailing bytes in agent sign response"
            )
        response = Message()
        response.add_byte(byte_chr(SSH2_AGENT_SIGN_RESPONSE))
        response.add_string(signature)
        return response.asbytes()

    def _roundtrip(self, message):
        """Send a validated message to the local agent; parse its answer."""
        if self._closed or self._conn is None:
            raise AgentSessionClosed(
                "agent forwarding session has been closed"
            )
        conn = self._conn
        conn.send(_frame_message(message.asbytes()))
        try:
            payload = _read_agent_message(conn)
        except OSError as error:
            raise AgentProtocolError(
                "lost connection to local SSH agent: {}".format(error)
            )
        if not payload:
            raise AgentProtocolError("local SSH agent closed the connection")
        answer = Message(payload)
        return ord(answer.get_byte()), answer


class ForwardedAgentThread(threading.Thread):
    """
    Background driver owning one `.ForwardedAgentSession`.

    A remote-side policy failure (closed session replay, unauthorized key,
    malformed message) terminates the thread and revokes the session instead
    of silently relaying data. The exception is retained on ``error`` for
    callers/tests that want to inspect why forwarding stopped.
    """

    def __init__(self, channel, agent_connection=None):
        super().__init__(target=self.run)
        self.channel = channel
        self._agent_connection = agent_connection
        self.session = None
        self.error = None

    def run(self):
        try:
            self.session = ForwardedAgentSession(
                self.channel, agent_connection=self._agent_connection
            )
            self.session.serve()
        except Exception as error:
            self.error = error
            if self.session is not None:
                self.session.close()


def get_agent_connection():
    """
    Returns some SSH agent object, or None if none were found/supported.

    .. versionadded:: 2.10
    """
    if ("SSH_AUTH_SOCK" in os.environ) and (sys.platform != "win32"):
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.connect(os.environ["SSH_AUTH_SOCK"])
            return conn
        except:
            # probably a dangling env var: the ssh agent is gone
            return
    elif sys.platform == "win32":
        from . import win_openssh, win_pageant

        conn = None
        if win_pageant.can_talk_to_agent():
            conn = win_pageant.PageantConnection()
        elif win_openssh.can_talk_to_agent():
            conn = win_openssh.OpenSSHAgentConnection()
        return conn
    else:
        # no agent support
        return


class AgentClientProxy:
    """
    Client-side handle for one remote request to our forwarded agent.

    Each instance owns a dedicated `.ForwardedAgentSession` (run via
    `.ForwardedAgentThread`) bound to the channel the server opened back to
    us. The session, not a stateless byte pump, decides which identities and
    signature requests may reach the local SSH agent, and it is revoked as
    soon as the channel or this proxy is closed.
    """

    def __init__(self, chanRemote, agent_connection=None):
        self.thread = ForwardedAgentThread(
            chanRemote, agent_connection=agent_connection
        )
        self.thread.start()

    def __del__(self):
        self.close()

    @property
    def session(self):
        """The `.ForwardedAgentSession` once the worker has created it."""
        return self.thread.session

    def close(self):
        """
        Revoke the forwarding session and terminate its worker thread.
        """
        thread = getattr(self, "thread", None)
        if thread is None:
            return
        if thread.session is not None:
            thread.session.close()
        thread.join(1000)


class AgentServerProxy(AgentSSH):
    """
    Allows an SSH server to access a forwarded agent.

    This also creates a unix domain socket on the system to allow external
    programs to also access the agent. For this reason, you probably only want
    to create one of these.

    :meth:`connect` must be called before it is usable. This will also load the
    list of keys the agent contains. You must also call :meth:`close` in
    order to clean up the unix socket and the thread that maintains it.
    (:class:`contextlib.closing` might be helpful to you.)

    :param .Transport t: Transport used for SSH Agent communication forwarding

    :raises: `.SSHException` -- mostly if we lost the agent
    """

    def __init__(self, t):
        AgentSSH.__init__(self)
        self.__t = t
        self._dir = tempfile.mkdtemp("sshproxy")
        os.chmod(self._dir, stat.S_IRWXU)
        self._file = self._dir + "/sshproxy.ssh"
        self.thread = AgentLocalProxy(self)
        self.thread.start()

    def __del__(self):
        self.close()

    def connect(self):
        conn_sock = self.__t.open_forward_agent_channel()
        if conn_sock is None:
            raise SSHException("lost ssh-agent")
        conn_sock.set_name("auth-agent")
        self._connect(conn_sock)

    def close(self):
        """
        Terminate the agent, clean the files, close connections
        Should be called manually
        """
        os.remove(self._file)
        os.rmdir(self._dir)
        self.thread._exit = True
        self.thread.join(1000)
        self._close()

    def get_env(self):
        """
        Helper for the environment under unix

        :return:
            a dict containing the ``SSH_AUTH_SOCK`` environment variables
        """
        return {"SSH_AUTH_SOCK": self._get_filename()}

    def _get_filename(self):
        return self._file


class AgentRequestHandler:
    """
    Primary/default implementation of SSH agent forwarding functionality.

    Simply instantiate this class, handing it a live command-executing session
    object, and it will handle forwarding any local SSH agent processes it
    finds.

    For example::

        # Connect
        client = SSHClient()
        client.connect(host, port, username)
        # Obtain session
        session = client.get_transport().open_session()
        # Forward local agent
        AgentRequestHandler(session)
        # Commands executed after this point will see the forwarded agent on
        # the remote end.
        session.exec_command("git clone https://my.git.repository/")
    """

    def __init__(self, chanClient):
        self._conn = None
        self.__chanC = chanClient
        chanClient.request_forward_agent(self._forward_agent_handler)
        self.__clientProxys = []

    def _forward_agent_handler(self, chanRemote):
        self.__clientProxys.append(AgentClientProxy(chanRemote))

    def __del__(self):
        self.close()

    def close(self):
        for p in self.__clientProxys:
            p.close()


class Agent(AgentSSH):
    """
    Client interface for using private keys from an SSH agent running on the
    local machine.  If an SSH agent is running, this class can be used to
    connect to it and retrieve `.PKey` objects which can be used when
    attempting to authenticate to remote SSH servers.

    Upon initialization, a session with the local machine's SSH agent is
    opened, if one is running. If no agent is running, initialization will
    succeed, but `get_keys` will return an empty tuple.

    :raises: `.SSHException` --
        if an SSH agent is found, but speaks an incompatible protocol

    .. versionchanged:: 2.10
        Added support for native openssh agent on windows (extending previous
        putty pageant support)
    """

    def __init__(self):
        AgentSSH.__init__(self)

        conn = get_agent_connection()
        if not conn:
            return
        self._connect(conn)

    def close(self):
        """
        Close the SSH agent connection.
        """
        self._close()


class AgentKey(PKey):
    """
    Private key held in a local SSH agent.  This type of key can be used for
    authenticating to a remote server (signing).  Most other key operations
    work as expected.

    .. versionchanged:: 3.2
        Added the ``comment`` kwarg and attribute.

    .. versionchanged:: 3.2
        Added the ``.inner_key`` attribute holding a reference to the 'real'
        key instance this key is a proxy for, if one was obtainable, else None.
    """

    def __init__(self, agent: Agent, blob: bytes, comment: str = ""):
        self.public_blob = None  # Match sibling key classes
        self.agent = agent
        self.blob = blob
        self.comment = comment
        msg = Message(blob)
        self.name = msg.get_text()
        self._logger = get_logger(__file__)
        self.inner_key = None
        try:
            self.inner_key = PKey.from_type_string(
                key_type=self.name, key_bytes=blob
            )
        except UnknownKeyType:
            # Log, but don't explode, since inner_key is a best-effort thing.
            err = "Unable to derive inner_key for agent key of type {!r}"
            self.log(DEBUG, err.format(self.name))

    def log(self, *args, **kwargs):
        return self._logger.log(*args, **kwargs)

    def asbytes(self):
        # Prefer inner_key.asbytes, since that will differ for eg RSA-CERT
        return self.inner_key.asbytes() if self.inner_key else self.blob

    def get_name(self):
        return self.name

    def get_bits(self):
        # Have to work around PKey's default get_bits being crap
        if self.inner_key is not None:
            return self.inner_key.get_bits()
        return super().get_bits()

    def __getattr__(self, name):
        """
        Proxy any un-implemented methods/properties to the inner_key.
        """
        if self.inner_key is None:  # nothing to proxy to
            raise AttributeError(name)
        return getattr(self.inner_key, name)

    @property
    def _fields(self):
        fallback = [self.get_name(), self.blob]
        return self.inner_key._fields if self.inner_key else fallback

    def sign_ssh_data(self, data, algorithm=None):
        msg = Message()
        msg.add_byte(cSSH2_AGENTC_SIGN_REQUEST)
        # NOTE: this used to be just self.blob, which is not entirely right for
        # RSA-CERT 'keys' - those end up always degrading to ssh-rsa type
        # signatures, for reasons probably internal to OpenSSH's agent code,
        # even if everything else wants SHA2 (including our flag map).
        msg.add_string(self.asbytes())
        msg.add_string(data)
        msg.add_int(ALGORITHM_FLAG_MAP.get(algorithm, 0))
        ptype, result = self.agent._send_message(msg)
        if ptype != SSH2_AGENT_SIGN_RESPONSE:
            raise SSHException("key cannot be used for signing")
        return result.get_binary()

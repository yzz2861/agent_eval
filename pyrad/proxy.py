# proxy.py
#
# Copyright 2005,2007 Wichert Akkerman <wichert@wiggy.net>
#
# A RADIUS proxy as defined in RFC 2865

from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import secrets
import select
import socket
import struct
import time

from pyrad.server import ServerPacketError
from pyrad.server import Server
from pyrad.server import _LookupHost
from pyrad import packet

# codes of the RADIUS replies accepted on the proxy socket
_REPLY_CODES = (packet.AccessAccept, packet.AccessReject,
                packet.AccountingResponse, packet.AccessChallenge,
                packet.DisconnectACK, packet.DisconnectNAK,
                packet.CoAACK, packet.CoANAK)

# The prefix makes it possible to recognise a state value which was created
# by a pyrad proxy. The instance id behind the prefix identifies this proxy
# and the nonce identifies the request.
_PROXY_STATE_PREFIX = b'pyrad-proxy-v1:'
_PROXY_INSTANCE_LENGTH = 16
_PROXY_NONCE_LENGTH = 16

_ACCOUNTING_STYLE_CODES = (
    packet.AccountingRequest, packet.CoARequest, packet.DisconnectRequest)

_REQUEST_REPLY_CODES = {
    packet.AccessRequest: (packet.AccessAccept, packet.AccessReject,
                           packet.AccessChallenge),
    packet.StatusServer: (packet.AccessAccept, packet.AccessReject,
                          packet.AccessChallenge, packet.AccountingResponse),
    packet.AccountingRequest: (packet.AccountingResponse,),
    packet.CoARequest: (packet.CoAACK, packet.CoANAK),
    packet.DisconnectRequest: (packet.DisconnectACK, packet.DisconnectNAK),
}

_INVALID_PROXY_REPLY = 'Dropping invalid proxy reply'


def _TrimPacket(raw):
    """Return a packet without octets outside its Length field."""
    if len(raw) < 4:
        raise packet.PacketError('Packet header is corrupt')
    length = struct.unpack('!H', raw[2:4])[0]
    if length < 20 or len(raw) < length:
        raise packet.PacketError('Packet has invalid length')
    return raw[:length]


def _RawPacket(pkt):
    """Return the wire form of a packet, encoding a local reply if needed."""
    raw = getattr(pkt, "raw_packet", None)
    if raw is None:
        if getattr(pkt, "_proxy_local_raw_failed", False):
            raise AttributeError("Local packet cannot be encoded")
        raw = pkt.ReplyPacket()
        pkt.raw_packet = raw
    return _TrimPacket(raw)


def _AttributeList(attributes):
    """Split raw attributes into ``(type, raw attribute)`` tuples."""
    result = []
    offset = 0
    while offset < len(attributes):
        if len(attributes) - offset < 2:
            raise packet.PacketError('Attribute header is corrupt')
        (code, length) = struct.unpack('!BB', attributes[offset:offset + 2])
        if length < 2 or offset + length > len(attributes):
            raise packet.PacketError('Attribute length is invalid')
        result.append((code, attributes[offset:offset + length]))
        offset += length
    return result


def _AttributeValue(raw_attribute):
    """Return the value of one encoded attribute."""
    return raw_attribute[2:]


def _EncodeAttribute(code, value):
    """Encode an attribute without applying dictionary value types."""
    return struct.pack('!BB', code, len(value) + 2) + value


def _AttributeValues(attributes, code):
    """Return all values of an attribute code in wire order."""
    return [_AttributeValue(raw_attribute)
            for (attr_code, raw_attribute) in _AttributeList(attributes)
            if attr_code == code]


def _RequestMessageAuthenticatorVector(code, authenticator):
    """Return the vector used by a request's Message-Authenticator."""
    if code in _ACCOUNTING_STYLE_CODES:
        return 16 * b'\x00'
    return authenticator


def _ReplyMessageAuthenticatorVector(reply_code, request_code,
                                     request_authenticator):
    """Return the vector used by a reply's Message-Authenticator."""
    if reply_code == packet.AccountingResponse and \
            request_code != packet.StatusServer:
        return 16 * b'\x00'
    return request_authenticator


def _SecretBytes(secret):
    """Return a shared secret as bytes."""
    if isinstance(secret, bytes):
        return secret
    if isinstance(secret, str):
        return secret.encode('utf-8')
    return bytes(secret)


def _Endpoint(address):
    """Return the host and port of a socket source address."""
    if address is None or len(address) < 2:
        return None
    return (address[0], address[1])


def _SameEndpoint(first, second):
    """Compare two socket endpoints, accepting IPv4-mapped IPv6 forms."""
    if first is None or second is None:
        return False
    if first == second:
        return True
    if first[1] != second[1]:
        return False

    def mapped(host):
        try:
            return ipaddress.ip_address(host).ipv4_mapped
        except (AttributeError, TypeError, ValueError):
            return host

    first_host = first[0]
    second_host = second[0]
    if first_host == second_host:
        return True
    first_mapped = mapped(first_host)
    second_mapped = mapped(second_host)
    if first_mapped is not None and second_mapped is not None:
        return first_mapped == second_mapped
    if first_mapped is not None and str(first_mapped) == second_host:
        return True
    return second_mapped is not None and str(second_mapped) == first_host


@dataclass
class ProxySession:
    """A request forwarded by :class:`Proxy` and the client awaiting it.

    The proxy state value is the opaque key of the session. A reply is only
    associated when its source, Identifier, Response Authenticator,
    Message-Authenticator and the complete set of Proxy-State values match
    this session. Reordered values are restored to the client order.
    ``sent_at`` is a :func:`time.monotonic` value.
    """

    client_address: tuple
    client_id: int
    request_authenticator: bytes
    request_code: int
    home_server: str
    home_port: int
    home_secret: bytes
    client_secret: bytes
    sent_at: float
    proxy_state: bytes
    original_proxy_states: tuple
    forwarded_proxy_states: tuple
    forwarded_id: int
    forwarded_authenticator: bytes
    forwarded_code: int
    raw_request: bytes
    client_fd: object = None
    attempts: int = 1
    replied: bool = False
    client_request: object = None

    @property
    def home_address(self):
        """The ``(host, port)`` endpoint the request was sent to."""
        return (self.home_server, self.home_port)

    @property
    def client(self):
        """Alias for :attr:`client_address`."""
        return self.client_address

    @property
    def client_addr(self):
        """Alias for :attr:`client_address`."""
        return self.client_address

    @property
    def source(self):
        """Alias for :attr:`client_address`."""
        return self.client_address

    @property
    def authenticator(self):
        """The client Request Authenticator."""
        return self.request_authenticator

    @property
    def home(self):
        """The home server address."""
        return self.home_server

    @property
    def original_id(self):
        """The client Identifier."""
        return self.client_id

    @property
    def token(self):
        """The Proxy-State value which identifies this session."""
        return self.proxy_state

    @property
    def state(self):
        """Alias for :attr:`proxy_state`."""
        return self.proxy_state

    @property
    def outbound_request(self):
        """The encoded request sent to the home server."""
        return self.raw_request

    @property
    def outbound_id(self):
        """The Identifier used towards the home server."""
        return self.forwarded_id

    @property
    def request_id(self):
        """The Identifier of the client request."""
        return self.client_id

    def expired(self, now, timeout):
        """Return whether the session is older than ``timeout``."""
        return now - self.sent_at > timeout


ProxyAssociation = ProxySession
_ProxySession = ProxySession


class _ProxyRequestBytes(bytes):
    """Encoded proxy request with the session that owns it."""

    def __new__(cls, data, session):
        value = bytes.__new__(cls, data)
        value.session = session
        return value


class Proxy(Server):
    """Base class for RADIUS proxies.

    A :class:`~pyrad.server.Server` with an extra socket,
    ``self._proxyfd``, to forward requests to home servers and receive
    their replies. :meth:`~pyrad.server.Server.Run` creates the socket
    (IPv4 only, not bound to a fixed port) before it starts waiting for
    packets.

    Use :meth:`AddProxySession` to prepare a request and
    :meth:`ForwardRequest` to send it. Every forwarded request gets an
    unpredictable Proxy-State value which is stored together with the
    client address and port, the client Identifier and Request
    Authenticator, the home server and the send time. Replies are matched
    by that complete association, never by the Identifier alone.

    A subclass can override :meth:`HandleProxyPacket` to inspect a verified
    reply. The default implementation strips the proxy's own Proxy-State
    and sends the reply to the client, signed with the client's secret.
    Raise :class:`~pyrad.server.ServerPacketError` to drop the request.
    """

    def __init__(self, *args, proxy_timeout=30.0, proxy_require_ma=True,
                 **kwargs):
        """
        :param proxy_timeout: seconds after which a pending proxy session
            expires
        :type  proxy_timeout: float
        :param proxy_require_ma: require a Message-Authenticator in
            Access- and Status-Server replies
        :type  proxy_require_ma: bool
        """
        Server.__init__(self, *args, **kwargs)
        self.proxy_timeout = proxy_timeout
        self.proxy_require_ma = proxy_require_ma
        self._proxy_instance = secrets.token_bytes(_PROXY_INSTANCE_LENGTH)
        self._proxy_sessions = {}
        self._proxy_request_index = {}
        # kept as aliases for applications which inspect the pending state
        self.proxy_sessions = self._proxy_sessions
        self.proxy_associations = self._proxy_sessions
        self.pending_proxy_requests = self._proxy_sessions
        self._proxy_associations = self._proxy_sessions

    @property
    def timeout(self):
        """Alias of :attr:`proxy_timeout`."""
        return self.proxy_timeout

    @timeout.setter
    def timeout(self, value):
        self.proxy_timeout = value

    def _PrepareSockets(self):
        Server._PrepareSockets(self)
        self._proxyfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._fdmap[self._proxyfd.fileno()] = self._proxyfd
        self._poll.register(self._proxyfd.fileno(),
                            (select.POLLIN | select.POLLPRI | select.POLLERR))

    def _ExpireProxySessions(self, now=None):
        """Drop sessions whose reply can no longer be accepted."""
        if now is None:
            now = time.monotonic()
        for session in list(self._proxy_sessions.values()):
            if session.expired(now, self.proxy_timeout):
                self._RemoveProxySession(session)

    def _RemoveProxySession(self, session):
        """Remove a session from the pending maps."""
        if self._proxy_sessions.get(session.proxy_state) is session:
            del self._proxy_sessions[session.proxy_state]
        for (key, value) in list(self._proxy_request_index.items()):
            if value is session:
                del self._proxy_request_index[key]

    def _ResolveHome(self, request, home_server, port):
        """Return the home address, port and secret for a request."""
        if isinstance(home_server, tuple):
            if len(home_server) < 2:
                raise ServerPacketError('Invalid proxy home server')
            if port is None:
                port = home_server[1]
            home_server = home_server[0]

        remote_host = None
        if not isinstance(home_server, str):
            remote_host = home_server
            home_server = getattr(home_server, 'address', None)
        if home_server is None:
            raise ServerPacketError('Invalid proxy home server')

        configured_host = _LookupHost(self.hosts, home_server)
        if remote_host is None:
            remote_host = configured_host
        elif configured_host is not None:
            remote_host = configured_host
        if remote_host is None:
            raise ServerPacketError('Received packet from unknown host')

        if port is None:
            if isinstance(request, packet.AuthPacket):
                port = getattr(remote_host, 'authport', 1812)
            elif isinstance(request, packet.CoAPacket):
                port = getattr(remote_host, 'coaport', 3799)
            elif isinstance(request, packet.AcctPacket):
                port = getattr(remote_host, 'acctport', 1813)
            elif request.code == packet.AccessRequest:
                port = getattr(remote_host, 'authport', 1812)
            elif request.code in (packet.CoARequest,
                                  packet.DisconnectRequest):
                port = getattr(remote_host, 'coaport', 3799)
            else:
                port = getattr(remote_host, 'acctport', 1813)

        return (home_server, port, _SecretBytes(remote_host.secret))

    def _CheckProxyStates(self, states):
        """Reject duplicate and looped Proxy-State attributes."""
        if len(set(states)) != len(states):
            raise ServerPacketError('Dropping request with duplicate Proxy-State')

        prefix_end = len(_PROXY_STATE_PREFIX) + _PROXY_INSTANCE_LENGTH
        for state in states:
            if not state.startswith(_PROXY_STATE_PREFIX):
                continue
            instance = state[len(_PROXY_STATE_PREFIX):prefix_end]
            if instance == self._proxy_instance:
                raise ServerPacketError('Dropping proxied request loop')

    def _NewProxyState(self):
        """Create a Proxy-State value which does not belong to a session."""
        while True:
            value = (_PROXY_STATE_PREFIX + self._proxy_instance +
                     secrets.token_bytes(_PROXY_NONCE_LENGTH))
            if value not in self._proxy_sessions:
                return value

    def _SignProxyRequest(self, raw, secret):
        """Re-sign a forwarded request with the home server's secret.

        Access- and Status-Server requests keep their random Request
        Authenticator. Accounting, CoA and Disconnect requests get the
        authenticator RFC 2866/RFC 5176 define for their new attributes.
        A Message-Authenticator, if present or added, is recalculated.
        """
        raw = _TrimPacket(raw)
        (code, identifier, length) = struct.unpack('!BBH', raw[:4])
        authenticator = raw[4:20]
        attributes = raw[20:length]
        attr_list = _AttributeList(attributes)

        ma_attrs = [raw_attr for (attr_code, raw_attr) in attr_list
                    if attr_code == 80]
        if len(ma_attrs) > 1:
            raise ServerPacketError(_INVALID_PROXY_REPLY)

        if code in (packet.AccessRequest, packet.StatusServer) and not ma_attrs:
            attr_list.insert(0, (80, _EncodeAttribute(80, 16 * b'\x00')))

        def encode_attrs():
            return b''.join(raw_attr for (_, raw_attr) in attr_list)

        def zero_message_authenticator(values):
            result = []
            for (attr_code, raw_attr) in values:
                if attr_code == 80:
                    result.append(
                        (attr_code, _EncodeAttribute(80, 16 * b'\x00')))
                else:
                    result.append((attr_code, raw_attr))
            return result

        ma_attrs = [raw_attr for (attr_code, raw_attr) in attr_list
                    if attr_code == 80]
        if ma_attrs:
            header = struct.pack('!BBH', code, identifier,
                                 20 + len(encode_attrs()))
            vector = _RequestMessageAuthenticatorVector(code, authenticator)
            zeroed = b''.join(
                raw_attr for (_, raw_attr) in
                zero_message_authenticator(attr_list))
            digest = hmac.new(secret, header + vector + zeroed,
                              digestmod='MD5').digest()
            patched = []
            for (attr_code, raw_attr) in attr_list:
                if attr_code == 80:
                    patched.append((attr_code,
                                    _EncodeAttribute(80, digest)))
                else:
                    patched.append((attr_code, raw_attr))
            attr_list = patched

        attributes = encode_attrs()
        header = struct.pack('!BBH', code, identifier, 20 + len(attributes))
        if code in _ACCOUNTING_STYLE_CODES:
            authenticator = hashlib.md5(
                header + 16 * b'\x00' + attributes + secret).digest()

        return header + authenticator + attributes

    def AddProxySession(self, request, home_server, port=None, sent_at=None):
        """Associate a client request with a home server.

        The request gets an unpredictable Proxy-State value appended and is
        re-signed with the home server's secret. Forwarding the same
        request to the same home server again reuses the association (a
        retransmission), but refreshes ``sent_at``.

        :param request: client request, received or locally created
        :type  request: pyrad.packet.Packet
        :param home_server: address of a home server from ``hosts``, a
            :class:`~pyrad.server.RemoteHost`, or an ``(address, port)``
            tuple
        :param port: home server port, by default the port for the request
            type of the ``RemoteHost`` entry
        :param sent_at: :func:`time.monotonic` value to use as send time
        :return: the proxy session, including ``raw_request``
        :rtype:  ProxySession
        """
        if request.raw_packet is None:
            raw = _TrimPacket(request.RequestPacket())
        else:
            raw = _TrimPacket(request.raw_packet)

        code = raw[0]
        identifier = raw[1]
        request_authenticator = raw[4:20]
        client_address = _Endpoint(getattr(request, 'source', None))
        client_fd = getattr(request, 'fd', None)
        client_secret = _SecretBytes(getattr(request, 'secret', b''))

        original_states = tuple(_AttributeValues(raw[20:], 33))
        self._CheckProxyStates(original_states)

        (home_address, home_port, home_secret) = self._ResolveHome(
            request, home_server, port)
        now = time.monotonic() if sent_at is None else sent_at
        if sent_at is None:
            self._ExpireProxySessions(now)

        index_key = (client_address, identifier, request_authenticator,
                     home_address, home_port)
        session = self._proxy_request_index.get(index_key)
        if session is not None:
            if session.expired(now, self.proxy_timeout):
                self._RemoveProxySession(session)
            else:
                session.sent_at = now
                session.attempts += 1
                session.client_fd = client_fd or session.client_fd
                session.client_request = request
                return session

        proxy_state = self._NewProxyState()
        forwarded_states = original_states + (proxy_state,)
        attributes = raw[20:] + _EncodeAttribute(33, proxy_state)
        forwarded = struct.pack('!BBH', code, identifier,
                                20 + len(attributes)) + \
            request_authenticator + attributes
        forwarded = self._SignProxyRequest(forwarded, home_secret)

        session = ProxySession(
            client_address=client_address,
            client_id=identifier,
            request_authenticator=request_authenticator,
            request_code=code,
            home_server=home_address,
            home_port=home_port,
            home_secret=home_secret,
            client_secret=client_secret,
            sent_at=now,
            proxy_state=proxy_state,
            original_proxy_states=original_states,
            forwarded_proxy_states=forwarded_states,
            forwarded_id=forwarded[1],
            forwarded_authenticator=forwarded[4:20],
            forwarded_code=forwarded[0],
            raw_request=forwarded,
            client_fd=client_fd,
            client_request=request,
        )
        self._proxy_sessions[proxy_state] = session
        self._proxy_request_index[index_key] = session
        request.proxy_session = session
        request.proxy_association = session
        request.proxy_state = proxy_state
        return session

    def CreateProxyRequest(self, request, home_server, port=None,
                           sent_at=None):
        """Create and register a request for a home server.

        :return: the encoded request; its ``session`` attribute is the
            :class:`ProxySession`
        :rtype:  bytes
        """
        session = self.AddProxySession(request, home_server, port=port,
                                       sent_at=sent_at)
        return _ProxyRequestBytes(session.raw_request, session)

    def ForwardRequest(self, request, home_server, port=None, sent_at=None):
        """Send a client request to a home server.

        The request is sent on ``self._proxyfd``. Calling this method again
        for the same request and home server retransmits it with the same
        Proxy-State value.

        :return: the proxy session
        :rtype:  ProxySession
        """
        session = self.AddProxySession(request, home_server, port=port,
                                       sent_at=sent_at)
        self._proxyfd.sendto(session.raw_request, session.home_address)
        return session

    AddProxyAssociation = AddProxySession
    RegisterProxySession = AddProxySession
    SendProxyRequest = ForwardRequest
    ForwardProxyRequest = ForwardRequest
    ProxyRequest = ForwardRequest

    def _FindProxySession(self, pkt):
        """Find the session a reply on the proxy socket belongs to."""
        try:
            raw = _RawPacket(pkt)
            states = tuple(_AttributeValues(raw[20:], 33))
        except (packet.PacketError, AttributeError, AssertionError):
            return None

        matches = [self._proxy_sessions[state] for state in states
                   if state in self._proxy_sessions]
        if len(matches) != 1:
            return None
        session = matches[0]
        if len(states) != len(session.forwarded_proxy_states) or \
                set(states) != set(session.forwarded_proxy_states):
            return None
        if pkt.id != session.forwarded_id:
            return None
        if not _SameEndpoint(_Endpoint(pkt.source), session.home_address):
            return None
        if session.expired(time.monotonic(), self.proxy_timeout):
            self._RemoveProxySession(session)
            return None
        return session

    def _AssociatePacket(self, pkt, fd):
        """Attach the matching proxy session to a received reply."""
        proxyfd = getattr(self, '_proxyfd', None)
        try:
            is_proxy_socket = proxyfd is not None and fd.fileno() == proxyfd.fileno()
        except AttributeError:
            is_proxy_socket = proxyfd is not None and fd is proxyfd
        if is_proxy_socket:
            session = self._FindProxySession(pkt)
            pkt.proxy_session = session
            pkt.proxy_association = session
            pkt.proxy_context = session
            pkt.proxy_state = getattr(session, 'proxy_state', None)

    def _VerifyProxyReply(self, session, pkt):
        """Verify a reply against the complete proxy session."""
        try:
            raw = _RawPacket(pkt)
            attr_list = _AttributeList(raw[20:])
        except (packet.PacketError, AttributeError, AssertionError):
            return False
        pkt.raw_packet = raw

        if time.monotonic() - session.sent_at > self.proxy_timeout:
            return False
        if pkt.id != session.forwarded_id:
            return False
        if not _SameEndpoint(_Endpoint(pkt.source), session.home_address):
            return False

        states = tuple(_AttributeValue(raw_attr)
                       for (code, raw_attr) in attr_list if code == 33)
        if len(states) != len(session.forwarded_proxy_states) or \
                set(states) != set(session.forwarded_proxy_states):
            return False

        allowed = _REQUEST_REPLY_CODES.get(session.request_code, _REPLY_CODES)
        if pkt.code not in allowed:
            return False

        expected = hashlib.md5(
            raw[:4] + session.forwarded_authenticator + raw[20:] +
            session.home_secret).digest()
        if not hmac.compare_digest(expected, raw[4:20]):
            return False

        ma_attrs = [raw_attr for (code, raw_attr) in attr_list if code == 80]
        if len(ma_attrs) > 1:
            return False
        if ma_attrs:
            if not pkt.verify_message_authenticator(
                    secret=session.home_secret,
                    original_authenticator=session.forwarded_authenticator,
                    original_code=session.forwarded_code):
                return False
        elif self.proxy_require_ma and session.request_code in (
                packet.AccessRequest, packet.StatusServer):
            return False
        return True

    def _BuildClientReply(self, session, pkt):
        """Strip the proxy state and sign the reply for the client."""
        raw = _RawPacket(pkt)
        attr_list = _AttributeList(raw[20:])

        filtered = []
        state_position = None
        for (code, raw_attr) in attr_list:
            if code == 33:
                if state_position is None:
                    state_position = len(filtered)
                continue
            filtered.append((code, raw_attr))
        if state_position is None:
            return None
        client_states = [(33, _EncodeAttribute(33, state))
                         for state in session.original_proxy_states]
        filtered[state_position:state_position] = client_states

        ma_attrs = [raw_attr for (code, raw_attr) in filtered if code == 80]
        if len(ma_attrs) > 1:
            return None
        if ma_attrs:
            header = struct.pack('!BBH', raw[0], session.client_id,
                                 20 + sum(len(raw_attr)
                                          for (_, raw_attr) in filtered))
            zeroed = b''.join(
                _EncodeAttribute(80, 16 * b'\x00') if code == 80
                else raw_attr for (code, raw_attr) in filtered)
            vector = _ReplyMessageAuthenticatorVector(
                raw[0], session.request_code,
                session.request_authenticator)
            digest = hmac.new(
                session.client_secret,
                header + vector + zeroed, digestmod='MD5').digest()
            patched = []
            for (code, raw_attr) in filtered:
                if code == 80:
                    patched.append((code, _EncodeAttribute(80, digest)))
                else:
                    patched.append((code, raw_attr))
            filtered = patched

        attributes = b''.join(raw_attr for (_, raw_attr) in filtered)
        header = struct.pack('!BBH', raw[0], session.client_id,
                             20 + len(attributes))
        authenticator = hashlib.md5(
            header + session.request_authenticator + attributes +
            session.client_secret).digest()
        return header + authenticator + attributes

    def _HandleProxyPacket(self, pkt):
        """Process a reply received on the proxy socket.

        The source host and its secret are checked first. A reply is only
        accepted when it belongs to a live proxy session, carries the
        complete set of Proxy-State values, has a valid Response
        Authenticator and, for Access- and Status-Server, a valid
        Message-Authenticator. All verification failures are dropped with
        the same error; nothing is sent to the client.

        :param pkt: received reply, with ``pkt.source`` set to the address
            of the home server
        :type  pkt: pyrad.packet.Packet
        """
        self._ExpireProxySessions()
        if isinstance(pkt, packet.Packet) and getattr(pkt, "raw_packet", None) is None:
            try:
                pkt.raw_packet = pkt.ReplyPacket()
            except Exception:
                pkt._proxy_local_raw_failed = True
        remote_host = _LookupHost(self.hosts, pkt.source[0])
        if remote_host is None:
            raise ServerPacketError('Received packet from unknown host')
        pkt.secret = remote_host.secret

        if pkt.code not in _REPLY_CODES:
            raise ServerPacketError('Received non-response on proxy socket')

        # Keep accepting simple test doubles and applications that used
        # the old hook for packets which did not come from the network.
        if not isinstance(pkt, packet.Packet):
            return

        session = getattr(pkt, 'proxy_session', None)
        if session is None:
            session = self._FindProxySession(pkt)
        if session is None or not self._VerifyProxyReply(session, pkt):
            raise ServerPacketError(_INVALID_PROXY_REPLY)

        client_reply = self._BuildClientReply(session, pkt)
        if client_reply is None:
            raise ServerPacketError(_INVALID_PROXY_REPLY)

        pkt.proxy_session = session
        pkt.proxy_association = session
        pkt.proxy_context = session
        pkt.proxy_state = session.proxy_state
        pkt.proxy_reply = client_reply
        try:
            self.HandleProxyPacket(pkt)
        finally:
            session.replied = True
            self._RemoveProxySession(session)

    def HandleProxyPacket(self, pkt):
        """Handle a verified reply from a home server.

        The default implementation sends the reply to the client. The
        session is available as ``pkt.proxy_session`` and the encoded,
        client-signed reply as ``pkt.proxy_reply``. A subclass may override
        this method to process the reply instead.

        :param pkt: verified reply
        :type  pkt: pyrad.packet.Packet
        """
        session = pkt.proxy_session
        if session.client_fd is not None:
            session.client_fd.sendto(pkt.proxy_reply,
                                     session.client_address)

    def _ProcessInput(self, fd):
        """Process available data.

        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop
        will drop the packet and log the reason.

        This function calls _HandleProxyPacket for the proxy socket and
        the base method for the other sockets.

        :param fd: socket to read packet from
        :type  fd: socket.socket
        """
        if fd.fileno() == self._proxyfd.fileno():
            pkt = self._GrabPacket(
                lambda data, s=self: s.CreatePacket(packet=data), fd)
            self._HandleProxyPacket(pkt)
        else:
            Server._ProcessInput(self, fd)

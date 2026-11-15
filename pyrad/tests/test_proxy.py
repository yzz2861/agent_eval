import hashlib
import hmac
import select
import socket
import struct
import unittest
from io import StringIO
from .mock import MockFd
from .mock import MockPoll
from .mock import MockSocket
from .mock import MockClassMethod
from .mock import UnmockClassMethods
from pyrad.proxy import Proxy
from pyrad import packet
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessAccept
from pyrad.packet import AccessRequest
from pyrad.server import RemoteHost
from pyrad.server import ServerPacketError
from pyrad.server import Server


PROXY_DICTIONARY = '''
ATTRIBUTE User-Name          1  string
ATTRIBUTE User-Password      2  string
ATTRIBUTE Reply-Message     18  string
ATTRIBUTE Proxy-State       33  octets
'''

CLIENT_SECRET = b'client-secret'
HOME_A_SECRET = b'home-a-secret'
HOME_B_SECRET = b'home-b-secret'


def forge_reply(raw, request_authenticator, secret, request_code, fix_ma=True):
    """Sign a modified reply as a home server would."""
    attributes = raw[20:]
    attr_list = []
    offset = 0
    while offset < len(attributes):
        length = attributes[offset + 1]
        attr_list.append(attributes[offset:offset + length])
        offset += length

    if fix_ma and any(attribute[0] == 80 for attribute in attr_list):
        zeroed = b''.join(
            b'\x50\x12' + 16 * b'\x00' if attribute[0] == 80
            else attribute for attribute in attr_list)
        header = raw[:4]
        if raw[0] == packet.AccountingResponse and \
                request_code != packet.StatusServer:
            vector = 16 * b'\x00'
        else:
            vector = request_authenticator
        digest = hmac.new(secret, header + vector + zeroed,
                          digestmod='MD5').digest()
        attr_list = [b'\x50\x12' + digest if attribute[0] == 80
                     else attribute for attribute in attr_list]

    attributes = b''.join(attr_list)
    header = raw[:4]
    authenticator = hashlib.md5(
        header + request_authenticator + attributes + secret).digest()
    return header + authenticator + attributes


class TrivialObject:
    """dummy object"""


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.orgsocket = socket.socket
        socket.socket = MockSocket
        self.proxy = Proxy()
        self.proxy._fdmap = {}

    def tearDown(self):
        socket.socket = self.orgsocket

    def testProxyFd(self):
        self.proxy._poll = MockPoll()
        self.proxy._PrepareSockets()
        self.assertTrue(isinstance(self.proxy._proxyfd, MockSocket))
        self.assertEqual(list(self.proxy._fdmap.keys()), [1])
        self.assertEqual(self.proxy._poll.registry,
                         {1: select.POLLIN | select.POLLPRI | select.POLLERR})


class ProxyPacketHandlingTests(unittest.TestCase):
    def setUp(self):
        self.proxy = Proxy()
        self.proxy.hosts['host'] = TrivialObject()
        self.proxy.hosts['host'].secret = 'supersecret'
        self.packet = TrivialObject()
        self.packet.code = AccessAccept
        self.packet.source = ('host', 'port')

    def testHandleProxyPacketUnknownHost(self):
        self.packet.source = ('stranger', 'port')
        try:
            self.proxy._HandleProxyPacket(self.packet)
        except ServerPacketError as e:
            self.assertTrue('unknown host' in str(e))
        else:
            self.fail()

    def testHandleProxyPacketSetsSecret(self):
        self.proxy._HandleProxyPacket(self.packet)
        self.assertEqual(self.packet.secret, 'supersecret')

    def testHandleProxyPacketMappedAddress(self):
        self.proxy.hosts['127.0.0.1'] = TrivialObject()
        self.proxy.hosts['127.0.0.1'].secret = 'v4secret'
        self.packet.source = ('::ffff:127.0.0.1', 1812, 0, 0)
        self.proxy._HandleProxyPacket(self.packet)
        self.assertEqual(self.packet.secret, 'v4secret')
        self.assertEqual(self.packet.source, ('::ffff:127.0.0.1', 1812, 0, 0))

    def testHandleProxyPacketHandlesWrongPacket(self):
        self.packet.code = AccessRequest
        try:
            self.proxy._HandleProxyPacket(self.packet)
        except ServerPacketError as e:
            self.assertTrue('non-response' in str(e))
        else:
            self.fail()

    def testHandleProxyPacketRejectsRequests(self):
        for code in (packet.AccessRequest, packet.AccountingRequest,
                     packet.StatusServer, packet.StatusClient,
                     packet.CoARequest, packet.DisconnectRequest):
            with self.subTest(code=code):
                self.packet.code = code
                self.assertRaises(ServerPacketError,
                                  self.proxy._HandleProxyPacket, self.packet)

    def testHandleProxyPacketAcceptsAllReplies(self):
        # Access-Challenge (RFC 2865 section 4.4) and the CoA and Disconnect
        # replies (RFC 5176) are forwarded like the other replies
        for code in (packet.AccessAccept, packet.AccessReject,
                     packet.AccountingResponse, packet.AccessChallenge,
                     packet.CoAACK, packet.CoANAK,
                     packet.DisconnectACK, packet.DisconnectNAK):
            with self.subTest(code=code):
                self.packet.code = code
                self.proxy._HandleProxyPacket(self.packet)


class OtherTests(unittest.TestCase):
    def setUp(self):
        self.proxy = Proxy()
        self.proxy._proxyfd = MockFd()

    def tearDown(self):
        UnmockClassMethods(Proxy)
        UnmockClassMethods(Server)

    def testProcessInputNonProxyPort(self):
        fd = MockFd(fd=111)
        MockClassMethod(Server, '_ProcessInput')
        self.proxy._ProcessInput(fd)
        self.assertEqual(self.proxy.called,
                         [('_ProcessInput', (fd,), {})])

    def testProcessInput(self):
        MockClassMethod(Proxy, '_GrabPacket')
        MockClassMethod(Proxy, '_HandleProxyPacket')
        self.proxy._ProcessInput(self.proxy._proxyfd)
        self.assertEqual([x[0] for x in self.proxy.called],
                         ['_GrabPacket', '_HandleProxyPacket'])




class ClientSocket:
    """Minimal client-side socket for proxy replies."""

    def __init__(self):
        self.output = []

    def sendto(self, data, target):
        self.output.append((data, target))


class ProxySessionTests(unittest.TestCase):
    def setUp(self):
        self.dict = Dictionary(StringIO(PROXY_DICTIONARY))
        self.proxy = Proxy(dict=self.dict, hosts={
            "127.0.0.1": RemoteHost("127.0.0.1", HOME_A_SECRET, "home-a",
                                    authport=1812),
            "127.0.0.2": RemoteHost("127.0.0.2", HOME_B_SECRET, "home-b",
                                    authport=1812),
        })
        self.proxy.proxy_timeout = 30
        self.client_fd = ClientSocket()

    def request(self, identifier=42, source=("192.0.2.10", 40000),
                proxy_state=None, message_authenticator=True):
        attributes = {"User_Name": "alice",
                      "message_authenticator": message_authenticator}
        if proxy_state is not None:
            attributes["Proxy_State"] = proxy_state
        req = packet.AuthPacket(code=AccessRequest, id=identifier,
                                secret=CLIENT_SECRET, dict=self.dict,
                                **attributes)
        raw = req.RequestPacket()
        decoded = self.proxy.CreateAuthPacket(packet=raw)
        decoded.secret = CLIENT_SECRET
        decoded.source = source
        decoded.fd = self.client_fd
        return req, decoded

    def reply(self, session, source=("127.0.0.1", 1812), **attributes):
        home_request = packet.AuthPacket(packet=session.raw_request,
                                         secret=HOME_A_SECRET,
                                         dict=self.dict)
        self.assertTrue(home_request.verify_message_authenticator())
        home_reply = home_request.CreateReply(
            Reply_Message="accepted", **attributes)
        raw = home_reply.ReplyPacket()
        decoded = self.proxy.CreatePacket(packet=raw)
        decoded.source = source
        return raw, decoded

    def testForwardedRequestHasHomeSignatureAndOpaqueState(self):
        request, decoded = self.request(proxy_state=[b"\x00first", b"last\xff"])
        session = self.proxy.AddProxySession(decoded, "127.0.0.1")

        home_request = packet.AuthPacket(packet=session.raw_request,
                                         secret=HOME_A_SECRET,
                                         dict=self.dict)
        self.assertTrue(home_request.verify_message_authenticator())
        self.assertEqual(home_request["Proxy-State"],
                         [b"\x00first", b"last\xff", session.proxy_state])
        self.assertEqual(request.id, home_request.id)
        self.assertEqual(request.authenticator, home_request.authenticator)

    def testReplyIsReboundToClientSession(self):
        request, decoded = self.request(proxy_state=[b"first", b"second"])
        session = self.proxy.AddProxySession(decoded, "127.0.0.1")
        raw, reply = self.reply(session)

        self.proxy._HandleProxyPacket(reply)

        self.assertEqual(len(self.client_fd.output), 1)
        (client_raw, target) = self.client_fd.output[0]
        self.assertEqual(target, ("192.0.2.10", 40000))
        client_reply = request.CreateReply(packet=client_raw)
        self.assertTrue(request.VerifyReply(client_reply, client_raw,
                                            enforce_ma=True))
        self.assertEqual(client_reply["Proxy-State"], [b"first", b"second"])

    def testReplyFromAnotherHomeServerIsDropped(self):
        _, decoded = self.request()
        session = self.proxy.AddProxySession(decoded, "127.0.0.1")
        _, reply = self.reply(session, source=("127.0.0.2", 1812))

        self.assertRaises(ServerPacketError, self.proxy._HandleProxyPacket,
                          reply)
        self.assertEqual(self.client_fd.output, [])

    def testDuplicateProxyStateIsDroppedBeforeForwarding(self):
        _, decoded = self.request(
            proxy_state=[b"duplicate", b"duplicate"])
        self.assertRaises(ServerPacketError, self.proxy.AddProxySession,
                          decoded, "127.0.0.1")

    def testProxyLoopIsDroppedBeforeForwarding(self):
        loop_state = (b"pyrad-proxy-v1:" + self.proxy._proxy_instance +
                      b"x" * 16)
        _, decoded = self.request(proxy_state=[loop_state])
        self.assertRaises(ServerPacketError, self.proxy.AddProxySession,
                          decoded, "127.0.0.1")

    def testWrongSecretReplyIsDropped(self):
        _, decoded = self.request()
        session = self.proxy.AddProxySession(decoded, "127.0.0.1")
        raw, _ = self.reply(session)
        tampered = forge_reply(raw, session.forwarded_authenticator,
                               b"wrong-secret", session.forwarded_code)
        reply = self.proxy.CreatePacket(packet=tampered)
        reply.source = ("127.0.0.1", 1812)

        self.assertRaises(ServerPacketError, self.proxy._HandleProxyPacket,
                          reply)
        self.assertEqual(self.client_fd.output, [])

    def testMissingMessageAuthenticatorIsDropped(self):
        _, decoded = self.request()
        session = self.proxy.AddProxySession(decoded, "127.0.0.1")
        _, reply = self.reply(session, message_authenticator=False)

        self.assertRaises(ServerPacketError, self.proxy._HandleProxyPacket,
                          reply)
        self.assertEqual(self.client_fd.output, [])

    def testTimedOutSessionIsDropped(self):
        _, decoded = self.request()
        session = self.proxy.AddProxySession(decoded, "127.0.0.1",
                                             sent_at=0)
        raw, _ = self.reply(session)
        reply = self.proxy.CreatePacket(packet=raw)
        reply.source = ("127.0.0.1", 1812)

        self.assertRaises(ServerPacketError, self.proxy._HandleProxyPacket,
                          reply)
        self.assertNotIn(session.proxy_state, self.proxy._proxy_sessions)
        self.assertEqual(self.client_fd.output, [])

    def testRetransmissionReusesSession(self):
        _, decoded = self.request()
        first = self.proxy.AddProxySession(decoded, "127.0.0.1")
        second = self.proxy.AddProxySession(decoded, "127.0.0.1")
        self.assertIs(first, second)
        self.assertEqual(first.attempts, 2)



    def testReplyWithReorderedProxyStateIsRestored(self):
        request, decoded = self.request(proxy_state=[b"first", b"second"])
        session = self.proxy.AddProxySession(decoded, "127.0.0.1")
        raw, _ = self.reply(session)

        states = []
        others = []
        offset = 20
        while offset < len(raw):
            length = raw[offset + 1]
            attribute = raw[offset:offset + length]
            if attribute[0] == 33:
                states.append(attribute)
            else:
                others.append(attribute)
            offset += length
        attributes = b"".join(others + [states[1], states[0], states[2]])
        reordered = struct.pack("!BBH", raw[0], raw[1], 20 + len(attributes))
        reordered += raw[4:20] + attributes
        reordered = forge_reply(reordered,
                                session.forwarded_authenticator,
                                HOME_A_SECRET, session.forwarded_code)
        reply = self.proxy.CreatePacket(packet=reordered)
        reply.source = ("127.0.0.1", 1812)

        self.proxy._HandleProxyPacket(reply)

        self.assertEqual(len(self.client_fd.output), 1)
        (client_raw, _) = self.client_fd.output[0]
        client_reply = request.CreateReply(packet=client_raw)
        self.assertTrue(request.VerifyReply(client_reply, client_raw,
                                            enforce_ma=True))
        self.assertEqual(client_reply["Proxy-State"],
                         [b"first", b"second"])

    def testDuplicateProxyStateInReplyIsDropped(self):
        _, decoded = self.request(proxy_state=[b"first"])
        session = self.proxy.AddProxySession(decoded, "127.0.0.1")
        raw, _ = self.reply(session)

        attributes = raw[20:] + b"\x21\x12" + session.proxy_state
        duplicated = struct.pack("!BBH", raw[0], raw[1], 20 + len(attributes))
        duplicated += raw[4:20] + attributes
        duplicated = forge_reply(duplicated,
                                 session.forwarded_authenticator,
                                 HOME_A_SECRET, session.forwarded_code)
        reply = self.proxy.CreatePacket(packet=duplicated)
        reply.source = ("127.0.0.1", 1812)

        self.assertRaises(ServerPacketError, self.proxy._HandleProxyPacket,
                          reply)
        self.assertEqual(self.client_fd.output, [])

    def testReplyWithAnotherSessionsStateIsDropped(self):
        _, first = self.request(source=("192.0.2.10", 40000))
        _, second = self.request(source=("192.0.2.11", 40001))
        first_session = self.proxy.AddProxySession(first, "127.0.0.1")
        second_session = self.proxy.AddProxySession(second, "127.0.0.1")
        raw, _ = self.reply(second_session)

        forged = raw.replace(second_session.proxy_state,
                             first_session.proxy_state)
        forged = forge_reply(forged, second_session.forwarded_authenticator,
                             HOME_A_SECRET, second_session.forwarded_code)
        reply = self.proxy.CreatePacket(packet=forged)
        reply.source = ("127.0.0.1", 1812)

        self.assertRaises(ServerPacketError, self.proxy._HandleProxyPacket,
                          reply)
        self.assertEqual(self.client_fd.output, [])

    def testStaleMessageAuthenticatorIsDropped(self):
        _, decoded = self.request()
        session = self.proxy.AddProxySession(decoded, "127.0.0.1")
        raw, _ = self.reply(session)
        tampered = bytearray(raw)
        tampered[22] ^= 0xff
        tampered = forge_reply(bytes(tampered),
                               session.forwarded_authenticator,
                               HOME_A_SECRET, session.forwarded_code,
                               fix_ma=False)
        reply = self.proxy.CreatePacket(packet=tampered)
        reply.source = ("127.0.0.1", 1812)

        self.assertRaises(ServerPacketError, self.proxy._HandleProxyPacket,
                          reply)
        self.assertEqual(self.client_fd.output, [])

    def testMultipleHomesCanReuseAnId(self):
        _, decoded_a = self.request(source=("192.0.2.10", 40000))
        _, decoded_b = self.request(source=("192.0.2.11", 40000))
        session_a = self.proxy.AddProxySession(decoded_a, "127.0.0.1")
        session_b = self.proxy.AddProxySession(decoded_b, "127.0.0.2")
        self.assertNotEqual(session_a.proxy_state, session_b.proxy_state)

        home_b_request = packet.AuthPacket(packet=session_b.raw_request,
                                           secret=HOME_B_SECRET,
                                           dict=self.dict)
        raw_b = home_b_request.CreateReply().ReplyPacket()
        reply_b = self.proxy.CreatePacket(packet=raw_b)
        reply_b.source = ("127.0.0.2", 1812)
        self.proxy._HandleProxyPacket(reply_b)

        raw_a, reply_a = self.reply(session_a)
        self.proxy._HandleProxyPacket(reply_a)

        self.assertEqual(len(self.client_fd.output), 2)
        self.assertEqual([target for (_, target) in self.client_fd.output],
                         [("192.0.2.11", 40000),
                          ("192.0.2.10", 40000)])

    def testIdWrapUsesStateAndAuthenticator(self):
        _, first = self.request(source=("192.0.2.10", 40000))
        _, second = self.request(source=("192.0.2.11", 40000))
        session_a = self.proxy.AddProxySession(first, "127.0.0.1")
        session_b = self.proxy.AddProxySession(second, "127.0.0.1")
        self.assertEqual(session_a.client_id, session_b.client_id)
        self.assertNotEqual(session_a.request_authenticator,
                            session_b.request_authenticator)
        self.assertNotEqual(session_a.proxy_state, session_b.proxy_state)

    def testGrabPacketAttachesSession(self):
        _, decoded = self.request()
        session = self.proxy.AddProxySession(decoded, "127.0.0.1")
        raw, _ = self.reply(session)
        self.proxy._proxyfd = MockFd(fd=99)
        fd = MockFd(fd=99)
        fd.data = raw
        fd.source = ("127.0.0.1", 1812)

        pkt = self.proxy._GrabPacket(
            lambda data, s=self.proxy: s.CreatePacket(packet=data), fd)

        self.assertIs(pkt.proxy_session, session)

    def testAccountingReplyIsResignedForClient(self):
        req = packet.AcctPacket(code=packet.AccountingRequest, id=9,
                                secret=CLIENT_SECRET, dict=self.dict)
        decoded = self.proxy.CreateAcctPacket(packet=req.RequestPacket())
        decoded.secret = CLIENT_SECRET
        decoded.source = ("192.0.2.10", 40000)
        decoded.fd = self.client_fd
        session = self.proxy.AddProxySession(decoded, "127.0.0.1")

        home_request = packet.AcctPacket(packet=session.raw_request,
                                         secret=HOME_A_SECRET,
                                         dict=self.dict)
        self.assertTrue(home_request.VerifyAcctRequest())
        raw = home_request.CreateReply().ReplyPacket()
        reply = self.proxy.CreatePacket(packet=raw)
        reply.source = ("127.0.0.1", 1813)

        self.proxy._HandleProxyPacket(reply)

        (client_raw, _) = self.client_fd.output[0]
        client_reply = req.CreateReply(packet=client_raw)
        self.assertTrue(req.VerifyReply(client_reply, client_raw))

    def testCreateProxyRequestReturnsBytesAndRegistersSession(self):
        _, decoded = self.request()
        encoded = self.proxy.CreateProxyRequest(decoded, "127.0.0.1")

        self.assertIsInstance(encoded, bytes)
        self.assertIs(encoded.session.client_request, decoded)
        self.assertIs(decoded.proxy_session, encoded.session)
        self.assertIn(encoded.session.proxy_state,
                      self.proxy._proxy_sessions)

    def testForwardRequestSendsToHomeServer(self):
        _, decoded = self.request()
        home_fd = ClientSocket()
        self.proxy._proxyfd = home_fd

        session = self.proxy.ForwardRequest(decoded, "127.0.0.1")

        self.assertEqual(home_fd.output,
                         [(session.raw_request, ("127.0.0.1", 1812))])

    def testLocallyBuiltReplyIsVerifiedWithItsSecret(self):
        request, decoded = self.request()
        session = self.proxy.AddProxySession(decoded, "127.0.0.1")
        home_request = packet.AuthPacket(packet=session.raw_request,
                                         secret=HOME_A_SECRET,
                                         dict=self.dict)
        reply = home_request.CreateReply(Reply_Message="local")
        reply.source = ("127.0.0.1", 1812)

        self.proxy._HandleProxyPacket(reply)

        (client_raw, _) = self.client_fd.output[0]
        client_reply = request.CreateReply(packet=client_raw)
        self.assertTrue(request.VerifyReply(client_reply, client_raw,
                                            enforce_ma=True))

    def testLocallyBuiltReplyWithWrongSecretIsDropped(self):
        _, decoded = self.request()
        session = self.proxy.AddProxySession(decoded, "127.0.0.1")
        home_request = packet.AuthPacket(packet=session.raw_request,
                                         secret=HOME_A_SECRET,
                                         dict=self.dict)
        reply = home_request.CreateReply()
        reply.secret = b"wrong-secret"
        reply.source = ("127.0.0.1", 1812)

        self.assertRaises(ServerPacketError, self.proxy._HandleProxyPacket,
                          reply)
        self.assertEqual(self.client_fd.output, [])


if not hasattr(select, "poll"):
    del SocketTests

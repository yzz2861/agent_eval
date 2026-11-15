#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    EDNS(0) server response-path tests.

    Exercises DNSHandler.get_reply with a lightweight fake handler (no
    sockets required) plus optional real loopback socket end-to-end tests
    when the platform permits binding.

    Covers:
      - UDP truncation/TC for 4096 / 512 / MTU-clamped payloads
      - TCP full (untruncated) responses
      - OPT echo semantics (single OPT, negotiated payload, DO, unknown opts)
      - duplicate OPT / bad version / malformed option error results
      - error responses never echo the question section
      - legacy non-EDNS behaviour is unchanged
"""

from __future__ import print_function

import socket
import struct
import unittest

from dnslib.dns import (DNSRecord, EDNS0, EDNSOption, RR, QTYPE, RCODE)
from dnslib.server import DNSHandler, DNSServer


class SilentLogger(object):
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


class FixedResolver(object):
    def __init__(self, answers=3):
        self.answers = answers

    def resolve(self, request, handler):
        reply = request.reply()
        for _ in range(self.answers):
            reply.add_answer(*RR.fromZone("abc.com 60 A 1.2.3.4"))
        return reply


class BigResolver(object):
    def __init__(self, count=40):
        self.count = count

    def resolve(self, request, handler):
        reply = request.reply()
        for _ in range(self.count):
            reply.add_answer(
                *RR.fromZone("abc.com 60 TXT %s" % ("x" * 255)))
        return reply


def make_handler(resolver, protocol="udp", edns_len=0,
                 link_mtu=0, udplen=0):
    handler = DNSHandler.__new__(DNSHandler)
    handler.protocol = protocol
    handler.edns_len = edns_len
    handler.link_mtu = link_mtu
    handler.udplen = udplen

    class FakeServer(object):
        pass

    fake = FakeServer()
    fake.resolver = resolver
    fake.logger = SilentLogger()
    handler.server = fake
    return handler


def edns_query(udp_len=4096, flags="", version=0, ext_rcode=0, opts=None):
    q = DNSRecord.question("abc.com")
    q.add_ar(EDNS0(udp_len=udp_len, flags=flags, version=version,
                   ext_rcode=ext_rcode, opts=opts))
    return q


class TestServerUDPLengths(unittest.TestCase):

    def test_udp_4096_truncated_with_tc(self):
        q = edns_query(4096, "do")
        out = make_handler(BigResolver()).get_reply(q.pack())
        self.assertLessEqual(len(out), 4096)
        reply = DNSRecord.parse(out)
        self.assertEqual(reply.header.tc, 1)

    def test_udp_512_truncated_with_tc(self):
        q = edns_query(512)
        out = make_handler(BigResolver()).get_reply(q.pack())
        self.assertLessEqual(len(out), 512)
        self.assertEqual(DNSRecord.parse(out).header.tc, 1)

    def test_udp_mtu_clamp_1200(self):
        q = edns_query(4096)
        out = make_handler(BigResolver(), link_mtu=1200).get_reply(q.pack())
        # 1200 - 28 = 1172 negotiated ceiling
        self.assertLessEqual(len(out), 1172)
        self.assertEqual(DNSRecord.parse(out).header.tc, 1)

    def test_udp_server_cap(self):
        q = edns_query(4096)
        out = make_handler(BigResolver(), edns_len=1000).get_reply(q.pack())
        self.assertLessEqual(len(out), 1000)
        self.assertEqual(DNSRecord.parse(out).header.tc, 1)

    def test_tcp_allows_full_response(self):
        q = edns_query(512)
        out = make_handler(BigResolver(), protocol="tcp").get_reply(q.pack())
        reply = DNSRecord.parse(out)
        self.assertEqual(reply.header.tc, 0)
        self.assertGreater(len(out), 512)

    def test_small_udp_response_not_truncated(self):
        q = edns_query(4096, "do")
        out = make_handler(FixedResolver()).get_reply(q.pack())
        reply = DNSRecord.parse(out)
        self.assertEqual(reply.header.tc, 0)
        self.assertLessEqual(len(out), 4096)


class TestServerOPTAssociation(unittest.TestCase):

    def test_reply_has_single_opt_with_negotiated_payload(self):
        q = edns_query(4096, "do")
        out = make_handler(FixedResolver()).get_reply(q.pack())
        opts = [r for r in DNSRecord.parse(out).ar if r.rtype == QTYPE.OPT]
        self.assertEqual(len(opts), 1)
        self.assertEqual(opts[0].edns_len, 4096)
        self.assertEqual(opts[0].edns_do, 1)

    def test_reply_opt_uses_server_capped_payload(self):
        q = edns_query(4096)
        out = make_handler(FixedResolver(), edns_len=1000).get_reply(q.pack())
        self.assertEqual(DNSRecord.parse(out).get_opt().edns_len, 1000)

    def test_unknown_option_retained_in_reply(self):
        q = edns_query(4096, opts=[EDNSOption(65001, b"abc")])
        out = make_handler(FixedResolver()).get_reply(q.pack())
        self.assertEqual(
            DNSRecord.parse(out).get_opt().rdata,
            [EDNSOption(65001, b"abc")])

    def test_plain_query_has_no_opt(self):
        q = DNSRecord.question("abc.com")
        out = make_handler(FixedResolver()).get_reply(q.pack())
        reply = DNSRecord.parse(out)
        self.assertIsNone(reply.get_opt())
        self.assertEqual(reply.header.rcode, RCODE.NOERROR)
        self.assertEqual(reply.header.a, 3)


class TestServerEDNSErrors(unittest.TestCase):

    def test_duplicate_opt_formerr_no_echo(self):
        q = DNSRecord.question("abc.com")
        q.add_ar(EDNS0(udp_len=4096, flags="do"))
        q.add_ar(EDNS0(udp_len=512))
        out = make_handler(FixedResolver()).get_reply(q.pack())
        reply = DNSRecord.parse(out)
        self.assertEqual(reply.header.rcode, RCODE.FORMERR)
        self.assertEqual(reply.header.q, 0)
        self.assertEqual(reply.header.ar, 0)

    def test_bad_version_badvers(self):
        q = edns_query(4096, version=1)
        out = make_handler(FixedResolver()).get_reply(q.pack())
        reply = DNSRecord.parse(out)
        self.assertEqual(reply.header.rcode, 1)
        self.assertEqual(reply.get_opt().edns_rcode, 16)
        self.assertEqual(reply.get_opt().edns_ver, 0)

    def test_reserved_flag_formerr(self):
        q = edns_query(4096)
        q.get_opt().ttl |= 0x0001
        out = make_handler(FixedResolver()).get_reply(q.pack())
        self.assertEqual(DNSRecord.parse(out).header.rcode, RCODE.FORMERR)

    def test_extended_rcode_formerr(self):
        q = edns_query(4096, ext_rcode=3)
        out = make_handler(FixedResolver()).get_reply(q.pack())
        self.assertEqual(DNSRecord.parse(out).header.rcode, RCODE.FORMERR)

    def test_malformed_wire_option_formerr(self):
        header = struct.pack("!HHHHHH", 9, 0x0100, 1, 0, 0, 1)
        question = bytes([1]) + b"a" + bytes([0,1,0,1])
        opt = (bytes([0]) + struct.pack("!HHIH", QTYPE.OPT, 4096, 0, 6)
               + struct.pack("!HH", 3, 6) + b"ab")
        out = make_handler(FixedResolver()).get_reply(header + question + opt)
        reply = DNSRecord.parse(out)
        self.assertEqual(reply.header.rcode, RCODE.FORMERR)
        self.assertEqual(reply.header.id, 9)
        self.assertEqual(reply.header.q, 0)

    def test_garbage_packet_does_not_crash(self):
        out = make_handler(FixedResolver()).get_reply(bytes([0x12, 0x34, 0x00]))
        reply = DNSRecord.parse(out)
        self.assertEqual(reply.header.rcode, RCODE.FORMERR)
        self.assertEqual(len(out), 12)


class TestLegacyBehaviour(unittest.TestCase):

    def test_legacy_udplen_header_only_truncate(self):
        q = DNSRecord.question("abc.com")
        out = make_handler(BigResolver(), udplen=100).get_reply(q.pack())
        reply = DNSRecord.parse(out)
        self.assertEqual(reply.header.tc, 1)
        self.assertEqual(reply.header.q, 0)
        self.assertEqual(len(out), 12)

    def test_legacy_no_udplen_no_truncation(self):
        q = DNSRecord.question("abc.com")
        out = make_handler(BigResolver()).get_reply(q.pack())
        self.assertEqual(DNSRecord.parse(out).header.tc, 0)


class TestLoopbackEndToEnd(unittest.TestCase):
    """Real socket exchange; skipped when loopback binding is forbidden."""

    def setUp(self):
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.bind(("127.0.0.1", 0))
                self.port = probe.getsockname()[1]
            finally:
                probe.close()
        except OSError:
            self.skipTest("loopback socket binding not permitted")

    def test_udp_and_tcp_exchange(self):
        resolver = BigResolver()
        udp_server = DNSServer(resolver, address="127.0.0.1",
                               port=self.port, tcp=False,
                               logger=SilentLogger())
        udp_server.start_thread()
        try:
            q = edns_query(4096)
            udp_reply = DNSRecord.parse(q.send("127.0.0.1", self.port))
            self.assertEqual(udp_reply.header.tc, 1)

            tcp_server = DNSServer(resolver, address="127.0.0.1",
                                   port=self.port + 1, tcp=True,
                                   logger=SilentLogger())
            tcp_server.start_thread()
            tcp_reply = DNSRecord.parse(
                q.send("127.0.0.1", self.port + 1, tcp=True))
            self.assertEqual(tcp_reply.header.tc, 0)
            tcp_server.stop()
        finally:
            udp_server.stop()


if __name__ == "__main__":
    unittest.main()

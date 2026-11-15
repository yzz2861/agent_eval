#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    EDNS(0) negotiation / OPT parsing tests (packet level).

    Covers DNSRecord.parse and the DNSRecord EDNS negotiation helpers:
      - single / duplicate OPT records
      - payload negotiation (4096 / 512 / sub-512 / server cap / MTU)
      - DO bit, reserved flags, EDNS version and extended RCODE
      - malformed OPT option lengths and unknown option preservation
      - size-aware truncation (TC)
"""

from __future__ import print_function

import struct
import unittest

from dnslib.dns import (DNSRecord, EDNS0, EDNSOption, EDNSDecodeError,
                        DNSError, RCODE, QTYPE, RR)


def opt_rr(udp_len=4096, ttl=0, rdata=b""):
    """Build a raw OPT RR (root owner name) with explicit wire fields."""
    return (b"\x00" +
            struct.pack("!HHIH", QTYPE.OPT, udp_len, ttl, len(rdata)) +
            rdata)


def query_with_ar(ar_rdata, msg_id=1):
    """Build a raw query (one A question) carrying the given AR bytes."""
    header = struct.pack("!HHHHHH", msg_id, 0x0100, 1, 0, 0, 1)
    question = b"\x01a\x00\x00\x01\x00\x01"
    return header + question + ar_rdata


class TestOPTParse(unittest.TestCase):

    def test_single_opt_roundtrip(self):
        q = DNSRecord.question("a.com")
        q.add_ar(EDNS0(udp_len=4096, flags="do"))
        parsed = DNSRecord.parse(q.pack())
        opt = parsed.get_opt()
        self.assertIsNotNone(opt)
        self.assertEqual(opt.edns_len, 4096)
        self.assertEqual(opt.edns_do, 1)
        self.assertEqual(opt.edns_ver, 0)

    def test_unknown_option_preserved(self):
        q = DNSRecord.question("a.com")
        q.add_ar(EDNS0(udp_len=4096,
                       opts=[EDNSOption(65001, b"\x01\x02\x03"),
                             EDNSOption(8, b"")]))
        parsed = DNSRecord.parse(q.pack())
        codes = [o.code for o in parsed.get_opt().rdata]
        self.assertEqual(codes, [65001, 8])
        self.assertEqual(parsed.get_opt().rdata[0].data, b"\x01\x02\x03")

    def test_bad_option_length_raises(self):
        # rdlen=6 but the single option declares length 6 with only 2 bytes
        bad = query_with_ar(opt_rr(
            rdata=struct.pack("!HH", 3, 6) + b"ab"))
        with self.assertRaises(DNSError):
            DNSRecord.parse(bad)

    def test_truncated_option_header_raises(self):
        # rdlen=3 but an option header needs 4 bytes
        bad = query_with_ar(opt_rr(rdata=b"\x00\x03\x00"))
        with self.assertRaises(DNSError):
            DNSRecord.parse(bad)

    def test_trailing_junk_raises(self):
        # One complete (empty) option plus one stray trailing byte
        good_opt = struct.pack("!HH", 3, 0)
        bad = query_with_ar(opt_rr(rdata=good_opt + b"\xff"))
        with self.assertRaises(DNSError):
            DNSRecord.parse(bad)


class TestEDNSNegotiation(unittest.TestCase):

    def _query(self, **kwargs):
        q = DNSRecord.question("a.com")
        q.add_ar(EDNS0(**kwargs))
        return q

    def test_no_opt_returns_none(self):
        self.assertIsNone(DNSRecord.question("a.com").negotiate_edns())

    def test_payload_4096(self):
        self.assertEqual(self._query(udp_len=4096).negotiate_edns(), 4096)

    def test_payload_512(self):
        self.assertEqual(self._query(udp_len=512).negotiate_edns(), 512)

    def test_payload_below_512_floored(self):
        self.assertEqual(self._query(udp_len=100).negotiate_edns(), 512)

    def test_payload_zero_floored(self):
        self.assertEqual(self._query(udp_len=0).negotiate_edns(), 512)

    def test_server_payload_cap(self):
        q = self._query(udp_len=4096)
        self.assertEqual(q.negotiate_edns(server_payload=1400), 1400)

    def test_link_mtu_cap(self):
        q = self._query(udp_len=4096)
        # 1200 - 28 (IPv4 UDP/IP overhead) = 1172
        self.assertEqual(q.negotiate_edns(link_mtu=1200), 1172)

    def test_min_of_requester_server_mtu(self):
        q = self._query(udp_len=4096)
        self.assertEqual(
            q.negotiate_edns(server_payload=1400, link_mtu=1200), 1172)
        self.assertEqual(
            q.negotiate_edns(server_payload=1000, link_mtu=1500), 1000)

    def test_mtu_cap_never_below_floor(self):
        q = self._query(udp_len=4096)
        self.assertEqual(q.negotiate_edns(link_mtu=540), 512)

    def test_do_bit_accepted(self):
        q = self._query(udp_len=4096, flags="do")
        self.assertEqual(q.negotiate_edns(), 4096)
        self.assertEqual(q.get_opt().edns_do, 1)

    def test_reserved_flag_bit_rejected(self):
        q = self._query(udp_len=4096)
        q.get_opt().ttl |= 0x0001
        with self.assertRaises(EDNSDecodeError) as ctx:
            q.negotiate_edns()
        self.assertEqual(ctx.exception.rcode, RCODE.FORMERR)

    def test_other_reserved_bits_rejected(self):
        for bit in (1, 2, 8, 14):
            q = self._query(udp_len=4096)
            q.get_opt().ttl |= (1 << bit)
            with self.assertRaises(EDNSDecodeError):
                q.negotiate_edns()

    def test_unsupported_version_badvers(self):
        q = self._query(udp_len=4096, version=1)
        with self.assertRaises(EDNSDecodeError) as ctx:
            q.negotiate_edns()
        self.assertEqual(ctx.exception.rcode, 1)
        self.assertEqual(ctx.exception.ext_rcode, 16)

    def test_non_zero_extended_rcode_rejected(self):
        q = self._query(udp_len=4096, ext_rcode=5)
        with self.assertRaises(EDNSDecodeError) as ctx:
            q.negotiate_edns()
        self.assertEqual(ctx.exception.rcode, RCODE.FORMERR)

    def test_duplicate_opt_rejected(self):
        q = DNSRecord.question("a.com")
        q.add_ar(EDNS0(udp_len=4096, flags="do"))
        q.add_ar(EDNS0(udp_len=512))
        with self.assertRaises(EDNSDecodeError) as ctx:
            q.negotiate_edns()
        self.assertEqual(ctx.exception.rcode, RCODE.FORMERR)

    def test_duplicate_opt_does_not_last_win_do(self):
        # A second OPT must not silently overwrite the first OPT DO bit.
        q = DNSRecord.question("a.com")
        q.add_ar(EDNS0(udp_len=4096, flags="do"))
        q.add_ar(EDNS0(udp_len=512))
        with self.assertRaises(EDNSDecodeError):
            q.negotiate_edns()

    def test_unknown_options_negotiate_fine(self):
        q = DNSRecord.question("a.com")
        q.add_ar(EDNS0(udp_len=2048,
                       opts=[EDNSOption(65001, b"abcd")]))
        self.assertEqual(q.negotiate_edns(), 2048)


class TestTruncate(unittest.TestCase):

    def _big_reply(self, count=40):
        q = DNSRecord.question("abc.com")
        reply = q.reply()
        for _ in range(count):
            reply.add_answer(
                *RR.fromZone("abc.com 60 TXT %s" % ("x" * 255)))
        return reply

    def test_legacy_truncate_header_only(self):
        truncated = self._big_reply().truncate()
        self.assertEqual(truncated.header.tc, 1)
        self.assertEqual(truncated.questions, [])
        self.assertEqual(truncated.rr, [])
        self.assertEqual(len(truncated.pack()), 12)

    def test_size_truncate_keeps_question_and_tc(self):
        truncated = self._big_reply().truncate(512)
        self.assertEqual(truncated.header.tc, 1)
        self.assertEqual(len(truncated.questions), 1)
        self.assertLessEqual(len(truncated.pack()), 512)

    def test_size_truncate_respects_mtu_limit(self):
        truncated = self._big_reply().truncate(1172)
        self.assertEqual(truncated.header.tc, 1)
        self.assertLessEqual(len(truncated.pack()), 1172)

    def test_size_truncate_keeps_opt_when_fitting(self):
        q = DNSRecord.question("abc.com")
        q.add_ar(EDNS0(udp_len=4096))
        reply = q.reply()
        reply.add_answer(*RR.fromZone("abc.com 60 A 1.2.3.4"))
        forced = reply.truncate(512)
        self.assertLessEqual(len(forced.pack()), 512)
        self.assertEqual(forced.header.tc, 1)
        if forced.get_opt() is not None:
            self.assertEqual(forced.get_opt().rtype, QTYPE.OPT)


if __name__ == "__main__":
    unittest.main()

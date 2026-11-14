#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Boundary tests for DNS name decompression (DNSBuffer.decode_name).

    Covers compression pointer loops, forward/out-of-bounds pointers,
    label/name length limits, the maximum pointer hop budget, buffer
    position restoration and DNSRecord.parse level behaviour.
"""

import unittest
import struct

from dnslib.buffer import BufferError
from dnslib.label import (DNSBuffer, DNSLabel,
                           DNSCompressionLoopError,
                           DNSDecodeError,
                           DNSInvalidLabelError,
                           DNSNameTooLongError,
                           DNSPointerOutOfBoundsError,
                           MAX_POINTER_HOPS)
from dnslib.dns import A, DNSError, DNSRecord, QTYPE, RR


def header(qd=1, an=0):
    """Minimal DNS header: id=0, flags=0 with the given section counts."""
    return b'\x00\x00\x00\x00' + \
           bytes([0, qd, 0, an, 0, 0, 0, 0])


def pointer(offset):
    return struct.pack("!H", 0xc000 | (offset & 0x3fff))


def decode(data, start=12):
    buf = DNSBuffer(data)
    buf.offset = start
    return buf.decode_name()


def build_pointer_chain(hops):
    """
    Build a strictly-backward compression chain of `hops` pointers.

    Layout (lowest address first): label root, then pointers p1..pN where
    p1 points at the root and each pN points at p(N-1).
    """
    data = bytearray(b'\x00')
    for n in range(1, hops + 1):
        target = 2 * n - 3
        if target < 0:
            target = 0
        data += pointer(target)
    return bytes(data)


class TestDecodeName(unittest.TestCase):

    def test_valid_compression(self):
        # Standard query: question name at offset 12, RR name pointer at 12
        packet = DNSRecord.question("www.example.com").pack()
        record = DNSRecord.parse(packet)
        self.assertEqual(str(record.q.qname), "www.example.com.")
        self.assertEqual(record.pack(), packet)

        # Multi-RR packet exercises a strictly-backward pointer: the answer
        # RR name points back to the question name encoded earlier
        record = DNSRecord.question("www.example.com")
        record.add_answer(RR("www.example.com", QTYPE.A, rdata=A("1.2.3.4"),
                            ttl=60))
        data = record.pack()
        self.assertIn(pointer(12), data)
        parsed = DNSRecord.parse(data)
        self.assertEqual(str(parsed.q.qname), "www.example.com.")
        self.assertEqual(str(parsed.rr[0].rname), "www.example.com.")

    def test_self_loop_pointer(self):
        # Name at offset 12 is a pointer back to offset 12
        data = header() + pointer(12) + b'\x00\x01\x00\x01'
        with self.assertRaises(DNSCompressionLoopError):
            decode(data)
        with self.assertRaises(DNSError):
            DNSRecord.parse(data)

    def test_two_node_pointer_cycle(self):
        # Offset 12 -> offset 14, offset 14 -> offset 12
        data = header() + pointer(14) + pointer(12) + b'\x00\x01\x00\x01'
        with self.assertRaises(DNSCompressionLoopError):
            decode(data)

    def test_forward_pointer(self):
        # Pointer at offset 12 jumps ahead to offset 20
        data = header() + pointer(20) + b'\x00' * 4 + b'\x03abc\x00' + \
               b'\x00\x01\x00\x01'
        with self.assertRaises(DNSCompressionLoopError):
            decode(data)

    def test_pointer_outside_message(self):
        data = header() + pointer(60) + b'\x00\x01\x00\x01'
        with self.assertRaises(DNSPointerOutOfBoundsError):
            decode(data)

    def test_truncated_pointer(self):
        # Second pointer octet missing -> cannot cross message boundary
        data = header() + b'\xc0'
        with self.assertRaises(DNSPointerOutOfBoundsError):
            decode(data)

    def test_oversized_label(self):
        # Length octet 64 exceeds the 63 octet uncompressed label limit
        data = bytearray(header())
        data.append(64)
        data += b'a' * 64
        with self.assertRaises(DNSInvalidLabelError):
            decode(bytes(data))

    def test_reserved_label_type(self):
        # Leading bits 01 and 10 are reserved label types
        for octet in (0x40, 0x80):
            data = header() + bytes([octet])
            with self.assertRaises(DNSInvalidLabelError):
                decode(data)

    def test_max_pointer_hops(self):
        # Exactly the budget of pointers is accepted (terminates at root)
        ok = build_pointer_chain(MAX_POINTER_HOPS)
        label = decode(ok, start=len(ok) - 2)
        self.assertEqual(str(label), ".")

        # One pointer too many is rejected as a loop/budget error, never
        # as a RecursionError
        bad = build_pointer_chain(MAX_POINTER_HOPS + 1)
        try:
            decode(bad, start=len(bad) - 2)
            self.fail("Expected DNSCompressionLoopError on long chain")
        except DNSCompressionLoopError:
            pass
        except RecursionError:
            self.fail("decode_name raised RecursionError on long chain")

    def test_expanded_name_too_long(self):
        # Four 63-octet labels force the expanded name past 255 wire octets
        data = bytearray(header())
        for _ in range(4):
            data.append(63)
            data += b'a' * 63
        data.append(0)
        with self.assertRaises(DNSNameTooLongError):
            decode(bytes(data))

    def test_failed_decode_restores_offset(self):
        data = header() + pointer(12) + b'\x00\x01\x00\x01'
        buf = DNSBuffer(data)
        buf.offset = 12
        self.assertEqual(buf.offset, 12)
        with self.assertRaises(BufferError):
            buf.decode_name()
        # Position restored to the start of the failed name
        self.assertEqual(buf.offset, 12)

    def test_failed_name_does_not_pollute_later_rr(self):
        # A self-looping question name aborts the whole parse cleanly rather
        # than leaving the buffer in an inconsistent state
        data = header() + pointer(12) + b'\x00\x01\x00\x01'
        with self.assertRaises(DNSError) as ctx:
            DNSRecord.parse(data)
        # The underlying failure is a compression loop error wrapped in DNSError
        self.assertIn("pointer", str(ctx.exception).lower())

    def test_looping_rr_aborts_record_parse(self):
        # A valid question followed by an RR whose owner name is a self-loop.
        # The parse must fail as a whole rather than return a partial record.
        question = b'\x03abc\x00\x00\x01\x00\x01'
        rr_loop = pointer(12 + len(question))
        data = header(qd=1, an=1) + question + rr_loop
        with self.assertRaises(DNSError):
            DNSRecord.parse(data)

    def test_valid_full_record_parse_vectors(self):
        # A spread of legal names (root, single label, long name, compressed
        # multi-RR) all parse at DNSRecord level and round-trip byte-for-byte
        root_record = DNSRecord.question(".")
        self.assertEqual(DNSRecord.parse(root_record.pack()).pack(),
                         root_record.pack())

        multi = DNSRecord.question("a.b.c.example")
        multi.add_answer(RR("a.b.c.example", QTYPE.A, rdata=A("10.0.0.1"),
                            ttl=30))
        multi.add_answer(RR("b.c.example", QTYPE.A, rdata=A("10.0.0.2"),
                            ttl=30))
        wire = multi.pack()
        parsed = DNSRecord.parse(wire)
        self.assertEqual(parsed.pack(), wire)
        self.assertEqual([str(r.rname) for r in parsed.rr],
                         ["a.b.c.example.", "b.c.example."])

    def test_long_valid_domain_roundtrip(self):
        # Long but legal domain (253 text octets) parses and repacks
        components = [b'a' * 49 for _ in range(5)]
        name = DNSLabel(components)
        record = DNSRecord.question(name)
        packet = record.pack()
        parsed = DNSRecord.parse(packet)
        self.assertEqual(parsed.q.qname, name)
        self.assertEqual(parsed.pack(), packet)

    def test_dnslabel_equality_and_serialisation_unchanged(self):
        a = DNSLabel("AAA.BBB.CCC.")
        b = DNSLabel([b"aaa", b"bbb", b"ccc"])
        self.assertEqual(a, b)
        self.assertEqual(a, "aaa.bbb.ccc")
        self.assertEqual(hash(a), hash(b))
        buf = DNSBuffer()
        buf.encode_name(a)
        buf.offset = 0
        self.assertEqual(buf.decode_name(), a)

    def test_all_decode_errors_are_buffer_errors(self):
        for exc in (DNSCompressionLoopError, DNSNameTooLongError,
                    DNSInvalidLabelError, DNSPointerOutOfBoundsError):
            self.assertTrue(issubclass(exc, DNSDecodeError))
            self.assertTrue(issubclass(exc, BufferError))


if __name__ == '__main__':
    unittest.main()

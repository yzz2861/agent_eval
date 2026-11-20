# -*- coding: utf-8 -*-
"""Tests for offline ICMP quote correlation."""
from __future__ import absolute_import

import io
import json
import socket
import struct

from . import pcap
from .icmp_quote import (
    QuoteEvidenceTable,
    STATUS_COMPLETE,
    STATUS_CONFLICT,
    STATUS_QUOTE_ONLY,
    verify_icmp_quotes,
)


def _ipv4(payload, proto, ident, src='192.0.2.10', dst='192.0.2.20'):
    total = 20 + len(payload)
    header = struct.pack(
        '>BBHHHBBH4s4s', 0x45, 0, total, ident, 0x4000, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst))
    return header + payload


def _udp(payload, sport=40000, dport=53):
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload


def _ipv4_udp(payload, ident, sport, dport):
    return _ipv4(_udp(payload, sport, dport), 17, ident)


def _ipv6(payload, next_header, flow=0x12345,
          src='2001:db8::1', dst='2001:db8::2'):
    header = struct.pack(
        '>IHBB16s16s', 0x60000000 | flow, len(payload), next_header, 64,
        socket.inet_pton(socket.AF_INET6, src),
        socket.inet_pton(socket.AF_INET6, dst))
    return header + payload


def _hop_by_hop(next_header):
    # PadN option: type 1, length 4, four zero bytes.  Header is 8 bytes.
    return bytes(bytearray([next_header, 0, 1, 4, 0, 0, 0, 0]))


def _icmp4_quote(quoted, quote_len, ident):
    body = struct.pack('>BBH', 3, 3, 0) + b'\x00' * 4 + quoted[:quote_len]
    return _ipv4(body, 1, ident, '203.0.113.1', '203.0.113.2')


def _icmp6_quote(quoted, quote_len, flow=0x54321):
    body = struct.pack('>BBH', 1, 4, 0) + b'\x00' * 4 + quoted[:quote_len]
    return _ipv6(body, 58, flow, '2001:db8:ffff::1', '2001:db8:ffff::2')


def _ethernet(ip, ethertype=0x0800):
    return b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02' + \
        struct.pack('>H', ethertype) + ip


def _in_memory_pcap(frames):
    output = io.BytesIO()
    writer = pcap.Writer(output, linktype=pcap.DLT_EN10MB, snaplen=65535)
    writer.writepkts([(1000.0 + index, frame)
                      for index, frame in enumerate(frames)])
    return output.getvalue()


def _three_case_capture():
    full = _ipv4_udp(b'full-correspondence', 0x1111, 41000, 53)
    only = _ipv4_udp(b'quote-without-original', 0x2222, 41002, 80)
    duplicate = _ipv4_udp(b'duplicate-original', 0x3333, 41004, 443)
    frames = [
        _ethernet(full),
        _ethernet(_icmp4_quote(full, len(full), 0x9001)),
        _ethernet(_icmp4_quote(only, 28, 0x9002)),
        _ethernet(duplicate),
        _ethernet(duplicate),
        _ethernet(_icmp4_quote(duplicate, 28, 0x9003)),
    ]
    return _in_memory_pcap(frames), full, only, duplicate


def test_in_memory_capture_has_three_queryable_outcomes():
    capture, full, only, duplicate = _three_case_capture()
    table = verify_icmp_quotes(capture)

    assert isinstance(table, QuoteEvidenceTable)
    assert len(table) == 3
    assert table.capture_frame_count == 6
    assert len(table.observed_packets) == 6
    assert table.status_counts() == {
        STATUS_COMPLETE: 1,
        STATUS_QUOTE_ONLY: 1,
        STATUS_CONFLICT: 1,
    }

    complete = table.query(status='complete')
    assert len(complete) == 1
    assert complete[0].frame_index == 1
    assert complete[0].quote_len == len(full)
    assert complete[0].quoted_packet_len == len(full)
    assert complete[0].quote_complete
    assert complete[0].candidate_indices == (0,)
    assert complete[0].icmp_offset == 34
    assert complete[0].quote_offset == 42

    quote_only = table.query(status='quote_only')
    assert len(quote_only) == 1
    assert quote_only[0].frame_index == 2
    assert quote_only[0].src == socket.inet_ntoa(only[12:16])
    assert quote_only[0].dst == socket.inet_ntoa(only[16:20])
    assert not quote_only[0].candidates
    assert quote_only[0].quote_len == 28

    conflict = table['conflict']
    assert len(conflict) == 1
    assert conflict[0].frame_index == 5
    assert conflict[0].candidate_indices == (3, 4)
    assert conflict[0].quote_len == 28
    assert all(candidate.packet_index in (3, 4)
               for candidate in conflict[0].candidates)

    # Convenience aliases used by reports should select the same rows.
    assert table.query(status='matched') == complete
    assert table.query(status='only_quote') == quote_only
    assert table.query(status='ambiguous') == conflict

    # The embedded quotes were never indexed as observations or candidates.
    assert 1 not in conflict[0].candidate_indices
    assert 2 not in conflict[0].candidate_indices
    assert 5 not in conflict[0].candidate_indices


def test_ipv6_extension_header_and_quote_truncation():
    udp = _udp(b'extension-header-payload', 42000, 4444)
    original = _ipv6(_hop_by_hop(17) + udp, 0)
    frames = [
        _ethernet(original, 0x86DD),
        _ethernet(_icmp6_quote(original, 48), 0x86DD),
        _ethernet(_icmp6_quote(original, 43), 0x86DD),
    ]
    table = verify_icmp_quotes(_in_memory_pcap(frames))

    assert len(table) == 2
    assert table.status_counts() == {STATUS_COMPLETE: 2}

    header_complete = table[0]
    assert header_complete.family == 'ipv6'
    assert header_complete.quote_len == 48
    assert header_complete.quoted_packet_len == len(original)
    assert header_complete.quote_truncated
    assert header_complete.quote_missing_bytes == len(original) - 48
    assert header_complete.extension_header_types == (0,)
    assert header_complete.extension_headers[0]['name'] == 'Hop-by-Hop Options'
    assert header_complete.proto == 17
    assert header_complete.transport_offset == 48
    assert not header_complete.transport_complete
    assert header_complete.candidate_indices == (0,)

    extension_truncated = table[1]
    assert extension_truncated.quote_len == 43
    assert extension_truncated.extension_header_types == (0,)
    assert extension_truncated.extension_headers_truncated
    assert not extension_truncated.extension_headers[0]['complete']
    assert extension_truncated.candidate_indices == (0,)
    assert table.query(has_extension_headers=True)[0] is header_complete
    assert table.query(min_quote_len=48).rows == [header_complete]


def test_truncated_observation_is_kept_as_partial_candidate():
    quoted = _ipv4_udp(b'truncated-original', 0x4444, 43000, 8080)
    truncated = quoted[:20]
    frames = [
        _ethernet(truncated),
        _ethernet(_icmp4_quote(quoted, 28, 0x9004)),
    ]
    table = verify_icmp_quotes(_in_memory_pcap(frames))

    assert len(table) == 1
    row = table[0]
    assert row.status == STATUS_QUOTE_ONLY
    assert row.quote_len == 28
    assert row.candidate_indices == ()
    assert row.partial_candidate_indices == (0,)
    assert row.partial_candidates[0].matched_bytes == 20
    assert row.capture_truncated
    assert any('truncated before quote end' in note for note in row.notes)


def test_raw_pcap_and_iterable_inputs():
    original = _ipv4_udp(b'raw-link-layer', 0x5151, 44000, 53)
    icmp = _icmp4_quote(original, len(original), 0x9101)

    iterable_table = verify_icmp_quotes(
        [(1000.0, original), (1001.0, icmp)], linktype=pcap.DLT_RAW)
    assert len(iterable_table) == 1
    assert iterable_table[0].status == STATUS_COMPLETE
    assert iterable_table[0].candidate_indices == (0,)
    assert iterable_table[0].quote_len == len(original)

    output = io.BytesIO()
    writer = pcap.Writer(output, linktype=pcap.DLT_RAW, snaplen=65535)
    writer.writepkts([(1000.0, original), (1001.0, icmp)])
    pcap_table = verify_icmp_quotes(output.getvalue())
    assert pcap_table.status_counts() == {STATUS_COMPLETE: 1}
    assert pcap_table[0].quote_len == len(original)


def test_icmp_truncated_before_quote_still_leaves_a_row():
    body = struct.pack('>BBH', 3, 3, 0)
    outer = _ipv4(body, 1, 0x9201, '203.0.113.9', '203.0.113.10')
    table = verify_icmp_quotes(_in_memory_pcap([_ethernet(outer)]))

    assert len(table) == 1
    row = table[0]
    assert row.status == STATUS_QUOTE_ONLY
    assert row.quote_len == 0
    assert row.quote_offset == 42
    assert row.quote_bytes == b''
    assert row.header_truncated
    assert row.parse_error
    assert any('truncated before the quoted datagram' in note
               for note in row.notes)


def test_mutable_ipv4_fields_still_pair_without_hiding_the_mode():
    original = _ipv4_udp(b'mutable-header', 0x6161, 46000, 53)
    quoted = bytearray(original)
    quoted[8] = 63              # TTL changed by a router
    quoted[10:12] = struct.pack('>H', 0x1234)  # checksum changed with it
    icmp = _icmp4_quote(bytes(quoted), len(original), 0x9301)
    table = verify_icmp_quotes(
        _in_memory_pcap([_ethernet(original), _ethernet(icmp)]))

    row = table[0]
    assert row.status == STATUS_COMPLETE
    assert row.candidate_indices == (0,)
    assert row.match_mode == 'normalized'
    assert not row.exact_match
    assert any('masking mutable' in note for note in row.notes)


def test_serializers_do_not_leak_method_objects():
    capture, _, _, _ = _three_case_capture()
    table = verify_icmp_quotes(capture)

    csv_text = table.to_csv()
    assert 'fragment_offset' in csv_text.splitlines()[0]
    assert 'bound method' not in csv_text

    payload = json.loads(table.to_json())
    assert len(payload) == 3
    assert payload[0]['fragment_offset'] == 0
    assert payload[0]['match_mode'] == 'exact'

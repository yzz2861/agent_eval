#!/usr/bin/env python
"""Generate the small, compressed evidence-projection test fixture.

The fixture intentionally contains no payload beyond what is needed to
exercise link/IP header offsets: one VLAN-tagged IHL=5 frame, one
VLAN-tagged IHL=6 frame, one truncated frame, one frame with an unknown
inner encapsulation, and one untagged frame.
"""
from __future__ import print_function

import gzip
import os
import struct


def _checksum(header):
    if len(header) % 2:
        header += b'\x00'
    total = 0
    for offset in range(0, len(header), 2):
        total += struct.unpack_from('>H', header, offset)[0]
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def _ipv4(src, dst, proto, payload, ttl, ident, flags_offset=0x4000, options=b''):
    ihl = 5 + (len(options) // 4)
    total_length = ihl * 4 + len(payload)
    header = struct.pack(
        '>BBHHHBBH4s4s',
        (4 << 4) | ihl,
        0,
        total_length,
        ident,
        flags_offset,
        ttl,
        proto,
        0,
        src,
        dst,
    ) + options
    header = header[:10] + struct.pack('>H', _checksum(header)) + header[12:]
    return header + payload


def _eth(dst, src, ethertype, payload):
    return dst + src + struct.pack('>H', ethertype) + payload


def _vlan(priority, vlan_id, inner_type, payload):
    tci = ((priority & 0x7) << 13) | (vlan_id & 0x0fff)
    return struct.pack('>HH', tci, inner_type) + payload


def _udp(sport, dport, payload=b''):
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload


def _tcp(sport, dport):
    return struct.pack('>HHIIBBHHH', sport, dport, 1, 0, 0x50, 0x10, 1024, 0, 0)


def _pcap_record(seconds, useconds, frame, original_length=None):
    if original_length is None:
        original_length = len(frame)
    return struct.pack('<IIII', seconds, useconds, len(frame), original_length) + frame


def build_fixture():
    dst = b'\x02\x00\x00\x00\x00\x01'
    src_a = b'\x02\x00\x00\x00\x00\x02'
    src_b = b'\x02\x00\x00\x00\x00\x03'

    ip0 = _ipv4(
        b'\x0a\x01\x02\x03', b'\xc0\x00\x02\x09', 17,
        _udp(12345, 53), ttl=64, ident=0x1234,
    )
    frame0 = _eth(dst, src_a, 0x8100, _vlan(5, 100, 0x0800, ip0))

    ip1 = _ipv4(
        b'\xac\x10\x09\x08', b'\xcb\x00\x71\x2a', 6,
        _tcp(443, 51515), ttl=33, ident=0x2345,
        flags_offset=0, options=b'\x01\x01\x01\x00',
    )
    frame1 = _eth(dst, src_b, 0x8100, _vlan(0, 200, 0x0800, ip1))

    ip2 = _ipv4(
        b'\xc6\x33\x64\x07', b'\xc6\x33\x64\x09', 1,
        b'\x08\x00\x00\x00', ttl=17, ident=0x3456,
        flags_offset=0,
    )
    full_frame2 = _eth(dst, src_a, 0x8100, _vlan(3, 300, 0x0800, ip2))
    # Cut the frame in the middle of the IPv4 header: bytes through ip.p
    # survive, while ip.sum/ip.src/ip.dst do not.
    frame2 = full_frame2[:28]

    frame3 = _eth(
        dst, src_b, 0x8100,
        _vlan(1, 400, 0x88b5, b'unknown-encapsulation'),
    )

    ip4 = _ipv4(
        b'\x64\x40\x00\x01', b'\x64\x40\x00\x02', 17,
        _udp(5353, 5353), ttl=1, ident=0x4567,
        flags_offset=0,
    )
    frame4 = _eth(dst, src_a, 0x0800, ip4)

    records = [
        _pcap_record(1700000000, 100000, frame0),
        _pcap_record(1700000001, 200000, frame1),
        _pcap_record(1700000002, 300000, frame2, original_length=len(full_frame2)),
        _pcap_record(1700000003, 400000, frame3),
        _pcap_record(1700000004, 500000, frame4),
    ]

    global_header = struct.pack(
        '<IHHIIII',
        0xa1b2c3d4,
        2,
        4,
        0,
        0,
        65535,
        1,
    )
    return global_header + b''.join(records)


def main():
    target = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'examples', 'data', 'evidence_projection.pcap.gz',
    )
    payload = build_fixture()
    with open(target, 'wb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as compressed:
            compressed.write(payload)
    print(target)


if __name__ == '__main__':
    main()

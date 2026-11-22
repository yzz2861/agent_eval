# -*- coding: utf-8 -*-
"""Offline direction attribution for captured frames.

This module is deliberately an *audit* helper, not a classifier based on
Ethernet addresses.  A MAC address is recorded as link-layer evidence, but it
is never used by itself to decide whether a frame was inbound or outbound.

The authoritative inputs are:

* a trusted mirror-port table (capture point -> mirror port/device, VLAN and
  mirror direction);
* the capture scope (capture points, VLANs, time window and optional
  addresses);
* the pcap/pcapng bytes themselves.

Every result keeps the evidence that led to it: link type, source/destination
MACs, EtherType, the complete outer VLAN tag stack, captured vs. original
length, a SHA-256 of the captured bytes and the parsed protocol stack.  A
frame may have more than one possible direction when the mirror ledger is
ambiguous (for example a bidirectional SPAN port or an untagged frame seen at
a port with several VLAN records).  A frame whose L2 header was truncated is
reported as unverifiable; no direction is invented for it.

Only offline parsing is performed.  This module never opens a network socket
and never sends packets.

Command line usage::

    python -m dpkt.direction audit \\
        --mirror mirror-ports.json \\
        --scope capture-scope.json \\
        --claims direction-claims.json \\
        --capture SPAN-A=span-a.pcapng \\
        --capture SPAN-B=span-b.pcapng

    python -m dpkt.direction demo
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse
import calendar
import csv
import datetime
import hashlib
import json
import os
import struct
import sys
import tempfile
import time
from collections import namedtuple

from . import dpkt
from . import ethernet
from . import ip
from . import ip6
from . import pcap
from . import pcapng
from . import sll
from . import sll2
from . import tcp
from . import udp
from .compat import StringIO
from .utils import inet_to_str, mac_to_str


INBOUND = 'inbound'
OUTBOUND = 'outbound'
BOTH = 'both'

DIRECTION_ORDER = {INBOUND: 0, OUTBOUND: 1}

# EtherTypes used for VLAN tag stacks.  802.1Q, 802.1ad and the two legacy
# QinQ EtherTypes all carry the same four-byte tag format.
VLAN_ETHERTYPES = frozenset((0x8100, 0x88a8, 0x9100, 0x9200))

ETH_HDR_LEN = 14
SLL_HDR_LEN = 16
SLL2_HDR_LEN = 20

_LINKTYPE_NAMES = {
    pcap.DLT_NULL: 'DLT_NULL',
    pcap.DLT_EN10MB: 'DLT_EN10MB',
    pcap.DLT_RAW: 'DLT_RAW',
    pcap.DLT_LOOP: 'DLT_LOOP',
    pcap.DLT_LINUX_SLL: 'DLT_LINUX_SLL',
    pcap.DLT_LINUX_SLL2: 'DLT_LINUX_SLL2',
}

_ETHERTYPE_NAMES = {
    0x0800: 'IPv4',
    0x0806: 'ARP',
    0x8100: '802.1Q',
    0x86dd: 'IPv6',
    0x88a8: '802.1ad',
    0x8847: 'MPLS',
    0x8848: 'MPLS-multicast',
    0x8863: 'PPPoE-discovery',
    0x8864: 'PPPoE-session',
    0x9100: 'QinQ-legacy-1',
    0x9200: 'QinQ-legacy-2',
}

_SLL_PACKET_TYPES = {
    0: 'host',
    1: 'broadcast',
    2: 'multicast',
    3: 'otherhost',
    4: 'outgoing',
}

_DIRECTION_ALIASEs = {
    'in': INBOUND,
    'inbound': INBOUND,
    'ingress': INBOUND,
    'ingress-only': INBOUND,
    'rx': INBOUND,
    'receive': INBOUND,
    'received': INBOUND,
    'to-us': INBOUND,
    'uplink': INBOUND,
    '入': INBOUND,
    '入站': INBOUND,
    '接收': INBOUND,
    'out': OUTBOUND,
    'outbound': OUTBOUND,
    'egress': OUTBOUND,
    'egress-only': OUTBOUND,
    'tx': OUTBOUND,
    'transmit': OUTBOUND,
    'transmitted': OUTBOUND,
    'from-us': OUTBOUND,
    'downlink': OUTBOUND,
    '出': OUTBOUND,
    '出站': OUTBOUND,
    '发送': OUTBOUND,
    'both': BOTH,
    'bi': BOTH,
    'bidirectional': BOTH,
    'inout': BOTH,
    'in/out': BOTH,
    'rx/tx': BOTH,
    '双向': BOTH,
    'unknown': None,
    'any': None,
    'n/a': None,
    '-': None,
}

_WEAK_BASIS_TOKENS = (
    'mac', 'oui', 'ether', 'l2', 'src_mac', 'dst_mac', 'source address',
    'destination address', '源mac', '目的mac', 'mac地址',
)


def normalize_direction(value):
    """Normalize a direction label.

    Returns ``'inbound'``, ``'outbound'``, ``'both'`` or ``None``.  A list or
    set of labels is normalized to ``'both'`` when it contains both single
    directions.
    """
    if value is None:
        return None
    if isinstance(value, (list, tuple, set, frozenset)):
        normalized = set()
        for item in value:
            direction = normalize_direction(item)
            if direction == BOTH:
                normalized.update((INBOUND, OUTBOUND))
            elif direction:
                normalized.add(direction)
        if len(normalized) > 1:
            return BOTH
        return normalized.pop() if normalized else None
    text = str(value).strip().lower()
    if text in _DIRECTION_ALIASEs:
        return _DIRECTION_ALIASEs[text]
    # Tolerate labels such as "ingress (SPAN)".
    for token in (INBOUND, OUTBOUND, BOTH, 'ingress', 'egress', 'rx', 'tx'):
        if token in text:
            return _DIRECTION_ALIASEs.get(token)
    return None


def _direction_tuple(values):
    directions = set()
    for value in values:
        direction = normalize_direction(value)
        if direction == BOTH:
            directions.update((INBOUND, OUTBOUND))
        elif direction:
            directions.add(direction)
    return tuple(sorted(directions, key=lambda item: DIRECTION_ORDER[item]))


def _as_mac(value):
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        if len(value) >= 6:
            return mac_to_str(bytes(value[:6]))
        return None
    return str(value).strip().lower()


def _as_vlan(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if text in ('', '-', 'none', 'null', 'any', '*'):
        return None
    if text.startswith('vlan'):
        text = text[4:].strip()
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        try:
            return int(text, 10)
        except (TypeError, ValueError):
            return None


def _as_vlan_set(value):
    if value is None:
        return None
    if isinstance(value, int):
        return set([value])
    if isinstance(value, (list, tuple, set, frozenset)):
        result = set()
        for item in value:
            vlan = _as_vlan(item)
            if vlan is not None:
                result.add(vlan)
        return result
    text = str(value).strip()
    if not text:
        return None
    parts = text.replace(';', ',').replace(' ', ',').split(',')
    result = set()
    for part in parts:
        vlan = _as_vlan(part)
        if vlan is not None:
            result.add(vlan)
    return result or None


def _as_capture_points(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple, set, frozenset)):
        result = set(str(item) for item in value if item is not None)
        return result or None
    if isinstance(value, dict):
        result = set(str(item) for item in value.keys() if item is not None)
        return result or None
    text = str(value).strip()
    if not text:
        return None
    if ',' in text or ';' in text:
        result = set(part.strip() for part in text.replace(';', ',').split(',') if part.strip())
        return result or None
    return set([text])


def _parse_time(value):
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        if value.tzinfo is not None:
            return value.timestamp()
        return calendar.timegm(value.timetuple()) + value.microsecond / 1000000.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    candidate = text
    if candidate.endswith('Z'):
        candidate = candidate[:-1] + '+00:00'
    try:
        parsed = datetime.datetime.fromisoformat(candidate)
    except AttributeError:
        parsed = None
    except ValueError:
        parsed = None
    if parsed is not None:
        if parsed.tzinfo is not None:
            return parsed.timestamp()
        return calendar.timegm(parsed.timetuple()) + parsed.microsecond / 1000000.0
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            parsed = datetime.datetime.strptime(text, fmt)
            return calendar.timegm(parsed.timetuple())
        except ValueError:
            continue
    raise ValueError('unrecognized time value: %r' % (value,))


def _iso_time(ts):
    if ts is None:
        return None
    sec = int(ts)
    micros = int(round((ts - sec) * 1000000))
    if micros >= 1000000:
        sec += 1
        micros = 0
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(sec)) + '.%06dZ' % micros


def _ethertype_name(value):
    return _ETHERTYPE_NAMES.get(value, '0x%04x' % value if value is not None else None)


def _linktype_name(value):
    return _LINKTYPE_NAMES.get(value, 'DLT_%s' % value)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


class VlanTag(object):
    """One 802.1Q/802.1ad tag from the outer tag stack."""

    __slots__ = ('index', 'tci', 'vid', 'pri', 'cfi', 'ethertype')

    def __init__(self, index, tci, vid, pri, cfi, ethertype):
        self.index = index
        self.tci = tci
        self.vid = vid
        self.pri = pri
        self.cfi = cfi
        self.ethertype = ethertype

    def to_dict(self):
        return {
            'index': self.index,
            'outer': self.index == 0,
            'tci': self.tci,
            'vid': self.vid,
            'pri': self.pri,
            'cfi': self.cfi,
            'ethertype': self.ethertype,
            'ethertype_name': _ethertype_name(self.ethertype),
        }

    def __repr__(self):
        return 'VlanTag(vid=%d, pri=%d, cfi=%d)' % (self.vid, self.pri, self.cfi)


class LinkEvidence(object):
    """Link-layer evidence retained for one captured frame."""

    def __init__(self, linktype, linktype_name, captured_len=0, original_len=0):
        self.linktype = linktype
        self.linktype_name = linktype_name
        self.captured_len = captured_len
        self.original_len = original_len
        self.l2_present = True
        self.dst_mac = None
        self.src_mac = None
        self.sll_address = None
        self.sll_packet_type = None
        self.sll_packet_type_name = None
        self.sll_ifindex = None
        self.ethertype = None
        self.ethertype_name = None
        self.vlan_tags = []
        self.header_len = None
        self.payload_offset = None
        self.header_complete = False
        self.header_truncated = False
        self.payload_truncated = False
        self.truncated = False
        self.truncation_reason = None
        self.parse_stack = []
        self.parse_error = None
        self.payload_protocol = None
        self.ipv4_src = None
        self.ipv4_dst = None
        self.ipv6_src = None
        self.ipv6_dst = None
        self.ip_proto = None
        self.sport = None
        self.dport = None
        self.direction_hint = None
        self.direction_hint_source = None
        self.notes = []
        self.sha256 = None
        self.raw_prefix_hex = None

    @property
    def outer_vlan(self):
        return self.vlan_tags[0].vid if self.vlan_tags else None

    @property
    def inner_vlan(self):
        return self.vlan_tags[1].vid if len(self.vlan_tags) > 1 else None

    @property
    def vlan_stack(self):
        return [tag.vid for tag in self.vlan_tags]
    @property
    def vlan(self):
        return self.outer_vlan

    def to_dict(self):
        return {
            'linktype': self.linktype,
            'linktype_name': self.linktype_name,
            'l2_present': self.l2_present,
            'dst_mac': self.dst_mac,
            'src_mac': self.src_mac,
            'sll_address': self.sll_address,
            'sll_packet_type': self.sll_packet_type,
            'sll_packet_type_name': self.sll_packet_type_name,
            'sll_ifindex': self.sll_ifindex,
            'ethertype': self.ethertype,
            'ethertype_name': self.ethertype_name,
            'vlan_tags': [tag.to_dict() for tag in self.vlan_tags],
            'vlan_stack': self.vlan_stack,
            'outer_vlan': self.outer_vlan,
            'inner_vlan': self.inner_vlan,
            'header_len': self.header_len,
            'payload_offset': self.payload_offset,
            'header_complete': self.header_complete,
            'header_truncated': self.header_truncated,
            'payload_truncated': self.payload_truncated,
            'truncated': self.truncated,
            'truncation_reason': self.truncation_reason,
            'parse_stack': list(self.parse_stack),
            'parse_error': self.parse_error,
            'payload_protocol': self.payload_protocol,
            'ipv4_src': self.ipv4_src,
            'ipv4_dst': self.ipv4_dst,
            'ipv6_src': self.ipv6_src,
            'ipv6_dst': self.ipv6_dst,
            'ip_proto': self.ip_proto,
            'sport': self.sport,
            'dport': self.dport,
            'direction_hint': self.direction_hint,
            'direction_hint_source': self.direction_hint_source,
            'captured_len': self.captured_len,
            'original_len': self.original_len,
            'sha256': self.sha256,
            'raw_prefix_hex': self.raw_prefix_hex,
            'notes': list(self.notes),
        }


def _scan_vlan_tags(data, offset, ethertype, max_tags=32):
    """Scan a VLAN tag stack.

    Returns ``(tags, final_ethertype, complete, reason)``.  ``complete`` is
    false if the capture ended in the middle of a tag, which is exactly the
    case where a direction must not be invented.
    """
    tags = []
    while ethertype in VLAN_ETHERTYPES:
        if len(data) < offset + 4:
            return (tags, ethertype, False,
                    'captured %d bytes; VLAN tag #%d needs 4 bytes at offset %d'
                    % (len(data), len(tags) + 1, offset))
        if len(tags) >= max_tags:
            return (tags, ethertype, False,
                    'VLAN tag stack has more than %d tags' % max_tags)
        tci, inner_type = struct.unpack('>HH', data[offset:offset + 4])
        tags.append(VlanTag(
            index=len(tags),
            tci=tci,
            vid=tci & 0x0fff,
            pri=(tci >> 13) & 0x7,
            cfi=(tci >> 12) & 0x1,
            ethertype=inner_type,
        ))
        offset += 4
        ethertype = inner_type
    return (tags, ethertype, True, None)


def _set_prefix_and_hash(evidence, data):
    evidence.sha256 = _sha256(data)
    evidence.raw_prefix_hex = data[:64].hex()


def _parse_ethernet_evidence(data, evidence):
    evidence.l2_present = True
    if len(data) >= 6:
        evidence.dst_mac = _as_mac(data[0:6])
    if len(data) >= 12:
        evidence.src_mac = _as_mac(data[6:12])
    if len(data) < ETH_HDR_LEN:
        evidence.truncation_reason = (
            'captured %d bytes; Ethernet header needs at least %d bytes '
            '(destination MAC 6 + source MAC 6 + EtherType 2)'
            % (len(data), ETH_HDR_LEN)
        )
        return
    ethertype = struct.unpack('>H', data[12:14])[0]
    evidence.ethertype = ethertype
    evidence.ethertype_name = _ethertype_name(ethertype)
    tags, final_type, complete, reason = _scan_vlan_tags(data, ETH_HDR_LEN, ethertype)
    evidence.vlan_tags = tags
    evidence.header_len = ETH_HDR_LEN + (4 * len(tags))
    evidence.payload_offset = evidence.header_len
    evidence.header_complete = complete
    if complete:
        evidence.ethertype = final_type
        evidence.ethertype_name = _ethertype_name(final_type)
    else:
        evidence.truncation_reason = reason


def _parse_sll_evidence(data, evidence):
    evidence.l2_present = True
    if len(data) < SLL_HDR_LEN:
        evidence.truncation_reason = (
            'captured %d bytes; Linux SLL header needs %d bytes'
            % (len(data), SLL_HDR_LEN)
        )
        return
    packet_type, hrd, hlen, hdr, ethertype = struct.unpack('>HHH8sH', data[:SLL_HDR_LEN])
    evidence.sll_packet_type = packet_type
    evidence.sll_packet_type_name = _SLL_PACKET_TYPES.get(packet_type, str(packet_type))
    evidence.sll_address = _as_mac(hdr[:min(hlen, 8)])
    evidence.src_mac = _as_mac(hdr[:6]) if hlen >= 6 else None
    evidence.direction_hint = OUTBOUND if packet_type == 4 else INBOUND
    evidence.direction_hint_source = 'linux-sll-packet-type'
    evidence.notes.append(
        'SLL packet type %s is link-local evidence only; mirror ledger is authoritative'
        % evidence.sll_packet_type_name
    )
    evidence.ethertype = ethertype
    evidence.ethertype_name = _ethertype_name(ethertype)
    tags, final_type, complete, reason = _scan_vlan_tags(data, SLL_HDR_LEN, ethertype)
    evidence.vlan_tags = tags
    evidence.header_len = SLL_HDR_LEN + (4 * len(tags))
    evidence.payload_offset = evidence.header_len
    evidence.header_complete = complete
    if complete:
        evidence.ethertype = final_type
        evidence.ethertype_name = _ethertype_name(final_type)
    else:
        evidence.truncation_reason = reason


def _parse_sll2_evidence(data, evidence):
    evidence.l2_present = True
    if len(data) < SLL2_HDR_LEN:
        evidence.truncation_reason = (
            'captured %d bytes; Linux SLL2 header needs %d bytes'
            % (len(data), SLL2_HDR_LEN)
        )
        return
    ethertype = struct.unpack('>H', data[0:2])[0]
    ifindex = struct.unpack('>i', data[4:8])[0]
    packet_type = struct.unpack('>B', data[10:11])[0]
    hlen = struct.unpack('>B', data[11:12])[0]
    hdr = data[12:20]
    evidence.sll_packet_type = packet_type
    evidence.sll_packet_type_name = _SLL_PACKET_TYPES.get(packet_type, str(packet_type))
    evidence.sll_ifindex = ifindex
    evidence.sll_address = _as_mac(hdr[:min(hlen, 8)])
    evidence.src_mac = _as_mac(hdr[:6]) if hlen >= 6 else None
    evidence.direction_hint = OUTBOUND if packet_type == 4 else INBOUND
    evidence.direction_hint_source = 'linux-sll2-packet-type'
    evidence.notes.append(
        'SLL2 packet type %s is link-local evidence only; mirror ledger is authoritative'
        % evidence.sll_packet_type_name
    )
    evidence.ethertype = ethertype
    evidence.ethertype_name = _ethertype_name(ethertype)
    tags, final_type, complete, reason = _scan_vlan_tags(data, SLL2_HDR_LEN, ethertype)
    evidence.vlan_tags = tags
    evidence.header_len = SLL2_HDR_LEN + (4 * len(tags))
    evidence.payload_offset = evidence.header_len
    evidence.header_complete = complete
    if complete:
        evidence.ethertype = final_type
        evidence.ethertype_name = _ethertype_name(final_type)
    else:
        evidence.truncation_reason = reason


def _parse_raw_evidence(data, evidence):
    evidence.l2_present = False
    evidence.header_len = 0
    evidence.payload_offset = 0
    if not data:
        evidence.truncation_reason = 'captured 0 bytes; raw IP header is missing'
        return
    version = data[0] >> 4
    evidence.ethertype = 0x0800 if version == 4 else 0x86dd if version == 6 else None
    evidence.ethertype_name = _ethertype_name(evidence.ethertype)
    evidence.header_complete = evidence.ethertype is not None
    if not evidence.header_complete:
        evidence.truncation_reason = 'raw IP header version nibble is invalid'


def _parse_null_evidence(data, evidence):
    evidence.l2_present = False
    evidence.header_len = 4
    evidence.payload_offset = 4
    if len(data) < 4:
        evidence.truncation_reason = 'captured %d bytes; NULL/LOOP header needs 4 bytes' % len(data)
        return
    family_le = struct.unpack('<I', data[:4])[0]
    family_be = struct.unpack('>I', data[:4])[0]
    family = family_le if family_le in (2, 24, 28, 30) else family_be
    if family == 2:
        evidence.ethertype = 0x0800
    elif family in (24, 28, 30):
        evidence.ethertype = 0x86dd
    evidence.ethertype_name = _ethertype_name(evidence.ethertype)
    evidence.header_complete = evidence.ethertype is not None
    if not evidence.header_complete:
        evidence.truncation_reason = 'NULL/LOOP address family %r is not IP' % family


def _collect_stack(root):
    stack = []
    current = root
    for _ in range(16):
        if current is None or isinstance(current, (bytes, bytearray)):
            break
        stack.append(current.__class__.__name__)
        current = getattr(current, 'data', None)
    return stack


def _extract_network_fields(evidence, root):
    current = root
    for _ in range(16):
        if current is None or isinstance(current, (bytes, bytearray)):
            break
        if isinstance(current, ip.IP):
            try:
                evidence.ipv4_src = inet_to_str(current.src)
                evidence.ipv4_dst = inet_to_str(current.dst)
                evidence.ip_proto = current.p
            except Exception:
                pass
        elif isinstance(current, ip6.IP6):
            try:
                evidence.ipv6_src = inet_to_str(current.src)
                evidence.ipv6_dst = inet_to_str(current.dst)
                evidence.ip_proto = current.nxt
            except Exception:
                pass
        elif isinstance(current, tcp.TCP):
            evidence.sport = current.sport
            evidence.dport = current.dport
        elif isinstance(current, udp.UDP):
            evidence.sport = current.sport
            evidence.dport = current.dport
        current = getattr(current, 'data', None)


def _parse_dpkt_payload(evidence, data):
    root = None
    try:
        if evidence.linktype == pcap.DLT_EN10MB:
            root = ethernet.Ethernet(data)
        elif evidence.linktype == pcap.DLT_LINUX_SLL:
            root = sll.SLL(data)
        elif evidence.linktype == pcap.DLT_LINUX_SLL2:
            root = sll2.SLL2(data)
        elif evidence.linktype == pcap.DLT_RAW:
            if evidence.ethertype == 0x0800:
                root = ip.IP(data)
            elif evidence.ethertype == 0x86dd:
                root = ip6.IP6(data)
        elif evidence.linktype in (pcap.DLT_NULL, pcap.DLT_LOOP):
            payload = data[4:]
            if evidence.ethertype == 0x0800:
                root = ip.IP(payload)
            elif evidence.ethertype == 0x86dd:
                root = ip6.IP6(payload)
        else:
            evidence.notes.append('payload parser not available for link type %s' % evidence.linktype)
    except (dpkt.UnpackError, dpkt.NeedData, struct.error, ValueError) as exc:
        evidence.parse_error = '%s: %s' % (exc.__class__.__name__, exc)
        return
    except Exception as exc:  # keep the audit running on malformed captures
        evidence.parse_error = '%s: %s' % (exc.__class__.__name__, exc)
        return
    if root is not None:
        evidence.parse_stack = _collect_stack(root)
        if evidence.parse_stack:
            evidence.payload_protocol = evidence.parse_stack[-1]
        _extract_network_fields(evidence, root)


def parse_link_evidence(data, linktype=pcap.DLT_EN10MB,
                        captured_len=None, original_len=None,
                        parse_payload=True):
    """Parse offline bytes into :class:`LinkEvidence`.

    ``data`` is the captured frame buffer.  ``original_len`` is the on-wire
    length from the pcap/pcapng record header; when it is larger than
    ``captured_len`` the payload was truncated by the snapshot length.
    Direction is only derivable when the complete L2 header (including every
    outer VLAN tag) is present.
    """
    if not isinstance(data, (bytes, bytearray)):
        data = bytes(data)
    else:
        data = bytes(data)
    captured_len = len(data) if captured_len is None else int(captured_len)
    original_len = captured_len if original_len is None else int(original_len)

    evidence = LinkEvidence(linktype, _linktype_name(linktype), captured_len, original_len)
    _set_prefix_and_hash(evidence, data)

    if linktype == pcap.DLT_EN10MB:
        _parse_ethernet_evidence(data, evidence)
    elif linktype == pcap.DLT_LINUX_SLL:
        _parse_sll_evidence(data, evidence)
    elif linktype == pcap.DLT_LINUX_SLL2:
        _parse_sll2_evidence(data, evidence)
    elif linktype == pcap.DLT_RAW:
        _parse_raw_evidence(data, evidence)
    elif linktype in (pcap.DLT_NULL, pcap.DLT_LOOP):
        _parse_null_evidence(data, evidence)
    else:
        evidence.truncation_reason = 'unsupported link type %s' % _linktype_name(linktype)

    evidence.header_truncated = not evidence.header_complete
    evidence.payload_truncated = captured_len < original_len
    evidence.truncated = evidence.header_truncated or evidence.payload_truncated
    if evidence.header_truncated and not evidence.truncation_reason:
        evidence.truncation_reason = 'L2 header is incomplete'

    if parse_payload and evidence.header_complete:
        _parse_dpkt_payload(evidence, data)

    return evidence


def _first(record, names, default=None):
    for name in names:
        if name in record and record[name] is not None:
            return record[name]
    return default


class MirrorPort(object):
    """One trusted mirror-port/ledger record."""

    _CAPTURE_KEYS = ('capture_point', 'capture', 'point', 'span', 'span_name',
                     'if_name', 'interface_name', 'capture_interface')
    _PORT_KEYS = ('mirror_port', 'port', 'interface', 'ifindex', 'src_port')
    _DEVICE_KEYS = ('device', 'switch', 'host', 'node', 'device_name')
    _VLAN_KEYS = ('vlan', 'outer_vlan', 'svlan', 'service_vlan', 'vlan_id')
    _INNER_VLAN_KEYS = ('inner_vlan', 'cvlan', 'customer_vlan')
    _DIRECTION_KEYS = ('direction', 'dir', 'span_direction', 'mirror_direction', 'role')
    _TRUSTED_KEYS = ('trusted', 'authoritative', 'verified')
    _DESCRIPTION_KEYS = ('description', 'note', 'comment')

    def __init__(self, capture_point=None, mirror_port=None, device=None,
                 vlan=None, inner_vlan=None, vlan_role='outer',
                 direction=None, trusted=True, description=None, **extra):
        self.capture_point = None if capture_point is None else str(capture_point).strip()
        self.mirror_port = None if mirror_port is None else str(mirror_port).strip()
        self.device = None if device is None else str(device)
        self.vlan = _as_vlan(vlan)
        self.inner_vlan = _as_vlan(inner_vlan)
        self.vlan_role = (vlan_role or 'outer').strip().lower()
        self.raw_direction = direction
        self.normalized_direction = normalize_direction(direction)
        self.trusted = (trusted if isinstance(trusted, bool) else
                        str(trusted).strip().lower() not in ('0', 'false', 'no', 'off', 'untrusted'))
        self.description = description
        self.extra = extra

    @classmethod
    def from_record(cls, record):
        if isinstance(record, cls):
            return record
        if not isinstance(record, dict):
            raise TypeError('mirror port record must be a dict or MirrorPort')
        vlan = _first(record, cls._VLAN_KEYS)
        direction = _first(record, cls._DIRECTION_KEYS)
        trusted = _first(record, cls._TRUSTED_KEYS, True)
        known = set(cls._CAPTURE_KEYS + cls._PORT_KEYS + cls._DEVICE_KEYS +
                    cls._VLAN_KEYS + cls._INNER_VLAN_KEYS + cls._DIRECTION_KEYS +
                    cls._TRUSTED_KEYS + cls._DESCRIPTION_KEYS + ('vlan_role',))
        extra = dict((key, value) for key, value in record.items() if key not in known)
        return cls(
            capture_point=_first(record, cls._CAPTURE_KEYS),
            mirror_port=_first(record, cls._PORT_KEYS),
            device=_first(record, cls._DEVICE_KEYS),
            vlan=vlan,
            inner_vlan=_first(record, cls._INNER_VLAN_KEYS),
            vlan_role=record.get('vlan_role', 'outer'),
            direction=direction,
            trusted=trusted,
            description=_first(record, cls._DESCRIPTION_KEYS),
            **extra
        )

    @property
    def directions(self):
        if self.normalized_direction == BOTH:
            return (INBOUND, OUTBOUND)
        if self.normalized_direction in (INBOUND, OUTBOUND):
            return (self.normalized_direction,)
        return ()

    def matches_vlans(self, outer_vlan, inner_vlan):
        if self.vlan is None:
            return True
        if self.vlan_role in ('inner', 'c', 'cvlan', 'customer'):
            frame_vlan = inner_vlan
        else:
            frame_vlan = outer_vlan
        # An untagged frame at a port whose trusted configuration assigns a
        # VLAN is not a contradiction; the tag merely is not visible.
        if frame_vlan is None:
            return True
        if self.vlan != frame_vlan:
            return False
        if self.inner_vlan is not None:
            if inner_vlan is not None and self.inner_vlan != inner_vlan:
                return False
        return True

    def to_dict(self):
        result = {
            'capture_point': self.capture_point,
            'mirror_port': self.mirror_port,
            'device': self.device,
            'vlan': self.vlan,
            'inner_vlan': self.inner_vlan,
            'vlan_role': self.vlan_role,
            'direction': self.normalized_direction,
            'raw_direction': self.raw_direction,
            'trusted': self.trusted,
            'description': self.description,
        }
        if self.extra:
            result['extra'] = dict(self.extra)
        return result

    def __repr__(self):
        return ('MirrorPort(capture_point=%r, mirror_port=%r, vlan=%r, direction=%r, trusted=%r)'
                % (self.capture_point, self.mirror_port, self.vlan, self.normalized_direction, self.trusted))


LookupResult = namedtuple('LookupResult', 'matches point_entries vlan_mismatches')


class MirrorPortTable(object):
    """A trusted mirror-port table keyed by capture point."""

    def __init__(self, ports=None):
        self.ports = []
        if ports is not None:
            self.add(ports)

    def __len__(self):
        return len(self.ports)

    def __iter__(self):
        return iter(self.ports)

    @classmethod
    def from_records(cls, records):
        return cls(records)

    @classmethod
    def from_csv(cls, text):
        if isinstance(text, bytes):
            text = text.decode('utf-8')
        text = text.lstrip('\ufeff')
        rows = list(csv.DictReader(StringIO(text)))
        return cls(rows)

    @classmethod
    def from_json(cls, text):
        return cls(json.loads(text))

    @classmethod
    def from_file(cls, path):
        if hasattr(os, 'PathLike') and isinstance(path, os.PathLike):
            path = os.fspath(path)
        with open(path, 'rb') as handle:
            text = handle.read()
        if path.lower().endswith('.csv'):
            return cls.from_csv(text)
        return cls.from_json(text.decode('utf-8') if isinstance(text, bytes) else text)

    def add(self, ports):
        if isinstance(ports, MirrorPortTable):
            self.ports.extend(ports.ports)
            return
        if isinstance(ports, MirrorPort):
            self.ports.append(ports)
            return
        if isinstance(ports, dict):
            record_keys = (MirrorPort._CAPTURE_KEYS + MirrorPort._PORT_KEYS +
                           MirrorPort._DEVICE_KEYS + MirrorPort._VLAN_KEYS +
                           MirrorPort._INNER_VLAN_KEYS + MirrorPort._DIRECTION_KEYS +
                           MirrorPort._TRUSTED_KEYS + MirrorPort._DESCRIPTION_KEYS +
                           ('vlan_role',))
            if any(key in ports for key in record_keys):
                self.ports.append(MirrorPort.from_record(ports))
                return
            for key in ('mirror_ports', 'ports', 'entries', 'table', 'records'):
                if key in ports:
                    self.add(ports[key])
                    return
            for capture_point, value in ports.items():
                if isinstance(value, list):
                    for item in value:
                        record = dict(item)
                        record.setdefault('capture_point', capture_point)
                        self.add(record)
                elif isinstance(value, dict):
                    record = dict(value)
                    record.setdefault('capture_point', capture_point)
                    self.add(record)
                else:
                    self.add({'capture_point': capture_point, 'direction': value})
            return
        if isinstance(ports, (list, tuple, set)):
            for item in ports:
                self.add(item)
            return
        raise TypeError('unsupported mirror port table input: %r' % (ports,))

    def lookup(self, capture_point, outer_vlan=None, inner_vlan=None, mirror_port=None):
        matches = []
        point_entries = []
        vlan_mismatches = []
        for entry in self.ports:
            if not entry.trusted:
                continue
            if entry.capture_point is not None and capture_point is not None:
                if entry.capture_point != capture_point:
                    continue
            elif entry.capture_point is not None and capture_point is None:
                continue
            if mirror_port is not None and entry.mirror_port is not None:
                if entry.mirror_port != mirror_port:
                    continue
            point_entries.append(entry)
            if entry.matches_vlans(outer_vlan, inner_vlan):
                matches.append(entry)
            elif outer_vlan is not None or inner_vlan is not None:
                vlan_mismatches.append(entry)
        return LookupResult(matches, point_entries, vlan_mismatches)

    def find(self, capture_point, outer_vlan=None, inner_vlan=None, mirror_port=None):
        return self.lookup(capture_point, outer_vlan, inner_vlan, mirror_port)

    def directions(self, capture_point, outer_vlan=None, inner_vlan=None):
        return _union_directions(self.lookup(capture_point, outer_vlan, inner_vlan).matches)

    def direction_for(self, capture_point, outer_vlan=None, inner_vlan=None):
        directions = self.directions(capture_point, outer_vlan, inner_vlan)
        return directions[0] if len(directions) == 1 else None

    def to_dict(self):
        return {'mirror_ports': [entry.to_dict() for entry in self.ports]}


class CaptureScope(object):
    """The part of a capture that the investigation accepts as authoritative."""

    def __init__(self, capture_points=None, vlans=None, start=None, end=None,
                 addresses=None, mirror_ports=None, require_vlan_tag=False, **extra):
        self.capture_points = _as_capture_points(capture_points)
        self.vlans = _as_vlan_set(vlans)
        self.start = _parse_time(start)
        self.end = _parse_time(end)
        self.addresses = self._normalize_addresses(addresses)
        self.mirror_ports = _as_capture_points(mirror_ports)
        self.require_vlan_tag = bool(require_vlan_tag)
        self.extra = extra

    @staticmethod
    def _normalize_addresses(addresses):
        if addresses is None:
            return None
        if isinstance(addresses, (str, int)):
            addresses = [addresses]
        result = set(str(item).strip().lower() for item in addresses if item is not None)
        return result or None

    @classmethod
    def from_mapping(cls, mapping):
        if mapping is None:
            return cls()
        if isinstance(mapping, cls):
            return mapping
        if not isinstance(mapping, dict):
            raise TypeError('capture scope must be a dict')
        if 'scope' in mapping and isinstance(mapping['scope'], dict):
            mapping = mapping['scope']
        return cls(
            capture_points=_first(mapping, ('capture_points', 'points', 'captures')),
            vlans=_first(mapping, ('vlans', 'vlan', 'vlan_ids')),
            start=_first(mapping, ('start', 'start_time', 'from')),
            end=_first(mapping, ('end', 'end_time', 'to')),
            addresses=_first(mapping, ('addresses', 'macs', 'ips', 'address')),
            mirror_ports=_first(mapping, ('mirror_ports', 'ports')),
            require_vlan_tag=bool(mapping.get('require_vlan_tag', False)),
        )

    def contains(self, frame, evidence):
        if self.capture_points:
            if frame.capture_point not in self.capture_points:
                return (False, 'capture point %r is outside scope %s'
                        % (frame.capture_point, sorted(self.capture_points)))
        if self.mirror_ports:
            if getattr(frame, 'mirror_port', None) is not None:
                if frame.mirror_port not in self.mirror_ports:
                    return (False, 'mirror port %r is outside scope %s'
                            % (frame.mirror_port, sorted(self.mirror_ports)))
        if self.vlans:
            outer_vlan = evidence.outer_vlan
            if outer_vlan is not None and outer_vlan not in self.vlans:
                return (False, 'outer VLAN %d is outside scope %s'
                        % (outer_vlan, sorted(self.vlans)))
            if outer_vlan is None and self.require_vlan_tag:
                return (False, 'frame is untagged but scope requires an outer VLAN tag')
        if self.start is not None and frame.ts < self.start:
            return (False, 'timestamp %s is before scope start %s'
                    % (_iso_time(frame.ts), _iso_time(self.start)))
        if self.end is not None and frame.ts > self.end:
            return (False, 'timestamp %s is after scope end %s'
                    % (_iso_time(frame.ts), _iso_time(self.end)))
        if self.addresses:
            observed = set()
            for value in (evidence.src_mac, evidence.dst_mac, evidence.sll_address,
                          evidence.ipv4_src, evidence.ipv4_dst,
                          evidence.ipv6_src, evidence.ipv6_dst):
                if value:
                    observed.add(str(value).lower())
            if not (observed & self.addresses):
                return (False, 'no scope address among %s' % sorted(observed))
        return (True, None)

    def to_dict(self):
        return {
            'capture_points': sorted(self.capture_points) if self.capture_points else None,
            'vlans': sorted(self.vlans) if self.vlans else None,
            'start': _iso_time(self.start),
            'end': _iso_time(self.end),
            'addresses': sorted(self.addresses) if self.addresses else None,
            'mirror_ports': sorted(self.mirror_ports) if self.mirror_ports else None,
            'require_vlan_tag': self.require_vlan_tag,
        }


class RawFrame(object):
    """One captured frame plus its capture-point metadata."""

    def __init__(self, index=0, data=b'', ts=0.0, linktype=pcap.DLT_EN10MB,
                 capture_point=None, interface_id=0, interface_name=None,
                 captured_len=None, original_len=None, local_index=None,
                 source=None, read_truncated=False):
        self.index = index
        self.local_index = index if local_index is None else local_index
        self.data = bytes(data)
        self.ts = float(ts or 0.0)
        self.linktype = int(linktype)
        self.capture_point = capture_point
        self.interface_id = interface_id
        self.interface_name = interface_name
        self.captured_len = len(self.data) if captured_len is None else int(captured_len)
        self.original_len = self.captured_len if original_len is None else int(original_len)
        self.source = source
        self.read_truncated = read_truncated

    def to_dict(self):
        return {
            'index': self.index,
            'local_index': self.local_index,
            'capture_point': self.capture_point,
            'interface_id': self.interface_id,
            'interface_name': self.interface_name,
            'timestamp': self.ts,
            'timestamp_iso': _iso_time(self.ts),
            'linktype': self.linktype,
            'linktype_name': _linktype_name(self.linktype),
            'captured_len': self.captured_len,
            'original_len': self.original_len,
            'read_truncated': self.read_truncated,
            'source': self.source,
            'sha256': _sha256(self.data),
        }

    def __repr__(self):
        return ('RawFrame(index=%r, capture_point=%r, ts=%r, captured_len=%r, original_len=%r)'
                % (self.index, self.capture_point, self.ts, self.captured_len, self.original_len))


def _pcap_ts_divisor(magic):
    if magic in (pcap.TCPDUMP_MAGIC_NANO, pcap.PMUDPCT_MAGIC_NANO):
        return 1000000000.0
    return 1000000.0


def _read_pcap_bytes(data, capture_point=None, source_name=None):
    if len(data) < pcap.FileHdr.__hdr_len__:
        raise ValueError('pcap header is truncated')
    file_header = pcap.FileHdr(data[:pcap.FileHdr.__hdr_len__])
    magic = file_header.magic
    if magic in (pcap.PMUDPCT_MAGIC, pcap.PMUDPCT_MAGIC_NANO, pcap.PACPDOM_MAGIC):
        file_header = pcap.LEFileHdr(data[:pcap.LEFileHdr.__hdr_len__])
    if magic not in pcap.MAGIC_TO_PKT_HDR:
        raise ValueError('invalid pcap magic 0x%08x' % magic)
    packet_header_cls = pcap.MAGIC_TO_PKT_HDR[magic]
    offset = pcap.FileHdr.__hdr_len__
    divisor = _pcap_ts_divisor(magic)
    frames = []
    while offset + packet_header_cls.__hdr_len__ <= len(data):
        header = packet_header_cls(data[offset:offset + packet_header_cls.__hdr_len__])
        offset += packet_header_cls.__hdr_len__
        available = len(data) - offset
        read_truncated = available < header.caplen
        packet_data = data[offset:offset + header.caplen]
        offset += len(packet_data)
        ts = header.tv_sec + (header.tv_usec / divisor)
        ifindex = getattr(header, 'ifindex', 0) or 0
        frames.append(RawFrame(
            index=len(frames),
            local_index=len(frames),
            data=packet_data,
            ts=ts,
            linktype=file_header.linktype,
            capture_point=capture_point or ('ifindex-%d' % ifindex if ifindex else 'pcap'),
            interface_id=ifindex,
            interface_name=None,
            captured_len=len(packet_data),
            original_len=header.len or len(packet_data),
            source=source_name,
            read_truncated=read_truncated,
        ))
        if read_truncated:
            break
    return frames


def _pcapng_option(idb, code, default=None):
    for option in getattr(idb, 'opts', []):
        if option.code == code:
            return option.data
    return default


def _pcapng_interface_info(idb, endian='<'):
    info = {
        'linktype': idb.linktype,
        'snaplen': idb.snaplen,
        'if_name': None,
        'if_description': None,
        'resolution': 1000000.0,
        'tsoffset': 0,
    }
    name = _pcapng_option(idb, pcapng.PCAPNG_OPT_IF_NAME)
    if name:
        info['if_name'] = name.rstrip(b'\x00').decode('utf-8', 'replace')
    description = _pcapng_option(idb, pcapng.PCAPNG_OPT_IF_DESCRIPTION)
    if description:
        info['if_description'] = description.rstrip(b'\x00').decode('utf-8', 'replace')
    tsresol = _pcapng_option(idb, pcapng.PCAPNG_OPT_IF_TSRESOL)
    if tsresol:
        value = struct.unpack('B', tsresol[:1])[0]
        if value & 0x80:
            info['resolution'] = float(2 ** (value & 0x7f))
        else:
            info['resolution'] = float(10 ** value)
    tsoffset = _pcapng_option(idb, pcapng.PCAPNG_OPT_IF_TSOFFSET)
    if tsoffset and len(tsoffset) >= 8:
        info['tsoffset'] = struct.unpack(endian + 'q', tsoffset[:8])[0]
    return info


def _read_pcapng_bytes(data, capture_point=None, source_name=None):
    if len(data) < 12 or data[:4] != b'\x0a\x0d\x0d\x0a':
        raise ValueError('not a pcapng capture')
    bom = data[8:12]
    if bom == b'\x4d\x3c\x2b\x1a':
        endian = '<'
    elif bom == b'\x1a\x2b\x3c\x4d':
        endian = '>'
    else:
        raise ValueError('unknown pcapng byte-order magic %r' % (bom,))

    interfaces = {}
    frames = []
    offset = 0
    section_index = 0
    while offset + 12 <= len(data):
        block_type = struct.unpack(endian + 'I', data[offset:offset + 4])[0]
        total_len = struct.unpack(endian + 'I', data[offset + 4:offset + 8])[0]
        if total_len < 12 or offset + total_len > len(data):
            break
        block = data[offset:offset + total_len]
        offset += total_len

        if block_type == pcapng.PCAPNG_BT_SHB:
            section_index += 1
            interfaces = {}
            if len(block) >= 12:
                block_bom = block[8:12]
                if block_bom == b'\x4d\x3c\x2b\x1a':
                    endian = '<'
                elif block_bom == b'\x1a\x2b\x3c\x4d':
                    endian = '>'
            continue

        if block_type == pcapng.PCAPNG_BT_IDB:
            idb_cls = pcapng.InterfaceDescriptionBlockLE if endian == '<' else pcapng.InterfaceDescriptionBlock
            idb = idb_cls(block)
            interfaces[len(interfaces)] = _pcapng_interface_info(idb, endian)
            continue

        if block_type == pcapng.PCAPNG_BT_EPB:
            epb_cls = pcapng.EnhancedPacketBlockLE if endian == '<' else pcapng.EnhancedPacketBlock
            epb = epb_cls(block)
            iface_id = epb.iface_id
            info = interfaces.get(iface_id, {})
            resolution = info.get('resolution', 1000000.0)
            raw_ts = (epb.ts_high << 32) | epb.ts_low
            ts = info.get('tsoffset', 0) + (raw_ts / resolution)
            point = capture_point or info.get('if_name') or info.get('if_description')
            if not point:
                point = 'interface-%d' % iface_id
            frames.append(RawFrame(
                index=len(frames),
                local_index=len(frames),
                data=epb.pkt_data,
                ts=ts,
                linktype=info.get('linktype', pcap.DLT_EN10MB),
                capture_point=point,
                interface_id=iface_id,
                interface_name=info.get('if_name'),
                captured_len=epb.caplen,
                original_len=epb.pkt_len or epb.caplen,
                source=source_name,
                read_truncated=epb.caplen > len(epb.pkt_data),
            ))
            continue

        if block_type == pcapng.PCAPNG_BT_PB:
            pb_cls = pcapng.PacketBlockLE if endian == '<' else pcapng.PacketBlock
            pb = pb_cls(block)
            iface_id = pb.iface_id
            info = interfaces.get(iface_id, {})
            resolution = info.get('resolution', 1000000.0)
            raw_ts = (pb.ts_high << 32) | pb.ts_low
            ts = info.get('tsoffset', 0) + (raw_ts / resolution)
            point = capture_point or info.get('if_name') or info.get('if_description')
            if not point:
                point = 'interface-%d' % iface_id
            frames.append(RawFrame(
                index=len(frames),
                local_index=len(frames),
                data=pb.pkt_data,
                ts=ts,
                linktype=info.get('linktype', pcap.DLT_EN10MB),
                capture_point=point,
                interface_id=iface_id,
                interface_name=info.get('if_name'),
                captured_len=pb.caplen,
                original_len=pb.pkt_len or pb.caplen,
                source=source_name,
                read_truncated=pb.caplen > len(pb.pkt_data),
            ))
            continue

        if block_type == pcapng.PCAPNG_BT_SPB:
            if len(block) < 16:
                continue
            original_len = struct.unpack(endian + 'I', block[8:12])[0]
            packet_data = block[12:-4]
            info = interfaces.get(0, {})
            point = capture_point or info.get('if_name') or info.get('if_description') or 'interface-0'
            frames.append(RawFrame(
                index=len(frames),
                local_index=len(frames),
                data=packet_data,
                ts=0.0,
                linktype=info.get('linktype', pcap.DLT_EN10MB),
                capture_point=point,
                interface_id=0,
                interface_name=info.get('if_name'),
                captured_len=len(packet_data),
                original_len=original_len or len(packet_data),
                source=source_name,
            ))
    return frames


def _read_capture_bytes(data, capture_point=None, source_name=None, linktype=None):
    if len(data) >= 4:
        first = data[:4]
        if first == b'\x0a\x0d\x0d\x0a':
            return _read_pcapng_bytes(data, capture_point, source_name)
        file_header = pcap.FileHdr(data[:pcap.FileHdr.__hdr_len__]) if len(data) >= 24 else None
        if file_header is not None and file_header.magic in pcap.MAGIC_TO_PKT_HDR:
            return _read_pcap_bytes(data, capture_point, source_name)
    if linktype is None:
        raise ValueError('input is neither pcap nor pcapng, and no link type was supplied')
    return [RawFrame(
        index=0,
        local_index=0,
        data=data,
        ts=0.0,
        linktype=linktype,
        capture_point=capture_point or 'bytes',
        source=source_name,
    )]


def _frame_from_item(item, index):
    if isinstance(item, RawFrame):
        item.index = index
        if item.local_index is None:
            item.local_index = index
        return item
    if isinstance(item, dict):
        data = _first(item, ('data', 'buf', 'packet', 'bytes', 'payload'))
        if data is None:
            raise ValueError('frame record has no data: %r' % (item,))
        return RawFrame(
            index=index,
            local_index=item.get('local_index', index),
            data=data,
            ts=_first(item, ('ts', 'timestamp', 'time'), 0.0),
            linktype=_first(item, ('linktype', 'dlt'), pcap.DLT_EN10MB),
            capture_point=_first(item, ('capture_point', 'capture', 'point')),
            interface_id=item.get('interface_id', 0),
            interface_name=item.get('interface_name'),
            captured_len=item.get('captured_len'),
            original_len=_first(item, ('original_len', 'orig_len', 'wire_len')),
            source=item.get('source'),
        )
    if isinstance(item, (tuple, list)):
        if len(item) == 2:
            ts, data = item
            return RawFrame(index=index, local_index=index, data=data, ts=ts)
        if len(item) >= 3:
            ts, data = item[0], item[1]
            metadata = item[2] if isinstance(item[2], dict) else {}
            point = item[2] if isinstance(item[2], str) else metadata.get('capture_point')
            original_len = None
            if len(item) >= 4:
                original_len = item[3]
            elif isinstance(item[2], int) and not isinstance(item[2], bool):
                original_len = item[2]
            return RawFrame(
                index=index,
                local_index=index,
                data=data,
                ts=ts,
                capture_point=point,
                linktype=metadata.get('linktype', pcap.DLT_EN10MB),
                original_len=original_len,
            )
    if isinstance(item, (bytes, bytearray)):
        return RawFrame(index=index, local_index=index, data=item)
    raise TypeError('unsupported frame item: %r' % (item,))


def _read_sequence(items, capture_point=None):
    frames = []
    for index, item in enumerate(items):
        frame = _frame_from_item(item, index)
        if capture_point is not None:
            frame.capture_point = capture_point
        frames.append(frame)
    return frames


def read_capture(source, capture_point=None, linktype=None):
    """Read one offline capture source into a list of :class:`RawFrame`.

    ``source`` may be a path, a bytes object containing a pcap/pcapng file,
    a file-like object, a single raw frame buffer (with ``linktype``), or an
    iterable of frame tuples/dicts.
    """
    if isinstance(source, RawFrame):
        return [source]
    if hasattr(os, 'PathLike') and isinstance(source, os.PathLike):
        source = os.fspath(source)
    if isinstance(source, (bytes, bytearray)):
        return _read_capture_bytes(bytes(source), capture_point, '<bytes>', linktype)
    if isinstance(source, str):
        if not os.path.exists(source):
            raise IOError('capture file not found: %s' % source)
        with open(source, 'rb') as handle:
            data = handle.read()
        return _read_capture_bytes(data, capture_point, source, linktype)
    if hasattr(source, 'read'):
        data = source.read()
        source_name = getattr(source, 'name', '<stream>')
        return _read_capture_bytes(data, capture_point, source_name, linktype)
    if isinstance(source, (list, tuple)) or hasattr(source, '__iter__'):
        return _read_sequence(list(source), capture_point)
    raise TypeError('unsupported capture source: %r' % (source,))


def _normalize_source_pairs(sources):
    if isinstance(sources, dict):
        for key in ('captures', 'sources', 'inputs'):
            if key in sources:
                return _normalize_source_pairs(sources[key])
        return list(sources.items())
    if isinstance(sources, (list, tuple)):
        if all(isinstance(item, (list, tuple)) and len(item) == 2 and
               (item[0] is None or isinstance(item[0], str)) and
               not isinstance(item[1], (int, float)) for item in sources):
            return [(item[0], item[1]) for item in sources]
        return [(None, item) for item in sources]
    return [(None, sources)]


def read_captures(sources):
    """Read one or more capture sources and assign stable global frame indexes.

    ``sources`` may be a single source, a list of sources, a list of
    ``(capture_point, source)`` pairs or a dict mapping capture point to
    source.
    """
    frames = []
    for capture_point, source in _normalize_source_pairs(sources):
        for frame in read_capture(source, capture_point=capture_point):
            frame.index = len(frames)
            frames.append(frame)
    return frames


def load_mirror_table(source):
    """Load a trusted mirror-port table from a path, JSON/CSV text or object."""
    if source is None:
        return MirrorPortTable()
    if hasattr(os, 'PathLike') and isinstance(source, os.PathLike):
        source = os.fspath(source)
    if isinstance(source, MirrorPortTable):
        return source
    if isinstance(source, (list, tuple, dict)):
        return MirrorPortTable(source)
    if isinstance(source, (bytes, bytearray)):
        source = bytes(source).decode('utf-8')
    if isinstance(source, str):
        if os.path.exists(source):
            return MirrorPortTable.from_file(source)
        text = source.strip()
        if text.startswith('{') or text.startswith('['):
            return MirrorPortTable.from_json(text)
        if ',' in text and ('\n' in text or 'capture' in text.lower() or 'direction' in text.lower()):
            return MirrorPortTable.from_csv(text)
    raise ValueError('cannot load mirror-port table from %r' % (source,))


def load_scope(source):
    if source is None:
        return CaptureScope()
    if hasattr(os, 'PathLike') and isinstance(source, os.PathLike):
        source = os.fspath(source)
    if isinstance(source, CaptureScope):
        return source
    if isinstance(source, (bytes, bytearray)):
        source = bytes(source).decode('utf-8')
    if isinstance(source, str):
        if os.path.exists(source):
            with open(source, 'rb') as handle:
                source = handle.read().decode('utf-8')
        source = json.loads(source)
    return CaptureScope.from_mapping(source)


class DirectionClaim(object):
    """A direction label asserted by the incident report."""

    def __init__(self, frame=None, direction=None, capture_point=None, vlan=None,
                 basis=None, local_index=None, raw=None):
        self.frame = frame
        self.local_index = local_index
        self.direction = direction
        self.normalized_direction = normalize_direction(direction)
        self.capture_point = None if capture_point is None else str(capture_point)
        self.vlan = _as_vlan(vlan)
        self.basis = basis
        self.raw = raw if raw is not None else {}

    @classmethod
    def from_any(cls, item, position=None):
        if isinstance(item, cls):
            return item
        if isinstance(item, dict):
            frame = _first(item, ('frame', 'frame_index', 'index', 'id', 'frame_id',
                                  'packet', 'packet_index'))
            local_index = _first(item, ('local_index', 'local_frame', 'local_frame_index'))
            return cls(
                frame=frame,
                local_index=local_index,
                direction=_first(item, ('direction', 'dir', 'claim', 'label')),
                capture_point=_first(item, ('capture_point', 'capture', 'point')),
                vlan=_first(item, ('vlan', 'claimed_vlan')),
                basis=_first(item, ('basis', 'reason', 'evidence', 'method')),
                raw=item,
            )
        if isinstance(item, (tuple, list)):
            if len(item) >= 2:
                return cls(frame=item[0], direction=item[1],
                           capture_point=item[2] if len(item) > 2 else None)
        if isinstance(item, (int, str)):
            if isinstance(item, str) and ':' in item:
                frame, direction = item.split(':', 1)
                try:
                    frame = int(frame)
                except ValueError:
                    pass
                return cls(frame=frame, direction=direction)
            if position is not None:
                return cls(frame=position, direction=item)
        raise TypeError('unsupported direction claim: %r' % (item,))


def load_claims(source):
    """Load direction claims from a path, JSON/CSV text or Python object."""
    if source is None:
        return []
    if hasattr(os, 'PathLike') and isinstance(source, os.PathLike):
        source = os.fspath(source)
    if isinstance(source, bytes):
        source = source.decode('utf-8')
    if isinstance(source, str):
        if os.path.exists(source):
            with open(source, 'rb') as handle:
                text = handle.read().decode('utf-8')
            if source.lower().endswith('.csv'):
                return _claims_from_csv(text)
            try:
                source = json.loads(text)
            except ValueError:
                return _claims_from_csv(text)
        else:
            text = source.strip()
            if text.startswith('[') or text.startswith('{'):
                source = json.loads(text)
            else:
                return _claims_from_csv(text)
    if isinstance(source, dict):
        if any(key in source for key in ('direction', 'dir', 'claim', 'label')):
            return [DirectionClaim.from_any(source)]
        for key in ('claims', 'frames', 'directions'):
            if key in source:
                return load_claims(source[key])
        claims = []
        for frame, direction in source.items():
            if isinstance(frame, tuple) and len(frame) == 2:
                claims.append(DirectionClaim(frame=frame[1], capture_point=frame[0],
                                             direction=direction, raw=source))
            else:
                claims.append(DirectionClaim(frame=frame, direction=direction, raw=source))
        return claims
    if isinstance(source, (list, tuple)):
        return [DirectionClaim.from_any(item, position=index)
                for index, item in enumerate(source)]
    if isinstance(source, DirectionClaim):
        return [source]
    raise TypeError('unsupported claims input: %r' % (source,))


def _claims_from_csv(text):
    if isinstance(text, bytes):
        text = text.decode('utf-8')
    text = text.lstrip('\ufeff')
    rows = list(csv.DictReader(StringIO(text)))
    if not rows:
        return []
    return [DirectionClaim.from_any(row) for row in rows]


def _union_directions(entries):
    directions = set()
    for entry in entries:
        directions.update(entry.directions)
    return tuple(sorted(directions, key=lambda item: DIRECTION_ORDER[item]))


def _join_ports(entries):
    values = []
    for entry in entries:
        value = entry.mirror_port or entry.device or entry.capture_point
        if value and value not in values:
            values.append(value)
    return ', '.join(values) if values else None


def _ledger_description(entries):
    if not entries:
        return 'no trusted mirror entry'
    parts = []
    for entry in entries:
        port = entry.mirror_port or '-'
        device = entry.device or '-'
        vlan = 'any' if entry.vlan is None else str(entry.vlan)
        direction = entry.normalized_direction or 'unknown'
        parts.append('%s/%s VLAN %s direction=%s' % (device, port, vlan, direction))
    return '; '.join(parts)


def _evidence_description(assessment):
    evidence = assessment.evidence
    outer = 'none' if evidence.outer_vlan is None else str(evidence.outer_vlan)
    return ('capture point %s, src=%s, dst=%s, outer VLAN=%s, captured=%d/%d bytes'
            % (assessment.frame.capture_point, evidence.src_mac or '-',
               evidence.dst_mac or '-', outer, evidence.captured_len,
               evidence.original_len))


class FrameAssessment(object):
    """Direction evidence for one frame, before comparing report claims."""

    def __init__(self, frame, evidence, capture_point, mirror_port,
                 ledger_entries, candidate_directions, possible_directions,
                 status, reasons, in_scope=True, scope_reason=None):
        self.frame = frame
        self.evidence = evidence
        self.capture_point = capture_point
        self.mirror_port = mirror_port
        self.ledger_entries = list(ledger_entries)
        self.candidate_directions = tuple(candidate_directions)
        self.possible_directions = tuple(possible_directions)
        self.status = status
        self.reasons = list(reasons)
        self.in_scope = in_scope
        self.scope_reason = scope_reason

    @property
    def direction(self):
        if len(self.candidate_directions) == 1:
            return self.candidate_directions[0]
        return None

    @property
    def direction_candidates(self):
        return self.candidate_directions

    @property
    def ambiguous(self):
        return len(self.candidate_directions) > 1

    def to_dict(self):
        return {
            'frame': self.frame.to_dict(),
            'capture_point': self.capture_point,
            'mirror_port': self.mirror_port,
            'evidence': self.evidence.to_dict(),
            'src_mac': self.evidence.src_mac,
            'dst_mac': self.evidence.dst_mac,
            'linktype': self.evidence.linktype,
            'outer_vlan': self.evidence.outer_vlan,
            'inner_vlan': self.evidence.inner_vlan,
           'vlan_stack': self.evidence.vlan_stack,
            'outer_tags': [tag.to_dict() for tag in self.evidence.vlan_tags],
            'truncated': self.evidence.truncated,
            'ledger_entries': [entry.to_dict() for entry in self.ledger_entries],
            'directions': list(self.candidate_directions),
            'direction': self.direction,
            'possible_directions': list(self.possible_directions),
            'ambiguous': self.ambiguous,
            'status': self.status,
            'in_scope': self.in_scope,
            'scope_reason': self.scope_reason,
            'reasons': list(self.reasons),
        }


def assess_frame(frame, mirror_table, scope=None):
    """Assess one frame against the trusted mirror ledger and capture scope."""
    table = mirror_table if isinstance(mirror_table, MirrorPortTable) else MirrorPortTable(mirror_table)
    scope = scope if isinstance(scope, CaptureScope) else CaptureScope.from_mapping(scope)
    evidence = parse_link_evidence(
        frame.data,
        linktype=frame.linktype,
        captured_len=frame.captured_len,
        original_len=frame.original_len,
    )
    in_scope, scope_reason = scope.contains(frame, evidence)
    reasons = []
    if scope_reason:
        reasons.append(scope_reason)

    if not evidence.header_complete:
        reasons.insert(0, evidence.truncation_reason or 'L2 header is incomplete')
        return FrameAssessment(
            frame=frame,
            evidence=evidence,
            capture_point=frame.capture_point,
            mirror_port=None,
            ledger_entries=[],
            candidate_directions=(),
            possible_directions=(INBOUND, OUTBOUND),
            status='unverifiable',
            reasons=reasons,
            in_scope=in_scope,
            scope_reason=scope_reason,
        )

    lookup = table.lookup(frame.capture_point, evidence.outer_vlan, evidence.inner_vlan)
    entries = lookup.matches
    mirror_port = _join_ports(entries)
    if scope.mirror_ports and entries:
        ledger_ports = set(entry.mirror_port for entry in entries if entry.mirror_port)
        if ledger_ports and not (ledger_ports & scope.mirror_ports):
            in_scope = False
            scope_reason = ('mirror port(s) %s are outside scope %s'
                            % (sorted(ledger_ports), sorted(scope.mirror_ports)))
            reasons.append(scope_reason)
    candidates = _union_directions(entries)
    possible = candidates or (INBOUND, OUTBOUND)

    if entries:
        if not candidates:
            status = 'unverifiable'
            reasons.append('trusted mirror entries have no usable direction: %s'
                           % _ledger_description(entries))
        elif len(candidates) > 1:
            status = 'ambiguous'
            reasons.append('trusted mirror ledger permits multiple directions: %s'
                           % _ledger_description(entries))
        elif not in_scope:
            status = 'out_of_scope'
        else:
            status = 'verified'
        return FrameAssessment(
            frame=frame,
            evidence=evidence,
            capture_point=frame.capture_point,
            mirror_port=mirror_port,
            ledger_entries=entries,
            candidate_directions=candidates,
            possible_directions=possible,
            status=status,
            reasons=reasons,
            in_scope=in_scope,
            scope_reason=scope_reason,
        )

    if lookup.vlan_mismatches:
        reasons.insert(0, 'frame outer VLAN %s does not match trusted entries at capture point %s: %s'
                       % ('none' if evidence.outer_vlan is None else evidence.outer_vlan,
                          frame.capture_point, _ledger_description(lookup.vlan_mismatches)))
        return FrameAssessment(
            frame=frame,
            evidence=evidence,
            capture_point=frame.capture_point,
            mirror_port=_join_ports(lookup.vlan_mismatches),
            ledger_entries=list(lookup.vlan_mismatches),
            candidate_directions=(),
            possible_directions=_union_directions(lookup.vlan_mismatches) or (INBOUND, OUTBOUND),
            status='vlan_conflict',
            reasons=reasons,
            in_scope=in_scope,
            scope_reason=scope_reason,
        )

    if not in_scope:
        status = 'out_of_scope'
    else:
        status = 'unattributed'
        reasons.append('no trusted mirror entry for capture point %r' % (frame.capture_point,))
    if evidence.direction_hint:
        possible = (evidence.direction_hint,)
        reasons.append('link-local direction hint %s from %s is not trusted without the mirror ledger'
                       % (evidence.direction_hint, evidence.direction_hint_source))
    return FrameAssessment(
        frame=frame,
        evidence=evidence,
        capture_point=frame.capture_point,
        mirror_port=None,
        ledger_entries=list(lookup.point_entries),
        candidate_directions=(),
        possible_directions=possible,
        status=status,
        reasons=reasons,
        in_scope=in_scope,
        scope_reason=scope_reason,
    )


def _basis_is_weak(basis):
    if basis is None:
        return False
    text = str(basis).lower()
    if any(token in text for token in ('mirror', 'span', 'port', 'vlan', 'ledger', 'scope')):
        return False
    return any(token in text for token in _WEAK_BASIS_TOKENS)


class ClaimVerdict(object):
    """The result of checking one incident-report claim against the ledger."""

    def __init__(self, claim, assessment, status, reason, ledger_directions,
                 direct_conflict=False, conflict_kind=None, matched=False,
                 basis_weak=False):
        self.claim = claim
        self.assessment = assessment
        self.status = status
        self.reason = reason
        self.ledger_directions = tuple(ledger_directions)
        self.direct_conflict = bool(direct_conflict)
        self.conflict_kind = conflict_kind
        self.matched = bool(matched)
        self.basis_weak = bool(basis_weak)

    def to_dict(self):
        assessment = self.assessment
        return {
            'frame': assessment.frame.index if assessment is not None else self.claim.frame,
            'capture_point': assessment.capture_point if assessment is not None else self.claim.capture_point,
            'claim': self.claim.direction,
            'normalized_claim': self.claim.normalized_direction,
            'basis': self.claim.basis,
            'claimed_vlan': self.claim.vlan,
            'ledger_directions': list(self.ledger_directions),
            'assessment_status': assessment.status if assessment is not None else None,
            'status': self.status,
            'matched': self.matched,
            'direct_conflict': self.direct_conflict,
            'conflict_kind': self.conflict_kind,
            'basis_weak': self.basis_weak,
            'reason': self.reason,
        }


class DirectionAudit(object):
    """Full offline direction-attribution audit."""

    def __init__(self, frames, mirror_table, scope=None, claims=None):
        self.frames = list(frames)
        self.table = mirror_table if isinstance(mirror_table, MirrorPortTable) else load_mirror_table(mirror_table)
        self.scope = scope if isinstance(scope, CaptureScope) else load_scope(scope)
        if claims is None:
            claim_items = []
        elif isinstance(claims, (list, tuple)) and all(isinstance(item, DirectionClaim) for item in claims):
            claim_items = list(claims)
        else:
            claim_items = load_claims(claims)
        self.claims = claim_items
        self.assessments = [assess_frame(frame, self.table, self.scope) for frame in self.frames]
        self._by_index = dict((assessment.frame.index, assessment) for assessment in self.assessments)
        self._by_point_local = {}
        self._by_point_index = {}
        for assessment in self.assessments:
            frame = assessment.frame
            self._by_point_local[(frame.capture_point, frame.local_index)] = assessment
            self._by_point_index[(frame.capture_point, frame.index)] = assessment
        self.verdicts = self._compare_claims()

    def _resolve_claim(self, claim, position):
        key = claim.frame
        if key is None:
            if claim.local_index is not None:
                key = claim.local_index
            elif position < len(self.assessments):
                return self.assessments[position]
            else:
                return None
        capture_point = claim.capture_point
        if isinstance(key, str):
            if '#' in key:
                point, value = key.rsplit('#', 1)
                capture_point = capture_point or point
                key = value
            elif ':' in key and capture_point is None:
                point, value = key.rsplit(':', 1)
                if point:
                    capture_point = point
                key = value
        try:
            key_int = int(key)
        except (TypeError, ValueError):
            key_int = key
        if capture_point is not None:
            assessment = self._by_point_local.get((capture_point, key_int))
            if assessment is None:
                assessment = self._by_point_index.get((capture_point, key_int))
            if assessment is not None:
                return assessment
        if isinstance(key_int, int):
            return self._by_index.get(key_int)
        return None

    def _compare_claims(self):
        verdicts = []
        for position, claim in enumerate(self.claims):
            assessment = self._resolve_claim(claim, position)
            if assessment is None:
                verdicts.append(ClaimVerdict(
                    claim=claim,
                    assessment=None,
                    status='unknown_frame',
                    reason='claim refers to frame %r, which is not present in the capture'
                           % (claim.frame,),
                    ledger_directions=(),
                    basis_weak=_basis_is_weak(claim.basis),
                ))
                continue
            verdicts.append(self._compare_one(assessment, claim))
        return verdicts

    @staticmethod
    def _compare_one(assessment, claim):
        evidence = assessment.evidence
        basis_weak = _basis_is_weak(claim.basis)
        ledger_dirs = assessment.candidate_directions
        ledger_desc = _ledger_description(assessment.ledger_entries)
        evidence_desc = _evidence_description(assessment)
        frame_id = assessment.frame.index
        claim_dir = claim.normalized_direction
        display_claim = claim.direction

        if claim.capture_point and claim.capture_point != assessment.capture_point:
            return ClaimVerdict(
                claim=claim,
                assessment=assessment,
                status='conflict',
                reason=('frame %d: claim is tied to capture point %r but the frame was captured at %r'
                        % (frame_id, claim.capture_point, assessment.capture_point)),
                ledger_directions=ledger_dirs,
                direct_conflict=True,
                conflict_kind='capture_point',
                basis_weak=basis_weak,
            )

        if claim.vlan is not None and evidence.outer_vlan is not None:
            if claim.vlan != evidence.outer_vlan:
                return ClaimVerdict(
                    claim=claim,
                    assessment=assessment,
                    status='conflict',
                    reason=('frame %d: claim says VLAN %d but frame outer VLAN is %d (%s)'
                            % (frame_id, claim.vlan, evidence.outer_vlan, evidence_desc)),
                    ledger_directions=ledger_dirs,
                    direct_conflict=True,
                    conflict_kind='vlan',
                    basis_weak=basis_weak,
                )

        if assessment.status == 'unverifiable':
            return ClaimVerdict(
                claim=claim,
                assessment=assessment,
                status='unverifiable',
                reason=('frame %d: claim %r is unverifiable, not a direct conflict: %s'
                        % (frame_id, display_claim,
                           evidence.truncation_reason or '; '.join(assessment.reasons))),
                ledger_directions=ledger_dirs,
                basis_weak=basis_weak,
            )

        if assessment.status == 'out_of_scope':
            return ClaimVerdict(
                claim=claim,
                assessment=assessment,
                status='out_of_scope',
                reason=('frame %d: claim %r is outside the accepted capture scope: %s'
                        % (frame_id, display_claim, assessment.scope_reason or 'scope rejected the frame')),
                ledger_directions=ledger_dirs,
                basis_weak=basis_weak,
            )

        if assessment.status == 'vlan_conflict':
            return ClaimVerdict(
                claim=claim,
                assessment=assessment,
                status='conflict',
                reason=('frame %d: claim %r directly conflicts with the mirror ledger; %s (%s)'
                        % (frame_id, display_claim,
                           '; '.join(assessment.reasons), evidence_desc)),
                ledger_directions=assessment.possible_directions,
                direct_conflict=True,
                conflict_kind='vlan',
                basis_weak=basis_weak,
            )

        if assessment.status == 'unattributed':
            return ClaimVerdict(
                claim=claim,
                assessment=assessment,
                status='unattributed',
                reason=('frame %d: claim %r cannot be checked against the ledger because %s'
                        % (frame_id, display_claim, '; '.join(assessment.reasons))),
                ledger_directions=ledger_dirs,
                basis_weak=basis_weak,
            )

        if claim_dir is None:
            return ClaimVerdict(
                claim=claim,
                assessment=assessment,
                status='invalid_claim',
                reason='frame %d: claim %r has no recognizable direction' % (frame_id, display_claim),
                ledger_directions=ledger_dirs,
                basis_weak=basis_weak,
            )

        if claim_dir == BOTH:
            return ClaimVerdict(
                claim=claim,
                assessment=assessment,
                status='ambiguous_claim',
                reason=('frame %d: claim %r does not assert a single direction; ledger permits %s'
                        % (frame_id, display_claim, list(ledger_dirs))),
                ledger_directions=ledger_dirs,
                basis_weak=basis_weak,
            )

        if assessment.status == 'ambiguous':
            if claim_dir in ledger_dirs:
                return ClaimVerdict(
                    claim=claim,
                    assessment=assessment,
                    status='ambiguous',
                    reason=('frame %d: claim %r is one of several directions permitted by the ledger (%s); %s'
                            % (frame_id, display_claim, list(ledger_dirs), ledger_desc)),
                    ledger_directions=ledger_dirs,
                    basis_weak=basis_weak,
                )
            return ClaimVerdict(
                claim=claim,
                assessment=assessment,
                status='conflict',
                reason=('frame %d: claim %r is not among directions permitted by the ledger (%s); %s'
                        % (frame_id, display_claim, list(ledger_dirs), ledger_desc)),
                ledger_directions=ledger_dirs,
                direct_conflict=True,
                conflict_kind='direction',
                basis_weak=basis_weak,
            )

        if assessment.status == 'verified':
            ledger_direction = assessment.candidate_directions[0]
            if claim_dir == ledger_direction:
                status = 'match_weak_basis' if basis_weak else 'match'
                if basis_weak:
                    reason = ('frame %d: claim %r agrees with ledger %r [%s], but basis %r is MAC-only '
                              'and is not direction evidence; the match depends on the mirror ledger'
                              % (frame_id, display_claim, ledger_direction, ledger_desc, claim.basis))
                else:
                    reason = ('frame %d: claim %r agrees with ledger %r [%s]; %s'
                              % (frame_id, display_claim, ledger_direction, ledger_desc, evidence_desc))
                return ClaimVerdict(
                    claim=claim,
                    assessment=assessment,
                    status=status,
                    reason=reason,
                    ledger_directions=ledger_dirs,
                    matched=True,
                    basis_weak=basis_weak,
                )
            return ClaimVerdict(
                claim=claim,
                assessment=assessment,
                status='conflict',
                reason=('frame %d: claim %r directly conflicts with the mirror ledger %r [%s]; %s'
                        % (frame_id, display_claim, ledger_direction, ledger_desc, evidence_desc)),
                ledger_directions=ledger_dirs,
                direct_conflict=True,
                conflict_kind='direction',
                basis_weak=basis_weak,
            )

        return ClaimVerdict(
            claim=claim,
            assessment=assessment,
            status='unverifiable',
            reason='frame %d: claim %r cannot be evaluated (assessment status %r)'
                   % (frame_id, display_claim, assessment.status),
            ledger_directions=ledger_dirs,
            basis_weak=basis_weak,
        )

    @property
    def direct_conflicts(self):
        return [verdict for verdict in self.verdicts if verdict.direct_conflict]

    @property
    def conflicts(self):
        return self.direct_conflicts

    @property
    def unverifiable(self):
        return [verdict for verdict in self.verdicts if verdict.status == 'unverifiable']

    @property
    def ambiguous(self):
        return [verdict for verdict in self.verdicts
                if verdict.status in ('ambiguous', 'ambiguous_claim')]

    @property
    def weak_basis_matches(self):
        return [verdict for verdict in self.verdicts if verdict.status == 'match_weak_basis']

    @property
    def summary(self):
        return {
            'frames': len(self.assessments),
            'claims': len(self.claims),
            'verified_frames': sum(1 for item in self.assessments if item.status == 'verified'),
            'ambiguous_frames': sum(1 for item in self.assessments if item.status == 'ambiguous'),
            'unverifiable_frames': sum(1 for item in self.assessments if item.status == 'unverifiable'),
            'out_of_scope_frames': sum(1 for item in self.assessments if item.status == 'out_of_scope'),
            'direct_conflicts': len(self.direct_conflicts),
            'unverifiable_claims': len(self.unverifiable),
            'ambiguous_claims': len(self.ambiguous),
            'weak_basis_matches': len(self.weak_basis_matches),
        }

    @property
    def conclusion(self):
        conflicts = self.direct_conflicts
        parts = []
        if conflicts:
            parts.append('%d direction claim(s) directly conflict with the trusted mirror ledger.'
                         % len(conflicts))
            for verdict in conflicts:
                assessment = verdict.assessment
                ledger = verdict.ledger_directions
                parts.append('frame #%d (%s): claim %r vs ledger %s. %s'
                             % (assessment.frame.index, assessment.capture_point,
                                verdict.claim.direction, list(ledger) or 'unknown',
                                verdict.reason))
        else:
            parts.append('No direction claim directly conflicts with the trusted mirror ledger.')
        if self.unverifiable:
            parts.append('%d claim(s) are unverifiable; they are not counted as ledger conflicts.'
                         % len(self.unverifiable))
            for verdict in self.unverifiable:
                frame = verdict.assessment.frame.index if verdict.assessment else verdict.claim.frame
                parts.append('frame #%s: %s' % (frame, verdict.reason))
        if self.weak_basis_matches:
            parts.append('%d claim(s) match the ledger but rest on a MAC-only basis; the match is '
                         'supported by the ledger, not by the MAC address.'
                         % len(self.weak_basis_matches))
        return ' '.join(parts)

    @property
    def conclusion_zh(self):
        conflicts = self.direct_conflicts
        parts = []
        if conflicts:
            parts.append('%d 条方向主张与可信镜像台账直接冲突。' % len(conflicts))
            for verdict in conflicts:
                assessment = verdict.assessment
                claim_dir = _zh_direction(verdict.claim.normalized_direction or verdict.claim.direction)
                ledger = '、'.join(_zh_direction(item) for item in verdict.ledger_directions) or '未知'
                parts.append('第 %d 帧（%s）：主张“%s”，台账“%s”。%s'
                             % (assessment.frame.index, assessment.capture_point,
                                 claim_dir, ledger, _zh_reason(verdict)))
        else:
            parts.append('没有方向主张与可信镜像台账直接冲突。')
        if self.unverifiable:
            parts.append('另有 %d 条主张无法验证，不能算作与台账直接冲突。' % len(self.unverifiable))
            for verdict in self.unverifiable:
                frame = verdict.assessment.frame.index if verdict.assessment else verdict.claim.frame
                parts.append('第 %s 帧：%s' % (frame, _zh_reason(verdict)))
        if self.weak_basis_matches:
            parts.append('有 %d 条主张方向与台账一致，但依据只是 MAC 地址；该结论来自镜像台账，'
                         '不能反过来证明按 MAC 判定方向成立。' % len(self.weak_basis_matches))
        return ' '.join(parts)

    def to_dict(self):
        return {
            'tool': 'dpkt.direction',
            'offline_only': True,
            'scope': self.scope.to_dict(),
            'mirror_table': self.table.to_dict(),
            'summary': self.summary,
            'frames': [assessment.to_dict() for assessment in self.assessments],
            'claims': [verdict.to_dict() for verdict in self.verdicts],
            'direct_conflicts': [verdict.to_dict() for verdict in self.direct_conflicts],
            'conclusion': self.conclusion,
            'conclusion_zh': self.conclusion_zh,
        }

    def render(self, lang='en'):
        zh = str(lang).lower().startswith('zh')
        lines = []
        if zh:
            lines.append('帧  采集点       外层VLAN  台账方向      主张      状态          说明')
        else:
            lines.append('idx capture     outer-vlan ledger        claim     status        note')
        lines.append('-' * 104)
        for assessment in self.assessments:
            evidence = assessment.evidence
            claim = None
            status = assessment.status
            note = '; '.join(assessment.reasons)
            for verdict in self.verdicts:
                if verdict.assessment is assessment:
                    claim = verdict.claim.direction
                    status = verdict.status
                    note = verdict.reason
                    break
            ledger = ','.join(assessment.candidate_directions) or '-'
            outer = '-' if evidence.outer_vlan is None else str(evidence.outer_vlan)
            lines.append('%-4d %-11s %-9s %-13s %-9s %-13s %s'
                         % (assessment.frame.index, assessment.capture_point,
                            outer, ledger, claim or '-', status, note))
        lines.append('')
        lines.append(self.conclusion_zh if zh else self.conclusion)
        return '\n'.join(lines)


def audit_frames(frames, mirror_table, scope=None, claims=None):
    """Audit already-read frames (RawFrame objects or frame tuples/dicts)."""
    normalized = []
    for index, item in enumerate(frames):
        if isinstance(item, RawFrame):
            normalized.append(item)
        else:
            normalized.append(_frame_from_item(item, index))
    return DirectionAudit(normalized, mirror_table, scope, claims)


def audit_capture(sources, mirror_table, scope=None, claims=None):
    """Read offline captures and audit them against the mirror ledger."""
    return DirectionAudit(read_captures(sources), mirror_table, scope, claims)


# Common aliases for callers who use different vocabulary.
verify_directions = audit_capture
direction_audit = audit_capture
audit_pcap = audit_capture
verify_capture = audit_capture
attribute_direction = assess_frame
classify_frame = assess_frame
parse_evidence = parse_link_evidence
read_frames = read_captures


def _zh_direction(value):
    if value == INBOUND:
        return '入站'
    if value == OUTBOUND:
        return '出站'
    if value == BOTH:
        return '双向'
    return '未知'

def _zh_reason(verdict):
    assessment = verdict.assessment
    if assessment is None:
        return verdict.reason
    evidence = assessment.evidence
    if verdict.status == "unverifiable":
        if evidence.header_truncated:
            return ("仅捕获 %d/%d 字节，二层头不完整（EtherType 或外层 VLAN 标签缺失），"
                    "无法判定方向。" % (evidence.captured_len, evidence.original_len))
        reason = evidence.truncation_reason or "；".join(assessment.reasons)
        return "证据不足，无法判定方向：%s" % reason
    if verdict.status == "match_weak_basis":
        return ("主张方向与台账一致，但依据只有 MAC 地址（%s）；该结论由镜像台账支撑，"
                "不能作为按 MAC 判定方向的证据。" % (verdict.claim.basis or "MAC"))
    if verdict.status == "ambiguous":
        dirs = "、".join(_zh_direction(item) for item in verdict.ledger_directions)
        return ("台账在采集点 %s 允许多个方向（%s），单一方向主张无法唯一核实。"
                % (assessment.capture_point, dirs))
    if verdict.conflict_kind == "direction":
        ledger_dir = assessment.direction or (verdict.ledger_directions[0] if verdict.ledger_directions else None)
        return ("帧外层 VLAN=%s，采集点 %s 的台账方向为“%s”，主张“%s”与台账相反；"
                "链路证据：%s → %s。"
                % (evidence.outer_vlan if evidence.outer_vlan is not None else "无",
                   assessment.capture_point, _zh_direction(ledger_dir),
                   _zh_direction(verdict.claim.normalized_direction or verdict.claim.direction),
                   evidence.src_mac or "-", evidence.dst_mac or "-"))
    if verdict.conflict_kind == "vlan":
        return ("帧外层 VLAN=%s 与采集点 %s 的台账 VLAN 记录不一致（%s）。"
                % (evidence.outer_vlan if evidence.outer_vlan is not None else "无",
                   assessment.capture_point, "；".join(assessment.reasons)))
    if verdict.conflict_kind == "capture_point":
        return "主张绑定采集点 %s，但帧实际来自 %s。" % (verdict.claim.capture_point, assessment.capture_point)
    if verdict.status == "unattributed":
        return "采集点 %s 没有可信镜像台账记录，方向主张无法核对。" % (assessment.capture_point,)
    if verdict.status == "out_of_scope":
        return "帧不在已接受的捕获范围内：%s。" % (assessment.scope_reason or "范围检查未通过",)
    return verdict.reason


def _mac_bytes(text):
    return bytes(bytearray(int(part, 16) for part in text.split(':')))


def _demo_frame(src_mac, dst_mac, vlan, src_ip, dst_ip, payload=b'direction-demo'):
    ip_packet = ip.IP(
        src=_ip_bytes(src_ip),
        dst=_ip_bytes(dst_ip),
        p=ip.IP_PROTO_UDP,
        ttl=64,
        data=udp.UDP(sport=40000, dport=53, data=payload),
    )
    frame = ethernet.Ethernet(
        dst=_mac_bytes(dst_mac),
        src=_mac_bytes(src_mac),
        vlan_tags=[ethernet.VLANtag8021Q(pri=0, cfi=0, id=vlan)],
        data=ip_packet,
    )
    return bytes(frame)


def _ip_bytes(text):
    return bytes(bytearray(int(part) for part in text.split('.')))


def _align4(value):
    remainder = value % 4
    return value if remainder == 0 else value + 4 - remainder


def _pack_epb(iface_id, ts, data, original_len):
    ts_us = int(round(ts * 1000000))
    ts_high = ts_us >> 32
    ts_low = ts_us & 0xffffffff
    caplen = len(data)
    padded_len = _align4(caplen)
    total_len = 28 + padded_len + 4
    header = struct.pack('<IIIIIII', pcapng.PCAPNG_BT_EPB, total_len, iface_id,
                         ts_high, ts_low, caplen, original_len)
    return header + data + (b'\x00' * (padded_len - caplen)) + struct.pack('<I', total_len)


def _write_demo_pcapng(path, frames):
    with open(path, 'wb') as handle:
        handle.write(bytes(pcapng.SectionHeaderBlockLE()))
        for name in ('SPAN-A', 'SPAN-B'):
            options = [
                pcapng.PcapngOptionLE(code=pcapng.PCAPNG_OPT_IF_NAME,
                                      data=name.encode('ascii')),
                pcapng.PcapngOptionLE(code=pcapng.PCAPNG_OPT_ENDOFOPT, data=b''),
            ]
            idb = pcapng.InterfaceDescriptionBlockLE(
                linktype=pcap.DLT_EN10MB, snaplen=65535, opts=options)
            handle.write(bytes(idb))
        for iface_id, ts, data, original_len in frames:
            handle.write(_pack_epb(iface_id, ts, data, original_len))


def build_demo(workdir=None, write_inputs=True):
    """Build the offline demonstration capture and return the audit.

    The fixture contains two ordinary frames with the *same source MAC* but
    different capture points (SPAN-A, VLAN 100, ingress-only; SPAN-B,
    VLAN 200, egress-only) and one frame at SPAN-A with only a truncated L2
    header.  The report claims all three are outbound on the basis of the MAC
    address.  Only the SPAN-A ordinary frame's claim directly conflicts with
    the ledger; the truncated frame cannot be verified either way.
    """
    workdir = workdir or tempfile.mkdtemp(prefix='dpkt-direction-')
    if not os.path.isdir(workdir):
        os.makedirs(workdir)
    capture_path = os.path.join(workdir, 'mirror-capture.pcapng')
    mirror_path = os.path.join(workdir, 'mirror-ports.json')
    scope_path = os.path.join(workdir, 'capture-scope.json')
    claims_path = os.path.join(workdir, 'direction-claims.json')

    src_mac = '02:00:00:00:00:01'
    dst_mac = '02:00:00:00:00:02'
    base_ts = _parse_time('2026-11-23T00:00:00Z')
    ordinary_a = _demo_frame(src_mac, dst_mac, 100, '192.0.2.10', '192.0.2.20')
    ordinary_b = _demo_frame(src_mac, dst_mac, 200, '192.0.2.10', '198.51.100.20',
                             payload=b'direction-demo-other-capture-point')
    truncated = ordinary_a[:10]

    _write_demo_pcapng(capture_path, [
        (0, base_ts + 1.0, ordinary_a, len(ordinary_a)),
        (1, base_ts + 2.0, ordinary_b, len(ordinary_b)),
        (0, base_ts + 3.0, truncated, len(ordinary_a)),
    ])

    mirror_table = {
        'mirror_ports': [
            {
                'capture_point': 'SPAN-A',
                'mirror_port': 'Gi0/1',
                'device': 'leaf-01',
                'vlan': 100,
                'direction': 'ingress',
                'trusted': True,
            },
            {
                'capture_point': 'SPAN-B',
                'mirror_port': 'Gi0/2',
                'device': 'leaf-02',
                'vlan': 200,
                'direction': 'egress',
                'trusted': True,
            },
        ]
    }
    scope = {
        'capture_points': ['SPAN-A', 'SPAN-B'],
        'vlans': [100, 200],
        'start': '2026-11-23T00:00:00Z',
        'end': '2026-11-24T00:00:00Z',
    }
    claims = [
        {'frame': 0, 'direction': 'outbound', 'capture_point': 'SPAN-A',
         'vlan': 100, 'basis': 'src_mac=' + src_mac},
        {'frame': 1, 'direction': 'outbound', 'capture_point': 'SPAN-B',
         'vlan': 200, 'basis': 'src_mac=' + src_mac},
        {'frame': 2, 'direction': 'outbound', 'capture_point': 'SPAN-A',
         'basis': 'src_mac=' + src_mac},
    ]

    if write_inputs:
        with open(mirror_path, 'w') as handle:
            json.dump(mirror_table, handle, indent=2, sort_keys=True)
        with open(scope_path, 'w') as handle:
            json.dump(scope, handle, indent=2, sort_keys=True)
        with open(claims_path, 'w') as handle:
            json.dump(claims, handle, indent=2, sort_keys=True)

    audit = audit_capture(capture_path, mirror_table, scope, claims)
    return {
        'workdir': workdir,
        'capture': capture_path,
        'pcapng': capture_path,
        'mirror_table': mirror_path if write_inputs else mirror_table,
        'scope': scope_path if write_inputs else scope,
        'claims': claims_path if write_inputs else claims,
        'audit': audit,
    }


def _parse_capture_argument(value):
    if '=' in value:
        point, path = value.split('=', 1)
        return (point or None, path)
    return (None, value)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='python -m dpkt.direction',
        description='Offline direction attribution against a trusted mirror-port ledger.',
    )
    subparsers = parser.add_subparsers(dest='command')

    audit_parser = subparsers.add_parser('audit', help='audit offline captures')
    audit_parser.add_argument('--mirror', required=True,
                              help='trusted mirror-port table (JSON or CSV)')
    audit_parser.add_argument('--scope', help='capture scope (JSON)')
    audit_parser.add_argument('--claims', help='direction claims (JSON or CSV)')
    audit_parser.add_argument('--capture', action='append', default=[],
                              metavar='[POINT=]FILE',
                              help='offline pcap/pcapng file; repeat for multiple capture points')
    audit_parser.add_argument('--json', action='store_true', help='emit JSON')
    audit_parser.add_argument('--output', help='write the JSON report to this path')
    audit_parser.add_argument('--lang', default='en', choices=('en', 'zh'))
    audit_parser.add_argument('--fail-on-conflict', action='store_true',
                              help='exit with status 2 when a claim directly conflicts')

    demo_parser = subparsers.add_parser('demo', help='run the built-in offline demonstration')
    demo_parser.add_argument('--workdir', help='directory for demo captures and JSON inputs')
    demo_parser.add_argument('--json', action='store_true', help='emit JSON')
    demo_parser.add_argument('--lang', default='zh', choices=('en', 'zh'))

    args = parser.parse_args(argv)
    if args.command == 'demo':
        result = build_demo(args.workdir)
        audit = result['audit']
        if args.json:
            payload = audit.to_dict()
            payload['demo_workdir'] = result['workdir']
            print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
        else:
            print('demo capture: %s' % result['capture'])
            print(audit.render(lang=args.lang))
        return 0

    if args.command == 'audit':
        if not args.capture:
            audit_parser.error('at least one --capture is required')
        sources = [_parse_capture_argument(value) for value in args.capture]
        table = load_mirror_table(args.mirror)
        scope = load_scope(args.scope) if args.scope else CaptureScope()
        claims = load_claims(args.claims) if args.claims else []
        audit = audit_capture(sources, table, scope, claims)
        if args.json or args.output:
            payload = json.dumps(audit.to_dict(), indent=2, ensure_ascii=False, sort_keys=True)
            if args.output:
                with open(args.output, 'w') as handle:
                    handle.write(payload + '\n')
            if args.json:
                print(payload)
            else:
                print(audit.render(lang=args.lang))
        else:
            print(audit.render(lang=args.lang))
        if args.fail_on_conflict and audit.direct_conflicts:
            return 2
        return 0

    parser.print_help()
    return 2


# ---------------------------------------------------------------------------
# Unit tests (pytest collects these together with the rest of the package)
# ---------------------------------------------------------------------------

def test_direction_normalize():
    assert normalize_direction('ingress') == INBOUND
    assert normalize_direction('TX') == OUTBOUND
    assert normalize_direction('双向') == BOTH
    assert normalize_direction(['rx', 'tx']) == BOTH
    assert normalize_direction('unknown') is None
    assert normalize_direction('mac:aa:bb:cc:dd:ee:ff') is None


def test_direction_vlan_stack_evidence():
    dst = b'\x02\x00\x00\x00\x00\x02'
    src = b'\x02\x00\x00\x00\x00\x01'
    payload = b'\x45' + b'\x00' * 19
    frame = (dst + src +
             struct.pack('>H', 0x88a8) + struct.pack('>HH', 0x0064, 0x8100) +
             struct.pack('>HH', 0x00c8, 0x0800) + payload)
    evidence = parse_link_evidence(frame)
    assert evidence.header_complete
    assert evidence.src_mac == '02:00:00:00:00:01'
    assert evidence.dst_mac == '02:00:00:00:00:02'
    assert evidence.outer_vlan == 100
    assert evidence.inner_vlan == 200
    assert evidence.vlan_stack == [100, 200]
    assert evidence.ethertype == 0x0800
    assert evidence.vlan_tags[0].to_dict()['outer'] is True


def test_direction_truncated_header_is_unverifiable():
    evidence = parse_link_evidence(b'\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00')
    assert not evidence.header_complete
    assert evidence.header_truncated
    assert evidence.truncated
    assert evidence.outer_vlan is None
    assert 'Ethernet header' in evidence.truncation_reason


def test_direction_same_mac_two_capture_points():
    src_mac = '02:00:00:00:00:01'
    dst_mac = '02:00:00:00:00:02'
    frame_a = _demo_frame(src_mac, dst_mac, 100, '192.0.2.10', '192.0.2.20')
    frame_b = _demo_frame(src_mac, dst_mac, 200, '192.0.2.10', '198.51.100.20')
    truncated = frame_a[:10]
    frames = [
        RawFrame(index=0, local_index=0, data=frame_a, ts=1000.0,
                 capture_point='SPAN-A', original_len=len(frame_a)),
        RawFrame(index=1, local_index=0, data=frame_b, ts=1001.0,
                 capture_point='SPAN-B', original_len=len(frame_b)),
        RawFrame(index=2, local_index=1, data=truncated, ts=1002.0,
                 capture_point='SPAN-A', original_len=len(frame_a)),
    ]
    table = MirrorPortTable([
        {'capture_point': 'SPAN-A', 'mirror_port': 'Gi0/1', 'vlan': 100,
         'direction': 'ingress'},
        {'capture_point': 'SPAN-B', 'mirror_port': 'Gi0/2', 'vlan': 200,
         'direction': 'egress'},
    ])
    scope = CaptureScope(capture_points=['SPAN-A', 'SPAN-B'], vlans=[100, 200])
    claims = [
        {'frame': 0, 'direction': 'outbound', 'basis': 'src_mac'},
        {'frame': 1, 'direction': 'outbound', 'basis': 'src_mac'},
        {'frame': 2, 'direction': 'outbound', 'basis': 'src_mac'},
    ]
    audit = audit_frames(frames, table, scope, claims)
    assert audit.assessments[0].candidate_directions == (INBOUND,)
    assert audit.assessments[1].candidate_directions == (OUTBOUND,)
    assert audit.assessments[1].evidence.src_mac == audit.assessments[0].evidence.src_mac
    assert audit.verdicts[0].status == 'conflict'
    assert audit.verdicts[0].direct_conflict
    assert audit.verdicts[1].status == 'match_weak_basis'
    assert not audit.verdicts[1].direct_conflict
    assert audit.verdicts[2].status == 'unverifiable'
    assert not audit.verdicts[2].direct_conflict
    assert len(audit.direct_conflicts) == 1
    assert 'frame #0' in audit.conclusion


def test_direction_vlan_conflict():
    frame = _demo_frame('02:00:00:00:00:01', '02:00:00:00:00:02',
                        300, '192.0.2.10', '192.0.2.20')
    raw = RawFrame(index=0, data=frame, capture_point='SPAN-A')
    table = MirrorPortTable([
        {'capture_point': 'SPAN-A', 'mirror_port': 'Gi0/1', 'vlan': 100,
         'direction': 'ingress'},
    ])
    audit = audit_frames([raw], table, CaptureScope(vlans=[100, 300]),
                         [{'frame': 0, 'direction': 'inbound'}])
    assert audit.assessments[0].status == 'vlan_conflict'
    assert audit.verdicts[0].status == 'conflict'
    assert audit.verdicts[0].conflict_kind == 'vlan'


def test_direction_demo_pcapng_roundtrip():
    import shutil
    workdir = tempfile.mkdtemp(prefix='dpkt-direction-test-')
    try:
        result = build_demo(workdir)
        audit = result['audit']
        assert len(audit.assessments) == 3
        assert audit.assessments[0].frame.capture_point == 'SPAN-A'
        assert audit.assessments[1].frame.capture_point == 'SPAN-B'
        assert audit.assessments[2].evidence.header_truncated
        assert audit.assessments[2].evidence.original_len > audit.assessments[2].evidence.captured_len
        assert len(audit.direct_conflicts) == 1
        assert audit.direct_conflicts[0].assessment.frame.index == 0
        assert audit.verdicts[1].status == 'match_weak_basis'
        assert audit.verdicts[2].status == 'unverifiable'
        payload = audit.to_dict()
        assert payload['summary']['direct_conflicts'] == 1
        assert payload['summary']['unverifiable_claims'] == 1
        assert payload['offline_only'] is True
    finally:
        shutil.rmtree(workdir)


if __name__ == '__main__':
    sys.exit(main())

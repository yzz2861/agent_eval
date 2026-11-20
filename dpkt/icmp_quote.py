# -*- coding: utf-8 -*-
"""Offline verification of IP datagrams quoted by ICMP errors.

An ICMP/ICMPv6 error message normally contains only the beginning of the
datagram that triggered it.  That embedded copy is *evidence*, not a second
observation of the original packet.  This module separates packets read at the
capture point from the bytes quoted inside an ICMP error and produces a table
which can be queried by result, address, protocol, truncation state, etc.

The public entry point is :func:`verify_icmp_quotes` (also exported as
``correlate_icmp_quotes`` and ``build_evidence_table``).  It accepts an
in-memory pcap/pcapng buffer, a path, or an iterable of ``(timestamp, frame)``
records.
"""
from __future__ import absolute_import, print_function

import argparse
import binascii
import csv
import hashlib
import io
import json
import struct
import sys

from . import pcap
from .utils import inet_to_str

__all__ = [
    'STATUS_COMPLETE', 'STATUS_QUOTE_ONLY', 'STATUS_CONFLICT',
    'MATCHED', 'QUOTE_ONLY', 'CONFLICT', 'AMBIGUOUS',
    'STATUS_MATCHED', 'STATUS_AMBIGUOUS', 'STATUS_ONLY_QUOTE',
    'STATUS_QUOTED_ONLY', 'STATUS_CANDIDATE_CONFLICT',
    'COMPLETE', 'ONLY_QUOTE', 'CANDIDATE_CONFLICT',
    'EvidenceStatus', 'CaptureRecord', 'ObservedPacket', 'QuoteCandidate',
    'QuoteEvidence', 'QuoteEvidenceTable',
    'EvidenceRow', 'EvidenceTable', 'Candidate',
    'verify_icmp_quotes', 'correlate_icmp_quotes', 'build_evidence_table',
    'verify_icmp_quote_references', 'analyze_capture', 'main',
]

# These are the three outcomes required by the evidence workflow.  The aliases
# below are accepted by QuoteEvidenceTable.query() so callers can use either
# the wording used in reports or the wording used by the API.
STATUS_COMPLETE = 'complete'
STATUS_QUOTE_ONLY = 'quote_only'
STATUS_CONFLICT = 'conflict'

MATCHED = STATUS_COMPLETE
QUOTE_ONLY = STATUS_QUOTE_ONLY
CONFLICT = STATUS_CONFLICT
AMBIGUOUS = STATUS_CONFLICT
STATUS_MATCHED = STATUS_COMPLETE
STATUS_AMBIGUOUS = STATUS_CONFLICT
STATUS_ONLY_QUOTE = STATUS_QUOTE_ONLY
STATUS_QUOTED_ONLY = STATUS_QUOTE_ONLY
STATUS_CANDIDATE_CONFLICT = STATUS_CONFLICT
COMPLETE = STATUS_COMPLETE
ONLY_QUOTE = STATUS_QUOTE_ONLY
CANDIDATE_CONFLICT = STATUS_CONFLICT


class EvidenceStatus(object):
    """Names for the supported evidence outcomes."""

    COMPLETE = STATUS_COMPLETE
    QUOTE_ONLY = STATUS_QUOTE_ONLY
    CONFLICT = STATUS_CONFLICT

    MATCHED = STATUS_COMPLETE
    AMBIGUOUS = STATUS_CONFLICT


_STATUS_ALIASES = {
    'complete': STATUS_COMPLETE,
    'completed': STATUS_COMPLETE,
    'match': STATUS_COMPLETE,
    'matched': STATUS_COMPLETE,
    'full': STATUS_COMPLETE,
    'full_match': STATUS_COMPLETE,
    'complete_match': STATUS_COMPLETE,
    'quote_only': STATUS_QUOTE_ONLY,
    'quoted_only': STATUS_QUOTE_ONLY,
    'only_quote': STATUS_QUOTE_ONLY,
    'only_quoted': STATUS_QUOTE_ONLY,
    'reference_only': STATUS_QUOTE_ONLY,
    'missing': STATUS_QUOTE_ONLY,
    'conflict': STATUS_CONFLICT,
    'ambiguous': STATUS_CONFLICT,
    'multiple': STATUS_CONFLICT,
    'candidate_conflict': STATUS_CONFLICT,
    'candidates_conflict': STATUS_CONFLICT,
    'multiple_candidates': STATUS_CONFLICT,
}


def _normalise_status(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple, set, frozenset)):
        return set(_normalise_status(item) for item in value)
    key = str(value).strip().lower().replace('-', '_').replace(' ', '_')
    return _STATUS_ALIASES.get(key, key)


def _u16(buf, offset):
    return (buf[offset] << 8) | buf[offset + 1]


def _u32(buf, offset):
    return ((buf[offset] << 24) | (buf[offset + 1] << 16) |
            (buf[offset + 2] << 8) | buf[offset + 3])


def _addr_to_str(value):
    try:
        return inet_to_str(value)
    except Exception:
        return binascii.hexlify(value).decode('ascii')


def _hexlify(value):
    return binascii.hexlify(value).decode('ascii')


def _is_bytes(value):
    return isinstance(value, (bytes, bytearray, memoryview))


def _as_bytes(value):
    if isinstance(value, memoryview):
        return value.tobytes() if hasattr(value, 'tobytes') else value.tostring()
    if isinstance(value, bytearray):
        return bytes(value)
    if not isinstance(value, bytes) and hasattr(value, '__bytes__'):
        return bytes(value)
    return value


def _normalise_match_bytes(data, version):
    """Mask fields which routers may legitimately rewrite.

    IPv4 TTL and header checksum change at every hop; IPv6 Hop Limit changes
    too.  These fields are not part of the identity of the quoted datagram.
    """
    if version == 4 and len(data) >= 9:
        normalized = data[:8] + b'\x00' + data[9:10]
        normalized += b'\x00' * max(0, min(2, len(data) - 10))
        normalized += data[min(12, len(data)):]
        return normalized
    if version == 6 and len(data) >= 8:
        return data[:7] + b'\x00' + data[8:]
    return data


def _infer_version(data, offset=0):
    if len(data) <= offset:
        return None
    version = data[offset] >> 4
    return version if version in (4, 6) else None


class CaptureRecord(object):
    """One frame read from the capture point.

    ``captured_len`` is the number of bytes actually present in the capture,
    while ``wire_len`` is the original length recorded by the pcap header.
    Keeping both makes snaplen truncation explicit.
    """

    def __init__(self, index, timestamp, data, captured_len=None, wire_len=None):
        self.index = index
        self.timestamp = timestamp
        self.data = _as_bytes(data)
        self.captured_len = len(self.data) if captured_len is None else captured_len
        self.wire_len = len(self.data) if wire_len is None else wire_len

    @property
    def capture_truncated(self):
        return self.captured_len < self.wire_len

    def __repr__(self):
        return 'CaptureRecord(index=%r, captured_len=%r, wire_len=%r)' % (
            self.index, self.captured_len, self.wire_len)


class ObservedPacket(object):
    """A top-level IP packet which was actually present in the capture."""

    def __init__(self, record, linktype, ip_offset, parsed):
        self.record = record
        self.index = record.index
        self.frame_index = record.index
        self.timestamp = record.timestamp
        self.linktype = linktype
        self.ip_offset = ip_offset
        self.data = parsed['raw']
        self.version = parsed['version']
        self.header_len = parsed['header_len']
        self.declared_len = parsed['declared_len']
        self.available_len = parsed['available_len']
        self.src = parsed['src']
        self.dst = parsed['dst']
        self.proto = parsed['proto']
        self.ip_id = parsed['ip_id']
        self.fragment_offset = parsed.get('fragment_offset', 0)
        self.extension_headers = parsed['extension_headers']
        self.transport_offset = parsed['transport_offset']
        self.capture_truncated = record.capture_truncated
        self.packet_truncated = parsed['truncated']

    @property
    def frame(self):
        return self.record.data

    @property
    def truncated(self):
        return self.capture_truncated or self.packet_truncated

    def __repr__(self):
        return 'ObservedPacket(index=%r, version=%r, src=%r, dst=%r, proto=%r)' % (
            self.index, self.version, self.src, self.dst, self.proto)


class QuoteCandidate(object):
    """A top-level captured packet which matches an ICMP quote."""

    def __init__(self, packet, quote_len, matched_bytes, complete=True,
                 note=None, match_mode='exact'):
        self.packet = packet
        self.packet_index = packet.index
        self.frame_index = packet.index
        self.timestamp = packet.timestamp
        self.captured_len = packet.record.captured_len
        self.wire_len = packet.record.wire_len
        self.ip_offset = packet.ip_offset
        self.ip_len = packet.declared_len
        self.available_ip_len = packet.available_len
        self.quote_len = quote_len
        self.matched_bytes = matched_bytes
        self.complete = complete
        self.coverage = (float(matched_bytes) / quote_len) if quote_len else 0.0
        self.capture_truncated = packet.truncated
        self.note = note
        self.match_mode = match_mode

    @property
    def packet_truncated(self):
        return self.packet.truncated

    def as_dict(self):
        return {
            'packet_index': self.packet_index,
            'frame_index': self.frame_index,
            'timestamp': self.timestamp,
            'captured_len': self.captured_len,
            'wire_len': self.wire_len,
            'ip_offset': self.ip_offset,
            'ip_len': self.ip_len,
            'available_ip_len': self.available_ip_len,
            'quote_len': self.quote_len,
            'matched_bytes': self.matched_bytes,
            'coverage': self.coverage,
            'complete': self.complete,
            'capture_truncated': self.capture_truncated,
            'match_mode': self.match_mode,
            'note': self.note,
        }

    def __getitem__(self, name):
        return getattr(self, name)

    def __repr__(self):
        return ('QuoteCandidate(frame_index=%r, matched_bytes=%r/%r, '
                'complete=%r, match_mode=%r)' % (
                    self.frame_index, self.matched_bytes, self.quote_len,
                    self.complete, self.match_mode))


class QuoteEvidence(object):
    """One ICMP/ICMPv6 quote and its relation to captured packets."""

    def __init__(self, record, outer, icmp_offset, quote_offset, quote_bytes,
                 quote_info, candidates, partial_candidates, status, notes):
        self.record = record
        self.frame_index = record.index
        self.timestamp = record.timestamp
        self.outer = outer
        self.icmp_offset = icmp_offset
        self.quote_offset = quote_offset
        self.quote_bytes = quote_bytes
        self.quote_info = quote_info
        self.candidates = tuple(candidates)
        self.partial_candidates = tuple(partial_candidates)
        self.status = status
        self.notes = tuple(notes)

    @property
    def icmp_type(self):
        return self.outer.get('icmp_type')

    @property
    def icmp_code(self):
        return self.outer.get('icmp_code')

    @property
    def icmp_family(self):
        return 'ipv4' if self.outer.get('version') == 4 else 'ipv6'

    @property
    def icmp_src(self):
        return self.outer.get('src')

    @property
    def icmp_dst(self):
        return self.outer.get('dst')

    @property
    def ip_version(self):
        return self.quote_info.get('version')

    @property
    def family(self):
        version = self.ip_version
        if version == 4:
            return 'ipv4'
        if version == 6:
            return 'ipv6'
        return None

    @property
    def src(self):
        return self.quote_info.get('src')

    @property
    def dst(self):
        return self.quote_info.get('dst')

    @property
    def proto(self):
        return self.quote_info.get('proto')

    @property
    def ip_id(self):
        return self.quote_info.get('ip_id')

    @property
    def ip_header_len(self):
        return self.quote_info.get('header_len')

    @property
    def quote_len(self):
        """Actual number of quoted bytes, never the embedded length field."""
        return len(self.quote_bytes)

    @property
    def quoted_packet_len(self):
        """Original datagram length claimed by the embedded IP header."""
        return self.quote_info.get('declared_len')

    @property
    def quote_missing_bytes(self):
        declared = self.quoted_packet_len
        if declared is None:
            return None
        return max(0, declared - self.quote_len)

    @property
    def quote_complete(self):
        declared = self.quoted_packet_len
        return bool(declared is not None and self.quote_len >= declared)

    @property
    def quote_truncated(self):
        declared = self.quoted_packet_len
        return bool(declared is not None and self.quote_len < declared)

    @property
    def header_truncated(self):
        return bool(self.quote_info.get('header_truncated'))

    @property
    def extension_headers(self):
        return tuple(self.quote_info.get('extension_headers') or ())

    @property
    def extension_header_types(self):
        return tuple(header.get('type') for header in self.extension_headers
                     if header.get('type') is not None)

    @property
    def has_extension_headers(self):
        return bool(self.extension_headers)

    @property
    def extension_headers_truncated(self):
        return bool(self.quote_info.get('extension_headers_truncated'))

    @property
    def ip_options_len(self):
        return self.quote_info.get('ip_options_len') or 0

    @property
    def fragmented(self):
        return bool(self.quote_info.get('fragmented'))

    @property
    def fragment_offset(self):
        return self.quote_info.get('fragment_offset') or 0

    @property
    def transport_offset(self):
        return self.quote_info.get('transport_offset')

    @property
    def transport_header_len(self):
        return self.quote_info.get('transport_header_len')

    @property
    def transport_complete(self):
        return bool(self.quote_info.get('transport_complete'))

    @property
    def l4_src_port(self):
        return self.quote_info.get('l4_src_port')

    @property
    def l4_dst_port(self):
        return self.quote_info.get('l4_dst_port')

    @property
    def l4_seq(self):
        return self.quote_info.get('l4_seq')

    @property
    def parse_error(self):
        return self.quote_info.get('parse_error')

    @property
    def candidate_count(self):
        return len(self.candidates)

    @property
    def candidate_indices(self):
        return tuple(candidate.frame_index for candidate in self.candidates)

    @property
    def partial_candidate_indices(self):
        return tuple(candidate.frame_index for candidate in self.partial_candidates)

    @property
    def match_bytes(self):
        if self.candidates:
            return self.quote_len
        if self.partial_candidates:
            return max(candidate.matched_bytes
                       for candidate in self.partial_candidates)
        return 0

    @property
    def match_mode(self):
        modes = set(candidate.match_mode
                    for candidate in self.candidates + self.partial_candidates)
        if not modes:
            return None
        if len(modes) == 1:
            return modes.pop()
        return 'mixed'

    @property
    def exact_match(self):
        return bool(self.candidates) and all(
            candidate.match_mode == 'exact' for candidate in self.candidates)

    @property
    def normalized_candidates(self):
        return tuple(candidate for candidate in self.candidates
                     if candidate.match_mode == 'normalized')

    @property
    def normalized_candidate_indices(self):
        return tuple(candidate.frame_index
                     for candidate in self.normalized_candidates)

    @property
    def quote_length(self):
        return self.quote_len

    @property
    def quoted_bytes(self):
        return self.quote_bytes

    @property
    def candidate_packet_indices(self):
        return self.candidate_indices

    @property
    def candidate_frame_indices(self):
        return self.candidate_indices

    @property
    def partial_frame_indices(self):
        return self.partial_candidate_indices

    @property
    def capture_truncated(self):
        values = [candidate.capture_truncated for candidate in self.candidates]
        values.extend(candidate.capture_truncated for candidate in self.partial_candidates)
        return any(values)

    @property
    def icmp_truncated(self):
        return bool(self.outer.get('truncated'))

    @property
    def truncated(self):
        return bool(self.quote_truncated or self.header_truncated or
                    self.extension_headers_truncated or
                    self.icmp_truncated or self.partial_candidates or
                    self.capture_truncated)

    @property
    def quote_hex(self):
        return _hexlify(self.quote_bytes)

    @property
    def quote_sha256(self):
        return hashlib.sha256(self.quote_bytes).hexdigest()

    @property
    def is_complete(self):
        return self.status == STATUS_COMPLETE

    @property
    def complete(self):
        return self.is_complete

    @property
    def is_quote_only(self):
        return self.status == STATUS_QUOTE_ONLY

    @property
    def quote_only(self):
        return self.is_quote_only

    @property
    def is_conflict(self):
        return self.status == STATUS_CONFLICT

    @property
    def conflict(self):
        return self.is_conflict

    @property
    def matched(self):
        return self.is_complete

    @property
    def ambiguous(self):
        return self.is_conflict

    def to_dict(self, include_quote=False):
        result = {
            'frame_index': self.frame_index,
            'timestamp': self.timestamp,
            'status': self.status,
            'icmp_family': self.icmp_family,
            'icmp_type': self.icmp_type,
            'icmp_code': self.icmp_code,
            'icmp_src': self.icmp_src,
            'icmp_dst': self.icmp_dst,
            'icmp_offset': self.icmp_offset,
            'icmp_truncated': self.icmp_truncated,
            'quote_offset': self.quote_offset,
            'quote_len': self.quote_len,
            'quoted_packet_len': self.quoted_packet_len,
            'quote_complete': self.quote_complete,
            'quote_truncated': self.quote_truncated,
            'quote_missing_bytes': self.quote_missing_bytes,
            'quote_sha256': self.quote_sha256,
            'ip_version': self.ip_version,
            'family': self.family,
            'ip_header_len': self.ip_header_len,
            'ip_options_len': self.ip_options_len,
            'src': self.src,
            'dst': self.dst,
            'proto': self.proto,
            'ip_id': self.ip_id,
            'fragmented': self.fragmented,
            'fragment_offset': self.fragment_offset,
            'match_mode': self.match_mode,
            'exact_match': self.exact_match,
            'normalized_candidate_indices': list(
                self.normalized_candidate_indices),
            'transport_offset': self.transport_offset,
            'transport_header_len': self.transport_header_len,
            'transport_complete': self.transport_complete,
            'l4_src_port': self.l4_src_port,
            'l4_dst_port': self.l4_dst_port,
            'l4_seq': self.l4_seq,
            'header_truncated': self.header_truncated,
            'extension_headers': [dict(header) for header in self.extension_headers],
            'extension_header_types': list(self.extension_header_types),
            'extension_headers_truncated': self.extension_headers_truncated,
            'candidate_count': self.candidate_count,
            'candidate_indices': list(self.candidate_indices),
            'candidates': [candidate.as_dict() for candidate in self.candidates],
            'partial_candidate_indices': list(self.partial_candidate_indices),
            'partial_candidates': [candidate.as_dict()
                                   for candidate in self.partial_candidates],
            'capture_truncated': self.capture_truncated,
            'parse_error': self.parse_error,
            'notes': list(self.notes),
        }
        if include_quote:
            result['quote_hex'] = self.quote_hex
        else:
            result['quote_preview_hex'] = _hexlify(self.quote_bytes[:32])
        return result

    def __getitem__(self, name):
        return getattr(self, name)

    def __repr__(self):
        return ('QuoteEvidence(frame_index=%r, status=%r, quote_len=%r, '
                'candidate_indices=%r)' % (
                    self.frame_index, self.status, self.quote_len,
                    self.candidate_indices))


_CSV_FIELDS = (
    'frame_index', 'timestamp', 'status', 'icmp_family', 'icmp_type',
    'icmp_code', 'icmp_src', 'icmp_dst', 'icmp_offset', 'icmp_truncated',
    'ip_version',
    'quote_offset',
    'quote_len', 'quoted_packet_len', 'quote_complete', 'quote_truncated',
    'quote_missing_bytes', 'header_truncated', 'extension_header_types',
    'extension_headers_truncated', 'ip_options_len', 'src', 'dst', 'proto',
    'ip_id', 'fragment_offset', 'match_mode', 'exact_match',
    'l4_src_port', 'l4_dst_port', 'l4_seq', 'candidate_count',
    'candidate_indices', 'partial_candidate_indices', 'capture_truncated',
    'notes',
)


class QuoteEvidenceTable(object):
    """Queryable collection of :class:`QuoteEvidence` rows."""

    def __init__(self, rows, frames=None, observed_packets=None, linktype=None):
        self._rows = tuple(rows)
        self.frames = tuple(frames or ())
        self.observed_packets = tuple(observed_packets or ())
        self.linktype = linktype
        self.source = None

    @property
    def rows(self):
        return list(self._rows)

    @property
    def quote_count(self):
        return len(self._rows)

    @property
    def capture_frame_count(self):
        return len(self.frames)

    @property
    def candidate_indices(self):
        result = []
        seen = set()
        for row in self._rows:
            for index in row.candidate_indices:
                if index not in seen:
                    seen.add(index)
                    result.append(index)
        return tuple(result)

    @property
    def candidate_count(self):
        return len(self.candidate_indices)

    def __iter__(self):
        return iter(self._rows)

    def __len__(self):
        return len(self._rows)

    def __bool__(self):
        return bool(self._rows)

    __nonzero__ = __bool__

    def __eq__(self, other):
        if isinstance(other, (list, tuple)):
            return self._rows == tuple(other)
        if not isinstance(other, QuoteEvidenceTable):
            return NotImplemented
        return self._rows == other._rows

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __getitem__(self, key):
        if isinstance(key, str):
            return self.query(status=key)
        return self._rows[key]

    def __call__(self, status=None, **filters):
        return self.query(status=status, **filters)

    def query(self, status=None, **filters):
        """Return rows matching ``status`` and the supplied field filters.

        ``status`` accepts ``complete``/``matched``, ``quote_only`` and
        ``conflict``/``ambiguous`` (plus the constants exported by this
        module).  Boolean filters such as ``truncated``,
        ``quote_truncated``, ``has_extension_headers`` and
        ``capture_truncated`` are supported directly.  Unknown keyword names
        are compared with the row attribute of the same name.
        """
        rows = list(self._rows)
        wanted_status = _normalise_status(status)
        if wanted_status is not None:
            if isinstance(wanted_status, set):
                rows = [row for row in rows if row.status in wanted_status]
            else:
                rows = [row for row in rows if row.status == wanted_status]

        where = filters.pop('where', None)
        for name, value in filters.items():
            if name in ('family', 'ip_family'):
                rows = [row for row in rows if _family_matches(row, value)]
            elif name in ('ip_version', 'version'):
                versions = _version_filter(value)
                rows = [row for row in rows if row.ip_version in versions]
            elif name == 'quote_len':
                rows = [row for row in rows if row.quote_len == value]
            elif name == 'min_quote_len':
                rows = [row for row in rows if row.quote_len >= value]
            elif name == 'max_quote_len':
                rows = [row for row in rows if row.quote_len <= value]
            elif name == 'candidate_count':
                rows = [row for row in rows if row.candidate_count == value]
            elif name == 'min_candidate_count':
                rows = [row for row in rows if row.candidate_count >= value]
            elif name == 'max_candidate_count':
                rows = [row for row in rows if row.candidate_count <= value]
            elif name in ('extension_header_type', 'extension_type'):
                rows = [row for row in rows
                        if value in row.extension_header_types]
            elif name == 'has_extension_headers':
                rows = [row for row in rows
                        if row.has_extension_headers == bool(value)]
            elif name == 'candidate_index':
                rows = [row for row in rows
                        if value in row.candidate_indices]
            elif name == 'match_mode':
                rows = [row for row in rows if row.match_mode == value]
            elif name == 'exact_match':
                rows = [row for row in rows if row.exact_match == bool(value)]
            elif name == 'frame_index':
                rows = [row for row in rows if row.frame_index == value]
            elif name == 'icmp_type':
                rows = [row for row in rows if row.icmp_type == value]
            elif name == 'icmp_code':
                rows = [row for row in rows if row.icmp_code == value]
            elif name in ('src', 'dst', 'proto', 'ip_id'):
                rows = [row for row in rows if getattr(row, name) == value]
            elif name == 'notes_contains':
                rows = [row for row in rows
                        if any(value in note for note in row.notes)]
            else:
                def matches(row):
                    try:
                        actual = getattr(row, name)
                    except AttributeError:
                        return False
                    if isinstance(value, (list, tuple, set, frozenset)):
                        return actual in value
                    return actual == value
                rows = [row for row in rows if matches(row)]

        if where is not None:
            rows = [row for row in rows if where(row)]
        result = QuoteEvidenceTable(rows, self.frames, self.observed_packets,
                                    self.linktype)
        result.source = getattr(self, 'source', None)
        return result

    filter = query

    def by_status(self, status=None):
        """Group rows by status, or return the rows for one status."""
        groups = {
            STATUS_COMPLETE: [],
            STATUS_QUOTE_ONLY: [],
            STATUS_CONFLICT: [],
        }
        for row in self._rows:
            groups.setdefault(row.status, []).append(row)
        if status is not None:
            wanted = _normalise_status(status)
            if not isinstance(wanted, set):
                return list(groups.get(wanted, []))
            result = []
            for key, value in groups.items():
                if key in wanted:
                    result.extend(value)
            return result
        return dict((key, list(value)) for key, value in groups.items())

    groups = by_status

    def status_counts(self):
        counts = {}
        for row in self._rows:
            counts[row.status] = counts.get(row.status, 0) + 1
        return counts

    @property
    def complete(self):
        return self.query(status=STATUS_COMPLETE)

    @property
    def matched(self):
        return self.complete

    @property
    def quote_only(self):
        return self.query(status=STATUS_QUOTE_ONLY)

    @property
    def conflicts(self):
        return self.query(status=STATUS_CONFLICT)

    conflict = conflicts

    @property
    def ambiguous(self):
        return self.conflicts

    def to_dicts(self, include_quote=False):
        return [row.to_dict(include_quote=include_quote) for row in self._rows]

    as_dicts = to_dicts

    def to_json(self, indent=2, include_quote=False):
        return json.dumps(self.to_dicts(include_quote=include_quote),
                          indent=indent, sort_keys=True)

    def to_csv(self):
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=_CSV_FIELDS,
                                extrasaction='ignore')
        writer.writeheader()
        for row in self._rows:
            writer.writerow(_flatten_row(row))
        return output.getvalue()

    def format_table(self):
        if not self._rows:
            return 'No ICMP/ICMPv6 quoted datagrams found.'
        header = ('FRAME', 'STATUS', 'FAMILY', 'TYPE/CODE', 'QUOTE',
                  'ORIGINAL', 'CANDIDATES', 'PATH', 'FLAGS')
        lines = ['%-7s %-10s %-7s %-10s %-13s %-10s %-10s %-28s %s' % header]
        for row in self._rows:
            quote = '%d/%d' % (row.quote_len,
                               row.quoted_packet_len
                               if row.quoted_packet_len is not None else -1)
            path = '%s -> %s' % (row.src or '?', row.dst or '?')
            flags = _row_flags(row)
            lines.append('%-7d %-10s %-7s %-10s %-13s %-10d %-10d %-28s %s' % (
                row.frame_index, row.status, row.family or '?',
                '%s/%s' % (row.icmp_type, row.icmp_code), quote,
                row.quoted_packet_len or 0, row.candidate_count, path,
                ','.join(flags) or '-'))
        return '\n'.join(lines)

    def __str__(self):
        return self.format_table()

    def __repr__(self):
        return 'QuoteEvidenceTable(rows=%r, statuses=%r)' % (
            len(self._rows), self.status_counts())


EvidenceRow = QuoteEvidence
EvidenceTable = QuoteEvidenceTable
Candidate = QuoteCandidate


def _row_flags(row):
    flags = []
    if row.icmp_truncated:
        flags.append('icmp-trunc')
    if row.header_truncated:
        flags.append('header-trunc')
    if row.extension_headers_truncated:
        flags.append('ext-trunc')
    if row.quote_truncated:
        flags.append('quote-trunc')
    if row.partial_candidates:
        flags.append('candidate-trunc')
    if row.candidates and not row.exact_match:
        flags.append('normalized')
    if row.candidate_count > 1:
        flags.append('multi-candidate')
    return flags


def _family_matches(row, value):
    if value is None:
        return True
    key = str(value).strip().lower()
    if key in ('4', 'ip4', 'ipv4', 'v4'):
        return row.ip_version == 4
    if key in ('6', 'ip6', 'ipv6', 'v6'):
        return row.ip_version == 6
    return row.family == key


def _version_filter(value):
    if isinstance(value, (list, tuple, set, frozenset)):
        versions = set()
        for item in value:
            versions.update(_version_filter(item))
        return versions
    key = str(value).strip().lower()
    if key in ('4', 'ip4', 'ipv4', 'v4'):
        return set([4])
    if key in ('6', 'ip6', 'ipv6', 'v6'):
        return set([6])
    try:
        return set([int(value)])
    except (TypeError, ValueError):
        return set()


def _flatten_row(row):
    result = {}
    for field in _CSV_FIELDS:
        value = getattr(row, field, None)
        if isinstance(value, tuple):
            value = '|'.join(str(item) for item in value)
        elif isinstance(value, list):
            value = '|'.join(str(item) for item in value)
        result[field] = value
    return result


def _read_source(source):
    """Return ``(data, name)`` for a path, bytes buffer or file object."""
    if _is_bytes(source):
        return _as_bytes(source), None

    if isinstance(source, str):
        with open(source, 'rb') as capture:
            return capture.read(), source

    if hasattr(source, '__fspath__'):
        path = source.__fspath__()
        with open(path, 'rb') as capture:
            return capture.read(), path

    if hasattr(source, 'read'):
        if hasattr(source, 'seek'):
            try:
                source.seek(0)
            except (IOError, OSError):
                pass
        data = source.read()
        return _as_bytes(data), getattr(source, 'name', None)

    return None, None


def _record_from_item(index, item):
    if isinstance(item, CaptureRecord):
        if item.index != index:
            item = CaptureRecord(index, item.timestamp, item.data,
                                 item.captured_len, item.wire_len)
        return item
    if _is_bytes(item):
        return CaptureRecord(index, None, item)
    if hasattr(item, '__bytes__'):
        return CaptureRecord(index, None, item)
    if isinstance(item, (tuple, list)):
        if len(item) == 2:
            return CaptureRecord(index, item[0], item[1])
        if len(item) >= 4:
            return CaptureRecord(index, item[0], item[1], item[2], item[3])
        if len(item) == 3:
            return CaptureRecord(index, item[0], item[1], wire_len=item[2])
    raise TypeError('unsupported capture item at index %d: %r' % (index, item))


def _iter_records(source):
    if isinstance(source, CaptureRecord):
        return [_record_from_item(0, source)], None, None

    data, name = _read_source(source)
    if data is not None:
        if data[:4] == b'\x0a\x0d\x0d\x0a':
            records, network = _iter_pcapng(data)
            return records, network, name
        records, network = _iter_pcap(data)
        return records, network, name

    records = [_record_from_item(index, item)
               for index, item in enumerate(source)]
    return records, None, name


_PCAP_ENDIAN = {
    b'\xd4\xc3\xb2\xa1': ('<', 1000000),
    b'\xa1\xb2\xc3\xd4': ('>', 1000000),
    b'\x4d\x3c\xb2\xa1': ('<', 1000000000),
    b'\xa1\xb2\x3c\x4d': ('>', 1000000000),
    b'\x34\xcd\xb2\xa1': ('<', 1000000),
    b'\xa1\xb2\xcd\x34': ('>', 1000000),
}


def _iter_pcap(data):
    if len(data) < 24:
        raise ValueError('short pcap global header')
    magic = data[:4]
    try:
        endian, divisor = _PCAP_ENDIAN[magic]
    except KeyError:
        raise ValueError('unknown pcap magic: %r' % magic)
    global_header = struct.unpack(endian + 'IHHIIII', data[:24])
    network = global_header[6]
    records = []
    offset = 24
    index = 0
    while offset + 16 <= len(data):
        ts_sec, ts_frac, caplen, wire_len = struct.unpack(
            endian + 'IIII', data[offset:offset + 16])
        offset += 16
        packet_data = data[offset:offset + caplen]
        offset += caplen
        records.append(CaptureRecord(
            index, ts_sec + (float(ts_frac) / divisor), packet_data,
            captured_len=len(packet_data), wire_len=wire_len))
        index += 1
    return records, network


def _iter_pcapng(data):
    from . import pcapng
    reader = pcapng.Reader(io.BytesIO(data))
    network = reader.datalink()
    records = []
    for index, (timestamp, packet_data) in enumerate(reader):
        records.append(CaptureRecord(index, timestamp, packet_data))
    return records, network


def _ethernet_payload(data):
    """Return ``(offset, ethertype)`` or ``(None, None)``."""
    if len(data) < 14:
        return None, None
    offset = 12
    ethertype = _u16(data, offset)
    offset += 2
    vlan_types = (0x8100, 0x88a8, 0x9100, 0x9200)
    while ethertype in vlan_types:
        if offset + 4 > len(data):
            return None, None
        ethertype = _u16(data, offset + 2)
        offset += 4
    if ethertype in (0x8847, 0x8848):
        while offset + 4 <= len(data):
            label = _u32(data, offset)
            offset += 4
            if label & 0x100:
                break
        version = _infer_version(data, offset)
        return (offset, 0x0800 if version == 4 else
                (0x86DD if version == 6 else None))
    if ethertype == 0x8864:  # PPPoE session
        offset += 6
        if offset + 2 <= len(data):
            offset += 2
            version = _infer_version(data, offset)
            return (offset, 0x0800 if version == 4 else
                    (0x86DD if version == 6 else None))
    if ethertype == 0x6558:  # transparent Ethernet bridging
        nested_offset, nested_type = _ethernet_payload(data[offset:])
        if nested_offset is None:
            return None, None
        return offset + nested_offset, nested_type
    return offset, ethertype


def _find_ip_offset(data, linktype=None):
    """Locate the top-level IP header in a captured frame."""
    if linktype in (pcap.DLT_RAW, pcap.DLT_IPV4, pcap.DLT_IPV6):
        return 0 if _infer_version(data, 0) else None
    if linktype in (pcap.DLT_NULL, pcap.DLT_LOOP):
        return 4 if len(data) > 4 and _infer_version(data, 4) else None
    if linktype == pcap.DLT_LINUX_SLL:
        return 16 if len(data) > 16 and _infer_version(data, 16) else None
    if linktype == pcap.DLT_LINUX_SLL2:
        return 20 if len(data) > 20 and _infer_version(data, 20) else None
    if linktype == pcap.DLT_EN10MB:
        offset, ethertype = _ethernet_payload(data)
        if (offset is not None and ethertype in (0x0800, 0x86DD) and
                _infer_version(data, offset) in (4, 6)):
            return offset
        return None

    if linktype is not None:
        offset = pcap.dltoff.get(linktype, 0)
        if _infer_version(data, offset):
            return offset

    # For an iterable of raw in-memory frames there may be no linktype.
    if _infer_version(data, 0):
        return 0
    offset, ethertype = _ethernet_payload(data)
    if offset is not None and ethertype in (0x0800, 0x86DD):
        if _infer_version(data, offset):
            return offset
    for offset in (4, 16, 20):
        if len(data) > offset and _infer_version(data, offset):
            return offset
    return None


def _parse_transport(raw, proto, offset, fragmented):
    result = {
        'transport_offset': offset,
        'transport_header_len': None,
        'transport_complete': False,
        'l4_src_port': None,
        'l4_dst_port': None,
        'l4_seq': None,
    }
    available = len(raw) - offset
    if offset < 0 or available <= 0 or fragmented:
        return result
    transport = raw[offset:]
    if proto == 6:  # TCP
        if available >= 4:
            result['l4_src_port'] = _u16(transport, 0)
            result['l4_dst_port'] = _u16(transport, 2)
        if available >= 8:
            result['l4_seq'] = _u32(transport, 4)
        if available >= 13:
            header_len = ((transport[12] >> 4) & 0x0f) * 4
            if header_len >= 20:
                result['transport_header_len'] = header_len
                result['transport_complete'] = available >= header_len
    elif proto == 17:  # UDP
        result['transport_header_len'] = 8
        if available >= 4:
            result['l4_src_port'] = _u16(transport, 0)
            result['l4_dst_port'] = _u16(transport, 2)
        result['transport_complete'] = available >= 8
    elif proto == 132:  # SCTP
        result['transport_header_len'] = 12
        if available >= 4:
            result['l4_src_port'] = _u16(transport, 0)
            result['l4_dst_port'] = _u16(transport, 2)
        result['transport_complete'] = available >= 12
    elif proto in (1, 58):  # ICMP / ICMPv6, useful for nested evidence
        if available >= 2:
            result['icmp_type'] = transport[0]
            result['icmp_code'] = transport[1]
        result['transport_header_len'] = 4 if proto == 1 else 4
        result['transport_complete'] = available >= 8
    return result


def _base_parse(version):
    return {
        'version': version,
        'raw': b'',
        'header_len': None,
        'declared_len': None,
        'available_len': 0,
        'src': None,
        'dst': None,
        'proto': None,
        'ip_id': None,
        'fragment_offset': 0,
        'fragmented': False,
        'header_truncated': False,
        'truncated': False,
        'extension_headers': [],
        'extension_headers_truncated': False,
        'ip_options_len': 0,
        'transport_offset': None,
        'transport_header_len': None,
        'transport_complete': False,
        'l4_src_port': None,
        'l4_dst_port': None,
        'l4_seq': None,
        'icmp_type': None,
        'icmp_code': None,
        'parse_error': None,
    }


def _parse_ipv4(raw):
    result = _base_parse(4)
    result['available_len'] = len(raw)
    if len(raw) < 20:
        result['header_truncated'] = True
        result['truncated'] = True
        result['parse_error'] = 'truncated IPv4 header'
        result['raw'] = raw
        return result

    ihl = (raw[0] & 0x0f) * 4
    total_len = _u16(raw, 2)
    declared = total_len if total_len >= ihl else len(raw)
    effective = raw[:declared] if declared < len(raw) else raw
    result.update({
        'raw': effective,
        'available_len': len(effective),
        'header_len': ihl,
        'declared_len': declared,
        'truncated': len(raw) < declared,
        'ip_id': _u16(raw, 4),
        'proto': raw[9],
        'src': _addr_to_str(raw[12:16]),
        'dst': _addr_to_str(raw[16:20]),
    })
    flags_offset = _u16(raw, 6)
    result['fragment_offset'] = flags_offset & 0x1fff
    result['fragmented'] = bool((flags_offset & 0x2000) or
                                result['fragment_offset'])
    if ihl < 20 or len(raw) < ihl:
        if ihl > 20:
            result['ip_options_len'] = ihl - 20
            result['extension_headers'].append({
                'kind': 'ipv4_options',
                'type': None,
                'name': 'IPv4 options',
                'offset': 20,
                'length': ihl - 20,
                'available': max(0, len(raw) - 20),
                'complete': False,
                'next': raw[9],
            })
            result['extension_headers_truncated'] = True
        result['header_truncated'] = True
        result['parse_error'] = 'invalid or truncated IPv4 header length'
        result['transport_offset'] = ihl if ihl >= 20 else None
        return result
    if ihl > 20:
        result['ip_options_len'] = ihl - 20
        result['extension_headers'].append({
            'kind': 'ipv4_options',
            'type': None,
            'name': 'IPv4 options',
            'offset': 20,
            'length': ihl - 20,
            'complete': True,
            'next': raw[9],
        })
    result.update(_parse_transport(
        effective, raw[9], ihl,
        bool(flags_offset & 0x1fff)))
    return result


_IPV6_EXT_NAMES = {
    0: 'Hop-by-Hop Options',
    43: 'Routing',
    44: 'Fragment',
    50: 'ESP',
    51: 'Authentication',
    60: 'Destination Options',
    135: 'Mobility',
    139: 'HIP',
    140: 'Shim6',
}


def _ipv6_ext_length(next_header, raw, offset):
    if next_header == 44:
        return 8
    if next_header == 51:
        return (raw[offset + 1] + 2) * 4
    if next_header in (0, 43, 60, 135, 139, 140):
        return (raw[offset + 1] + 1) * 8
    return None


def _parse_ipv6(raw):
    result = _base_parse(6)
    result['available_len'] = len(raw)
    if len(raw) < 40:
        result['header_truncated'] = True
        result['truncated'] = True
        result['parse_error'] = 'truncated IPv6 header'
        result['raw'] = raw
        return result

    payload_len = _u16(raw, 4)
    declared = 40 + payload_len if payload_len else len(raw)
    effective = raw[:declared] if declared < len(raw) else raw
    result.update({
        'raw': effective,
        'available_len': len(effective),
        'header_len': 40,
        'declared_len': declared,
        'truncated': len(raw) < declared,
        'proto': raw[6],
        'src': _addr_to_str(raw[8:24]),
        'dst': _addr_to_str(raw[24:40]),
    })

    next_header = raw[6]
    fragment_offset = 0
    offset = 40
    while next_header in _IPV6_EXT_NAMES:
        name = _IPV6_EXT_NAMES[next_header]
        if next_header == 50:  # ESP payload is opaque
            result['extension_headers'].append({
                'kind': 'ipv6',
                'type': next_header,
                'name': name,
                'offset': offset,
                'length': max(0, len(effective) - offset),
                'complete': len(effective) >= offset,
                'next': None,
            })
            result['proto'] = next_header
            result['transport_offset'] = offset
            return result
        if offset + 2 > len(effective):
            result['extension_headers'].append({
                'kind': 'ipv6',
                'type': next_header,
                'name': name,
                'offset': offset,
                'length': max(0, len(effective) - offset),
                'complete': False,
                'next': None,
            })
            result['extension_headers_truncated'] = True
            result['proto'] = next_header
            result['transport_offset'] = offset
            return result

        ext_len = _ipv6_ext_length(next_header, effective, offset)
        if ext_len is None:
            break
        complete = offset + ext_len <= len(effective)
        following = effective[offset] if offset < len(effective) else None
        result['extension_headers'].append({
            'kind': 'ipv6',
            'type': next_header,
            'name': name,
            'offset': offset,
            'length': ext_len,
            'complete': complete,
            'next': following,
        })
        if next_header == 44 and complete:
            fragment_offset = (_u16(effective, offset + 2) >> 3) & 0x1fff
            result['fragment_offset'] = fragment_offset
            if fragment_offset:
                result['fragmented'] = True
            result['ip_id'] = _u32(effective, offset + 4)
        if not complete:
            result['extension_headers_truncated'] = True
            result['proto'] = following
            result['transport_offset'] = offset
            return result
        offset += ext_len
        next_header = following

    result['proto'] = next_header
    result.update(_parse_transport(
        effective, next_header, offset, result['fragmented']))
    return result


def _parse_ip(raw):
    if len(raw) < 1:
        result = _base_parse(None)
        result['parse_error'] = 'empty IP buffer'
        return result
    version = raw[0] >> 4
    if version == 4:
        return _parse_ipv4(raw)
    if version == 6:
        return _parse_ipv6(raw)
    result = _base_parse(version)
    result['raw'] = raw
    result['available_len'] = len(raw)
    result['parse_error'] = 'unsupported IP version %r' % version
    return result


def _icmp_error_types(version):
    if version == 4:
        return frozenset([3, 4, 5, 11, 12])
    if version == 6:
        return frozenset([1, 2, 3, 4])
    return frozenset()


def _build_observed(record, linktype):
    ip_offset = _find_ip_offset(record.data, linktype)
    if ip_offset is None:
        return None
    parsed = _parse_ip(record.data[ip_offset:])
    if parsed['version'] not in (4, 6):
        return None
    return ObservedPacket(record, linktype, ip_offset, parsed)


def _quote_from_icmp(record, observed):
    if observed.proto not in (1, 58) or observed.fragment_offset:
        return None
    outer = {
        'version': observed.version,
        'src': observed.src,
        'dst': observed.dst,
        'proto': observed.proto,
        'icmp_type': None,
        'icmp_code': None,
        'truncated': observed.truncated,
    }
    transport_offset = observed.transport_offset
    if transport_offset is None or observed.available_len < transport_offset + 4:
        return None
    ip_bytes = observed.data
    icmp = ip_bytes[transport_offset:]
    icmp_type = icmp[0]
    icmp_code = icmp[1]
    outer['icmp_type'] = icmp_type
    outer['icmp_code'] = icmp_code
    if icmp_type not in _icmp_error_types(observed.version):
        return None
    if len(icmp) < 8:
        quote = b""
        quote_info = _base_parse(None)
        quote_info["parse_error"] = "ICMP error is truncated before the quoted datagram"
        quote_info["header_truncated"] = True
        frame_quote_offset = observed.ip_offset + transport_offset + 8
        return outer, transport_offset, frame_quote_offset, quote, quote_info

    quote_offset_in_ip = transport_offset + 8
    quote = ip_bytes[quote_offset_in_ip:]
    frame_quote_offset = observed.ip_offset + quote_offset_in_ip
    quote_info = _parse_ip(quote) if quote else _base_parse(None)
    if not quote:
        quote_info['parse_error'] = 'ICMP error has no quoted bytes'
    return outer, transport_offset, frame_quote_offset, quote, quote_info


def _dedupe_candidates(candidates):
    result = []
    seen = set()
    for candidate in candidates:
        if candidate.frame_index in seen:
            continue
        seen.add(candidate.frame_index)
        result.append(candidate)
    return result


def _find_candidates(quote, observed_packets, source_index):
    full = []
    partial = []
    exact_full = []
    exact_partial = []
    normal_full = []
    normal_partial = []
    quote_len = len(quote)
    if not quote_len:
        return full, partial
    version = quote[0] >> 4
    normal_quote = _normalise_match_bytes(quote, version)
    for packet in observed_packets:
        if packet.index == source_index:
            continue
        candidate = packet.data
        compared = min(quote_len, len(candidate))
        if not compared:
            continue
        if candidate[:compared] == quote[:compared]:
            target = exact_full if compared == quote_len else exact_partial
            target.append(QuoteCandidate(
                packet, quote_len, compared, compared == quote_len,
                None if compared == quote_len else
                'captured packet ends after %d of %d quoted bytes' % (
                    compared, quote_len), 'exact'))
            continue
        normal_candidate = _normalise_match_bytes(candidate, version)
        if normal_candidate[:compared] == normal_quote[:compared]:
            target = normal_full if compared == quote_len else normal_partial
            target.append(QuoteCandidate(
                packet, quote_len, compared, compared == quote_len,
                None if compared == quote_len else
                'captured packet ends after %d of %d quoted bytes' % (
                    compared, quote_len), 'normalized'))
    if exact_full:
        full = exact_full
        partial = exact_partial
    elif normal_full:
        full = normal_full
        partial = _dedupe_candidates(exact_partial + normal_partial)
    else:
        partial = _dedupe_candidates(exact_partial + normal_partial)
    return full, partial


def _evidence_rows(records, linktype):
    observed_packets = []
    for record in records:
        observed = _build_observed(record, linktype)
        if observed is not None:
            observed_packets.append(observed)

    rows = []
    for observed in observed_packets:
        extracted = _quote_from_icmp(observed.record, observed)
        if extracted is None:
            continue
        outer, icmp_offset, quote_offset, quote, quote_info = extracted
        candidates, partial = _find_candidates(
            quote, observed_packets, observed.index)

        notes = []
        if outer.get('truncated'):
            notes.append('ICMP error frame was truncated at the capture point')
        if quote_info.get('header_truncated'):
            notes.append('quoted IP header is truncated')
        if quote_info.get('extension_headers_truncated'):
            notes.append('quoted IPv6 extension header is truncated')
        if quote_info.get('parse_error'):
            notes.append(quote_info['parse_error'])
        if partial:
            notes.append('possible original packet(s) truncated before quote end: %s' %
                         ', '.join(str(item.frame_index) for item in partial))
        if len(candidates) > 1:
            notes.append('multiple captured packets match the same quote')
        if any(candidate.match_mode != 'exact' for candidate in candidates):
            notes.append('matched after masking mutable TTL/hop-limit and '
                         'IPv4 header checksum fields')
        if any(candidate.capture_truncated
               for candidate in candidates + partial):
            notes.append('one or more candidate observations were truncated '
                         'at the capture point')
        if not candidates:
            if partial:
                notes.append('no complete captured original; only truncated '
                             'candidate(s) matched the quote')
            else:
                notes.append('quoted datagram was not observed at the '
                             'capture point')

        if len(candidates) > 1:
            status = STATUS_CONFLICT
        elif len(candidates) == 1:
            status = STATUS_COMPLETE
        else:
            status = STATUS_QUOTE_ONLY

        rows.append(QuoteEvidence(
            observed.record, outer, observed.ip_offset + icmp_offset,
            quote_offset, quote,
            quote_info, candidates, partial, status, notes))
    return rows, observed_packets


def verify_icmp_quotes(source, linktype=None):
    """Correlate ICMP/ICMPv6 quotes with top-level captured packets.

    Args:
        source: In-memory pcap/pcapng bytes, a file path, a binary file-like
            object, or an iterable of ``(timestamp, frame)`` items.
        linktype: Optional pcap link type for an iterable of raw frames.

    Returns:
        QuoteEvidenceTable: Rows can be split with
        ``table.query(status='complete')``, ``status='quote_only'`` and
        ``status='conflict'``.
    """
    records, network, name = _iter_records(source)
    if linktype is None:
        linktype = network
    records = list(records)
    rows, observed = _evidence_rows(records, linktype)
    table = QuoteEvidenceTable(rows, frames=records,
                               observed_packets=observed, linktype=linktype)
    if name:
        table.source = name
    else:
        table.source = None
    return table


correlate_icmp_quotes = verify_icmp_quotes
build_evidence_table = verify_icmp_quotes
verify_icmp_quote_references = verify_icmp_quotes
analyze_capture = verify_icmp_quotes


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Verify ICMP/ICMPv6 quoted datagrams against a capture.')
    parser.add_argument('capture', help='pcap/pcapng file, or - for stdin')
    parser.add_argument('--status', action='append',
                        choices=sorted(_STATUS_ALIASES.keys()),
                        help='only show rows with this status (repeatable)')
    parser.add_argument('--family', choices=('ipv4', 'ipv6'),
                        help='only show quoted IPv4 or IPv6 datagrams')
    parser.add_argument('--quote-truncated', action='store_true',
                        help='only show quotes shorter than the quoted datagram')
    parser.add_argument('--extension-headers', action='store_true',
                        help='only show quotes with extension headers')
    parser.add_argument('--format', choices=('table', 'json', 'csv'),
                        default='table')
    parser.add_argument('--include-quote', action='store_true',
                        help='include full quoted bytes in JSON output')
    args = parser.parse_args(argv)

    if args.capture == '-':
        source = getattr(sys.stdin, 'buffer', sys.stdin).read()
    else:
        source = args.capture
    table = verify_icmp_quotes(source)
    filters = {}
    if args.status:
        wanted = set(_normalise_status(value) for value in args.status)
        table = table.query(status=wanted)
    if args.family:
        filters['family'] = args.family
    if args.quote_truncated:
        filters['quote_truncated'] = True
    if args.extension_headers:
        filters['has_extension_headers'] = True
    if filters:
        table = table.query(**filters)

    if args.format == 'json':
        print(table.to_json(include_quote=args.include_quote))
    elif args.format == 'csv':
        print(table.to_csv(), end='')
    else:
        print(table.format_table())
    return 0


if __name__ == '__main__':
    sys.exit(main())

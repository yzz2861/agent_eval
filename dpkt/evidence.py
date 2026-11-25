# -*- coding: utf-8 -*-
"""Offline, read-only evidence projection for selected packet headers.

The projector answers a narrow question: which allow-listed link-layer and
IPv4-header fields may leave the internal network, where are those exact
bytes in the saved capture, and what commitments bind the disclosed value
to that source range?

It never rewrites a capture and never opens a network socket.  A projection
contains no raw frame bytes.  Link addresses are represented by keyed
HMAC-SHA256 pseudonyms, while fields that are safe to disclose verbatim are
represented as ordinary integers or hex strings.  A verifier can either
check the projection's internal commitments alone or re-project the original
capture and compare the result.

The public API is:

    project(source, fields=None, records=None, salt=None) -> dict
    verify(projection, source=None) -> VerificationResult
    is_valid(projection, source=None) -> bool

``source`` may be a path, a binary file object, or raw (possibly gzip
compressed) pcap bytes.  ``records`` selects zero-based record indexes and
may be a list/iterable or a string such as ``"0,2-4"``.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse
import binascii
import gzip
import hashlib
import hmac
import io
import json
import os
import struct
import sys

from . import dpkt
from . import ethernet
from . import ip as ip_module
from . import pcap


SCHEMA = 'dpkt.evidence.projection/1'

# Only these fields may be emitted.  Names are deliberately layer-qualified
# so that a policy is unambiguous and cannot accidentally disclose payload.
DEFAULT_FIELDS = (
    'eth.dst',
    'eth.src',
    'eth.type',
    'vlan.pri',
    'vlan.cfi',
    'vlan.id',
    'vlan.type',
    'ip.v',
    'ip.hl',
    'ip.tos',
    'ip.len',
    'ip.id',
    'ip.rf',
    'ip.df',
    'ip.mf',
    'ip.offset',
    'ip.ttl',
    'ip.p',
    'ip.sum',
    'ip.src',
    'ip.dst',
    'ip.opts',
)

# Address fields must never use the verbatim representation.
SENSITIVE_FIELDS = frozenset((
    'eth.dst',
    'eth.src',
    'ip.src',
    'ip.dst',
))

_ADDRESS_FAMILY = {
    'eth.dst': 'mac',
    'eth.src': 'mac',
    'ip.src': 'ipv4',
    'ip.dst': 'ipv4',
}

_FIELD_ALIASES = {
    'eth.ethertype': 'eth.type',
    'eth.dst_mac': 'eth.dst',
    'eth.src_mac': 'eth.src',
    'eth.destination': 'eth.dst',
    'eth.source': 'eth.src',
    'vlan.priority': 'vlan.pri',
    'vlan.pcp': 'vlan.pri',
    'vlan.dei': 'vlan.cfi',
    'vlan.vid': 'vlan.id',
    'vlan.ethertype': 'vlan.type',
    'ip.version': 'ip.v',
    'ip.ihl': 'ip.hl',
    'ip.header_length': 'ip.hl',
    'ip.protocol': 'ip.p',
    'ip.proto': 'ip.p',
    'ip.checksum': 'ip.sum',
    'ip.frag_offset': 'ip.offset',
    'ip.fragment_offset': 'ip.offset',
    'ip.frag_off': 'ip.offset',
    'ip.options': 'ip.opts',
}

_LAYER_OF = {}
for _name in DEFAULT_FIELDS:
    _LAYER_OF[_name] = _name.split('.', 1)[0]
_LAYER_OF['vlan.pri'] = 'vlan'
_LAYER_OF['vlan.cfi'] = 'vlan'
_LAYER_OF['vlan.id'] = 'vlan'

_ETH_TYPE_IP = 0x0800
_ETH_TYPE_8021Q = 0x8100
_VLAN_ETHERTYPES = frozenset((
    ethernet.ETH_TYPE_8021Q,
    ethernet.ETH_TYPE_8021AD,
    ethernet.ETH_TYPE_QINQ1,
    ethernet.ETH_TYPE_QINQ2,
))

# libpcap's LINKTYPE_RAW (101) and the BSD DLT_RAW value (12) both mean
# that the saved frame starts at the IPv4 header.  LINKTYPE_IPV4 (228) is
# the explicit IPv4 variant.
_RAW_LINKTYPES = frozenset((12, 101, 228))


class EvidenceError(ValueError):
    """Raised when a capture or projection cannot be processed safely."""


class EvidenceVerificationError(EvidenceError):
    """Raised by ``verify(..., raise_on_error=True)``."""


class VerificationResult(dict):
    """Dictionary result whose truth value follows its ``ok`` member."""

    @property
    def ok(self):
        return bool(dict.get(self, 'ok'))

    @property
    def errors(self):
        return dict.get(self, 'errors') or []

    @property
    def checked(self):
        return dict.get(self, 'checked') or {}

    def __bool__(self):
        return self.ok

    __nonzero__ = __bool__


def _packet_layout(packet_class):
    """Derive byte/bit locations from a dpkt class's declared header layout."""
    fields = {}
    cursor = 0
    bit_fields = getattr(packet_class, '__bit_fields__', {})

    for name, fmt, _default in packet_class.__hdr__:
        size = struct.calcsize('>' + fmt)
        subfields = bit_fields.get(name)
        if subfields:
            total_bits = size * 8
            bit_cursor = 0
            for sub_name, sub_bits in subfields:
                if sub_name.startswith('_'):
                    bit_cursor += sub_bits
                    continue
                first_byte = bit_cursor // 8
                last_byte = (bit_cursor + sub_bits - 1) // 8
                fields[sub_name] = {
                    'offset': cursor + first_byte,
                    'length': last_byte - first_byte + 1,
                    'bit_offset': bit_cursor - (first_byte * 8),
                    'bit_length': sub_bits,
                    'kind': 'uint',
                }
                bit_cursor += sub_bits
            assert bit_cursor == total_bits
        else:
            fields[name] = {
                'offset': cursor,
                'length': size,
                'bit_offset': 0,
                'bit_length': size * 8,
                'kind': 'bytes' if fmt.endswith('s') else 'uint',
            }
        cursor += size

    return fields


_LAYOUTS = {
    'eth': _packet_layout(ethernet.Ethernet),
    'vlan': _packet_layout(ethernet.VLANtag8021Q),
    'ip': _packet_layout(ip_module.IP),
}

# IP options are variable-length and live after the fixed IPv4 header.
_LAYOUTS['ip']['opts'] = {
    'offset': ip_module.IP.__hdr_len__,
    'length': None,
    'bit_offset': 0,
    'bit_length': None,
    'kind': 'bytes',
}

_FIXED_LAYOUT = {}
for _layer, _layout in _LAYOUTS.items():
    for _field_name, _info in _layout.items():
        _FIXED_LAYOUT['%s.%s' % (_layer, _field_name)] = _info

_SUPPORTED_FIELDS = frozenset(_FIXED_LAYOUT)


def _canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(',', ':'), ensure_ascii=True
    ).encode('utf-8')


def _hash(value):
    return 'sha256:' + hashlib.sha256(_canonical_json(value)).hexdigest()


def _entry_commitment(entry):
    body = dict((k, v) for k, v in entry.items() if k != 'commitment')
    return _hash(body)


def _manifest_commitment(projection):
    body = dict((k, v) for k, v in projection.items() if k != 'commitment')
    return _hash(body)


def _normalize_field(name):
    if not isinstance(name, str):
        raise EvidenceError('field name must be a string: %r' % (name,))
    canonical = name.strip().lower()
    canonical = _FIELD_ALIASES.get(canonical, canonical)
    if canonical not in _SUPPORTED_FIELDS:
        raise EvidenceError('field is not in the disclosure allow-list: %s' % name)
    return canonical


def _normalize_fields(fields):
    if fields is None:
        return list(DEFAULT_FIELDS)
    if isinstance(fields, str):
        fields = [part for part in fields.split(',') if part.strip()]
    normalized = []
    seen = set()
    for name in fields:
        canonical = _normalize_field(name)
        if canonical not in seen:
            normalized.append(canonical)
            seen.add(canonical)
    return normalized


def _parse_record_token(token):
    token = token.strip()
    if not token:
        return []
    if '-' in token:
        first, last = token.split('-', 1)
        first = int(first)
        last = int(last)
        if last < first:
            raise EvidenceError('invalid descending record range: %s' % token)
        return list(range(first, last + 1))
    return [int(token)]


def _normalize_records(records, count):
    if records is None:
        return list(range(count))
    if isinstance(records, int):
        records = [records]
    elif isinstance(records, str):
        tokens = []
        for part in records.split(','):
            tokens.extend(_parse_record_token(part))
        records = tokens

    selected = []
    seen = set()
    for index in records:
        if not isinstance(index, int):
            raise EvidenceError('record index must be an integer: %r' % (index,))
        if index < 0 or index >= count:
            raise EvidenceError(
                'record index %d is outside the capture (0..%d)' % (index, count - 1)
            )
        if index not in seen:
            selected.append(index)
            seen.add(index)
    return selected


def _normalize_salt(salt):
    if salt is None:
        return os.urandom(16)
    if isinstance(salt, str):
        try:
            return binascii.unhexlify(salt)
        except (TypeError, binascii.Error):
            raise EvidenceError('salt must be hexadecimal')
    if isinstance(salt, (bytes, bytearray)):
        return bytes(salt)
    raise EvidenceError('salt must be bytes or a hexadecimal string')


def _read_source(source):
    """Return ``(pcap_bytes, basename_or_None, compressed)``."""
    name = None
    if isinstance(source, (bytes, bytearray, memoryview)):
        blob = bytes(source)
    else:
        close_after = False
        if isinstance(source, str) or hasattr(source, '__fspath__'):
            path = os.fspath(source)
            name = os.path.basename(path)
            fileobj = open(path, 'rb')
            close_after = True
        elif hasattr(source, 'read'):
            fileobj = source
            name = os.path.basename(getattr(source, 'name', '') or '') or None
            try:
                fileobj.seek(0)
            except (AttributeError, IOError, OSError):
                pass
        else:
            raise EvidenceError('source must be a path, file object, or bytes')
        try:
            blob = fileobj.read()
        finally:
            if close_after:
                fileobj.close()

    if not isinstance(blob, (bytes, bytearray)):
        raise EvidenceError('capture source must be opened in binary mode')

    compressed = bytes(blob[:2]) == b'\x1f\x8b'
    if compressed:
        try:
            decompress = gzip.decompress
        except AttributeError:  # Python 2 compatibility
            with gzip.GzipFile(fileobj=io.BytesIO(bytes(blob)), mode='rb') as stream:
                blob = stream.read()
        else:
            try:
                blob = decompress(bytes(blob))
            except (IOError, OSError, EOFError) as exc:
                raise EvidenceError('cannot decompress gzip capture: %s' % exc)
    return bytes(blob), name, compressed


# magic bytes -> (struct byte order, timestamp divisor, record header length)
_PCAP_MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1000000, 16),
    b'\xa1\xb2\xc3\xd4': ('>', 1000000, 16),
    b'\x4d\x3c\xb2\xa1': ('<', 1000000000, 16),
    b'\xa1\xb2\x3c\x4d': ('>', 1000000000, 16),
    b'\x34\xcd\xb2\xa1': ('<', 1000000, 24),
    b'\xa1\xb2\xcd\x34': ('>', 1000000, 24),
}


def _validate_pcap_with_dpkt(blob):
    """Use dpkt's pcap reader to validate the container and its link type."""
    try:
        reader = pcap.Reader(io.BytesIO(blob))
    except Exception as exc:
        raise EvidenceError('dpkt rejected the pcap container: %s' % exc)
    return reader.datalink(), reader.snaplen


def _parse_pcap(blob):
    if len(blob) < 24:
        raise EvidenceError('truncated pcap global header')

    info = _PCAP_MAGICS.get(blob[:4])
    if info is None:
        raise EvidenceError('unsupported capture format (expected pcap)')
    endian, divisor, record_header_len = info

    _v_major, _v_minor, _thiszone, _sigfigs, snaplen, linktype = struct.unpack_from(
        endian + 'HHiIII', blob, 4
    )
    if _v_major != 2:
        raise EvidenceError('unsupported pcap version %d.%d' % (_v_major, _v_minor))

    dpkt_linktype, dpkt_snaplen = _validate_pcap_with_dpkt(blob)
    if dpkt_linktype != linktype:
        raise EvidenceError(
            'inconsistent link type (manual=%d, dpkt=%d)'
            % (linktype, dpkt_linktype)
        )

    records = []
    pos = 24
    index = 0
    while pos + record_header_len <= len(blob):
        record_header_offset = pos
        tv_sec, tv_usec, caplen, original_length = struct.unpack_from(
            endian + 'IIII', blob, pos
        )
        packet_offset = pos + record_header_len
        frame = blob[packet_offset:packet_offset + caplen]
        captured_length = len(frame)
        records.append({
            'index': index,
            'timestamp': tv_sec + (tv_usec / divisor),
            'record_header_offset': record_header_offset,
            'packet_offset': packet_offset,
            'declared_captured_length': caplen,
            'captured_length': captured_length,
            'original_length': original_length,
            'linktype': linktype,
            'frame': frame,
        })
        index += 1
        pos = packet_offset + caplen
        if pos > len(blob):
            break

    return {
        'snaplen': snaplen or dpkt_snaplen,
        'linktype': linktype,
        'records': records,
    }


def _decode_context(frame, linktype):
    """Locate the IPv4 header without guessing across unknown encapsulation."""
    context = {
        'link_layer': 'unknown',
        'link_truncated': False,
        'vlan_present': False,
        'ip_offset': None,
        'ip_reason': 'unknown_encapsulation',
        'ip_version': None,
    }
    captured = len(frame)

    if linktype == pcap.DLT_EN10MB:
        context['link_layer'] = 'ethernet'
        if captured < ethernet.Ethernet.__hdr_len__:
            context['link_truncated'] = True
            context['ip_reason'] = 'truncated'
            return context

        ethertype = struct.unpack_from('>H', frame, 12)[0]
        if ethertype in _VLAN_ETHERTYPES:
            context['vlan_present'] = True
            if captured < ethernet.Ethernet.__hdr_len__ + ethernet.VLANtag8021Q.__hdr_len__:
                context['ip_reason'] = 'truncated'
                return context
            inner_type = struct.unpack_from('>H', frame, 16)[0]
            if inner_type == _ETH_TYPE_8021Q:
                context['ip_reason'] = 'unsupported_vlan_stack'
            elif inner_type == _ETH_TYPE_IP:
                context['ip_offset'] = (
                    ethernet.Ethernet.__hdr_len__
                    + ethernet.VLANtag8021Q.__hdr_len__
                )
            else:
                context['ip_reason'] = 'unknown_encapsulation'
        elif ethertype == _ETH_TYPE_IP:
            context['ip_offset'] = ethernet.Ethernet.__hdr_len__
        else:
            context['ip_reason'] = 'unknown_encapsulation'

    elif linktype in _RAW_LINKTYPES:
        context['link_layer'] = 'raw'
        context['ip_offset'] = 0
    else:
        context['link_layer'] = 'unsupported'
        context['ip_reason'] = 'unsupported_linktype'

    return context


def _unlocated(name, reason):
    entry = {
        'name': name,
        'layer': _LAYER_OF[name],
        'status': 'unlocated',
        'reason': reason,
        'source': None,
        'representation': None,
    }
    entry['commitment'] = _entry_commitment(entry)
    return entry


def _bytes_to_int(value):
    if not value:
        return 0
    return int(binascii.hexlify(value), 16)


def _extract_value(frame, offset, length, bit_offset, bit_length, kind):
    chunk = frame[offset:offset + length]
    if kind == 'bytes':
        return chunk
    value = _bytes_to_int(chunk)
    shift = (length * 8) - bit_offset - bit_length
    if shift:
        value >>= shift
    if bit_length != length * 8:
        value &= (1 << bit_length) - 1
    return value


def _representation(name, raw_value, salt):
    if name in SENSITIVE_FIELDS:
        family = _ADDRESS_FAMILY[name]
        mac = hmac.new(salt, digestmod=hashlib.sha256)
        mac.update(b'address\x00')
        mac.update(family.encode('ascii'))
        mac.update(b'\x00')
        mac.update(raw_value)
        return {
            'kind': 'redacted',
            'algorithm': 'hmac-sha256',
            'family': family,
            'length': len(raw_value),
            'value': 'hmac-sha256:' + mac.hexdigest(),
        }

    if isinstance(raw_value, bytes):
        return {
            'kind': 'verbatim',
            'encoding': 'hex',
            'value': binascii.hexlify(raw_value).decode('ascii'),
        }
    return {
        'kind': 'verbatim',
        'encoding': 'uint',
        'value': raw_value,
    }


def _source_commitment(name, raw_value, salt):
    mac = hmac.new(salt, digestmod=hashlib.sha256)
    mac.update(b'source\x00')
    mac.update(name.encode('ascii'))
    mac.update(b'\x00')
    if isinstance(raw_value, bytes):
        encoded = raw_value
    else:
        encoded = ('uint:%d' % raw_value).encode('ascii')
    mac.update(encoded)
    return 'hmac-sha256:' + mac.hexdigest()


def _evaluate_field(name, record, context, salt):
    frame = record['frame']
    captured = record['captured_length']
    layer, local_name = name.split('.', 1)

    if layer == 'eth':
        info = _FIXED_LAYOUT[name]
        if context['link_layer'] == 'raw':
            return _unlocated(name, 'link_layer_absent')
        if context['link_layer'] == 'unsupported':
            return _unlocated(name, 'unsupported_linktype')
        offset = info['offset']
        length = info['length']
        if offset + length > captured:
            return _unlocated(name, 'truncated')

    elif layer == 'vlan':
        info = _FIXED_LAYOUT[name]
        if context['link_layer'] == 'raw':
            return _unlocated(name, 'link_layer_absent')
        if context['link_layer'] == 'unsupported':
            return _unlocated(name, 'unsupported_linktype')
        if not context['vlan_present']:
            if context.get('link_truncated'):
                return _unlocated(name, 'truncated')
            return _unlocated(name, 'not_present')
        offset = ethernet.Ethernet.__hdr_len__ + info['offset']
        length = info['length']
        if offset + length > captured:
            return _unlocated(name, 'truncated')

    else:
        ip_offset = context['ip_offset']
        if ip_offset is None:
            return _unlocated(name, context['ip_reason'])

        if local_name == 'opts':
            if ip_offset >= captured:
                return _unlocated(name, 'truncated')
            ihl = frame[ip_offset] & 0x0f
            if ihl < 5:
                return _unlocated(name, 'invalid_ip_header_length')
            offset = ip_offset + ip_module.IP.__hdr_len__
            length = (ihl - 5) * 4
            if offset + length > captured:
                return _unlocated(name, 'truncated')
            info = _LAYOUTS['ip']['opts']
        else:
            info = _FIXED_LAYOUT[name]
            if ip_offset >= captured:
                return _unlocated(name, 'truncated')
            version = frame[ip_offset] >> 4
            if version != 4 and local_name not in ('v', 'hl'):
                return _unlocated(name, 'unsupported_ip_version')
            offset = ip_offset + info['offset']
            length = info['length']
            if offset + length > captured:
                return _unlocated(name, 'truncated')

    raw_value = _extract_value(
        frame,
        offset,
        length,
        info['bit_offset'],
        info['bit_length'] if info['bit_length'] is not None else length * 8,
        info['kind'],
    )
    entry = {
        'name': name,
        'layer': _LAYER_OF[name],
        'status': 'located',
        'source': {
            'offset': offset,
            'length': length,
            'file_offset': record['packet_offset'] + offset,
            'bit_offset': info['bit_offset'],
            'bit_length': (
                info['bit_length'] if info['bit_length'] is not None else length * 8
            ),
        },
        'representation': _representation(name, raw_value, salt),
        'source_commitment': _source_commitment(name, raw_value, salt),
    }
    entry['commitment'] = _entry_commitment(entry)
    return entry, raw_value


def _crosscheck_with_dpkt(record, context, raw_values):
    """Check a fully captured frame against dpkt's own decoder."""
    if record['captured_length'] != record['declared_captured_length']:
        return
    frame = record['frame']
    if not raw_values:
        return

    try:
        if record['linktype'] == pcap.DLT_EN10MB:
            packet = ethernet.Ethernet(frame)
            try:
                ip_packet = packet[ip_module.IP]
            except (KeyError, AttributeError):
                ip_packet = None
        elif record['linktype'] in _RAW_LINKTYPES:
            packet = ip_module.IP(frame)
            ip_packet = packet
        else:
            return
    except (dpkt.UnpackError, dpkt.NeedData, struct.error, IndexError, ValueError):
        return

    def check(name, actual):
        if name in raw_values and raw_values[name] != actual:
            raise EvidenceError(
                'internal inconsistency for %s: layout=%r dpkt=%r'
                % (name, raw_values[name], actual)
            )

    if context['link_layer'] == 'ethernet':
        check('eth.dst', packet.dst)
        check('eth.src', packet.src)
        check('eth.type', packet.type)
        if getattr(packet, 'vlan_tags', None):
            tag = packet.vlan_tags[0]
            check('vlan.pri', tag.pri)
            check('vlan.cfi', tag.cfi)
            check('vlan.id', tag.id)
            check('vlan.type', tag.type)

    if ip_packet is not None:
        check('ip.v', ip_packet.v)
        check('ip.hl', ip_packet.hl)
        check('ip.tos', ip_packet.tos)
        check('ip.len', ip_packet.len)
        check('ip.id', ip_packet.id)
        check('ip.rf', ip_packet.rf)
        check('ip.df', ip_packet.df)
        check('ip.mf', ip_packet.mf)
        check('ip.offset', ip_packet.offset)
        check('ip.ttl', ip_packet.ttl)
        check('ip.p', ip_packet.p)
        check('ip.sum', ip_packet.sum)
        check('ip.src', ip_packet.src)
        check('ip.dst', ip_packet.dst)
        check('ip.opts', ip_packet.opts)


def _project_record(record, fields, salt):
    context = _decode_context(record['frame'], record['linktype'])
    entries = []
    raw_values = {}
    for name in fields:
        result = _evaluate_field(name, record, context, salt)
        if isinstance(result, tuple):
            entry, raw_value = result
            raw_values[name] = raw_value
        else:
            entry = result
        entries.append(entry)

    _crosscheck_with_dpkt(record, context, raw_values)

    output = {
        'index': record['index'],
        'linktype': record['linktype'],
        'record_header_offset': record['record_header_offset'],
        'packet_offset': record['packet_offset'],
        'captured_length': record['captured_length'],
        'declared_captured_length': record['declared_captured_length'],
        'original_length': record['original_length'],
        'truncated': record['captured_length'] < record['original_length'],
        'encapsulation': {
            'link_layer': context['link_layer'],
            'vlan_tags': 1 if context['vlan_present'] else 0,
            'ip_offset': context['ip_offset'],
        },
        'fields': entries,
    }
    return output


def project(source, fields=None, records=None, salt=None):
    """Project an allow-listed subset of link and IPv4 header fields.

    The source is only read.  The returned dictionary contains byte ranges
    in the saved capture, not the capture bytes themselves.  Address fields
    are HMAC-redacted with the projection-level salt.
    """
    field_names = _normalize_fields(fields)
    salt_bytes = _normalize_salt(salt)
    blob, source_name, compressed = _read_source(source)
    parsed = _parse_pcap(blob)
    selected = _normalize_records(records, len(parsed['records']))

    projected_records = [
        _project_record(parsed['records'][index], field_names, salt_bytes)
        for index in selected
    ]

    projection = {
        'schema': SCHEMA,
        'source': {
            'format': 'pcap',
            'compression': 'gzip' if compressed else 'none',
            'name': source_name,
            'size': len(blob),
            'sha256': 'sha256:' + hashlib.sha256(blob).hexdigest(),
            'linktype': parsed['linktype'],
            'snaplen': parsed['snaplen'],
            'record_count': len(parsed['records']),
        },
        'policy': {
            'fields': field_names,
            'records': selected,
        },
        'redaction': {
            'address_fields': sorted(SENSITIVE_FIELDS),
            'algorithm': 'hmac-sha256',
            'salt': binascii.hexlify(salt_bytes).decode('ascii'),
        },
        'records': projected_records,
    }
    projection['commitment'] = _manifest_commitment(projection)
    return projection


def dumps_projection(projection, indent=None):
    """Serialize a projection deterministically without exposing raw frames."""
    if isinstance(projection, VerificationResult):
        # Python's C JSON encoder consults truthiness for dict subclasses;
        # a failed result is falsy, so serialize an ordinary dict instead.
        projection = dict(projection)
    return json.dumps(
        projection,
        sort_keys=True,
        indent=indent,
        separators=(',', ': ') if indent is not None else (',', ':'),
        ensure_ascii=True,
    )


def load_projection(fileobj):
    if isinstance(fileobj, (str, bytes)) or hasattr(fileobj, '__fspath__'):
        with open(fileobj, 'r') as stream:
            return json.load(stream)
    return json.load(fileobj)


def _expected_location(name, record, field_by_name):
    """Return the layout-derived absolute source offset, when knowable."""
    layer, local_name = name.split('.', 1)
    context = record.get('encapsulation') or {}
    link_layer = context.get('link_layer')

    if layer == 'eth':
        if link_layer != 'ethernet':
            return None
        return _FIXED_LAYOUT[name]['offset']

    if layer == 'vlan':
        if link_layer != 'ethernet' or context.get('vlan_tags') != 1:
            return None
        return ethernet.Ethernet.__hdr_len__ + _FIXED_LAYOUT[name]['offset']

    ip_offset = context.get('ip_offset')
    if ip_offset is None:
        return None
    if local_name == 'opts':
        hl_entry = field_by_name.get('ip.hl')
        if not hl_entry or hl_entry.get('status') != 'located':
            return None
        representation = hl_entry.get('representation') or {}
        if representation.get('kind') != 'verbatim':
            return None
        ihl = representation.get('value')
        if not isinstance(ihl, int):
            return None
        return ip_offset + ip_module.IP.__hdr_len__
    return ip_offset + _FIXED_LAYOUT[name]['offset']


def _verify_structure(projection, errors, checked):
    if projection.get('schema') != SCHEMA:
        errors.append({
            'code': 'unsupported_schema',
            'path': 'schema',
            'message': 'expected %s' % SCHEMA,
        })
        return

    expected_manifest = _manifest_commitment(projection)
    if projection.get('commitment') != expected_manifest:
        errors.append({
            'code': 'manifest_commitment_mismatch',
            'path': 'commitment',
            'message': 'projection contents do not match the manifest commitment',
        })

    policy = projection.get('policy')
    if not isinstance(policy, dict):
        errors.append({
            'code': 'invalid_policy',
            'path': 'policy',
            'message': 'policy must be an object',
        })
        return
    if not isinstance(policy.get('fields'), list):
        errors.append({
            'code': 'invalid_policy',
            'path': 'policy.fields',
            'message': 'fields must be a list',
        })
        return
    try:
        policy_fields = [_normalize_field(name) for name in policy['fields']]
    except (EvidenceError, TypeError) as exc:
        errors.append({
            'code': 'invalid_policy',
            'path': 'policy.fields',
            'message': str(exc),
        })
        return

    records = projection.get('records')
    if not isinstance(records, list):
        errors.append({
            'code': 'invalid_records',
            'path': 'records',
            'message': 'records must be a list',
        })
        return

    for record in records:
        if not isinstance(record, dict):
            errors.append({
                'code': 'invalid_record',
                'path': 'records',
                'message': 'record entries must be objects',
            })
            continue
        checked['records'] += 1
        record_path = 'records[%s]' % record.get('index')
        packet_offset = record.get('packet_offset')
        if not isinstance(packet_offset, int) or packet_offset < 0:
            errors.append({
                'code': 'invalid_record_offset',
                'path': record_path + '.packet_offset',
                'message': 'packet_offset must be a non-negative integer',
            })

        fields = record.get('fields')
        if not isinstance(fields, list):
            errors.append({
                'code': 'invalid_fields',
                'path': record_path + '.fields',
                'message': 'fields must be a list',
            })
            continue
        if len(fields) != len(policy_fields):
            errors.append({
                'code': 'field_count_mismatch',
                'path': record_path + '.fields',
                'message': 'record fields do not match policy allow-list',
            })

        field_by_name = {}
        for field in fields:
            if not isinstance(field, dict):
                errors.append({
                    'code': 'invalid_field',
                    'path': record_path + '.fields',
                    'message': 'field entries must be objects',
                })
                continue
            checked['fields'] += 1
            name = field.get('name')
            field_path = record_path + '.fields[' + str(name) + ']'
            if not isinstance(name, str) or name not in _SUPPORTED_FIELDS:
                errors.append({
                    'code': 'unsupported_field',
                    'path': field_path,
                    'message': 'field is not allow-listed',
                })
                continue
            field_by_name[name] = field
            if name not in policy_fields:
                errors.append({
                    'code': 'field_not_in_policy',
                    'path': field_path,
                    'message': 'field is absent from policy.fields',
                })

            expected_commitment = _entry_commitment(field)
            if field.get('commitment') != expected_commitment:
                errors.append({
                    'code': 'field_commitment_mismatch',
                    'path': field_path + '.commitment',
                    'message': 'field value or source position was changed',
                })

            status = field.get('status')
            if status == 'unlocated':
                checked['unlocated'] += 1
                if field.get('source') is not None or field.get('representation') is not None:
                    errors.append({
                        'code': 'unlocated_has_source',
                        'path': field_path,
                        'message': 'unlocated fields must not carry offsets or values',
                    })
                if not isinstance(field.get('reason'), str) or not field['reason']:
                    errors.append({
                        'code': 'missing_unlocated_reason',
                        'path': field_path + '.reason',
                        'message': 'unlocated fields need a reason',
                    })
                continue
            if status != 'located':
                errors.append({
                    'code': 'invalid_status',
                    'path': field_path + '.status',
                    'message': 'status must be located or unlocated',
                })
                continue

            checked['located'] += 1
            encapsulation = record.get('encapsulation')
            if not isinstance(encapsulation, dict):
                encapsulation = {}
            if name.startswith('eth.') and encapsulation.get('link_layer') != 'ethernet':
                errors.append({
                    'code': 'encapsulation_conflict',
                    'path': field_path + '.status',
                    'message': 'Ethernet fields cannot be located in this encapsulation',
                })
            if name.startswith('vlan.') and encapsulation.get('vlan_tags') != 1:
                errors.append({
                    'code': 'encapsulation_conflict',
                    'path': field_path + '.status',
                    'message': 'VLAN fields require exactly one decoded VLAN tag',
                })
            if name.startswith('ip.') and encapsulation.get('ip_offset') is None:
                errors.append({
                    'code': 'encapsulation_conflict',
                    'path': field_path + '.status',
                    'message': 'IP fields cannot be located for unknown encapsulation',
                })
            source = field.get('source')
            representation = field.get('representation')
            if not isinstance(source, dict) or not isinstance(representation, dict):
                errors.append({
                    'code': 'missing_source_or_value',
                    'path': field_path,
                    'message': 'located fields need source and representation',
                })
                continue

            for key in ('offset', 'length', 'file_offset', 'bit_offset', 'bit_length'):
                value = source.get(key)
                if not isinstance(value, int) or value < 0:
                    errors.append({
                        'code': 'invalid_source_position',
                        'path': field_path + '.source.' + key,
                        'message': '%s must be a non-negative integer' % key,
                    })
            if any(
                not isinstance(source.get(key), int) or source.get(key) < 0
                for key in ('offset', 'length', 'file_offset', 'bit_offset', 'bit_length')
            ):
                continue

            if isinstance(packet_offset, int):
                expected_file_offset = packet_offset + source['offset']
                if source['file_offset'] != expected_file_offset:
                    errors.append({
                        'code': 'file_offset_inconsistent',
                        'path': field_path + '.source.file_offset',
                        'message': 'file_offset must equal packet_offset + offset',
                    })

            bit_capacity = source['length'] * 8
            if (
                source['bit_length'] > bit_capacity
                or source['bit_offset'] + source['bit_length'] > bit_capacity
            ):
                errors.append({
                    'code': 'invalid_bit_range',
                    'path': field_path + '.source',
                    'message': 'bit range is outside the located bytes',
                })

            fixed = _FIXED_LAYOUT.get(name)
            if fixed is not None and name != 'ip.opts':
                if (
                    source['length'] != fixed['length']
                    or source['bit_offset'] != fixed['bit_offset']
                    or source['bit_length'] != fixed['bit_length']
                ):
                    errors.append({
                        'code': 'layout_mismatch',
                        'path': field_path + '.source',
                        'message': 'source range does not match the field layout',
                    })

            expected_offset = _expected_location(name, record, field_by_name)
            if expected_offset is not None and source['offset'] != expected_offset:
                errors.append({
                    'code': 'source_offset_mismatch',
                    'path': field_path + '.source.offset',
                    'message': 'source offset does not match the decoded encapsulation',
                })

            representation_kind = representation.get('kind')
            if representation_kind not in ('verbatim', 'redacted'):
                errors.append({
                    'code': 'invalid_representation',
                    'path': field_path + '.representation.kind',
                    'message': 'representation kind must be verbatim or redacted',
                })
            if 'value' not in representation:
                errors.append({
                    'code': 'missing_representation_value',
                    'path': field_path + '.representation.value',
                    'message': 'representation must carry a value',
                })

            source_commitment = field.get('source_commitment')
            if (not isinstance(source_commitment, str)
                    or not source_commitment.startswith('hmac-sha256:')):
                errors.append({
                    'code': 'missing_source_commitment',
                    'path': field_path + '.source_commitment',
                    'message': 'located fields need a keyed source commitment',
                })

            if name == 'ip.opts':
                hl_entry = field_by_name.get('ip.hl')
                if hl_entry and hl_entry.get('status') == 'located':
                    hl_value = (hl_entry.get('representation') or {}).get('value')
                    if isinstance(hl_value, int) and hl_value >= 5:
                        expected_length = (hl_value - 5) * 4
                        if source['length'] != expected_length:
                            errors.append({
                                'code': 'layout_mismatch',
                                'path': field_path + '.source.length',
                                'message': 'IP options length does not match IHL',
                            })

            if name in SENSITIVE_FIELDS:
                if representation.get('kind') != 'redacted':
                    errors.append({
                        'code': 'address_not_redacted',
                        'path': field_path + '.representation',
                        'message': 'address fields must use the redacted representation',
                    })
                value = representation.get('value')
                if not isinstance(value, str) or not value.startswith('hmac-sha256:'):
                    errors.append({
                        'code': 'invalid_redaction',
                        'path': field_path + '.representation.value',
                        'message': 'redacted value must be an hmac-sha256 pseudonym',
                    })


def _verify_against_source(projection, source, errors, checked):
    policy = projection.get('policy')
    if not isinstance(policy, dict):
        policy = {}
    redaction = projection.get('redaction')
    if not isinstance(redaction, dict):
        redaction = {}
    try:
        rebuilt = project(
            source,
            fields=policy.get('fields'),
            records=policy.get('records'),
            salt=redaction.get('salt'),
        )
    except Exception as exc:
        errors.append({
            'code': 'source_unreadable',
            'path': 'source',
            'message': 'cannot re-project source: %s' % exc,
        })
        return

    projected_source = projection.get('source')
    if not isinstance(projected_source, dict):
        projected_source = {}
    expected_digest = projected_source.get('sha256')
    actual_digest = rebuilt['source']['sha256']
    checked['source_digest_match'] = expected_digest == actual_digest
    if expected_digest != actual_digest:
        errors.append({
            'code': 'source_digest_mismatch',
            'path': 'source.sha256',
            'message': 'source capture is not the committed capture',
        })
        return

    checked['rebuilt'] = True
    original_records = projection.get('records')
    if not isinstance(original_records, list):
        original_records = []
    rebuilt_records = rebuilt['records']
    if len(original_records) != len(rebuilt_records):
        errors.append({
            'code': 'record_set_mismatch',
            'path': 'records',
            'message': 'selected record set does not match the source',
        })
        return

    for original, fresh in zip(original_records, rebuilt_records):
        record_path = 'records[%s]' % original.get('index')
        for key in (
            'index',
            'linktype',
            'record_header_offset',
            'packet_offset',
            'captured_length',
            'declared_captured_length',
            'original_length',
            'truncated',
            'encapsulation',
        ):
            if original.get(key) != fresh.get(key):
                errors.append({
                    'code': 'record_metadata_mismatch',
                    'path': record_path + '.' + key,
                    'message': 'record metadata does not match the source',
                })

        original_fields = dict(
            (field.get('name'), field)
            for field in (original.get('fields') or [])
            if isinstance(field, dict) and isinstance(field.get('name'), str)
        )
        fresh_fields = dict(
            (field.get('name'), field)
            for field in (fresh.get('fields') or [])
            if isinstance(field, dict) and isinstance(field.get('name'), str)
        )
        for name in sorted(set(original_fields) | set(fresh_fields)):
            old = original_fields.get(name)
            new = fresh_fields.get(name)
            if old == new:
                continue
            field_path = record_path + '.fields[' + str(name) + ']'
            old_source = (old or {}).get('source')
            new_source = (new or {}).get('source')
            old_value = (old or {}).get('representation')
            new_value = (new or {}).get('representation')
            if old_source != new_source:
                code = 'source_location_mismatch'
                path = field_path + '.source'
            elif old_value != new_value:
                code = 'disclosed_value_mismatch'
                path = field_path + '.representation'
            else:
                code = 'field_mismatch'
                path = field_path
            errors.append({
                'code': code,
                'path': path,
                'message': 'projection does not match a fresh projection',
            })


def verify(projection, source=None, raise_on_error=False):
    """Verify commitments and, optionally, re-project the original capture."""
    errors = []
    checked = {
        'records': 0,
        'fields': 0,
        'located': 0,
        'unlocated': 0,
        'source_digest_match': None,
        'rebuilt': False,
    }

    if not isinstance(projection, dict):
        errors.append({
            'code': 'invalid_projection',
            'path': '',
            'message': 'projection must be a JSON object',
        })
    else:
        _verify_structure(projection, errors, checked)
        if source is not None:
            _verify_against_source(projection, source, errors, checked)

    result = VerificationResult(
        ok=not errors,
        errors=errors,
        checked=checked,
    )
    if errors and raise_on_error:
        raise EvidenceVerificationError(
            '; '.join(error['message'] for error in errors)
        )
    return result


def is_valid(projection, source=None):
    """Boolean convenience wrapper around :func:`verify`."""
    return bool(verify(projection, source=source))


review = verify
verify_projection = verify
verify_commitments = verify
verify_capture = verify
build_projection = project
make_projection = project
project_pcap = project
EvidenceProjectionError = EvidenceError


class EvidenceProjector(object):
    """Reusable projector with a fixed field policy and redaction salt."""

    def __init__(self, fields=None, salt=None):
        self.fields = _normalize_fields(fields)
        self.salt = _normalize_salt(salt)

    def project(self, source, records=None):
        return project(source, fields=self.fields, records=records, salt=self.salt)

    def verify(self, projection, source=None):
        return verify(projection, source=source)


def _parse_cli_records(spec):
    if spec is None or spec == '':
        return None
    tokens = []
    for part in spec.split(','):
        tokens.extend(_parse_record_token(part))
    return tokens


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='python -m dpkt.evidence',
        description='Read-only packet evidence projection',
    )
    subparsers = parser.add_subparsers(dest='command')

    project_parser = subparsers.add_parser(
        'project', help='emit a disclosure projection for selected records'
    )
    project_parser.add_argument('source', help='pcap or pcap.gz capture')
    project_parser.add_argument(
        '--fields',
        default=None,
        help='comma-separated allow-list (default: link and IPv4 headers)',
    )
    project_parser.add_argument(
        '--records',
        default=None,
        help='zero-based record indexes, e.g. 0,2-4',
    )
    project_parser.add_argument(
        '--salt',
        default=None,
        help='hex-encoded redaction salt (default: random)',
    )
    project_parser.add_argument('--output', '-o', default=None)
    project_parser.add_argument('--pretty', action='store_true')

    verify_parser = subparsers.add_parser(
        'verify', help='verify commitments and optionally the source capture'
    )
    verify_parser.add_argument('projection', help='projection JSON file, or - for stdin')
    verify_parser.add_argument('--source', default=None)

    args = parser.parse_args(argv)
    if args.command == 'project':
        try:
            projection = project(
                args.source,
                fields=args.fields,
                records=_parse_cli_records(args.records),
                salt=args.salt,
            )
            text = dumps_projection(projection, indent=2 if args.pretty else None)
            if args.output:
                with open(args.output, 'w') as stream:
                    stream.write(text + '\n')
            else:
                print(text)
        except (EvidenceError, IOError, OSError) as exc:
            print('error: %s' % exc, file=sys.stderr)
            return 2
        return 0

    if args.command == 'verify':
        try:
            if args.projection == '-':
                projection = json.load(sys.stdin)
            else:
                projection = load_projection(args.projection)
        except (IOError, OSError, ValueError) as exc:
            print('error: cannot read projection: %s' % exc, file=sys.stderr)
            return 2
        result = verify(projection, source=args.source)
        print(dumps_projection(result, indent=2))
        return 0 if result.ok else 1

    parser.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())

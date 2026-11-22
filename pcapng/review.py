"""
Read-only review of a redacted pcap-ng file against its original.

The reviewer answers a narrow question: did the redaction stay inside the
approval that was granted for it?  To do that it keeps the original byte
range of every block, field and option, matches packets by their original
identity rather than by a possibly renumbered interface id, and reports both
approved changes and unauthorised changes.

The public entry points are :func:`compare_files` and :func:`compare`.
They never write to, truncate or otherwise modify either source.
"""

import argparse
import hashlib
import io
import json
import os
import struct
import sys
from collections import defaultdict

import pcapng.blocks as blocks
from pcapng.scanner import FileScanner
from pcapng.writer import FileWriter


__all__ = [
    "SourceRange",
    "Approval",
    "RedactionApproval",
    "ApprovalGrant",
    "PcapngComparer",
    "PcapngReviewer",
    "RedactionReviewer",
    "RedactionComparator",
    "Grant",
    "Finding",
    "Difference",
    "Change",
    "RedactionFinding",
    "ReviewReport",
    "ComparisonReport",
    "ComparisonResult",
    "ReviewResult",
    "AuditReport",
    "DiffReport",
    "RedactionReview",
    "RedactionViolation",
    "compare",
    "compare_files",
    "compare_pcapng",
    "compare_streams",
    "compare_readonly",
    "compare_read_only",
    "read_only_compare",
    "review",
    "review_files",
    "review_redaction",
    "audit",
    "audit_files",
    "audit_redaction",
    "check_redaction",
    "diff",
    "compare_captures",
    "review_captures",
    "audit_captures",
    "packet_identifier",
    "PRESERVATION_FIELDS",
]


class SourceRange(tuple):
    """A half-open byte range in the source document."""

    __slots__ = ()

    def __new__(cls, start, end):
        return tuple.__new__(cls, (start, end))

    @property
    def start(self):
        return self[0]

    @property
    def end(self):
        return self[1]

    @property
    def stop(self):
        return self[1]

    def __repr__(self):
        return tuple.__repr__(self)


PRESERVATION_FIELDS = frozenset(
    [
        "packet_data",
        "packet_len",
        "captured_len",
        "timestamp_high",
        "timestamp_low",
        "epb_hash",
        "pack_hash",
        "epb_packetid",
        "packet_id",
        "interface_id",
        "drops_count",
        "epb_dropcount",
        "section_length",
        "snaplen",
        "link_type",
        "reserved",
        "records",
        "if_MACaddr",
        "if_EUIaddr",
    ]
)


_DOMAIN_ALIASES = {
    "shb": "section",
    "section_header": "section",
    "sectionheader": "section",
    "section": "section",
    "idb": "interface",
    "interface_description": "interface",
    "interfacedescription": "interface",
    "interface": "interface",
    "epb": "packet",
    "enhanced_packet": "packet",
    "enhancedpacket": "packet",
    "packet": "packet",
    "packets": "packet",
    "packet_comment": "packet",
    "packet_comments": "packet",
    "comment": "packet",
    "comments": "packet",
    "annotation": "packet",
    "annotations": "packet",
    "packet_option": "packet",
    "packet_options": "packet",
    "epb_option": "packet",
    "epb_options": "packet",
    "idb_option": "interface",
    "idb_options": "interface",
    "shb_option": "section",
    "shb_options": "section",
    "isb_option": "interface_statistics",
    "isb_options": "interface_statistics",
    "spb": "packet",
    "simple_packet": "packet",
    "simplepacket": "packet",
    "pb": "packet",
    "obsolete_packet": "packet",
    "obsoletepacket": "packet",
    "isb": "interface_statistics",
    "interface_statistics": "interface_statistics",
    "interfacestatistics": "interface_statistics",
    "statistics": "interface_statistics",
    "stats": "interface_statistics",
    "nrb": "name_resolution",
    "name_resolution": "name_resolution",
    "nameresolution": "name_resolution",
    "unknown": "unknown",
    "unknown_block": "unknown",
    "preservation": "*",
    "preservation_field": "*",
    "integrity": "*",
    "option": "*",
    "any": "*",
    "*": "*",
}


_FIELD_ALIASES = {
    "comment": "opt_comment",
    "comments": "opt_comment",
    "packet_comment": "opt_comment",
    "packet_comments": "opt_comment",
    "epb_comment": "opt_comment",
    "pack_comment": "opt_comment",
    "pack_comments": "opt_comment",
    "opt_comment": "opt_comment",
    "opt_comments": "opt_comment",
    "hash": "epb_hash",
    "packet_hash": "epb_hash",
    "epb_hash": "epb_hash",
    "epb_packet_id": "epb_packetid",
    "packetid": "epb_packetid",
    "packet_id_option": "epb_packetid",
    "pack_flags": "epb_flags",
    "pack_hash": "epb_hash",
    "caplen": "captured_len",
    "capture_len": "captured_len",
    "captured_length": "captured_len",
    "captured_len": "captured_len",
    "wire_len": "packet_len",
    "original_len": "packet_len",
    "orig_len": "packet_len",
    "packet_length": "packet_len",
    "packet_len": "packet_len",
    "iface": "interface_id",
    "interface": "interface_id",
    "interface_id": "interface_id",
    "timestamp": "timestamp",
    "timestamp_high": "timestamp_high",
    "ts_high": "timestamp_high",
    "timestamp_low": "timestamp_low",
    "ts_low": "timestamp_low",
    "data": "packet_data",
    "payload": "packet_data",
    "packet_data": "packet_data",
    "snaplen": "snaplen",
    "snap_len": "snaplen",
    "section_length": "section_length",
    "section_len": "section_length",
}


_COUNT_OPTIONS = frozenset(["isb_ifrecv", "isb_usrdeliv", "isb_filteraccept"])


def _norm_domain(value):
    if value is None:
        return None
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    text = text.replace(".", "_")
    if text in _DOMAIN_ALIASES:
        return _DOMAIN_ALIASES[text]
    if text.endswith("_option"):
        text = text[: -len("_option")]
    if text in _DOMAIN_ALIASES:
        return _DOMAIN_ALIASES[text]
    for prefix in (
        "interface_statistics",
        "interface_description",
        "section_header",
        "enhanced_packet",
        "obsolete_packet",
        "simple_packet",
        "name_resolution",
        "unknown_block",
    ):
        if text.startswith(prefix + "_"):
            return _DOMAIN_ALIASES[prefix]
    head = text.split("_", 1)[0]
    if head in _DOMAIN_ALIASES:
        return _DOMAIN_ALIASES[head]
    return text


def _norm_field(value):
    if value is None:
        return None
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    text = text.lower().replace("-", "_").replace(" ", "_")
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    if text.startswith("opt_") and text in _FIELD_ALIASES:
        return _FIELD_ALIASES[text]
    if text in _FIELD_ALIASES:
        return _FIELD_ALIASES[text]
    if text.startswith("pack_"):
        candidate = "epb_" + text[len("pack_") :]
        if candidate in _FIELD_ALIASES:
            return _FIELD_ALIASES[candidate]
    if text.endswith("comment"):
        return "opt_comment"
    if text.endswith("hash"):
        return "epb_hash"
    for canonical in (
        "captured_len",
        "packet_len",
        "packet_data",
        "timestamp_high",
        "timestamp_low",
        "interface_id",
        "section_length",
        "snaplen",
    ):
        if text.endswith(canonical):
            return canonical
    return text


def _block_domain(block):
    if isinstance(block, blocks.SectionHeader):
        return "section"
    if isinstance(block, blocks.InterfaceDescription):
        return "interface"
    if isinstance(block, blocks.InterfaceStatistics):
        return "interface_statistics"
    if isinstance(block, blocks.NameResolution):
        return "name_resolution"
    if isinstance(block, blocks.BasePacketBlock):
        return "packet"
    return "unknown"


def _align4(size):
    return size + ((4 - (size % 4)) % 4)


def _as_text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _normalise_value(value):
    if hasattr(value, "get") and value.__class__.__name__ == "EPBFlags":
        try:
            return int(value)
        except Exception:
            pass
    if isinstance(value, dict):
        return tuple(sorted((str(k), _normalise_value(v)) for k, v in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_normalise_value(v) for v in value)
    if isinstance(value, bytearray):
        return bytes(value)
    return value


def _value_repr(value):
    value = _normalise_value(value)
    if isinstance(value, bytes):
        return "0x" + value.hex()
    return repr(value)


class _OptionSpan(object):
    __slots__ = [
        "code",
        "name",
        "occurrence",
        "start",
        "end",
        "value_start",
        "value_end",
        "raw",
        "value",
    ]

    def __init__(self, code, name, occurrence, start, end, value_start, value_end, raw):
        self.code = code
        self.name = name
        self.occurrence = occurrence
        self.start = start
        self.end = end
        self.value_start = value_start
        self.value_end = value_end
        self.raw = raw
        self.value = raw


class _Record(object):
    __slots__ = [
        "index",
        "section_index",
        "block",
        "start",
        "end",
        "body_start",
        "body_end",
        "domain",
        "options_start",
        "options",
        "packet_ordinal",
        "interface_ordinal",
    ]

    def __init__(self, index, section_index, block, start, end):
        self.index = index
        self.section_index = section_index
        self.block = block
        self.start = start
        self.end = end
        self.body_start = start + 8
        self.body_end = end - 4
        self.domain = _block_domain(block)
        self.options_start = None
        self.options = []
        self.packet_ordinal = None
        self.interface_ordinal = None

    @property
    def block_range(self):
        return SourceRange(self.start, self.end)


class _Document(object):
    __slots__ = ["source", "data", "records", "sections", "errors"]

    def __init__(self, source, data):
        self.source = source
        self.data = data
        self.records = []
        self.sections = []
        self.errors = []


def _serialize_blocks(records):
    stream = io.BytesIO()
    writer = None
    for record in records:
        if isinstance(record, blocks.SectionHeader):
            writer = FileWriter(stream, record)
            continue
        if writer is None:
            raise TypeError("block list must start with a SectionHeader")
        if isinstance(record, blocks.InterfaceDescription):
            if record.interface_id in writer.interfaces:
                continue
        writer.write_block(record)
    return stream.getvalue()


def _read_source(source):
    if isinstance(source, (list, tuple)) and source:
        if all(isinstance(record, blocks.Block) for record in source):
            return "<blocks>", _serialize_blocks(source)
    if isinstance(source, FileScanner):
        source = source.stream
    if isinstance(source, bytes):
        return "<bytes>", source
    if isinstance(source, (bytearray, memoryview)):
        return "<bytes>", bytes(source)
    if isinstance(source, (str, bytes, os.PathLike)):
        label = os.fspath(source)
        with open(source, "rb") as fp:
            return label, fp.read()
    if hasattr(source, "read"):
        label = getattr(source, "name", "<stream>")
        position = None
        if hasattr(source, "tell"):
            try:
                position = source.tell()
            except Exception:
                position = None
        if hasattr(source, "seek"):
            try:
                source.seek(0)
            except Exception:
                pass
        data = source.read()
        if position is not None and hasattr(source, "seek"):
            try:
                source.seek(position)
            except Exception:
                pass
        if isinstance(data, str):
            data = data.encode("latin-1")
        return label, bytes(data)
    raise TypeError(
        "expected a path, bytes, or a readable file-like object, got {!r}".format(
            type(source).__name__
        )
    )


def _section_endianness(record):
    block = record.block
    if isinstance(block, blocks.SectionHeader):
        return block.endianness
    section = getattr(block, "section", None)
    if section is not None:
        return section.endianness
    return "="


def _raw_field(record, name):
    block = record.block
    decoded = getattr(block, "_decoded", None)
    if decoded is not None and name in decoded:
        return decoded[name]
    return getattr(block, name)


def _options_start(record, data=None):
    block = record.block
    body = record.body_start
    if isinstance(block, blocks.SectionHeader):
        return body + 4 + 12
    if isinstance(block, blocks.InterfaceDescription):
        return body + 8
    if isinstance(block, blocks.InterfaceStatistics):
        return body + 12
    if isinstance(block, (blocks.EnhancedPacket, blocks.ObsoletePacket)):
        captured = _raw_field(record, "captured_len")
        return body + 20 + _align4(int(captured or 0))
    if isinstance(block, blocks.NameResolution):
        endian = _section_endianness(record)
        cursor = body
        body_end = record.body_end
        while cursor + 4 <= body_end:
            if data is None or cursor + 4 > len(data):
                break
            record_type, record_length = struct.unpack(
                endian + "HH", data[cursor : cursor + 4]
            )
            cursor += 4
            if record_type == 0:
                break
            cursor += _align4(record_length)
        return cursor
    return None


def _option_name(block, code):
    options = getattr(block, "options", None)
    if options is not None:
        info = getattr(options, "schema", {}).get(code)
        if info is not None:
            return info.name
    return "option_{}".format(code)


def _parse_options(record, data):
    block = record.block
    if not hasattr(block, "options"):
        return []
    start = _options_start(record, data)
    if start is None or start >= record.body_end:
        return []
    endian = _section_endianness(record)
    cursor = start
    occurrences = defaultdict(int)
    result = []
    while cursor + 4 <= record.body_end:
        code, length = struct.unpack(endian + "HH", data[cursor : cursor + 4])
        if code == 0:
            break
        value_start = cursor + 4
        value_end = value_start + length
        padded_end = value_start + _align4(length)
        if value_end > record.body_end or padded_end > record.body_end:
            break
        occurrence = occurrences[code]
        occurrences[code] += 1
        span = _OptionSpan(
            code=code,
            name=_option_name(block, code),
            occurrence=occurrence,
            start=cursor,
            end=padded_end,
            value_start=value_start,
            value_end=value_end,
            raw=data[value_start:value_end],
        )
        options = getattr(block, "options", None)
        if options is not None:
            values = options.data.get(code, [])
            if occurrence < len(values):
                span.value = values[occurrence]
        result.append(span)
        cursor = padded_end
    return result


def _scan(source):
    label, data = _read_source(source)
    document = _Document(label, data)
    stream = io.BytesIO(data)
    scanner = FileScanner(stream)
    iterator = iter(scanner)
    section_index = -1
    packet_ordinal = 0
    interface_ordinal = 0
    index = 0
    while True:
        start = stream.tell()
        try:
            block = next(iterator)
        except StopIteration:
            break
        except Exception as exc:
            document.errors.append((start, len(data), exc))
            break
        end = stream.tell()
        if isinstance(block, blocks.SectionHeader):
            section_index += 1
            packet_ordinal = 0
            interface_ordinal = 0
            document.sections.append([])
        record = _Record(index, section_index, block, start, end)
        if isinstance(block, blocks.InterfaceDescription):
            record.interface_ordinal = interface_ordinal
            interface_ordinal += 1
        elif isinstance(block, blocks.BasePacketBlock):
            record.packet_ordinal = packet_ordinal
            packet_ordinal += 1
        record.options = _parse_options(record, data)
        document.records.append(record)
        if section_index >= 0:
            document.sections[section_index].append(record)
        index += 1
    return document


def _field_range(record, field):
    block = record.block
    body = record.body_start
    name = _norm_field(field)
    if isinstance(block, blocks.SectionHeader):
        payload = body + 4
        ranges = {
            "version_major": (payload, payload + 2),
            "version_minor": (payload + 2, payload + 4),
            "section_length": (payload + 4, payload + 12),
        }
        found = ranges.get(name)
        return SourceRange(*found) if found is not None else None
    if isinstance(block, blocks.InterfaceDescription):
        ranges = {
            "link_type": (body, body + 2),
            "reserved": (body + 2, body + 4),
            "snaplen": (body + 4, body + 8),
        }
        found = ranges.get(name)
        return SourceRange(*found) if found is not None else None
    if isinstance(block, blocks.EnhancedPacket):
        captured = int(_raw_field(record, "captured_len") or 0)
        ranges = {
            "interface_id": (body, body + 4),
            "timestamp_high": (body + 4, body + 8),
            "timestamp_low": (body + 8, body + 12),
            "timestamp": (body + 4, body + 12),
            "captured_len": (body + 12, body + 16),
            "packet_len": (body + 16, body + 20),
            "packet_data": (body + 20, body + 20 + captured),
        }
        found = ranges.get(name)
        return SourceRange(*found) if found is not None else None
    if isinstance(block, blocks.ObsoletePacket):
        captured = int(_raw_field(record, "captured_len") or 0)
        ranges = {
            "interface_id": (body, body + 2),
            "drops_count": (body + 2, body + 4),
            "timestamp_high": (body + 4, body + 8),
            "timestamp_low": (body + 8, body + 12),
            "timestamp": (body + 4, body + 12),
            "captured_len": (body + 12, body + 16),
            "packet_len": (body + 16, body + 20),
            "packet_data": (body + 20, body + 20 + captured),
        }
        found = ranges.get(name)
        return SourceRange(*found) if found is not None else None
    if isinstance(block, blocks.SimplePacket):
        ranges = {
            "packet_len": (body, body + 4),
            "packet_data": (body + 4, body + 4 + len(block.packet_data)),
        }
        found = ranges.get(name)
        return SourceRange(*found) if found is not None else None
    if isinstance(block, blocks.InterfaceStatistics):
        ranges = {
            "interface_id": (body, body + 4),
            "timestamp_high": (body + 4, body + 8),
            "timestamp_low": (body + 8, body + 12),
            "timestamp": (body + 4, body + 12),
        }
        found = ranges.get(name)
        return SourceRange(*found) if found is not None else None
    if isinstance(block, blocks.NameResolution):
        return SourceRange(body, record.body_end)
    return None


def _option_index(record):
    index = {}
    for span in record.options:
        index[(span.code, span.occurrence)] = span
    return index


def _options_by_code(record):
    result = defaultdict(list)
    for span in record.options:
        result[span.code].append(span)
    return result


def _option_field_name(span):
    return _norm_field(span.name) if span.name else "option_{}".format(span.code)


def _packet_ordinal(record):
    return record.packet_ordinal or 0


def _explicit_packet_id(record):
    block = record.block
    options = getattr(block, "options", None)
    if options is None:
        return None
    values = options.data.get(5)
    if values:
        return values[0]
    return None


def _packet_signature(record):
    block = record.block
    data = getattr(block, "packet_data", b"") or b""
    digest = hashlib.sha256(data).hexdigest()
    if isinstance(block, blocks.EnhancedPacket):
        return (
            "epb",
            int(block.timestamp_high),
            int(block.timestamp_low),
            int(_raw_field(record, "packet_len") or 0),
            len(data),
            digest,
        )
    if isinstance(block, blocks.ObsoletePacket):
        return (
            "pb",
            int(block.timestamp_high),
            int(block.timestamp_low),
            int(_raw_field(record, "packet_len") or 0),
            len(data),
            digest,
        )
    if isinstance(block, blocks.SimplePacket):
        return ("spb", int(_raw_field(record, "packet_len") or 0), len(data), digest)
    return (type(block).__name__, len(data), digest)


def packet_identifier(record_or_block, section_index=None):
    """
    Return the stable identity used to bind an approval to an original packet.

    The explicit ``epb_packetid`` option is preferred.  The remaining values
    are useful fallbacks for captures which do not carry that option.
    """

    if isinstance(record_or_block, _Record):
        explicit = _explicit_packet_id(record_or_block)
        if explicit is not None:
            return explicit
        return "{}:{}".format(
            record_or_block.section_index, _packet_ordinal(record_or_block)
        )
    block = record_or_block
    options = getattr(block, "options", None)
    if options is not None:
        values = options.data.get(5)
        if values:
            return values[0]
    data = getattr(block, "packet_data", b"") or b""
    if data:
        return "sha256:{}".format(hashlib.sha256(data).hexdigest())
    raise TypeError("packet_identifier expects a packet record or block")


def _packet_id_candidates(record):
    candidates = set()
    explicit = _explicit_packet_id(record)
    if explicit is not None:
        candidates.add(str(explicit))
        candidates.add("packetid:{}".format(explicit))
    else:
        ordinal = _packet_ordinal(record)
        candidates.add(str(ordinal))
        candidates.add("packet:{}".format(ordinal))
        candidates.add("packet:{}:{}".format(record.section_index, ordinal))
        candidates.add("{}:{}".format(record.section_index, ordinal))
    block = record.block
    if isinstance(block, blocks.BlockWithTimestampMixin):
        try:
            candidates.add("timestamp:{}".format(block.timestamp))
        except Exception:
            pass
    data = getattr(block, "packet_data", b"") or b""
    digest = hashlib.sha256(data).hexdigest()
    candidates.add("sha256:{}".format(digest))
    candidates.add(digest)
    return candidates


def _interface_option(record, name):
    block = record.block
    options = getattr(block, "options", None)
    if options is None:
        return None
    try:
        return options[name]
    except (KeyError, TypeError):
        return None


def _interface_keys(record, kind):
    block = record.block
    if kind == "name":
        value = _interface_option(record, "if_name")
        return ("name", _as_text(value)) if value is not None else None
    if kind == "mac":
        value = _interface_option(record, "if_MACaddr")
        return ("mac", _normalise_value(value)) if value is not None else None
    if kind == "eui":
        value = _interface_option(record, "if_EUIaddr")
        return ("eui", _normalise_value(value)) if value is not None else None
    if kind == "description":
        value = _interface_option(record, "if_description")
        return ("description", _as_text(value)) if value is not None else None
    if kind == "shape":
        return (
            "shape",
            int(getattr(block, "link_type", 0)),
            int(getattr(block, "snaplen", 0)),
        )
    return None


def _interface_id(record):
    return getattr(record.block, "interface_id", None)


def _match_interfaces(original_records, redacted_records):
    original = [
        record
        for record in original_records
        if isinstance(record.block, blocks.InterfaceDescription)
    ]
    redacted = [
        record
        for record in redacted_records
        if isinstance(record.block, blocks.InterfaceDescription)
    ]
    original_used = set()
    redacted_used = set()
    pairs = []
    for kind in ("name", "mac", "eui", "description"):
        redacted_by_key = {}
        for index, record in enumerate(redacted):
            if index in redacted_used:
                continue
            key = _interface_keys(record, kind)
            if key is not None:
                redacted_by_key.setdefault(key, []).append(index)
        for oi, orec in enumerate(original):
            if oi in original_used:
                continue
            key = _interface_keys(orec, kind)
            if key is None:
                continue
            choices = redacted_by_key.get(key)
            if not choices:
                continue
            ri = choices.pop(0)
            original_used.add(oi)
            redacted_used.add(ri)
            pairs.append((orec, redacted[ri]))
    remaining_original = [i for i in range(len(original)) if i not in original_used]
    remaining_redacted = [i for i in range(len(redacted)) if i not in redacted_used]
    for oi, ri in zip(remaining_original, remaining_redacted):
        original_used.add(oi)
        redacted_used.add(ri)
        pairs.append((original[oi], redacted[ri]))
    interface_map = {}
    reverse_map = {}
    for orec, rrec in pairs:
        oid = _interface_id(orec)
        rid = _interface_id(rrec)
        if rid is not None and oid is not None:
            interface_map[rid] = oid
            reverse_map[oid] = rid
    unmatched_original = [
        original[i] for i in range(len(original)) if i not in original_used
    ]
    unmatched_redacted = [
        redacted[i] for i in range(len(redacted)) if i not in redacted_used
    ]
    return pairs, interface_map, reverse_map, unmatched_original, unmatched_redacted


def _match_records(original, redacted, key_func):
    original_unused = set(range(len(original)))
    redacted_unused = set(range(len(redacted)))
    pairs = []
    keys = {}
    for ri, record in enumerate(redacted):
        keys.setdefault(key_func(record), []).append(ri)
    for oi, record in enumerate(original):
        key = key_func(record)
        choices = keys.get(key, [])
        while choices and choices[0] in redacted_unused:
            ri = choices.pop(0)
            original_unused.discard(oi)
            redacted_unused.discard(ri)
            pairs.append((record, redacted[ri]))
            break
    remaining_original = [original[i] for i in sorted(original_unused)]
    remaining_redacted = [redacted[i] for i in sorted(redacted_unused)]
    used_original = set(id(pair[0]) for pair in pairs)
    used_redacted = set(id(pair[1]) for pair in pairs)
    for orec in remaining_original:
        if id(orec) in used_original:
            continue
        for rrec in remaining_redacted:
            if id(rrec) in used_redacted:
                continue
            if type(orec.block) is type(rrec.block):
                pairs.append((orec, rrec))
                used_original.add(id(orec))
                used_redacted.add(id(rrec))
                break
    paired_original = set(id(pair[0]) for pair in pairs)
    paired_redacted = set(id(pair[1]) for pair in pairs)
    return (
        pairs,
        [r for r in original if id(r) not in paired_original],
        [r for r in redacted if id(r) not in paired_redacted],
    )


def _match_packets(original, redacted):
    original_unused = set(range(len(original)))
    redacted_unused = set(range(len(redacted)))
    pairs = []

    def take_pass(key_func):
        keys = {}
        for ri, record in enumerate(redacted):
            if ri not in redacted_unused:
                continue
            keys.setdefault(key_func(record), []).append(ri)
        for oi, record in enumerate(original):
            if oi not in original_unused:
                continue
            key = key_func(record)
            if key is None:
                continue
            choices = keys.get(key)
            if not choices:
                continue
            ri = None
            while choices:
                candidate = choices.pop(0)
                if candidate in redacted_unused:
                    ri = candidate
                    break
            if ri is None:
                continue
            original_unused.discard(oi)
            redacted_unused.discard(ri)
            pairs.append((record, redacted[ri]))

    take_pass(_explicit_packet_id)
    take_pass(_packet_signature)
    for oi, ri in zip(sorted(original_unused), sorted(redacted_unused)):
        original_unused.discard(oi)
        redacted_unused.discard(ri)
        pairs.append((original[oi], redacted[ri]))
    return (
        pairs,
        [original[i] for i in sorted(original_unused)],
        [redacted[i] for i in sorted(redacted_unused)],
    )


def _approval_lookup(
    approvals, domain, packet_record, redacted_record, field, action, context
):
    for approval in approvals:
        if approval.matches(
            domain=domain,
            packet_record=packet_record,
            redacted_record=redacted_record,
            field=field,
            action=action,
            context=context,
        ):
            return approval
    return None


class Approval(object):
    """
    A single redaction grant.

    A grant is scoped by field domain (``packet``, ``interface``, ``section``,
    ``interface_statistics``, ...), by the original packet identity when the
    domain is packet-scoped, and by field/option name.  ``action`` may be
    ``delete``, ``modify``, ``add`` or ``any``.
    """

    __slots__ = [
        "domain",
        "field",
        "fields",
        "packet_id",
        "action",
        "section",
        "interface",
        "raw",
    ]

    _DOMAIN_KEYS = (
        "domain",
        "field_domain",
        "field_scope",
        "scope",
        "block",
        "block_type",
        "target_domain",
        "owner",
    )
    _FIELD_KEYS = (
        "field",
        "field_name",
        "option",
        "option_name",
        "path",
        "field_path",
    )
    _PACKET_KEYS = (
        "packet_id",
        "packet",
        "packet_identifier",
        "original_packet_id",
        "original_packet",
        "packetid",
    )
    _ACTION_KEYS = ("action", "operation", "permission", "change", "effect")

    def __init__(
        self,
        domain=None,
        field=None,
        packet_id=None,
        action=None,
        section=None,
        interface=None,
        fields=None,
        raw=None,
        **kwargs
    ):
        if isinstance(domain, (list, tuple)):
            parts = list(domain)
            domain = parts[0] if len(parts) > 0 else None
            if len(parts) > 1 and packet_id is None:
                packet_id = parts[1]
            if len(parts) > 2 and field is None:
                field = parts[2]
            if len(parts) > 3 and action is None:
                action = parts[3]
        if isinstance(packet_id, dict):
            for key in (
                "packet_id",
                "epb_packetid",
                "original_packet_id",
                "id",
                "packet",
            ):
                if key in packet_id:
                    packet_id = packet_id[key]
                    break
        if isinstance(domain, dict):
            raw = dict(domain)
            domain = None
        raw = dict(raw or {})
        raw.update(kwargs)
        if raw:
            for key in self._DOMAIN_KEYS:
                if key in raw and domain is None:
                    domain = raw[key]
            for key in self._FIELD_KEYS:
                if key in raw and field is None:
                    field = raw[key]
            for key in self._PACKET_KEYS:
                if key in raw and packet_id is None:
                    packet_id = raw[key]
            for key in self._ACTION_KEYS:
                if key in raw and action is None:
                    action = raw[key]
            if section is None:
                section = raw.get("section", raw.get("section_index"))
            if interface is None:
                interface = raw.get(
                    "interface",
                    raw.get("interface_id", raw.get("interface_name")),
                )
            if fields is None:
                fields = raw.get("fields", raw.get("allowed_fields"))
            if domain is None:
                domain = raw.get("target", raw.get("target_type"))
        domain_text = str(domain).lower() if domain is not None else ""
        self.domain = _norm_domain(domain)
        values = []
        for value in (field, fields):
            if value is None:
                continue
            if isinstance(value, (list, tuple, set, frozenset)):
                values.extend(value)
            else:
                values.append(value)
        if not values and "comment" in domain_text:
            values.append("opt_comment")
        self.fields = tuple(_norm_field(value) for value in values) or (None,)
        self.field = self.fields[0]
        self.packet_id = packet_id
        self.action = str(action).strip().lower() if action is not None else None
        self.section = section
        self.interface = interface
        self.raw = raw

    @classmethod
    def from_dict(cls, data):
        return cls(data)

    @classmethod
    def from_json(cls, data):
        return cls(json.loads(data))

    @property
    def field_domain(self):
        return self.domain

    @property
    def field_name(self):
        return self.field

    @property
    def allowed_fields(self):
        return self.fields

    @property
    def original_packet_id(self):
        return self.packet_id

    @property
    def packet_identifier(self):
        return self.packet_id

    def __repr__(self):
        return "<Approval domain={!r} packet={!r} field={!r} action={!r}>".format(
            self.domain, self.packet_id, self.field, self.action
        )

    def matches(self, domain, packet_record, redacted_record, field, action, context):
        approval_domain = self.domain
        if approval_domain not in (None, "*") and approval_domain != domain:
            return False
        field = _norm_field(field)
        allowed = self.fields
        if not any(value in (None, "*") or value == field for value in allowed):
            return False
        if self.action not in (None, "*", "any"):
            normal = self.action
            if normal in ("delete", "remove", "drop") and action != "deleted":
                return False
            if (
                normal in ("modify", "change", "replace", "redact")
                and action != "modified"
            ):
                return False
            if normal in ("add", "insert") and action != "added":
                return False
        if self.section is not None:
            try:
                if int(self.section) != int(context.get("section_index")):
                    return False
            except (TypeError, ValueError):
                return False
        if self.interface is not None:
            candidates = context.get("interface_candidates", set())
            if str(self.interface) not in candidates:
                return False
        if domain == "packet":
            if self.packet_id is None:
                return False
            candidates = (
                _packet_id_candidates(packet_record)
                if packet_record is not None
                else set()
            )
            if redacted_record is not None:
                candidates |= _packet_id_candidates(redacted_record)
            requested = set([str(self.packet_id)])
            if isinstance(self.packet_id, (list, tuple)):
                joined = ":".join(str(part) for part in self.packet_id)
                requested.add(joined)
                requested.add("packet:" + joined)
            if not requested & candidates:
                return False
        return True


RedactionApproval = Approval
Grant = Approval
ApprovalGrant = Approval


class Finding(object):
    """
    One reviewed change, including its exact original byte range.
    """

    __slots__ = [
        "code",
        "severity",
        "domain",
        "field",
        "packet_id",
        "section_index",
        "original_range",
        "redacted_range",
        "original_value_range",
        "redacted_value_range",
        "block_range",
        "original_block_range",
        "redacted_block_range",
        "original_block_index",
        "redacted_block_index",
        "original_value",
        "redacted_value",
        "approved",
        "action",
        "message",
        "overclaims",
    ]

    _ALIASES = {
        "kind": "code",
        "category": "code",
        "field_name": "field",
        "packet": "packet_id",
        "packet_identifier": "packet_id",
        "range": "original_range",
        "start": "original_start",
        "end": "original_end",
        "status": "status",
        "is_approved": "approved",
        "authorised": "approved",
        "authorized": "approved",
        "is_authorized": "approved",
        "is_authorised": "approved",
        "source_range": "original_range",
        "original_option_range": "original_range",
        "value_range": "original_value_range",
        "original_byte_range": "original_range",
        "redacted_byte_range": "redacted_range",
        "original_offset": "original_start",
        "offset": "original_start",
        "reason": "message",
        "change": "action",
        "change_type": "action",
        "operation": "action",
        "type": "code",
        "original_span": "original_range",
        "byte_range": "original_range",
        "block": "original_block_range",
        "section": "section_index",
    }

    def __init__(
        self,
        code,
        domain,
        field,
        packet_id=None,
        section_index=None,
        original_range=None,
        redacted_range=None,
        original_value_range=None,
        redacted_value_range=None,
        block_range=None,
        original_block_range=None,
        redacted_block_range=None,
        original_block_index=None,
        redacted_block_index=None,
        original_value=None,
        redacted_value=None,
        approved=False,
        action=None,
        message="",
        severity="error",
        overclaims=False,
    ):
        self.code = code
        self.severity = severity
        self.domain = domain
        self.field = field
        self.packet_id = packet_id
        self.section_index = section_index
        self.original_range = original_range
        self.redacted_range = redacted_range
        self.original_value_range = original_value_range
        self.redacted_value_range = redacted_value_range
        self.block_range = block_range or original_block_range
        self.original_block_range = original_block_range
        self.redacted_block_range = redacted_block_range
        self.original_block_index = original_block_index
        self.redacted_block_index = redacted_block_index
        self.original_value = original_value
        self.redacted_value = redacted_value
        self.approved = bool(approved)
        self.action = action
        self.message = message
        self.overclaims = bool(overclaims)

    @property
    def original_start(self):
        return self.original_range[0] if self.original_range else None

    @property
    def original_end(self):
        return self.original_range[1] if self.original_range else None

    @property
    def redacted_start(self):
        return self.redacted_range[0] if self.redacted_range else None

    @property
    def redacted_end(self):
        return self.redacted_range[1] if self.redacted_range else None

    @property
    def block_start(self):
        return self.original_block_range[0] if self.original_block_range else None

    @property
    def block_end(self):
        return self.original_block_range[1] if self.original_block_range else None

    @property
    def status(self):
        return "approved" if self.approved else "violation"

    @property
    def is_violation(self):
        return not self.approved

    @property
    def is_unauthorized(self):
        return not self.approved

    @property
    def requires_review(self):
        return not self.approved

    @property
    def code_aliases(self):
        aliases = {
            "approved_redaction": ("approved_redaction", "approved_change"),
            "approved_change": ("approved_change", "approved_redaction"),
            "unauthorized_comment_deletion": (
                "unauthorized_comment_deletion",
                "unauthorized_change",
            ),
            "preservation_field_changed": (
                "preservation_field_changed",
                "unauthorized_change",
                "preservation_change",
            ),
            "metadata_overclaim": (
                "metadata_overclaim",
                "unauthorized_change",
                "overclaim",
            ),
            "count_overclaim": (
                "count_overclaim",
                "unauthorized_change",
                "overclaim",
            ),
        }
        return aliases.get(self.code, (self.code,))

    def __getattr__(self, name):
        try:
            target = self._ALIASES[name]
        except KeyError:
            raise AttributeError(name)
        if target == "status":
            return self.status
        return getattr(self, target)

    def __getitem__(self, key):
        return getattr(self, key)

    def to_dict(self):
        return {
            "code": self.code,
            "severity": self.severity,
            "domain": self.domain,
            "field": self.field,
            "packet_id": self.packet_id,
            "section_index": self.section_index,
            "original_range": self.original_range,
            "original_start": self.original_start,
            "original_end": self.original_end,
            "original_value_range": self.original_value_range,
            "redacted_range": self.redacted_range,
            "redacted_value_range": self.redacted_value_range,
            "block_range": self.block_range,
            "original_value": _value_repr(self.original_value),
            "redacted_value": _value_repr(self.redacted_value),
            "approved": self.approved,
            "action": self.action,
            "message": self.message,
        }

    def __repr__(self):
        return (
            "<Finding {code} {domain}.{field} "
            "range={range} approved={approved}>"
        ).format(
            code=self.code,
            domain=self.domain,
            field=self.field,
            range=self.original_range,
            approved=self.approved,
        )


Difference = Finding
Change = Finding
RedactionFinding = Finding


class ReviewReport(object):
    """
    Result of a read-only redaction review.

    ``findings`` contains every reviewed change (approved and unapproved).
    ``violations`` is the subset that was not covered by an approval.
    """

    __slots__ = [
        "original_source",
        "redacted_source",
        "findings",
        "interfaces",
        "packets",
        "errors",
    ]

    def __init__(self, original_source, redacted_source):
        self.original_source = original_source
        self.redacted_source = redacted_source
        self.findings = []
        self.interfaces = {}
        self.packets = {}
        self.errors = []

    @property
    def changes(self):
        return self.findings

    @property
    def differences(self):
        return self.findings

    @property
    def issues(self):
        return self.violations

    @property
    def approved_redactions(self):
        return self.approved

    @property
    def unauthorized_changes(self):
        return self.violations

    @property
    def all_findings(self):
        return self.findings

    @property
    def original(self):
        return self.original_source

    @property
    def redacted(self):
        return self.redacted_source

    @property
    def violations(self):
        return [finding for finding in self.findings if not finding.approved]

    @property
    def unauthorized(self):
        return self.violations

    @property
    def unapproved(self):
        return self.violations

    @property
    def approved(self):
        return [finding for finding in self.findings if finding.approved]

    @property
    def approved_changes(self):
        return self.approved

    @property
    def approved_findings(self):
        return self.approved

    @property
    def unauthorized_findings(self):
        return self.violations

    @property
    def violation_count(self):
        return len(self.violations)

    @property
    def ok(self):
        return not self.violations

    @property
    def is_ok(self):
        return self.ok

    @property
    def passed(self):
        return self.ok

    @property
    def within_approval(self):
        return self.ok

    @property
    def is_within_approval(self):
        return self.ok

    @property
    def has_unauthorized_changes(self):
        return self.has_violations

    @property
    def is_clean(self):
        return self.ok

    @property
    def is_compliant(self):
        return self.ok

    @property
    def compliant(self):
        return self.ok

    @property
    def has_violations(self):
        return bool(self.violations)

    @property
    def summary(self):
        result = defaultdict(int)
        for finding in self.findings:
            result[finding.code] += 1
        return dict(result)

    def by_code(self, code):
        return [
            finding
            for finding in self.findings
            if code in finding.code_aliases
        ]

    def findings_by_code(self, code):
        return self.by_code(code)

    def by_field(self, field):
        field = _norm_field(field)
        return [finding for finding in self.findings if finding.field == field]

    def findings_by_field(self, field):
        return self.by_field(field)

    def for_packet(self, packet_id):
        return [
            finding
            for finding in self.findings
            if str(finding.packet_id) == str(packet_id)
        ]

    def __iter__(self):
        return iter(self.findings)

    def __len__(self):
        return len(self.findings)

    def __getitem__(self, index):
        if isinstance(index, str):
            return getattr(self, index)
        return self.findings[index]

    def get(self, key, default=None):
        try:
            return self[key]
        except (AttributeError, KeyError, IndexError):
            return default

    def keys(self):
        return [
            "original_source",
            "redacted_source",
            "findings",
            "violations",
            "summary",
            "ok",
        ]

    def __contains__(self, key):
        return key in self.keys()

    def items(self):
        return [(key, self[key]) for key in self.keys()]

    def __bool__(self):
        return self.ok

    __nonzero__ = __bool__

    def raise_for_violations(self):
        if self.violations:
            raise RedactionViolation(self)

    def to_dict(self):
        return {
            "original": self.original_source,
            "redacted": self.redacted_source,
            "ok": self.ok,
            "findings": [finding.to_dict() for finding in self.findings],
            "violations": [finding.to_dict() for finding in self.violations],
            "summary": self.summary,
        }

    def to_json(self, **kwargs):
        return json.dumps(self.to_dict(), **kwargs)

    def __repr__(self):
        return "<ReviewReport findings={} violations={} ok={}>".format(
            len(self.findings), len(self.violations), self.ok
        )


ComparisonReport = ReviewReport
ComparisonResult = ReviewReport
ReviewResult = ReviewReport
AuditReport = ReviewReport
DiffReport = ReviewReport
RedactionReview = ReviewReport


class RedactionViolation(Exception):
    """Raised when a review contains unauthorised changes."""

    def __init__(self, report):
        self.report = report
        super(RedactionViolation, self).__init__(
            "redaction review found {} unauthorised change(s)".format(
                len(report.violations)
            )
        )


def _approval_from_value(domain, packet_id, value):
    action = None
    fields = value
    if isinstance(value, dict):
        action = (
            value.get("action")
            or value.get("operation")
            or value.get("permission")
        )
        fields = value.get(
            "fields",
            value.get(
                "allowed_fields",
                value.get("field", value.get("field_name")),
            ),
        )
        if packet_id is None:
            packet_id = value.get(
                "packet_id",
                value.get("original_packet_id", value.get("packet")),
            )
    return Approval(
        domain=domain, packet_id=packet_id, fields=fields, action=action
    )


def _coerce_approvals(approvals):
    if approvals is None:
        return []
    if isinstance(approvals, Approval):
        return [approvals]
    if hasattr(approvals, "read") and not isinstance(approvals, (bytes, str)):
        approvals = json.load(approvals)
    if isinstance(approvals, str):
        text = approvals.strip()
        if not text:
            return []
        if os.path.isfile(text):
            with open(text, "r") as fp:
                approvals = json.load(fp)
        else:
            try:
                approvals = json.loads(text)
            except ValueError:
                approvals = [{"field": text}]
    if isinstance(approvals, dict):
        keys = set(approvals.keys())
        approval_keys = (
            set(Approval._DOMAIN_KEYS)
            | set(Approval._FIELD_KEYS)
            | set(Approval._PACKET_KEYS)
            | set(Approval._ACTION_KEYS)
            | {"fields", "allowed_fields"}
        )
        known_domains = set(_DOMAIN_ALIASES.values()) - {"*"}
        nested_domains = bool(keys) and all(
            isinstance(key, str)
            and _norm_domain(key) in known_domains
            and isinstance(approvals[key], dict)
            for key in keys
        )
        if keys & approval_keys and not nested_domains:
            return [Approval(approvals)]
        result = []
        for key, value in approvals.items():
            domain_key = _norm_domain(key) if isinstance(key, str) else None
            if domain_key in known_domains:
                if isinstance(value, dict):
                    for nested_key, nested_value in value.items():
                        result.append(
                            _approval_from_value(key, nested_key, nested_value)
                        )
                else:
                    result.append(_approval_from_value(key, None, value))
                continue
            if isinstance(key, str) and ":" in key:
                parts = key.split(":", 2)
                if _norm_domain(parts[0]) in known_domains:
                    packet_id = parts[1] if len(parts) > 1 else None
                    field = parts[2] if len(parts) > 2 else value
                    result.append(
                        Approval(
                            domain=parts[0],
                            packet_id=packet_id,
                            field=field,
                            action=value if len(parts) > 2 else None,
                        )
                    )
                    continue
            if isinstance(key, tuple):
                parts = list(key)
                tuple_field = parts[2] if len(parts) > 2 else None
                result.append(
                    Approval(
                        domain=parts[0] if len(parts) > 0 else None,
                        packet_id=parts[1] if len(parts) > 1 else None,
                        field=tuple_field,
                        fields=value if isinstance(value, (list, tuple)) else None,
                    )
                )
                if len(parts) <= 2 and not isinstance(value, (list, tuple)):
                    result[-1].fields = (_norm_field(value),)
                    result[-1].field = result[-1].fields[0]
                elif len(parts) > 2 and isinstance(value, str):
                    result[-1].action = value.strip().lower()
            elif isinstance(value, dict):
                item = dict(value)
                item.setdefault("packet_id", key)
                result.append(Approval(item))
            elif isinstance(value, (list, tuple, set, frozenset)):
                result.append(Approval(packet_id=key, fields=value))
            else:
                result.append(Approval(packet_id=key, field=value))
        return result
    result = []
    for item in approvals:
        if isinstance(item, Approval):
            result.append(item)
        elif isinstance(item, dict):
            result.append(Approval(item))
        elif isinstance(item, (list, tuple)):
            item = list(item)
            result.append(
                Approval(
                    domain=item[0] if len(item) > 0 else None,
                    packet_id=item[1] if len(item) > 1 else None,
                    field=item[2] if len(item) > 2 else None,
                    action=item[3] if len(item) > 3 else None,
                )
            )
        else:
            result.append(Approval(field=item))
    return result


def _range_for_option(span):
    if span is None:
        return None
    return SourceRange(span.start, span.end)


def _range_for_field(record, field):
    return _field_range(record, field)


def _same_interface(
    original_record, redacted_record, interface_map, reverse_map, context
):
    try:
        original_id = _raw_field(original_record, "interface_id")
        redacted_id = _raw_field(redacted_record, "interface_id")
    except (AttributeError, KeyError):
        return None
    mapped = interface_map.get(redacted_id)
    if mapped is not None:
        return int(mapped) == int(original_id)
    if len(reverse_map) == 0 and original_id == redacted_id:
        return True
    return False


def _interface_candidates(record, interface_map):
    candidates = set()
    if record is None:
        return candidates
    block = record.block
    interface_id = getattr(block, "interface_id", None)
    if interface_id is not None:
        candidates.add(str(interface_id))
        mapped = interface_map.get(interface_id)
        if mapped is not None:
            candidates.add(str(mapped))
    for kind in ("name", "mac", "eui", "description"):
        key = _interface_keys(record, kind)
        if key is not None:
            candidates.add(str(key[1]))
            candidates.add("{}:{}".format(key[0], key[1]))
    return candidates


def _add_finding(report, **kwargs):
    finding = Finding(**kwargs)
    report.findings.append(finding)
    return finding


def _approved_matches(
    approvals, domain, packet_record, redacted_record, field, action, context
):
    return _approval_lookup(
        approvals, domain, packet_record, redacted_record, field, action, context
    )


def _compare_field(
    report,
    approvals,
    original_record,
    redacted_record,
    field,
    original_value,
    redacted_value,
    context,
    action="modified",
):
    if original_value == redacted_value:
        return
    if _normalise_value(original_value) == _normalise_value(redacted_value):
        return
    domain = original_record.domain
    field_name = _norm_field(field)
    packet_id = None
    if domain == "packet":
        packet_id = packet_identifier(original_record)
    approval = _approved_matches(
        approvals,
        domain,
        original_record,
        redacted_record,
        field_name,
        action,
        context,
    )
    approved = approval is not None
    if approved:
        code = "approved_change"
        severity = "info"
    elif field_name in PRESERVATION_FIELDS or _norm_field(field) in PRESERVATION_FIELDS:
        code = "preservation_field_changed"
        severity = "error"
    else:
        code = "unauthorized_change"
        severity = "error"
    _add_finding(
        report,
        code=code,
        severity=severity,
        domain=domain,
        field=field_name,
        packet_id=packet_id,
        section_index=original_record.section_index,
        original_range=_range_for_field(original_record, field_name),
        redacted_range=_range_for_field(redacted_record, field_name),
        original_value_range=_range_for_field(original_record, field_name),
        redacted_value_range=_range_for_field(redacted_record, field_name),
        block_range=original_record.block_range,
        original_block_range=original_record.block_range,
        redacted_block_range=redacted_record.block_range,
        original_block_index=original_record.index,
        redacted_block_index=redacted_record.index,
        original_value=original_value,
        redacted_value=redacted_value,
        approved=approved,
        action=action,
        message=(
            "{} change to {}.{} is covered by an approval".format(
                action, domain, field_name
            )
            if approved
            else "{} change to {}.{} is not covered by an approval".format(
                action, domain, field_name
            )
        ),
    )


def _compare_options(
    report, approvals, original_record, redacted_record, context
):
    original_by_code = _options_by_code(original_record)
    redacted_by_code = _options_by_code(redacted_record)
    codes = sorted(set(original_by_code) | set(redacted_by_code))
    for code in codes:
        original_spans = original_by_code.get(code, [])
        redacted_spans = redacted_by_code.get(code, [])
        used_original = set()
        used_redacted = set()
        for oi, original_span in enumerate(original_spans):
            original_value = _normalise_value(original_span.value)
            for ri, redacted_span in enumerate(redacted_spans):
                if ri in used_redacted:
                    continue
                if _normalise_value(redacted_span.value) == original_value:
                    used_original.add(oi)
                    used_redacted.add(ri)
                    break
        remaining_original = [
            index for index in range(len(original_spans)) if index not in used_original
        ]
        remaining_redacted = [
            index for index in range(len(redacted_spans)) if index not in used_redacted
        ]
        changes = []
        paired = 0
        for oi, ri in zip(remaining_original, remaining_redacted):
            changes.append((original_spans[oi], redacted_spans[ri], "modified"))
            paired += 1
        for oi in remaining_original[paired:]:
            changes.append((original_spans[oi], None, "deleted"))
        for ri in remaining_redacted[paired:]:
            changes.append((None, redacted_spans[ri], "added"))
        for original_span, redacted_span, action in changes:
            if action == "deleted":
                field = _option_field_name(original_span)
                original_value = original_span.value
                redacted_value = None
            elif action == "added":
                field = _option_field_name(redacted_span)
                original_value = None
                redacted_value = redacted_span.value
            else:
                field = _option_field_name(original_span)
                original_value = original_span.value
                redacted_value = redacted_span.value
            domain = original_record.domain
            packet_id = (
                packet_identifier(original_record) if domain == "packet" else None
            )
            approval = _approved_matches(
                approvals,
                domain,
                original_record,
                redacted_record,
                field,
                action,
                context,
            )
            approved = approval is not None
            if approved:
                code_name = (
                    "approved_redaction" if action == "deleted" else "approved_change"
                )
                severity = "info"
            elif action == "deleted" and field == "opt_comment":
                code_name = "unauthorized_comment_deletion"
                severity = "error"
            elif field in PRESERVATION_FIELDS or field in (
                "epb_hash",
                "pack_hash",
            ):
                code_name = "preservation_field_changed"
                severity = "error"
            else:
                code_name = "unauthorized_change"
                severity = "error"
            _add_finding(
                report,
                code=code_name,
                severity=severity,
                domain=domain,
                field=field,
                packet_id=packet_id,
                section_index=original_record.section_index,
                original_range=_range_for_option(original_span),
                redacted_range=_range_for_option(redacted_span),
                original_value_range=(
                    SourceRange(original_span.value_start, original_span.value_end)
                    if original_span is not None
                    else None
                ),
                redacted_value_range=(
                    SourceRange(redacted_span.value_start, redacted_span.value_end)
                    if redacted_span is not None
                    else None
                ),
                block_range=original_record.block_range,
                original_block_range=original_record.block_range,
                redacted_block_range=redacted_record.block_range,
                original_block_index=original_record.index,
                redacted_block_index=redacted_record.index,
                original_value=original_value,
                redacted_value=redacted_value,
                approved=approved,
                action=action,
                message=(
                    "{} of {}.{} is covered by an approval".format(
                        action, domain, field
                    )
                    if approved
                    else "{} of {}.{} is not covered by an approval".format(
                        action, domain, field
                    )
                ),
            )


def _compare_pair(report, approvals, original_record, redacted_record, context):
    original_fields = [item[0] for item in getattr(original_record.block, "schema", [])]
    redacted_fields = [item[0] for item in getattr(redacted_record.block, "schema", [])]
    if original_fields != redacted_fields:
        _add_finding(
            report,
            code="block_shape_changed",
            severity="error",
            domain=original_record.domain,
            field="schema",
            packet_id=(
                packet_identifier(original_record)
                if original_record.domain == "packet"
                else None
            ),
            section_index=original_record.section_index,
            original_range=original_record.block_range,
            redacted_range=redacted_record.block_range,
            block_range=original_record.block_range,
            original_block_range=original_record.block_range,
            redacted_block_range=redacted_record.block_range,
            original_block_index=original_record.index,
            redacted_block_index=redacted_record.index,
            original_value=original_fields,
            redacted_value=redacted_fields,
            approved=False,
            message="block type/shape changed",
        )
        return
    for field in original_fields:
        if field == "options":
            continue
        if field == "interface_id" and isinstance(
            original_record.block, (blocks.BasePacketBlock, blocks.InterfaceStatistics)
        ):
            same = _same_interface(
                original_record,
                redacted_record,
                context["interface_map"],
                context["reverse_interface_map"],
                context,
            )
            if same:
                continue
        original_value = _raw_field(original_record, field)
        redacted_value = _raw_field(redacted_record, field)
        _compare_field(
            report,
            approvals,
            original_record,
            redacted_record,
            field,
            original_value,
            redacted_value,
            context,
        )
    _compare_options(report, approvals, original_record, redacted_record, context)


def _packet_count_by_interface(records, interface_map=None):
    counts = defaultdict(int)
    for record in records:
        if not isinstance(record.block, blocks.BasePacketBlock):
            continue
        interface_id = getattr(record.block, "interface_id", 0)
        if interface_map is not None:
            interface_id = interface_map.get(interface_id, interface_id)
        counts[interface_id] += 1
    return counts


def _check_packet_metadata(
    report, approvals, original_record, redacted_record, context
):
    original_block = original_record.block
    redacted_block = redacted_record.block
    packet_id = packet_identifier(original_record)
    original_data_len = len(getattr(original_block, "packet_data", b"") or b"")
    redacted_data_len = len(getattr(redacted_block, "packet_data", b"") or b"")
    original_captured = None
    redacted_captured = None
    if (
        hasattr(original_block, "_decoded")
        and "captured_len" in original_block._decoded
    ):
        original_captured = original_block._decoded["captured_len"]
    if (
        hasattr(redacted_block, "_decoded")
        and "captured_len" in redacted_block._decoded
    ):
        redacted_captured = redacted_block._decoded["captured_len"]
    original_packet_len = int(_raw_field(original_record, "packet_len") or 0)
    redacted_packet_len = int(_raw_field(redacted_record, "packet_len") or 0)
    overclaims = []
    if redacted_captured is not None and redacted_captured > original_data_len:
        overclaims.append(
            ("captured_len", redacted_captured, original_data_len)
        )
    if (
        original_captured is not None
        and redacted_captured is not None
        and redacted_captured > original_captured
    ):
        overclaims.append(
            ("captured_len", redacted_captured, original_captured)
        )
    if redacted_packet_len > original_packet_len and original_packet_len > 0:
        overclaims.append(
            ("packet_len", redacted_packet_len, original_packet_len)
        )
    if redacted_captured is not None and redacted_packet_len:
        if redacted_captured > redacted_packet_len:
            overclaims.append(
                ("captured_len", redacted_captured, redacted_packet_len)
            )
    if redacted_data_len < original_data_len and redacted_captured is not None:
        if redacted_captured >= original_data_len:
            overclaims.append(
                ("captured_len", redacted_captured, redacted_data_len)
            )
    unique_overclaims = {}
    for field, claimed, observed in overclaims:
        field_name = _norm_field(field)
        previous = unique_overclaims.get(field_name)
        if previous is None or observed < previous[1]:
            unique_overclaims[field_name] = (claimed, observed)
    for field_name, (claimed, observed) in unique_overclaims.items():
        approval = _approved_matches(
            approvals,
            original_record.domain,
            original_record,
            redacted_record,
            field_name,
            "modified",
            context,
        )
        existing = [
            finding
            for finding in report.findings
            if finding.original_block_index == original_record.index
            and finding.field == field_name
            and finding.redacted_value == _raw_field(redacted_record, field_name)
        ]
        if existing and not existing[0].approved:
            existing[0].overclaims = True
        _add_finding(
            report,
            code="metadata_overclaim",
            severity="error",
            domain=original_record.domain,
            field=field_name,
            packet_id=packet_id,
            section_index=original_record.section_index,
            original_range=_range_for_field(original_record, field_name),
            redacted_range=_range_for_field(redacted_record, field_name),
            block_range=original_record.block_range,
            original_block_range=original_record.block_range,
            redacted_block_range=redacted_record.block_range,
            original_block_index=original_record.index,
            redacted_block_index=redacted_record.index,
            original_value=observed,
            redacted_value=claimed,
            approved=approval is not None,
            action="modified",
            message=(
                "packet metadata {} claims {} but only {} observation(s) remain".format(
                    field_name, claimed, observed
                )
            ),
            overclaims=True,
        )


def _check_statistics(
    report,
    approvals,
    original_section,
    redacted_section,
    interface_map,
    context,
):
    original_counts = _packet_count_by_interface(original_section)
    redacted_counts = _packet_count_by_interface(redacted_section, interface_map)
    original_stats = [
        record
        for record in original_section
        if isinstance(record.block, blocks.InterfaceStatistics)
    ]
    redacted_stats = [
        record
        for record in redacted_section
        if isinstance(record.block, blocks.InterfaceStatistics)
    ]
    original_unused = set(range(len(original_stats)))
    redacted_unused = set(range(len(redacted_stats)))
    pairs = []
    for ri, rrec in enumerate(redacted_stats):
        rid = _raw_field(rrec, "interface_id")
        mapped = interface_map.get(rid, rid)
        for oi, orec in enumerate(original_stats):
            if oi not in original_unused:
                continue
            oid = _raw_field(orec, "interface_id")
            if oid == mapped:
                original_unused.discard(oi)
                redacted_unused.discard(ri)
                pairs.append((orec, rrec))
                break
    for oi, ri in zip(sorted(original_unused), sorted(redacted_unused)):
        pairs.append((original_stats[oi], redacted_stats[ri]))
    for orec, rrec in pairs:
        interface_id = _raw_field(orec, "interface_id")
        retained = redacted_counts.get(interface_id, 0)
        observed = original_counts.get(interface_id, 0)
        original_spans = _options_by_code(orec)
        redacted_spans = _options_by_code(rrec)
        for code in sorted(set(original_spans) | set(redacted_spans)):
            spans = redacted_spans.get(code) or original_spans.get(code)
            name = _option_field_name(spans[0])
            if name not in _COUNT_OPTIONS:
                continue
            redacted_span = redacted_spans.get(code, [None])[0]
            original_span = original_spans.get(code, [None])[0]
            if redacted_span is None:
                continue
            try:
                claimed = int(redacted_span.value)
            except (TypeError, ValueError):
                continue
            original_claimed = None
            if original_span is not None:
                try:
                    original_claimed = int(original_span.value)
                except (TypeError, ValueError):
                    original_claimed = None
            overclaim = False
            observed_limit = observed
            if retained < observed:
                observed_limit = retained
            if claimed > observed_limit:
                overclaim = True
            if original_claimed is not None and claimed > original_claimed:
                overclaim = True
            if not overclaim:
                continue
            approval = _approved_matches(
                approvals,
                "interface_statistics",
                orec,
                rrec,
                name,
                "modified",
                context,
            )
            existing = [
                finding
                for finding in report.findings
                if finding.original_block_index == orec.index
                and finding.field == name
            ]
            if existing and not existing[0].approved:
                existing[0].overclaims = True
            _add_finding(
                report,
                code="count_overclaim",
                severity="error",
                domain="interface_statistics",
                field=name,
                packet_id=None,
                section_index=orec.section_index,
                original_range=_range_for_option(original_span),
                redacted_range=_range_for_option(redacted_span),
                block_range=orec.block_range,
                original_block_range=orec.block_range,
                redacted_block_range=rrec.block_range,
                original_block_index=orec.index,
                redacted_block_index=rrec.index,
                original_value=original_claimed,
                redacted_value=claimed,
                approved=approval is not None,
                action="modified",
                message=(
                    (
                        "statistic {} claims {} observation(s), "
                        "but at most {} remain"
                    ).format(name, claimed, observed_limit)
                ),
                overclaims=True,
            )


def compare_files(original, redacted, approvals=None, **kwargs):
    """
    Compare an original pcap-ng file with its redacted copy.

    :param original: path, bytes, or readable file-like object for the original.
    :param redacted: path, bytes, or readable file-like object for the copy.
    :param approvals: an iterable of :class:`Approval` objects or mappings.
    :return: :class:`ReviewReport`
    """

    for alias in ("approval", "grants", "authorizations", "authorisations"):
        if alias in kwargs:
            extra = kwargs.pop(alias)
            approvals = list(_coerce_approvals(approvals))
            approvals += list(_coerce_approvals(extra))
    if kwargs:
        unexpected = set(kwargs) - {"strict", "read_only", "readonly"}
        if unexpected:
            raise TypeError(
                "unexpected keyword argument(s): {}".format(
                    ", ".join(sorted(unexpected))
                )
            )
    original_document = _scan(original)
    redacted_document = _scan(redacted)
    grants = _coerce_approvals(approvals)
    report = ReviewReport(original_document.source, redacted_document.source)
    for error in original_document.errors + redacted_document.errors:
        report.errors.append(error)

    section_count = max(
        len(original_document.sections), len(redacted_document.sections)
    )
    for section_index in range(section_count):
        original_section = (
            original_document.sections[section_index]
            if section_index < len(original_document.sections)
            else []
        )
        redacted_section = (
            redacted_document.sections[section_index]
            if section_index < len(redacted_document.sections)
            else []
        )
        (
            interface_pairs,
            interface_map,
            reverse_map,
            missing_interfaces,
            added_interfaces,
        ) = _match_interfaces(original_section, redacted_section)
        report.interfaces[section_index] = {
            "pairs": interface_pairs,
            "map": interface_map,
            "reverse": reverse_map,
        }
        context = {
            "section_index": section_index,
            "interface_map": interface_map,
            "reverse_interface_map": reverse_map,
            "interface_candidates": set(),
        }

        for original_record, redacted_record in interface_pairs:
            context["interface_candidates"] = _interface_candidates(
                original_record, interface_map
            )
            _compare_pair(
                report, grants, original_record, redacted_record, context
            )
        for record in missing_interfaces:
            _add_finding(
                report,
                code="block_removed",
                severity="error",
                domain="interface",
                field="interface",
                original_range=record.block_range,
                block_range=record.block_range,
                original_block_range=record.block_range,
                original_block_index=record.index,
                approved=False,
                message="interface block was removed",
            )
        for record in added_interfaces:
            _add_finding(
                report,
                code="block_added",
                severity="error",
                domain="interface",
                field="interface",
                redacted_range=record.block_range,
                block_range=record.block_range,
                redacted_block_range=record.block_range,
                redacted_block_index=record.index,
                approved=False,
                message="interface block was added",
            )

        original_packets = [
            record
            for record in original_section
            if isinstance(record.block, blocks.BasePacketBlock)
        ]
        redacted_packets = [
            record
            for record in redacted_section
            if isinstance(record.block, blocks.BasePacketBlock)
        ]
        packet_pairs, missing_packets, added_packets = _match_packets(
            original_packets, redacted_packets
        )
        report.packets[section_index] = packet_pairs
        for original_record, redacted_record in packet_pairs:
            context["interface_candidates"] = _interface_candidates(
                original_record, interface_map
            )
            _compare_pair(
                report, grants, original_record, redacted_record, context
            )
            _check_packet_metadata(
                report, grants, original_record, redacted_record, context
            )
        for record in missing_packets:
            _add_finding(
                report,
                code="packet_removed",
                severity="error",
                domain="packet",
                field="packet",
                packet_id=packet_identifier(record),
                section_index=section_index,
                original_range=record.block_range,
                block_range=record.block_range,
                original_block_range=record.block_range,
                original_block_index=record.index,
                approved=False,
                message="packet block was removed",
            )
        for record in added_packets:
            _add_finding(
                report,
                code="packet_added",
                severity="error",
                domain="packet",
                field="packet",
                packet_id=packet_identifier(record),
                section_index=section_index,
                redacted_range=record.block_range,
                block_range=record.block_range,
                redacted_block_range=record.block_range,
                redacted_block_index=record.index,
                approved=False,
                message="packet block was added",
            )

        other_types = (
            blocks.InterfaceStatistics,
            blocks.NameResolution,
            blocks.UnknownBlock,
        )
        original_other = [
            record
            for record in original_section
            if isinstance(record.block, other_types)
        ]
        redacted_other = [
            record
            for record in redacted_section
            if isinstance(record.block, other_types)
        ]
        other_pairs, missing_other, added_other = _match_records(
            original_other,
            redacted_other,
            lambda record: (
                type(record.block).__name__,
                record.block_type
                if isinstance(record.block, blocks.UnknownBlock)
                else None,
            ),
        )
        for original_record, redacted_record in other_pairs:
            _compare_pair(
                report, grants, original_record, redacted_record, context
            )
        for record in missing_other:
            _add_finding(
                report,
                code="block_removed",
                severity="error",
                domain=record.domain,
                field="block",
                section_index=section_index,
                original_range=record.block_range,
                block_range=record.block_range,
                original_block_range=record.block_range,
                original_block_index=record.index,
                approved=False,
                message="{} block was removed".format(type(record.block).__name__),
            )
        for record in added_other:
            _add_finding(
                report,
                code="block_added",
                severity="error",
                domain=record.domain,
                field="block",
                section_index=section_index,
                redacted_range=record.block_range,
                block_range=record.block_range,
                redacted_block_range=record.block_range,
                redacted_block_index=record.index,
                approved=False,
                message="{} block was added".format(type(record.block).__name__),
            )
        _check_statistics(
            report,
            grants,
            original_section,
            redacted_section,
            interface_map,
            context,
        )

    report.findings.sort(
        key=lambda finding: (
            finding.original_start is None,
            finding.original_start or 0,
            finding.redacted_start or 0,
            finding.code,
        )
    )
    return report


def compare(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def compare_streams(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files` suitable for file-like objects."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def compare_readonly(original, redacted, approvals=None, **kwargs):
    """Explicit read-only alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def review(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def review_redaction(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def audit(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def audit_redaction(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def compare_pcapng(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def compare_read_only(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def read_only_compare(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def review_files(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def audit_files(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def check_redaction(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def diff(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


class PcapngComparer(object):
    """Small stateful wrapper around :func:`compare_files`."""

    __slots__ = ["approvals"]

    def __init__(self, approvals=None):
        self.approvals = approvals

    def compare(self, original, redacted, approvals=None, **kwargs):
        grants = self.approvals if approvals is None else approvals
        return compare_files(original, redacted, approvals=grants, **kwargs)

    __call__ = compare


PcapngReviewer = PcapngComparer
RedactionReviewer = PcapngComparer
RedactionComparator = PcapngComparer


def compare_pcapng_files(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def review_pcapng(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def audit_pcapng(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def compare_captures(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def review_captures(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def audit_captures(original, redacted, approvals=None, **kwargs):
    """Alias for :func:`compare_files`."""

    return compare_files(original, redacted, approvals=approvals, **kwargs)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only comparison of a pcap-ng original and redacted copy."
    )
    parser.add_argument("original")
    parser.add_argument("redacted")
    parser.add_argument(
        "--approval",
        action="append",
        default=[],
        help="approval as JSON (repeatable)",
    )
    parser.add_argument(
        "--approval-file",
        help="JSON file containing one approval or a list of approvals",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    parser.add_argument(
        "--fail-on-violation",
        action="store_true",
        help="exit with status 1 when unauthorised changes are found",
    )
    args = parser.parse_args(argv)
    approvals = list(args.approval)
    if args.approval_file:
        with open(args.approval_file, "r") as fp:
            loaded = json.load(fp)
        if isinstance(loaded, dict):
            approvals.append(loaded)
        else:
            approvals.extend(loaded)
    report = compare_files(args.original, args.redacted, approvals=approvals)
    if args.json:
        print(report.to_json(indent=2, sort_keys=True))
    else:
        print(
            "{} finding(s), {} violation(s)".format(
                len(report.findings), len(report.violations)
            )
        )
        for finding in report.findings:
            print(
                "{status} {code} {domain}.{field} original_range={range}".format(
                    status=finding.status,
                    code=finding.code,
                    domain=finding.domain,
                    field=finding.field,
                    range=finding.original_range,
                )
            )
    if args.fail_on_violation and report.violations:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

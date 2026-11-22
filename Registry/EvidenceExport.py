"""
Read-only registry evidence export built on top of python-registry.

Delivery tools sometimes pass registry values to other teams as plain JSON
values.  That loses the distinction between a genuinely empty record and an
empty string whose terminator was repaired by a reader.  This module exports
each value with evidence that can be checked independently:

  * the key path and value name,
  * the declared data type (raw numeric code and symbolic name),
  * the declared data length, the storage location (inline / data cell) and
    the absolute file offset where the raw bytes were observed,
  * the raw bytes themselves (hex + sha256), whose length equals the declared
    length and can be re-hashed by the recipient,
  * a parsed view produced by python-registry, kept separate from the evidence,
  * and a restoration conclusion that only claims an exact round trip when the
    bytes re-encode to the observed payload.  Values with bad encoding, a
    missing terminator or a type/length mismatch are reported as
    ``range_only``: only the observed byte range is asserted.

The exporter only opens files for reading and never writes to the hive.
"""
from __future__ import print_function

import binascii
import hashlib
import json
import struct

NUL2 = struct.pack("<H", 0)

from . import Registry
from . import RegistryParse


RESTORED = "restored"
EMPTY_RECORD = "empty_record"
RANGE_ONLY = "range_only"
RAW_CARRY = "raw_carry"

STRING_TYPES = (RegistryParse.RegSZ, RegistryParse.RegExpandSZ)
EXPECTED_SIZE = {
    RegistryParse.RegDWord: 4,
    RegistryParse.RegQWord: 8,
    RegistryParse.RegBigEndian: 4,
}


def _type_name(data_type):
    """Return the symbolic type name, including for unknown type codes."""
    name = RegistryParse.VKRecord.data_type_str.__doc__  # noqa: SF01
    # data_type_str() itself handles the "Unknown type: 0x.." case.
    dummy = _TypeProbe(data_type)
    return dummy.data_type_str()


class _TypeProbe(RegistryParse.VKRecord):
    """VKRecord.data_type_str() only depends on data_type(); reuse the map."""
    def __init__(self, data_type):
        self._data_type = data_type

    def data_type(self):
        return self._data_type


def _has_lone_surrogate(text):
    for char in text:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            return True
    return False


def _decode_utf16le(raw):
    """Best-effort UTF-16LE decode, returning (text, error_message)."""
    try:
        if len(raw) % 2:
            return raw.decode("utf-16le", errors="replace"), "odd_byte_length"
        return raw.decode("utf-16le"), None
    except UnicodeDecodeError as exc:
        return raw.decode("utf-16le", errors="replace"), "decode_error: %s" % exc


def _reader_view(value):
    """Safely collect the python-registry parsed view for comparison."""
    try:
        parsed = value.value()
    except Exception as exc:  # noqa: BLE001 - reader failures are evidence
        return None, "%s: %s" % (exc.__class__.__name__, exc)
    return _json_safe(parsed), None


def _json_safe(obj):
    """Convert bytes/datetime/other values into JSON-serialisable views."""
    if isinstance(obj, bytes):
        return {"kind": "bytes", "hex": binascii.hexlify(obj).decode("ascii")}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(item) for item in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return {"kind": obj.__class__.__name__, "repr": repr(obj)}


def _independent_raw_slice(vk):
    """
    Slice the value data directly from the hive buffer using only declared
    metadata, so the result length always equals the declared data length.
    This avoids reader behaviour such as padding inline strings to four bytes.
    """
    declared = vk.data_length()
    raw_length_field = vk.raw_data_length()
    inline = raw_length_field < 5 or raw_length_field >= 0x80000000
    if inline:
        # Inline payload lives in the four VK bytes at record offset 0x8.
        start = vk.offset() + 0x8
    else:
        # A separate data cell is [int32 size][payload]; data_offset() points
        # at the cell start, so the observed payload begins four bytes later.
        start = vk.data_offset() + 4
    return bytes(vk._buf[start:start + declared]), inline, start


def _evaluate_string(raw):
    """Evaluate REG_SZ / REG_EXPAND_SZ payloads."""
    anomalies = []
    declared = len(raw)
    if declared == 0:
        return {
            "restoration": EMPTY_RECORD,
            "parsed": "",
            "anomalies": ["zero_length_record"],
            "round_trip_verified": False,
        }
    if declared % 2:
        anomalies.append("odd_byte_length")
    decoded, decode_error = _decode_utf16le(raw)
    if decode_error:
        anomalies.append(decode_error)
    if _has_lone_surrogate(decoded):
        anomalies.append("lone_surrogate")
    terminator_ok = declared >= 2 and raw[-2:] == b"\x00\x00"
    if not terminator_ok:
        anomalies.append("missing_terminator")
    # The payload excludes one trailing NUL terminator.
    payload = decoded[:-1] if terminator_ok else decoded
    reencoded = payload.encode("utf-16le") + b"\x00\x00"
    round_trip = (not anomalies) and reencoded == raw
    if round_trip:
        restoration = RESTORED
    else:
        restoration = RANGE_ONLY
    return {
        "restoration": restoration,
        "parsed": payload,
        "anomalies": anomalies,
        "round_trip_verified": round_trip,
    }


def _evaluate_multi_sz(raw):
    """Evaluate REG_MULTI_SZ payloads."""
    anomalies = []
    declared = len(raw)
    if declared == 0:
        return {
            "restoration": EMPTY_RECORD,
            "parsed": [],
            "anomalies": ["zero_length_record"],
            "round_trip_verified": False,
        }
    if declared % 2:
        anomalies.append("odd_byte_length")
    decoded, decode_error = _decode_utf16le(raw)
    if decode_error:
        anomalies.append(decode_error)
    parts = decoded.split("\x00")
    # A canonical REG_MULTI_SZ ends in two NULs, so splitting yields a
    # trailing empty element that is not part of the logical list.
    terminator_ok = declared >= 2 and raw[-2:] == b"\x00\x00"
    if not terminator_ok:
        anomalies.append("missing_terminator")
        logical = parts
    else:
        # The double NUL terminator decodes to trailing empty elements; drop
        # every terminating empty element so only the logical strings remain.
        logical = list(parts)
        while logical and logical[-1] == "":
            logical.pop()
    if any(_has_lone_surrogate(part) for part in logical):
        anomalies.append("lone_surrogate")
    # Each logical string carries its own terminating NUL code unit,
    # and the sequence is closed by one additional NUL (double NUL end).
    rebuilt = b"".join(part.encode("utf-16le") + NUL2 for part in logical)
    if terminator_ok:
        rebuilt += NUL2
    round_trip = (not anomalies) and rebuilt == raw
    return {
        "restoration": RESTORED if round_trip else RANGE_ONLY,
        "parsed": logical,
        "anomalies": anomalies,
        "round_trip_verified": round_trip,
    }


def _evaluate_fixed_numeric(raw, data_type, structure):
    """Evaluate fixed-width numeric types (DWORD / QWORD / big endian)."""
    import struct

    expected = EXPECTED_SIZE[data_type]
    anomalies = []
    if len(raw) != expected:
        anomalies.append("declared_length_mismatch:expected_%d" % expected)
        return {
            "restoration": RANGE_ONLY,
            "parsed": None,
            "anomalies": anomalies,
            "round_trip_verified": False,
        }
    if data_type == RegistryParse.RegBigEndian:
        value = struct.unpack(">I", raw)[0]
        packed = struct.pack(">I", value)
    elif data_type == RegistryParse.RegQWord:
        value = struct.unpack("<Q", raw)[0]
        packed = struct.pack("<Q", value)
    else:
        value = struct.unpack("<I", raw)[0]
        packed = struct.pack("<I", value)
    round_trip = packed == raw
    return {
        "restoration": RESTORED if round_trip else RANGE_ONLY,
        "parsed": value,
        "anomalies": anomalies,
        "round_trip_verified": round_trip,
    }


def _evaluate_value(vk, value, key_path):
    raw, inline, data_start = _independent_raw_slice(vk)
    data_type = vk.data_type()
    declared = vk.data_length()
    anomalies = []

    if data_type in STRING_TYPES:
        conclusion = _evaluate_string(raw)
    elif data_type == RegistryParse.RegMultiSZ:
        conclusion = _evaluate_multi_sz(raw)
    elif data_type in EXPECTED_SIZE:
        conclusion = _evaluate_fixed_numeric(raw, data_type, None)
    elif data_type in (RegistryParse.RegBin, RegistryParse.RegNone):
        conclusion = {
            "restoration": RAW_CARRY if raw else EMPTY_RECORD,
            "parsed": _json_safe(raw),
            "anomalies": [] if raw else ["zero_length_record"],
            "round_trip_verified": bool(raw),
        }
    else:
        # Link / resource list / file time and other structural types: carry
        # the raw range; the reader may still provide a best-effort view.
        conclusion = {
            "restoration": RAW_CARRY,
            "parsed": None,
            "anomalies": ["structural_type_not_reencoded"],
            "round_trip_verified": False,
        }

    reader_parsed, reader_error = _reader_view(value)

    return {
        "key_path": key_path,
        "value_name": value.name(),
        "is_default": not vk.has_name(),
        "declared_type": {
            "code": data_type,
            "name": _type_name(data_type),
        },
        "storage": {
            "inline": inline,
            "vk_offset": vk.offset(),
            "data_offset": data_start,
        },
        "raw": {
            "declared_length": declared,
            "observed_length": len(raw),
            "hex": binascii.hexlify(raw).decode("ascii"),
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        "parsed_view": {
            "value": conclusion["parsed"],
            "restoration": conclusion["restoration"],
            "round_trip_verified": conclusion["round_trip_verified"],
            "anomalies": anomalies + conclusion["anomalies"],
        },
        "reader_view": {
            "value": reader_parsed,
            "error": reader_error,
        },
    }


def _walk(registry_key, sink):
    key_path = registry_key.path()
    for value in registry_key.values():
        sink.append(_evaluate_value(value._vkrecord, value, key_path))
    for subkey in registry_key.subkeys():
        _walk(subkey, sink)


def export_evidence(filelike_or_path):
    """
    Export read-only evidence for every value in a registry hive.

    Returns a plain dict suitable for ``json.dumps``.  The hive is opened with
    the read-based ``Registry`` interface and is never modified.
    """
    if hasattr(filelike_or_path, "read"):
        source = getattr(filelike_or_path, "name", "<stream>")
        filelike_or_path.seek(0)
        data = filelike_or_path.read()
        hive = Registry.Registry(__import__("io").BytesIO(data))
        digest = hashlib.sha256(data).hexdigest()
        size = len(data)
    else:
        source = filelike_or_path
        with open(filelike_or_path, "rb") as handle:
            data = handle.read()
        hive = Registry.Registry(filelike_or_path)
        digest = hashlib.sha256(data).hexdigest()
        size = len(data)

    root = hive.root()
    entries = []
    _walk(root, entries)
    return {
        "schema_version": 1,
        "source": {
            "path": source,
            "hive_name": hive.hive_name(),
            "file_size": size,
            "sha256": digest,
        },
        "root_key": root.path(),
        "value_count": len(entries),
        "values": entries,
    }


def export_evidence_json(filelike_or_path, indent=2):
    """Export evidence and return it directly as a JSON text string."""
    return dumps(export_evidence(filelike_or_path), indent=indent)


def dumps(evidence, indent=2):
    """Serialise an evidence document to JSON text."""
    return json.dumps(evidence, indent=indent, ensure_ascii=False, sort_keys=False)


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        description="Read-only registry evidence exporter (python-registry).")
    parser.add_argument("hive", help="path to a registry hive file")
    parser.add_argument("-o", "--output", help="write JSON here (default stdout)")
    args = parser.parse_args(argv)
    evidence = export_evidence(args.hive)
    text = dumps(evidence)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        print(text)


if __name__ == "__main__":
    main()

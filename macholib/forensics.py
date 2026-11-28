"""
Forensic excerpt verification for multi-architecture Mach-O files.

Mach-O stores two different kinds of file offsets and confusing them is a
common forensic error:

* **file coordinates** measure from the first byte of the file that was
  handed to the examiner (the *file header*, including the fat header of a
  universal binary).  This is what older tooling recorded.
* **slice coordinates** measure from the first byte of an individual
  ``Mach-O`` image inside the file.  Mach-O load commands (``fileoff``,
  section ``offset``, ...) use this coordinate system.

For a thin Mach-O both coordinate systems start at zero.  For a universal
(fat) binary they differ by the slice base recorded in the fat architecture
table.  An excerpt can therefore have exactly the same bytes and the same
digest at two places in a file, while belonging to only one slice.

This module verifies excerpt declarations against the slices discovered by
``macholib.MachO`` and never treats a digest match alone as proof of
ownership.  Every declaration is resolved to an explicit coordinate system,
an owning architecture and a per-segment byte count before the local bytes
are hashed.

The :func:`verify_excerpt` and :func:`verify_excerpts` helpers accept a
filename, an already loaded :class:`macholib.MachO.MachO` instance, or a
path-like object.  Declarations may be mappings or simple objects with
attributes.  :func:`verify_ledger` handles a mixed ledger whose rows may
each name their own file.  A small command line entry point is available as
``python -m macholib.forensics IMAGE LEDGER.json``.

Minimal declaration::

    {
        "id": "payload@0x200",
        "coordinate_system": "slice",
        "offset": 0x200,
        "length": 16,
        "digest": "<hex sha256>",
        "arch": "arm64",
    }

The returned :class:`VerificationResult` reports the resolved absolute and
slice-relative offsets, the owning slice, the per-segment lengths and, for
old *file coordinate* records, the reconstructed slice offset.
"""

from __future__ import print_function

import binascii
import hashlib
import os
import sys

from .mach_o import (
    CPU_TYPE_NAMES,
    LC_SEGMENT,
    LC_SEGMENT_64,
    get_cpu_subtype,
)

# Public coordinate system names.  The aliases accepted by the parser are
# listed in _COORDINATE_ALIASES.
COORDINATE_FILE = "file"
COORDINATE_SLICE = "slice"
COORDINATE_SYSTEMS = (COORDINATE_FILE, COORDINATE_SLICE)

# Backwards/alternate spellings used by callers.
FILE_COORDINATE = COORDINATE_FILE
SLICE_COORDINATE = COORDINATE_SLICE

# Verification outcomes.
STATUS_VERIFIED = "verified"
STATUS_AMBIGUOUS = "ambiguous"
STATUS_OWNERSHIP_MISMATCH = "ownership_mismatch"
STATUS_ARCHITECTURE_MISMATCH = "architecture_mismatch"
STATUS_DIGEST_MISMATCH = "digest_mismatch"
STATUS_SEGMENT_LENGTH_MISMATCH = "segment_length_mismatch"
STATUS_OUT_OF_BOUNDS = "out_of_bounds"
STATUS_COORDINATE_MISSING = "coordinate_missing"
STATUS_INVALID_DECLARATION = "invalid_declaration"
STATUS_UNVERIFIED = "unverified"

# Stable names used in ``missing_evidence``.
EVIDENCE_COORDINATE = "coordinate_system"
EVIDENCE_ARCHITECTURE = "owning_architecture"
EVIDENCE_SLICE_INDEX = "slice_index"
EVIDENCE_DIGEST = "digest"
EVIDENCE_OWNER_BYTES = "digest_in_declared_owning_slice"
EVIDENCE_SEGMENT_BOUNDARY = "segment_fileoff_filesize"

_MISSING = object()

_COORDINATE_ALIASES = {
    "file": COORDINATE_FILE,
    "files": COORDINATE_FILE,
    "file_header": COORDINATE_FILE,
    "fileheader": COORDINATE_FILE,
    "file-coordinate": COORDINATE_FILE,
    "file_coordinate": COORDINATE_FILE,
    "file_offset": COORDINATE_FILE,
    "fileoffset": COORDINATE_FILE,
    "absolute": COORDINATE_FILE,
    "fat": COORDINATE_FILE,
    "fat_file": COORDINATE_FILE,
    "old": COORDINATE_FILE,
    "legacy": COORDINATE_FILE,
    "offset_from_file": COORDINATE_FILE,
    "offset_from_file_header": COORDINATE_FILE,
    "slice": COORDINATE_SLICE,
    "slices": COORDINATE_SLICE,
    "slice_relative": COORDINATE_SLICE,
    "slice-relative": COORDINATE_SLICE,
    "slice_coordinate": COORDINATE_SLICE,
    "image": COORDINATE_SLICE,
    "image_relative": COORDINATE_SLICE,
    "macho": COORDINATE_SLICE,
    "relative": COORDINATE_SLICE,
    "new": COORDINATE_SLICE,
    "offset_from_slice": COORDINATE_SLICE,
}

_ARCH_ALIASES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86-64": "x86_64",
    "aarch64": "arm64",
    "arm64e": "arm64",
    "armv8": "arm64",
}

_DIGEST_KEYS = (
    ("sha256", "sha256"),
    ("sha1", "sha1"),
    ("sha512", "sha512"),
    ("md5", "md5"),
    ("blake2b", "blake2b"),
    ("blake2s", "blake2s"),
)


class ExcerptError(ValueError):
    """Raised for malformed excerpt declarations."""


class AmbiguousOffsetError(ExcerptError):
    """Raised when an offset cannot be mapped to exactly one slice."""

    def __init__(self, message, candidates=None, missing_evidence=None):
        ExcerptError.__init__(self, message)
        self.candidates = candidates or []
        self.missing_evidence = missing_evidence or []


def _as_int(value, field):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ExcerptError("%s must be an integer, got %r" % (field, value))


def _decode_name(value):
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode("ascii", "replace")
    return str(value).rstrip("\x00")


def _get(declaration, names, default=_MISSING):
    if isinstance(declaration, dict):
        for name in names:
            if name in declaration and declaration[name] is not None:
                return declaration[name]
        return default
    for name in names:
        if hasattr(declaration, name):
            value = getattr(declaration, name)
            if value is not None:
                return value
    return default


def _normalize_coordinate(value):
    if value is None:
        return None
    if value in (COORDINATE_FILE, COORDINATE_SLICE):
        return value
    key = str(value).strip().lower().replace(" ", "_").replace("-", "_")
    return _COORDINATE_ALIASES.get(key)


def _arch_spec(value):
    """Normalise an architecture declaration.

    Returns ``(cputype, cpusubtype, name)`` where any component can be None.
    """
    cputype = None
    cpusubtype = None
    name = None

    if value is None:
        return cputype, cpusubtype, name
    if isinstance(value, (tuple, list)):
        if len(value) >= 1 and value[0] is not None:
            try:
                cputype = _as_int(value[0], "arch cputype")
            except ExcerptError:
                cputype, cpusubtype, name = _arch_spec(value[0])
        if len(value) >= 2 and value[1] is not None:
            cpusubtype = _as_int(value[1], "arch cpusubtype")
        return cputype, cpusubtype, name
    if isinstance(value, dict) or hasattr(value, "cputype"):
        raw_type = _get(value, ("cputype", "cpu_type", "type"), None)
        raw_subtype = _get(value, ("cpusubtype", "cpu_subtype", "subtype"), None)
        raw_name = _get(value, ("name", "arch", "architecture"), None)
        if raw_type is not None:
            cputype = _as_int(raw_type, "arch cputype")
        if raw_subtype is not None:
            cpusubtype = _as_int(raw_subtype, "arch cpusubtype")
        if raw_name is not None:
            name = str(raw_name).strip().lower()
        return cputype, cpusubtype, name
    if isinstance(value, int):
        return value, None, None

    text = str(value).strip()
    if not text:
        return None, None, None
    if text.isdigit() or (
        text.lower().startswith("0x") and text[2:].strip() != ""
    ):
        return int(text, 0), None, None

    parts = text.replace("/", ":").split(":")
    text = parts[0].strip().lower()
    if len(parts) > 1 and parts[1].strip():
        cpusubtype = int(parts[1].strip(), 0)
    name = _ARCH_ALIASES.get(text, text)
    for cpu, cpu_name in CPU_TYPE_NAMES.items():
        if cpu_name.lower() == name:
            cputype = cpu
            break
    return cputype, cpusubtype, name


def _arch_matches(slice_record, spec):
    cputype, cpusubtype, name = spec
    if cputype is None and cpusubtype is None and name is None:
        return True
    if cputype is not None and cputype != slice_record.cputype:
        return False
    if cpusubtype is not None:
        if (cpusubtype & 0x0FFFFFFF) != (slice_record.cpusubtype & 0x0FFFFFFF):
            return False
    if name is not None and cputype is None:
        candidates = (slice_record.arch, slice_record.subtype)
        lowered = [str(item).lower() for item in candidates]
        if name not in lowered and name != slice_record.arch.lower():
            return False
    return True


def _arch_label(spec):
    if spec is None:
        return None
    cputype, cpusubtype, name = spec
    if name is None and cputype is not None:
        name = CPU_TYPE_NAMES.get(cputype, str(cputype))
    if name is None and cpusubtype is None:
        return None
    label = name or ""
    if cpusubtype is not None:
        label = (label + ":" + str(cpusubtype)) if label else str(cpusubtype)
    return label


class SegmentRecord(object):
    """A file-backed Mach-O segment, with offsets converted to file space."""

    def __init__(self, name, fileoff, filesize, slice_base, sections=None):
        self.name = name
        self.fileoff = int(fileoff)
        self.filesize = int(filesize)
        self.slice_base = int(slice_base)
        self.sections = sections or []

    @property
    def absolute_offset(self):
        return self.slice_base + self.fileoff

    @property
    def absolute_end(self):
        return self.absolute_offset + self.filesize

    def to_dict(self):
        return {
            "name": self.name,
            "fileoff": self.fileoff,
            "filesize": self.filesize,
            "absolute_offset": self.absolute_offset,
            "absolute_end": self.absolute_end,
            "sections": list(self.sections),
        }


class SliceRecord(object):
    """One Mach-O slice discovered by ``macholib.MachO``."""

    def __init__(self, index, offset, size, cputype, cpusubtype, segments=None):
        self.index = int(index)
        self.offset = int(offset)
        self.size = int(size)
        self.cputype = int(cputype)
        self.cpusubtype = int(cpusubtype)
        self.segments = segments or []
        self.arch = CPU_TYPE_NAMES.get(self.cputype, str(self.cputype))
        self.subtype = get_cpu_subtype(self.cputype, self.cpusubtype)

    @property
    def end(self):
        return self.offset + self.size

    def contains(self, absolute_offset, length=1):
        return (
            absolute_offset >= self.offset
            and absolute_offset + length <= self.end
        )

    def to_slice_offset(self, absolute_offset):
        return absolute_offset - self.offset

    def to_file_offset(self, slice_offset):
        return self.offset + slice_offset

    def to_dict(self):
        return {
            "index": self.index,
            "offset": self.offset,
            "size": self.size,
            "arch": self.arch,
            "subtype": self.subtype,
            "cputype": self.cputype,
            "cpusubtype": self.cpusubtype,
            "segments": [segment.to_dict() for segment in self.segments],
        }

    def __repr__(self):
        return "<SliceRecord #%d arch=%s offset=%d size=%d>" % (
            self.index,
            self.arch,
            self.offset,
            self.size,
        )


def slice_records(macho):
    """Build :class:`SliceRecord` objects from a parsed ``MachO`` instance."""
    slices = []
    for index, header in enumerate(macho.headers):
        mach_header = header.header
        segments = []
        for load_command, command, data in header.commands:
            if load_command.cmd not in (LC_SEGMENT, LC_SEGMENT_64):
                continue
            sections = []
            section_data = data if isinstance(data, list) else []
            for section in section_data:
                sections.append(
                    {
                        "sectname": _decode_name(section.sectname),
                        "segname": _decode_name(section.segname),
                        "offset": int(section.offset),
                        "size": int(section.size),
                    }
                )
            segments.append(
                SegmentRecord(
                    _decode_name(command.segname),
                    command.fileoff,
                    command.filesize,
                    header.offset,
                    sections=sections,
                )
            )
        slices.append(
            SliceRecord(
                index,
                header.offset,
                header.size,
                mach_header.cputype,
                mach_header.cpusubtype,
                segments,
            )
        )
    return slices


def _normalize_digest(declaration):
    digest = None
    algorithm = None
    for key, default_algorithm in _DIGEST_KEYS:
        value = _get(declaration, (key,), None)
        if value is not None:
            digest = value
            algorithm = default_algorithm
            break
    if digest is None:
        digest = _get(declaration, ("digest", "hash", "checksum"), None)
        algorithm = _get(
            declaration,
            ("digest_algorithm", "hash_algorithm", "algorithm"),
            None,
        )
    if digest is None:
        return None, algorithm or "sha256"
    if isinstance(digest, dict) or hasattr(digest, "value"):
        raw_algorithm = _get(digest, ("algorithm", "algo", "name"), None)
        raw_value = _get(digest, ("value", "hexdigest", "digest"), None)
        if raw_algorithm is not None:
            algorithm = raw_algorithm
        digest = raw_value
    if algorithm is None:
        algorithm = "sha256"
    algorithm = str(algorithm).strip().lower().replace("-", "")
    if isinstance(digest, bytes):
        try:
            digest = digest.decode("ascii")
        except UnicodeDecodeError:
            return binascii.hexlify(digest).decode("ascii"), algorithm
    digest = str(digest).strip()
    if ":" in digest:
        prefix, remainder = digest.split(":", 1)
        if prefix.strip():
            algorithm = prefix.strip().lower().replace("-", "")
            digest = remainder
    digest = digest.strip().replace(" ", "").lower()
    if not digest:
        return None, algorithm
    return digest, algorithm


def _normalize_parts(declaration, coordinate_system):
    raw_parts = _get(declaration, ("parts", "spans", "ranges"), _MISSING)
    if raw_parts is _MISSING:
        raw_parts = None
    if raw_parts is None:
        raw_parts = [declaration]
    elif isinstance(raw_parts, dict) or not isinstance(raw_parts, (list, tuple)):
        raw_parts = [raw_parts]

    parts = []
    for position, raw_part in enumerate(raw_parts):
        if isinstance(raw_part, (tuple, list)):
            if len(raw_part) != 2:
                raise ExcerptError(
                    "part %d must be an (offset, length) pair" % (position,)
                )
            raw_offset, raw_length = raw_part
            part_coordinate = coordinate_system
        else:
            raw_offset = _get(
                raw_part,
                ("offset", "slice_offset", "file_offset", "start", "begin"),
                _MISSING,
            )
            raw_length = _get(
                raw_part,
                ("length", "size", "byte_count", "nbytes", "len"),
                _MISSING,
            )
            part_coordinate = _get(
                raw_part,
                ("coordinate_system", "coordinate", "origin"),
                coordinate_system,
            )
            part_coordinate = _normalize_coordinate(part_coordinate)
            if _get(raw_part, ("absolute_offset",), None) is not None:
                raw_offset = _get(raw_part, ("absolute_offset",), None)
                part_coordinate = COORDINATE_FILE
        if raw_offset is _MISSING or raw_length is _MISSING:
            raise ExcerptError(
                "part %d needs both an offset and a length" % (position,)
            )
        length = _as_int(raw_length, "part length")
        if length < 0:
            raise ExcerptError("part length must not be negative")
        parts.append(
            {
                "index": position,
                "offset": _as_int(raw_offset, "part offset"),
                "length": length,
                "coordinate_system": part_coordinate,
            }
        )
    return parts


def _normalize_segment_lengths(declaration):
    expected = _get(
        declaration, ("segment_lengths", "per_segment_lengths"), None
    )
    if expected is None:
        return None
    if isinstance(expected, dict):
        return dict((str(k), int(v)) for k, v in expected.items())
    if isinstance(expected, (list, tuple)):
        normalized = {}
        for item in expected:
            if isinstance(item, dict):
                name = _get(item, ("name", "segment", "segname"), None)
                length = _get(item, ("length", "size"), None)
                if name is not None and length is not None:
                    normalized[str(name)] = int(length)
        if normalized:
            return normalized
    raise ExcerptError("segment_lengths must be a mapping or a list of mappings")


def _normalize_declaration(declaration, default_coordinate_system, default_arch):
    if isinstance(declaration, (str, bytes)):
        raise ExcerptError("an excerpt declaration must be a mapping or object")

    coordinate_system = _get(
        declaration,
        (
            "coordinate_system",
            "coordinate",
            "coordinate_type",
            "origin",
            "offset_from",
        ),
        None,
    )
    coordinate_system = _normalize_coordinate(coordinate_system)
    if coordinate_system is None:
        coordinate_system = _normalize_coordinate(default_coordinate_system)
    if coordinate_system is None:
        # Explicit booleans make old ledgers usable without guessing from the
        # numeric value (the value alone is exactly what caused the original
        # mixed-coordinate error).
        if _get(declaration, ("legacy", "old"), False):
            coordinate_system = COORDINATE_FILE
        elif _get(declaration, ("slice_relative", "new"), False):
            coordinate_system = COORDINATE_SLICE

    parts = _normalize_parts(declaration, coordinate_system)
    if coordinate_system is None and parts:
        part_coordinates = set(
            part["coordinate_system"] for part in parts if part["coordinate_system"]
        )
        if len(part_coordinates) == 1:
            coordinate_system = part_coordinates.pop()
        elif len(part_coordinates) > 1:
            coordinate_system = "mixed"
    declared_length = _get(
        declaration, ("length", "size", "byte_count", "nbytes"), None
    )
    total_length = sum(part["length"] for part in parts)
    if declared_length is not None:
        declared_length = _as_int(declared_length, "length")
        if declared_length != total_length:
            raise ExcerptError(
                "declared length %d does not match the %d bytes in parts"
                % (declared_length, total_length)
            )

    arch_value = _get(
        declaration, ("arch", "architecture", "cpu", "cputype"), None
    )
    if arch_value is None:
        arch_value = default_arch
    if arch_value is not None:
        subtype = _get(
            declaration, ("cpusubtype", "cpu_subtype", "subtype"), None
        )
        if subtype is not None and not (
            isinstance(arch_value, dict) or hasattr(arch_value, "cputype")
        ):
            arch_value = (arch_value, subtype)

    slice_index = _get(
        declaration, ("slice_index", "arch_index", "slice"), None
    )
    if isinstance(slice_index, str) and not slice_index.strip().isdigit():
        # Allow "slice:0" / "#0" forms without treating an architecture name
        # as an index.
        text = slice_index.strip().lstrip("#")
        if ":" in text:
            text = text.split(":", 1)[1]
        slice_index = text if text.isdigit() else None
    if slice_index is not None:
        slice_index = _as_int(slice_index, "slice_index")

    base_offset = _get(
        declaration,
        ("base_offset", "slice_base", "slice_file_offset", "slice_start"),
        None,
    )
    if base_offset is not None:
        base_offset = _as_int(base_offset, "base_offset")

    digest, digest_algorithm = _normalize_digest(declaration)
    return {
        "id": _get(declaration, ("id", "identifier", "name", "ref"), None),
        "coordinate_system": coordinate_system,
        "parts": parts,
        "length": total_length,
        "declared_length": declared_length,
        "digest": digest,
        "digest_algorithm": digest_algorithm,
        "arch": _arch_spec(arch_value) if arch_value is not None else None,
        "slice_index": slice_index,
        "base_offset": base_offset,
        "segment_lengths": _normalize_segment_lengths(declaration),
    }


def _read_range(fileobj, offset, length):
    if length == 0:
        return b""
    fileobj.seek(offset)
    return fileobj.read(length)


def _file_size(fileobj):
    here = fileobj.tell()
    fileobj.seek(0, os.SEEK_END)
    size = fileobj.tell()
    fileobj.seek(here)
    return size


def _segment_lengths_for_range(slice_record, absolute_offset, length):
    """Split ``[absolute_offset, absolute_offset + length)`` by segment."""
    result = {}
    covered = 0
    end = absolute_offset + length
    for segment in slice_record.segments:
        if segment.filesize <= 0:
            continue
        low = max(absolute_offset, segment.absolute_offset)
        high = min(end, segment.absolute_end)
        if high > low:
            result[segment.name] = result.get(segment.name, 0) + (high - low)
            covered += high - low
    if covered < length:
        result["<unmapped>"] = result.get("<unmapped>", 0) + (length - covered)
    return result


def _evaluate_slice(slice_record, parts, fileobj, file_size, algorithm):
    evaluation = {
        "slice_index": slice_record.index,
        "in_bounds": True,
        "parts": [],
        "problems": [],
        "segment_lengths": {},
        "bytes": [],
        "digest": None,
        "digest_match": False,
    }

    for part in parts:
        coordinate = part["coordinate_system"]
        if coordinate == COORDINATE_FILE:
            absolute_offset = part["offset"]
            slice_offset = slice_record.to_slice_offset(absolute_offset)
        elif coordinate == COORDINATE_SLICE:
            slice_offset = part["offset"]
            absolute_offset = slice_record.to_file_offset(slice_offset)
        else:
            evaluation["in_bounds"] = False
            evaluation["problems"].append(
                "part %d has no explicit coordinate system" % (part["index"],)
            )
            evaluation["parts"].append(
                {
                    "index": part["index"],
                    "coordinate_system": None,
                    "declared_offset": part["offset"],
                    "declared_length": part["length"],
                    "absolute_offset": None,
                    "slice_offset": None,
                    "available_length": 0,
                    "segment_lengths": {},
                }
            )
            continue

        length = part["length"]
        in_bounds = True
        if slice_offset < 0 or slice_offset + length > slice_record.size:
            in_bounds = False
            evaluation["problems"].append(
                "part %d [%d, %d) lies outside slice #%d [%d, %d)"
                % (
                    part["index"],
                    slice_offset,
                    slice_offset + length,
                    slice_record.index,
                    0,
                    slice_record.size,
                )
            )
        if absolute_offset < 0 or absolute_offset + length > file_size:
            in_bounds = False
            evaluation["problems"].append(
                "part %d [%d, %d) lies outside the file of %d bytes"
                % (
                    part["index"],
                    absolute_offset,
                    absolute_offset + length,
                    file_size,
                )
            )

        data = b""
        if in_bounds:
            data = _read_range(fileobj, absolute_offset, length)
            if len(data) != length:
                in_bounds = False
                evaluation["problems"].append(
                    "part %d only has %d of %d bytes available"
                    % (part["index"], len(data), length)
                )

        segment_lengths = _segment_lengths_for_range(
            slice_record, absolute_offset, length
        )
        for name, count in segment_lengths.items():
            evaluation["segment_lengths"][name] = (
                evaluation["segment_lengths"].get(name, 0) + count
            )

        if not in_bounds:
            evaluation["in_bounds"] = False
        else:
            evaluation["bytes"].append(data)
        evaluation["parts"].append(
            {
                "index": part["index"],
                "coordinate_system": coordinate,
                "declared_offset": part["offset"],
                "declared_length": length,
                "absolute_offset": absolute_offset,
                "slice_offset": slice_offset,
                "available_length": len(data),
                "segment_lengths": segment_lengths,
                "segments": sorted(
                    name for name in segment_lengths if name != "<unmapped>"
                ),
            }
        )

    if evaluation["in_bounds"] and len(evaluation["bytes"]) == len(parts):
        blob = b"".join(evaluation["bytes"])
        try:
            evaluation["digest"] = hashlib.new(algorithm, blob).hexdigest()
        except (ValueError, TypeError):
            evaluation["problems"].append(
                "unknown digest algorithm %r" % (algorithm,)
            )
    return evaluation


def _conversion(slice_record, evaluation):
    parts = []
    for part in evaluation["parts"]:
        if part["absolute_offset"] is None:
            continue
        parts.append(
            {
                "index": part["index"],
                "absolute_offset": part["absolute_offset"],
                "slice_offset": part["slice_offset"],
                "length": part["declared_length"],
                "segment_lengths": dict(part["segment_lengths"]),
            }
        )
    if not parts:
        return None
    return {
        "source_coordinate_system": None,
        "slice_index": slice_record.index,
        "slice_base": slice_record.offset,
        "slice_size": slice_record.size,
        "arch": slice_record.arch,
        "offset": parts[0]["slice_offset"],
        "absolute_offset": parts[0]["absolute_offset"],
        "length": sum(part["length"] for part in parts),
        "parts": parts,
    }


def _segment_lengths_equal(expected, actual):
    clean_actual = dict((k, v) for k, v in actual.items() if k != "<unmapped>")
    expected = dict((str(k), int(v)) for k, v in expected.items())
    # Ignore zero-length segments on either side.
    expected = dict((k, v) for k, v in expected.items() if v)
    clean_actual = dict((k, v) for k, v in clean_actual.items() if v)
    return expected == clean_actual


class VerificationResult(object):
    """The outcome of verifying a single excerpt declaration."""

    def __init__(self, declaration, status, slices, evaluations, **extra):
        self.declaration = declaration
        self.status = status
        self.slices = slices
        self.evaluations = evaluations
        self.coordinate_system = declaration["coordinate_system"]
        self.declared_length = declaration["length"]
        self.arch = _arch_label(declaration["arch"])
        self.slice_index = None
        self.slice = None
        self.parts = []
        self.converted = None
        self.segment_lengths = {}
        self.digest_algorithm = declaration["digest_algorithm"]
        self.declared_digest = declaration["digest"]
        self.actual_digest = None
        self.missing_evidence = []
        self.problems = []
        self.candidates = []
        self.ownership = None
        for key, value in extra.items():
            setattr(self, key, value)

    @property
    def id(self):
        return self.declaration["id"]

    @property
    def ok(self):
        return self.status == STATUS_VERIFIED

    @property
    def resolved_arch(self):
        return self.slice.arch if self.slice is not None else None

    def to_dict(self):
        return {
            "id": self.id,
            "status": self.status,
            "ok": self.ok,
            "coordinate_system": self.coordinate_system,
            "declared_length": self.declared_length,
            "arch": self.arch,
            "resolved_arch": self.resolved_arch,
            "slice_index": self.slice_index,
            "slice": self.slice.to_dict() if self.slice is not None else None,
            "parts": self.parts,
            "segment_lengths": dict(self.segment_lengths),
            "digest_algorithm": self.digest_algorithm,
            "declared_digest": self.declared_digest,
            "actual_digest": self.actual_digest,
            "converted": self.converted,
            "ownership": self.ownership,
            "missing_evidence": list(self.missing_evidence),
            "problems": list(self.problems),
            "candidates": self.candidates,
        }

    def __bool__(self):
        return self.ok

    __nonzero__ = __bool__

    def __repr__(self):
        return "<VerificationResult id=%r status=%s>" % (self.id, self.status)


class LedgerResult(object):
    """The result of verifying a bound ledger of excerpt declarations."""

    def __init__(self, entries):
        self.entries = entries

    @property
    def ok(self):
        return all(entry.ok for entry in self.entries)

    @property
    def duplicate_digests(self):
        """Groups of entries that share a digest but are distinct records.

        Identical short digests are precisely what hid mixed coordinate
        systems in old ledgers.  They are reported here even when every entry
        verifies independently.
        """
        groups = {}
        for entry in self.entries:
            if not entry.declared_digest:
                continue
            key = "%s:%s" % (entry.digest_algorithm, entry.declared_digest)
            groups.setdefault(key, []).append(entry.id)
        return dict((key, ids) for key, ids in groups.items() if len(ids) > 1)

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)

    def __getitem__(self, index):
        return self.entries[index]

    def to_dict(self):
        return {
            "ok": self.ok,
            "duplicate_digests": self.duplicate_digests,
            "entries": [entry.to_dict() for entry in self.entries],
        }


def _coerce_macho(source):
    """Return ``(macho, filename, owns_filename)`` for a supported source."""
    if hasattr(source, "headers") and hasattr(source, "filename"):
        return source, source.filename, False
    from .MachO import MachO

    macho = MachO(source)
    return macho, source, False


def _open_source(source, fileobj):
    macho, filename, _owns = _coerce_macho(source)
    if fileobj is not None:
        return macho, fileobj, False
    return macho, open(filename, "rb"), True


def verify_excerpt(
    source,
    declaration,
    fileobj=None,
    default_coordinate_system=None,
    default_arch=None,
    slice_index=None,
    base_offset=None,
):
    """Verify one excerpt declaration against a Mach-O file.

    ``source`` can be a filename, a path-like object or a parsed
    :class:`macholib.MachO.MachO` instance.  ``fileobj`` can be supplied when
    the bytes are not reachable through ``source.filename``.
    """
    macho, fp, close = _open_source(source, fileobj)
    try:
        slices = slice_records(macho)
        return _verify_one(
            slices,
            fp,
            declaration,
            default_coordinate_system,
            default_arch,
            {"slice_index": slice_index, "base_offset": base_offset},
        )
    finally:
        if close:
            fp.close()


def verify_excerpts(
    source,
    declarations,
    fileobj=None,
    default_coordinate_system=None,
    default_arch=None,
    slice_index=None,
    base_offset=None,
):
    """Verify a ledger (iterable) of excerpt declarations."""
    macho, fp, close = _open_source(source, fileobj)
    try:
        slices = slice_records(macho)
        entries = [
            _verify_one(
                slices,
                fp,
                declaration,
                default_coordinate_system,
                default_arch,
                {"slice_index": slice_index, "base_offset": base_offset},
            )
            for declaration in declarations
        ]
        return LedgerResult(entries)
    finally:
        if close:
            fp.close()


def verify_ledger(
    declarations,
    source=None,
    fileobj=None,
    default_coordinate_system=None,
    default_arch=None,
):
    """Verify excerpts that may each name their own Mach-O file.

    A declaration can carry ``path``/``filename``/``file``.  When it does not,
    ``source`` is used.  Declarations for the same file share one parsed
    :class:`ExcerptVerifier`.
    """
    verifiers = []
    entries = []
    try:
        for declaration in declarations:
            path = _get(declaration, ("path", "filename", "file"), None)
            if path is None:
                if source is None:
                    raise ExcerptError(
                        "declaration has no path and no default source was given"
                    )
                path = source
            verifier = None
            for existing_path, existing_verifier in verifiers:
                if existing_path is path:
                    verifier = existing_verifier
                    break
                try:
                    if existing_path == path:
                        verifier = existing_verifier
                        break
                except Exception:
                    continue
            if verifier is None:
                verifier = ExcerptVerifier(
                    path,
                    fileobj=fileobj if path is source else None,
                )
                verifiers.append((path, verifier))
            entries.append(
                verifier.verify(
                    declaration,
                    default_coordinate_system=default_coordinate_system,
                    default_arch=default_arch,
                )
            )
        return LedgerResult(entries)
    finally:
        for _path, verifier in verifiers:
            verifier.close()


def _verify_one(
    slices,
    fileobj,
    declaration,
    default_coordinate_system,
    default_arch,
    overrides=None,
):
    problems = []
    missing = []
    try:
        normalized = _normalize_declaration(
            declaration, default_coordinate_system, default_arch
        )
    except ExcerptError as exc:
        result = VerificationResult(
            {
                "id": _get(declaration, ("id", "identifier", "name", "ref"), None),
                "coordinate_system": None,
                "length": None,
                "arch": None,
                "digest": None,
                "digest_algorithm": "sha256",
            },
            STATUS_INVALID_DECLARATION,
            slices,
            [],
        )
        result.problems.append(str(exc))
        return result

    if overrides:
        for key in ("slice_index", "base_offset"):
            if normalized.get(key) is None and overrides.get(key) is not None:
                normalized[key] = overrides[key]

    algorithm = normalized["digest_algorithm"]
    try:
        hashlib.new(algorithm)
    except (ValueError, TypeError):
        result = VerificationResult(
            normalized, STATUS_INVALID_DECLARATION, slices, []
        )
        result.problems.append("unknown digest algorithm %r" % (algorithm,))
        return result

    if not slices:
        result = VerificationResult(
            normalized, STATUS_INVALID_DECLARATION, slices, []
        )
        result.problems.append("the file contains no Mach-O slices")
        return result

    if any(part["coordinate_system"] is None for part in normalized["parts"]):
        missing.append(EVIDENCE_COORDINATE)

    file_size = _file_size(fileobj)
    evaluations = [
        _evaluate_slice(
            slice_record, normalized["parts"], fileobj, file_size, algorithm
        )
        for slice_record in slices
    ]
    for evaluation in evaluations:
        if evaluation["digest"] is not None and normalized["digest"] is not None:
            evaluation["digest_match"] = (
                evaluation["digest"].lower() == normalized["digest"]
            )

    arch = normalized["arch"]
    explicit_slice = normalized["slice_index"]
    explicit_base = normalized["base_offset"]
    explicit_ownership = (
        arch is not None or explicit_slice is not None or explicit_base is not None
    )

    owner_indices = list(range(len(slices)))
    if explicit_slice is not None:
        if explicit_slice < 0 or explicit_slice >= len(slices):
            owner_indices = []
            problems.append(
                "declared slice_index %d is outside 0..%d"
                % (explicit_slice, len(slices) - 1)
            )
        else:
            owner_indices = [explicit_slice]
            if arch is not None and not _arch_matches(slices[explicit_slice], arch):
                problems.append(
                    "declared architecture does not match slice #%d (%s)"
                    % (explicit_slice, slices[explicit_slice].arch)
                )
    elif arch is not None:
        owner_indices = [
            index
            for index, slice_record in enumerate(slices)
            if _arch_matches(slice_record, arch)
        ]
    elif explicit_base is not None:
        owner_indices = [
            index
            for index, slice_record in enumerate(slices)
            if slice_record.offset == explicit_base
        ]

    matches_all = [
        index
        for index, evaluation in enumerate(evaluations)
        if evaluation["digest_match"]
    ]
    in_bounds_owner = [
        index
        for index in owner_indices
        if evaluations[index]["in_bounds"]
    ]
    matches_owner = [
        index for index in owner_indices if evaluations[index]["digest_match"]
    ]
    outside_matches = [index for index in matches_all if index not in owner_indices]

    status = None
    selected = None
    ownership = None

    if missing and EVIDENCE_COORDINATE in missing:
        status = STATUS_COORDINATE_MISSING
    elif normalized["digest"] is None:
        status = STATUS_UNVERIFIED
        missing.append(EVIDENCE_DIGEST)
    elif explicit_slice is not None and not owner_indices:
        status = STATUS_OWNERSHIP_MISMATCH
        missing.append(EVIDENCE_SLICE_INDEX)
    elif arch is not None and not owner_indices:
        # No slice carries the declared architecture.  If the same bytes do
        # exist elsewhere this is an ownership error, not a missing digest.
        missing.append(EVIDENCE_ARCHITECTURE)
        if matches_all:
            status = STATUS_OWNERSHIP_MISMATCH
            missing.append(EVIDENCE_OWNER_BYTES)
        else:
            status = STATUS_ARCHITECTURE_MISMATCH
    elif matches_owner:
        if len(matches_owner) == 1:
            selected = matches_owner[0]
            status = STATUS_VERIFIED
            if not explicit_ownership:
                # The declaration did not name an owner; this can only pass
                # when geometry (file coordinates) points at one slice.
                if len(slices) > 1 and len(in_bounds_owner) != 1:
                    status = STATUS_AMBIGUOUS
                    missing.append(EVIDENCE_ARCHITECTURE)
                else:
                    ownership = "inferred_from_slice_bounds"
            else:
                ownership = "declared"
        else:
            status = STATUS_AMBIGUOUS
            if arch is not None:
                missing.append(EVIDENCE_SLICE_INDEX)
            else:
                missing.append(EVIDENCE_ARCHITECTURE)
                missing.append(EVIDENCE_SLICE_INDEX)
    elif explicit_ownership:
        if outside_matches:
            status = STATUS_OWNERSHIP_MISMATCH
            missing.append(EVIDENCE_OWNER_BYTES)
            problems.append(
                "digest matches slice(s) %s but not the declared owner"
                % (
                    ", ".join(
                        "#%d (%s)" % (i, slices[i].arch)
                        for i in outside_matches
                    ),
                )
            )
        elif not in_bounds_owner:
            status = STATUS_OUT_OF_BOUNDS
        else:
            status = STATUS_DIGEST_MISMATCH
    elif matches_all:
        # No ownership was declared.  Accept only when the geometry itself
        # identifies a single slice; a digest match is not ownership.
        if len(matches_all) == 1 and len(in_bounds_owner) == 1:
            selected = matches_all[0]
            status = STATUS_VERIFIED
            ownership = "inferred_from_slice_bounds"
        else:
            status = STATUS_AMBIGUOUS
            missing.append(EVIDENCE_ARCHITECTURE)
            if len(matches_all) > 1:
                missing.append(EVIDENCE_SLICE_INDEX)
    else:
        if not in_bounds_owner:
            status = STATUS_OUT_OF_BOUNDS
        else:
            status = STATUS_DIGEST_MISMATCH

    if selected is None:
        if explicit_slice is not None and owner_indices:
            if evaluations[owner_indices[0]]["in_bounds"]:
                selected = owner_indices[0]
        elif len(in_bounds_owner) == 1:
            selected = in_bounds_owner[0]
        elif len(matches_all) == 1 and len(in_bounds_owner) == 1:
            selected = matches_all[0]

    expected_segment_lengths = normalized["segment_lengths"]
    if (
        expected_segment_lengths is not None
        and selected is not None
        and evaluations[selected]["in_bounds"]
    ):
        actual = evaluations[selected]["segment_lengths"]
        if not _segment_lengths_equal(expected_segment_lengths, actual):
            problems.append(
                "declared per-segment lengths %r do not match %r"
                % (expected_segment_lengths, actual)
            )
            if status == STATUS_VERIFIED:
                status = STATUS_SEGMENT_LENGTH_MISMATCH

    result = VerificationResult(normalized, status, slices, evaluations)
    result.problems = _unique(problems)
    result.ownership = ownership
    if selected is not None:
        result.slice_index = selected
        result.slice = slices[selected]
        result.parts = evaluations[selected]["parts"]
        result.segment_lengths = dict(evaluations[selected]["segment_lengths"])
        result.actual_digest = evaluations[selected]["digest"]
        result.converted = _conversion(slices[selected], evaluations[selected])
        if result.converted is not None:
            result.converted["source_coordinate_system"] = normalized[
                "coordinate_system"
            ]
            # Explicitly state the coordinate system produced by the
            # conversion.  Old file-coordinate records are rebuilt into slice
            # coordinates, the reverse conversion is offered as well.
            if normalized["coordinate_system"] == COORDINATE_FILE:
                result.converted["coordinate_system"] = COORDINATE_SLICE
                result.converted["reconstructed"] = True
            elif normalized["coordinate_system"] == COORDINATE_SLICE:
                result.converted["coordinate_system"] = COORDINATE_FILE
                result.converted["reconstructed"] = False
            else:
                result.converted["coordinate_system"] = "mixed"
                result.converted["reconstructed"] = None
    for evaluation in evaluations:
        result.candidates.append(_candidate_dict(slices, evaluation))
    if selected is not None:
        unmapped = result.segment_lengths.get("<unmapped>", 0)
        if unmapped and unmapped >= normalized["length"]:
            missing.append(EVIDENCE_SEGMENT_BOUNDARY)
    result.missing_evidence = _unique(missing)
    return result


def _candidate_dict(slices, evaluation):
    slice_record = slices[evaluation["slice_index"]]
    return {
        "slice_index": slice_record.index,
        "slice_offset": slice_record.offset,
        "slice_size": slice_record.size,
        "arch": slice_record.arch,
        "subtype": slice_record.subtype,
        "in_bounds": evaluation["in_bounds"],
        "digest_match": evaluation["digest_match"],
        "digest": evaluation["digest"],
        "parts": evaluation["parts"],
        "segment_lengths": dict(evaluation["segment_lengths"]),
        "problems": list(evaluation["problems"]),
    }


def _unique(values):
    result = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def convert_offset(
    source,
    offset,
    coordinate_system,
    arch=None,
    slice_index=None,
    length=1,
    fileobj=None,
):
    """Convert ``offset`` between file and slice coordinates.

    The conversion is only returned when the owning slice can be determined
    uniquely.  Otherwise :class:`AmbiguousOffsetError` explains which piece of
    evidence is missing.  This is the helper to use for old records whose
    offsets were recorded from the file header.
    """
    coordinate_system = _normalize_coordinate(coordinate_system)
    if coordinate_system not in COORDINATE_SYSTEMS:
        raise ExcerptError(
            "coordinate_system must be %r or %r"
            % (COORDINATE_FILE, COORDINATE_SLICE)
        )
    macho, fp, close = _open_source(source, fileobj)
    try:
        slices = slice_records(macho)
        spec = _arch_spec(arch) if arch is not None else None
        candidates = list(slices)
        if slice_index is not None:
            if slice_index < 0 or slice_index >= len(slices):
                raise ExcerptError("slice_index %d is out of range" % (slice_index,))
            candidates = [slices[slice_index]]
        elif spec is not None:
            candidates = [
                slice_record
                for slice_record in slices
                if _arch_matches(slice_record, spec)
            ]
            if not candidates:
                raise AmbiguousOffsetError(
                    "no slice matches architecture %r" % (arch,),
                    missing_evidence=[EVIDENCE_ARCHITECTURE],
                )

        if coordinate_system == COORDINATE_FILE:
            candidates = [
                slice_record
                for slice_record in candidates
                if slice_record.contains(offset, length)
            ]
        else:
            candidates = [
                slice_record
                for slice_record in candidates
                if 0 <= offset and offset + length <= slice_record.size
            ]

        if len(candidates) != 1:
            missing = [EVIDENCE_ARCHITECTURE]
            if len(candidates) > 1:
                missing.append(EVIDENCE_SLICE_INDEX)
            raise AmbiguousOffsetError(
                "offset %d maps to %d slices; cannot rebuild a unique offset"
                % (offset, len(candidates)),
                candidates=[slice_record.to_dict() for slice_record in candidates],
                missing_evidence=missing,
            )
        slice_record = candidates[0]
        if coordinate_system == COORDINATE_FILE:
            return {
                "source_coordinate_system": COORDINATE_FILE,
                "coordinate_system": COORDINATE_SLICE,
                "offset": slice_record.to_slice_offset(offset),
                "absolute_offset": offset,
                "slice_offset": slice_record.to_slice_offset(offset),
                "slice_index": slice_record.index,
                "slice_base": slice_record.offset,
                "slice_size": slice_record.size,
                "arch": slice_record.arch,
                "length": length,
                "reconstructed": True,
            }
        return {
            "source_coordinate_system": COORDINATE_SLICE,
            "coordinate_system": COORDINATE_FILE,
            "offset": slice_record.to_file_offset(offset),
            "absolute_offset": slice_record.to_file_offset(offset),
            "slice_offset": offset,
            "slice_index": slice_record.index,
            "slice_base": slice_record.offset,
            "slice_size": slice_record.size,
            "arch": slice_record.arch,
            "length": length,
            "reconstructed": False,
        }
    finally:
        if close:
            fp.close()


class ExcerptVerifier(object):
    """Reusable verifier bound to one Mach-O file."""

    def __init__(self, source, fileobj=None):
        self.macho, self.fileobj, self._close = _open_source(source, fileobj)
        self.slices = slice_records(self.macho)

    def close(self):
        if self._close:
            self.fileobj.close()
            self._close = False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def verify(
        self,
        declaration,
        default_coordinate_system=None,
        default_arch=None,
        slice_index=None,
        base_offset=None,
    ):
        return _verify_one(
            self.slices,
            self.fileobj,
            declaration,
            default_coordinate_system,
            default_arch,
            {"slice_index": slice_index, "base_offset": base_offset},
        )

    def verify_all(
        self,
        declarations,
        default_coordinate_system=None,
        default_arch=None,
        slice_index=None,
        base_offset=None,
    ):
        return LedgerResult(
            [
                self.verify(
                    declaration,
                    default_coordinate_system=default_coordinate_system,
                    default_arch=default_arch,
                    slice_index=slice_index,
                    base_offset=base_offset,
                )
                for declaration in declarations
            ]
        )

    def convert(self, offset, coordinate_system, arch=None, slice_index=None, length=1):
        normalized = _normalize_coordinate(coordinate_system)
        if normalized not in COORDINATE_SYSTEMS:
            raise ExcerptError(
                "coordinate_system must be %r or %r"
                % (COORDINATE_FILE, COORDINATE_SLICE)
            )
        spec = _arch_spec(arch) if arch is not None else None
        candidates = list(self.slices)
        if slice_index is not None:
            if slice_index < 0 or slice_index >= len(self.slices):
                raise ExcerptError(
                    "slice_index %d is out of range" % (slice_index,)
                )
            candidates = [self.slices[slice_index]]
        elif spec is not None:
            candidates = [
                slice_record
                for slice_record in candidates
                if _arch_matches(slice_record, spec)
            ]
        if normalized == COORDINATE_FILE:
            candidates = [
                slice_record
                for slice_record in candidates
                if slice_record.contains(offset, length)
            ]
        else:
            candidates = [
                slice_record
                for slice_record in candidates
                if 0 <= offset and offset + length <= slice_record.size
            ]
        if len(candidates) != 1:
            raise AmbiguousOffsetError(
                "offset %d maps to %d slices" % (offset, len(candidates)),
                candidates=[slice_record.to_dict() for slice_record in candidates],
                missing_evidence=[EVIDENCE_ARCHITECTURE],
            )
        slice_record = candidates[0]
        absolute = (
            offset
            if normalized == COORDINATE_FILE
            else slice_record.to_file_offset(offset)
        )
        return {
            "coordinate_system": (
                COORDINATE_SLICE
                if normalized == COORDINATE_FILE
                else COORDINATE_FILE
            ),
            "offset": (
                slice_record.to_slice_offset(offset)
                if normalized == COORDINATE_FILE
                else slice_record.to_file_offset(offset)
            ),
            "absolute_offset": absolute,
            "slice_offset": slice_record.to_slice_offset(absolute),
            "slice_index": slice_record.index,
            "slice_base": slice_record.offset,
            "slice_size": slice_record.size,
            "arch": slice_record.arch,
            "length": length,
        }


def format_report(result):
    """Render a human readable excerpt verification report."""
    if isinstance(result, LedgerResult):
        lines = ["excerpt ledger: ok=%s entries=%d" % (result.ok, len(result))]
        for key, ids in sorted(result.duplicate_digests.items()):
            lines.append(
                "  duplicate digest %s shared by: %s"
                % (key, ", ".join(str(identifier) for identifier in ids))
            )
        for entry in result:
            lines.append("")
            lines.extend(format_report(entry).splitlines())
        return "\n".join(lines)

    lines = [
        "excerpt %r: %s" % (result.id, result.status),
        "  coordinate system: %s" % (result.coordinate_system,),
        "  declared architecture: %s" % (result.arch,),
        "  declared length: %s" % (result.declared_length,),
    ]
    if result.slice is not None:
        lines.append(
            "  owning slice: #%d %s base=%d size=%d"
            % (
                result.slice.index,
                result.slice.arch,
                result.slice.offset,
                result.slice.size,
            )
        )
        lines.append("  resolved architecture: %s" % (result.slice.arch,))
    lines.append(
        "  segment lengths: %s"
        % ", ".join(
            "%s=%d" % (name, count)
            for name, count in sorted(result.segment_lengths.items())
        )
        if result.segment_lengths
        else "  segment lengths: unresolved"
    )
    if result.declared_digest is None:
        digest_state = "not declared"
    elif result.actual_digest is None:
        matched = [c for c in result.candidates if c["digest_match"]]
        digest_state = (
            "matches %d candidate slice(s)" % len(matched)
            if matched
            else "not checked"
        )
    elif result.actual_digest.lower() == result.declared_digest:
        digest_state = "match"
    else:
        digest_state = "mismatch"
    lines.append(
        "  digest %s: %s"
        % (
            result.digest_algorithm,
            digest_state,
        )
    )
    if result.converted is not None:
        lines.append(
            "  converted %s offset: %d"
            % (
                result.converted["coordinate_system"],
                result.converted["offset"],
            )
        )
    if result.missing_evidence:
        lines.append("  missing evidence: %s" % ", ".join(result.missing_evidence))
    if not result.ok:
        for candidate in result.candidates:
            if not candidate["in_bounds"] and not candidate["digest_match"]:
                continue
            lengths = ", ".join(
                "%s=%d" % (name, count)
                for name, count in sorted(candidate["segment_lengths"].items())
            )
            lines.append(
                "  candidate slice #%d %s: digest=%s segment lengths=%s"
                % (
                    candidate["slice_index"],
                    candidate["arch"],
                    "match" if candidate["digest_match"] else "mismatch",
                    lengths or "unresolved",
                )
            )
    for problem in result.problems:
        lines.append("  problem: %s" % (problem,))
    return "\n".join(lines)


def main(argv=None):
    """Verify a JSON ledger: ``python -m macholib.forensics IMAGE LEDGER``."""
    import json

    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = False
    if "--json" in argv:
        argv.remove("--json")
        as_json = True
    if len(argv) != 2:
        print("usage: python -m macholib.forensics [--json] IMAGE LEDGER.json")
        return 2
    with open(argv[1], "r") as stream:
        declarations = json.load(stream)
    if isinstance(declarations, dict) and "entries" in declarations:
        declarations = declarations["entries"]
    result = verify_excerpts(argv[0], declarations)
    if as_json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(format_report(result))
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())

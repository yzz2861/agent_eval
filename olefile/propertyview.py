"""Read-only forensic views for OLE property sets.

This module keeps physical property-set sections and property identifiers
separate.  It intentionally never collapses repeated display names into one
ordinary ``name -> value`` dictionary.
"""

from __future__ import print_function

import codecs
import datetime
import struct
from collections import namedtuple

try:
    from types import MappingProxyType as _mapping_proxy
except ImportError:  # Python 2
    _mapping_proxy = None

from .olefile import OleMetadata, VT, VT_VECTOR, _clsid


try:
    _text_type = unicode  # noqa: F821 (Python 2)
except NameError:
    _text_type = str


FMTID_SUMMARY_INFORMATION = "F29F85E0-4FF9-1068-AB91-08002B27B3D9"
FMTID_DOCUMENT_SUMMARY_INFORMATION = "D5CDD502-2E9C-101B-9397-08002B2CF9AE"
FMTID_USER_DEFINED_PROPERTIES = "D5CDD505-2E9C-101B-9397-08002B2CF9AE"

_AUTHORITATIVE_ENCODING_STATUSES = frozenset((
    "decoded", "ascii_without_codepage", "decoded_bom"
))
_ENCODING_ISSUE_CODES = frozenset((
    "missing_encoding_evidence", "unknown_codepage", "text_decode_failed"
))


TextResult = namedtuple("TextResult", (
    "text", "decoded_text", "tentative_text", "encoding", "status",
    "authoritative", "issue_code", "message"
))


class _ReadOnlyObject(object):
    """Immutable record base used by forensic view objects."""

    __slots__ = ("_frozen",)

    def __setattr__(self, name, value):
        if getattr(self, "_frozen", False):
            raise AttributeError("%s is read-only" % type(self).__name__)
        super(_ReadOnlyObject, self).__setattr__(name, value)

    def _freeze(self):
        object.__setattr__(self, "_frozen", True)


def _readonly_mapping(values):
    values = dict(values)
    if _mapping_proxy is None:
        return values.copy()
    return _mapping_proxy(values)


def _fmt_offset(offset):
    if offset is None:
        return "<unknown>"
    return "0x%08X (%d)" % (offset, offset)


def _hex_bytes(value, limit=None):
    if value is None:
        return None
    if limit is not None and len(value) > limit:
        return value[:limit].hex() + "...(%d bytes)" % len(value)
    try:
        return value.hex()
    except AttributeError:  # Python 2
        return value.encode("hex")


def normalize_stream_path(stream_path):
    if stream_path is None:
        return ()
    if isinstance(stream_path, (list, tuple)):
        return tuple(stream_path)
    return (stream_path,)


def normalize_fmtid(fmtid):
    if not fmtid:
        return None
    result = _text_type(fmtid).upper().replace("{", "").replace("}", "")
    return result or None


def codec_for_codepage(codepage):
    """Return a Python codec name for a Windows code page identifier."""
    if codepage in (None, 0):
        return None
    fixed = {
        1200: "utf-16-le",
        1201: "utf-16-be",
        65001: "utf-8",
        20127: "ascii",
        28591: "latin-1",
    }
    if codepage in fixed:
        return fixed[codepage]
    candidate = "cp%d" % codepage
    try:
        codecs.lookup(candidate)
    except LookupError:
        return None
    return candidate


def decode_property_text(raw, codepage=None):
    """Decode property/dictionary text without hiding encoding evidence."""
    if raw is None:
        raw = b""
    codec = codec_for_codepage(codepage)
    if codec is not None:
        try:
            decoded = raw.decode(codec).rstrip("\x00")
            return TextResult(decoded, decoded, decoded, codec, "decoded",
                               True, None, None)
        except Exception as exc:
            tentative = raw.decode(codec, "replace").rstrip("\x00")
            return TextResult(tentative, None, tentative, codec,
                               "text_decode_failed", False,
                               "text_decode_failed", str(exc))

    if raw.startswith(codecs.BOM_UTF16_LE) or raw.startswith(b"\xff\xfe"):
        try:
            decoded = raw.decode("utf-16").rstrip("\x00")
            return TextResult(decoded, decoded, decoded, "utf-16",
                               "decoded_bom", True, None, None)
        except Exception:
            pass

    try:
        decoded = raw.decode("ascii").rstrip("\x00")
        return TextResult(decoded, decoded, decoded, "ascii",
                          "ascii_without_codepage", True,
                          "missing_encoding_evidence",
                          "ASCII text is unambiguous, but no code page property was found")
    except Exception:
        pass

    try:
        decoded = raw.decode("utf-8").rstrip("\x00")
        return TextResult(decoded, None, decoded, "utf-8",
                          "utf8_without_codepage", False,
                          "missing_encoding_evidence",
                          "Valid UTF-8 is only a heuristic because the code page is absent")
    except Exception:
        tentative = raw.decode("utf-8", "replace").rstrip("\x00")
        return TextResult(tentative, None, tentative, None,
                          "undecoded_without_codepage", False,
                          "missing_encoding_evidence",
                          "Non-ASCII text has no code page or other reliable encoding evidence")


def property_type_name(property_type):
    if property_type is None:
        return None
    if property_type in VT:
        return VT[property_type]
    if property_type & VT_VECTOR:
        base = property_type & ~VT_VECTOR
        return "VT_VECTOR|" + VT.get(base, "UNKNOWN_0x%04X" % base)
    return "UNKNOWN_0x%08X" % property_type


def standard_property_names(fmtid):
    """Return olefile's built-in legacy property-number dictionaries."""
    fmtid = normalize_fmtid(fmtid)
    if fmtid == FMTID_SUMMARY_INFORMATION:
        names = OleMetadata.SUMMARY_ATTRIBS
    elif fmtid == FMTID_DOCUMENT_SUMMARY_INFORMATION:
        names = OleMetadata.DOCSUM_ATTRIBS
    else:
        return {}
    return dict((index + 1, name) for index, name in enumerate(names))


class PropertyViewIssue(_ReadOnlyObject):
    """A queryable parsing/forensic issue."""

    __slots__ = ("code", "message", "severity", "stream_path",
                 "section_index", "fmtid", "property_id", "offset",
                 "details")

    def __init__(self, code, message, severity="warning", stream_path=None,
                 section_index=None, fmtid=None, property_id=None,
                 offset=None, details=None):
        self.code = code
        self.message = message
        self.severity = severity
        self.stream_path = tuple(stream_path or ())
        self.section_index = section_index
        self.fmtid = normalize_fmtid(fmtid)
        self.property_id = property_id
        self.offset = offset
        self.details = details or {}
        self._freeze()

    @property
    def reference(self):
        return "issue:%s section=%s pid=%s offset=%s" % (
            self.code, self.section_index, self.property_id,
            _fmt_offset(self.offset))

    def to_dict(self):
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "stream_path": list(self.stream_path),
            "section_index": self.section_index,
            "fmtid": self.fmtid,
            "property_id": self.property_id,
            "offset": self.offset,
            "details": self.details,
            "reference": self.reference,
        }

    def __repr__(self):
        return "<PropertyViewIssue %s: %s>" % (self.code, self.message)


class PhysicalSource(_ReadOnlyObject):
    """Exact physical origin of one property-set record."""

    __slots__ = ("stream_path", "section_index", "fmtid", "section_offset",
                 "entry_index", "entry_offset", "property_id",
                 "relative_value_offset", "value_offset", "type_offset",
                 "dictionary_offset")

    def __init__(self, stream_path=(), section_index=None, fmtid=None,
                 section_offset=None, entry_index=None, entry_offset=None,
                 property_id=None, relative_value_offset=None,
                 value_offset=None, type_offset=None,
                 dictionary_offset=None):
        self.stream_path = tuple(stream_path or ())
        self.section_index = section_index
        self.fmtid = normalize_fmtid(fmtid)
        self.section_offset = section_offset
        self.entry_index = entry_index
        self.entry_offset = entry_offset
        self.property_id = property_id
        self.relative_value_offset = relative_value_offset
        self.value_offset = value_offset
        self.type_offset = type_offset if type_offset is not None else value_offset
        self.dictionary_offset = dictionary_offset
        self._freeze()

    @property
    def stream_repr(self):
        return repr(self.stream_path)

    @property
    def reference(self):
        return (
            "stream=%s section=%s fmtid=%s entry=%s pid=%s "
            "section_offset=%s value_offset=%s"
        ) % (
            self.stream_repr, self.section_index,
            self.fmtid or "<unknown>", self.entry_index, self.property_id,
            _fmt_offset(self.section_offset), _fmt_offset(self.value_offset)
        )

    def to_dict(self):
        result = dict((name, getattr(self, name)) for name in self.__slots__)
        result["stream_path"] = list(self.stream_path)
        result["stream_repr"] = self.stream_repr
        result["reference"] = self.reference
        return result


class PropertyNameEntry(_ReadOnlyObject):
    """One raw dictionary entry, preserving encoding status and location."""

    __slots__ = ("property_id", "name", "decoded_name", "tentative_name",
                 "raw_name", "encoding", "encoding_status",
                 "encoding_authoritative", "issue_code", "issue_message",
                 "dictionary_offset", "entry_index", "entry_offset",
                 "declared_length", "source")

    def __init__(self, property_id, name=None, decoded_name=None,
                 tentative_name=None, raw_name=b"", encoding=None,
                 encoding_status=None, encoding_authoritative=False,
                 issue_code=None, issue_message=None,
                 dictionary_offset=None, entry_index=None,
                 entry_offset=None, declared_length=None,
                 source="section-dictionary"):
        self.property_id = property_id
        self.name = name
        self.decoded_name = decoded_name
        self.tentative_name = tentative_name
        self.raw_name = raw_name
        self.encoding = encoding
        self.encoding_status = encoding_status
        self.encoding_authoritative = encoding_authoritative
        self.issue_code = issue_code
        self.issue_message = issue_message
        self.dictionary_offset = dictionary_offset
        self.entry_index = entry_index
        self.entry_offset = entry_offset
        self.declared_length = declared_length
        self.source = source
        self._freeze()

    @property
    def authoritative(self):
        return bool(self.encoding_authoritative)

    def to_dict(self):
        return {
            "property_id": self.property_id,
            "name": self.name,
            "decoded_name": self.decoded_name,
            "tentative_name": self.tentative_name,
            "raw_name_hex": _hex_bytes(self.raw_name),
            "raw_name_length": len(self.raw_name or b""),
            "encoding": self.encoding,
            "encoding_status": self.encoding_status,
            "encoding_authoritative": self.encoding_authoritative,
            "issue_code": self.issue_code,
            "issue_message": self.issue_message,
            "dictionary_offset": self.dictionary_offset,
            "entry_index": self.entry_index,
            "entry_offset": self.entry_offset,
            "declared_length": self.declared_length,
            "source": self.source,
        }


class PropertyDictionary(_ReadOnlyObject):
    """A PID 0 property-name dictionary in one section."""

    __slots__ = ("offset", "declared_count", "entries", "raw_bytes")

    def __init__(self, offset, declared_count, entries, raw_bytes=None):
        self.offset = offset
        self.declared_count = declared_count
        self.entries = tuple(entries)
        self.raw_bytes = raw_bytes
        self._freeze()

    def names_for_property_id(self, property_id):
        return tuple(entry for entry in self.entries
                     if entry.property_id == property_id)

    def to_dict(self):
        return {
            "offset": self.offset,
            "declared_count": self.declared_count,
            "entries": [entry.to_dict() for entry in self.entries],
        }


class PropertyEvidence(_ReadOnlyObject):
    """One physical property entry, with type, value, names and provenance."""

    __slots__ = ("section", "source", "entry_index", "property_id",
                 "type_tag_raw", "property_type", "base_type",
                 "type_name", "is_vector", "value", "text_value",
                 "raw_value", "value_encoding", "value_encoding_status",
                 "parse_status", "parse_message", "name_entries",
                 "standard_name", "standard_namespace", "issues")

    def __init__(self, source, property_id, entry_index=None, section=None,
                 type_tag_raw=None, property_type=None, value=None,
                 text_value=None, raw_value=None, value_encoding=None,
                 value_encoding_status=None, parse_status="ok",
                 parse_message=None, name_entries=(), standard_name=None,
                 standard_namespace=None, issues=(), base_type=None,
                 type_name=None, is_vector=False):
        self.section = section
        self.source = source
        self.entry_index = entry_index
        self.property_id = property_id
        self.type_tag_raw = type_tag_raw
        self.property_type = property_type
        self.base_type = base_type
        self.type_name = type_name or property_type_name(property_type)
        self.is_vector = is_vector
        self.value = value
        self.text_value = text_value
        self.raw_value = raw_value
        self.value_encoding = value_encoding
        self.value_encoding_status = value_encoding_status
        self.parse_status = parse_status
        self.parse_message = parse_message
        self.name_entries = tuple(name_entries)
        self.standard_name = standard_name
        self.standard_namespace = standard_namespace
        self.issues = tuple(issues)
        self._freeze()

    @property
    def reference(self):
        return self.source.reference

    @property
    def stable_reference(self):
        return self.source.reference

    @property
    def physical_source(self):
        return self.source

    @property
    def provenance(self):
        return self.source

    @property
    def locator(self):
        return self.reference

    @property
    def type(self):
        return self.property_type

    @property
    def actual_type(self):
        return self.property_type

    @property
    def actual_property_type(self):
        return self.property_type

    @property
    def type_code(self):
        return self.property_type

    @property
    def names(self):
        result = []
        for entry in self.name_entries:
            if entry.name is not None and entry.name not in result:
                result.append(entry.name)
        if self.standard_name and self.standard_name not in result:
            result.append(self.standard_name)
        return tuple(result)

    @property
    def dictionary_names(self):
        return tuple(entry.name for entry in self.name_entries
                     if entry.name is not None)

    @property
    def aliases(self):
        primary = self.name
        return tuple(name for name in self.names if name != primary)

    @property
    def name(self):
        for entry in self.name_entries:
            if entry.decoded_name is not None:
                return entry.decoded_name
        for entry in self.name_entries:
            if entry.name is not None:
                return entry.name
        return self.standard_name

    @property
    def is_named(self):
        return self.name is not None

    @property
    def fmtid(self):
        return self.source.fmtid

    @property
    def section_index(self):
        return self.source.section_index

    def get(self, key, default=None):
        return getattr(self, key, default)

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def to_dict(self):
        return {
            "property_id": self.property_id,
            "name": self.name,
            "names": list(self.names),
            "aliases": list(self.aliases),
            "dictionary_names": list(self.dictionary_names),
            "standard_name": self.standard_name,
            "standard_namespace": self.standard_namespace,
            "type_tag_raw": self.type_tag_raw,
            "property_type": self.property_type,
            "type_name": self.type_name,
            "is_vector": self.is_vector,
            "value": _json_safe(self.value),
            "text_value": self.text_value,
            "raw_value_hex": _hex_bytes(self.raw_value),
            "value_encoding": self.value_encoding,
            "value_encoding_status": self.value_encoding_status,
            "parse_status": self.parse_status,
            "parse_message": self.parse_message,
            "reference": self.reference,
            "source": self.source.to_dict(),
            "name_entries": [entry.to_dict() for entry in self.name_entries],
            "issues": [issue.to_dict() for issue in self.issues],
        }


class PropertySectionView(_ReadOnlyObject):
    """One FMTID section in a property-set stream."""

    __slots__ = ("view", "index", "fmtid", "offset", "declared_size",
                 "size", "declared_property_count", "property_count",
                 "codepage", "encoding", "codepage_sources",
                 "dictionaries", "properties", "issues",
                 "standard_names")

    def __init__(self, index, fmtid, offset, declared_size=None, size=None,
                 declared_property_count=None, property_count=None,
                 codepage=None, encoding=None, codepage_sources=(),
                 dictionaries=(), properties=(), issues=(),
                 standard_names=None):
        self.view = None
        self.index = index
        self.fmtid = normalize_fmtid(fmtid)
        self.offset = offset
        self.declared_size = declared_size
        self.size = size
        self.declared_property_count = declared_property_count
        self.property_count = property_count
        self.codepage = codepage
        self.encoding = encoding
        self.codepage_sources = tuple(codepage_sources)
        self.dictionaries = tuple(dictionaries)
        self.properties = tuple(properties)
        self.issues = tuple(issues)
        self.standard_names = dict(standard_names or standard_property_names(fmtid))
        for prop in self.properties:
            object.__setattr__(prop, "section", self)
        self._freeze()

    @property
    def records(self):
        return self.properties

    @property
    def name_dictionary(self):
        if not self.dictionaries:
            return ()
        return self.dictionaries[0].entries

    @property
    def name_entries(self):
        result = []
        for dictionary in self.dictionaries:
            result.extend(dictionary.entries)
        return tuple(result)

    def get(self, property_id):
        return tuple(prop for prop in self.properties
                     if prop.property_id == property_id)

    def find_name(self, name):
        return tuple(prop for prop in self.properties if name in prop.names)

    def to_dict(self):
        return {
            "index": self.index,
            "fmtid": self.fmtid,
            "offset": self.offset,
            "declared_size": self.declared_size,
            "size": self.size,
            "declared_property_count": self.declared_property_count,
            "property_count": self.property_count,
            "codepage": self.codepage,
            "encoding": self.encoding,
            "codepage_sources": [source.to_dict() for source in self.codepage_sources],
            "dictionaries": [dictionary.to_dict() for dictionary in self.dictionaries],
            "name_dictionary": [entry.to_dict() for entry in self.name_entries],
            "properties": [prop.to_dict() for prop in self.properties],
            "issues": [issue.to_dict() for issue in self.issues],
        }


class PropertySetView(_ReadOnlyObject):
    """Read-only, provenance-preserving view of all property-set sections."""

    __slots__ = ("stream_path", "data", "byte_order", "format_version",
                 "system_identifier", "header_clsid", "declared_section_count",
                 "section_descriptors", "sections", "issues",
                 "properties", "records", "_name_index",
                 "_dictionary_name_index", "_issues_by_code")

    def __init__(self, data=b"", stream_path=(), byte_order=None,
                 format_version=None, system_identifier=None,
                 header_clsid=None, declared_section_count=None,
                 section_descriptors=(), sections=(), issues=()):
        self.stream_path = normalize_stream_path(stream_path)
        self.data = data
        self.byte_order = byte_order
        self.format_version = format_version
        self.system_identifier = system_identifier
        self.header_clsid = header_clsid
        self.declared_section_count = declared_section_count
        self.section_descriptors = tuple(section_descriptors)
        self.sections = tuple(sections)
        self.issues = tuple(issues)
        for section in self.sections:
            object.__setattr__(section, "view", self)
        self.properties = tuple(prop for section in self.sections
                                for prop in section.properties)
        self.records = self.properties
        self._name_index = self._build_name_index(dictionary_only=False)
        self._dictionary_name_index = self._build_name_index(dictionary_only=True)
        self._issues_by_code = {}
        for issue in self.issues:
            self._issues_by_code.setdefault(issue.code, []).append(issue)
        self._issues_by_code = dict(
            (code, tuple(items)) for code, items in self._issues_by_code.items()
        )
        self._freeze()

    def _build_name_index(self, dictionary_only):
        result = {}
        for prop in self.properties:
            names = prop.dictionary_names if dictionary_only else prop.names
            for name in names:
                result.setdefault(name, []).append(prop)
        return dict((name, tuple(props)) for name, props in result.items())

    @property
    def stream_name(self):
        if not self.stream_path:
            return "<property-set-bytes>"
        return "/".join(_text_type(part) for part in self.stream_path)

    @property
    def name_index(self):
        return self._name_index

    @property
    def names(self):
        return tuple(self._name_index.keys())

    @property
    def duplicate_name_groups(self):
        return dict((name, props) for name, props
                    in self._dictionary_name_index.items() if len(props) > 1)

    @property
    def duplicate_names(self):
        return self.duplicate_name_groups

    @property
    def unmapped_properties(self):
        return tuple(prop for prop in self.properties if not prop.is_named)

    @property
    def encoding_issues(self):
        return tuple(issue for issue in self.issues
                     if issue.code in _ENCODING_ISSUE_CODES
                     or "encoding" in issue.code)

    def issues_by_code(self, code=None):
        if code is None:
            return self._issues_by_code
        return self._issues_by_code.get(code, ())

    def find(self, name=None, property_id=None, pid=None, fmtid=None,
             section=None, section_index=None):
        """Find records without collapsing duplicate names.

        ``section`` may be a section index or FMTID.  ``name`` matches both
        section-dictionary names and built-in standard names.
        """
        if pid is not None:
            property_id = pid
        if section is not None:
            if isinstance(section, int):
                section_index = section
            else:
                fmtid = section
        fmtid = normalize_fmtid(fmtid)
        results = list(self.properties)
        if name is not None:
            results = [prop for prop in results if name in prop.names]
        if property_id is not None:
            results = [prop for prop in results
                       if prop.property_id == property_id]
        if fmtid is not None:
            results = [prop for prop in results if prop.fmtid == fmtid]
        if section_index is not None:
            results = [prop for prop in results
                       if prop.section_index == section_index]
        return tuple(results)

    def find_by_name(self, name):
        return self.find(name=name)

    def find_by_property_id(self, property_id):
        return self.find(property_id=property_id)

    def citation_for(self, prop):
        same_name = self._dictionary_name_index.get(prop.name, ()) if prop.name else ()
        authoritative_name = bool(prop.standard_name) or any(
            entry.authoritative for entry in prop.name_entries)
        if prop.name is None:
            status = "physical-reference-only-unmapped-id"
        elif not authoritative_name:
            status = "physical-reference-only-encoding-unverified"
        elif len(same_name) > 1:
            status = "section-qualified-reference-required"
        else:
            status = "unique-name-reference"
        return {
            "status": status,
            "simple_name": prop.name,
            "stable_reference": prop.stable_reference,
            "section_qualified": (
                "section[%d]/%s/pid[%d]" % (
                    prop.section_index, prop.fmtid, prop.property_id)
                if prop.fmtid else
                "section[%d]/pid[%d]" % (prop.section_index, prop.property_id)
            ),
        }

    def audit_report(self):
        lines = [
            "OLE property-set forensic view",
            "stream: %r" % (self.stream_path,),
            "byte_order: %r version=%r clsid=%r sections=%d" % (
                self.byte_order, self.format_version, self.header_clsid,
                len(self.sections)),
        ]
        for section in self.sections:
            lines.append("")
            lines.append("Section %d FMTID=%s offset=%s codepage=%s encoding=%s" % (
                section.index, section.fmtid, _fmt_offset(section.offset),
                section.codepage, section.encoding))
            for dictionary in section.dictionaries:
                lines.append("  dictionary at %s entries=%s" % (
                    _fmt_offset(dictionary.offset), dictionary.declared_count))
                for entry in dictionary.entries:
                    lines.append(
                        "    pid=%-5s name=%r status=%s encoding=%s raw=%s" % (
                            entry.property_id, entry.name,
                            entry.encoding_status, entry.encoding,
                            _hex_bytes(entry.raw_name, 24)))
            for prop in section.properties:
                citation = self.citation_for(prop)
                lines.append(
                    "  property pid=%-5s type=%s(0x%X) name=%r aliases=%r" % (
                        prop.property_id, prop.type_name,
                        prop.property_type or 0, prop.name, prop.aliases))
                lines.append("    value=%r text=%r parse=%s" % (
                    prop.value, prop.text_value, prop.parse_status))
                lines.append("    citation=%s [%s]" % (
                    citation["section_qualified"], citation["status"]))
                lines.append("    source=%s" % prop.reference)
        if self.issues:
            lines.append("")
            lines.append("Queryable records/issues (%d):" % len(self.issues))
            for issue in self.issues:
                lines.append("  [%s] %s: %s" % (
                    issue.severity, issue.code, issue.message))
        return "\n".join(lines)

    def to_dict(self):
        return {
            "stream_path": list(self.stream_path),
            "stream_name": self.stream_name,
            "byte_order": self.byte_order,
            "format_version": self.format_version,
            "system_identifier": self.system_identifier,
            "header_clsid": self.header_clsid,
            "declared_section_count": self.declared_section_count,
            "sections": [section.to_dict() for section in self.sections],
            "issues": [issue.to_dict() for issue in self.issues],
            "duplicate_name_groups": dict(
                (name, [prop.reference for prop in props])
                for name, props in self.duplicate_name_groups.items()
            ),
        }

    def __repr__(self):
        return "<PropertySetView stream=%r sections=%d properties=%d issues=%d>" % (
            self.stream_path, len(self.sections), len(self.properties),
            len(self.issues))


def _json_safe(value):
    if isinstance(value, bytes):
        return {"bytes_hex": _hex_bytes(value)}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return dict((key, _json_safe(item)) for key, item in value.items())
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    return value


def _u16(data, offset):
    if offset is None or offset < 0 or offset + 2 > len(data):
        return None
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data, offset):
    if offset is None or offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data, offset):
    if offset is None or offset < 0 or offset + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, offset)[0]


def _add_issue(issues, code, message, severity="warning", **kwargs):
    issue = PropertyViewIssue(code, message, severity=severity, **kwargs)
    issues.append(issue)
    return issue


def parse_property_set(data, stream_path=None, convert_time=True):
    """Parse a PropertySetStream byte string into a :class:`PropertySetView`."""
    if data is None:
        raise ValueError("property-set data must not be None")
    if isinstance(data, bytearray):
        data = bytes(data)
    if not isinstance(data, bytes):
        try:
            data = data.read()
        except AttributeError:
            raise TypeError("data must be bytes or a binary file-like object")
    path = normalize_stream_path(stream_path)
    issues = []

    byte_order = _u16(data, 0)
    format_version = _u16(data, 2)
    system_identifier = _u32(data, 4)
    header_clsid = _clsid(data[8:24]) if len(data) >= 24 else None
    declared_count = _u32(data, 24)

    if len(data) < 28 or declared_count is None:
        _add_issue(issues, "truncated_property_set_header",
                   "Property set header is shorter than 28 bytes",
                   severity="error", stream_path=path, offset=len(data))
        declared_count = 0
    if byte_order != 0xFFFE:
        _add_issue(issues, "unexpected_byte_order",
                   "Expected little-endian byte-order marker 0xFFFE",
                   stream_path=path, offset=0,
                   details={"byte_order": byte_order})

    max_descriptors = max(0, (len(data) - 28) // 20)
    section_count = declared_count or 0
    if section_count > max_descriptors:
        _add_issue(issues, "invalid_section_count",
                   "Declared section count exceeds available section descriptors",
                   severity="error", stream_path=path, offset=24,
                   details={"declared": section_count,
                            "available": max_descriptors})
        section_count = max_descriptors

    descriptors = []
    for index in range(section_count):
        desc_offset = 28 + index * 20
        fmtid = _clsid(data[desc_offset:desc_offset + 16])
        section_offset = _u32(data, desc_offset + 16)
        descriptors.append({"index": index, "fmtid": fmtid,
                            "offset": section_offset,
                            "descriptor_offset": desc_offset})

    sections = []
    for descriptor in descriptors:
        sections.append(_parse_section(
            data, descriptor["index"], descriptor["fmtid"],
            descriptor["offset"], path, issues, convert_time))

    _add_duplicate_name_issues(sections, issues, path)
    return PropertySetView(
        data=data, stream_path=path, byte_order=byte_order,
        format_version=format_version, system_identifier=system_identifier,
        header_clsid=header_clsid, declared_section_count=declared_count,
        section_descriptors=tuple(descriptors), sections=sections,
        issues=issues)


def _add_duplicate_name_issues(sections, issues, path):
    grouped = {}
    for section in sections:
        for prop in section.properties:
            for name in prop.dictionary_names:
                grouped.setdefault(name, set()).add(prop)
    for name, props in grouped.items():
        if len(props) <= 1:
            continue
        references = tuple(sorted(prop.reference for prop in props))
        first = sorted(props, key=lambda prop: (prop.section_index or 0,
                                               prop.entry_index or 0))[0]
        _add_issue(issues, "duplicate_name",
                   "Dictionary name %r identifies %d independent physical properties"
                   % (name, len(props)),
                   stream_path=path, section_index=first.section_index,
                   fmtid=first.fmtid, property_id=first.property_id,
                   details={"name": name, "references": references})


def _parse_section(data, index, fmtid, offset, path, issues, convert_time):
    local_issues = []
    standard_names = standard_property_names(fmtid)

    def issue(code, message, severity="warning", property_id=None,
              abs_offset=None, details=None):
        item = _add_issue(
            issues, code, message, severity=severity, stream_path=path,
            section_index=index, fmtid=fmtid, property_id=property_id,
            offset=abs_offset, details=details)
        local_issues.append(item)
        return item

    if offset is None or offset + 8 > len(data):
        issue("truncated_section", "Section header is outside the stream",
              severity="error", abs_offset=offset)
        return PropertySectionView(index, fmtid, offset, issues=local_issues,
                                   standard_names=standard_names)

    declared_size = _u32(data, offset)
    declared_count = _u32(data, offset + 4)
    if declared_size is None or declared_size < 8:
        issue("invalid_section_size", "Section size is missing or invalid",
              severity="error", abs_offset=offset,
              details={"declared_size": declared_size})
        end = len(data)
        size = len(data) - offset
    elif offset + declared_size > len(data):
        issue("truncated_section", "Declared section size exceeds stream length",
              severity="error", abs_offset=offset,
              details={"declared_size": declared_size,
                       "available": len(data) - offset})
        end = len(data)
        size = len(data) - offset
    else:
        end = offset + declared_size
        size = declared_size

    max_count = max(0, (end - offset - 8) // 8)
    count = declared_count or 0
    if count > max_count:
        issue("invalid_property_count",
              "Property count exceeds available identifier/offset entries",
              severity="error", abs_offset=offset + 4,
              details={"declared_count": declared_count, "available": max_count})
        count = max_count

    entries = []
    for entry_index in range(count):
        entry_offset = offset + 8 + entry_index * 8
        pid = _u32(data, entry_offset)
        relative_offset = _u32(data, entry_offset + 4)
        value_offset = offset + relative_offset if relative_offset is not None else None
        valid = (value_offset is not None and value_offset >= offset + 8
                 and value_offset + 4 <= len(data))
        if not valid:
            issue("invalid_property_offset",
                  "Property identifier/offset entry does not point to a readable typed value",
                  property_id=pid, abs_offset=entry_offset + 4,
                  details={"relative_offset": relative_offset})
        entries.append({
            "index": entry_index, "offset": entry_offset,
            "property_id": pid, "relative_offset": relative_offset,
            "value_offset": value_offset, "valid": valid,
        })

    pid_groups = {}
    for entry in entries:
        pid_groups.setdefault(entry["property_id"], []).append(entry)
    for pid, grouped in pid_groups.items():
        if pid is not None and len(grouped) > 1:
            issue("duplicate_property_id",
                  "Property ID %d has %d physical identifier/offset entries"
                  % (pid, len(grouped)), property_id=pid,
                  details={"entry_indexes": [item["index"] for item in grouped]})

    codepage = None
    encoding = None
    codepage_sources = []
    for entry in entries:
        if entry["property_id"] != 1 or not entry["valid"]:
            continue
        type_raw = _u32(data, entry["value_offset"])
        cp_value = _u16(data, entry["value_offset"] + 4)
        source = PhysicalSource(
            path, index, fmtid, offset, entry["index"], entry["offset"], 1,
            entry["relative_offset"], entry["value_offset"])
        codepage_sources.append(source)
        if type_raw is not None and (type_raw & 0xFFFF) != 2:
            issue("invalid_codepage_type",
                  "Code page property should have VT_I2 (2), found %s" %
                  property_type_name(type_raw & 0xFFFF),
                  property_id=1, abs_offset=entry["value_offset"])
        if cp_value is not None:
            if codepage is None:
                codepage = cp_value if cp_value != 0 else None
                encoding = codec_for_codepage(codepage)
            elif codepage != cp_value:
                issue("conflicting_codepage",
                      "Multiple code-page properties declare different encodings",
                      property_id=1, abs_offset=entry["value_offset"],
                      details={"values": [codepage, cp_value]})
    if codepage is not None and encoding is None:
        issue("unknown_codepage",
              "Code page %d has no known Python codec" % codepage,
              property_id=1, details={"codepage": codepage})

    dictionaries = []
    names_by_pid = {}
    for entry in entries:
        if entry["property_id"] != 0 or not entry["valid"]:
            continue
        dictionary = _parse_dictionary(
            data, entry["value_offset"], index, fmtid, offset, path,
            codepage, issue)
        dictionaries.append(dictionary)
        for name_entry in dictionary.entries:
            names_by_pid.setdefault(name_entry.property_id, []).append(name_entry)

    entry_pids = set(entry["property_id"] for entry in entries)
    for name_entry in (item for dictionary in dictionaries
                      for item in dictionary.entries):
        if name_entry.property_id not in entry_pids:
            issue("orphan_dictionary_name",
                  "Dictionary name %r refers to property ID %s absent from the section"
                  % (name_entry.name, name_entry.property_id),
                  property_id=name_entry.property_id,
                  abs_offset=name_entry.entry_offset,
                  details={"name": name_entry.name})

    properties = []
    for entry in entries:
        pid = entry["property_id"]
        if pid in (0, 1):
            continue
        source = PhysicalSource(
            path, index, fmtid, offset, entry["index"], entry["offset"], pid,
            entry["relative_offset"], entry["value_offset"])
        name_entries = tuple(names_by_pid.get(pid, ()))
        standard_name = standard_names.get(pid)
        type_raw = None
        type_code = None
        value = None
        text_value = None
        raw_value = None
        value_encoding = None
        value_encoding_status = None
        parse_status = "ok"
        parse_message = None
        prop_issues = []

        if not entry["valid"]:
            parse_status = "invalid_offset"
            parse_message = "Property value offset is outside readable data"
        else:
            type_raw = _u32(data, entry["value_offset"])
            type_code = type_raw & 0xFFFF if type_raw is not None else None
            try:
                parsed = _parse_typed_value(
                    data, entry["value_offset"], type_code, codepage,
                    convert_time)
                value = parsed["value"]
                text_value = parsed.get("text_value")
                raw_value = parsed.get("raw_value")
                value_encoding = parsed.get("encoding")
                value_encoding_status = parsed.get("encoding_status")
                if parsed.get("issue_code"):
                    parse_status = parsed["issue_code"]
                    parse_message = parsed.get("message")
                    prop_issue = issue(
                        parsed["issue_code"], parse_message or "Text decoding issue",
                        property_id=pid, abs_offset=entry["value_offset"],
                        details={"encoding_status": value_encoding_status})
                    prop_issues.append(prop_issue)
            except Exception as exc:
                parse_status = "parse_error"
                parse_message = str(exc)
                prop_issues.append(issue(
                    "property_parse_error", "Could not parse property value: %s" % exc,
                    property_id=pid, abs_offset=entry["value_offset"]))

        if not name_entries and standard_name is None:
            prop_issues.append(issue(
                "unmapped_property_id",
                "Property ID %d has neither a dictionary name nor a known standard name" % pid,
                property_id=pid, abs_offset=entry["value_offset"],
                details={"type_name": property_type_name(type_code)}))

        prop = PropertyEvidence(
            source=source, property_id=pid, entry_index=entry["index"],
            type_tag_raw=type_raw, property_type=type_code,
            base_type=(type_code & ~VT_VECTOR) if type_code and type_code & VT_VECTOR else type_code,
            type_name=property_type_name(type_code),
            is_vector=bool(type_code and type_code & VT_VECTOR),
            value=value, text_value=text_value, raw_value=raw_value,
            value_encoding=value_encoding,
            value_encoding_status=value_encoding_status,
            parse_status=parse_status, parse_message=parse_message,
            name_entries=name_entries, standard_name=standard_name,
            standard_namespace=fmtid if standard_name else None,
            issues=prop_issues)
        properties.append(prop)

    return PropertySectionView(
        index, fmtid, offset, declared_size=declared_size, size=size,
        declared_property_count=declared_count, property_count=count,
        codepage=codepage, encoding=encoding,
        codepage_sources=codepage_sources, dictionaries=dictionaries,
        properties=properties, issues=local_issues,
        standard_names=standard_names)


def _parse_dictionary(data, dict_offset, section_index, fmtid,
                      section_offset, path, codepage, issue):
    entries = []
    declared_count = _u32(data, dict_offset)
    if declared_count is None:
        issue("truncated_dictionary", "Dictionary header is unreadable",
              abs_offset=dict_offset)
        return PropertyDictionary(dict_offset, None, entries)

    cursor = dict_offset + 4
    for entry_index in range(declared_count):
        name_pid = _u32(data, cursor)
        length = _u32(data, cursor + 4)
        entry_offset = cursor
        if name_pid is None or length is None or cursor + 8 > len(data):
            issue("truncated_dictionary", "Dictionary entry header is truncated",
                  abs_offset=cursor)
            break
        raw_start = cursor + 8
        raw_end = raw_start + length
        if raw_end > len(data):
            raw_name = data[raw_start:]
            issue("truncated_dictionary",
                  "Dictionary name extends beyond the property stream",
                  property_id=name_pid, abs_offset=cursor,
                  details={"declared_length": length,
                           "available": len(data) - raw_start})
            entries.append(_build_name_entry(
                name_pid, raw_name, codepage, dict_offset, entry_index,
                entry_offset, length, issue))
            break
        raw_name = data[raw_start:raw_end]
        entries.append(_build_name_entry(
            name_pid, raw_name, codepage, dict_offset, entry_index,
            entry_offset, length, issue))
        cursor = raw_end

    return PropertyDictionary(dict_offset, declared_count, entries)


def _build_name_entry(pid, raw_name, codepage, dict_offset, entry_index,
                      entry_offset, declared_length, issue):
    decoded = decode_property_text(raw_name, codepage)
    issue_code = decoded.issue_code
    if issue_code == "missing_encoding_evidence" and codepage is None:
        issue(issue_code, decoded.message,
              severity="info" if decoded.authoritative else "warning",
              property_id=pid, abs_offset=entry_offset,
              details={"encoding_status": decoded.status,
                       "raw_name_hex": _hex_bytes(raw_name)})
    elif issue_code:
        issue(issue_code, decoded.message or "Dictionary text decoding issue",
              property_id=pid, abs_offset=entry_offset,
              details={"encoding_status": decoded.status,
                       "codepage": codepage})
    return PropertyNameEntry(
        property_id=pid, name=decoded.text,
        decoded_name=decoded.decoded_text,
        tentative_name=decoded.tentative_text, raw_name=raw_name,
        encoding=decoded.encoding, encoding_status=decoded.status,
        encoding_authoritative=decoded.authoritative,
        issue_code=issue_code, issue_message=decoded.message,
        dictionary_offset=dict_offset, entry_index=entry_index,
        entry_offset=entry_offset, declared_length=declared_length)


def _parse_typed_value(data, type_offset, type_code, codepage, convert_time):
    pos = type_offset + 4
    if type_code is not None and type_code & VT_VECTOR:
        base = type_code & ~VT_VECTOR
        count = _u32(data, pos)
        if count is None:
            raise ValueError("truncated VT_VECTOR count")
        cursor = pos + 4
        values = []
        raw_parts = []
        for _ in range(count):
            parsed = _parse_scalar_at(data, cursor, base, codepage, convert_time)
            values.append(parsed["value"])
            if parsed.get("raw_value") is not None:
                raw_parts.append(parsed["raw_value"])
            cursor += parsed["size"]
        return {"value": values, "raw_value": b"".join(raw_parts),
                "text_value": None, "size": cursor - pos}
    parsed = _parse_scalar_at(data, pos, type_code, codepage, convert_time)
    return parsed


def _parse_scalar_at(data, pos, type_code, codepage, convert_time):
    result = {"value": None, "raw_value": b"", "size": 0,
              "text_value": None, "encoding": None,
              "encoding_status": None, "issue_code": None,
              "message": None}
    if type_code == 2:  # VT_I2
        result["value"] = struct.unpack_from("<h", data, pos)[0]
        result["raw_value"] = data[pos:pos + 2]
        result["size"] = 2
    elif type_code == 18:
        result["value"] = struct.unpack_from("<H", data, pos)[0]
        result["raw_value"] = data[pos:pos + 2]
        result["size"] = 2
    elif type_code in (3, 10, 22):  # VT_I4, VT_ERROR, VT_INT
        result["value"] = struct.unpack_from("<i", data, pos)[0]
        result["raw_value"] = data[pos:pos + 4]
        result["size"] = 4
    elif type_code in (19, 23):  # VT_UI4, VT_UINT
        result["value"] = struct.unpack_from("<I", data, pos)[0]
        result["raw_value"] = data[pos:pos + 4]
        result["size"] = 4
    elif type_code == 17:
        result["value"] = data[pos]
        result["raw_value"] = data[pos:pos + 1]
        result["size"] = 1
    elif type_code == 11:
        result["value"] = bool(struct.unpack_from("<h", data, pos)[0])
        result["raw_value"] = data[pos:pos + 2]
        result["size"] = 2
    elif type_code in (30, 8):  # VT_LPSTR, VT_BSTR as CodePageString
        count = _u32(data, pos)
        if count is None:
            raise ValueError("truncated CodePageString length")
        raw = data[pos + 4:pos + 4 + count]
        decoded = decode_property_text(raw, codepage)
        result.update({
            "raw_value": raw, "size": 4 + count,
            "text_value": decoded.text, "encoding": decoded.encoding,
            "encoding_status": decoded.status,
            "issue_code": decoded.issue_code, "message": decoded.message,
            "value": decoded.decoded_text if decoded.authoritative else raw.rstrip(b"\x00"),
        })
    elif type_code == 31:  # VT_LPWSTR
        count = _u32(data, pos)
        if count is None:
            raise ValueError("truncated UnicodeString length")
        raw = data[pos + 4:pos + 4 + count * 2]
        text = raw.decode("utf-16-le", "replace").rstrip("\x00")
        result.update({"value": text, "text_value": text, "raw_value": raw,
                       "encoding": "utf-16-le", "encoding_status": "decoded",
                       "size": 4 + count * 2})
    elif type_code == 64:  # VT_FILETIME
        filetime = _u64(data, pos)
        raw = data[pos:pos + 8]
        if convert_time and filetime is not None:
            epoch = datetime.datetime(1601, 1, 1)
            value = epoch + datetime.timedelta(microseconds=filetime // 10)
        else:
            value = filetime
        result.update({"value": value, "raw_value": raw, "size": 8})
    elif type_code == 72:  # VT_CLSID
        raw = data[pos:pos + 16]
        result.update({"value": _clsid(raw), "raw_value": raw, "size": 16})
    elif type_code == 65:  # VT_BLOB
        count = _u32(data, pos)
        raw = data[pos + 4:pos + 4 + count]
        result.update({"value": raw, "raw_value": raw, "size": 4 + count})
    else:
        result["encoding_status"] = "unsupported_type"
        result["issue_code"] = "unsupported_property_type"
        result["message"] = "Property type %s is not decoded by the forensic view" % (
            property_type_name(type_code),)
    return result


def read_property_set(source, stream_path=None, **kwargs):
    """Read bytes, a binary file-like object, or an :class:`OleFileIO` stream."""
    if hasattr(source, "openstream") and stream_path is not None:
        data = source.openstream(stream_path).read()
        return parse_property_set(data, stream_path=stream_path, **kwargs)
    if isinstance(source, (bytes, bytearray)) or hasattr(source, "read"):
        return parse_property_set(source, stream_path=stream_path, **kwargs)
    raise TypeError("unsupported property-set source: %r" % type(source))


# Descriptive aliases for downstream forensic and audit code.
PropertySet = PropertySetView
ForensicPropertyView = PropertySetView
ForensicPropertySetView = PropertySetView
PropertySection = PropertySectionView
PropertyRecord = PropertyEvidence
ForensicPropertyRecord = PropertyEvidence
PropertyIssue = PropertyViewIssue


__all__ = [
    "FMTID_SUMMARY_INFORMATION",
    "FMTID_DOCUMENT_SUMMARY_INFORMATION",
    "FMTID_USER_DEFINED_PROPERTIES",
    "PhysicalSource",
    "PropertyNameEntry",
    "PropertyDictionary",
    "PropertyEvidence",
    "PropertySectionView",
    "PropertySetView",
    "PropertyViewIssue",
    "PropertySet",
    "ForensicPropertyView",
    "ForensicPropertySetView",
    "PropertySection",
    "PropertyRecord",
    "ForensicPropertyRecord",
    "PropertyIssue",
    "parse_property_set",
    "read_property_set",
    "decode_property_text",
    "property_type_name",
    "standard_property_names",
]

"""Strict decoding and sanitization for archived documents.

The regular :meth:`html_sanitizer.Sanitizer.sanitize` entry point accepts a
``str``.  Archived material often arrives as bytes together with an encoding
declaration from a catalogue or another independent source.  This module adds
an explicit, fail-closed path for that material:

* bytes are decoded with ``errors="strict"``;
* the independent declaration is compared with byte-order marks and in-document
  metadata (MIME headers, XML declarations and HTML ``meta`` tags);
* accepted documents are sanitized to a Unicode string and carry the exact
  input byte range plus a SHA-256 digest for reviewers;
* conflicts retain the source and the byte/line/column of the failure.

The result object is returned for both outcomes so that review screens can show
which item may be signed off.  Call :meth:`ArchiveResult.raise_for_conflict` or
pass ``on_conflict="raise"`` when an exception is preferred.
"""

from __future__ import annotations

import codecs
import hashlib
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from .sanitizer import Sanitizer


__all__ = (
    "ArchiveConflict",
    "ArchiveConflictError",
    "ArchiveError",
    "ArchiveResult",
    "ArchiveStatus",
    "ByteRange",
    "EncodingEvidence",
    "FailurePosition",
    "InputRange",
    "SourcePosition",
    "render_review",
    "render_reviews",
    "review_archive",
    "review_archives",
    "sanitize_archive",
)


class ArchiveStatus(str, Enum):
    """The outcome of a strict archive check."""

    ACCEPTED = "accepted"
    CONFLICT = "conflict"

    @property
    def ok(self):
        return self is ArchiveStatus.ACCEPTED

    def __str__(self):
        return self.value


@dataclass(frozen=True, slots=True)
class InputRange:
    """A half-open byte range in the original archive input."""

    start: int
    end: int
    source: str | None = None
    encoding: str | None = None

    def __post_init__(self):
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"Invalid input range: {self.start!r}..{self.end!r}")

    @property
    def length(self):
        return self.end - self.start

    @property
    def offset(self):
        """Alias for the first byte, convenient for failure reports."""
        return self.start

    def __contains__(self, offset):
        return self.start <= offset < self.end

    def __iter__(self):
        yield self.start
        yield self.end

    def __str__(self):
        source = f"{self.source}:" if self.source else ""
        return f"{source}{self.start}:{self.end}"


ByteRange = InputRange


@dataclass(frozen=True, slots=True)
class SourcePosition:
    """A one-based source position for a failure; columns count bytes."""

    byte_offset: int
    line: int
    column: int
    source: str | None = None

    @property
    def offset(self):
        return self.byte_offset

    def __str__(self):
        source = self.source or "<memory>"
        return f"{source}:{self.line}:{self.column} (byte {self.byte_offset})"


FailurePosition = SourcePosition


@dataclass(frozen=True, slots=True)
class EncodingEvidence:
    """One piece of in-document or byte-level encoding evidence."""

    kind: str
    encoding: str | None
    raw_value: str
    byte_range: InputRange
    error: str | None = None

    @property
    def label(self):
        return self.encoding or self.raw_value


@dataclass(frozen=True, slots=True)
class ArchiveConflict:
    """A fail-closed archive check result with a precise location."""

    code: str
    message: str
    position: SourcePosition
    source: str | None = None
    declared_encoding: str | None = None
    metadata_encoding: str | None = None
    metadata_kind: str | None = None
    byte_range: InputRange | None = None

    @property
    def location(self):
        return self.position

    @property
    def reason(self):
        return self.message

    @property
    def offset(self):
        return self.position.byte_offset

    @property
    def line(self):
        return self.position.line

    @property
    def column(self):
        return self.position.column

    def __str__(self):
        return f"{self.code} at {self.position}: {self.message}"


@dataclass(frozen=True, slots=True)
class ArchiveResult:
    """The outcome of :func:`sanitize_archive`.

    ``html`` and ``text`` are only populated for accepted material.  Conflicts
    always carry ``source`` (if supplied), a byte range and a line/column.
    """

    source: str | None
    status: ArchiveStatus
    digest: str
    input_range: InputRange
    document_range: InputRange
    declared_encoding: str | None = None
    encoding: str | None = None
    text: str | None = None
    html: str | None = None
    metadata: tuple[EncodingEvidence, ...] = ()
    conflicts: tuple[ArchiveConflict, ...] = ()
    warnings: tuple[str, ...] = ()
    character_form: str = "NFKC"

    @property
    def ok(self):
        return self.status.ok

    @property
    def accepted(self):
        return self.ok

    @property
    def can_sign_off(self):
        return self.ok

    @property
    def signed_off(self):
        return self.ok

    @property
    def sanitized(self):
        return self.html

    @property
    def sanitized_html(self):
        return self.html

    @property
    def output(self):
        return self.html

    @property
    def decoded(self):
        return self.text

    @property
    def decoded_text(self):
        return self.text

    @property
    def byte_range(self):
        return self.input_range

    @property
    def source_range(self):
        return self.input_range

    @property
    def error(self):
        return self.conflicts[0] if self.conflicts else None

    @property
    def conflict(self):
        return self.error

    @property
    def failure_position(self):
        return self.error.position if self.error else None

    @property
    def position(self):
        return self.failure_position

    @property
    def error_code(self):
        return self.error.code if self.error else None

    @property
    def reason(self):
        return self.error.message if self.error else None

    def raise_for_conflict(self):
        """Raise :class:`ArchiveConflictError` when the archive was rejected."""
        if self.conflicts:
            raise ArchiveConflictError(self)
        return self

    def as_dict(self):
        """Return a JSON-serializable representation for a review UI."""
        return {
            "status": self.status.value,
            "ok": self.ok,
            "can_sign_off": self.can_sign_off,
            "source": self.source,
            "digest": self.digest,
            "declared_encoding": self.declared_encoding,
            "encoding": self.encoding,
            "character_form": self.character_form,
            "input_range": {
                "start": self.input_range.start,
                "end": self.input_range.end,
                "source": self.input_range.source,
                "encoding": self.input_range.encoding,
            },
            "document_range": {
                "start": self.document_range.start,
                "end": self.document_range.end,
            },
            "metadata": [
                {
                    "kind": item.kind,
                    "encoding": item.encoding,
                    "raw_value": item.raw_value,
                    "start": item.byte_range.start,
                    "end": item.byte_range.end,
                    "error": item.error,
                }
                for item in self.metadata
            ],
            "conflicts": [
                {
                    "code": item.code,
                    "message": item.message,
                    "source": item.source,
                    "byte_offset": item.position.byte_offset,
                    "line": item.position.line,
                    "column": item.position.column,
                    "declared_encoding": item.declared_encoding,
                    "metadata_encoding": item.metadata_encoding,
                    "metadata_kind": item.metadata_kind,
                    "range_start": item.byte_range.start
                    if item.byte_range is not None
                    else None,
                    "range_end": item.byte_range.end
                    if item.byte_range is not None
                    else None,
                }
                for item in self.conflicts
            ],
            "warnings": list(self.warnings),
            "html": self.html,
        }

    def __bool__(self):
        return self.ok

    def __str__(self):
        return render_review(self)


class ArchiveConflictError(ValueError):
    """Raised when strict archive mode rejects a document."""

    def __init__(self, result: ArchiveResult):
        self.result = result
        conflict = result.error
        if conflict is None:
            message = "Archive did not produce a result"
        else:
            message = str(conflict)
            extra = len(result.conflicts) - 1
            if extra:
                message = f"{message} ({extra} more conflict(s))"
        super().__init__(message)

    @property
    def source(self):
        return self.result.source

    @property
    def position(self):
        return self.result.failure_position

    @property
    def conflicts(self):
        return self.result.conflicts


ArchiveError = ArchiveConflictError


_UTF8_FAMILY = frozenset({"utf-8", "utf-8-sig"})
_UTF16_FAMILY = frozenset({"utf-16", "utf-16-le", "utf-16-be"})
_UTF32_FAMILY = frozenset({"utf-32", "utf-32-le", "utf-32-be"})

_ENCODING_ALIASES = {
    "unicode": "utf-8",
    "unicode-1-1-utf-8": "utf-8",
    "x-unicode20utf8": "utf-8",
    "us-ascii": "ascii",
    "windows-1252": "cp1252",
    "x-sjis": "shift_jis",
    "ms_kanji": "shift_jis",
    "csshiftjis": "shift_jis",
    "gb_2312-80": "gb2312",
    "x-gbk": "gbk",
    "ks_c_5601-1987": "cp949",
}

_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)

_META_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_ATTRIBUTE_RE = re.compile(r"""([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
_CHARSET_RE = re.compile(
    r"""charset\s*=\s*(?:"([^"]*)"|'([^']*)'|([^;\s"']+))""",
    re.IGNORECASE,
)
_XML_DECL_RE = re.compile(
    r"""<\?xml\b[^?]*?\bencoding\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9!#$%&'*+\-.^_`|~]+")
_HEADER_SEPARATOR_RE = re.compile(rb"\r?\n\r?\n")

_KNOWN_EMAIL_HEADERS = frozenset(
    {
        "bcc",
        "cc",
        "content-disposition",
        "content-transfer-encoding",
        "content-type",
        "date",
        "from",
        "message-id",
        "mime-version",
        "received",
        "reply-to",
        "return-path",
        "sender",
        "subject",
        "to",
    }
)

_IDENTITY_TRANSFER_ENCODINGS = frozenset({"", "7bit", "8bit", "binary", "identity"})
_METADATA_SCAN_LIMIT = 64 * 1024


@dataclass(frozen=True, slots=True)
class _EmailParts:
    body_start: int
    headers: dict[str, tuple[str, int, int]]


def _canonical_encoding(label: str):
    if not isinstance(label, str):
        raise TypeError(f"Encoding must be a string, got {type(label)!r}")
    value = label.strip().strip("\"'").strip()
    if not value:
        raise LookupError("Empty encoding label")
    try:
        info = codecs.lookup(value)
    except LookupError:
        replacement = _ENCODING_ALIASES.get(value.lower())
        if replacement is None:
            raise
        info = codecs.lookup(replacement)
    if not getattr(info, "_is_text_encoding", True):
        raise LookupError(f"{label!r} is not a text encoding")
    return info.name


def _same_family(first: str, second: str):
    if first == second:
        return True
    if first in _UTF8_FAMILY and second in _UTF8_FAMILY:
        return True
    if first == "utf-16" and second in _UTF16_FAMILY:
        return True
    if second == "utf-16" and first in _UTF16_FAMILY:
        return True
    if first == "utf-32" and second in _UTF32_FAMILY:
        return True
    return second == "utf-32" and first in _UTF32_FAMILY


def _detect_bom(data: bytes, start: int = 0):
    prefix = data[start : start + 4]
    for bom, encoding in _BOMS:
        if prefix.startswith(bom):
            return bom, encoding
    return b"", None


def _position(raw: bytes, source: str | None, offset: int):
    offset = max(0, min(offset, len(raw)))
    prefix = raw[:offset]
    line = prefix.count(b"\n") + 1
    column = offset - prefix.rfind(b"\n")
    return SourcePosition(offset, line, column, source)


def _conflict(
    code,
    message,
    raw,
    source,
    offset,
    *,
    declared_encoding=None,
    metadata_encoding=None,
    metadata_kind=None,
    byte_range=None,
):
    if byte_range is None:
        start = max(0, min(offset, len(raw)))
        byte_range = InputRange(start, min(start + 1, len(raw)), source)
    return ArchiveConflict(
        code=code,
        message=message,
        position=_position(raw, source, offset),
        source=source,
        declared_encoding=declared_encoding,
        metadata_encoding=metadata_encoding,
        metadata_kind=metadata_kind,
        byte_range=byte_range,
    )


def _make_evidence(kind, raw_value, source, start, end):
    value = raw_value.strip().strip("\"'").strip()
    try:
        encoding = _canonical_encoding(value)
    except (LookupError, TypeError) as exc:
        encoding = None
        error = str(exc) or "Unknown encoding"
    else:
        error = None
    return EncodingEvidence(
        kind=kind,
        encoding=encoding,
        raw_value=value,
        byte_range=InputRange(max(0, start), max(start, end), source),
        error=error,
    )


def _split_email_headers(data: bytes):
    match = _HEADER_SEPARATOR_RE.search(data[:_METADATA_SCAN_LIMIT])
    if match is None or match.start() == 0:
        return None

    header_text = data[: match.start()].decode("latin-1")
    headers: dict[str, tuple[str, int, int]] = {}
    offset = 0
    for line in header_text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        if not content or content[0] in " \t":
            offset += len(line)
            continue
        name, separator, value = content.partition(":")
        if not separator or not _HEADER_NAME_RE.fullmatch(name):
            return None
        key = name.lower()
        raw_value = content[len(name) + 1 :]
        stripped_value = raw_value.strip()
        leading = len(raw_value) - len(raw_value.lstrip())
        value_start = offset + len(name) + 1 + leading
        headers.setdefault(
            key,
            (value.strip(), value_start, value_start + len(stripped_value)),
        )
        offset += len(line)

    if not (_KNOWN_EMAIL_HEADERS & headers.keys()):
        return None
    return _EmailParts(body_start=match.end(), headers=headers)


def _decode_for_scan(body: bytes, probe: str | None):
    """Return text and a character-index -> byte-offset mapper."""
    if probe:
        try:
            if not probe.startswith(("utf-16", "utf-32")) and (
                b"<meta charset='utf-8'>".decode(probe) == "<meta charset='utf-8'>"
            ):
                return body.decode("latin-1"), lambda index: index
            text = body.decode(probe, errors="replace")
        except (LookupError, UnicodeError):
            pass
        else:
            return text, lambda index: _encoded_prefix_length(text, index, probe)
    return body.decode("latin-1"), lambda index: index


def _encoded_prefix_length(text: str, index: int, encoding: str):
    try:
        return len(text[:index].encode(encoding, errors="replace"))
    except (LookupError, UnicodeError):
        return index


def _inside_comment(text: str, index: int):
    return text.rfind("<!--", 0, index) > text.rfind("-->", 0, index)


def _attribute_values(tag_text: str):
    values = {}
    for match in _ATTRIBUTE_RE.finditer(tag_text):
        group = match.lastindex
        if group is None:
            continue
        values[match.group(1).lower()] = (
            match.group(group),
            match.start(group),
            match.end(group),
        )
    return values


def _charset_value(value: str):
    match = _CHARSET_RE.search(value)
    if match is None:
        return None
    group = match.lastindex
    if group is None:
        return None
    return match.group(group), match.start(group), match.end(group)


def _scan_body_metadata(raw: bytes, start: int, probe: str | None, source: str | None):
    body = raw[start:]
    text, to_byte = _decode_for_scan(body, probe)
    evidence = []

    leading = re.match(r"[\s\ufeff]*", text)
    xml_start = leading.end() if leading else 0
    xml_match = _XML_DECL_RE.match(text, xml_start)
    if xml_match is not None:
        evidence.append(
            _make_evidence(
                "xml",
                xml_match.group(1),
                source,
                start + to_byte(xml_match.start(1)),
                start + to_byte(xml_match.end(1)),
            )
        )

    scan_text = text[:_METADATA_SCAN_LIMIT]
    for match in _META_RE.finditer(scan_text):
        if _inside_comment(text, match.start()):
            continue
        tag = match.group(0)
        attributes = _attribute_values(tag)
        charset = attributes.get("charset")
        if charset is not None:
            value, value_start, value_end = charset
            evidence.append(
                _make_evidence(
                    "html-meta",
                    value,
                    source,
                    start + to_byte(match.start() + value_start),
                    start + to_byte(match.start() + value_end),
                )
            )
            continue

        http_equiv = attributes.get("http-equiv")
        content = attributes.get("content")
        if (
            http_equiv is None
            or content is None
            or http_equiv[0].strip().lower() != "content-type"
        ):
            continue
        parsed = _charset_value(content[0])
        if parsed is None:
            continue
        value, value_start, _value_end = parsed
        absolute_start = match.start() + content[1] + value_start
        absolute_end = match.start() + content[1] + parsed[2]
        evidence.append(
            _make_evidence(
                "html-meta",
                value,
                source,
                start + to_byte(absolute_start),
                start + to_byte(absolute_end),
            )
        )

    return evidence


def _email_metadata(raw: bytes, email: _EmailParts, source: str | None):
    evidence = []
    conflicts = []

    content_type = email.headers.get("content-type")
    if content_type is not None:
        value, value_start, _value_end = content_type
        parsed = _charset_value(value)
        if parsed is not None:
            charset, charset_start, charset_end = parsed
            evidence.append(
                _make_evidence(
                    "mime",
                    charset,
                    source,
                    value_start + charset_start,
                    value_start + charset_end,
                )
            )
        media_type = value.split(";", 1)[0].strip().lower()
        if media_type.startswith("multipart/"):
            conflicts.append(
                _conflict(
                    "unsupported_multipart",
                    f"Multipart email bodies are not supported ({media_type!r})",
                    raw,
                    source,
                    value_start,
                    byte_range=InputRange(
                        value_start, value_start + len(value), source
                    ),
                )
            )

    transfer = email.headers.get("content-transfer-encoding")
    if transfer is not None:
        value, value_start, _value_end = transfer
        encoding = value.strip().lower()
        if encoding not in _IDENTITY_TRANSFER_ENCODINGS:
            conflicts.append(
                _conflict(
                    "unsupported_transfer_encoding",
                    (
                        "Content-Transfer-Encoding "
                        f"{value.strip()!r} is not supported; the archive bytes"
                        " were not altered"
                    ),
                    raw,
                    source,
                    value_start,
                    byte_range=InputRange(
                        value_start, value_start + len(value), source
                    ),
                )
            )

    return evidence, conflicts


def _resolved_declared_encoding(
    declared_raw, evidence, bom_encoding, raw, source, conflicts
):
    if declared_raw is not None:
        try:
            return _canonical_encoding(declared_raw)
        except LookupError as exc:
            conflicts.append(
                _conflict(
                    "unknown_declared_encoding",
                    f"Unknown encoding declaration {declared_raw!r}: {exc}",
                    raw,
                    source,
                    0,
                    declared_encoding=declared_raw,
                )
            )
            return None

    if bom_encoding is not None:
        return bom_encoding

    candidates = []
    for item in evidence:
        if item.encoding is not None and item.encoding not in candidates:
            candidates.append(item.encoding)
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        conflicts.append(
            _conflict(
                "missing_declared_encoding",
                "No encoding declaration was supplied and the document has no metadata",
                raw,
                source,
                0,
            )
        )
    else:
        conflicts.append(
            _conflict(
                "ambiguous_declared_encoding",
                (
                    "No encoding declaration was supplied and body metadata"
                    f" disagrees: {', '.join(candidates)}"
                ),
                raw,
                source,
                0,
            )
        )
    return None


def _decode_payload(payload, payload_start, encoding, raw, source, declared, conflicts):
    try:
        return payload.decode(encoding, errors="strict")
    except UnicodeDecodeError as exc:
        failure = payload_start + exc.start
        end = payload_start + max(exc.end, exc.start + 1)
        conflicts.append(
            _conflict(
                "undecodable_bytes",
                (
                    f"Bytes are not decodable as {encoding!r} at byte {failure}:"
                    f" {exc.reason}"
                ),
                raw,
                source,
                failure,
                declared_encoding=declared,
                byte_range=InputRange(failure, min(end, len(raw)), source),
            )
        )
    except UnicodeError as exc:
        conflicts.append(
            _conflict(
                "undecodable_bytes",
                f"Bytes are not decodable as {encoding!r}: {exc}",
                raw,
                source,
                payload_start,
                declared_encoding=declared,
            )
        )
    except LookupError as exc:
        conflicts.append(
            _conflict(
                "unknown_encoding",
                f"Encoding {encoding!r} is unavailable: {exc}",
                raw,
                source,
                payload_start,
                declared_encoding=declared,
            )
        )
    return None


def _decode_with_evidence(encoding, bom_encoding):
    if bom_encoding is not None and encoding in {"utf-16", "utf-32"}:
        return bom_encoding
    return encoding


def _check_metadata(
    evidence,
    payload,
    payload_start,
    expected_text,
    declared,
    bom_encoding,
    raw,
    source,
    conflicts,
    warnings,
    *,
    strict_labels=True,
):
    corroborated = bom_encoding is not None and _same_family(bom_encoding, declared)
    comparison_encoding = _decode_with_evidence(declared, bom_encoding)
    for item in evidence:
        if item.kind == "bom" and bom_encoding is not None:
            continue
        if item.encoding is None:
            conflicts.append(
                _conflict(
                    "unknown_metadata_encoding",
                    (
                        f"{item.kind} declares unknown encoding"
                        f" {item.raw_value!r}: {item.error or 'unknown encoding'}"
                    ),
                    raw,
                    source,
                    item.byte_range.start,
                    declared_encoding=declared,
                    metadata_encoding=item.raw_value,
                    metadata_kind=item.kind,
                    byte_range=item.byte_range,
                )
            )
            continue
        if _same_family(item.encoding, comparison_encoding):
            corroborated = True
            continue

        if strict_labels:
            conflicts.append(
                _conflict(
                    "metadata_mismatch",
                    (
                        f"{item.kind} declares {item.raw_value!r}, but the"
                        f" declaration says {declared!r}"
                    ),
                    raw,
                    source,
                    item.byte_range.start,
                    declared_encoding=declared,
                    metadata_encoding=item.encoding,
                    metadata_kind=item.kind,
                    byte_range=item.byte_range,
                )
            )
            continue

        alternative_encoding = _decode_with_evidence(item.encoding, bom_encoding)
        try:
            alternative_text = _strip_leading_bom(
                payload.decode(alternative_encoding, errors="strict")
            )
        except (LookupError, UnicodeError) as exc:
            conflicts.append(
                _conflict(
                    "metadata_undecodable",
                    (
                        f"{item.kind} declares {item.raw_value!r}, which cannot"
                        f" decode the archive body: {exc}"
                    ),
                    raw,
                    source,
                    item.byte_range.start,
                    declared_encoding=declared,
                    metadata_encoding=item.encoding,
                    metadata_kind=item.kind,
                    byte_range=item.byte_range,
                )
            )
            continue

        if alternative_text != expected_text:
            difference = _first_difference(alternative_text, expected_text)
            conflicts.append(
                _conflict(
                    "metadata_mismatch",
                    (
                        f"{item.kind} declares {item.raw_value!r}, but the"
                        f" body decoded as {declared!r} differs; the two"
                        f" interpretations differ at character {difference}"
                    ),
                    raw,
                    source,
                    item.byte_range.start,
                    declared_encoding=declared,
                    metadata_encoding=item.encoding,
                    metadata_kind=item.kind,
                    byte_range=item.byte_range,
                )
            )
        else:
            corroborated = True
            warnings.append(
                f"{item.kind} label {item.raw_value!r} differs from"
                f" {declared!r} but the body decodes identically"
            )
    return corroborated


def _strip_leading_bom(text: str):
    if text.startswith("\ufeff"):
        return text[1:]
    return text


def _first_difference(first: str, second: str):
    for index, (left, right) in enumerate(zip(first, second, strict=False)):
        if left != right:
            return index
    return min(len(first), len(second))


def _check_ambiguity(
    payload,
    payload_start,
    expected_text,
    declared,
    corroborated,
    raw,
    source,
    conflicts,
):
    """Reject legacy-looking bytes which are also a different valid UTF-8 text.

    An independent declaration is authoritative when it is corroborated by
    in-document metadata.  Without such evidence, accepting a legacy byte
    sequence which is also valid UTF-8 would silently choose one of two
    observable interpretations.
    """

    if declared in _UTF8_FAMILY or corroborated:
        return
    try:
        alternative = _strip_leading_bom(payload.decode("utf-8", errors="strict"))
    except UnicodeError:
        return
    if alternative == expected_text:
        return
    conflicts.append(
        _conflict(
            "ambiguous_interpretation",
            (
                f"Body is valid as both {declared!r} and 'utf-8' with different"
                " text, and no BOM or body metadata corroborates the declaration"
            ),
            raw,
            source,
            payload_start,
            declared_encoding=declared,
            metadata_encoding="utf-8",
        )
    )


def sanitize_archive(  # noqa: C901 -- explicit validation and audit steps
    data,
    declared_encoding=None,
    *,
    source=None,
    encoding=None,
    sanitizer=None,
    require_metadata=False,
    check_ambiguity=True,
    strict_labels=True,
    on_conflict="return",
    strict=None,
):
    """Strictly decode *data* and sanitize it.

    :param data: Archive document bytes (``bytes``, ``bytearray`` or
        ``memoryview``).  Strings deliberately belong to
        :meth:`Sanitizer.sanitize`.
    :param declared_encoding: Encoding label supplied by an independent
        catalogue/import source.  ``encoding=`` is an alias.
    :param source: Optional source name stored in every result and conflict.
    :param sanitizer: Optional :class:`Sanitizer` instance.
    :param require_metadata: Require BOM/MIME/XML/HTML metadata corroborating
        the declaration.  Disabled by default so archives whose headers were
        lost can still use an independent declaration.
    :param check_ambiguity: Reject uncorroborated legacy input which is also
        valid UTF-8 with a different text.
    :param strict_labels: Require in-document metadata to use the same
        canonical encoding label as the declaration.  Set to ``False`` to
        accept a different label when it decodes the body identically.
    :param on_conflict: ``"return"`` (default) returns a conflict result;
        ``"raise"`` raises :class:`ArchiveConflictError`.
    :param strict: Optional boolean alias for ``on_conflict``.
    """

    if declared_encoding is not None and not isinstance(declared_encoding, str):
        raise TypeError(
            "declared_encoding must be a string or None,"
            f" got {type(declared_encoding)!r}"
        )
    if encoding is not None and not isinstance(encoding, str):
        raise TypeError(f"encoding must be a string or None, got {type(encoding)!r}")

    if encoding is not None:
        if declared_encoding is not None:
            try:
                same = _canonical_encoding(declared_encoding) == _canonical_encoding(
                    encoding
                )
            except (LookupError, TypeError):
                same = False
            if not same:
                raise ValueError(
                    "declared_encoding and encoding refer to different encodings"
                )
        declared_encoding = encoding

    if strict is not None:
        on_conflict = "raise" if strict else "return"
    if on_conflict not in {"return", "raise"}:
        raise ValueError("on_conflict must be 'return' or 'raise'")

    if isinstance(data, str):
        raise TypeError("sanitize_archive() requires bytes; use sanitize() for strings")
    try:
        raw = bytes(data)
    except TypeError as exc:
        raise TypeError(
            f"sanitize_archive() requires bytes-like data, got {type(data)!r}"
        ) from exc
    if source is not None and not isinstance(source, str):
        try:
            source = os.fspath(source)
        except TypeError as exc:
            raise TypeError(
                "source must be a string, path-like object or None,"
                f" got {type(source)!r}"
            ) from exc
        if not isinstance(source, str):
            raise TypeError("source must resolve to a string")
    if not isinstance(require_metadata, bool):
        raise TypeError("require_metadata must be a boolean")
    if not isinstance(check_ambiguity, bool):
        raise TypeError("check_ambiguity must be a boolean")
    if not isinstance(strict_labels, bool):
        raise TypeError("strict_labels must be a boolean")

    sanitizer = Sanitizer() if sanitizer is None else sanitizer
    character_form = (
        "NFC" if getattr(sanitizer, "keep_typographic_whitespace", False) else "NFKC"
    )
    digest = hashlib.sha256(raw).hexdigest()
    document_range = InputRange(0, len(raw), source)
    conflicts = []
    warnings = []

    email = _split_email_headers(raw)
    body_start = email.body_start if email is not None else 0
    bom, bom_encoding = _detect_bom(raw, body_start)
    payload_start = body_start + len(bom)
    payload = raw[payload_start:]

    metadata = []
    if bom_encoding is not None:
        metadata.append(
            EncodingEvidence(
                kind="bom",
                encoding=bom_encoding,
                raw_value=bom.hex(),
                byte_range=InputRange(body_start, payload_start, source, bom_encoding),
            )
        )
    if email is not None:
        email_evidence, email_conflicts = _email_metadata(raw, email, source)
        metadata.extend(email_evidence)
        conflicts.extend(email_conflicts)

    probe = bom_encoding
    if probe is None and declared_encoding is not None:
        try:
            probe = _canonical_encoding(declared_encoding)
        except (LookupError, TypeError):
            probe = None
    metadata.extend(_scan_body_metadata(raw, payload_start, probe, source))

    declared = _resolved_declared_encoding(
        declared_encoding,
        metadata,
        bom_encoding,
        raw,
        source,
        conflicts,
    )

    if declared is None:
        return _finish_result(
            raw=raw,
            source=source,
            digest=digest,
            document_range=document_range,
            input_range=InputRange(payload_start, len(raw), source),
            declared_encoding=declared_encoding,
            encoding=None,
            metadata=metadata,
            conflicts=conflicts,
            warnings=warnings,
            on_conflict=on_conflict,
            character_form=character_form,
        )

    if bom_encoding is not None and not _same_family(declared, bom_encoding):
        conflicts.append(
            _conflict(
                "bom_mismatch",
                (
                    f"Byte-order mark indicates {bom_encoding!r} but the"
                    f" declaration says {declared!r}"
                ),
                raw,
                source,
                body_start,
                declared_encoding=declared,
                metadata_encoding=bom_encoding,
                metadata_kind="bom",
                byte_range=InputRange(body_start, payload_start, source),
            )
        )

    decode_encoding = _decode_with_evidence(declared, bom_encoding)
    text = _decode_payload(
        payload,
        payload_start,
        decode_encoding,
        raw,
        source,
        declared,
        conflicts,
    )

    text_start = payload_start
    if text is not None and text.startswith("\ufeff"):
        text = text[1:]
        text_start += _encoded_prefix_length("\ufeff", 1, decode_encoding)

    if text is not None:
        corroborated = _check_metadata(
            metadata,
            payload,
            payload_start,
            text,
            declared,
            bom_encoding,
            raw,
            source,
            conflicts,
            warnings,
            strict_labels=strict_labels,
        )
        if not corroborated and not conflicts:
            warnings.append(
                f"No BOM or body metadata corroborates the declaration {declared!r}"
            )
        if require_metadata and not metadata:
            conflicts.append(
                _conflict(
                    "missing_metadata",
                    (
                        "Strict mode requires BOM or body metadata corroborating"
                        f" the declaration {declared!r}, but none was found"
                    ),
                    raw,
                    source,
                    payload_start,
                    declared_encoding=declared,
                )
            )
        if check_ambiguity:
            _check_ambiguity(
                payload,
                payload_start,
                text,
                declared,
                corroborated,
                raw,
                source,
                conflicts,
            )

    html = None
    if text is not None and not conflicts:
        try:
            html = sanitizer.sanitize(text)
        except Exception as exc:
            conflicts.append(
                _conflict(
                    "sanitization_error",
                    f"Sanitizer failed: {exc}",
                    raw,
                    source,
                    payload_start,
                    declared_encoding=declared,
                )
            )

    return _finish_result(
        raw=raw,
        source=source,
        digest=digest,
        document_range=document_range,
        input_range=InputRange(
            text_start,
            len(raw),
            source,
            decode_encoding if text is not None else None,
        ),
        declared_encoding=declared,
        encoding=decode_encoding,
        text=text if not conflicts else None,
        html=html,
        metadata=metadata,
        conflicts=conflicts,
        warnings=warnings,
        on_conflict=on_conflict,
        character_form=character_form,
    )


def _finish_result(
    *,
    raw,
    source,
    digest,
    document_range,
    input_range,
    declared_encoding,
    encoding,
    metadata,
    conflicts,
    warnings,
    on_conflict,
    character_form="NFKC",
    text=None,
    html=None,
):
    unique_warnings = tuple(dict.fromkeys(warnings))
    result = ArchiveResult(
        source=source,
        status=ArchiveStatus.CONFLICT if conflicts else ArchiveStatus.ACCEPTED,
        digest=digest,
        input_range=input_range,
        document_range=document_range,
        declared_encoding=declared_encoding,
        encoding=encoding,
        text=text,
        html=html,
        metadata=tuple(metadata),
        conflicts=tuple(conflicts),
        warnings=unique_warnings,
        character_form=character_form,
    )
    if on_conflict == "raise" and conflicts:
        raise ArchiveConflictError(result)
    return result


def review_archive(data, declared_encoding=None, **kwargs):
    """Return an :class:`ArchiveResult` without raising on conflicts."""
    kwargs["on_conflict"] = "return"
    return sanitize_archive(data, declared_encoding, **kwargs)


def render_review(result: ArchiveResult, *, include_html=False):
    """Render one human-readable review line."""
    source = result.source or "<memory>"
    digest = result.digest[:16]
    if result.ok:
        line = (
            f"ACCEPTED {source} bytes={result.input_range.start}:"
            f"{result.input_range.end} encoding={result.encoding or '-'}"
            f" sha256={digest}"
        )
        if result.warnings:
            line += f" warnings={len(result.warnings)}"
        if include_html:
            line += f" html={result.html!r}"
        return line

    conflict = result.error
    if conflict is None:
        return f"CONFLICT {source} sha256={digest}"
    extra = (
        f" metadata={conflict.metadata_encoding}" if conflict.metadata_encoding else ""
    )
    position = conflict.position
    if position.source == result.source:
        location = f"{position.line}:{position.column} (byte {position.byte_offset})"
    else:
        location = str(position)
    return (
        f"CONFLICT {source} {location} code={conflict.code}"
        f" declared={conflict.declared_encoding or result.declared_encoding or '-'}"
        f"{extra} sha256={digest}: {conflict.message}"
    )


def render_reviews(results: Iterable[ArchiveResult], *, include_html=False):
    """Render multiple review lines, accepted and rejected alike."""
    return "\n".join(
        render_review(result, include_html=include_html) for result in results
    )


def review_archives(archives, *, sanitizer=None, include_html=False, **kwargs):
    """Review several archives and return a printable report.

    Items may be ``(source, data, encoding)`` tuples, ``(data, encoding)``
    tuples, mappings with ``data``/``source``/``encoding`` keys, or existing
    :class:`ArchiveResult` objects.
    """
    results = []
    for item in archives:
        if isinstance(item, ArchiveResult):
            results.append(item)
            continue
        if isinstance(item, dict):
            data = item["data"]
            declared = item.get("declared_encoding") or item.get("encoding")
            source = item.get("source")
            results.append(
                sanitize_archive(
                    data,
                    declared,
                    source=source,
                    sanitizer=sanitizer,
                    on_conflict="return",
                    **kwargs,
                )
            )
            continue
        if len(item) == 3:
            source, data, declared = item
        elif len(item) == 2:
            data, declared = item
            source = None
        else:
            raise TypeError(
                "Archive entries must be (source, data, encoding) or (data, encoding)"
            )
        results.append(
            sanitize_archive(
                data,
                declared,
                source=source,
                sanitizer=sanitizer,
                on_conflict="return",
                **kwargs,
            )
        )
    return render_reviews(results, include_html=include_html)

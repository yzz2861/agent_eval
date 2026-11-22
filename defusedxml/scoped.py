# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Grant-scoped reading on top of the defused SAX parser.

The module is intended for import services that fan one XML document out to
several processors.  A processor never receives the parsed document or a SAX
handler.  It only receives a :class:`ProcessorView` containing materialized
copies of the tree segments named in its :class:`ReadGrant`.

The grant is attached when a source is opened, copied into the SAX handler,
and copied again into every output view.  The same source digest and grant id
can therefore be checked at all three stages.

Only authorized element copies are kept in a view.  There is no lazy lookup
back into the complete tree, no reference to the parser/handler, and no raw
source buffer.  Asking for a branch that is not covered by the grant raises
:class:`AccessDenied` with a constant message.  The exception deliberately
does not inherit from ``KeyError``/``LookupError`` and does not echo the
requested path or any XML value.
"""

from __future__ import absolute_import

import hashlib
import io
import os
from itertools import combinations
from types import MappingProxyType
from xml.etree.ElementTree import Element
from xml.sax import SAXParseException
from xml.sax.handler import ContentHandler

from .common import (
    DTDForbidden,
    DefusedXmlException,
    EntitiesForbidden,
    ExternalReferenceForbidden,
)
from .sax import make_parser

__all__ = [
    "AccessDenied",
    "AuditEntry",
    "DeniedEvidence",
    "FailureEvidence",
    "GrantView",
    "ManagedReader",
    "ProcessorView",
    "ReadGrant",
    "ScopedDocument",
    "ScopedReadError",
    "ScopedSegment",
    "SegmentBoundary",
    "SourceInfo",
    "open_scoped",
    "read_scoped",
]


_DENIED_MESSAGE = "requested tree segment is not available"


def _normalize_path(path):
    if isinstance(path, str):
        value = path.strip()
        if value.startswith("/"):
            value = value[1:]
        if not value:
            raise ValueError("segment path must not be empty")
        parts = tuple(value.split("/"))
    elif isinstance(path, (tuple, list)):
        parts = tuple(path)
    else:
        raise TypeError("segment path must be a string or a sequence of names")

    if not parts:
        raise ValueError("segment path must not be empty")
    for part in parts:
        if not isinstance(part, str) or not part:
            raise ValueError("segment path names must be non-empty strings")
        if "/" in part or part in (".", ".."):
            raise ValueError("segment path names must be single XML names")
    return parts


def _normalize_paths(paths):
    if isinstance(paths, str):
        paths = (paths,)
    elif (
        isinstance(paths, tuple)
        and paths
        and all(isinstance(path, str) for path in paths)
        and not any("/" in path for path in paths)
    ):
        # A tuple of bare names is one component path.
        paths = (paths,)
    elif (
        isinstance(paths, (tuple, list))
        and paths
        and all(isinstance(path, (str, tuple, list)) for path in paths)
    ):
        # A list, or a tuple containing slash-delimited strings, is a
        # collection of paths.
        paths = tuple(paths)
    try:
        return tuple(_normalize_path(path) for path in paths)
    except TypeError:
        raise TypeError("paths must be an iterable of segment paths")


def _is_prefix(prefix, path):
    return path[: len(prefix)] == prefix


def _path_text(path):
    return "/".join(path)


def _path_digest(path):
    return hashlib.sha256(_path_text(path).encode("utf-8")).hexdigest()[:16]


class ReadGrant(object):
    """Immutable authorization declaration for one processor.

    ``allowed`` names absolute element paths relative to the document root.
    Every element whose path equals an allowed path starts one output tree
    segment.  All of its descendants belong to that segment unless they match
    ``denied``.

    ``required`` defaults to ``allowed``.  A required path that never occurs is
    reported as a missing segment instead of an exception.
    """

    __slots__ = ("processor", "allowed", "required", "denied")

    def __init__(self, processor, allowed, required=None, denied=()):
        if not isinstance(processor, str) or not processor:
            raise ValueError("processor must be a non-empty string")
        allowed = _normalize_paths(allowed)
        denied = _normalize_paths(denied) if denied else ()
        required = allowed if required is None else _normalize_paths(required)

        if not allowed:
            raise ValueError("a grant must allow at least one tree segment")
        for left, right in combinations(allowed, 2):
            if _is_prefix(left, right) or _is_prefix(right, left):
                raise ValueError("allowed tree segments must not overlap")
        for path in required:
            if not any(_is_prefix(segment, path) for segment in allowed):
                raise ValueError("required paths must be covered by an allowed segment")
        for segment in allowed:
            if any(_is_prefix(path, segment) for path in denied):
                raise ValueError("an allowed tree segment must not be denied")

        self.processor = processor
        self.allowed = allowed
        self.required = required
        self.denied = denied

    def __repr__(self):
        return "ReadGrant(processor={!r}, allowed={!r}, required={!r}, denied={!r})".format(
            self.processor, self.allowed, self.required, self.denied
        )


class GrantView(object):
    """Read-only snapshot of a grant as carried through the parse."""

    __slots__ = ("processor", "allowed", "required", "denied", "grant_id", "source_digest")

    def __init__(self, grant, source_digest):
        self.processor = grant.processor
        self.allowed = grant.allowed
        self.required = grant.required
        self.denied = grant.denied
        self.source_digest = source_digest
        material = "\0".join(
            [grant.processor, source_digest]
            + [_path_text(path) for path in grant.allowed]
            + [_path_text(path) for path in grant.required]
            + [_path_text(path) for path in grant.denied]
        )
        self.grant_id = hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]

    def __repr__(self):
        return "GrantView(processor={!r}, grant_id={!r}, allowed={!r}, required={!r})".format(
            self.processor, self.grant_id, self.allowed, self.required
        )


class SourceInfo(object):
    """Safe source metadata; raw bytes are intentionally not retained."""

    __slots__ = ("name", "sha256", "size")

    def __init__(self, name, sha256, size):
        self.name = name
        self.sha256 = sha256
        self.size = size

    def __repr__(self):
        return "SourceInfo(name={!r}, sha256={!r}, size={!r})".format(
            self.name, self.sha256, self.size
        )


class SegmentBoundary(object):
    """Location of one concrete or missing tree segment.

    Event indexes count start/end element events in the complete document.
    Line and column values come from the SAX locator.
    """

    __slots__ = (
        "path",
        "present",
        "reason",
        "start_event",
        "end_event",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
        "depth",
    )

    def __init__(
        self,
        path,
        present,
        reason,
        start_event=None,
        end_event=None,
        start_line=None,
        start_column=None,
        end_line=None,
        end_column=None,
    ):
        self.path = path
        self.present = present
        self.reason = reason
        self.start_event = start_event
        self.end_event = end_event
        self.start_line = start_line
        self.start_column = start_column
        self.end_line = end_line
        self.end_column = end_column
        self.depth = len(path)

    @property
    def path_text(self):
        return _path_text(self.path)

    def as_dict(self):
        return {
            "path": _path_text(self.path),
            "present": self.present,
            "reason": self.reason,
            "start_event": self.start_event,
            "end_event": self.end_event,
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "depth": self.depth,
        }

    def __repr__(self):
        return "SegmentBoundary(path={!r}, present={!r}, reason={!r}, events={!r}..{!r})".format(
            _path_text(self.path),
            self.present,
            self.reason,
            self.start_event,
            self.end_event,
        )


class ScopedSegment(object):
    """A materialized tree segment, or a safe missing-item hint."""

    __slots__ = ("path", "boundary", "root", "grant_id")

    def __init__(self, path, boundary, root, grant_id):
        self.path = path
        self.boundary = boundary
        self.root = root
        self.grant_id = grant_id

    @property
    def present(self):
        return self.root is not None

    @property
    def missing(self):
        return self.root is None

    @property
    def path_text(self):
        return _path_text(self.path)

    def to_xml(self):
        if self.root is None:
            return ""
        from xml.etree.ElementTree import tostring

        return tostring(self.root, encoding="unicode")

    def __repr__(self):
        return "ScopedSegment(path={!r}, present={!r}, boundary={!r})".format(
            _path_text(self.path), self.present, self.boundary
        )


class AuditEntry(object):
    """Sanitized audit evidence.

    Unauthorized paths are represented by a truncated digest, never by their
    text.  XML values, entity names, and parser error messages are not stored.
    """

    __slots__ = (
        "kind",
        "processor",
        "grant_id",
        "outcome",
        "code",
        "path_digest",
        "source_digest",
        "event_count",
    )

    def __init__(
        self,
        kind,
        outcome,
        processor=None,
        grant_id=None,
        code=None,
        path_digest=None,
        source_digest=None,
        event_count=None,
    ):
        self.kind = kind
        self.processor = processor
        self.grant_id = grant_id
        self.outcome = outcome
        self.code = code
        self.path_digest = path_digest
        self.source_digest = source_digest
        self.event_count = event_count

    def as_dict(self):
        return {
            "kind": self.kind,
            "processor": self.processor,
            "grant_id": self.grant_id,
            "outcome": self.outcome,
            "code": self.code,
            "path_digest": self.path_digest,
            "source_digest": self.source_digest,
            "event_count": self.event_count,
        }

    def __repr__(self):
        return (
            "AuditEntry(kind={!r}, processor={!r}, outcome={!r}, code={!r}, " "path_digest={!r})"
        ).format(self.kind, self.processor, self.outcome, self.code, self.path_digest)


class DeniedEvidence(object):
    """Evidence for one refused view lookup."""

    __slots__ = ("kind", "processor", "grant_id", "source_digest", "path_digest", "code")

    def __init__(self, processor, grant_id, source_digest, path_digest):
        self.kind = "access_denied"
        self.processor = processor
        self.grant_id = grant_id
        self.source_digest = source_digest
        self.path_digest = path_digest
        self.code = "not_authorized"

    def as_dict(self):
        return {
            "kind": self.kind,
            "processor": self.processor,
            "grant_id": self.grant_id,
            "source_digest": self.source_digest,
            "path_digest": self.path_digest,
            "code": self.code,
        }

    def __repr__(self):
        return "DeniedEvidence(processor={!r}, grant_id={!r}, path_digest={!r})".format(
            self.processor, self.grant_id, self.path_digest
        )


class FailureEvidence(object):
    """Sanitized evidence for a rejected source/parse."""

    __slots__ = ("kind", "source_digest", "code", "grant_ids", "event_count")

    def __init__(self, source_digest, code, grant_ids, event_count=None, kind="parse_failure"):
        self.kind = kind
        self.source_digest = source_digest
        self.code = code
        self.grant_ids = grant_ids
        self.event_count = event_count

    def as_dict(self):
        return {
            "kind": self.kind,
            "source_digest": self.source_digest,
            "code": self.code,
            "grant_ids": self.grant_ids,
            "event_count": self.event_count,
        }

    def __repr__(self):
        return "FailureEvidence(code={!r}, source_digest={!r}, event_count={!r})".format(
            self.code, self.source_digest, self.event_count
        )


class AccessDenied(Exception):
    """The lookup is outside the processor's grant.

    The message and ``args`` are constant so that a generic exception handler,
    traceback formatter, or debugger cannot recover the requested path or a
    value from an unauthorized branch.
    """

    __slots__ = ("evidence",)

    def __init__(self, evidence):
        super(AccessDenied, self).__init__()
        self.evidence = evidence

    def __str__(self):
        return _DENIED_MESSAGE

    def __repr__(self):
        return "AccessDenied()"


class ScopedReadError(Exception):
    """A source or parse failure with a stable, non-echoing error code."""

    __slots__ = ("code", "evidence")

    def __init__(self, code, evidence=None):
        super(ScopedReadError, self).__init__(code)
        self.code = code
        self.evidence = evidence

    def __str__(self):
        return "scoped XML read failed ({})".format(self.code)


class _AuditLog(object):
    __slots__ = ("_entries",)

    def __init__(self):
        self._entries = []

    def record(self, **kwargs):
        entry = AuditEntry(**kwargs)
        self._entries.append(entry)
        return entry

    @property
    def entries(self):
        return tuple(self._entries)


class _RawNode(object):
    __slots__ = (
        "tag",
        "attrib",
        "path",
        "authorized",
        "children",
        "text",
        "tail",
        "start_event",
        "end_event",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
    )

    def __init__(self, tag, attrib, path, authorized, locator):
        self.tag = tag
        self.attrib = attrib
        self.path = path
        self.authorized = authorized
        self.children = []
        self.text = []
        self.tail = []
        self.start_event = None
        self.end_event = None
        self.start_line = None
        self.start_column = None
        self.end_line = None
        self.end_column = None
        if locator is not None:
            self.start_line = locator.getLineNumber()
            self.start_column = locator.getColumnNumber()


def _to_element(node, index=None):
    element = Element(node.tag)
    if node.attrib:
        element.attrib.update(node.attrib)
    if node.text:
        element.text = "".join(node.text)
    if index is not None:
        index.append((node.path, node, element))
    for child in node.children:
        if not child.authorized:
            continue
        child_element = _to_element(child, index)
        if child.tail:
            child_element.tail = "".join(child.tail)
        element.append(child_element)
    return element


class _SegmentBuilder(object):
    __slots__ = (
        "grant",
        "segment_path",
        "start_event",
        "stack",
        "root_node",
        "end_event",
        "end_line",
        "end_column",
    )

    def __init__(self, grant, segment_path, start_event, locator):
        self.grant = grant
        self.segment_path = segment_path
        self.start_event = start_event
        self.stack = []
        self.root_node = None
        self.end_event = None
        self.end_line = None
        self.end_column = None

    def _denied(self, path):
        return any(_is_prefix(denied, path) for denied in self.grant.denied)

    def start(self, path, tag, attrs, event_index, locator):
        authorized = not self._denied(path)
        if authorized:
            node = _RawNode(tag, dict(attrs), path, True, locator)
        else:
            # Keep the denied subtree only as a positional placeholder.  Its
            # tag, attributes, text, and path are never retained.
            node = _RawNode(None, None, None, False, locator)
        node.start_event = event_index
        if self.stack:
            self.stack[-1].children.append(node)
        else:
            self.root_node = node
        self.stack.append(node)

    def characters(self, data):
        if not self.stack:
            return
        node = self.stack[-1]
        if not node.authorized:
            return
        if node.children:
            last = node.children[-1]
            if last.authorized:
                last.tail.append(data)
        else:
            node.text.append(data)

    def end(self, path, event_index, locator):
        if not self.stack:
            return
        node = self.stack.pop()
        node.end_event = event_index
        if locator is not None:
            node.end_line = locator.getLineNumber()
            node.end_column = locator.getColumnNumber()
        if not self.stack:
            self.end_event = event_index
            if locator is not None:
                self.end_line = locator.getLineNumber()
                self.end_column = locator.getColumnNumber()

    def finish(self):
        index = []
        _to_element(self.root_node, index)
        segments = []
        for path, node, element in index:
            boundary = SegmentBoundary(
                path,
                True,
                "matched",
                start_event=node.start_event,
                end_event=node.end_event,
                start_line=node.start_line,
                start_column=node.start_column,
                end_line=node.end_line,
                end_column=node.end_column,
            )
            segments.append(ScopedSegment(path, boundary, element, self.grant.grant_id))
        return tuple(segments)


class _GrantCapture(object):
    __slots__ = (
        "grant",
        "segments",
        "started_allowed",
        "seen_required",
        "active",
    )

    def __init__(self, grant):
        self.grant = grant
        self.segments = []
        self.started_allowed = set()
        self.seen_required = set()
        self.active = None

    def _denied(self, path):
        return any(_is_prefix(denied, path) for denied in self.grant.denied)

    def start(self, path, tag, attrs, event_index, locator):
        if self.active is not None:
            self.active.start(path, tag, attrs, event_index, locator)
        elif not self._denied(path) and path in self.grant.allowed:
            self.active = _SegmentBuilder(self.grant, path, event_index, locator)
            self.active.start(path, tag, attrs, event_index, locator)
            self.started_allowed.add(path)

        if path in self.grant.required and not self._denied(path):
            self.seen_required.add(path)

    def characters(self, data):
        if self.active is not None:
            self.active.characters(data)

    def end(self, path, event_index, locator):
        if self.active is None:
            return
        self.active.end(path, event_index, locator)
        if not self.active.stack:
            self.segments.extend(self.active.finish())
            self.active = None

    def clear(self):
        self.segments = []
        self.active = None

    def finish(self):
        by_path = {}
        for segment in self.segments:
            by_path.setdefault(segment.path, []).append(segment)

        missing = []
        for path in self.grant.allowed:
            if path not in self.started_allowed:
                missing.append(path)
        for path in self.grant.required:
            if path not in self.seen_required and path not in missing:
                missing.append(path)

        for path in missing:
            boundary = SegmentBoundary(path, False, "not_found")
            segment = ScopedSegment(path, boundary, None, self.grant.grant_id)
            by_path.setdefault(path, []).append(segment)

        frozen = {path: tuple(values) for path, values in by_path.items()}
        declared = list(self.grant.allowed)
        for path in self.grant.required:
            if path not in declared:
                declared.append(path)
        return ProcessorView(
            self.grant,
            declared,
            frozen,
            tuple(missing),
            self.grant.required,
        )


class _ScopedContentHandler(ContentHandler):
    """SAX sink that only materializes granted segments."""

    __slots__ = ("_captures", "_path", "_event_index", "_locator")

    def __init__(self, grants):
        ContentHandler.__init__(self)
        self._captures = [_GrantCapture(grant) for grant in grants]
        self._path = []
        self._event_index = 0
        self._locator = None

    def setDocumentLocator(self, locator):
        self._locator = locator

    def startElement(self, name, attrs):
        self._path.append(name)
        self._event_index += 1
        path = tuple(self._path)
        for capture in self._captures:
            capture.start(path, name, attrs, self._event_index, self._locator)

    def endElement(self, name):
        self._event_index += 1
        path = tuple(self._path)
        for capture in self._captures:
            capture.end(path, self._event_index, self._locator)
        self._path.pop()

    def characters(self, content):
        for capture in self._captures:
            capture.characters(content)

    @property
    def event_count(self):
        return self._event_index

    def finish(self):
        return tuple(capture.finish() for capture in self._captures)

    def clear(self):
        for capture in self._captures:
            capture.clear()
        self._captures = []
        self._path = []
        self._locator = None


class ProcessorView(object):
    """The only XML-facing object handed to a business processor."""

    __slots__ = (
        "processor",
        "authorization",
        "source",
        "event_count",
        "_declared",
        "_by_path",
        "_missing",
        "_requirements",
        "_evidence",
    )

    def __init__(self, grant, declared, by_path, missing, required):
        self.processor = grant.processor
        self.authorization = grant
        self.source = None
        self.event_count = None
        self._declared = tuple(declared)
        self._by_path = MappingProxyType(by_path)
        self._missing = tuple(missing)
        self._requirements = MappingProxyType({path: path not in missing for path in required})
        self._evidence = []

    @property
    def allowed_paths(self):
        return self.authorization.allowed

    @property
    def required_paths(self):
        return self.authorization.required

    @property
    def requirements(self):
        return self._requirements

    @property
    def missing_paths(self):
        return self._missing

    @property
    def missing(self):
        values = []
        for path in self._missing:
            values.extend(self._by_path.get(path, ()))
        return tuple(values)

    @property
    def evidence(self):
        return tuple(self._evidence)

    def _covered(self, path):
        if any(_is_prefix(denied, path) for denied in self.authorization.denied):
            return False
        return any(_is_prefix(allowed, path) for allowed in self.authorization.allowed)

    def _deny(self, path):
        digest = _path_digest(path)
        evidence = DeniedEvidence(
            self.processor,
            self.authorization.grant_id,
            self.authorization.source_digest,
            digest,
        )
        self._evidence.append(
            AuditEntry(
                kind="access_denied",
                outcome="denied",
                processor=self.processor,
                grant_id=self.authorization.grant_id,
                code="not_authorized",
                path_digest=digest,
                source_digest=self.authorization.source_digest,
            )
        )
        raise AccessDenied(evidence)

    def segments(self, path):
        """Return all authorized occurrences of a path.

        Every element inside a granted segment is indexed, so a nested
        ``required`` path also gets concrete boundaries.  A required path that
        did not occur returns one missing :class:`ScopedSegment`.  Anything
        outside the grant raises :class:`AccessDenied` with a constant message.
        """
        path = _normalize_path(path)
        if path in self._by_path:
            return self._by_path[path]
        if self._covered(path):
            return ()
        self._deny(path)

    def segment(self, path):
        segments = self.segments(path)
        if segments:
            return segments[0]
        return None

    def elements(self, path):
        return tuple(segment.root for segment in self.segments(path) if segment.present)

    def __getitem__(self, path):
        segment = self.segment(path)
        if segment is None:
            raise AccessDenied(
                DeniedEvidence(
                    self.processor,
                    self.authorization.grant_id,
                    self.authorization.source_digest,
                    _path_digest(_normalize_path(path)),
                )
            )
        return segment

    def __iter__(self):
        for path in self._declared:
            for segment in self._by_path.get(path, ()):
                yield segment

    def __len__(self):
        return sum(len(self._by_path.get(path, ())) for path in self._declared)

    def __repr__(self):
        return (
            "ProcessorView(processor={!r}, grant_id={!r}, allowed={!r}, "
            "segments={!r}, missing={!r})"
        ).format(
            self.processor,
            self.authorization.grant_id,
            self.authorization.allowed,
            len(self),
            tuple(_path_text(path) for path in self._missing),
        )


class ScopedDocument(object):
    """Output of one managed read: one isolated view per processor."""

    __slots__ = ("source", "event_count", "audit", "_views", "_authorizations")

    def __init__(self, source, event_count, grants, views, audit):
        self.source = source
        self.event_count = event_count
        self.audit = tuple(audit)
        self._views = MappingProxyType(
            {grant.processor: view for grant, view in zip(grants, views)}
        )
        self._authorizations = MappingProxyType({grant.processor: grant for grant in grants})
        for view in views:
            view.source = source
            view.event_count = event_count

    @property
    def views(self):
        return self._views

    @property
    def authorizations(self):
        return self._authorizations

    def for_processor(self, processor):
        view = self._views.get(processor)
        if view is None:
            raise AccessDenied(DeniedEvidence(processor, None, self.source.sha256, None))
        return view

    def __iter__(self):
        return iter(self._views.values())

    def __len__(self):
        return len(self._views)

    def __repr__(self):
        return "ScopedDocument(source={!r}, processors={!r}, events={!r})".format(
            self.source, tuple(self._views), self.event_count
        )


class AuthorizedSource(object):
    """An opened source with its grant snapshot attached."""

    __slots__ = ("_reader", "_data", "source", "_grants", "_parsed")

    def __init__(self, reader, data, source, grants):
        self._reader = reader
        self._data = data
        self.source = source
        self._grants = grants
        self._parsed = False

    @property
    def grants(self):
        return MappingProxyType({grant.processor: grant for grant in self._grants})

    def parse(self):
        if self._data is None or self._parsed:
            raise ScopedReadError("source_closed")

        handler = _ScopedContentHandler(self._grants)
        parser = make_parser()
        parser.forbid_dtd = self._reader.forbid_dtd
        parser.forbid_entities = self._reader.forbid_entities
        parser.forbid_external = self._reader.forbid_external
        parser.setContentHandler(handler)

        failure = None
        try:
            parser.parse(io.BytesIO(self._data))
        except Exception as exc:
            code = _parse_error_code(exc)
            failure = ScopedReadError(
                code,
                FailureEvidence(
                    self.source.sha256,
                    code,
                    tuple(grant.grant_id for grant in self._grants),
                    handler.event_count,
                ),
            )
        finally:
            self._data = None
            self._parsed = True

        if failure is not None:
            event_count = failure.evidence.event_count
            handler.clear()
            parser = None
            self._reader._audit.record(
                kind="parse_failure",
                outcome="failed",
                code=failure.code,
                source_digest=self.source.sha256,
                event_count=event_count,
            )
            raise failure

        finish_code = None
        try:
            views = handler.finish()
        except RecursionError:
            finish_code = "document_too_deep"
            views = None
        except Exception:
            finish_code = "materialization_failed"
            views = None
        if views is None:
            event_count = handler.event_count
            handler.clear()
            parser = None
            error = ScopedReadError(
                finish_code,
                FailureEvidence(
                    self.source.sha256,
                    finish_code,
                    tuple(grant.grant_id for grant in self._grants),
                    event_count,
                ),
            )
            self._reader._audit.record(
                kind="parse_failure",
                outcome="failed",
                code=finish_code,
                source_digest=self.source.sha256,
                event_count=event_count,
            )
            raise error

        document = ScopedDocument(
            self.source,
            handler.event_count,
            self._grants,
            views,
            self._reader._audit.entries,
        )
        self._reader._audit.record(
            kind="parse",
            outcome="ok",
            source_digest=self.source.sha256,
            event_count=handler.event_count,
        )
        document.audit = self._reader._audit.entries
        return document

    def close(self):
        self._data = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False


def _parse_error_code(exc):
    if isinstance(exc, DTDForbidden):
        return "dtd_forbidden"
    if isinstance(exc, EntitiesForbidden):
        return "entities_forbidden"
    if isinstance(exc, ExternalReferenceForbidden):
        return "external_reference_forbidden"
    if isinstance(exc, DefusedXmlException):
        return "defused_xml_rejected"
    if isinstance(exc, SAXParseException):
        return "malformed_xml"
    if isinstance(exc, RecursionError):
        return "document_too_deep"
    return "parse_failed"


def _read_source(source):
    if isinstance(source, (bytes, bytearray)):
        return bytes(source), "<bytes>"
    if isinstance(source, (str, os.PathLike)):
        path = os.fspath(source)
        with open(path, "rb") as stream:
            return stream.read(), os.path.basename(path) or path

    read = getattr(source, "read", None)
    if read is None:
        raise TypeError("source must be a path, bytes, or a readable file object")
    data = read()
    if isinstance(data, str):
        data = data.encode("utf-8")
    elif isinstance(data, bytearray):
        data = bytes(data)
    elif not isinstance(data, bytes):
        raise TypeError("source.read() must return str or bytes")
    name = getattr(source, "name", None) or "<stream>"
    return data, str(name)


class ManagedReader(object):
    """Defused parser plus grant routing.

    The reader holds only declarations and sanitized audit entries.  Raw XML
    bytes live on :class:`AuthorizedSource` until parsing finishes.
    """

    __slots__ = (
        "forbid_dtd",
        "forbid_entities",
        "forbid_external",
        "max_bytes",
        "_grants",
        "_audit",
    )

    def __init__(
        self,
        grants,
        forbid_dtd=True,
        forbid_entities=True,
        forbid_external=True,
        max_bytes=None,
    ):
        grants = tuple(grants)
        if not grants:
            raise ValueError("at least one ReadGrant is required")
        processors = [grant.processor for grant in grants]
        if len(set(processors)) != len(processors):
            raise ValueError("processor names must be unique")
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external
        self.max_bytes = max_bytes
        self._grants = tuple(
            ReadGrant(grant.processor, grant.allowed, grant.required, grant.denied)
            for grant in grants
        )
        self._audit = _AuditLog()

    @property
    def grants(self):
        return self._grants

    @property
    def audit(self):
        return self._audit.entries

    def open(self, source):
        error = None
        try:
            data, name = _read_source(source)
        except OSError:
            error = ScopedReadError(
                "source_unreadable",
                FailureEvidence(None, "source_unreadable", (), kind="open_failure"),
            )
        if error is not None:
            self._audit.record(
                kind="open",
                outcome="failed",
                code=error.code,
            )
            raise error
        return self._open_data(data, name)

    def _open_data(self, data, name):
        if self.max_bytes is not None and len(data) > self.max_bytes:
            code = "source_too_large"
            digest = hashlib.sha256(data).hexdigest()
            self._audit.record(
                kind="open",
                outcome="failed",
                code=code,
                source_digest=digest,
            )
            raise ScopedReadError(code, FailureEvidence(digest, code, (), kind="open_failure"))

        digest = hashlib.sha256(data).hexdigest()
        info = SourceInfo(name, digest, len(data))
        grants = tuple(GrantView(grant, digest) for grant in self._grants)
        self._audit.record(
            kind="open",
            outcome="ok",
            source_digest=digest,
            event_count=0,
        )
        return AuthorizedSource(self, data, info, grants)

    def fromstring(self, text, name="<string>"):
        if isinstance(text, str):
            data = text.encode("utf-8")
        elif isinstance(text, (bytes, bytearray)):
            data = bytes(text)
        else:
            raise TypeError("text must be str or bytes")
        return self._open_data(data, name)

    def read(self, source):
        with self.open(source) as opened:
            return opened.parse()


def open_scoped(source, grants, **kwargs):
    """Open ``source`` with a fresh :class:`ManagedReader`."""
    return ManagedReader(grants, **kwargs).open(source)


def read_scoped(source, grants, **kwargs):
    """Open and parse ``source`` in one step."""
    return ManagedReader(grants, **kwargs).read(source)

# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Scoped, namespace-aware summaries for defused XML documents.

The summary API is intentionally separate from the normal parse entry points.
A caller has to approve the exact element paths that may be published and a
hard cap for the returned excerpt text.  Only fully expanded names are
matched, so a nested namespace declaration cannot smuggle an identically
named, unapproved element into the result.

Example::

    from defusedxml.summary import summarize

    xml = (
        '<feed xmlns="urn:public">'
        "<title>Release</title>"
        '<scope xmlns="urn:internal"><title>secret</title></scope>'
        "</feed>"
    )
    result = summarize(
        xml,
        approved_paths=["{urn:public}feed/{urn:public}title"],
        max_output=1024,
        method="tree",
    )
    assert [excerpt.text for excerpt in result] == ["Release"]

Offsets in :attr:`Excerpt.start` and :attr:`Excerpt.end` refer to the source
object with the same unit: character offsets for ``str`` input and byte
offsets for ``bytes`` input.  ``end`` is exclusive.
"""

from __future__ import absolute_import, print_function

import bisect
import io
import os
from collections.abc import Mapping
from xml.etree.ElementTree import Element

__all__ = [
    "DEFAULT_MAX_OUTPUT",
    "Excerpt",
    "ScopedExcerpt",
    "ScopedSummary",
    "Summary",
    "scoped_summary",
    "scoped_summary_iter",
    "scoped_summary_tree",
    "summarize",
    "summarize_iter",
    "summarize_tree",
]


# A summary is an external-facing document.  Keep the default payload small
# even when a caller forgets to provide an explicit disaster-recovery cap.
DEFAULT_MAX_OUTPUT = 64 * 1024

_UNSET = object()


class Excerpt(object):
    """A single approved excerpt and its range in the original source."""

    __slots__ = ("label", "path", "text", "start", "end", "raw")

    def __init__(self, label, path, text, start, end, raw):
        self.label = label
        self.path = tuple(path)
        self.text = text
        self.start = start
        self.end = end
        self.raw = raw

    @property
    def tag(self):
        return self.path[-1] if self.path else None

    @property
    def range(self):
        return (self.start, self.end)

    span = range
    source_range = range
    source_start = property(lambda self: self.start)
    source_end = property(lambda self: self.end)
    value = property(lambda self: self.text)

    def as_dict(self):
        return {
            "label": self.label,
            "path": self.path,
            "tag": self.tag,
            "text": self.text,
            "start": self.start,
            "end": self.end,
            "range": self.range,
            "raw": self.raw,
        }

    def __getitem__(self, key):
        if isinstance(key, str):
            if key in ("text", "value"):
                return self.text
            if key in ("start", "source_start"):
                return self.start
            if key in ("end", "source_end"):
                return self.end
            if key in ("range", "span", "source_range"):
                return self.range
            if key in ("path", "label", "tag", "raw"):
                return getattr(self, key)
            raise KeyError(key)
        return (self.label, self.path, self.text, self.start, self.end, self.raw)[key]

    def __repr__(self):
        return "Excerpt(label={!r}, path={!r}, text={!r}, start={!r}, end={!r})".format(
            self.label, self.path, self.text, self.start, self.end
        )


class Summary(object):
    """The result of :func:`summarize`.

    The object is sequence-like so ``for excerpt in result`` and
    ``result[0]`` behave as expected.  ``truncated`` is true when the
    disaster-recovery output cap prevented one or more approved excerpts
    from being returned.
    """

    __slots__ = ("excerpts", "truncated", "limit", "output_size")

    def __init__(self, excerpts, truncated, limit, output_size):
        self.excerpts = tuple(excerpts)
        self.truncated = truncated
        self.limit = limit
        self.output_size = output_size

    @property
    def size(self):
        return self.output_size

    def as_dict(self):
        return {
            "excerpts": [excerpt.as_dict() for excerpt in self.excerpts],
            "truncated": self.truncated,
            "limit": self.limit,
            "output_size": self.output_size,
        }

    to_dict = as_dict

    def __iter__(self):
        return iter(self.excerpts)

    def __len__(self):
        return len(self.excerpts)

    def __bool__(self):
        return bool(self.excerpts)

    def __getitem__(self, key):
        if isinstance(key, str):
            return self.as_dict()[key]
        return self.excerpts[key]

    def __eq__(self, other):
        if isinstance(other, Summary):
            return self.excerpts == other.excerpts
        if isinstance(other, (list, tuple)):
            return list(self.excerpts) == list(other)
        return NotImplemented

    def __repr__(self):
        return "Summary(excerpts={!r}, truncated={!r}, limit={!r}, output_size={!r})".format(
            self.excerpts, self.truncated, self.limit, self.output_size
        )


ScopedExcerpt = Excerpt
ScopedSummary = Summary


class _Pattern(object):
    __slots__ = ("label", "segments", "descendant")

    def __init__(self, label, segments, descendant):
        self.label = label
        self.segments = segments
        self.descendant = descendant


class _Frame(object):
    __slots__ = (
        "tag",
        "path",
        "start",
        "end",
        "parts",
        "needs_text",
        "approved",
        "label",
        "elem",
        "text",
        "self_closing",
    )

    def __init__(self, tag, path, start, needs_text, approved, label, elem):
        self.tag = tag
        self.path = path
        self.start = start
        self.end = start
        self.parts = []
        self.needs_text = needs_text
        self.approved = approved
        self.label = label
        self.elem = elem
        self.text = ""
        self.self_closing = False


def _take_alias(kwargs, names):
    found = [name for name in names if name in kwargs]
    if len(found) > 1:
        raise TypeError("conflicting keyword arguments: {}".format(", ".join(found)))
    if found:
        return kwargs.pop(found[0]), True
    return None, False


def _load_source(source):
    if isinstance(source, str):
        stripped = source.lstrip("\ufeff \t\r\n")
        if not stripped.startswith("<"):
            try:
                is_file = os.path.exists(source)
            except (OSError, ValueError):
                is_file = False
            if is_file:
                with open(source, "rb") as fp:
                    return fp.read()
        return source
    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source)
    if hasattr(source, "read"):
        return _load_source(source.read())
    if isinstance(source, os.PathLike):
        with open(source, "rb") as fp:
            return fp.read()
    raise TypeError("XML source must be text, bytes, a path, or a file-like object")


def _normalize_segment(segment, namespaces):
    if isinstance(namespaces, str):
        namespaces = {"": namespaces}
    if not isinstance(segment, str):
        raise TypeError("path segments must be strings")
    segment = segment.strip()
    if not segment:
        raise ValueError("empty path segment")
    if segment == "*":
        return segment
    if segment == "**":
        raise ValueError("'**' is not a supported approved path segment")
    if segment.startswith("{"):
        close = segment.find("}")
        if close <= 1 or close == len(segment) - 1:
            raise ValueError("invalid expanded name: {!r}".format(segment))
        return "{" + segment[1:close] + "}" + segment[close + 1 :]
    if ":" in segment:
        prefix, local = segment.split(":", 1)
        if not prefix or not local:
            raise ValueError("invalid namespace-qualified name: {!r}".format(segment))
        if namespaces is None or prefix not in namespaces:
            raise ValueError(
                "namespace prefix {!r} is not approved; pass namespaces={{...}}".format(prefix)
            )
        uri = namespaces[prefix]
        if uri:
            return "{" + uri + "}" + local
        return local
    if namespaces:
        uri = namespaces.get("", namespaces.get(None))
        if uri:
            return "{" + uri + "}" + segment
    return segment


def _split_string_path(path):
    if not isinstance(path, str):
        raise TypeError("approved paths must be strings or sequences of strings")
    path = path.strip()
    if not path:
        raise ValueError("approved path must not be empty")
    descendant = False
    if path.startswith(".//"):
        descendant = True
        path = path[3:]
    elif path.startswith("//"):
        descendant = True
        path = path[2:]
    elif path.startswith("./"):
        path = path[2:]
    if path.startswith("/"):
        path = path[1:]
    parts = [part for part in path.split("/") if part]
    if not parts:
        raise ValueError("approved path must contain an element name")
    return parts, descendant


def _normalize_approved(approved_paths, namespaces):
    if approved_paths is None:
        raise TypeError("approved_paths is required")
    if isinstance(approved_paths, Mapping):
        raw_paths = list(approved_paths.items())
    elif isinstance(approved_paths, (str, bytes)):
        raw_paths = [(None, approved_paths)]
    else:
        raw_paths = [(None, path) for path in approved_paths]

    patterns = []
    for label, path in raw_paths:
        if isinstance(path, (tuple, list)):
            parts = list(path)
            descendant = False
        else:
            parts, descendant = _split_string_path(path)
        segments = tuple(_normalize_segment(part, namespaces) for part in parts)
        if not segments:
            raise ValueError("approved path must contain an element name")
        patterns.append(_Pattern(label, segments, descendant))
    return tuple(patterns)


def _segment_matches(pattern, tag):
    if pattern == "*":
        return True
    if pattern.startswith("{") and pattern.endswith("}*"):
        return tag.startswith(pattern[:-1])
    return pattern == tag


def _find_pattern(patterns, path):
    for pattern in patterns:
        segments = pattern.segments
        if pattern.descendant:
            if len(path) < len(segments):
                continue
            candidate = path[-len(segments) :]
        else:
            if len(path) != len(segments):
                continue
            candidate = path
        if all(_segment_matches(part, tag) for part, tag in zip(segments, candidate)):
            return pattern
    return None


def _is_char(source, index, char):
    if index < 0 or index >= len(source):
        return False
    expected = char.encode("ascii") if isinstance(source, (bytes, bytearray)) else char
    return source[index : index + 1] == expected


def _find_start_tag_end(source, start):
    quote = None
    index = start + 1
    length = len(source)
    while index < length:
        char = source[index]
        if quote is not None:
            if char == quote:
                quote = None
        elif char == '"' or char == "'" or char == 34 or char == 39:
            quote = char
        elif char == ">" or char == 62:
            return index + 1
        index += 1
    return length


def _element_end(source, frame, index):
    if frame.self_closing:
        return min(index, len(source))
    if _is_char(source, index, "<") and _is_char(source, index + 1, "/"):
        close_token = ">" if isinstance(source, str) else b">"
        close = source.find(close_token, index + 2)
        if close >= 0:
            return close + 1
    return min(index, len(source))


def _offset_converter(source):
    """Map expat's UTF-8 byte offsets back to str character offsets."""
    if not isinstance(source, str):
        return lambda index: index

    boundaries = [0]
    total = 0
    for char in source:
        total += len(char.encode("utf-8"))
        boundaries.append(total)

    def convert(byte_index):
        index = bisect.bisect_left(boundaries, byte_index)
        if index < len(boundaries) and boundaries[index] == byte_index:
            return index
        return max(0, index - 1)

    return convert


class _CaptureTarget(object):
    """Build a tree (optional) and capture approved element ranges."""

    def __init__(self, source, patterns, build_tree):
        self.source = source
        self.patterns = patterns
        self.build_tree = build_tree
        self.stack = []
        self.root = None
        self.captured = []
        self.by_element = {}
        self.parser = None
        self._to_index = _offset_converter(source)

    def start(self, tag, attrib):
        index = self._to_index(self.parser.parser.CurrentByteIndex)
        parent = self.stack[-1] if self.stack else None
        path = parent.path + (tag,) if parent is not None else (tag,)
        pattern = _find_pattern(self.patterns, path)
        approved = pattern is not None
        label = pattern.label if pattern is not None else None
        needs_text = approved or (parent is not None and parent.needs_text)

        elem = None
        if self.build_tree:
            elem = Element(tag, attrib)
            if parent is not None:
                parent.elem.append(elem)
            else:
                self.root = elem

        start_end = _find_start_tag_end(self.source, index)
        frame = _Frame(tag, path, index, needs_text, approved, label, elem)
        close_token = "/>" if isinstance(self.source, str) else b"/>"
        frame.self_closing = (
            start_end >= 2 and self.source[start_end - 2 : start_end] == close_token
        )
        self.stack.append(frame)
        return elem

    def data(self, data):
        if not data:
            return
        for frame in self.stack:
            if frame.needs_text:
                frame.parts.append(data)
        if self.build_tree and self.stack:
            elem = self.stack[-1].elem
            if len(elem):
                elem[-1].tail = (elem[-1].tail or "") + data
            else:
                elem.text = (elem.text or "") + data

    def end(self, tag):
        frame = self.stack.pop()
        index = self._to_index(self.parser.parser.CurrentByteIndex)
        frame.end = _element_end(self.source, frame, index)
        if frame.approved:
            frame.text = "".join(frame.parts)
            self.captured.append(frame)
            if frame.elem is not None:
                self.by_element[id(frame.elem)] = frame

    def close(self):
        return self.root


def _make_parser(target, forbid_dtd, forbid_entities, forbid_external):
    from .ElementTree import DefusedXMLParser

    parser = DefusedXMLParser(
        target=target,
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )
    target.parser = parser
    return parser


def _parse_tree(source, patterns, forbid_dtd, forbid_entities, forbid_external):
    target = _CaptureTarget(source, patterns, build_tree=True)
    parser = _make_parser(target, forbid_dtd, forbid_entities, forbid_external)
    parser.feed(source)
    parser.close()
    return target


def _parse_iter(source, patterns, forbid_dtd, forbid_entities, forbid_external):
    from .ElementTree import iterparse

    target = _CaptureTarget(source, patterns, build_tree=False)
    parser = _make_parser(target, forbid_dtd, forbid_entities, forbid_external)
    stream = io.StringIO(source) if isinstance(source, str) else io.BytesIO(source)
    try:
        for _event in iterparse(stream, events=("start", "end"), parser=parser):
            pass
    finally:
        stream.close()
    return target


def _tree_frames(target):
    frames = []
    visited = set()

    def walk(elem, path):
        if not isinstance(elem.tag, str):
            return
        path = path + (elem.tag,)
        frame = target.by_element.get(id(elem))
        if frame is not None and id(frame) not in visited:
            visited.add(id(frame))
            frames.append(frame)
        for child in elem:
            walk(child, path)

    if target.root is not None:
        walk(target.root, ())
    return frames


def _route(method, kwargs):
    use_iterparse, found = _take_alias(kwargs, ("use_iterparse", "use_iter", "iterative"))
    if found:
        method = "iter" if use_iterparse else "tree"
    reader, found = _take_alias(kwargs, ("reader", "mode", "route", "read_path"))
    if found:
        method = reader
    if method is None:
        method = "tree"
    if isinstance(method, bool):
        return "iter" if method else "tree"
    normalized = str(method).lower().replace("-", "").replace("_", "")
    if normalized in ("tree", "parse", "fromstring", "document", "etree"):
        return "tree"
    if normalized in ("iter", "iterparse", "pull", "stream", "streaming"):
        return "iter"
    raise ValueError("unknown summary reader: {!r}".format(method))


def _normalize_limit(max_output, kwargs):
    if max_output is _UNSET:
        value, found = _take_alias(
            kwargs, ("limit", "output_limit", "max_length", "max_chars", "max_output_chars")
        )
        max_output = value if found else DEFAULT_MAX_OUTPUT
    elif any(
        name in kwargs
        for name in ("limit", "output_limit", "max_length", "max_chars", "max_output_chars")
    ):
        raise TypeError("max_output was provided more than once")
    if max_output is None:
        max_output = DEFAULT_MAX_OUTPUT
    if isinstance(max_output, bool) or not isinstance(max_output, int):
        raise TypeError("max_output must be an integer")
    if max_output < 0:
        return None
    return max_output


def _finish(frames, source, output_limit):
    frames = sorted(frames, key=lambda frame: frame.start)
    excerpts = []
    used = 0
    truncated = False
    for frame in frames:
        text = frame.text
        size = len(text)
        if output_limit is not None and used + size > output_limit:
            truncated = True
            break
        raw = source[frame.start : frame.end]
        excerpts.append(Excerpt(frame.label, frame.path, text, frame.start, frame.end, raw))
        used += size
    return Summary(excerpts, truncated, output_limit, used)


def summarize(
    source=None,
    approved_paths=None,
    max_output=_UNSET,
    method="tree",
    namespaces=None,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    **kwargs,
):
    """Return only explicitly approved excerpts of an XML document.

    :param source: XML text, bytes, a path, or a file-like object.
    :param approved_paths: Exact element paths that may be published.  A path
        string contains slash-separated expanded names such as
        ``"{urn:public}feed/{urn:public}title"``.  Plain names only match
        elements without a namespace.  A mapping may be used to associate a
        label with each path.  Leading ``.//``/``//`` marks a descendant
        suffix match.
    :param max_output: Maximum number of characters of excerpt text that may
        be returned.  A negative value disables the cap.  The default is
        :data:`DEFAULT_MAX_OUTPUT`.
    :param method: ``"tree"`` (parse/fromstring) or ``"iter"`` (iterparse).
    :param namespaces: Optional prefix-to-URI mapping used to expand prefixes
        in approved paths.  An empty-string (or ``None``) key supplies the
        default namespace for unprefixed segments.  Without it, only expanded
        names and unprefixed no-namespace names are accepted.
    :param forbid_dtd: Passed to the defused parser.
    :param forbid_entities: Passed to the defused parser.
    :param forbid_external: Passed to the defused parser.
    :return: A :class:`Summary` sequence of :class:`Excerpt` objects.
    """
    if source is None:
        source, found = _take_alias(kwargs, ("xml", "text", "data", "document"))
        if not found:
            raise TypeError("missing XML source")

    if approved_paths is None:
        approved_paths, found = _take_alias(
            kwargs,
            (
                "paths",
                "approved",
                "approvals",
                "allowlist",
                "approved_fields",
                "fields",
            ),
        )
        if not found:
            raise TypeError("approved_paths is required")

    if namespaces is None:
        namespaces, _found = _take_alias(kwargs, ("namespace_map", "prefixes"))

    if "stream" in kwargs:
        stream, _found = _take_alias(kwargs, ("stream",))
        if stream and method == "tree":
            method = "iter"

    output_limit = _normalize_limit(max_output, kwargs)
    route = _route(method, kwargs)
    if kwargs:
        raise TypeError("unexpected keyword argument(s): {}".format(", ".join(sorted(kwargs))))

    source = _load_source(source)
    patterns = _normalize_approved(approved_paths, namespaces)
    if route == "tree":
        target = _parse_tree(source, patterns, forbid_dtd, forbid_entities, forbid_external)
        frames = _tree_frames(target)
    else:
        target = _parse_iter(source, patterns, forbid_dtd, forbid_entities, forbid_external)
        frames = target.captured
    return _finish(frames, source, output_limit)


scoped_summary = summarize


def summarize_tree(
    source=None,
    approved_paths=None,
    max_output=_UNSET,
    namespaces=None,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    **kwargs,
):
    """Tree-reader convenience wrapper for :func:`summarize`."""
    for name in ("method", "reader", "mode", "route", "read_path"):
        kwargs.pop(name, None)
    for name in ("use_iterparse", "use_iter", "iterative", "stream"):
        kwargs.pop(name, None)
    return summarize(
        source,
        approved_paths,
        max_output,
        method="tree",
        namespaces=namespaces,
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
        **kwargs,
    )


def summarize_iter(
    source=None,
    approved_paths=None,
    max_output=_UNSET,
    namespaces=None,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    **kwargs,
):
    """Iterparse-reader convenience wrapper for :func:`summarize`."""
    for name in ("method", "reader", "mode", "route", "read_path"):
        kwargs.pop(name, None)
    for name in ("use_iterparse", "use_iter", "iterative", "stream"):
        kwargs.pop(name, None)
    return summarize(
        source,
        approved_paths,
        max_output,
        method="iter",
        namespaces=namespaces,
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
        **kwargs,
    )


scoped_summary_tree = summarize_tree
scoped_summary_iter = summarize_iter

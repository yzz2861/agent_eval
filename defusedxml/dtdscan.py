# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Pre-parse DTD scanner for advanced and obfuscated constructs.

The scanner is deliberately independent of expat.  Expat reports parameter
entity references through its default handler and does not expose conditional
sections at all.  A malformed conditional section in an internal subset fails
with a generic syntax error before any callback is invoked.  Scanning the
prolog first gives every backend the same classification and prevents external
resources from being touched before a decision is made.
"""
import re

from .common import (
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
    ParameterEntityForbidden,
    UnparsedEntityForbidden,
    NotationForbidden,
    ConditionalSectionForbidden,
)

__all__ = [
    "scan_document",
    "DTDScanGuard",
    "raise_entity_decl",
    "raise_unparsed_entity_decl",
    "raise_notation_decl",
    "raise_external_reference",
]

_DOCTYPE = "<!DOCTYPE"
_INCOMPLETE = object()
_NO_DOCTYPE = object()
_PE_REF = re.compile(r"%([^\s;%<>]+);")


def _metadata(depth, source, line, column, offset):
    return {
        "depth": depth,
        "source": source,
        "line": line,
        "column": column,
        "offset": offset,
    }


def raise_entity_decl(
    name,
    is_parameter_entity,
    value,
    base,
    sysid,
    pubid,
    notation_name,
    forbid_entities=True,
    forbid_external=True,
    depth=1,
    source="dtd",
    line=None,
    column=None,
    offset=None,
):
    """Classify an expat EntityDeclHandler event for all backends."""
    metadata = _metadata(depth, source, line, column, offset)
    if forbid_entities:
        if is_parameter_entity:
            raise ParameterEntityForbidden(
                name,
                value,
                base,
                sysid,
                pubid,
                notation_name,
                construct="parameter-entity-declaration",
                **metadata
            )
        if notation_name:
            raise UnparsedEntityForbidden(
                name,
                value,
                base,
                sysid,
                pubid,
                notation_name,
                construct="unparsed-entity-declaration",
                **metadata
            )
        construct = "external-entity-declaration"
        if sysid is None and pubid is None:
            construct = "internal-entity-declaration"
        raise EntitiesForbidden(
            name,
            value,
            base,
            sysid,
            pubid,
            notation_name,
            construct=construct,
            **metadata
        )
    if forbid_external and (sysid is not None or pubid is not None):
        raise ExternalReferenceForbidden(
            "external-entity-declaration",
            base,
            sysid,
            pubid,
            construct="external-entity-declaration",
            **metadata
        )


def raise_unparsed_entity_decl(
    name,
    base,
    sysid,
    pubid,
    notation_name,
    forbid_entities=True,
    forbid_external=True,
    depth=1,
    source="dtd",
    line=None,
    column=None,
    offset=None,
):
    metadata = _metadata(depth, source, line, column, offset)
    if forbid_entities:
        raise UnparsedEntityForbidden(
            name,
            None,
            base,
            sysid,
            pubid,
            notation_name,
            construct="unparsed-entity-declaration",
            **metadata
        )
    if forbid_external and (sysid is not None or pubid is not None):
        raise ExternalReferenceForbidden(
            "unparsed-entity-declaration",
            base,
            sysid,
            pubid,
            construct="unparsed-entity-declaration",
            **metadata
        )


def raise_notation_decl(
    name,
    base,
    sysid,
    pubid,
    forbid_entities=True,
    forbid_external=True,
    depth=1,
    source="dtd",
    line=None,
    column=None,
    offset=None,
):
    metadata = _metadata(depth, source, line, column, offset)
    if forbid_entities:
        raise NotationForbidden(
            name,
            None,
            base,
            sysid,
            pubid,
            name,
            construct="notation-declaration",
            **metadata
        )
    if forbid_external and (sysid is not None or pubid is not None):
        raise ExternalReferenceForbidden(
            "notation-declaration",
            base,
            sysid,
            pubid,
            construct="notation-declaration",
            **metadata
        )


def raise_external_reference(
    context,
    base,
    sysid,
    pubid,
    depth=1,
    source="dtd",
    line=None,
    column=None,
    offset=None,
):
    raise ExternalReferenceForbidden(
        context,
        base,
        sysid,
        pubid,
        construct="external-reference",
        depth=depth,
        source=source,
        line=line,
        column=column,
        offset=offset,
    )


class _DoctypeInfo(object):
    __slots__ = (
        "start",
        "name",
        "name_offset",
        "sysid",
        "pubid",
        "subset_start",
        "subset_end",
        "end",
    )

    def __init__(self, start, name, name_offset, sysid, pubid):
        self.start = start
        self.name = name
        self.name_offset = name_offset
        self.sysid = sysid
        self.pubid = pubid
        self.subset_start = None
        self.subset_end = None
        self.end = None


def _as_text(data):
    if isinstance(data, bytes):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1")
    return data


def _line_column(text, offset):
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    column = offset + 1 if last_newline < 0 else offset - last_newline
    return line, column


def _location(text, offset):
    line, column = _line_column(text, offset)
    return {"line": line, "column": column, "offset": offset}


def _skip_ws(text, i, limit=None):
    if limit is None:
        limit = len(text)
    while i < limit and text[i] in " \t\r\n":
        i += 1
    return i


def _read_name(text, i, limit=None):
    if limit is None:
        limit = len(text)
    start = i
    while i < limit and text[i] not in " \t\r\n[]<>":
        i += 1
    return text[start:i], i


def _read_literal(text, i, limit=None):
    if limit is None:
        limit = len(text)
    if i >= limit or text[i] not in "'\"":
        return _INCOMPLETE, None, i
    quote = text[i]
    end = text.find(quote, i + 1, limit)
    if end < 0:
        return _INCOMPLETE, None, i
    return True, text[i + 1 : end], end + 1


def _skip_comment(text, i, limit=None):
    if limit is None:
        limit = len(text)
    end = text.find("-->", i + 4, limit)
    if end < 0:
        return _INCOMPLETE
    return end + 3


def _skip_pi(text, i, limit=None):
    if limit is None:
        limit = len(text)
    end = text.find("?>", i + 2, limit)
    if end < 0:
        return _INCOMPLETE
    return end + 2


def _find_tag_end(text, i, limit=None):
    if limit is None:
        limit = len(text)
    quote = None
    while i < limit:
        char = text[i]
        if quote:
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == ">":
            return i + 1
        i += 1
    return _INCOMPLETE


def _find_conditional_end(text, start, limit=None):
    """Return the offset just after the closing ``]]>`` of a section."""
    if limit is None:
        limit = len(text)
    i = start + 3
    i = _skip_ws(text, i, limit)
    keyword = ""
    while i < limit and text[i].isalpha():
        keyword += text[i]
        i += 1
    if keyword not in ("INCLUDE", "IGNORE"):
        return _INCOMPLETE
    i = _skip_ws(text, i, limit)
    if i >= limit or text[i] != "[":
        return _INCOMPLETE
    i += 1
    depth = 1
    quote = None
    while i < limit:
        char = text[i]
        if quote:
            if char == quote:
                quote = None
            i += 1
            continue
        if char in "'\"":
            quote = char
            i += 1
            continue
        if text.startswith("<!--", i):
            end = _skip_comment(text, i, limit)
            if end is _INCOMPLETE:
                return _INCOMPLETE
            i = end
            continue
        if text.startswith("<![", i):
            depth += 1
            i += 3
            continue
        if text.startswith("]]>", i):
            depth -= 1
            i += 3
            if depth == 0:
                return i
            continue
        i += 1
    return _INCOMPLETE


def _find_subset_end(text, start, limit=None):
    if limit is None:
        limit = len(text)
    i = start
    while i < limit:
        char = text[i]
        if char in "'\"":
            end = text.find(char, i + 1, limit)
            if end < 0:
                return _INCOMPLETE
            i = end + 1
        elif text.startswith("<!--", i):
            end = _skip_comment(text, i, limit)
            if end is _INCOMPLETE:
                return _INCOMPLETE
            i = end
        elif text.startswith("<?", i):
            end = _skip_pi(text, i, limit)
            if end is _INCOMPLETE:
                return _INCOMPLETE
            i = end
        elif text.startswith("<![", i):
            end = _find_conditional_end(text, i, limit)
            if end is _INCOMPLETE:
                return _INCOMPLETE
            i = end
        elif char == "]":
            return i
        else:
            i += 1
    return _INCOMPLETE


def _parse_doctype(text, start):
    limit = len(text)
    i = start + len(_DOCTYPE)
    i = _skip_ws(text, i, limit)
    if i >= limit:
        return _INCOMPLETE
    name, i = _read_name(text, i, limit)
    if not name:
        return _NO_DOCTYPE
    info = _DoctypeInfo(start, name, i - len(name), None, None)
    i = _skip_ws(text, i, limit)
    if i >= limit:
        return _INCOMPLETE

    keyword = text[i : i + 6]
    if keyword == "SYSTEM":
        state, value, i = _read_literal(text, _skip_ws(text, i + 6, limit), limit)
        if state is _INCOMPLETE:
            return _INCOMPLETE
        info.sysid = value
        i = _skip_ws(text, i, limit)
    elif keyword == "PUBLIC":
        state, value, i = _read_literal(text, _skip_ws(text, i + 6, limit), limit)
        if state is _INCOMPLETE:
            return _INCOMPLETE
        info.pubid = value
        state, value, i = _read_literal(text, _skip_ws(text, i, limit), limit)
        if state is _INCOMPLETE:
            return _INCOMPLETE
        info.sysid = value
        i = _skip_ws(text, i, limit)

    if i >= limit:
        return _INCOMPLETE
    if text[i] == "[":
        subset_end = _find_subset_end(text, i + 1, limit)
        if subset_end is _INCOMPLETE:
            return _INCOMPLETE
        info.subset_start = i + 1
        info.subset_end = subset_end
        i = _skip_ws(text, subset_end + 1, limit)
        if i >= limit:
            return _INCOMPLETE
        if text[i] == ">":
            info.end = i + 1
            return info
        return _NO_DOCTYPE
    if text[i] == ">":
        info.end = i + 1
        return info
    return _NO_DOCTYPE


def _find_doctype(text):
    limit = len(text)
    i = 0
    while i < limit:
        lt = text.find("<", i)
        if lt < 0:
            return _INCOMPLETE
        i = lt
        if text.startswith("<!--", i):
            end = _skip_comment(text, i, limit)
            if end is _INCOMPLETE:
                return _INCOMPLETE
            i = end
        elif text.startswith("<![CDATA[", i):
            end = text.find("]]>", i + 9, limit)
            if end < 0:
                return _INCOMPLETE
            i = end + 3
        elif text.startswith("<?", i):
            end = _skip_pi(text, i, limit)
            if end is _INCOMPLETE:
                return _INCOMPLETE
            i = end
        elif text.startswith(_DOCTYPE, i):
            return _parse_doctype(text, i)
        elif text.startswith("<!", i):
            return _NO_DOCTYPE
        else:
            return _NO_DOCTYPE
    return _INCOMPLETE


def _parse_entity_decl(text, start, limit):
    i = _skip_ws(text, start + len("<!ENTITY"), limit)
    parameter = False
    if i < limit and text[i] == "%":
        parameter = True
        i = _skip_ws(text, i + 1, limit)
    name, i = _read_name(text, i, limit)
    if not name:
        return None
    i = _skip_ws(text, i, limit)
    value = None
    sysid = None
    pubid = None
    notation_name = None
    if i < limit and text[i] in "'\"":
        state, value, i = _read_literal(text, i, limit)
        if state is _INCOMPLETE:
            return None
    elif text.startswith("SYSTEM", i):
        state, sysid, i = _read_literal(text, _skip_ws(text, i + 6, limit), limit)
        if state is _INCOMPLETE:
            return None
    elif text.startswith("PUBLIC", i):
        state, pubid, i = _read_literal(text, _skip_ws(text, i + 6, limit), limit)
        if state is _INCOMPLETE:
            return None
        i = _skip_ws(text, i, limit)
        if i < limit and text[i] in "'\"":
            state, sysid, i = _read_literal(text, i, limit)
            if state is _INCOMPLETE:
                return None
    i = _skip_ws(text, i, limit)
    if text.startswith("NDATA", i):
        i = _skip_ws(text, i + 5, limit)
        notation_name, i = _read_name(text, i, limit)
    end = _find_tag_end(text, i, limit)
    if end is _INCOMPLETE:
        return None
    return {
        "name": name,
        "parameter": parameter,
        "value": value,
        "sysid": sysid,
        "pubid": pubid,
        "notation_name": notation_name,
        "offset": start,
        "end": end,
    }


def _parse_notation_decl(text, start, limit):
    i = _skip_ws(text, start + len("<!NOTATION"), limit)
    name, i = _read_name(text, i, limit)
    if not name:
        return None
    i = _skip_ws(text, i, limit)
    sysid = None
    pubid = None
    if text.startswith("SYSTEM", i):
        state, sysid, i = _read_literal(text, _skip_ws(text, i + 6, limit), limit)
        if state is _INCOMPLETE:
            return None
    elif text.startswith("PUBLIC", i):
        state, pubid, i = _read_literal(text, _skip_ws(text, i + 6, limit), limit)
        if state is _INCOMPLETE:
            return None
        i = _skip_ws(text, i, limit)
        if i < limit and text[i] in "'\"":
            state, sysid, i = _read_literal(text, i, limit)
            if state is _INCOMPLETE:
                return None
    end = _find_tag_end(text, i, limit)
    if end is _INCOMPLETE:
        return None
    return {"name": name, "sysid": sysid, "pubid": pubid, "offset": start, "end": end}


def _entity_error(decl, depth, source, text):
    offset = decl["offset"]
    line, column = _line_column(text, offset)
    common = {
        "depth": depth,
        "source": source,
        "line": line,
        "column": column,
        "offset": offset,
    }
    if decl["parameter"]:
        return ParameterEntityForbidden(
            decl["name"],
            None,
            None,
            decl["sysid"],
            decl["pubid"],
            decl["notation_name"],
            construct="parameter-entity-declaration",
            **common
        )
    if decl["notation_name"]:
        return UnparsedEntityForbidden(
            decl["name"],
            None,
            None,
            decl["sysid"],
            decl["pubid"],
            decl["notation_name"],
            construct="unparsed-entity-declaration",
            **common
        )
    if decl["sysid"] is not None or decl["pubid"] is not None:
        return EntitiesForbidden(
            decl["name"],
            None,
            None,
            decl["sysid"],
            decl["pubid"],
            None,
            construct="external-entity-declaration",
            **common
        )
    return EntitiesForbidden(
        decl["name"],
        None,
        None,
        None,
        None,
        None,
        construct="internal-entity-declaration",
        **common
    )


def _external_error(name, sysid, pubid, construct, depth, source, text, offset):
    line, column = _line_column(text, offset)
    return ExternalReferenceForbidden(
        construct,
        None,
        sysid,
        pubid,
        construct=construct,
        depth=depth,
        source=source,
        line=line,
        column=column,
        offset=offset,
    )


def _scan_subset(
    text,
    start,
    end,
    forbid_entities,
    forbid_external,
    depth,
    source,
    known_parameters=None,
):
    if known_parameters is None:
        known_parameters = set()
    i = start
    while i < end:
        i = _skip_ws(text, i, end)
        if i >= end:
            break
        char = text[i]
        if text.startswith("<!--", i):
            comment_end = _skip_comment(text, i, end)
            if comment_end is _INCOMPLETE:
                break
            i = comment_end
            continue
        if text.startswith("<?", i):
            pi_end = _skip_pi(text, i, end)
            if pi_end is _INCOMPLETE:
                break
            i = pi_end
            continue
        if text.startswith("<![", i):
            section_end = _find_conditional_end(text, i, end)
            if section_end is _INCOMPLETE:
                break
            marker_end = _skip_ws(text, i + 3, end)
            keyword_start = marker_end
            while marker_end < end and text[marker_end].isalpha():
                marker_end += 1
            keyword = text[keyword_start:marker_end]
            marker_end = _skip_ws(text, marker_end, end)
            if marker_end < end and text[marker_end] == "[":
                content_start = marker_end + 1
            else:
                content_start = marker_end
            if forbid_entities:
                line, column = _line_column(text, i)
                raise ConditionalSectionForbidden(
                    keyword or "condition-section",
                    None,
                    None,
                    None,
                    None,
                    None,
                    construct="conditional-section",
                    depth=depth + 1,
                    source=source,
                    line=line,
                    column=column,
                    offset=i,
                )
            if keyword == "INCLUDE":
                _scan_subset(
                    text,
                    content_start,
                    section_end - 3,
                    forbid_entities,
                    forbid_external,
                    depth + 1,
                    source,
                    known_parameters,
                )
            if forbid_external:
                line, column = _line_column(text, i)
                raise ConditionalSectionForbidden(
                    keyword or "condition-section",
                    None,
                    None,
                    None,
                    None,
                    None,
                    construct="conditional-section",
                    depth=depth + 1,
                    source=source,
                    line=line,
                    column=column,
                    offset=i,
                )
            i = section_end
            continue
        if char == "%":
            match = _PE_REF.match(text, i, end)
            if match is not None:
                if forbid_entities:
                    line, column = _line_column(text, i)
                    raise ParameterEntityForbidden(
                        match.group(1),
                        None,
                        None,
                        None,
                        None,
                        None,
                        construct="parameter-entity-reference",
                        depth=depth,
                        source=source,
                        line=line,
                        column=column,
                        offset=i,
                    )
                if forbid_external and match.group(1) not in known_parameters:
                    line, column = _line_column(text, i)
                    raise ExternalReferenceForbidden(
                        "parameter-entity-reference",
                        None,
                        None,
                        None,
                        construct="parameter-entity-reference",
                        depth=depth,
                        source=source,
                        line=line,
                        column=column,
                        offset=i,
                    )
                i = match.end()
                continue
            i += 1
            continue
        if text.startswith("<!ENTITY", i):
            decl = _parse_entity_decl(text, i, end)
            if decl is None:
                break
            if forbid_entities:
                raise _entity_error(decl, depth, source, text)
            if (
                decl["parameter"]
                and decl["value"] is not None
                and decl["sysid"] is None
                and decl["pubid"] is None
            ):
                known_parameters.add(decl["name"])
            if forbid_external and (decl["sysid"] is not None or decl["pubid"] is not None):
                construct = "external-entity-declaration"
                if decl["notation_name"]:
                    construct = "unparsed-entity-declaration"
                raise _external_error(
                    decl["name"],
                    decl["sysid"],
                    decl["pubid"],
                    construct,
                    depth,
                    source,
                    text,
                    decl["offset"],
                )
            if decl["parameter"] and decl["value"]:
                _scan_subset(
                    decl["value"],
                    0,
                    len(decl["value"]),
                    forbid_entities,
                    forbid_external,
                    depth + 1,
                    "parameter-entity",
                    known_parameters,
                )
            i = decl["end"]
            continue
        if text.startswith("<!NOTATION", i):
            decl = _parse_notation_decl(text, i, end)
            if decl is None:
                break
            if forbid_entities:
                line, column = _line_column(text, decl["offset"])
                raise NotationForbidden(
                    decl["name"],
                    None,
                    None,
                    decl["sysid"],
                    decl["pubid"],
                    decl["name"],
                    construct="notation-declaration",
                    depth=depth,
                    source=source,
                    line=line,
                    column=column,
                    offset=decl["offset"],
                )
            if forbid_external and (decl["sysid"] is not None or decl["pubid"] is not None):
                raise _external_error(
                    decl["name"],
                    decl["sysid"],
                    decl["pubid"],
                    "notation-declaration",
                    depth,
                    source,
                    text,
                    decl["offset"],
                )
            i = decl["end"]
            continue
        if text.startswith("<!", i):
            tag_end = _find_tag_end(text, i, end)
            if tag_end is _INCOMPLETE:
                break
            i = tag_end
            continue
        i += 1


def scan_document(
    data,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    source="internal_subset",
):
    """Scan an XML document or prolog and raise on forbidden DTD constructs."""
    if not forbid_dtd and not forbid_entities and not forbid_external:
        return
    text = _as_text(data)
    info = _find_doctype(text)
    if info is _INCOMPLETE or info is _NO_DOCTYPE:
        return
    if forbid_dtd:
        line, column = _line_column(text, info.start)
        raise DTDForbidden(
            info.name,
            info.sysid,
            info.pubid,
            construct="doctype",
            depth=0,
            source="doctype",
            line=line,
            column=column,
            offset=info.start,
        )
    if info.subset_start is not None:
        _scan_subset(
            text,
            info.subset_start,
            info.subset_end,
            forbid_entities,
            forbid_external,
            1,
            source,
        )
        if forbid_external and (info.sysid is not None or info.pubid is not None):
            line, column = _line_column(text, info.start)
            raise ExternalReferenceForbidden(
                "external-subset",
                None,
                info.sysid,
                info.pubid,
                construct="external-subset",
                depth=1,
                source="external_subset",
                line=line,
                column=column,
                offset=info.start,
            )


def _join(chunks):
    if not chunks:
        return b""
    if isinstance(chunks[0], bytes):
        parts = []
        for chunk in chunks:
            if isinstance(chunk, bytes):
                parts.append(chunk)
            else:
                parts.append(chunk.encode("utf-8"))
        return b"".join(parts)
    parts = []
    for chunk in chunks:
        if isinstance(chunk, bytes):
            parts.append(chunk.decode("utf-8", "replace"))
        else:
            parts.append(chunk)
    return "".join(parts)


class DTDScanGuard(object):
    """Buffer just enough of the prolog to scan the complete DOCTYPE."""

    __slots__ = ("_chunks", "_done", "_flags", "_source")

    def __init__(self, forbid_dtd=False, forbid_entities=True, forbid_external=True, source=None):
        self._chunks = []
        self._done = not (forbid_dtd or forbid_entities or forbid_external)
        self._flags = (forbid_dtd, forbid_entities, forbid_external)
        self._source = source or "internal_subset"

    def update_flags(self, forbid_dtd=False, forbid_entities=True, forbid_external=True):
        if not self._done:
            self._flags = (forbid_dtd, forbid_entities, forbid_external)

    def feed(self, data, is_final=False):
        if self._done:
            return data
        self._chunks.append(data)
        joined = _join(self._chunks)
        info = _find_doctype(_as_text(joined))
        if info is _INCOMPLETE:
            if not is_final:
                return None
            self._done = True
            self._chunks = []
            return joined
        self._done = True
        self._chunks = []
        scan_document(joined, *self._flags, source=self._source)
        return joined

    def finish(self):
        """Return buffered data and run a best-effort scan at end of input."""
        if self._done:
            return None
        joined = _join(self._chunks)
        self._done = True
        self._chunks = []
        scan_document(joined, *self._flags, source=self._source)
        return joined

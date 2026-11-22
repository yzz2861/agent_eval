# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.etree.ElementTree facade
"""
from __future__ import print_function, absolute_import

import sys
import warnings
from xml.etree.ElementTree import ParseError
from xml.etree.ElementTree import TreeBuilder as _TreeBuilder
from xml.etree.ElementTree import XMLPullParser as _XMLPullParser
from xml.etree.ElementTree import parse as _parse
from xml.etree.ElementTree import tostring

import importlib


from .common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden
from .session import ProtectedReadSession, ReadState

__origin__ = "xml.etree.ElementTree"


def _get_py3_cls():
    """Python 3.3 hides the pure Python code but defusedxml requires it.

    The code is based on test.support.import_fresh_module().
    """
    pymodname = "xml.etree.ElementTree"
    cmodname = "_elementtree"

    pymod = sys.modules.pop(pymodname, None)
    cmod = sys.modules.pop(cmodname, None)

    sys.modules[cmodname] = None
    try:
        pure_pymod = importlib.import_module(pymodname)
    finally:
        # restore module
        sys.modules[pymodname] = pymod
        if cmod is not None:
            sys.modules[cmodname] = cmod
        else:
            sys.modules.pop(cmodname, None)
        # restore attribute on original package
        etree_pkg = sys.modules["xml.etree"]
        if pymod is not None:
            etree_pkg.ElementTree = pymod
        elif hasattr(etree_pkg, "ElementTree"):
            del etree_pkg.ElementTree

    _XMLParser = pure_pymod.XMLParser
    _iterparse = pure_pymod.iterparse
    # patch pure module to use ParseError from C extension
    pure_pymod.ParseError = ParseError

    return _XMLParser, _iterparse


_XMLParser, _iterparse = _get_py3_cls()

_sentinel = object()


class DefusedXMLParser(_XMLParser):
    def __init__(
        self,
        html=_sentinel,
        target=None,
        encoding=None,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
    ):
        super().__init__(target=target, encoding=encoding)
        if html is not _sentinel:
            # the 'html' argument has been deprecated and ignored in all
            # supported versions of Python. Python 3.8 finally removed it.
            if html:
                raise TypeError("'html=True' is no longer supported.")
            else:
                warnings.warn(
                    "'html' keyword argument is no longer supported. Pass "
                    "in arguments as keyword arguments.",
                    category=DeprecationWarning,
                )

        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external
        parser = self.parser
        if self.forbid_dtd:
            parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        if self.forbid_entities:
            parser.EntityDeclHandler = self.defused_entity_decl
            parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
        if self.forbid_external:
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler

    def defused_start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        raise DTDForbidden(name, sysid, pubid)

    def defused_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        raise EntitiesForbidden(name, value, base, sysid, pubid, notation_name)

    def defused_unparsed_entity_decl(self, name, base, sysid, pubid, notation_name):
        # expat 1.2
        raise EntitiesForbidden(name, None, base, sysid, pubid, notation_name)  # pragma: no cover

    def defused_external_entity_ref_handler(self, context, base, sysid, pubid):
        raise ExternalReferenceForbidden(context, base, sysid, pubid)


class _TargetTracker(object):
    """Proxy a tree builder and notice when the document element closes."""

    def __init__(self, target):
        self.target = target
        self.depth = 0
        self.root_closed = False
        self.root_element = None

    def __getattr__(self, name):
        return getattr(self.target, name)

    def start(self, tag, attrs):
        element = self.target.start(tag, attrs)
        if self.depth == 0:
            self.root_element = element
        self.depth += 1
        return element

    def end(self, tag):
        element = self.target.end(tag)
        if self.depth:
            self.depth -= 1
        if self.depth == 0:
            self.root_closed = True
        return element


class IterParseSession(ProtectedReadSession):
    """Bounded, explicitly closable session for :func:`iterparse`.

    The session yields events exactly like ``iterparse``.  It stops feeding
    the parser as soon as the single document element is complete, so bytes
    after the document remain available to the owner of the stream.
    """

    def __init__(
        self,
        source,
        events=None,
        parser=None,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
        close_source=None,
        bufsize=16 * 1024,
    ):
        super().__init__(source, close_source=close_source, bufsize=bufsize)
        self._parser = None
        self._pullparser = None
        self._tracker = None
        try:
            if parser is None:
                parser = DefusedXMLParser(
                    target=_TreeBuilder(),
                    forbid_dtd=forbid_dtd,
                    forbid_entities=forbid_entities,
                    forbid_external=forbid_external,
                )
            self._parser = parser
            target = getattr(parser, "target", None)
            if target is not None and hasattr(target, "start") and hasattr(target, "end"):
                self._tracker = _TargetTracker(target)
                parser.target = self._tracker
                if hasattr(parser, "_target"):
                    parser._target = self._tracker
            self._pullparser = _XMLPullParser(events=events, _parser=parser)
        except BaseException as exc:
            self._mark_failed(exc)
            raise

    def _record_event(self, event):
        super()._record_event(event)
        if self._tracker is not None and self._tracker.root_element is not None:
            self._partial_document = self._tracker.root_element

    def _poll_event(self):
        if self._pullparser is None:
            return None
        try:
            return next(self._pullparser.read_events())
        except StopIteration:
            return None

    def _next_event(self):
        while True:
            if self._state is not ReadState.OPEN:
                raise StopIteration
            try:
                event = self._poll_event()
            except BaseException as exc:
                self._mark_failed(exc)
                raise
            if event is not None:
                self._record_event(event)
                return event
            if self._tracker is not None and self._tracker.root_closed:
                segment = self._reader.read_trailing_misc_segment()
                if segment is not None:
                    try:
                        self._pullparser.feed(segment)
                    except BaseException as exc:
                        self._mark_failed(exc)
                        raise
                    continue
                self._finalize_complete()
                if self._state is not ReadState.OPEN:
                    raise StopIteration
                continue
            if self._owner.eof:
                self._finalize_complete()
                if self._state is not ReadState.OPEN:
                    raise StopIteration
                continue
            segment = self._reader.read_segment()
            if segment is None:
                continue
            try:
                self._pullparser.feed(segment)
            except BaseException as exc:
                self._mark_failed(exc)
                raise

    def _finalize_complete(self):
        if self._finalized:
            return
        self._finalized = True
        try:
            close_and_return_root = getattr(
                self._pullparser, "_close_and_return_root", None
            )
            if close_and_return_root is not None:
                document = close_and_return_root()
            else:  # pragma: no cover - old ElementTree implementations
                self._pullparser.close()
                document = getattr(self._parser, "root", None)
        except BaseException as exc:
            self._mark_failed(exc)
            raise
        if document is None and self._tracker is not None:
            document = self._tracker.root_element
        self._mark_complete(document)

    def _release_parser(self):
        parser = self._parser
        tracker = self._tracker
        self._pullparser = None
        self._parser = None
        self._tracker = None
        if parser is not None and tracker is not None:
            if getattr(parser, "target", None) is tracker:
                parser.target = tracker.target
            if getattr(parser, "_target", None) is tracker:
                parser._target = tracker.target


# aliases
# XMLParse is a typo, keep it for backwards compatibility
XMLTreeBuilder = XMLParse = XMLParser = DefusedXMLParser


def parse(source, parser=None, forbid_dtd=False, forbid_entities=True, forbid_external=True):
    if parser is None:
        parser = DefusedXMLParser(
            target=_TreeBuilder(),
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
    return _parse(source, parser)


def iterparse(
    source,
    events=None,
    parser=None,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    close_source=None,
    bufsize=16 * 1024,
):
    return IterParseSession(
        source,
        events=events,
        parser=parser,
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
        close_source=close_source,
        bufsize=bufsize,
    )


iterparse_session = iterparse
open_session = iterparse
IterparseSession = IterParseSession
BoundedIterParseSession = IterParseSession


def fromstring(text, forbid_dtd=False, forbid_entities=True, forbid_external=True):
    parser = DefusedXMLParser(
        target=_TreeBuilder(),
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )
    parser.feed(text)
    return parser.close()


XML = fromstring


def fromstringlist(sequence, forbid_dtd=False, forbid_entities=True, forbid_external=True):
    parser = DefusedXMLParser(
        target=_TreeBuilder(),
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
    )
    for text in sequence:
        parser.feed(text)
    return parser.close()


__all__ = [
    "ParseError",
    "XML",
    "XMLParse",
    "XMLParser",
    "XMLTreeBuilder",
    "fromstring",
    "fromstringlist",
    "IterParseSession",
    "IterparseSession",
    "BoundedIterParseSession",
    "iterparse",
    "iterparse_session",
    "open_session",
    "parse",
    "tostring",
]

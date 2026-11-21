# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.etree.ElementTree facade"""

from __future__ import print_function, absolute_import

import sys
import warnings
from collections import namedtuple
from xml.etree.ElementTree import ParseError
from xml.etree.ElementTree import TreeBuilder as _TreeBuilder
from xml.etree.ElementTree import parse as _parse
from xml.etree.ElementTree import tostring
from xml.etree.ElementTree import XMLPullParser as _XMLPullParser

import importlib


from .common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden

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
    _pullparser = getattr(pure_pymod, "XMLPullParser", None) or _XMLPullParser
    # patch pure module to use ParseError from C extension
    pure_pymod.ParseError = ParseError

    return _XMLParser, _iterparse, _pullparser


_XMLParser, _iterparse, _pure_XMLPullParser = _get_py3_cls()

_sentinel = object()

Progress = namedtuple("Progress", "bytes events complete")


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


class DefusedXMLPullParser(_pure_XMLPullParser):
    # Defused incremental pull parser.  feed() stages a bounded prefix and
    # read_events() publishes ready events.  flush() publishes events that
    # Expat still holds for reparse deferral, while close() is the document
    # completion boundary.
    def __init__(
        self,
        events=None,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
        target=None,
        encoding=None,
        _parser=None,
    ):
        if _parser is None:
            parser = DefusedXMLParser(
                target=target if target is not None else _TreeBuilder(),
                encoding=encoding,
                forbid_dtd=forbid_dtd,
                forbid_entities=forbid_entities,
                forbid_external=forbid_external,
            )
        else:
            parser = _parser
        self.bytes_read = 0
        self.events_read = 0
        parent = _pure_XMLPullParser
        try:
            parent.__init__(self, events=events, _parser=parser)
        except TypeError:  # older pull-parser signatures
            parent.__init__(self, events=events)
            self._parser = parser
            if events is None:
                events = ("end",)
            parser._setevents(self._events_queue, events)

    @property
    def complete(self):
        # XMLPullParser releases its parser only after close() succeeded.
        # A queued syntax exception means read_events() has not yet reported
        # the failure, so the document is not committable.
        if self._parser is not None:
            return False
        return not any(isinstance(event, Exception) for event in self._events_queue)

    @property
    def can_commit(self):
        return self.complete

    @property
    def progress(self):
        return Progress(self.bytes_read, self.events_read, self.complete)

    def feed(self, data):
        if data and not self.complete:
            self.bytes_read += len(data)
        return _pure_XMLPullParser.feed(self, data)

    def read_events(self):
        events = _pure_XMLPullParser.read_events(self)
        for event in events:
            self.events_read += 1
            yield event


XMLPullParser = DefusedXMLPullParser


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


class _IterParseHandle:
    # Iterator wrapper with deterministic input-source ownership.  Only a
    # source opened by iterparse() is closed; a caller stream is never closed.
    def __init__(self, iterator, owned_source=None):
        self._iterator = iterator
        self._owned_source = owned_source
        self._closed = False
        self._exhausted = False
        self.events = 0

    @property
    def root(self):
        return getattr(self._iterator, "root", None)

    @property
    def complete(self):
        return self._exhausted

    @property
    def progress(self):
        return (self.events, self._exhausted)

    def __iter__(self):
        return self

    def __next__(self):
        if self._closed:
            raise StopIteration
        try:
            event = next(self._iterator)
        except StopIteration:
            self._exhausted = True
            self.close()
            raise
        except BaseException:
            self.close()
            raise
        else:
            self.events += 1
            return event

    def close(self):
        if self._closed:
            return
        self._closed = True
        source = self._owned_source
        self._owned_source = None
        if source is not None:
            source.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def iterparse(
    source,
    events=None,
    parser=None,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
):
    # A filename or path is opened and closed here.  A caller-owned stream is
    # never closed, whether iteration completes, raises, or exits early.
    # Events are consumed in bounded chunks; close() (or exhaustion) is the
    # document-completion boundary.
    owned_source = None
    if not hasattr(source, "read"):
        owned_source = open(source, "rb")
        source = owned_source
    if parser is None:
        parser = DefusedXMLParser(
            target=_TreeBuilder(),
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
    try:
        iterator = _iterparse(source, events, parser)
    except BaseException:
        if owned_source is not None:
            owned_source.close()
        raise
    return _IterParseHandle(iterator, owned_source)


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
    "Progress",
    "XML",
    "XMLParse",
    "XMLParser",
    "XMLPullParser",
    "XMLTreeBuilder",
    "fromstring",
    "fromstringlist",
    "DefusedXMLPullParser",
    "iterparse",
    "parse",
    "tostring",
]

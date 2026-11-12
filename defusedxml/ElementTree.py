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
from xml.etree.ElementTree import parse as _parse
from xml.etree.ElementTree import tostring

import importlib


from .common import DTDForbidden, ParameterEntityForbidden
from .dtdscan import (
    DTDScanGuard,
    raise_entity_decl,
    raise_unparsed_entity_decl,
    raise_notation_decl,
    raise_external_reference,
)

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
        self._dtd_depth = 0
        self._dtd_source = "internal_subset"
        self._dtd_guard = DTDScanGuard(
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
        parser = self.parser
        parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        parser.EndDoctypeDeclHandler = self.defused_end_doctype_decl
        parser.EntityDeclHandler = self.defused_entity_decl
        parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
        parser.NotationDeclHandler = self.defused_notation_decl
        self._orig_default_handler_expand = parser.DefaultHandlerExpand
        parser.DefaultHandlerExpand = self.defused_default_handler_expand
        if self.forbid_external:
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler

    def _location(self):
        parser = self.parser
        try:
            return parser.CurrentLineNumber, parser.CurrentColumnNumber + 1
        except AttributeError:
            return None, None

    def feed(self, data):
        self._dtd_guard.update_flags(
            forbid_dtd=self.forbid_dtd,
            forbid_entities=self.forbid_entities,
            forbid_external=self.forbid_external,
        )
        buffered = self._dtd_guard.feed(data)
        if buffered is None:
            return
        super().feed(buffered)

    def close(self):
        pending = self._dtd_guard.finish()
        if pending is not None:
            super().feed(pending)
        return super().close()

    def defused_start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        self._dtd_depth = 1
        self._dtd_source = "internal_subset" if has_internal_subset else "external_subset"
        if self.forbid_dtd:
            line, column = self._location()
            raise DTDForbidden(
                name,
                sysid,
                pubid,
                construct="doctype",
                depth=0,
                source="doctype",
                line=line,
                column=column,
            )

    def defused_end_doctype_decl(self):
        self._dtd_depth = 0

    def defused_default_handler_expand(self, text):
        if self.forbid_entities and self._dtd_depth and text.strip().startswith("%"):
            name = text.strip()[1:-1]
            line, column = self._location()
            raise ParameterEntityForbidden(
                name,
                None,
                None,
                None,
                None,
                None,
                construct="parameter-entity-reference",
                depth=self._dtd_depth,
                source=self._dtd_source,
                line=line,
                column=column,
            )
        if self._orig_default_handler_expand is not None:
            return self._orig_default_handler_expand(text)

    def defused_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        line, column = self._location()
        raise_entity_decl(
            name,
            is_parameter_entity,
            value,
            base,
            sysid,
            pubid,
            notation_name,
            forbid_entities=self.forbid_entities,
            forbid_external=self.forbid_external,
            depth=max(self._dtd_depth, 1),
            source=self._dtd_source,
            line=line,
            column=column,
        )

    def defused_unparsed_entity_decl(self, name, base, sysid, pubid, notation_name):
        line, column = self._location()
        raise_unparsed_entity_decl(
            name,
            base,
            sysid,
            pubid,
            notation_name,
            forbid_entities=self.forbid_entities,
            forbid_external=self.forbid_external,
            depth=max(self._dtd_depth, 1),
            source=self._dtd_source,
            line=line,
            column=column,
        )

    def defused_notation_decl(self, name, base, sysid, pubid):
        line, column = self._location()
        raise_notation_decl(
            name,
            base,
            sysid,
            pubid,
            forbid_entities=self.forbid_entities,
            forbid_external=self.forbid_external,
            depth=max(self._dtd_depth, 1),
            source=self._dtd_source,
            line=line,
            column=column,
        )

    def defused_external_entity_ref_handler(self, context, base, sysid, pubid):
        line, column = self._location()
        raise_external_reference(
            context,
            base,
            sysid,
            pubid,
            depth=max(self._dtd_depth, 1),
            source=self._dtd_source,
            line=line,
            column=column,
        )


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
):
    if parser is None:
        parser = DefusedXMLParser(
            target=_TreeBuilder(),
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
    return _iterparse(source, events, parser)


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
    "iterparse",
    "parse",
    "tostring",
]

# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.dom.expatbuilder
"""
from __future__ import print_function, absolute_import

from xml.dom.expatbuilder import ExpatBuilder as _ExpatBuilder
from xml.dom.expatbuilder import Namespaces as _Namespaces

from .common import DTDForbidden
from .dtdscan import (
    DTDScanGuard,
    raise_entity_decl,
    raise_unparsed_entity_decl,
    raise_notation_decl,
    raise_external_reference,
)

__origin__ = "xml.dom.expatbuilder"


class DefusedExpatBuilder(_ExpatBuilder):
    """Defused document builder"""

    def __init__(
        self, options=None, forbid_dtd=False, forbid_entities=True, forbid_external=True
    ):
        _ExpatBuilder.__init__(self, options)
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external
        self._dtd_depth = 0
        self._dtd_source = "internal_subset"

    def _make_guard(self):
        return DTDScanGuard(
            forbid_dtd=self.forbid_dtd,
            forbid_entities=self.forbid_entities,
            forbid_external=self.forbid_external,
        )

    def _location(self):
        parser = self._parser
        try:
            return parser.CurrentLineNumber, parser.CurrentColumnNumber + 1
        except AttributeError:
            return None, None

    def _is_own_end_handler(self, handler):
        return getattr(handler, "__func__", None) is self.defused_end_doctype_decl.__func__

    def _scan(self, data):
        guard = self._make_guard()
        guard.feed(data, is_final=True)

    def parseString(self, string):
        self._scan(string)
        return _ExpatBuilder.parseString(self, string)

    def parseFile(self, file):
        data = file.read()
        return self.parseString(data)

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
        if self._orig_start_doctype is not None:
            result = self._orig_start_doctype(name, sysid, pubid, has_internal_subset)
        else:
            result = None
        end_handler = self._parser.EndDoctypeDeclHandler
        if end_handler is not None and not self._is_own_end_handler(end_handler):
            self._orig_end_doctype = end_handler
            self._parser.EndDoctypeDeclHandler = self.defused_end_doctype_decl
        return result

    def defused_end_doctype_decl(self):
        self._dtd_depth = 0
        if self._orig_end_doctype is not None:
            return self._orig_end_doctype()

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
        if self._orig_entity_decl is not None:
            return self._orig_entity_decl(
                name, is_parameter_entity, value, base, sysid, pubid, notation_name
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
        if self._orig_unparsed_entity_decl is not None:
            return self._orig_unparsed_entity_decl(
                name, base, sysid, pubid, notation_name
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
        if self._orig_notation_decl is not None:
            return self._orig_notation_decl(name, base, sysid, pubid)

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

    def install(self, parser):
        _ExpatBuilder.install(self, parser)
        self._dtd_depth = 0
        self._dtd_source = "internal_subset"
        self._orig_start_doctype = parser.StartDoctypeDeclHandler
        self._orig_end_doctype = parser.EndDoctypeDeclHandler
        if self._is_own_end_handler(self._orig_end_doctype):
            self._orig_end_doctype = None
        self._orig_entity_decl = parser.EntityDeclHandler
        self._orig_unparsed_entity_decl = parser.UnparsedEntityDeclHandler
        self._orig_notation_decl = parser.NotationDeclHandler
        parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        parser.EndDoctypeDeclHandler = self.defused_end_doctype_decl
        parser.EntityDeclHandler = self.defused_entity_decl
        parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
        parser.NotationDeclHandler = self.defused_notation_decl
        if self.forbid_external:
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler


class DefusedExpatBuilderNS(_Namespaces, DefusedExpatBuilder):
    """Defused document builder that supports namespaces."""

    def install(self, parser):
        DefusedExpatBuilder.install(self, parser)
        if self._options.namespace_declarations:
            parser.StartNamespaceDeclHandler = self.start_namespace_decl_handler

    def reset(self):
        DefusedExpatBuilder.reset(self)
        self._initNamespaces()


def parse(file, namespaces=True, forbid_dtd=False, forbid_entities=True, forbid_external=True):
    """Parse a document, returning the resulting Document node.

    'file' may be either a file name or an open file object.
    """
    if namespaces:
        build_builder = DefusedExpatBuilderNS
    else:
        build_builder = DefusedExpatBuilder
    builder = build_builder(
        forbid_dtd=forbid_dtd, forbid_entities=forbid_entities, forbid_external=forbid_external
    )

    if isinstance(file, str):
        fp = open(file, "rb")
        try:
            result = builder.parseFile(fp)
        finally:
            fp.close()
    else:
        result = builder.parseFile(file)
    return result


def parseString(
    string, namespaces=True, forbid_dtd=False, forbid_entities=True, forbid_external=True
):
    """Parse a document from a string, returning the resulting
    Document node.
    """
    if namespaces:
        build_builder = DefusedExpatBuilderNS
    else:
        build_builder = DefusedExpatBuilder
    builder = build_builder(
        forbid_dtd=forbid_dtd, forbid_entities=forbid_entities, forbid_external=forbid_external
    )
    return builder.parseString(string)

# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.sax.expatreader
"""
from __future__ import print_function, absolute_import

from xml.sax.expatreader import ExpatParser as _ExpatParser

from .common import DTDForbidden, ParameterEntityForbidden
from .dtdscan import (
    DTDScanGuard,
    raise_entity_decl,
    raise_unparsed_entity_decl,
    raise_notation_decl,
    raise_external_reference,
)

__origin__ = "xml.sax.expatreader"


class DefusedExpatParser(_ExpatParser):
    """Defused SAX driver for the pyexpat C module."""

    def __init__(
        self,
        namespaceHandling=0,
        bufsize=2**16 - 20,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
    ):
        super().__init__(namespaceHandling, bufsize)
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external
        self._dtd_depth = 0
        self._dtd_source = "internal_subset"
        self._dtd_guard = self._make_guard()

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
            return self._orig_start_doctype(name, sysid, pubid, has_internal_subset)

    def defused_end_doctype_decl(self):
        self._dtd_depth = 0
        if self._orig_end_doctype is not None:
            return self._orig_end_doctype()

    def defused_default_handler(self, text):
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
        if self._orig_default_handler is not None:
            return self._orig_default_handler(text)

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

    def feed(self, data, isFinal=False):
        self._dtd_guard.update_flags(
            forbid_dtd=self.forbid_dtd,
            forbid_entities=self.forbid_entities,
            forbid_external=self.forbid_external,
        )
        buffered = self._dtd_guard.feed(data, is_final=isFinal)
        if buffered is None:
            return
        super().feed(buffered, isFinal)

    def reset(self):
        super().reset()
        parser = self._parser
        self._dtd_depth = 0
        self._dtd_source = "internal_subset"
        self._dtd_guard = self._make_guard()
        self._orig_start_doctype = parser.StartDoctypeDeclHandler
        self._orig_end_doctype = parser.EndDoctypeDeclHandler
        self._orig_entity_decl = parser.EntityDeclHandler
        self._orig_unparsed_entity_decl = parser.UnparsedEntityDeclHandler
        self._orig_notation_decl = parser.NotationDeclHandler
        self._orig_default_handler = parser.DefaultHandler
        parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        parser.EndDoctypeDeclHandler = self.defused_end_doctype_decl
        parser.EntityDeclHandler = self.defused_entity_decl
        parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
        parser.NotationDeclHandler = self.defused_notation_decl
        if self.forbid_entities:
            parser.DefaultHandler = self.defused_default_handler
        if self.forbid_external:
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler


def create_parser(*args, **kwargs):
    return DefusedExpatParser(*args, **kwargs)

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

from .common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden

__origin__ = "xml.dom.expatbuilder"


class DefusedExpatBuilder(_ExpatBuilder):
    """Defused document builder"""

    def __init__(
        self,
        options=None,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
        security_mode=None,
    ):
        _ExpatBuilder.__init__(self, options)
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external
        self.security_mode = security_mode

    def defused_start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        raise DTDForbidden(
            name, sysid, pubid, security_mode=self.security_mode, parser=self._parser
        )

    def defused_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        raise EntitiesForbidden(
            name,
            value,
            base,
            sysid,
            pubid,
            notation_name,
            security_mode=self.security_mode,
            parser=self._parser,
        )

    def defused_unparsed_entity_decl(self, name, base, sysid, pubid, notation_name):
        # expat 1.2
        raise EntitiesForbidden(  # pragma: no cover
            name,
            None,
            base,
            sysid,
            pubid,
            notation_name,
            security_mode=self.security_mode,
            parser=self._parser,
        )

    def defused_external_entity_ref_handler(self, context, base, sysid, pubid):
        raise ExternalReferenceForbidden(
            context,
            base,
            sysid,
            pubid,
            security_mode=self.security_mode,
            parser=self._parser,
        )

    def install(self, parser):
        _ExpatBuilder.install(self, parser)

        if self.forbid_dtd:
            parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        if self.forbid_entities:
            # if self._options.entities:
            parser.EntityDeclHandler = self.defused_entity_decl
            parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
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


def parse(
    file,
    namespaces=True,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    security_mode=None,
):
    """Parse a document, returning the resulting Document node.

    'file' may be either a file name or an open file object.
    """
    if namespaces:
        build_builder = DefusedExpatBuilderNS
    else:
        build_builder = DefusedExpatBuilder
    builder = build_builder(
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
        security_mode=security_mode,
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
    string,
    namespaces=True,
    forbid_dtd=False,
    forbid_entities=True,
    forbid_external=True,
    security_mode=None,
):
    """Parse a document from a string, returning the resulting
    Document node.
    """
    if namespaces:
        build_builder = DefusedExpatBuilderNS
    else:
        build_builder = DefusedExpatBuilder
    builder = build_builder(
        forbid_dtd=forbid_dtd,
        forbid_entities=forbid_entities,
        forbid_external=forbid_external,
        security_mode=security_mode,
    )
    return builder.parseString(string)

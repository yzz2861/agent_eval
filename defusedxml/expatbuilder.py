# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.dom.expatbuilder"""

from __future__ import print_function, absolute_import

from xml.dom.expatbuilder import ExpatBuilder as _ExpatBuilder
from xml.dom.expatbuilder import Namespaces as _Namespaces
from xml.dom.expatbuilder import ParseEscape

from .common import (
    DTDForbidden,
    EntitiesForbidden,
    ExpansionPolicy,
    ExternalReferenceForbidden,
)

__origin__ = "xml.dom.expatbuilder"


class DefusedExpatBuilder(_ExpatBuilder):
    """Defused document builder"""

    def __init__(
        self,
        options=None,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
        expansion_policy=None,
    ):
        _ExpatBuilder.__init__(self, options)
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external
        self.expansion_policy = expansion_policy
        self.expansion_state = None

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

    def install(self, parser):
        _ExpatBuilder.install(self, parser)

        if self.forbid_dtd:
            parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        if self.expansion_policy is not None and self.expansion_policy.enabled:
            self.expansion_state = self.expansion_policy.create_state()
            parser.EntityDeclHandler = self.expansion_entity_decl
            parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
            parser.StartDoctypeDeclHandler = self.expansion_start_doctype_decl
            parser.EndDoctypeDeclHandler = self.expansion_end_doctype_decl
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler
            parser.DefaultHandler = self.expansion_default
            parser.StartElementHandler = self.expansion_start_element
        elif self.forbid_entities:
            # if self._options.entities:
            parser.EntityDeclHandler = self.defused_entity_decl
            parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
        if self.forbid_external:
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler

    def parseFile(self, file):
        parser = self.getParser()
        first_buffer = True
        try:
            while True:
                buffer = file.read(16 * 1024)
                if not buffer:
                    break
                parser.Parse(buffer, False)
                if first_buffer and self.document.documentElement:
                    self._setup_subset(buffer)
                first_buffer = False
            parser.Parse(b"", True)
        except ParseEscape:
            pass
        except Exception:
            self.reset()
            self._parser = None
            raise
        doc = self.document
        self.reset()
        self._parser = None
        return doc

    def parseString(self, string):
        parser = self.getParser()
        try:
            parser.Parse(string, True)
            self._setup_subset(string)
        except ParseEscape:
            pass
        except Exception:
            self.reset()
            self._parser = None
            raise
        doc = self.document
        self.reset()
        self._parser = None
        return doc

    def expansion_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        self.expansion_state.entity_declared(
            name, is_parameter_entity, value, base, sysid, pubid, notation_name
        )
        self.entity_decl_handler(
            name, is_parameter_entity, value, base, sysid, pubid, notation_name
        )

    def expansion_start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        self.start_doctype_decl_handler(name, sysid, pubid, has_internal_subset)
        self._parser.EndDoctypeDeclHandler = self.expansion_end_doctype_decl

    def expansion_end_doctype_decl(self):
        self.expansion_state.finalize_declarations()
        self.end_doctype_decl_handler()

    def expansion_start_element(self, name, attributes):
        self.expansion_state.count_raw_entities(self._parser.GetInputContext())
        if self.document.documentElement is None:
            self.first_element_handler(name, attributes)
            self._parser.StartElementHandler = self.expansion_start_element
        else:
            self.start_element_handler(name, attributes)

    def expansion_default(self, text):
        if not text.startswith("&") or not text.endswith(";") or len(text) < 3:
            return
        value = self.expansion_state.reference(text[1:-1])
        if value is not None:
            self.character_data_handler(value)


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
    expansion_policy=None,
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
        expansion_policy=expansion_policy,
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
    expansion_policy=None,
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
        expansion_policy=expansion_policy,
    )
    return builder.parseString(string)

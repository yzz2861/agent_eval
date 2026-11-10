# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.sax.expatreader"""

from __future__ import print_function, absolute_import

from xml.sax.expatreader import ExpatParser as _ExpatParser

from .common import (
    DTDForbidden,
    EntitiesForbidden,
    ExpansionPolicy,
    ExternalReferenceForbidden,
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
        expansion_policy=None,
    ):
        super().__init__(namespaceHandling, bufsize)
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

    def reset(self):
        super().reset()
        parser = self._parser
        if self.forbid_dtd:
            parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        if self.expansion_policy is not None and self.expansion_policy.enabled:
            self.expansion_state = self.expansion_policy.create_state()
            parser.EntityDeclHandler = self.expansion_entity_decl
            parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
            parser.EndDoctypeDeclHandler = self.expansion_end_doctype_decl
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler
            parser.DefaultHandler = self.expansion_default
            parser.SkippedEntityHandler = self.expansion_skipped_entity
            if self._namespaces:
                parser.StartElementHandler = self.expansion_start_element_ns
            else:
                parser.StartElementHandler = self.expansion_start_element
        elif self.forbid_entities:
            parser.EntityDeclHandler = self.defused_entity_decl
            parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
        if self.forbid_external:
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler

    def expansion_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        self.expansion_state.entity_declared(
            name, is_parameter_entity, value, base, sysid, pubid, notation_name
        )

    def expansion_end_doctype_decl(self):
        self.expansion_state.finalize_declarations()

    def expansion_start_element(self, name, attrs):
        self.expansion_state.count_raw_entities(self._parser.GetInputContext())
        self.start_element(name, attrs)

    def expansion_start_element_ns(self, name, attrs):
        self.expansion_state.count_raw_entities(self._parser.GetInputContext())
        self.start_element_ns(name, attrs)

    def expansion_default(self, text):
        if not text.startswith("&") or not text.endswith(";") or len(text) < 3:
            return
        value = self.expansion_state.reference(text[1:-1])
        if value is not None:
            self._cont_handler.characters(value)

    def expansion_skipped_entity(self, name, is_parameter_entity):
        if is_parameter_entity:
            self.skipped_entity_handler(name, is_parameter_entity)
            return
        value = self.expansion_state.reference(name)
        if value is None:
            self.skipped_entity_handler(name, is_parameter_entity)
        else:
            self._cont_handler.characters(value)


def create_parser(*args, **kwargs):
    return DefusedExpatParser(*args, **kwargs)

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
from ._expat_policy import ExpatPolicyHandler
from .policy import BACKEND_MINIDOM, XMLSecurityPolicy

__origin__ = "xml.dom.expatbuilder"


class DefusedExpatBuilder(_ExpatBuilder):
    """Defused document builder"""

    def __init__(
        self,
        options=None,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
        policy=None,
    ):
        _ExpatBuilder.__init__(self, options)
        if policy is not None and not isinstance(policy, XMLSecurityPolicy):
            raise TypeError(
                "policy must be an XMLSecurityPolicy instance, got {!r}".format(
                    type(policy).__name__
                )
            )
        self._policy = policy
        self._backend = BACKEND_MINIDOM
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external

    # Shared XMLSecurityPolicy implementation.
    _position = ExpatPolicyHandler._position
    policy_start_doctype_decl = ExpatPolicyHandler.policy_start_doctype_decl
    policy_entity_decl = ExpatPolicyHandler.policy_entity_decl
    policy_unparsed_entity_decl = ExpatPolicyHandler.policy_unparsed_entity_decl
    policy_external_entity_ref_handler = (
        ExpatPolicyHandler.policy_external_entity_ref_handler
    )
    install_policy = ExpatPolicyHandler.install_policy

    def _raise(self, exc, policy_item):
        exc.backend = self._backend
        exc.policy_item = policy_item
        exc.position = self._position()
        raise exc

    # The stdlib ExpatBuilder handlers construct DOM nodes and maintain
    # parser state.  Run them first so an *allowed* document still builds a
    # correct DOM; a denied document raises from the policy check afterwards,
    # before any external content can be fetched.
    def policy_start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        _ExpatBuilder.start_doctype_decl_handler(
            self, name, sysid, pubid, has_internal_subset
        )
        return ExpatPolicyHandler.policy_start_doctype_decl(
            self, name, sysid, pubid, has_internal_subset
        )

    def policy_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        _ExpatBuilder.entity_decl_handler(
            self,
            name,
            is_parameter_entity,
            value,
            base,
            sysid,
            pubid,
            notation_name,
        )
        return ExpatPolicyHandler.policy_entity_decl(
            self,
            name,
            is_parameter_entity,
            value,
            base,
            sysid,
            pubid,
            notation_name,
        )

    def policy_unparsed_entity_decl(
        self, name, base, sysid, pubid, notation_name
    ):
        if hasattr(_ExpatBuilder, "unparsed_entity_decl_handler"):
            _ExpatBuilder.unparsed_entity_decl_handler(
                self, name, base, sysid, pubid, notation_name
            )
        return ExpatPolicyHandler.policy_unparsed_entity_decl(
            self, name, base, sysid, pubid, notation_name
        )

    def policy_external_entity_ref_handler(self, context, base, sysid, pubid):
        # Check first: the stdlib handler would attempt to open the URI.
        ExpatPolicyHandler.policy_external_entity_ref_handler(
            self, context, base, sysid, pubid
        )
        return _ExpatBuilder.external_entity_ref_handler(
            self, context, base, sysid, pubid
        )

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
        if self._policy is not None:
            self.install_policy(parser)
            return

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
    policy=None,
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
        policy=policy,
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
    policy=None,
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
        policy=policy,
    )
    return builder.parseString(string)

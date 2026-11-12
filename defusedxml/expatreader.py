# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xml.sax.expatreader
"""
from __future__ import print_function, absolute_import

from xml.sax.expatreader import ExpatParser as _ExpatParser

from .common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden
from ._expat_policy import ExpatPolicyHandler
from .policy import BACKEND_SAX, XMLSecurityPolicy

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
        policy=None,
    ):
        super().__init__(namespaceHandling, bufsize)
        if policy is not None and not isinstance(policy, XMLSecurityPolicy):
            raise TypeError(
                "policy must be an XMLSecurityPolicy instance, got {!r}".format(
                    type(policy).__name__
                )
            )
        self._policy = policy
        self._backend = BACKEND_SAX
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external

    # Shared XMLSecurityPolicy implementation.  The mixin reads
    # ``self._parser`` which the SAX base class creates in reset().
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
        if self._policy is not None:
            self.install_policy(parser)
            return
        if self.forbid_dtd:
            parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        if self.forbid_entities:
            parser.EntityDeclHandler = self.defused_entity_decl
            parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
        if self.forbid_external:
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler


def create_parser(*args, **kwargs):
    return DefusedExpatParser(*args, **kwargs)

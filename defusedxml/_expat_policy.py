# defusedxml
#
# Copyright (c) 2026 by the defusedxml authors
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license/license
"""Shared pyexpat glue for :mod:`defusedxml.policy`.

All stdlib backends (ElementTree, minidom/expatbuilder, sax/expatreader,
pulldom and xmlrpc) sit on top of pyexpat and therefore expose the same
callback surface.  The :class:`ExpatPolicyHandler` implements the shared
:class:`~defusedxml.policy.XMLSecurityPolicy` once; each backend only has to
call :meth:`install` on its raw pyexpat parser.
"""
from __future__ import absolute_import

from .common import (
    DTDForbidden,
    EntitiesForbidden,
    ExternalDTDForbidden,
    ExternalReferenceForbidden,
    ParameterEntityForbidden,
    UnparsedEntityForbidden,
    XMLPosition,
)
from .policy import (
    POLICY_DTD,
    POLICY_EXTERNAL_DTD,
    POLICY_EXTERNAL_REFERENCES,
    POLICY_INTERNAL_ENTITIES,
    POLICY_PARAMETER_ENTITIES,
    POLICY_UNPARSED_ENTITIES,
)


class ExpatPolicyHandler:
    """Map an :class:`XMLSecurityPolicy` onto pyexpat callback handlers.

    The mixin expects the consuming class to provide ``self._parser`` (a
    raw :mod:`xml.parsers.expat` parser), ``self._policy`` and
    ``self._backend``.  It never reads or stores document content; entity
    *values* are deliberately dropped from the raised exceptions.
    """

    def _position(self):
        parser = getattr(self, "_parser", None)
        if parser is None:
            return None
        try:
            return XMLPosition(
                byte_index=parser.CurrentByteIndex,
                line=parser.CurrentLineNumber,
                column=parser.CurrentColumnNumber,
            )
        except Exception:
            return None

    def _raise(self, exc, policy_item):
        exc.backend = self._backend
        exc.policy_item = policy_item
        exc.position = self._position()
        raise exc

    def policy_start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        # An external DTD subset is referenced through a non-empty system
        # (or public) identifier on the doctype declaration itself.
        if not self._policy.allow_external_dtd and (sysid or pubid):
            self._raise(
                ExternalDTDForbidden(
                    name, sysid, pubid, self._position()
                ),
                POLICY_EXTERNAL_DTD,
            )
        if not self._policy.allow_dtd:
            self._raise(
                DTDForbidden(name, sysid, pubid, self._position()),
                POLICY_DTD,
            )

    def policy_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        position = self._position()
        if is_parameter_entity:
            if not self._policy.allow_parameter_entities:
                self._raise(
                    ParameterEntityForbidden(name, base, sysid, pubid, position),
                    POLICY_PARAMETER_ENTITIES,
                )
            return
        if notation_name:
            # pyexpat routes NDATA declarations to UnparsedEntityDeclHandler;
            # keep a defensive branch in case a build reports them here.
            if not self._policy.allow_unparsed_entities:
                self._raise(
                    UnparsedEntityForbidden(
                        name, base, sysid, pubid, notation_name, position
                    ),
                    POLICY_UNPARSED_ENTITIES,
                )
            return
        if sysid or pubid:
            # External general entity *declaration*.  Rejecting the
            # declaration means no resolver is ever invoked, so the
            # referenced URI is never fetched.
            if not self._policy.allow_external_references:
                self._raise(
                    EntitiesForbidden(
                        name, None, base, sysid, pubid, notation_name, position
                    ),
                    POLICY_EXTERNAL_REFERENCES,
                )
            return
        if not self._policy.allow_internal_entities:
            self._raise(
                EntitiesForbidden(
                    name, None, base, sysid, pubid, notation_name, position
                ),
                POLICY_INTERNAL_ENTITIES,
            )

    def policy_unparsed_entity_decl(
        self, name, base, sysid, pubid, notation_name
    ):
        if not self._policy.allow_unparsed_entities:
            self._raise(
                UnparsedEntityForbidden(
                    name,
                    base,
                    sysid,
                    pubid,
                    notation_name,
                    self._position(),
                ),
                POLICY_UNPARSED_ENTITIES,
            )

    def policy_external_entity_ref_handler(self, context, base, sysid, pubid):
        # Belt-and-braces: reached when an external entity is actually
        # referenced even though its declaration was allowed.
        if not self._policy.allow_external_references:
            self._raise(
                ExternalReferenceForbidden(
                    context, base, sysid, pubid, self._position()
                ),
                POLICY_EXTERNAL_REFERENCES,
            )
        return 1

    def install_policy(self, parser):
        """Register every callback needed to enforce ``self._policy``."""
        parser.StartDoctypeDeclHandler = self.policy_start_doctype_decl
        parser.EntityDeclHandler = self.policy_entity_decl
        parser.UnparsedEntityDeclHandler = self.policy_unparsed_entity_decl
        parser.ExternalEntityRefHandler = self.policy_external_entity_ref_handler


__all__ = ("ExpatPolicyHandler",)

# defusedxml
#
# Copyright (c) 2026 by the defusedxml authors
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license/license
"""lxml implementation of the shared :class:`XMLSecurityPolicy`.

lxml is an optional dependency.  The module imports :mod:`lxml.etree`
lazily so that simply importing :mod:`defusedxml` never fails on systems
without lxml; attempting to *use* the backend raises
:class:`~defusedxml.common.BackendUnavailable`.

lxml cannot distinguish a parameter entity declaration from an ordinary
general entity declaration (both surface through the same DTD entity API).
When the policy denies parameter entities, parsing therefore fails with
:class:`~defusedxml.common.NotSupportedError` rather than silently allowing
the document through.  Unparsed (NDATA) entities *are* recognizable because
they carry both a system URI and a notation name and can be enforced.
"""
from __future__ import absolute_import

from .common import (
    BackendUnavailable,
    DTDForbidden,
    EntitiesForbidden,
    ExternalDTDForbidden,
    UnparsedEntityForbidden,
)
from .policy import (
    BACKEND_LXML,
    POLICY_DTD,
    POLICY_EXTERNAL_DTD,
    POLICY_EXTERNAL_REFERENCES,
    POLICY_INTERNAL_ENTITIES,
    POLICY_UNPARSED_ENTITIES,
    check_capability,
)

__origin__ = "lxml.etree"

_etree = None
_import_error = None


def _load_lxml():
    """Import lxml.etree once, caching any ImportError."""
    global _etree, _import_error
    if _etree is None and _import_error is None:
        try:
            from lxml import etree
        except ImportError as exc:
            _import_error = exc
        else:
            _etree = etree
    if _etree is None:
        raise BackendUnavailable(BACKEND_LXML, _import_error)
    return _etree


def is_available():
    """Return True when the lxml backend can be imported."""
    try:
        _load_lxml()
    except BackendUnavailable:
        return False
    return True


def _raise_policy(exc, policy_item):
    exc.backend = BACKEND_LXML
    exc.policy_item = policy_item
    # lxml reports syntax positions on XMLSyntaxError only; policy violations
    # are detected on the parsed DTD without a stable byte offset.
    exc.position = None
    raise exc


def _build_parser(etree, parser):
    if parser is not None:
        return parser
    # Never resolve entities and never touch the network.  The policy checks
    # below run on the declarations, so a forbidden declaration is rejected
    # even though expansion itself would have been suppressed.
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
    )


def _check_tree(elementtree, policy):
    """Inspect docinfo/DTD declarations against the shared policy."""
    docinfo = elementtree.docinfo

    if docinfo.doctype:
        if not policy.allow_external_dtd and (docinfo.system_url or docinfo.public_id):
            _raise_policy(
                ExternalDTDForbidden(
                    docinfo.root_name if hasattr(docinfo, "root_name") else None,
                    docinfo.system_url,
                    docinfo.public_id,
                ),
                POLICY_EXTERNAL_DTD,
            )
        if not policy.allow_dtd:
            _raise_policy(
                DTDForbidden(
                    docinfo.root_name if hasattr(docinfo, "root_name") else None,
                    docinfo.system_url,
                    docinfo.public_id,
                ),
                POLICY_DTD,
            )

    for dtd in (docinfo.internalDTD, docinfo.externalDTD):
        if dtd is None:
            continue
        for entity in dtd.iterentities():
            system_url = getattr(entity, "system_url", None)
            content = getattr(entity, "content", None)
            # An unparsed (NDATA) entity has both a system URI and its
            # "content" set to the notation name instead of replacement text.
            is_unparsed = bool(system_url) and content is not None
            if is_unparsed:
                if not policy.allow_unparsed_entities:
                    _raise_policy(
                        UnparsedEntityForbidden(
                            entity.name, None, system_url, None, content, None
                        ),
                        POLICY_UNPARSED_ENTITIES,
                    )
            elif system_url:
                if not policy.allow_external_references:
                    _raise_policy(
                        EntitiesForbidden(
                            entity.name, None, None, system_url, None, None
                        ),
                        POLICY_EXTERNAL_REFERENCES,
                    )
            else:
                if not policy.allow_internal_entities:
                    _raise_policy(
                        EntitiesForbidden(
                            entity.name, None, None, None, None, None
                        ),
                        POLICY_INTERNAL_ENTITIES,
                    )


def parse(source, policy, parser=None, base_url=None):
    """Parse a file/path with lxml under an explicit policy."""
    etree = _load_lxml()
    check_capability(BACKEND_LXML, policy)
    parser = _build_parser(etree, parser)
    tree = etree.parse(source, parser, base_url=base_url)
    _check_tree(tree, policy)
    return tree


def fromstring(text, policy, parser=None, base_url=None):
    """Parse an in-memory document with lxml under an explicit policy."""
    etree = _load_lxml()
    check_capability(BACKEND_LXML, policy)
    parser = _build_parser(etree, parser)
    root = etree.fromstring(text, parser, base_url=base_url)
    tree = root.getroottree()
    _check_tree(tree, policy)
    return root

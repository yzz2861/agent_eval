# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license/license
"""lxml.etree protection.

The historical :func:`parse`/:func:`fromstring` helpers (legacy
``forbid_dtd`` / ``forbid_entities`` booleans) remain available, but the
module now also implements the shared
:class:`~defusedxml.policy.XMLSecurityPolicy`.  Pass ``policy=`` to opt into
the unified, capability-checked behavior.

lxml is optional: importing this module never raises when lxml is missing.
Calling a function that needs lxml then raises
:class:`~defusedxml.common.BackendUnavailable`.
"""
from __future__ import print_function, absolute_import

import threading
import warnings

from . import _lxml_policy
from .common import (
    DTDForbidden,
    EntitiesForbidden,
    NotSupportedError,
)
from .policy import XMLSecurityPolicy

__origin__ = "lxml.etree"


def _etree():
    return _lxml_policy._load_lxml()


def is_available():
    """Return True when a usable lxml installation is importable."""
    return _lxml_policy.is_available()


# ``tostring`` and the version flag used to be module attributes evaluated at
# import time.  Expose them lazily so the module imports without lxml.
def __getattr__(name):
    if name == "tostring":
        return _etree().tostring
    if name == "LXML3":
        return _etree().LXML_VERSION[0] >= 3
    raise AttributeError("module {!r} has no attribute {!r}".format(__name__, name))


warnings.warn(
    "defusedxml.lxml is deprecated; use the XMLSecurityPolicy entry in "
    "defusedxml.policy instead.",
    category=DeprecationWarning,
    stacklevel=2,
)


RestrictedElement = None


def _get_restricted_element_class():
    """Build the lxml-dependent RestrictedElement subclass on first use."""
    global RestrictedElement
    if RestrictedElement is None:
        etree = _etree()

        class RestrictedElementImpl(etree.ElementBase):
            __slots__ = ()
            blacklist = etree._Entity

            def _filter(self, iterator):
                blacklist = type(self).blacklist
                for child in iterator:
                    if isinstance(child, blacklist):
                        continue
                    yield child

            def __iter__(self):
                iterator = super(RestrictedElementImpl, self).__iter__()
                return self._filter(iterator)

            def iterchildren(self, tag=None, reversed=False):
                iterator = super(RestrictedElementImpl, self).iterchildren(
                    tag=tag, reversed=reversed
                )
                return self._filter(iterator)

            def iter(self, tag=None, *tags):
                iterator = super(RestrictedElementImpl, self).iter(tag=tag, *tags)
                return self._filter(iterator)

            def iterdescendants(self, tag=None, *tags):
                iterator = super(RestrictedElementImpl, self).iterdescendants(
                    tag=tag, *tags
                )
                return self._filter(iterator)

            def itersiblings(self, tag=None, preceding=False):
                iterator = super(RestrictedElementImpl, self).itersiblings(
                    tag=tag, preceding=preceding
                )
                return self._filter(iterator)

            def getchildren(self):
                iterator = super(RestrictedElementImpl, self).__iter__()
                return list(self._filter(iterator))

            def getiterator(self, tag=None):
                iterator = super(RestrictedElementImpl, self).getiterator(tag)
                return self._filter(iterator)

        RestrictedElement = RestrictedElementImpl
    return RestrictedElement


class GlobalParserTLS(threading.local):
    """Thread local context for custom parser instances"""

    parser_config = {
        "resolve_entities": False,
    }

    element_class = None

    def createDefaultParser(self):
        etree = _etree()
        parser = etree.XMLParser(**self.parser_config)
        element_class = _get_restricted_element_class()
        lookup = etree.ElementDefaultClassLookup(element=element_class)
        parser.set_element_class_lookup(lookup)
        return parser

    def setDefaultParser(self, parser):
        self._default_parser = parser

    def getDefaultParser(self):
        parser = getattr(self, "_default_parser", None)
        if parser is None:
            parser = self.createDefaultParser()
            self.setDefaultParser(parser)
        return parser


_parser_tls = GlobalParserTLS()
getDefaultParser = _parser_tls.getDefaultParser


def check_docinfo(elementtree, forbid_dtd=False, forbid_entities=True):
    """Legacy check of docinfo for DTD and entity declarations."""
    etree = _etree()
    lxml3 = etree.LXML_VERSION[0] >= 3
    docinfo = elementtree.docinfo
    if docinfo.doctype:
        if forbid_dtd:
            raise DTDForbidden(docinfo.doctype, docinfo.system_url, docinfo.public_id)
        if forbid_entities and not lxml3:
            raise NotSupportedError(
                "Unable to check for entity declarations in lxml 2.x"
            )

    if forbid_entities:
        for dtd in docinfo.internalDTD, docinfo.externalDTD:
            if dtd is None:
                continue
            for entity in dtd.iterentities():
                raise EntitiesForbidden(
                    entity.name, entity.content, None, None, None, None
                )


def parse(
    source,
    parser=None,
    base_url=None,
    forbid_dtd=False,
    forbid_entities=True,
    policy=None,
):
    if policy is not None:
        if not isinstance(policy, XMLSecurityPolicy):
            raise TypeError(
                "policy must be an XMLSecurityPolicy instance, got {!r}".format(
                    type(policy).__name__
                )
            )
        return _lxml_policy.parse(
            source, policy, parser=parser, base_url=base_url
        )
    if parser is None:
        parser = getDefaultParser()
    elementtree = _etree().parse(source, parser, base_url=base_url)
    check_docinfo(elementtree, forbid_dtd, forbid_entities)
    return elementtree


def fromstring(
    text,
    parser=None,
    base_url=None,
    forbid_dtd=False,
    forbid_entities=True,
    policy=None,
):
    if policy is not None:
        if not isinstance(policy, XMLSecurityPolicy):
            raise TypeError(
                "policy must be an XMLSecurityPolicy instance, got {!r}".format(
                    type(policy).__name__
                )
            )
        return _lxml_policy.fromstring(
            text, policy, parser=parser, base_url=base_url
        )
    if parser is None:
        parser = getDefaultParser()
    rootelement = _etree().fromstring(text, parser, base_url=base_url)
    elementtree = rootelement.getroottree()
    check_docinfo(elementtree, forbid_dtd, forbid_entities)
    return rootelement


XML = fromstring


def iterparse(*args, **kwargs):
    raise NotSupportedError("defused lxml.etree.iterparse not available")
